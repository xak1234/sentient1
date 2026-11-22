// Package engine turns bait access events into verdicts, responses and alerts.
//
// Order of operations for a new reader (speed matters: many stealers collect
// everything first and upload once at the end):
//
//  1. instant verdict from path/name alone, assuming the binary is unsigned
//  2. freeze immediately if that verdict's response includes freezing
//  3. verify the signature, compute the final verdict
//  4. unfreeze if the final verdict doesn't warrant it (e.g. a signed app)
//  5. collect forensics while the process is frozen
//  6. block / kill / isolate as configured, then alert
package engine

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/xak1234/sentient1/internal/alerts"
	"github.com/xak1234/sentient1/internal/authenticode"
	"github.com/xak1234/sentient1/internal/baits"
	"github.com/xak1234/sentient1/internal/classify"
	"github.com/xak1234/sentient1/internal/config"
	"github.com/xak1234/sentient1/internal/evtlog"
	"github.com/xak1234/sentient1/internal/paths"
	"github.com/xak1234/sentient1/internal/procinfo"
	"github.com/xak1234/sentient1/internal/winsec"
)

// Ops are the side effects the engine needs; the service provides real ones.
type Ops interface {
	ImagePath(pid uint32) (string, error)
	CreateTime(pid uint32) int64
	Verify(path string) authenticode.Result
	SuspendTree(pid uint32) ([]uint32, error)
	Resume(pids []uint32)
	KillTree(pid uint32) error
	Forensics(pid uint32, p *alerts.Process)
	BlockProgram(path string) error
	Isolate() error
	DisableAdapters() ([]string, error)
	SaveAlert(a *alerts.Alert) error
	UpdateState(fn func(*config.State) error) error
	NotifyDesktop(a *alerts.Alert)
	NotifyPhone(a *alerts.Alert)
	RetireDecoy(baitID string, why string)
	PendingTest() *TestRequest
	UserSession(pid uint32) bool // runs in an interactive user session (not session 0)
	IsSelf(image string) bool    // the executable is SENTIENT1 itself (same file hash as the service)
	Elevated(pid uint32) bool    // runs with an elevated (admin) token
	Hash(image string) string    // SHA-256 of a file (cached)
	CommandLine(pid uint32) string
	// InjectedCode looks inside a process for running code that isn't from any
	// file on disk (a stealer injected into a legitimate program).
	InjectedCode(pid uint32) (string, bool)
	ClearTest()
	Logf(format string, args ...any)
}

// TestRequest marks a reader process started by `sentient1 test`.
type TestRequest struct {
	PID   uint32    `json:"pid"`
	Nonce string    `json:"nonce"`
	Since time.Time `json:"since"`
}

// Engine is safe for concurrent use.
type Engine struct {
	Ops     Ops
	SelfPID uint32

	mu          sync.Mutex
	cfg         *config.Config
	classifier  *classify.Classifier
	index       map[string]string // lower path -> bait id
	baitNames   map[string]string
	incidents   map[uint32]*incident
	claimed     map[uint32]time.Time     // PIDs the instant path is handling
	seen        map[string]time.Time     // program|bait -> last notification, for alerts with no action
	touched     map[uint32]*sweep        // baits each process opened recently
	sids        map[uint32]string        // account (SID) a process read baits as, from the audit event
	pending     map[uint32]chan struct{} // instant decisions in progress
	eventFrozen map[uint32]time.Time     // processes the event-log path froze
}

// sweep is what one process has opened lately. Stealers grab everything they
// know (browsers, Discord, wallets…) in seconds; a real app only ever touches
// its own data. So a process that reads several different apps' baits is a
// stealer, whatever it is or claims to be: a trusted app with code injected
// into it, a signed program, a Windows component.
type sweep struct {
	createTime int64
	baits      map[string]time.Time
}

// sweepApps distinct baits within window make a sweep.
const sweepApps = 3

type incident struct {
	alert      *alerts.Alert
	createTime int64
	last       time.Time
}

// aggregation window: further bait hits by the same process join one alert.
const window = 2 * time.Minute

func New(ops Ops, selfPID uint32) *Engine {
	return &Engine{Ops: ops, SelfPID: selfPID, incidents: map[uint32]*incident{}, claimed: map[uint32]time.Time{},
		seen: map[string]time.Time{}, touched: map[uint32]*sweep{}, sids: map[uint32]string{},
		pending: map[uint32]chan struct{}{}, eventFrozen: map[uint32]time.Time{}}
}

// Configure (re)loads config and the bait index.
func (e *Engine) Configure(cfg *config.Config, st *config.State) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg = cfg
	e.classifier = &classify.Classifier{Env: classify.DefaultEnv(), Ignore: cfg.Ignore,
		Hash: e.Ops.Hash, CommandLine: e.Ops.CommandLine, UserSession: e.userSession}
	e.index = baits.Index(st)
	e.baitNames = map[string]string{}
	for id, b := range st.Baits {
		e.baitNames[id] = b.Name
	}
}

// IsBait reports whether path is a watched bait file.
func (e *Engine) IsBait(path string) (string, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	id, ok := e.index[paths.Key(path)]
	return id, ok
}

// processes we never suspend or kill (would hang or crash Windows / the desktop).
var neverTouch = map[string]bool{
	"system": true, "csrss.exe": true, "lsass.exe": true, "wininit.exe": true, "winlogon.exe": true,
	"services.exe": true, "smss.exe": true, "svchost.exe": true, "explorer.exe": true, "dwm.exe": true,
	"msmpeng.exe": true, "fontdrvhost.exe": true, "lsaiso.exe": true, "registry": true,
	"memory compression": true, "secure system": true, "sihost.exe": true, "ctfmon.exe": true,
	"audiodg.exe": true, "conhost.exe": true, "runtimebroker.exe": true, "searchhost.exe": true,
}

func (e *Engine) touchable(pid uint32, image string) bool {
	if pid == 0 || pid == 4 || pid == e.SelfPID {
		return false
	}
	return !neverTouch[strings.ToLower(filepath.Base(image))]
}

// DecideInstant runs while a bait opener is paused inside Windows (see package
// instant). It reports whether pid should be frozen right now, before it can
// read. It's deliberately conservative: only ordinary programs in a user
// session whose verdict calls for freezing. Everything else is let through
// and handled by the normal audit-log path if it actually reads.
func (e *Engine) DecideInstant(pid uint32, path string) bool {
	ok, _ := e.DecideInstantWhy(pid, path)
	return ok
}

// DecideInstantWhy is DecideInstant plus the reason, for the service log.
func (e *Engine) DecideInstantWhy(pid uint32, path string) (bool, string) {
	e.mu.Lock()
	cfg, cls := e.cfg, e.classifier
	baitID, isBait := e.index[paths.Key(path)]
	e.mu.Unlock()
	if cfg == nil || !isBait || pid == e.SelfPID {
		return false, "not a bait / SENTIENT1 itself"
	}
	image, err := e.Ops.ImagePath(pid)
	if err != nil || image == "" {
		return false, "can't see its executable"
	}
	if !e.touchable(pid, image) {
		return false, image + " is a protected system process"
	}
	if tr := e.Ops.PendingTest(); tr != nil && tr.PID == pid {
		e.claim(pid)
		return true, image + " is the `sentient1 test` reader"
	}
	if !cfg.InstantFreeze {
		return false, "instant freeze is off"
	}
	// From here on this pid is being decided: the event-log path waits for
	// the decision instead of freezing it too (hashing and the signature check
	// below can take longer than Windows takes to log the read).
	done := e.beginDecision(pid)
	if done == nil {
		return false, image + " is already being handled (another bait or the event log got there first)"
	}
	// Instant freeze acts on a split-second inference, so it only touches
	// ordinary, non-elevated programs in a user session. Admin tools that inspect
	// baits (and elevated malware, out of scope) go through the event-log path.
	if !e.Ops.UserSession(pid) {
		done(false)
		return false, image + " runs in session 0 (system/service)"
	}
	if e.Ops.Elevated(pid) {
		done(false)
		return false, image + " runs as administrator"
	}
	if e.Ops.IsSelf(image) {
		done(false)
		return false, image + " is SENTIENT1 itself"
	}
	sig := e.Ops.Verify(image)
	v := cls.Final(image, pid, baitRef(baitID), sig)
	if swept := e.touch(pid, baitID, time.Now()); len(swept) >= sweepApps && !cls.SweepExempt(image, pid, &sig) {
		v = e.sweepVerdict(v, swept)
	}
	if v.Ignored || v.DecoyOwner {
		done(false)
		return false, image + " is ignored or the real app"
	}
	if !config.Has(cfg.ActionsFor(v.Tier, time.Now()), config.ActionFreeze) {
		done(false)
		return false, fmt.Sprintf("%s is %s; that tier doesn't freeze right now", image, v.Tier)
	}
	done(true)
	return true, fmt.Sprintf("%s is %s", image, v.Tier)
}

// claimDedupe: several bait guards can fire in the same instant (e.g. while
// the service re-arms them) and all point at the same opener. Only the first
// may freeze it: Windows stacks suspensions, so a second freeze would leave it
// suspended after the user unfreezes it once.
const claimDedupe = 2 * time.Second

// beginDecision starts an instant decision about pid, or returns nil if pid
// is already being decided, was just claimed, or was frozen by the event-log
// path. The returned func ends the decision; claimed=true claims pid.
//
// Exactly one of the two paths may freeze a process: Windows stacks
// suspensions, so a double freeze leaves it suspended after one unfreeze.
func (e *Engine) beginDecision(pid uint32) func(claimed bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pending[pid] != nil {
		return nil
	}
	if t, ok := e.claimed[pid]; ok && time.Since(t) < claimDedupe {
		return nil
	}
	if t, ok := e.eventFrozen[pid]; ok && time.Since(t) < window {
		return nil
	}
	ch := make(chan struct{})
	e.pending[pid] = ch
	return func(claimed bool) {
		e.mu.Lock()
		if claimed {
			e.claimed[pid] = time.Now()
		}
		if e.pending[pid] == ch {
			delete(e.pending, pid)
		}
		e.mu.Unlock()
		close(ch)
	}
}

// waitDecision waits (briefly) for an instant decision about pid in progress.
func (e *Engine) waitDecision(pid uint32) {
	e.mu.Lock()
	ch := e.pending[pid]
	e.mu.Unlock()
	if ch != nil {
		select {
		case <-ch:
		case <-time.After(2 * time.Second):
		}
	}
}

// ownFreeze is the event-log path asking to freeze pid itself: false if the
// instant path is deciding about it or has claimed it.
func (e *Engine) ownFreeze(pid uint32) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.pending[pid] != nil {
		return false
	}
	if t, ok := e.claimed[pid]; ok && time.Since(t) < window {
		return false
	}
	for p, t := range e.eventFrozen {
		if time.Since(t) > window {
			delete(e.eventFrozen, p)
		}
	}
	e.eventFrozen[pid] = time.Now()
	return true
}

// claim marks pid as handled by the instant path, so the event-log path (which
// fires a moment later for the same read) doesn't freeze it a second time:
// Windows stacks suspensions, so a double freeze would need two unfreezes.
func (e *Engine) claim(pid uint32) {
	e.mu.Lock()
	now := time.Now()
	for p, t := range e.claimed {
		if now.Sub(t) > window {
			delete(e.claimed, p) // expired claims
		}
	}
	e.claimed[pid] = now
	e.mu.Unlock()
}

// Unclaim releases a claim (e.g. the instant freeze itself failed).
func (e *Engine) Unclaim(pid uint32) {
	e.mu.Lock()
	delete(e.claimed, pid)
	e.mu.Unlock()
}

// HandleOpen raises the alert (and runs the remaining responses) for a reader
// that DecideInstant froze mid-open. frozen is what was suspended.
func (e *Engine) HandleOpen(pid uint32, path string, at time.Time, frozen []uint32) {
	e.handle(&evtlog.ObjectAccess{ProcessID: pid, ObjectName: path, AccessMask: 1, Time: at}, frozen)
}

func baitRef(id string) classify.Bait {
	b := classify.Bait{ID: id}
	if s, ok := baits.ByID(id); ok {
		b.OwnerExes, b.OwnerSigner, b.SharedSDK = s.OwnerExes, s.Signer, s.SharedSDK
	}
	return b
}

// HandleAccess processes one 4663 event.
func (e *Engine) HandleAccess(oa *evtlog.ObjectAccess) { e.handle(oa, nil) }

// handle processes a bait access. preFrozen is non-nil when the reader was
// already frozen by the instant path, the moment it opened the bait.
func (e *Engine) handle(oa *evtlog.ObjectAccess, preFrozen []uint32) {
	instant := preFrozen != nil
	claimedNow := func() bool {
		e.mu.Lock()
		t, ok := e.claimed[oa.ProcessID]
		e.mu.Unlock()
		return ok && time.Since(t) < window
	}
	// tryFreeze: the event-log path may freeze only what the instant path
	// isn't freezing (a decision in progress is waited for).
	tryFreeze := func() bool {
		if e.ownFreeze(oa.ProcessID) {
			return true
		}
		e.waitDecision(oa.ProcessID)
		return e.ownFreeze(oa.ProcessID)
	}
	if !instant {
		e.waitDecision(oa.ProcessID)
		if claimedNow() {
			return // the instant path already caught and is reporting this process
		}
	}
	received := time.Now()
	baitID, ok := e.IsBait(oa.ObjectName)
	if !ok || oa.ProcessID == e.SelfPID {
		return
	}
	// A delayed Security-log event must never suspend an unrelated process
	// that was created later with the same PID. Keep the historical evidence.
	if !instant && EventPredatesProcess(e.Ops.CreateTime(oa.ProcessID), oa.Time) {
		a := &alerts.Alert{ID: alerts.NewID(time.Now()), Time: time.Now(), Kind: alerts.KindRead,
			Tier: config.TierWarn, Status: "open", Title: "Historical decoy access: process ID reused",
			Summary: "The recorded access predates the current process. No response was applied to the reused PID.",
			Process: &alerts.Process{PID: oa.ProcessID, Image: oa.ProcessName, Exited: true},
			Baits:   []alerts.BaitHit{{ID: baitID, Path: oa.ObjectName, Time: oa.Time, Access: "historical"}}}
		if err := e.Ops.SaveAlert(a); err != nil {
			e.Ops.Logf("save historical alert: %v", err)
		}
		e.Ops.NotifyDesktop(a)
		return
	}
	access := "read"
	switch {
	case winsec.AccessMaskIsDelete(oa.AccessMask) && !winsec.AccessMaskIsRead(oa.AccessMask):
		access = "delete"
	case !winsec.AccessMaskIsRead(oa.AccessMask):
		return
	}

	if oa.UserSID != "" {
		e.mu.Lock()
		if len(e.sids) > 4096 {
			e.sids = map[uint32]string{}
		}
		e.sids[oa.ProcessID] = oa.UserSID
		e.mu.Unlock()
	}
	var swept []string
	if access == "read" {
		swept = e.touch(oa.ProcessID, baitID, time.Now())
		if len(swept) >= sweepApps && !e.sweepable(oa.ProcessID) {
			swept = nil
		}
	}

	e.mu.Lock()
	cfg, cls, name := e.cfg, e.classifier, e.baitNames[baitID]
	hit := alerts.BaitHit{ID: baitID, Name: name, Path: oa.ObjectName, Access: access, Time: oa.Time}
	if inc := e.incidents[oa.ProcessID]; !instant && inc != nil && len(swept) >= sweepApps && inc.alert.Tier != config.TierCritical {
		// It started out looking harmless and has now read several apps' data:
		// handle it again as a sweep, with the full response.
		delete(e.incidents, oa.ProcessID)
	}
	// Aggregate repeat hits into the open alert, except for instant catches: a
	// new freeze always gets its own alert and its own record in state (the
	// earlier alert may already be resolved, e.g. the user resumed the process).
	if inc := e.incidents[oa.ProcessID]; !instant && inc != nil && time.Since(inc.last) < window &&
		(inc.createTime == 0 || inc.createTime == e.Ops.CreateTime(oa.ProcessID)) {
		inc.last = time.Now()
		a := inc.alert
		dup := false
		for _, h := range a.Baits {
			dup = dup || (strings.EqualFold(h.Path, hit.Path) && h.Access == hit.Access)
		}
		if !dup {
			a.Baits = append(a.Baits, hit)
			e.mu.Unlock()
			e.Ops.SaveAlert(a)
			return
		}
		e.mu.Unlock()
		return
	}
	e.mu.Unlock()

	now := time.Now()
	image := oa.ProcessName
	if image == "" || !strings.Contains(image, `\`) {
		if p, err := e.Ops.ImagePath(oa.ProcessID); err == nil {
			image = p
		}
	}
	test := false
	if tr := e.Ops.PendingTest(); tr != nil && tr.PID == oa.ProcessID {
		test = true
	}
	if !test && e.Ops.IsSelf(image) {
		return // SENTIENT1's own binary (doctor, bait adoption…), recognised by its hash
	}
	createTime := e.Ops.CreateTime(oa.ProcessID)
	ref := baitRef(baitID)
	learning := cfg.Learning(now) && !test
	actionsFor := func(t config.Tier) []config.Action {
		if test {
			return []config.Action{config.ActionFreeze} // a test never cuts the network
		}
		if access == "delete" {
			return nil // deleting isn't exfiltration; notify + auto-repair instead
		}
		return cfg.ActionsFor(t, now)
	}

	isSweep := len(swept) >= sweepApps

	// 1-2. Instant verdict, freeze first.
	pre := cls.Prelim(image, oa.ProcessID, ref)
	if isSweep && !cls.SweepExempt(image, oa.ProcessID, nil) {
		pre = e.sweepVerdict(pre, swept)
	}
	if pre.Ignored && !instant {
		e.Ops.Logf("ignored %s of %s by %s (%s)", access, oa.ObjectName, image, strings.Join(pre.Reasons, "; "))
		return
	}
	frozen := preFrozen
	var latency time.Duration
	canTouch := e.touchable(oa.ProcessID, image)
	if instant {
		latency = time.Since(oa.Time)
	} else if canTouch && config.Has(actionsFor(pre.Tier), config.ActionFreeze) {
		if !tryFreeze() {
			if claimedNow() {
				return // the instant path froze it and reports it
			}
		} else {
			frozen, _ = e.Ops.SuspendTree(oa.ProcessID)
			latency = time.Since(oa.Time)
		}
	}

	// 3-4. Signature and final verdict.
	sig := authenticode.Result{}
	if image != "" {
		sig = e.Ops.Verify(image)
	}
	v := cls.Final(image, oa.ProcessID, ref, sig)
	if isSweep && !cls.SweepExempt(image, oa.ProcessID, &sig) {
		v = e.sweepVerdict(v, swept)
	}
	// A Windows program reading app data is how injected stealers look: check
	// whether it's running code that isn't from any file on disk. (Trust rules
	// don't skip this; Defender and Windows Search do.)
	if !test && !v.Builtin && !v.DecoyOwner && v.Tier != config.TierCritical && access == "read" &&
		cls.WindowsBinary(image) && e.Ops.UserSession(oa.ProcessID) && !e.Ops.Elevated(oa.ProcessID) {
		if detail, found := e.Ops.InjectedCode(oa.ProcessID); found {
			v = classify.Verdict{Tier: config.TierCritical,
				Reasons: append([]string{filepath.Base(image) + " is part of Windows, but " + detail}, v.Reasons...)}
		}
	}
	if v.Ignored {
		e.Ops.Resume(frozen)
		e.Ops.Logf("ignored %s of %s by %s (%s)", access, oa.ObjectName, image, strings.Join(v.Reasons, "; "))
		return
	}
	acts := actionsFor(v.Tier)
	if v.DecoyOwner {
		acts = nil
	}
	if len(frozen) > 0 && !config.Has(acts, config.ActionFreeze) {
		e.Ops.Resume(frozen)
		frozen = nil
	} else if len(frozen) == 0 && canTouch && config.Has(acts, config.ActionFreeze) {
		if instant || tryFreeze() {
			frozen, _ = e.Ops.SuspendTree(oa.ProcessID)
			latency = time.Since(oa.Time)
		} else if claimedNow() {
			return // the instant path froze it and reports it
		}
	}

	a := &alerts.Alert{
		ID: alerts.NewID(now), Time: now, Kind: alerts.KindRead, Tier: v.Tier, Verdict: v,
		Learning: learning && v.Tier != config.TierCritical && len(cfg.Responses[v.Tier]) > 0, Test: test, Status: "open",
		Baits:   []alerts.BaitHit{hit},
		Process: &alerts.Process{PID: oa.ProcessID, Image: image, User: oa.User, Signature: sig, CreateTime: createTime},
	}
	a.Instant = instant && len(frozen) > 0
	if access == "delete" {
		a.Kind = alerts.KindDelete
	}
	if test {
		a.Kind = alerts.KindTest
	}
	if config.Has(acts, config.ActionFreeze) {
		if len(frozen) > 0 {
			detail := fmt.Sprintf("%d process(es) frozen", len(frozen))
			if instant {
				detail += " the moment it opened the bait"
			}
			a.AddAction(config.ActionFreeze, nil, detail)
		} else if !canTouch {
			a.AddAction(config.ActionFreeze, fmt.Errorf("refused"), "protected system process")
		} else {
			a.AddAction(config.ActionFreeze, fmt.Errorf("could not suspend"), "")
		}
	}
	if latency > 0 {
		a.LatencyMS = latency.Milliseconds()
	}
	a.DeliveryMS = received.Sub(oa.Time).Milliseconds()

	// 5. Forensics while frozen.
	e.Ops.Forensics(oa.ProcessID, a.Process)
	a.SetReaderName()

	// 6. Remaining responses.
	var blocked, isolated bool
	var adapters []string
	for _, act := range acts {
		switch act {
		case config.ActionBlockProgram:
			if image == "" {
				a.AddAction(act, fmt.Errorf("unknown executable"), "")
				continue
			}
			err := e.Ops.BlockProgram(image)
			a.AddAction(act, err, image)
			blocked = err == nil
		case config.ActionKill:
			if !canTouch {
				a.AddAction(act, fmt.Errorf("refused"), "protected system process")
				continue
			}
			err := e.Ops.KillTree(oa.ProcessID)
			a.AddAction(act, err, "")
			if err == nil {
				frozen = nil
			}
		case config.ActionIsolate:
			err := e.Ops.Isolate()
			a.AddAction(act, err, "")
			isolated = err == nil
		case config.ActionDisableAdapters:
			names, err := e.Ops.DisableAdapters()
			a.AddAction(act, err, strings.Join(names, ", "))
			adapters = names
		}
	}

	e.describe(a, v)
	if v.DecoyOwner {
		a.Kind = alerts.KindDecoyRetired
	}

	e.Ops.UpdateState(func(st *config.State) error {
		for _, p := range frozen {
			ct := e.Ops.CreateTime(p)
			img, _ := e.Ops.ImagePath(p)
			st.Frozen = append(st.Frozen, config.FrozenProcess{PID: p, CreateTime: ct, Image: img, AlertID: a.ID, Since: now})
		}
		if blocked && !st.IsBlocked(image) {
			st.Blocked = append(st.Blocked, config.BlockedProgram{Path: image, AlertID: a.ID, Since: now})
		}
		if isolated && st.Isolation == nil {
			st.Isolation = &config.Isolation{Since: now, AlertID: a.ID, Method: "wfp"}
		}
		if len(adapters) > 0 {
			st.DisabledAdapters = appendUnique(st.DisabledAdapters, adapters...)
			if st.Isolation == nil {
				st.Isolation = &config.Isolation{Since: now, AlertID: a.ID, Method: "adapters"}
			}
		}
		return nil
	})
	if err := e.Ops.SaveAlert(a); err != nil {
		e.Ops.Logf("save alert: %v", err)
	}

	e.mu.Lock()
	e.incidents[oa.ProcessID] = &incident{alert: a, createTime: createTime, last: time.Now()}
	for pid, inc := range e.incidents {
		if time.Since(inc.last) > window {
			delete(e.incidents, pid)
		}
	}
	e.mu.Unlock()

	// Script hosts and runtimes are never quieted: the next script could be a
	// different one. Neither are critical alerts.
	if !test && len(a.Actions) == 0 && !v.DecoyOwner && v.Tier != config.TierCritical &&
		!classify.ScriptHost(image) && !procinfo.SharedHost(image) && e.repeat(image, baitID, now) {
		// Same program, same bait, nothing done about it: it's in the history,
		// but don't pop up on every launch of an app you haven't marked yet.
		e.Ops.Logf("alert %s: repeat of %s reading %s, not notified again", a.ID, image, baitID)
		return
	}
	e.Ops.NotifyDesktop(a)
	if test || v.Tier.Rank() >= cfg.PhoneMinTier.Rank() {
		e.Ops.NotifyPhone(a)
	}
	if v.DecoyOwner {
		e.Ops.RetireDecoy(baitID, a.Summary)
	}
	if test {
		e.Ops.KillTree(oa.ProcessID)
		e.Ops.ClearTest()
		// The test reader is gone: don't leave it on the frozen list.
		e.Ops.UpdateState(func(st *config.State) error {
			var keep []config.FrozenProcess
			for _, f := range st.Frozen {
				if f.AlertID != a.ID {
					keep = append(keep, f)
				}
			}
			st.Frozen = keep
			return nil
		})
	}
	e.Ops.Logf("alert %s: %s [%s] actions=%d latency=%dms (delivery %dms)", a.ID, a.Title, a.Tier, len(a.Actions), a.LatencyMS, a.DeliveryMS)
}

// filesUnit stands for all the plain-file baits together (passwords.txt on
// the Desktop, in Documents…).
const filesUnit = "files"

// sweepUnit is what a bait counts as in a sweep. Plain files in your folders
// all count as one: OneDrive, a backup or zipping up Documents legitimately
// reads them all. Each app's data (a browser, Discord, a wallet) counts on its
// own: nothing but a backup of AppData or a stealer goes through those.
func sweepUnit(baitID string) string {
	if s, ok := baits.ByID(baitID); ok && s.Kind == baits.KindFile {
		return filesUnit
	}
	return baitID
}

// touch records that pid opened baitID and returns every sweep unit (see
// sweepUnit) it opened within the window, this one included.
func (e *Engine) touch(pid uint32, baitID string, now time.Time) []string {
	ct := e.Ops.CreateTime(pid)
	e.mu.Lock()
	defer e.mu.Unlock()
	for p, sw := range e.touched {
		fresh := false
		for _, t := range sw.baits {
			fresh = fresh || now.Sub(t) < window
		}
		if !fresh {
			delete(e.touched, p)
		}
	}
	sw := e.touched[pid]
	// A different process that reuses the PID starts afresh. (ct is 0 once the
	// process has exited: its late audit events still count.)
	if sw == nil || (ct != 0 && sw.createTime != 0 && sw.createTime != ct) {
		sw = &sweep{createTime: ct, baits: map[string]time.Time{}}
		e.touched[pid] = sw
	}
	if sw.createTime == 0 {
		sw.createTime = ct
	}
	sw.baits[sweepUnit(baitID)] = now
	var ids []string
	for id, t := range sw.baits {
		if now.Sub(t) < window {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// SweepSuspect returns which of pids (programs paused inside an open of path)
// would complete a sweep by opening it: the one that already read two other
// apps' data within the window. Instant freeze normally identifies the opener
// by letting the open go through and seeing who wakes, so a quick sweeper got
// the third app's data (and could even exit) before it was frozen. With a
// suspect known, it's decided while the open is still paused. 0 if none, or
// more than one.
func (e *Engine) SweepSuspect(path string, pids []uint32) uint32 {
	now := time.Now()
	e.mu.Lock()
	baitID, ok := e.index[paths.Key(path)]
	if !ok {
		e.mu.Unlock()
		return 0
	}
	unit := sweepUnit(baitID)
	var hit uint32
	var hitCT int64
	n := 0
	for _, pid := range pids {
		sw := e.touched[pid]
		if pid == e.SelfPID || sw == nil {
			continue
		}
		others := 0
		for u, t := range sw.baits {
			if u != unit && now.Sub(t) < window {
				others++
			}
		}
		if others+1 >= sweepApps {
			hit, hitCT = pid, sw.createTime
			n++
		}
	}
	e.mu.Unlock()
	if n != 1 {
		return 0
	}
	if ct := e.Ops.CreateTime(hit); ct != 0 && hitCT != 0 && ct != hitCT {
		return 0 // the PID was reused by another process
	}
	return hit
}

// sweepable: a sweep only counts for ordinary programs in a user session.
// Services and admin tools (backup, antivirus) are out of reach of a
// user-level stealer, and `sentient1 test` is a test.
func (e *Engine) sweepable(pid uint32) bool {
	if tr := e.Ops.PendingTest(); tr != nil && tr.PID == pid {
		return false
	}
	if !e.userSession(pid) {
		return false
	}
	// Once it has exited its elevation can't be checked; it's judged by what it read.
	return e.Ops.CreateTime(pid) == 0 || !e.Ops.Elevated(pid)
}

// userSession reports whether pid is an ordinary user's program rather than
// a Windows service. While it runs, its session says so. A fast reader (or a
// stealer that grabs everything and quits) may be gone by the time the audit
// event arrives; then the account it read as, from that event, says so.
func (e *Engine) userSession(pid uint32) bool {
	if e.Ops.UserSession(pid) {
		return true
	}
	if e.Ops.CreateTime(pid) != 0 {
		return false // running, in session 0
	}
	e.mu.Lock()
	sid := e.sids[pid]
	e.mu.Unlock()
	return sid != "" && !serviceAccount(sid)
}

// serviceAccount: SYSTEM, LOCAL/NETWORK SERVICE and per-service accounts.
func serviceAccount(sid string) bool {
	switch sid {
	case "S-1-5-18", "S-1-5-19", "S-1-5-20":
		return true
	}
	for _, p := range []string{"S-1-5-80-", "S-1-5-82-", "S-1-5-90-", "S-1-5-96-"} {
		if strings.HasPrefix(sid, p) {
			return true
		}
	}
	return false
}

// sweepVerdict turns a verdict into a critical one: the reader went through
// several apps' data.
func (e *Engine) sweepVerdict(v classify.Verdict, swept []string) classify.Verdict {
	e.mu.Lock()
	var names []string
	for _, id := range swept {
		n := e.baitNames[id]
		switch {
		case id == filesUnit:
			n = "your password/recovery files"
		case n == "":
			n = id
		}
		names = append(names, n)
	}
	e.mu.Unlock()
	why := fmt.Sprintf("it read the data of %d different apps within %d minutes (%s): stealers sweep everything, real apps only touch their own",
		len(swept), int(window.Minutes()), strings.Join(names, ", "))
	return classify.Verdict{Tier: config.TierCritical, Swept: swept, Reasons: append([]string{why}, v.Reasons...)}
}

// repeatWindow is how long a no-action alert for the same program and bait
// stays quiet after its first notification.
const repeatWindow = 12 * time.Hour

func (e *Engine) repeat(image, baitID string, now time.Time) bool {
	key := strings.ToLower(image) + "|" + baitID
	e.mu.Lock()
	defer e.mu.Unlock()
	if last, ok := e.seen[key]; ok && now.Sub(last) < repeatWindow {
		return true
	}
	e.seen[key] = now
	return false
}

func (e *Engine) describe(a *alerts.Alert, v classify.Verdict) {
	exe := a.ReaderName()
	what := "read"
	if a.Kind == alerts.KindDelete {
		what = "deleted"
	}
	if a.Instant {
		what = "opened"
	}
	switch {
	case a.Test && a.Instant:
		a.Title = "Test detection: " + exe + " was frozen the moment it opened a bait"
	case a.Test:
		a.Title = "Test detection: " + exe + " read a bait"
	case v.DecoyOwner:
		a.Title = exe + " is installed: retiring its decoy"
	case v.Tier == config.TierCritical:
		a.Title = "Possible stealer: " + exe + " " + what + " your bait"
	case v.Tier == config.TierWarn:
		a.Title = exe + " " + what + " a bait"
	default:
		a.Title = exe + " " + what + " a bait (looks legitimate)"
	}
	if len(v.Reasons) > 0 {
		a.Summary = v.Reasons[0]
	}
	if a.Instant {
		a.Summary = "Caught the moment it opened the bait (instant freeze). " + a.Summary
	}
}

func appendUnique(xs []string, add ...string) []string {
	for _, a := range add {
		found := false
		for _, x := range xs {
			found = found || strings.EqualFold(x, a)
		}
		if !found {
			xs = append(xs, a)
		}
	}
	return xs
}

// SystemAlert raises an alert not tied to a reader (tamper, missing bait, retirement).
func (e *Engine) SystemAlert(kind string, tier config.Tier, title, summary string, hits []alerts.BaitHit) *alerts.Alert {
	now := time.Now()
	a := &alerts.Alert{ID: alerts.NewID(now), Time: now, Kind: kind, Tier: tier, Title: title, Summary: summary,
		Baits: hits, Status: "open", Verdict: classify.Verdict{Tier: tier, Reasons: []string{summary}}}
	e.Ops.SaveAlert(a)
	e.Ops.NotifyDesktop(a)
	e.mu.Lock()
	min := config.TierWarn
	if e.cfg != nil {
		min = e.cfg.PhoneMinTier
	}
	e.mu.Unlock()
	if tier.Rank() >= min.Rank() {
		e.Ops.NotifyPhone(a)
	}
	return a
}

// ProcessDetails is the default Forensics implementation.
func ProcessDetails(pid uint32, p *alerts.Process) {
	if p.CreateTime == 0 {
		p.CreateTime, _ = procinfo.CreateTime(pid)
	}
	if p.CreateTime == 0 || !procinfo.Alive(pid, p.CreateTime) {
		p.Exited = true
		p.Hosted = procinfo.ResolveHosted(0, p.Image, p.CommandLine, 0)
		return
	}
	p.CommandLine, _ = procinfo.CommandLine(pid)
	p.Hosted = procinfo.ResolveHosted(pid, p.Image, p.CommandLine, p.CreateTime)
	if snap, err := procinfo.Snapshot(); err == nil {
		p.Parents = procinfo.ParentChain(snap, pid, 4)
		p.TreePIDs = procinfo.Tree(snap, pid)
	}
	pids := p.TreePIDs
	if len(pids) == 0 {
		pids = []uint32{pid}
	}
	p.Connections, _ = procinfo.Connections(pids)
	if p.Image != "" {
		p.SHA256, _ = procinfo.FileSHA256(p.Image)
	}
	if !procinfo.Alive(pid, p.CreateTime) {
		p.Exited = true
		p.CommandLine, p.Parents, p.TreePIDs, p.Connections = "", nil, nil, nil
		p.Hosted = procinfo.ResolveHosted(0, p.Image, "", 0)
	}
}
