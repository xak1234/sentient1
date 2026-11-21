package engine

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xak1234/sentient1/internal/alerts"
	"github.com/xak1234/sentient1/internal/authenticode"
	"github.com/xak1234/sentient1/internal/config"
	"github.com/xak1234/sentient1/internal/evtlog"
)

type fakeOps struct {
	mu        sync.Mutex
	sigs      map[string]authenticode.Result
	suspended []uint32
	resumed   []uint32
	killed    []uint32
	blocked   []string
	isolated  int
	saved     map[string]*alerts.Alert
	desktop   []string
	phone     []string
	retired   []string
	state     *config.State
	test      *TestRequest
	images    map[uint32]string
	hashes    map[string]string
	cmdlines  map[uint32]string
	injected  map[uint32]string
	elevated  map[uint32]bool
	gone      map[uint32]bool // exited: no session, no create time
	slowSig   time.Duration   // Verify takes this long (signature checks can be slow)
}

func newFake() *fakeOps {
	return &fakeOps{images: map[uint32]string{}, sigs: map[string]authenticode.Result{}, saved: map[string]*alerts.Alert{}, state: config.NewState(),
		hashes: map[string]string{}, cmdlines: map[uint32]string{}, injected: map[uint32]string{}, elevated: map[uint32]bool{}, gone: map[uint32]bool{}}
}

func (f *fakeOps) ImagePath(pid uint32) (string, error) {
	if img, ok := f.images[pid]; ok {
		return img, nil
	}
	return "", fmt.Errorf("n/a")
}
func (f *fakeOps) CreateTime(pid uint32) int64 {
	if f.gone[pid] {
		return 0
	}
	return 1
}
func (f *fakeOps) Verify(p string) authenticode.Result {
	time.Sleep(f.slowSig)
	return f.sigs[p]
}
func (f *fakeOps) SuspendTree(pid uint32) ([]uint32, error) {
	f.suspended = append(f.suspended, pid)
	return []uint32{pid, pid + 1}, nil
}
func (f *fakeOps) Resume(p []uint32)                      { f.resumed = append(f.resumed, p...) }
func (f *fakeOps) KillTree(pid uint32) error              { f.killed = append(f.killed, pid); return nil }
func (f *fakeOps) Forensics(uint32, *alerts.Process)      {}
func (f *fakeOps) BlockProgram(p string) error            { f.blocked = append(f.blocked, p); return nil }
func (f *fakeOps) Isolate() error                         { f.isolated++; return nil }
func (f *fakeOps) DisableAdapters() ([]string, error)     { return []string{"Wi-Fi"}, nil }
func (f *fakeOps) SaveAlert(a *alerts.Alert) error        { f.saved[a.ID] = a; return nil }
func (f *fakeOps) NotifyDesktop(a *alerts.Alert)          { f.desktop = append(f.desktop, a.ID) }
func (f *fakeOps) NotifyPhone(a *alerts.Alert)            { f.phone = append(f.phone, a.ID) }
func (f *fakeOps) RetireDecoy(id, why string)             { f.retired = append(f.retired, id) }
func (f *fakeOps) PendingTest() *TestRequest              { return f.test }
func (f *fakeOps) ClearTest()                             { f.test = nil }
func (f *fakeOps) UserSession(pid uint32) bool            { return !f.gone[pid] }
func (f *fakeOps) Elevated(pid uint32) bool               { return pid == 777 || f.elevated[pid] }
func (f *fakeOps) Hash(img string) string                 { return f.hashes[img] }
func (f *fakeOps) CommandLine(pid uint32) string          { return f.cmdlines[pid] }
func (f *fakeOps) InjectedCode(pid uint32) (string, bool) { d, ok := f.injected[pid]; return d, ok }
func (f *fakeOps) IsSelf(img string) bool {
	return strings.HasSuffix(strings.ToLower(img), `\sentient1.exe`)
}
func (f *fakeOps) Logf(string, ...any)                            {}
func (f *fakeOps) UpdateState(fn func(*config.State) error) error { return fn(f.state) }

const desktopBait = `C:\Users\bob\Desktop\passwords.txt`

const (
	discordBait  = `C:\Users\bob\AppData\Roaming\discord\Local Storage\leveldb\000005.ldb`
	awsBait      = `C:\Users\bob\.aws\credentials`
	chromeBait   = `C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Login Data`
	metamaskBait = `C:\Users\bob\AppData\Local\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn\000003.log`
)

func setup(preset string) (*Engine, *fakeOps) {
	f := newFake()
	e := New(f, 999)
	cfg := config.Default()
	cfg.InstantFreeze = true // existing instant-path tests opt in explicitly
	cfg.ApplyPreset(preset)
	st := config.NewState()
	st.Baits["desktop-passwords"] = &config.BaitState{ID: "desktop-passwords", Name: "passwords.txt on the Desktop",
		Files: []config.BaitFile{{Path: desktopBait, Audit: true}}}
	st.Baits["discord"] = &config.BaitState{ID: "discord", Name: "Discord token store",
		Files: []config.BaitFile{{Path: `C:\Users\bob\AppData\Roaming\discord\Local Storage\leveldb\000005.ldb`, Audit: true}}}
	for id, path := range map[string]string{"aws": awsBait, "chrome": chromeBait, "metamask": metamaskBait} {
		st.Baits[id] = &config.BaitState{ID: id, Name: id + " data", Files: []config.BaitFile{{Path: path, Audit: true}}}
	}
	e.Configure(cfg, st)
	return e, f
}

func ev(pid uint32, image, obj string, mask uint32) *evtlog.ObjectAccess {
	return &evtlog.ObjectAccess{ProcessID: pid, ProcessName: image, ObjectName: obj, AccessMask: mask, Time: time.Now()}
}

func only(f *fakeOps) *alerts.Alert {
	for _, a := range f.saved {
		return a
	}
	return nil
}

func TestStealerIsFrozenAndBlocked(t *testing.T) {
	e, f := setup("balanced")
	img := `C:\Users\bob\AppData\Local\Temp\x\stealer.exe`
	e.HandleAccess(ev(100, img, desktopBait, 1))
	a := only(f)
	if a == nil || a.Tier != config.TierCritical || !a.Did(config.ActionFreeze) || !a.Did(config.ActionBlockProgram) {
		t.Fatalf("alert: %+v", a)
	}
	if len(f.resumed) != 0 || len(f.blocked) != 1 || f.isolated != 0 {
		t.Fatalf("ops: resumed=%v blocked=%v isolated=%d", f.resumed, f.blocked, f.isolated)
	}
	if len(f.state.Frozen) != 2 || len(f.state.Blocked) != 1 || len(f.phone) != 1 || len(f.desktop) != 1 {
		t.Fatalf("state/notify: %+v phone=%v", f.state, f.phone)
	}
	// The same stealer reading a second bait joins the same alert, no new responses.
	e.HandleAccess(ev(100, img, `C:\Users\bob\AppData\Roaming\discord\Local Storage\leveldb\000005.ldb`, 1))
	if len(f.saved) != 1 || len(a.Baits) != 2 || len(f.suspended) != 1 || len(f.desktop) != 1 {
		t.Fatalf("aggregation failed: alerts=%d baits=%d suspends=%d", len(f.saved), len(a.Baits), len(f.suspended))
	}
}

func TestSignedUserFolderAppIsUnfrozen(t *testing.T) {
	e, f := setup("balanced")
	img := `C:\Users\bob\AppData\Local\Programs\Microsoft VS Code\Code.exe`
	f.sigs[img] = authenticode.Result{Signed: true, Valid: true, Signer: "Microsoft Corporation"}
	e.HandleAccess(ev(200, img, desktopBait, 1))
	a := only(f)
	if a.Tier != config.TierWarn || len(f.suspended) != 1 || len(f.resumed) != 2 || len(f.state.Frozen) != 0 || len(f.blocked) != 0 {
		t.Fatalf("tier=%s suspended=%v resumed=%v frozen=%v blocked=%v", a.Tier, f.suspended, f.resumed, f.state.Frozen, f.blocked)
	}
}

func TestStrictIsolates(t *testing.T) {
	e, f := setup("strict")
	e.HandleAccess(ev(300, `C:\Users\bob\Downloads\crack.exe`, desktopBait, 1))
	if f.isolated != 1 || only(f).Tier != config.TierCritical || f.state.Isolation == nil {
		t.Fatalf("isolated=%d state=%+v", f.isolated, f.state.Isolation)
	}
}

func TestLearningModeStillStopsCritical(t *testing.T) {
	e, f := setup("strict")
	e.cfg.LearningUntil = time.Now().Add(time.Hour)
	e.HandleAccess(ev(300, `C:\Users\bob\Downloads\crack.exe`, desktopBait, 1))
	a := only(f)
	if len(f.suspended) == 0 || f.isolated != 1 || a.Learning {
		t.Fatalf("critical reader must be stopped even while learning: %+v", a)
	}
}

func TestLearningModeHoldsBackWarn(t *testing.T) {
	e, f := setup("strict") // strict freezes warn-tier readers
	e.cfg.LearningUntil = time.Now().Add(time.Hour)
	img := `C:\Users\bob\AppData\Local\Programs\SyncTool\sync.exe`
	f.sigs[img] = authenticode.Result{Signed: true, Valid: true, Signer: "Sync Corp"}
	e.HandleAccess(ev(300, img, desktopBait, 1))
	a := only(f)
	if a.Tier != config.TierWarn || len(f.state.Frozen) != 0 || len(a.Actions) != 0 || !a.Learning {
		t.Fatalf("learning mode should only alert on warn: %+v", a)
	}
	if len(f.desktop) != 1 {
		t.Fatal("learning alerts must still reach the desktop (one-click trust)")
	}
}

func TestSignedSDKReadOfAWSIsNotAnAlert(t *testing.T) {
	e, f := setup("balanced")
	aws := `C:\Users\bob\.aws\credentials`
	st := config.NewState()
	st.Baits["aws"] = &config.BaitState{ID: "aws", Name: "AWS credentials", Files: []config.BaitFile{{Path: aws, Audit: true}}}
	e.Configure(e.cfg, st)
	oc := `C:\Users\bob\AppData\Roaming\npm\node_modules\@opencode\cli\bin\opencode.exe`
	f.sigs[oc] = authenticode.Result{Signed: true, Valid: true, Signer: "Anomaly Innovations, Inc"}
	e.HandleAccess(ev(400, oc, aws, 1))
	if len(f.saved) != 0 {
		t.Fatalf("signed SDK user reading ~/.aws must not alert: %+v", only(f))
	}
	e.HandleAccess(ev(401, `C:\Users\bob\AppData\Local\Temp\x\stealer.exe`, aws, 1))
	if a := only(f); a == nil || a.Tier != config.TierCritical {
		t.Fatalf("unsigned reader of ~/.aws must still be critical: %+v", a)
	}
}

func TestRepeatAlertsDontPopUpAgain(t *testing.T) {
	e, f := setup("balanced") // warn = alert only
	img := `C:\Users\bob\AppData\Local\Programs\Tool\tool.exe`
	f.sigs[img] = authenticode.Result{Signed: true, Valid: true, Signer: "Tool Inc"}
	e.HandleAccess(ev(500, img, desktopBait, 1))
	e.HandleAccess(ev(501, img, desktopBait, 1))
	if len(f.saved) != 2 || len(f.desktop) != 1 {
		t.Fatalf("want 2 alerts saved, 1 notified; got %d saved, %d notified", len(f.saved), len(f.desktop))
	}
	e.HandleAccess(ev(502, `C:\Users\bob\AppData\Local\Temp\x\stealer.exe`, desktopBait, 1))
	if len(f.desktop) != 2 {
		t.Fatal("a different program must still notify")
	}
}

func TestIgnoredAndUnrelatedEvents(t *testing.T) {
	e, f := setup("strict")
	e.HandleAccess(ev(1, `C:\Users\bob\Downloads\x.exe`, `C:\not\a\bait.txt`, 1))
	e.HandleAccess(ev(999, `C:\Program Files\sentient1 Monitor\sentient1svc.exe`, desktopBait, 1)) // ourselves
	def := `C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.1-0\MsMpEng.exe`
	f.sigs[def] = authenticode.Result{Signed: true, Valid: true, Signer: "Microsoft Corporation"}
	e.HandleAccess(ev(5, def, desktopBait, 1))
	if len(f.saved) != 0 || len(f.suspended) != 0 {
		t.Fatalf("should be silent: alerts=%d suspended=%v", len(f.saved), f.suspended)
	}
}

func TestDecoyOwnerRetires(t *testing.T) {
	e, f := setup("strict")
	img := `C:\Users\bob\AppData\Local\Discord\app-1.0.9172\Discord.exe`
	f.sigs[img] = authenticode.Result{Signed: true, Valid: true, Signer: "Discord Inc."}
	e.HandleAccess(ev(400, img, `C:\Users\bob\AppData\Roaming\discord\Local Storage\leveldb\000005.ldb`, 1))
	a := only(f)
	if a.Kind != alerts.KindDecoyRetired || len(f.retired) != 1 || len(f.state.Frozen) != 0 || f.isolated != 0 {
		t.Fatalf("alert=%+v retired=%v frozen=%v", a, f.retired, f.state.Frozen)
	}
}

func TestTestModeNeverCutsNetwork(t *testing.T) {
	e, f := setup("strict")
	f.test = &TestRequest{PID: 500}
	e.HandleAccess(ev(500, `C:\Users\bob\AppData\Local\Temp\sentient1-test-reader.exe`, desktopBait, 1))
	a := only(f)
	if !a.Test || f.isolated != 0 || len(f.blocked) != 0 || !a.Did(config.ActionFreeze) || len(f.killed) != 1 || f.test != nil {
		t.Fatalf("test alert=%+v isolated=%d blocked=%v killed=%v", a, f.isolated, f.blocked, f.killed)
	}
}

func TestDeleteOnlyNotifies(t *testing.T) {
	e, f := setup("strict")
	e.HandleAccess(ev(600, `C:\Users\bob\Downloads\x.exe`, desktopBait, 0x10000))
	a := only(f)
	if a.Kind != alerts.KindDelete || len(a.Actions) != 0 || len(f.suspended) != 0 {
		t.Fatalf("delete: %+v suspended=%v", a, f.suspended)
	}
}

func TestProtectedProcessesNeverFrozen(t *testing.T) {
	e, f := setup("strict")
	// explorer.exe unsigned (prelim) would be "warn" -> strict freezes warn; must refuse.
	e.HandleAccess(ev(700, `C:\Windows\explorer.exe`, desktopBait, 1))
	if len(f.suspended) != 0 {
		t.Fatalf("froze explorer: %v", f.suspended)
	}
}

func TestInstantFreezeDecisions(t *testing.T) {
	e, f := setup("balanced")
	e.cfg.InstantFreeze = true
	stealer := `C:\Users\bob\AppData\Local\Temp\x\stealer.exe`
	code := `C:\Users\bob\AppData\Local\Programs\Microsoft VS Code\Code.exe`
	f.images[100] = stealer
	f.images[200] = code
	f.images[300] = `C:\Windows\explorer.exe`
	f.sigs[code] = authenticode.Result{Signed: true, Valid: true, Signer: "Microsoft Corporation"}

	if !e.DecideInstant(100, desktopBait) {
		t.Error("unsigned program in Temp should be frozen mid-open")
	}
	if e.DecideInstant(200, desktopBait) {
		t.Error("signed app should be let through (warn = notify only on balanced)")
	}
	if e.DecideInstant(300, desktopBait) {
		t.Error("explorer must never be frozen")
	}
	if e.DecideInstant(100, `C:\not\a\bait.txt`) {
		t.Error("only baits")
	}
	if e.DecideInstant(999, desktopBait) {
		t.Error("never ourselves")
	}
	e.cfg.LearningUntil = time.Now().Add(time.Hour)
	f.images[101] = stealer
	if !e.DecideInstant(101, desktopBait) {
		t.Error("learning mode must still freeze critical readers")
	}
	e.cfg.LearningUntil = time.Time{}
	e.cfg.InstantFreeze = false
	if e.DecideInstant(100, desktopBait) {
		t.Error("instant freeze switched off")
	}
	f.test = &TestRequest{PID: 100}
	if !e.DecideInstant(100, desktopBait) {
		t.Error("`sentient1 test` always demonstrates the freeze")
	}
}

func TestHandleOpenUsesThePreFreeze(t *testing.T) {
	e, f := setup("balanced")
	f.images[100] = `C:\Users\bob\AppData\Local\Temp\x\stealer.exe`
	e.HandleOpen(100, desktopBait, time.Now().Add(-70*time.Millisecond), []uint32{100})
	a := only(f)
	if a == nil || !a.Instant || a.Tier != config.TierCritical || !a.Did(config.ActionFreeze) || !a.Did(config.ActionBlockProgram) {
		t.Fatalf("alert: %+v", a)
	}
	if len(f.suspended) != 0 {
		t.Fatalf("already frozen mid-open; must not suspend again (suspend counts stack): %v", f.suspended)
	}
	if len(f.state.Frozen) != 1 || f.state.Frozen[0].PID != 100 {
		t.Fatalf("state should record the pre-frozen pid: %+v", f.state.Frozen)
	}
	if !strings.Contains(a.Title, "opened") || !strings.Contains(a.Summary, "instant freeze") {
		t.Fatalf("title/summary: %q / %q", a.Title, a.Summary)
	}
}

func TestEventLogPathDoesNotDoubleFreezeInstantCatch(t *testing.T) {
	e, f := setup("balanced")
	img := `C:\Users\bob\AppData\Local\Temp\x\stealer.exe`
	f.images[100] = img
	if !e.DecideInstant(100, desktopBait) {
		t.Fatal("should be claimed and frozen by the instant path")
	}
	e.HandleOpen(100, desktopBait, time.Now(), []uint32{100})
	// The same read then arrives through the event log.
	e.HandleAccess(ev(100, img, desktopBait, 1))
	if len(f.suspended) != 0 || len(f.saved) != 1 {
		t.Fatalf("double handling: suspended=%v alerts=%d", f.suspended, len(f.saved))
	}
	// A failed instant freeze must hand the process back to the normal path.
	f.images[101] = img
	e.DecideInstant(101, desktopBait)
	e.Unclaim(101)
	e.HandleAccess(ev(101, img, desktopBait, 1))
	if len(f.suspended) != 1 {
		t.Fatalf("unclaimed process should be frozen by the normal path: %v", f.suspended)
	}
}

func TestInstantSkipsSelfAndElevated(t *testing.T) {
	e, f := setup("balanced")
	f.images[100] = `D:\a\build\dist\sentient1.exe` // SENTIENT1's own CLI run from a build folder (CI hang)
	f.images[777] = `C:\Users\bob\Downloads\admin-tool.exe`
	if e.DecideInstant(100, desktopBait) {
		t.Error("SENTIENT1 must never instant-freeze itself (e.g. `sentient1 doctor`)")
	}
	if e.DecideInstant(777, desktopBait) {
		t.Error("elevated programs are left to the event-log path")
	}
	f.test = &TestRequest{PID: 100}
	if !e.DecideInstant(100, desktopBait) {
		t.Error("`sentient1 test` reader (a copy of SENTIENT1) must still be frozen")
	}
}

func TestTestReaderLeavesFrozenList(t *testing.T) {
	e, f := setup("balanced")
	f.test = &TestRequest{PID: 500}
	e.HandleAccess(ev(500, `C:\Users\bob\AppData\Local\Temp\sentient1-test-1.exe`, desktopBait, 1))
	if len(f.killed) != 1 || len(f.state.Frozen) != 0 {
		t.Fatalf("killed=%v frozen=%+v: the killed test reader must not stay on the frozen list", f.killed, f.state.Frozen)
	}
}

// Resume a frozen process, it opens another bait within the aggregation
// window: the new instant freeze must get its own alert and state record,
// or `sentient1 release` would never know about it.
func TestInstantRefreezeIsTracked(t *testing.T) {
	e, f := setup("balanced")
	f.images[100] = `C:\Users\bob\AppData\Local\Temp\x\stealer.exe`
	e.DecideInstant(100, desktopBait)
	e.HandleOpen(100, desktopBait, time.Now(), []uint32{100})
	f.state.Frozen = nil // user resumed it (`sentient1 resume`), a while later
	e.mu.Lock()
	e.claimed[100] = time.Now().Add(-claimDedupe)
	e.mu.Unlock()
	e.DecideInstant(100, desktopBait)
	e.HandleOpen(100, `C:\Users\bob\AppData\Roaming\discord\Local Storage\leveldb\000005.ldb`, time.Now(), []uint32{100})
	if len(f.saved) != 2 || len(f.state.Frozen) != 1 {
		t.Fatalf("second freeze untracked: alerts=%d frozen=%+v", len(f.saved), f.state.Frozen)
	}
}

// lastAlert returns the most severe alert (the latest, in these tests).
func lastAlert(f *fakeOps) *alerts.Alert {
	var last *alerts.Alert
	for _, a := range f.saved {
		if last == nil || a.Tier.Rank() > last.Tier.Rank() {
			last = a
		}
	}
	return last
}

func TestSweepCatchesInjectedTrustedApp(t *testing.T) {
	e, f := setup("balanced")
	// You trusted OpenCode for ~/.aws. Code injected into it then goes after
	// Discord and Chrome: the trust doesn't cover those, and reading three
	// apps' data is a sweep, so it's stopped whatever it is.
	oc := `C:\Users\bob\AppData\Roaming\npm\node_modules\opencode-ai\bin\opencode.exe`
	f.sigs[oc] = authenticode.Result{Signed: true, Valid: true, Signer: "Anomaly Innovations, Inc."}
	e.cfg.Ignore = []config.IgnoreRule{{Path: `C:\Users\*\AppData\Roaming\npm\**\opencode.exe`, Signer: "Anomaly", Baits: []string{"aws"}}}
	e.Configure(e.cfg, stateWithAll())
	e.HandleAccess(ev(800, oc, awsBait, 1))
	if len(f.saved) != 0 {
		t.Fatal("trusted read of ~/.aws should be silent")
	}
	e.HandleAccess(ev(800, oc, discordBait, 1))
	if a := only(f); a == nil || a.Tier != config.TierWarn {
		t.Fatalf("second bait: %+v", a)
	}
	e.HandleAccess(ev(800, oc, chromeBait, 1))
	a := lastAlert(f)
	if a.Tier != config.TierCritical || len(a.Verdict.Swept) != 3 || !a.Did(config.ActionFreeze) || !a.Did(config.ActionBlockProgram) {
		t.Fatalf("sweep must be critical and stopped: %+v", a)
	}
	if !strings.Contains(a.Summary, "3 different apps") {
		t.Fatalf("summary: %s", a.Summary)
	}
}

func stateWithAll() *config.State {
	st := config.NewState()
	for id, path := range map[string]string{"desktop-passwords": desktopBait, "discord": discordBait, "aws": awsBait, "chrome": chromeBait, "metamask": metamaskBait} {
		st.Baits[id] = &config.BaitState{ID: id, Name: id + " data", Files: []config.BaitFile{{Path: path, Audit: true}}}
	}
	return st
}

func TestSweepByWindowsProgram(t *testing.T) {
	e, f := setup("balanced")
	exp := `C:\Windows\explorer.exe`
	f.sigs[exp] = authenticode.Result{Signed: true, Valid: true, Signer: "Microsoft Windows"}
	for _, b := range []string{discordBait, chromeBait, metamaskBait} {
		e.HandleAccess(ev(900, exp, b, 1))
	}
	a := lastAlert(f)
	if a.Tier != config.TierCritical || len(a.Verdict.Swept) != 3 {
		t.Fatalf("explorer sweeping baits: %+v", a)
	}
	if len(f.suspended) != 0 || len(f.blocked) != 1 {
		t.Fatalf("explorer is never frozen, but its network is cut: suspended=%v blocked=%v", f.suspended, f.blocked)
	}
}

func TestSweepNotForAdminToolsOrExemptPrograms(t *testing.T) {
	e, f := setup("balanced")
	bb := `C:\Program Files\Backblaze\bztransmit64.exe`
	f.sigs[bb] = authenticode.Result{Signed: true, Valid: true, Signer: "Backblaze, Inc."}
	e.cfg.Ignore = []config.IgnoreRule{{Path: bb, Signer: "Backblaze"}} // all baits
	e.Configure(e.cfg, stateWithAll())
	adm := `C:\Program Files\Tool\tool.exe`
	f.sigs[adm] = authenticode.Result{Signed: true, Valid: true, Signer: "Tool Inc"}
	f.elevated[1001] = true
	for _, b := range []string{discordBait, chromeBait, metamaskBait, awsBait} {
		e.HandleAccess(ev(1000, bb, b, 1))
		e.HandleAccess(ev(1001, adm, b, 1))
	}
	for _, a := range f.saved {
		if a.Tier == config.TierCritical {
			t.Fatalf("not a sweep: %+v", a)
		}
	}
	// (The backup tool may be paused for the moment its signature is checked.)
	if len(f.state.Frozen) != 0 || len(f.blocked) != 0 {
		t.Fatalf("left frozen/blocked: %v %v", f.state.Frozen, f.blocked)
	}
}

func TestInstantSweep(t *testing.T) {
	e, f := setup("balanced")
	e.cfg.InstantFreeze = true
	code := `C:\Users\bob\AppData\Local\Programs\Microsoft VS Code\Code.exe`
	f.images[200] = code
	f.sigs[code] = authenticode.Result{Signed: true, Valid: true, Signer: "Microsoft Corporation"}
	if e.DecideInstant(200, discordBait) || e.DecideInstant(200, chromeBait) {
		t.Fatal("a signed app opening one or two baits is only a warning in balanced")
	}
	if !e.DecideInstant(200, metamaskBait) {
		t.Fatal("third app's bait in a row: freeze before it reads")
	}
}

func TestSweepSuspect(t *testing.T) {
	e, f := setup("balanced")
	e.cfg.InstantFreeze = true
	find := `C:\Windows\System32\find.exe`
	f.images[300], f.images[301] = find, find
	f.sigs[find] = authenticode.Result{Signed: true, Valid: true, Signer: "Microsoft Windows"}
	if e.SweepSuspect(metamaskBait, []uint32{300}) != 0 {
		t.Fatal("nothing read yet: no suspect")
	}
	e.DecideInstant(300, discordBait)
	if e.SweepSuspect(metamaskBait, []uint32{300, 301}) != 0 {
		t.Fatal("one app's data so far: no suspect")
	}
	e.DecideInstant(300, chromeBait)
	e.DecideInstant(301, chromeBait)
	if e.SweepSuspect(discordBait, []uint32{300}) != 0 {
		t.Fatal("opening an app it already read isn't a third app")
	}
	if got := e.SweepSuspect(metamaskBait, []uint32{301, 300, 999}); got != 300 {
		t.Fatalf("the program that read two other apps is the suspect, got %d", got)
	}
	if !e.DecideInstant(300, metamaskBait) {
		t.Fatal("deciding on the suspect: freeze before it reads the third app's data")
	}
	if e.SweepSuspect(`C:\not\a\bait.txt`, []uint32{300}) != 0 {
		t.Fatal("not a bait")
	}
}

func TestInjectedWindowsProgramIsCritical(t *testing.T) {
	e, f := setup("balanced")
	np := `C:\Windows\System32\notepad.exe`
	f.sigs[np] = authenticode.Result{Signed: true, Valid: true, Signer: "Microsoft Windows"}
	e.HandleAccess(ev(1100, np, desktopBait, 1))
	if a := only(f); a.Tier != config.TierWarn {
		t.Fatalf("clean notepad opening a bait: %+v", a)
	}
	f.injected[1200] = "it's running a whole program from memory that isn't backed by any file on disk (412 KB): code was injected into it"
	e.HandleAccess(ev(1200, np, discordBait, 1))
	a := lastAlert(f)
	if a.Tier != config.TierCritical || !a.Did(config.ActionFreeze) || !strings.Contains(a.Summary, "injected") {
		t.Fatalf("injected notepad: %+v", a)
	}
	// A trust rule doesn't skip the check.
	e2, f2 := setup("balanced")
	f2.sigs[np] = f.sigs[np]
	e2.cfg.Ignore = []config.IgnoreRule{{Path: np, Signer: "Microsoft"}}
	e2.Configure(e2.cfg, stateWithAll())
	f2.injected[1300] = "injected"
	e2.HandleAccess(ev(1300, np, discordBait, 1))
	if a := only(f2); a == nil || a.Tier != config.TierCritical {
		t.Fatalf("trusted but injected: %+v", a)
	}
}

func TestScriptHostRepeatsStillNotify(t *testing.T) {
	e, f := setup("balanced")
	py := `C:\Python312\python.exe`
	f.sigs[py] = authenticode.Result{Signed: true, Valid: true, Signer: "Python Software Foundation"}
	e.HandleAccess(ev(1400, py, desktopBait, 1))
	e.HandleAccess(ev(1401, py, desktopBait, 1))
	if len(f.desktop) != 2 {
		t.Fatalf("each script run through python.exe must notify: %d", len(f.desktop))
	}
}

func TestYourFilesCountAsOneInASweep(t *testing.T) {
	e, f := setup("balanced")
	st := stateWithAll()
	docs := `C:\Users\bob\Documents\passwords.txt`
	seed := `C:\Users\bob\Documents\recovery phrase.txt`
	st.Baits["documents-passwords"] = &config.BaitState{ID: "documents-passwords", Name: "passwords.txt in Documents", Files: []config.BaitFile{{Path: docs, Audit: true}}}
	st.Baits["seed-phrase"] = &config.BaitState{ID: "seed-phrase", Name: "recovery phrase", Files: []config.BaitFile{{Path: seed, Audit: true}}}
	e.Configure(e.cfg, st)
	// OneDrive syncing Desktop and Documents reads all of those: not a sweep.
	od := `C:\Users\bob\AppData\Local\Microsoft\OneDrive\OneDrive.exe`
	f.sigs[od] = authenticode.Result{Signed: true, Valid: true, Signer: "Microsoft Corporation"}
	for _, b := range []string{desktopBait, docs, seed} {
		e.HandleAccess(ev(1500, od, b, 1))
	}
	for _, a := range f.saved {
		if a.Tier == config.TierCritical {
			t.Fatalf("syncing your documents is not a sweep: %+v", a)
		}
	}
	// Your files plus two apps' data is.
	e.HandleAccess(ev(1500, od, discordBait, 1))
	e.HandleAccess(ev(1500, od, chromeBait, 1))
	if a := lastAlert(f); a.Tier != config.TierCritical || len(a.Verdict.Swept) != 3 {
		t.Fatalf("files + 2 apps: %+v", a)
	}
}

func TestConcurrentGuardsFreezeOnce(t *testing.T) {
	e, f := setup("balanced")
	e.cfg.InstantFreeze = true
	f.images[100] = `C:\Users\bob\AppData\Local\Temp\x\stealer.exe`
	// Two baits' guards fire at the same instant and both point at pid 100.
	var wg sync.WaitGroup
	results := make(chan bool, 2)
	for _, b := range []string{desktopBait, discordBait} {
		wg.Add(1)
		go func(b string) { defer wg.Done(); results <- e.DecideInstant(100, b) }(b)
	}
	wg.Wait()
	close(results)
	n := 0
	for ok := range results {
		if ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("frozen %d times; must be exactly once (suspensions stack)", n)
	}
}

func TestSweepByProcessThatAlreadyExited(t *testing.T) {
	// A fast Windows program (or a stealer that grabs everything and quits)
	// is gone by the time the audit events arrive: no session to look up.
	// The account it read as decides: a user, not a service.
	e, f := setup("balanced")
	find := `C:\Windows\System32\find.exe`
	f.sigs[find] = authenticode.Result{Signed: true, Valid: true, Signer: "Microsoft Windows"}
	f.gone[1600] = true
	for _, b := range []string{desktopBait, discordBait, chromeBait} {
		x := ev(1600, find, b, 1)
		x.UserSID = "S-1-5-21-1111-2222-3333-1001"
		e.HandleAccess(x)
	}
	if a := lastAlert(f); a == nil || a.Tier != config.TierCritical || len(a.Verdict.Swept) != 3 || !a.Did(config.ActionBlockProgram) {
		t.Fatalf("exited sweeper: %+v", a)
	}
	// The same from a service account is not a sweep.
	e2, f2 := setup("balanced")
	f2.sigs[find] = f.sigs[find]
	f2.gone[1700] = true
	for _, b := range []string{desktopBait, discordBait, chromeBait} {
		x := ev(1700, find, b, 1)
		x.UserSID = "S-1-5-18"
		e2.HandleAccess(x)
	}
	for _, a := range f2.saved {
		if a.Tier == config.TierCritical {
			t.Fatalf("SYSTEM reader treated as a user sweep: %+v", a)
		}
	}
}

func TestInstantAndEventLogNeverBothFreeze(t *testing.T) {
	// The instant path is still checking the signature (slow) when Windows
	// has already logged the read: the event-log path must wait for that
	// decision instead of freezing the process a second time.
	e, f := setup("balanced")
	e.cfg.InstantFreeze = true
	img := `C:\Users\bob\AppData\Local\Temp\x\stealer.exe`
	f.images[100] = img
	f.slowSig = 150 * time.Millisecond
	got := make(chan bool, 1)
	go func() { got <- e.DecideInstant(100, desktopBait) }()
	time.Sleep(30 * time.Millisecond)
	e.HandleAccess(ev(100, img, desktopBait, 1))
	if !<-got {
		t.Fatal("instant path should freeze it")
	}
	if len(f.suspended) != 0 || len(f.saved) != 0 {
		t.Fatalf("event-log path froze/alerted too: suspended=%v alerts=%d", f.suspended, len(f.saved))
	}

	// The other way round: the event-log path froze it first, so a late
	// instant decision for the same process declines.
	e2, f2 := setup("balanced")
	e2.cfg.InstantFreeze = true
	f2.images[200] = img
	e2.HandleAccess(ev(200, img, desktopBait, 1))
	if len(f2.suspended) != 1 {
		t.Fatalf("event-log path should freeze: %v", f2.suspended)
	}
	if e2.DecideInstant(200, discordBait) {
		t.Fatal("instant path froze a process the event-log path already froze")
	}
}
