// Package alerts defines detections and stores them as JSON files in the data dir.
package alerts

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/xak1234/sentient1/internal/authenticode"
	"github.com/xak1234/sentient1/internal/classify"
	"github.com/xak1234/sentient1/internal/config"
	"github.com/xak1234/sentient1/internal/paths"
	"github.com/xak1234/sentient1/internal/procinfo"
)

// Kinds of alert.
const (
	KindRead          = "read"           // a bait was read
	KindDelete        = "delete"         // a bait was deleted or renamed
	KindBaitMissing   = "bait-missing"   // a bait vanished without a delete event
	KindAuditRemoved  = "audit-removed"  // a bait's audit rule was stripped
	KindAuditDisabled = "audit-disabled" // file auditing was switched off system-wide
	KindDecoyRetired  = "decoy-retired"  // the real app got installed; decoy removed
	KindTest          = "test"
)

type BaitHit struct {
	ID     string    `json:"id"`
	Name   string    `json:"name"`
	Path   string    `json:"path"`
	Access string    `json:"access"` // read | delete
	Time   time.Time `json:"time"`
}

type Process struct {
	DisplayName string               `json:"displayName,omitempty"`
	CreateTime  int64                `json:"createTime,omitempty"`
	Hosted      *procinfo.HostedInfo `json:"hosted,omitempty"`
	PID         uint32               `json:"pid"`
	Image       string               `json:"image"`
	CommandLine string               `json:"commandLine,omitempty"`
	User        string               `json:"user,omitempty"`
	SHA256      string               `json:"sha256,omitempty"`
	Signature   authenticode.Result  `json:"signature"`
	Parents     []procinfo.Parent    `json:"parents,omitempty"`
	Connections []procinfo.Conn      `json:"connections,omitempty"`
	TreePIDs    []uint32             `json:"treePids,omitempty"`
	Exited      bool                 `json:"exited,omitempty"`
}

type ActionResult struct {
	Action config.Action `json:"action"`
	OK     bool          `json:"ok"`
	Detail string        `json:"detail,omitempty"`
	Time   time.Time     `json:"time"`
}

type Alert struct {
	ID         string           `json:"id"`
	Time       time.Time        `json:"time"`
	Kind       string           `json:"kind"`
	Tier       config.Tier      `json:"tier"`
	Title      string           `json:"title"`
	Summary    string           `json:"summary,omitempty"`
	Learning   bool             `json:"learning,omitempty"`
	Test       bool             `json:"test,omitempty"`
	Baits      []BaitHit        `json:"baits,omitempty"`
	Process    *Process         `json:"process,omitempty"`
	Verdict    classify.Verdict `json:"verdict"`
	Actions    []ActionResult   `json:"actions,omitempty"`
	LatencyMS  int64            `json:"latencyMs,omitempty"`  // event logged -> first response
	DeliveryMS int64            `json:"deliveryMs,omitempty"` // event logged -> SENTIENT1 received it
	Instant    bool             `json:"instant,omitempty"`    // caught the moment it opened the bait (instant freeze), not via the event log
	Status     string           `json:"status"`               // open | resolved
	Note       string           `json:"note,omitempty"`
	Controls   *Controls        `json:"controls,omitempty"` // live UI hints; never persisted
}

// NewID returns a sortable, unique alert ID.
func NewID(t time.Time) string {
	b := make([]byte, 8)
	rand.Read(b)
	return t.Format("20060102-150405") + "-" + hex.EncodeToString(b)
}

func (a *Alert) Did(act config.Action) bool {
	for _, r := range a.Actions {
		if r.Action == act && r.OK {
			return true
		}
	}
	return false
}

func (a *Alert) AddAction(act config.Action, err error, detail string) {
	r := ActionResult{Action: act, OK: err == nil, Detail: detail, Time: time.Now()}
	if err != nil {
		r.Detail = strings.TrimSpace(detail + " " + err.Error())
	}
	a.Actions = append(a.Actions, r)
}

// ExeName is the reader's file name, or a placeholder.
func (a *Alert) ExeName() string {
	if a.Process == nil || a.Process.Image == "" {
		if a.Process != nil && a.Process.PID == 4 {
			return "System (kernel / network share)"
		}
		return "unknown process"
	}
	return procinfo.BaseName(a.Process.Image)
}

// ReaderName names the hosted component while retaining the actual executable.
func (a *Alert) ReaderName() string {
	if a.Process != nil && a.Process.Hosted != nil {
		return a.Process.Hosted.Label() + " (via " + a.ExeName() + ")"
	}
	return a.ExeName()
}

func (a *Alert) SetReaderName() {
	if a.Process != nil {
		a.Process.DisplayName = a.ReaderName()
	}
}

func file(id string) string { return filepath.Join(paths.AlertsDir(), id+".json") }

// Save writes the alert (admin only).
func Save(a *Alert) error {
	if a == nil || !ValidID(a.ID) {
		return errors.New("invalid alert ID")
	}
	if err := os.MkdirAll(paths.AlertsDir(), 0o755); err != nil {
		return err
	}
	saved := *a
	saved.Controls = nil
	b, err := json.MarshalIndent(&saved, "", "  ")
	if err != nil {
		return err
	}
	tmp := file(a.ID) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, file(a.ID))
}

// Load reads an alert by full ID or unique prefix/suffix.
func Load(id string) (*Alert, error) {
	if !ValidID(id) {
		return nil, errors.New("invalid alert ID: use a full ID or a unique alphanumeric prefix/suffix")
	}
	b, err := os.ReadFile(file(id))
	if errors.Is(err, os.ErrNotExist) {
		all, _ := ids()
		var matches []string
		for _, x := range all {
			if strings.HasPrefix(x, id) || strings.HasSuffix(x, id) {
				matches = append(matches, x)
			}
		}
		switch len(matches) {
		case 0:
			return nil, fmt.Errorf("no alert %q", id)
		case 1:
			b, err = os.ReadFile(file(matches[0]))
		default:
			return nil, fmt.Errorf("%q matches %d alerts; be more specific", id, len(matches))
		}
	}
	if err != nil {
		return nil, err
	}
	a := &Alert{}
	if err := json.Unmarshal(b, a); err != nil {
		return nil, err
	}
	if !ValidID(a.ID) {
		return nil, errors.New("alert contains an invalid ID")
	}
	if p := a.Process; p != nil && p.Hosted == nil && procinfo.SharedHost(p.Image) {
		// Historical enrichment uses the saved command line, never a live PID
		// which may since have been reused. Its provenance is explicitly marked.
		p.Hosted = procinfo.ResolveHosted(0, p.Image, p.CommandLine, 0)
	}
	a.SetReaderName()
	return a, nil
}

func ids() ([]string, error) {
	entries, err := os.ReadDir(paths.AlertsDir())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if n := e.Name(); strings.HasSuffix(n, ".json") {
			out = append(out, strings.TrimSuffix(n, ".json"))
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(out)))
	return out, nil
}

// List returns up to limit alerts, newest first (limit <= 0: all).
func List(limit int) ([]*Alert, error) {
	all, err := ids()
	if err != nil {
		return nil, err
	}
	var out []*Alert
	for _, id := range all {
		if limit > 0 && len(out) >= limit {
			break
		}
		if a, err := Load(id); err == nil {
			out = append(out, a)
		}
	}
	return out, nil
}

// Update loads, modifies and saves an alert.
func Update(id string, fn func(*Alert)) (*Alert, error) {
	a, err := Load(id)
	if err != nil {
		return nil, err
	}
	fn(a)
	return a, Save(a)
}

// Checklist is what to do after a critical detection.
func Checklist(a *Alert) []string {
	steps := []string{
		"Keep this PC offline. Don't log in to anything from it until it's cleaned.",
		"From another device (your phone), change your passwords: email first (it resets everything else), then banking, then anything saved in this PC's browsers.",
		"Log out everywhere: stolen browser cookies keep sessions alive after a password change. Use 'Sign out of all devices' for Google, Microsoft, Discord, Steam, Telegram (Settings > Devices > Terminate all), social media.",
		"Crypto: move funds to a NEW wallet created on a clean device. Treat every seed phrase this PC has ever seen as burned.",
		"Turn on 2FA with an authenticator app (not SMS) for important accounts.",
		"Run a Microsoft Defender Offline scan, then strongly consider resetting Windows: stealers often drop more malware.",
	}
	if a.Process != nil && a.Process.SHA256 != "" {
		steps = append(steps, "Look the file up on VirusTotal from another device: https://www.virustotal.com/gui/file/"+a.Process.SHA256)
	}
	return steps
}
