// Package netguard cuts network access using the Windows Filtering Platform
// (the same engine Windows Firewall and enterprise EDR "isolate device" use).
//
// Rules are persistent: they survive reboots and a stopped service, so a
// stealer can't wait out the isolation. `sentient1 release` removes them.
package netguard

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"syscall"

	"github.com/tailscale/wf"
	"github.com/xak1234/sentient1/internal/paths"
	"golang.org/x/sys/windows"
)

var (
	providerID = wf.ProviderID{Data1: 0x9e782681, Data2: 0x0962, Data3: 0x4dda, Data4: [8]byte{0x9f, 0x2a, 0x46, 0xb1, 0xd0, 0xc3, 0xe9, 0xa1}}
	sublayerID = wf.SublayerID{Data1: 0x9e782681, Data2: 0x0962, Data3: 0x4dda, Data4: [8]byte{0x9f, 0x2a, 0x46, 0xb1, 0xd0, 0xc3, 0xe9, 0xa2}}
)

var (
	connectLayers = []wf.LayerID{wf.LayerALEAuthConnectV4, wf.LayerALEAuthConnectV6}
	acceptLayers  = []wf.LayerID{wf.LayerALEAuthRecvAcceptV4, wf.LayerALEAuthRecvAcceptV6}
	allLayers     = append(append([]wf.LayerID{}, connectLayers...), acceptLayers...)
)

// Weights inside our sublayer: the highest matching rule wins.
const (
	wBlockAll     = 0
	wBlockProgram = 5
	wPermitLoop   = 10
	wPermitSelf   = 20
)

func ruleID(parts ...string) wf.RuleID {
	h := sha1.Sum([]byte("sentient1/" + strings.Join(parts, "/")))
	return wf.RuleID{
		Data1: uint32(h[0])<<24 | uint32(h[1])<<16 | uint32(h[2])<<8 | uint32(h[3]),
		Data2: uint16(h[4])<<8 | uint16(h[5]),
		Data3: (uint16(h[6])<<8|uint16(h[7]))&0x0fff | 0x5000, // name-based GUID
		Data4: [8]byte{h[8]&0x3f | 0x80, h[9], h[10], h[11], h[12], h[13], h[14], h[15]},
	}
}

func open() (*wf.Session, error) {
	s, err := wf.New(&wf.Options{Name: "sentient1", Description: "sentient1 network response"})
	if err != nil {
		return nil, fmt.Errorf("open Windows Filtering Platform: %w", err)
	}
	if err := ensureBase(s); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func ensureBase(s *wf.Session) error {
	provs, err := s.Providers()
	if err != nil {
		return err
	}
	has := false
	for _, p := range provs {
		has = has || p.ID == providerID
	}
	if !has {
		if err := s.AddProvider(&wf.Provider{ID: providerID, Name: "sentient1", Description: "sentient1 bait response", Persistent: true}); err != nil {
			return fmt.Errorf("add WFP provider: %w", err)
		}
	}
	subs, err := s.Sublayers(providerID)
	if err != nil {
		return err
	}
	for _, sl := range subs {
		if sl.ID == sublayerID {
			return nil
		}
	}
	if err := s.AddSublayer(&wf.Sublayer{ID: sublayerID, Name: "sentient1", Description: "sentient1 bait response", Persistent: true, Provider: providerID, Weight: 0xffff}); err != nil {
		return fmt.Errorf("add WFP sublayer: %w", err)
	}
	return nil
}

func addRules(s *wf.Session, rules []*wf.Rule) error {
	for _, r := range rules {
		r.Sublayer, r.Provider, r.Persistent = sublayerID, providerID, true
		if err := s.AddRule(r); err != nil && !alreadyExists(err) {
			return fmt.Errorf("add rule %q: %w", r.Name, err)
		}
	}
	return nil
}

func alreadyExists(err error) bool {
	var en syscall.Errno
	const fwpEAlreadyExists = 0x80320009
	return errors.As(err, &en) && uint32(en) == fwpEAlreadyExists
}

func deleteRules(s *wf.Session, ids []wf.RuleID) {
	for _, id := range ids {
		s.DeleteRule(id) // not-found is fine
	}
}

func isolationRuleIDs() []wf.RuleID {
	var ids []wf.RuleID
	for _, l := range allLayers {
		ids = append(ids, ruleID("isolate", l.String(), "block"), ruleID("isolate", l.String(), "loopback"), ruleID("isolate", l.String(), "self"))
	}
	return ids
}

// Isolate blocks all inbound and outbound connections except loopback and
// selfExe (SENTIENT1's service, so phone alerts still get out).
func Isolate(selfExe string) error {
	s, err := open()
	if err != nil {
		return err
	}
	defer s.Close()
	appID, err := appIDFor(selfExe)
	if err != nil {
		return fmt.Errorf("app id for %s: %w", selfExe, err)
	}
	// Permits go in before the blocks so SENTIENT1 itself is never cut off, even briefly.
	var permits, blocks []*wf.Rule
	for _, l := range allLayers {
		permits = append(permits,
			&wf.Rule{ID: ruleID("isolate", l.String(), "loopback"), Name: "SENTIENT1: isolate (allow loopback)", Layer: l, Weight: wPermitLoop, Action: wf.ActionPermit,
				Conditions: []*wf.Match{{Field: wf.FieldFlags, Op: wf.MatchTypeFlagsAllSet, Value: wf.ConditionFlagIsLoopback}}},
			&wf.Rule{ID: ruleID("isolate", l.String(), "self"), Name: "SENTIENT1: isolate (allow SENTIENT1 alerts)", Layer: l, Weight: wPermitSelf, Action: wf.ActionPermit,
				Conditions: []*wf.Match{{Field: wf.FieldALEAppID, Op: wf.MatchTypeEqual, Value: appID}}})
		blocks = append(blocks,
			&wf.Rule{ID: ruleID("isolate", l.String(), "block"), Name: "SENTIENT1: isolate (block all)", Layer: l, Weight: wBlockAll, Action: wf.ActionBlock})
	}
	return addRules(s, append(permits, blocks...))
}

// Unisolate removes isolation.
func Unisolate() error {
	s, err := open()
	if err != nil {
		return err
	}
	defer s.Close()
	deleteRules(s, isolationRuleIDs())
	return nil
}

func programRuleIDs(path string) []wf.RuleID {
	var ids []wf.RuleID
	for _, l := range allLayers {
		ids = append(ids, ruleID("block", paths.Key(path), l.String()))
	}
	return ids
}

// BlockProgram blocks all network traffic of one executable.
func BlockProgram(path string) error {
	s, err := open()
	if err != nil {
		return err
	}
	defer s.Close()
	appID, err := appIDFor(path)
	if err != nil {
		return fmt.Errorf("app id for %s: %w", path, err)
	}
	var rules []*wf.Rule
	for i, l := range allLayers {
		rules = append(rules, &wf.Rule{ID: programRuleIDs(path)[i], Name: "SENTIENT1: block " + path, Layer: l, Weight: wBlockProgram, Action: wf.ActionBlock,
			Conditions: []*wf.Match{{Field: wf.FieldALEAppID, Op: wf.MatchTypeEqual, Value: appID}}})
	}
	return addRules(s, rules)
}

// UnblockProgram removes a program block.
func UnblockProgram(path string) error {
	s, err := open()
	if err != nil {
		return err
	}
	defer s.Close()
	deleteRules(s, programRuleIDs(path))
	return nil
}

// Status reports what SENTIENT1 currently enforces in WFP.
type Status struct {
	Isolated bool
	Rules    int
}

func GetStatus() (st Status, err error) {
	// Enumerating every filter on the system parses third-party rules too;
	// never let an unexpected one crash the caller.
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("reading firewall rules: %v", r)
		}
	}()
	s, err := wf.New(&wf.Options{Name: "SENTIENT1 status"})
	if err != nil {
		return Status{}, err
	}
	defer s.Close()
	rules, err := s.Rules()
	if err != nil {
		return Status{}, err
	}
	iso := map[wf.RuleID]bool{}
	for _, id := range isolationRuleIDs() {
		iso[id] = true
	}
	for _, r := range rules {
		if r.Provider != providerID {
			continue
		}
		st.Rules++
		if iso[r.ID] && r.Action == wf.ActionBlock {
			st.Isolated = true
		}
	}
	return st, nil
}

// RemoveAll deletes every SENTIENT1 rule, the sublayer and the provider (uninstall).
func RemoveAll() error {
	s, err := wf.New(&wf.Options{Name: "SENTIENT1 uninstall"})
	if err != nil {
		return err
	}
	defer s.Close()
	rules, err := s.Rules()
	if err != nil {
		return err
	}
	for _, r := range rules {
		if r.Provider == providerID {
			s.DeleteRule(r.ID)
		}
	}
	s.DeleteSublayer(sublayerID)
	s.DeleteProvider(providerID)
	return nil
}

// ---- Fallback: disable adapters ----

// DisableAdapters turns off every enabled network adapter and returns their names.
func DisableAdapters() ([]string, error) {
	out, err := powershell(`Get-NetAdapter | Where-Object Status -ne 'Disabled' | ForEach-Object { $_.Name }`)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, n := range strings.Split(strings.TrimSpace(out), "\n") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return nil, nil
	}
	_, err = powershell(`Get-NetAdapter | Where-Object Status -ne 'Disabled' | Disable-NetAdapter -Confirm:$false`)
	return names, err
}

// EnableAdapters turns the named adapters back on.
func EnableAdapters(names []string) error {
	var firstErr error
	for _, n := range names {
		q := strings.ReplaceAll(n, "'", "''")
		if _, err := powershell("Enable-NetAdapter -Name '" + q + "' -Confirm:$false"); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("%s: %w", n, err)
		}
	}
	return firstErr
}

func powershell(script string) (string, error) {
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	b, err := cmd.CombinedOutput()
	if err != nil {
		return string(b), fmt.Errorf("%v: %s", err, strings.TrimSpace(string(b)))
	}
	return string(b), nil
}

// appIDFor returns WFP's application ID for an executable. WFP matches the
// running program by its full long path, so 8.3 short names
// (C:\Users\RUNNER~1\...) must be expanded first or the rule never applies.
func appIDFor(exe string) (string, error) {
	return wf.AppID(paths.Long(exe))
}
