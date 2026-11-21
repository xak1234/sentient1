package ui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/xak1234/sentient1/internal/alerts"
	"github.com/xak1234/sentient1/internal/authenticode"
	"github.com/xak1234/sentient1/internal/classify"
	"github.com/xak1234/sentient1/internal/config"
	"github.com/xak1234/sentient1/internal/procinfo"
	"github.com/xak1234/sentient1/internal/svcctl"
)

func sampleAlert() *alerts.Alert {
	a := &alerts.Alert{
		ID: "20261116-151253-9f3a", Time: time.Now().Add(-3 * time.Minute), Kind: alerts.KindRead, Tier: config.TierCritical,
		Title: "Possible stealer: svch0st.exe read your bait", Status: "open", LatencyMS: 4,
		Summary: `unsigned program running from a user-writable folder (C:\Users\bob\AppData\Local\Temp\x7f3): typical of stealers`,
		Baits: []alerts.BaitHit{
			{Name: "passwords.txt on the Desktop", Path: `C:\Users\bob\Desktop\passwords.txt`, Access: "read", Time: time.Now()},
			{Name: "Exodus wallet", Path: `C:\Users\bob\AppData\Roaming\Exodus\exodus.wallet\seed.seco`, Access: "read", Time: time.Now()},
		},
		Process: &alerts.Process{PID: 7712, Image: `C:\Users\bob\AppData\Local\Temp\x7f3\svch0st.exe`,
			CommandLine: `"C:\Users\bob\AppData\Local\Temp\x7f3\svch0st.exe" --silent`, User: `PC\bob`,
			SHA256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", Signature: authenticode.Result{},
			Parents:     []procinfo.Parent{{PID: 6620, Image: `C:\Windows\System32\cmd.exe`}, {PID: 4410, Image: `C:\Windows\explorer.exe`}},
			Connections: []procinfo.Conn{{Proto: "tcp", Local: "192.168.1.20:51544", Remote: "185.234.72.11:443", State: "ESTABLISHED"}}},
		Verdict: classify.Verdict{Tier: config.TierCritical, Reasons: []string{"unsigned program running from a user-writable folder: typical of stealers", "unsigned"}},
	}
	a.AddAction(config.ActionFreeze, nil, "2 process(es) frozen")
	a.AddAction(config.ActionBlockProgram, nil, a.Process.Image)
	return a
}

func TestRenderDashboardAndAlert(t *testing.T) {
	cfg := config.Default()
	cfg.ApplyPreset("strict") // learning mode only shows when it changes something
	cfg.LearningUntil = time.Now().Add(50 * time.Hour)
	st := config.NewState()
	st.Heartbeat = time.Now().Add(-40 * time.Second)
	st.Health = []config.HealthItem{{Name: "File auditing", OK: true, Detail: "on"}}
	st.Baits["a"] = &config.BaitState{Status: "ok"}
	st.Baits["b"] = &config.BaitState{Status: "ok"}
	st.Frozen = []config.FrozenProcess{{PID: 7712}}
	st.Blocked = []config.BlockedProgram{{Path: "x"}}
	info := &alerts.Alert{ID: "20261116-101500-11aa", Time: time.Now().Add(-5 * time.Hour), Tier: config.TierInfo, Kind: alerts.KindRead,
		Baits: []alerts.BaitHit{{Name: "passwords.txt on the Desktop"}}, Process: &alerts.Process{Image: `C:\Program Files (x86)\Microsoft\Copilot\Application\copilotapp.exe`}}
	d := StatusData{Cfg: cfg, State: st, Service: svcctl.Running, Alerts: []*alerts.Alert{sampleAlert(), info}}
	out := RenderStatus(d)
	for _, want := range []string{"RESPONSE ACTIVE", "1 process frozen", "learning, ", "svch0st.exe", "copilotapp.exe", "2 of 2 baits healthy"} {
		if !strings.Contains(out, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
	det := AlertDetail(sampleAlert())
	for _, want := range []string{"CRITICAL", "185.234.72.11", "sentient1 kill 9f3a", "sentient1 trust 9f3a", "4 ms", "virustotal.com", "explorer.exe (pid 4410)"} {
		if !strings.Contains(det, want) {
			t.Errorf("alert detail missing %q", want)
		}
	}
	if testing.Verbose() {
		fmt.Println(out)
		fmt.Println(det)
	}
}
