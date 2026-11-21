package notify

import (
	"strings"
	"testing"

	"github.com/xak1234/sentient1/internal/alerts"
	"github.com/xak1234/sentient1/internal/config"
	"github.com/xak1234/sentient1/internal/procinfo"
)

func TestPopupTextReadsCleanly(t *testing.T) {
	a := &alerts.Alert{Summary: "unsigned program running from a user-writable folder",
		Baits:   []alerts.BaitHit{{Name: "passwords.txt on the Desktop", Path: `C:\Users\you\Desktop\passwords.txt`, Access: "read"}},
		Process: &alerts.Process{PID: 4242, Image: `C:\Users\you\Downloads\FreeRobux.exe`, Parents: []procinfo.Parent{{PID: 1, Image: `C:\Windows\explorer.exe`}}}}
	a.AddAction(config.ActionFreeze, nil, "2 process(es) frozen")
	a.AddAction(config.ActionBlockProgram, nil, `C:\Users\you\Downloads\FreeRobux.exe`)
	got := Details(a)
	for _, want := range []string{"Program: FreeRobux.exe (pid 4242)", "Started by: explorer.exe", "It read: passwords.txt on the Desktop",
		"What SENTIENT1 did:", "✓ Froze it and 1 process(es) it started", "✓ Cut its internet"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in:\n%s", want, got)
		}
	}
	if strings.Contains(got, "   ") {
		t.Errorf("column padding left in popup text:\n%s", got)
	}
	if testing.Verbose() {
		t.Log("\n" + got)
	}
}
