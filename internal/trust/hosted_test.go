package trust

import (
	"strings"
	"testing"

	"github.com/xak1234/sentient1/internal/alerts"
	"github.com/xak1234/sentient1/internal/authenticode"
)

func TestSharedHostCannotBecomeBlanketTrust(t *testing.T) {
	for _, executable := range []string{"dllhost.exe", "rundll32.exe", "svchost.exe"} {
		a := &alerts.Alert{Process: &alerts.Process{Image: `C:\Windows\System32\` + executable,
			Signature: authenticode.Result{Signed: true, Valid: true, Signer: "Microsoft Windows"}},
			Baits: []alerts.BaitHit{{ID: "desktop-passwords"}}}
		if rule, why := Rule(a); why == "" || !strings.Contains(why, "shared executable") || rule.Path != "" {
			t.Fatalf("%s acquired a broad trust rule: %+v (%s)", executable, rule, why)
		}
		if OneClick(a) {
			t.Fatalf("%s allowed permanent trust from the popup", executable)
		}
	}
}
