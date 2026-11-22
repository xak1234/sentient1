package notify

import (
	"strings"
	"testing"

	"github.com/xak1234/sentient1/internal/alerts"
	"github.com/xak1234/sentient1/internal/authenticode"
	"github.com/xak1234/sentient1/internal/procinfo"
)

func TestHostedIdentityVisibleInBothNotificationFormats(t *testing.T) {
	signature := authenticode.Result{Signed: true, Valid: true, Signer: "Malwarebytes Inc"}
	a := &alerts.Alert{Process: &alerts.Process{PID: 11120, Image: `C:\Windows\System32\dllhost.exe`,
		Hosted: &procinfo.HostedInfo{Status: "observed", Components: []procinfo.HostedComponent{{
			Name: "Malwarebytes Anti-Malware", Module: `C:\Program Files\Malwarebytes\Anti-Malware\mbshlext.appx.dll`, Loaded: true,
			Source: "Packaged COM registration; matching module observed in the process", Signature: &signature}}}}}
	for _, body := range []string{Details(a), FromAlert(a).Body} {
		for _, want := range []string{"Malwarebytes Anti-Malware (via dllhost.exe)", "mbshlext.appx.dll", "Malwarebytes Inc", "matching module observed"} {
			if !strings.Contains(body, want) {
				t.Errorf("notification missing %q: %s", want, body)
			}
		}
	}
}
