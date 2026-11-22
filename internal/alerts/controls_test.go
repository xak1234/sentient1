package alerts

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xak1234/sentient1/internal/config"
)

func TestManualControlsGuardAndPersistence(t *testing.T) {
	t.Setenv("ProgramData", t.TempDir())
	a := &Alert{ID: NewID(time.Now()), Process: &Process{PID: 123, Image: `C:\Windows\System32\dllhost.exe`}}
	a.RefreshControls(config.NewState())
	if a.Controls.CanFreeze || !strings.Contains(a.Controls.FreezeReason, "creation time") {
		t.Fatalf("old alert not safely disabled: %+v", a.Controls)
	}
	if err := Save(a); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(file(a.ID))
	if err != nil || strings.Contains(string(b), `"controls"`) {
		t.Fatalf("live controls must never be persisted: %v", err)
	}
	a.Process.Image = `C:\Windows\System32\svchost.exe`
	a.RefreshControls(config.NewState())
	if a.Controls.CanFreeze || !strings.Contains(a.Controls.FreezeReason, "protected") {
		t.Fatalf("protected host accepted: %+v", a.Controls)
	}
	a.RefreshControls(nil)
	if a.Controls.CanFreeze || !strings.Contains(a.Controls.FreezeReason, "state is unavailable") {
		t.Fatal("missing state did not disable freeze")
	}
}
