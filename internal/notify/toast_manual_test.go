package notify

import (
	"os"
	"os/exec"
	"testing"
)

// Run manually: SENTIENT1_TOAST_TEST=1 go test -run TestToastManual ./internal/notify/
func TestToastManual(t *testing.T) {
	if os.Getenv("SENTIENT1_TOAST_TEST") != "1" {
		t.Skip("shows a real notification; set SENTIENT1_TOAST_TEST=1")
	}
	toastRun = func(cmd *exec.Cmd) ([]byte, error) { return cmd.CombinedOutput() }
	Toast("SENTIENT1: Possible stealer: FreeRobux.exe read your bait", "DEMO notification from SENTIENT1's real code path. Nothing happened.")
	if lastToastErr != "" {
		t.Fatalf("toast failed: %s", lastToastErr)
	}
}
