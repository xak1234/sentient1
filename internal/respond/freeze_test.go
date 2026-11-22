package respond

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xak1234/sentient1/internal/alerts"
	"github.com/xak1234/sentient1/internal/config"
	"github.com/xak1234/sentient1/internal/paths"
	"github.com/xak1234/sentient1/internal/procinfo"
	"golang.org/x/sys/windows"
)

// A real disposable reader, with a heartbeat that stops when Windows suspends it.
func TestManualFreezeHeartbeat(t *testing.T) {
	path := os.Getenv("SENTIENT1_FREEZE_TEST_HEARTBEAT")
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		if _, err := f.Write([]byte{1}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func freezeReader(t *testing.T) (*alerts.Alert, string) {
	t.Helper()
	t.Setenv("ProgramData", t.TempDir())
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	beat := filepath.Join(t.TempDir(), "heartbeat")
	cmd := exec.Command(exe, "-test.run=^TestManualFreezeHeartbeat$")
	cmd.Env = append(os.Environ(), "SENTIENT1_FREEZE_TEST_HEARTBEAT="+beat)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	pid := uint32(cmd.Process.Pid)
	created, err := procinfo.CreateTime(pid)
	if err != nil || created == 0 {
		t.Fatal("child creation time unavailable:", err)
	}
	a := &alerts.Alert{ID: alerts.NewID(time.Now()), Kind: alerts.KindRead, Status: "open",
		Process: &alerts.Process{PID: pid, CreateTime: created, Image: exe}}
	if err := alerts.Save(a); err != nil {
		t.Fatal(err)
	}
	waitBeat(t, beat, 0)
	return a, beat
}

func beatSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}

func waitBeat(t *testing.T, path string, previous int64) {
	t.Helper()
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		if beatSize(path) > previous {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("reader heartbeat did not advance")
}

func requireDesktopSession(t *testing.T) {
	t.Helper()
	var session uint32
	if err := windows.ProcessIdToSessionId(uint32(os.Getpid()), &session); err != nil {
		t.Fatal(err)
	}
	if session == 0 {
		t.Skip("manual freeze excludes services; run this test binary in an elevated desktop session")
	}
}

func TestManualFreezeRejectsStaleIdentity(t *testing.T) {
	a, beat := freezeReader(t)
	before := beatSize(beat)
	for _, change := range []struct {
		created int64
		image   string
	}{
		{0, a.Process.Image},
		{a.Process.CreateTime + 1, a.Process.Image},
		{a.Process.CreateTime, a.Process.Image + ".different"},
	} {
		recorded := *a.Process
		a.Process.CreateTime, a.Process.Image = change.created, change.image
		if err := alerts.Save(a); err != nil {
			t.Fatal(err)
		}
		if _, err := Freeze(a.ID); err == nil {
			t.Fatal("unsafe process identity accepted")
		}
		*a.Process = recorded
	}
	waitBeat(t, beat, before)
	st, err := config.LoadState()
	if err != nil || len(st.Frozen) != 0 {
		t.Fatalf("rejected request changed state: %+v, %v", st, err)
	}
}

func TestManualFreezeRealLifecycle(t *testing.T) {
	requireDesktopSession(t)
	a, beat := freezeReader(t)
	a.RefreshControls(config.NewState())
	if !a.Controls.CanFreeze {
		t.Fatal(a.Controls.FreezeReason)
	}
	if _, err := Freeze(a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := Freeze(a.ID); err != nil {
		t.Fatal("second click should be harmless:", err)
	}
	st, err := config.LoadState()
	if err != nil || len(st.Frozen) != 1 || st.Frozen[0].CreateTime != a.Process.CreateTime {
		t.Fatalf("expected one exact recovery record: %+v, %v", st, err)
	}
	a.RefreshControls(st)
	if a.Controls.CanFreeze || !a.Controls.Frozen {
		t.Fatal("frozen controls did not update")
	}
	before := beatSize(beat)
	time.Sleep(200 * time.Millisecond)
	if beatSize(beat) != before {
		t.Fatal("Windows did not pause the reader")
	}
	if _, err := Resume(a.ID); err != nil {
		t.Fatal(err)
	}
	waitBeat(t, beat, before)
	st, err = config.LoadState()
	if err != nil || len(st.Frozen) != 0 || len(st.Blocked) != 0 || st.Isolation != nil {
		t.Fatalf("unexpected containment after resume: %+v, %v", st, err)
	}
	t.Log("PASS: live reader paused, duplicate click harmless, one resume restored heartbeat")
}

func TestManualFreezeStateSaveRollback(t *testing.T) {
	requireDesktopSession(t)
	a, beat := freezeReader(t)
	if err := config.UpdateState(func(*config.State) error { return nil }); err != nil {
		t.Fatal(err)
	}
	name, err := windows.UTF16PtrFromString(paths.StateFile())
	if err != nil {
		t.Fatal(err)
	}
	// Real file sharing semantics prevent the atomic state replacement.
	h, err := windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)
	before := beatSize(beat)
	rep, err := Freeze(a.ID)
	if err == nil || !strings.Contains(strings.Join(rep.Lines, " "), "resumed the reader") {
		t.Fatalf("expected save error and successful rollback: %+v, %v", rep, err)
	}
	waitBeat(t, beat, before)
	st, err := config.LoadState()
	if err != nil || len(st.Frozen) != 0 {
		t.Fatalf("failed save left a record: %+v, %v", st, err)
	}
	t.Log("PASS: failed recovery-record save automatically resumed the real reader")
}
