// Package integration holds tests that need administrator rights: real audit
// rules, the real Security log, real WFP filters. They run in CI (GitHub's
// Windows runners are admin) when SENTIENT1_INTEGRATION=1.
package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/xak1234/sentient1/internal/evtlog"
	"github.com/xak1234/sentient1/internal/netguard"
	"github.com/xak1234/sentient1/internal/winsec"
)

func requireAdmin(t *testing.T) {
	t.Helper()
	if os.Getenv("SENTIENT1_INTEGRATION") != "1" {
		t.Skip("set SENTIENT1_INTEGRATION=1 (admin) to run")
	}
	if !winsec.IsElevated() {
		t.Fatal("integration tests need an elevated shell")
	}
}

// The whole detection path: audit policy + SACL -> 4663 in the Security log ->
// our subscription -> parsed ObjectAccess with the right process.
func TestBaitReadIsDetected(t *testing.T) {
	requireAdmin(t)
	orig, err := winsec.FileSystemAudit()
	if err != nil {
		t.Fatal(err)
	}
	defer winsec.SetFileSystemAudit(orig)
	if _, err := winsec.EnsureFileSystemAudit(); err != nil {
		t.Fatal(err)
	}

	bait := filepath.Join(t.TempDir(), "passwords.txt")
	os.WriteFile(bait, []byte("hunter2"), 0o644)
	if err := winsec.SetBaitAudit(bait); err != nil {
		t.Fatal(err)
	}
	if ok, err := winsec.HasBaitAudit(bait); !ok || err != nil {
		t.Fatalf("HasBaitAudit = %v, %v", ok, err)
	}

	sub, err := evtlog.Subscribe("Security", evtlog.BaitQuery, "")
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	got := make(chan *evtlog.ObjectAccess, 16)
	go sub.Run(ctx, func(x string) {
		if e, err := evtlog.Parse(x); err == nil {
			if oa, ok := e.AsObjectAccess(); ok && strings.EqualFold(oa.ObjectName, bait) {
				got <- oa
			}
		}
	})
	time.Sleep(300 * time.Millisecond)
	start := time.Now()
	if out, err := exec.Command("cmd.exe", "/c", "type", bait).CombinedOutput(); err != nil {
		t.Fatalf("type: %v %s", err, out)
	}
	select {
	case oa := <-got:
		t.Logf("detected read by %s (pid %d) in %v", oa.ProcessName, oa.ProcessID, time.Since(start))
		if !strings.HasSuffix(strings.ToLower(oa.ProcessName), `\cmd.exe`) || !winsec.AccessMaskIsRead(oa.AccessMask) {
			t.Fatalf("unexpected event: %+v", oa)
		}
	case <-ctx.Done():
		t.Fatal("no 4663 event for the bait read")
	}

	if err := winsec.ClearAudit(bait); err != nil {
		t.Fatal(err)
	}
	if ok, _ := winsec.HasBaitAudit(bait); ok {
		t.Fatal("audit rule still present after ClearAudit")
	}
}

// Per-program blocking through WFP, on a private copy of curl.exe so nothing
// else on the machine is affected.
func TestBlockProgram(t *testing.T) {
	requireAdmin(t)
	src := filepath.Join(os.Getenv("SystemRoot"), `System32\curl.exe`)
	b, err := os.ReadFile(src)
	if err != nil {
		t.Skip("no curl.exe")
	}
	curl := filepath.Join(t.TempDir(), "sentient1-curl.exe")
	os.WriteFile(curl, b, 0o755)
	get := func() error {
		return exec.Command(curl, "-sS", "-o", "NUL", "--max-time", "8", "https://www.microsoft.com").Run()
	}
	if err := get(); err != nil {
		t.Skipf("no internet on this runner: %v", err)
	}
	if err := netguard.BlockProgram(curl); err != nil {
		t.Fatal(err)
	}
	defer netguard.RemoveAll()
	if err := get(); err == nil {
		t.Fatal("blocked program still reached the internet")
	}
	if err := netguard.UnblockProgram(curl); err != nil {
		t.Fatal(err)
	}
	// The internet itself can hiccup on CI runners: allow a few attempts.
	var lastErr error
	for i := 0; i < 3; i++ {
		if lastErr = get(); lastErr == nil {
			return
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("unblocked program still can't connect after 3 tries: %v", lastErr)
}
