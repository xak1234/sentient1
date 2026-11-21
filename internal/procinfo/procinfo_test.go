package procinfo

import (
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestSelfInfo(t *testing.T) {
	pid := uint32(os.Getpid())
	img, err := ImagePath(pid)
	exe, _ := os.Executable()
	if err != nil || !strings.EqualFold(img, exe) {
		t.Fatalf("ImagePath = %q, %v; want %q", img, err, exe)
	}
	cl, err := CommandLine(pid)
	if err != nil || !strings.Contains(strings.ToLower(cl), ".test") {
		t.Fatalf("CommandLine = %q, %v", cl, err)
	}
	snap, err := Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if chain := ParentChain(snap, pid, 3); len(chain) == 0 {
		t.Fatal("no parent chain")
	}
}

func TestSuspendResumeKillTree(t *testing.T) {
	// parent cmd that spawns a long-running child
	cmd := exec.Command("cmd.exe", "/c", "ping -n 30 127.0.0.1 >nul")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	pid := uint32(cmd.Process.Pid)
	time.Sleep(500 * time.Millisecond)

	frozen, err := SuspendTree(pid)
	if err != nil || len(frozen) < 2 {
		t.Fatalf("SuspendTree = %v, %v (want parent + ping child)", frozen, err)
	}
	for _, p := range frozen {
		if err := Resume(p); err != nil {
			t.Fatalf("resume %d: %v", p, err)
		}
	}
	if err := KillTree(pid); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	for _, p := range frozen {
		if Alive(p, 0) {
			t.Fatalf("pid %d still alive after KillTree", p)
		}
	}
}

func TestConnections(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	conns, err := Connections([]uint32{uint32(os.Getpid())})
	if err != nil {
		t.Fatal(err)
	}
	want := l.Addr().String()
	for _, c := range conns {
		if c.Local == want && c.State == "LISTEN" {
			return
		}
	}
	t.Fatalf("listener %s not found in %+v", want, conns)
}

func TestIntegrityLevel(t *testing.T) {
	lvl, err := IntegrityLevel(uint32(os.Getpid()))
	if err != nil || lvl < IntegrityLow || lvl > IntegritySystem+0x100 {
		t.Fatalf("IntegrityLevel = 0x%x, %v", lvl, err)
	}
	t.Logf("this test runs at integrity 0x%x", lvl)
}
