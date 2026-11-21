package procinfo

import (
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestInjectedCodeCleanWindowsProcess(t *testing.T) {
	cmd := exec.Command(`C:\Windows\System32\PING.EXE`, "-n", "6", "127.0.0.1")
	if err := cmd.Start(); err != nil {
		t.Skip(err)
	}
	defer cmd.Process.Kill()
	time.Sleep(500 * time.Millisecond)
	if d, found := InjectedCode(uint32(cmd.Process.Pid)); found {
		t.Fatalf("clean ping.exe flagged: %s", d)
	}
	// Whatever explorer looks like on this machine (informational: shell
	// extensions and overlays vary).
	if snap, err := Snapshot(); err == nil {
		for pid, e := range snap {
			if strings.EqualFold(e.Exe, "explorer.exe") {
				d, found := InjectedCode(pid)
				t.Logf("explorer.exe pid %d: found=%v %s", pid, found, d)
			}
		}
	}
}

func TestInjectedCodeFindsPrivateExecutableMemory(t *testing.T) {
	pid := uint32(os.Getpid())
	if d, found := InjectedCode(pid); found {
		t.Logf("note: test process already has unbacked code: %s", d)
	}
	size := uintptr(128 << 10)
	addr, err := windows.VirtualAlloc(0, size, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.VirtualFree(addr, 0, windows.MEM_RELEASE)
	mz := []byte("MZ")
	if err := windows.WriteProcessMemory(windows.CurrentProcess(), addr, &mz[0], 2, nil); err != nil {
		t.Fatal(err)
	}
	var old uint32
	if err := windows.VirtualProtect(addr, size, windows.PAGE_EXECUTE_READ, &old); err != nil {
		t.Fatal(err)
	}
	d, found := InjectedCode(pid)
	if !found || !strings.Contains(d, "whole program") {
		t.Fatalf("injected region not found: %q", d)
	}
	t.Log(d)
}

func TestInjectedCodeIgnoresSmallHooks(t *testing.T) {
	pid := uint32(os.Getpid())
	// Ten 4 KB trampolines and one 64 KB thunk block, like explorer.exe with
	// a few shell extensions and overlays: not an injected program.
	var allocs []uintptr
	for _, size := range []uintptr{64 << 10, 4 << 10, 4 << 10, 4 << 10, 4 << 10, 4 << 10, 4 << 10, 4 << 10, 4 << 10, 4 << 10, 4 << 10} {
		addr, err := windows.VirtualAlloc(0, size, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READ)
		if err != nil {
			t.Fatal(err)
		}
		allocs = append(allocs, addr)
	}
	defer func() {
		for _, a := range allocs {
			windows.VirtualFree(a, 0, windows.MEM_RELEASE)
		}
	}()
	if d, found := InjectedCode(pid); found {
		t.Fatalf("small hooks flagged as injection: %s", d)
	}
}
