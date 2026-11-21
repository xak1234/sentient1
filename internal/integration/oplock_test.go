package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/xak1234/sentient1/internal/evtlog"
	"github.com/xak1234/sentient1/internal/procinfo"
	"github.com/xak1234/sentient1/internal/winsec"
)

// Experiment: "freeze before it reads". While we hold an exclusive oplock on
// a bait, a reader's open is paused inside Windows. Does the audit event that
// names the reader arrive while it's paused, so we can freeze it before it
// gets a single byte?
func TestOplockFreezeBeforeRead(t *testing.T) {
	requireAdmin(t)
	orig, _ := winsec.FileSystemAudit()
	defer winsec.SetFileSystemAudit(orig)
	winsec.EnsureFileSystemAudit()

	dir := t.TempDir()
	bait := filepath.Join(dir, "passwords.txt")
	os.WriteFile(bait, []byte("email / hunter2\r\n"), 0o644)
	if err := winsec.SetBaitAudit(bait); err != nil {
		t.Fatal(err)
	}
	stolen := filepath.Join(dir, "stolen.txt")

	sub, err := evtlog.Subscribe("Security", "*[System[(EventID=4656 or EventID=4663)]]", "")
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	type seen struct {
		id  int
		pid uint32
		at  time.Time
	}
	events := make(chan seen, 64)
	go sub.Run(ctx, func(x string) {
		e, err := evtlog.Parse(x)
		if err != nil || !strings.EqualFold(e.Data["ObjectName"], bait) {
			return
		}
		pid := uint32(0)
		fmt.Sscanf(strings.TrimPrefix(strings.ToLower(e.Data["ProcessId"]), "0x"), "%x", &pid)
		events <- seen{e.ID, pid, time.Now()}
	})
	time.Sleep(300 * time.Millisecond)

	h, ev := holdOplock(t, bait)
	held := true
	release := func() {
		if held {
			windows.CloseHandle(h)
			held = false
		}
	}
	defer release()

	start := time.Now()
	reader := exec.Command("cmd.exe", "/c", "type", bait, ">", stolen)
	if err := reader.Start(); err != nil {
		t.Fatal(err)
	}
	defer reader.Process.Kill()
	readerPID := uint32(reader.Process.Pid)
	done := make(chan struct{})
	go func() { reader.Wait(); close(done) }()

	if r, _ := windows.WaitForSingleObject(ev, 10_000); r != windows.WAIT_OBJECT_0 {
		t.Fatal("no oplock break: the reader's open didn't touch our oplock")
	}
	t.Logf("oplock break after %v", time.Since(start))

	// While the reader is paused, wait for an audit event that names it.
	// (cmd.exe may hand the read to a child; accept any PID in its tree.)
	var hit *seen
	deadline := time.After(10 * time.Second)
wait:
	for {
		select {
		case s := <-events:
			snap, _ := procinfo.Snapshot()
			tree := procinfo.Tree(snap, readerPID)
			for _, p := range tree {
				if p == s.pid {
					hit = &s
					break wait
				}
			}
			t.Logf("event %d from pid %d (not the reader)", s.id, s.pid)
		case <-done:
			t.Fatal("reader finished while we held the oplock")
		case <-deadline:
			break wait
		}
	}
	if hit == nil {
		// Known result: Windows writes the audit record when data is read, not at
		// open, so a reader paused on the oplock can't be named this way.
		t.Skip("RESULT: no audit event while the reader is paused (expected; see design notes)")
	}
	b, _ := os.ReadFile(stolen)
	t.Logf("RESULT: event %d named the reader (pid %d) %v after start, while it was still paused with %d bytes read",
		hit.id, hit.pid, hit.at.Sub(start), len(b))

	// Freeze it, then let go of the oplock: it must not get the data.
	frozen, err := procinfo.SuspendTree(hit.pid)
	if err != nil {
		t.Fatalf("suspend: %v", err)
	}
	release()
	time.Sleep(2 * time.Second)
	b, _ = os.ReadFile(stolen)
	if len(b) != 0 {
		t.Fatalf("frozen reader still got %d bytes", len(b))
	}
	t.Logf("RESULT: frozen before reading; 2s after releasing the oplock it still has %d bytes", len(b))
	for _, p := range frozen {
		procinfo.Resume(p)
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("reader didn't finish after resume")
	}
}

func holdOplock(t *testing.T, path string) (windows.Handle, windows.Handle) {
	t.Helper()
	type in struct {
		Version, Length uint16
		Level, Flags    uint32
	}
	type out struct {
		Version, Length         uint16
		OriginalLevel, NewLevel uint32
		Flags, AccessMode       uint32
		ShareMode, _            uint16
	}
	p, _ := windows.UTF16PtrFromString(path)
	h, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		t.Fatal(err)
	}
	ev, _ := windows.CreateEvent(nil, 1, 0, nil)
	ov := &windows.Overlapped{HEvent: ev}
	req := &in{Version: 1, Length: uint16(unsafe.Sizeof(in{})), Level: 0x7, Flags: 0x1}
	res := &out{}
	err = windows.DeviceIoControl(h, 0x00090240, (*byte)(unsafe.Pointer(req)), uint32(unsafe.Sizeof(*req)),
		(*byte)(unsafe.Pointer(res)), uint32(unsafe.Sizeof(*res)), nil, ov)
	if err != windows.ERROR_IO_PENDING {
		t.Fatalf("oplock not granted: %v", err)
	}
	t.Cleanup(func() { _ = ov; _ = req; _ = res })
	return h, ev
}
