package instant

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// Reading a bait's permissions (like `sentient1 doctor` does) must not count as a read.
func TestSecurityCheckIsNotARead(t *testing.T) {
	dir := t.TempDir()
	bait := filepath.Join(dir, "passwords.txt")
	os.WriteFile(bait, []byte("x"), 0o644)
	type ev struct {
		read   bool
		access uint32
	}
	got := make(chan ev, 4)
	w := &Watcher{Self: 1, // treat our own PID as "someone else" for this test
		OnOpen:  func(string, time.Time, []uint32) { got <- ev{read: true} },
		OnOther: func(_ string, a uint32) { got <- ev{access: a} }}
	w.Sync([]string{bait})
	defer w.Stop()
	time.Sleep(100 * time.Millisecond)

	if _, err := windows.GetNamedSecurityInfo(bait, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION|windows.OWNER_SECURITY_INFORMATION); err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-got:
		if e.read {
			t.Fatal("a permissions check was treated as a read")
		}
		t.Logf("permissions check let through (access 0x%x)", e.access)
	case <-time.After(3 * time.Second):
		t.Log("permissions check didn't break the oplock at all")
	}
}
