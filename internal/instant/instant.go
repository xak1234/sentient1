// Package instant catches a bait reader the moment it opens a bait.
//
// How it works, without a kernel driver:
//
//  1. SENTIENT1 holds an exclusive opportunistic lock (oplock) on every bait file.
//  2. When another program opens the bait, Windows pauses that program inside
//     its "open file" call and tells SENTIENT1 immediately (an oplock break).
//  3. Windows doesn't say who opened it, so SENTIENT1 notes the threads whose kernel
//     wait began at that moment and are still stuck a few ms later.
//  4. SENTIENT1 lets go. The opener wakes at that exact instant; an innocent thread
//     that happened to get stuck at the same time (e.g. reading a pipe) does
//     not. Whoever woke is the opener, identified precisely.
//  5. The service applies the usual verdict and freezes it a few ms after it
//     opened the bait, without waiting for the event log (0.2-1 s).
//
// (An earlier version froze candidates *before* releasing, so the reader got 0
// bytes, but CI showed that can freeze an innocent bystander. Precision wins.)
//
// The regular audit-log detection keeps running as a backup in case the
// opener couldn't be pinpointed.
package instant

import (
	"errors"
	"sort"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ---- oplock guard on one file ----

const (
	fsctlRequestOplock = 0x00090240
	oplockRWH          = 0x7 // read | handle | write caching: any other open breaks it
	oplockFlagRequest  = 0x1
)

type oplockIn struct {
	Version, Length uint16
	Level, Flags    uint32
}

type oplockOut struct {
	Version, Length         uint16
	OriginalLevel, NewLevel uint32
	Flags, AccessMode       uint32
	ShareMode, _            uint16
}

// Guard holds an oplock on one file. Its event fires when someone opens it.
type Guard struct {
	Path  string
	h     windows.Handle
	event windows.Handle
	// Kept alive (and in place) while the request is pending in the kernel.
	ov  *windows.Overlapped
	in  *oplockIn
	out *oplockOut
}

// ErrNotGranted means another handle is open right now; try again later.
var ErrNotGranted = errors.New("oplock not granted (file is open elsewhere)")

// Arm opens path and requests an exclusive oplock. The open asks for read
// access but never reads, so it doesn't produce an audit event.
func Arm(path string) (*Guard, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OVERLAPPED, 0)
	if err != nil {
		return nil, err
	}
	ev, err := windows.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	g := &Guard{Path: path, h: h, event: ev, ov: &windows.Overlapped{HEvent: ev},
		in:  &oplockIn{Version: 1, Length: uint16(unsafe.Sizeof(oplockIn{})), Level: oplockRWH, Flags: oplockFlagRequest},
		out: &oplockOut{}}
	err = windows.DeviceIoControl(h, fsctlRequestOplock,
		(*byte)(unsafe.Pointer(g.in)), uint32(unsafe.Sizeof(*g.in)),
		(*byte)(unsafe.Pointer(g.out)), uint32(unsafe.Sizeof(*g.out)), nil, g.ov)
	if err != windows.ERROR_IO_PENDING {
		windows.CloseHandle(h)
		windows.CloseHandle(ev)
		if err == nil {
			return nil, ErrNotGranted // completed immediately: not held
		}
		return nil, ErrNotGranted
	}
	return g, nil
}

// Event is signalled when another program opens the file.
func (g *Guard) Event() windows.Handle { return g.event }

// Release lets go: the paused opener's open completes.
func (g *Guard) Release() {
	if g.h != 0 {
		windows.CloseHandle(g.h)
		g.h = 0
	}
	if g.event != 0 {
		windows.CloseHandle(g.event)
		g.event = 0
	}
}

// ---- finding the opener ----

var (
	ntdll                        = windows.NewLazySystemDLL("ntdll.dll")
	procNtQuerySystemInformation = ntdll.NewProc("NtQuerySystemInformation")
)

// Thread is a thread currently blocked in a kernel ("Executive") wait.
type Thread struct {
	PID, TID    uint32
	WaitTime    uint32 // tick count when the wait began
	CtxSwitches uint32
}

const (
	systemProcessInformation = 5
	statusInfoLengthMismatch = 0xC0000004
	threadStateWaiting       = 5
	waitReasonExecutive      = 0

	// x64 / arm64 layouts of SYSTEM_PROCESS_INFORMATION / SYSTEM_THREAD_INFORMATION.
	procInfoSize   = 0x100
	procPIDOffset  = 0x50
	threadInfoSize = 0x50
	thWaitTime     = 0x18
	thTID          = 0x30
	thCtxSwitches  = 0x40
	thState        = 0x44
	thWaitReason   = 0x48
)

// StuckThreads lists threads in an Executive wait, excluding PIDs 0, 4 and skip.
func StuckThreads(skip uint32) ([]Thread, error) {
	size := uint32(1 << 20)
	var buf []byte
	for i := 0; ; i++ {
		buf = make([]byte, size)
		var ret uint32
		r, _, _ := procNtQuerySystemInformation.Call(systemProcessInformation, uintptr(unsafe.Pointer(&buf[0])), uintptr(size), uintptr(unsafe.Pointer(&ret)))
		if r == 0 {
			break
		}
		if uint32(r) != statusInfoLengthMismatch || i > 6 {
			return nil, errors.New("NtQuerySystemInformation failed")
		}
		size *= 2
		if ret > size {
			size = ret + 64<<10
		}
	}
	var out []Thread
	for off := 0; off+procInfoSize <= len(buf); {
		base := buf[off:]
		next := le32(base, 0)
		n := int(le32(base, 4))
		pid := uint32(le64(base, procPIDOffset))
		if pid > 4 && pid != skip {
			for i := 0; i < n && procInfoSize+(i+1)*threadInfoSize <= len(base); i++ {
				t := base[procInfoSize+i*threadInfoSize:]
				if le32(t, thState) == threadStateWaiting && le32(t, thWaitReason) == waitReasonExecutive {
					out = append(out, Thread{PID: pid, TID: uint32(le64(t, thTID)), WaitTime: le32(t, thWaitTime), CtxSwitches: le32(t, thCtxSwitches)})
				}
			}
		}
		if next == 0 {
			break
		}
		off += int(next)
	}
	return out, nil
}

func le32(b []byte, off int) uint32 { return *(*uint32)(unsafe.Pointer(&b[off])) }
func le64(b []byte, off int) uint64 { return *(*uint64)(unsafe.Pointer(&b[off])) }

var sharedTickAddr = uintptr(0x7FFE0320) // KUSER_SHARED_DATA.TickCount (low part), same clock as WaitTime

// Tick returns the kernel tick count (~15.6 ms per tick).
func Tick() uint32 { return **(**uint32)(unsafe.Pointer(&sharedTickAddr)) }

// FindStuck returns threads that got stuck at tick0 (the break) and are still
// stuck after settle. The opener is always among them, but so may be an
// innocent thread that happened to start a long wait (e.g. a pipe read) at the
// same moment, which is why Woke is used to tell them apart.
func FindStuck(tick0 uint32, skip uint32, settle time.Duration) []Thread {
	time.Sleep(settle / 3)
	s1, err := StuckThreads(skip)
	if err != nil {
		return nil
	}
	time.Sleep(settle - settle/3)
	s2, err := StuckThreads(skip)
	if err != nil {
		return nil
	}
	later := map[[2]uint32]Thread{}
	for _, t := range s2 {
		later[[2]uint32{t.PID, t.TID}] = t
	}
	var out []Thread
	for _, t := range s1 {
		if t.WaitTime+3 < tick0 || t.WaitTime > tick0+2 {
			continue // started waiting well before or after the open
		}
		if t2, ok := later[[2]uint32{t.PID, t.TID}]; ok && t2.WaitTime == t.WaitTime && t2.CtxSwitches == t.CtxSwitches {
			out = append(out, t) // still stuck in the very same wait
		}
	}
	return out
}

// Woke returns the PIDs of stuck threads that left their wait right after we
// released the oplock: the opener wakes at that exact moment, while innocent
// threads stuck on something else keep waiting.
func Woke(stuck []Thread, skip uint32, after time.Duration) []uint32 {
	if len(stuck) == 0 {
		return nil
	}
	time.Sleep(after)
	now, err := StuckThreads(skip)
	if err != nil {
		return nil
	}
	still := map[[2]uint32]Thread{}
	for _, t := range now {
		still[[2]uint32{t.PID, t.TID}] = t
	}
	pids := map[uint32]bool{}
	for _, t := range stuck {
		if n, ok := still[[2]uint32{t.PID, t.TID}]; ok && n.WaitTime == t.WaitTime && n.CtxSwitches == t.CtxSwitches {
			continue // still in the same wait: not the opener
		}
		pids[t.PID] = true
	}
	var out []uint32
	for p := range pids {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func selfIn(stuck []Thread, self uint32) bool {
	for _, t := range stuck {
		if self != 0 && t.PID == self {
			return true
		}
	}
	return false
}

// ---- watcher over all baits ----

// Watcher keeps a guard on every bait and reports openers while they're paused.
type Watcher struct {
	// OnOpen gets the program(s) that opened the bait, identified by waking up
	// exactly when SENTIENT1 let go. It runs a few ms after the open.
	OnOpen func(path string, at time.Time, pids []uint32)
	// OnOther runs for opens that don't read contents (delete, security checks).
	OnOther func(path string, access uint32)
	// Suspect (optional) picks, among programs paused inside an open, one
	// already known to be sweeping: it's reported before the open is let go.
	Suspect func(path string, pids []uint32) uint32
	Logf    func(format string, args ...any)
	Self    uint32
	Settle  time.Duration

	mu     sync.Mutex
	active map[string]windows.Handle // requested path -> stop event
	armed  map[string]windows.Handle // actual successful locks -> owning stop event
	wg     sync.WaitGroup
}

// Sync guards exactly the given paths (arming new ones, releasing removed ones).
func (w *Watcher) Sync(paths []string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.active == nil {
		w.active = map[string]windows.Handle{}
		w.armed = map[string]windows.Handle{}
	}
	want := map[string]bool{}
	for _, p := range paths {
		want[p] = true
		if _, ok := w.active[p]; !ok {
			stop, err := windows.CreateEvent(nil, 1, 0, nil)
			if err != nil {
				continue
			}
			w.active[p] = stop
			w.wg.Add(1)
			go w.guard(p, stop)
		}
	}
	for p, stop := range w.active {
		if !want[p] {
			windows.SetEvent(stop)
			delete(w.active, p)
			delete(w.armed, p)
		}
	}
}

// Release lets go of the given paths right away (e.g. before deleting them).
func (w *Watcher) Release(paths []string) {
	w.mu.Lock()
	for _, p := range paths {
		if stop, ok := w.active[p]; ok {
			windows.SetEvent(stop)
			delete(w.active, p)
			delete(w.armed, p)
		}
	}
	w.mu.Unlock()
}

// Stop releases every guard and waits for them to finish.
func (w *Watcher) Stop() {
	w.Sync(nil)
	w.wg.Wait()
}

// Count reports actual held locks, excluding missing, busy or failed paths.
func (w *Watcher) Count() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return len(w.armed)
}

func (w *Watcher) markArmed(path string, stop windows.Handle, armed bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if armed {
		if w.active[path] == stop {
			w.armed[path] = stop
		}
	} else if w.armed[path] == stop {
		delete(w.armed, path)
	}
}

func (w *Watcher) logf(f string, a ...any) {
	if w.Logf != nil {
		w.Logf(f, a...)
	}
}

func (w *Watcher) guard(path string, stop windows.Handle) {
	defer w.wg.Done()
	defer w.markArmed(path, stop, false)
	defer windows.CloseHandle(stop)
	settle := w.Settle
	if settle == 0 {
		settle = 60 * time.Millisecond
	}
	stopped := func(d time.Duration) bool {
		r, _ := windows.WaitForSingleObject(stop, uint32(d.Milliseconds()))
		return r == windows.WAIT_OBJECT_0
	}
	for {
		g, err := Arm(path)
		if err != nil {
			if stopped(time.Second) { // busy or missing: retry quietly
				return
			}
			continue
		}
		w.markArmed(path, stop, true)
		r, _ := windows.WaitForMultipleObjects([]windows.Handle{g.Event(), stop}, false, windows.INFINITE)
		w.markArmed(path, stop, false)
		if r != windows.WAIT_OBJECT_0 {
			g.Release()
			return
		}
		tick0, at := Tick(), time.Now()
		// Only opens that can read the contents count. Windows reports the
		// requested access for some opens (e.g. delete) but not for plain reads,
		// so "unknown" is treated as a possible read.
		access, known := g.OpenerAccess()
		if known && !WantsContents(access) {

			if w.OnOther != nil {
				w.OnOther(path, access)
			}
			g.Release()
			if stopped(150 * time.Millisecond) {
				return
			}
			continue
		}
		// SENTIENT1's own threads are included on purpose: when SENTIENT1 itself reads a
		// bait (health check, repair), its stuck thread is the opener. Leaving it
		// out made any program that happened to wake at that instant look like
		// the opener, and get frozen for a read it never made.
		stuck := FindStuck(tick0, 0, settle)
		// A program already known to be sweeping (it read other apps' data) is
		// decided while the open is still paused, so it never gets this file.
		if w.Suspect != nil && !selfIn(stuck, w.Self) {
			if p := w.Suspect(path, stuckPIDs(stuck)); p != 0 {
				w.logf("instant: %s opened while pid %d (already sweeping) was paused in it", path, p)
				w.report(path, at, []uint32{p})
				g.Release()
				if stopped(150 * time.Millisecond) {
					return
				}
				continue
			}
		}
		g.Release()
		pids := Woke(stuck, 0, 3*time.Millisecond)
		if selfIn(stuck, w.Self) {
			pids = nil // our own read
		} else if len(pids) > 1 {
			// More than one program woke at that instant: don't guess. The
			// event-log path still catches whichever one actually reads.
			w.logf("instant: %s opened, but %v all woke at once; leaving it to the event log", path, pids)
			pids = nil
		} else if len(pids) == 1 {
			w.logf("instant: %s opened by pid %d", path, pids[0])
		}
		w.report(path, at, pids)
		// Give the opener time to finish before re-arming (a trusted reader may
		// still hold the file; Arm just retries until it's free).
		if stopped(150 * time.Millisecond) {
			return
		}
	}
}

func (w *Watcher) report(path string, at time.Time, pids []uint32) {
	if w.OnOpen == nil {
		return
	}
	defer func() {
		if p := recover(); p != nil {
			w.logf("instant freeze handler panicked: %v", p)
		}
	}()
	w.OnOpen(path, at, pids)
}

func stuckPIDs(stuck []Thread) []uint32 {
	seen := map[uint32]bool{}
	var out []uint32
	for _, t := range stuck {
		if !seen[t.PID] {
			seen[t.PID] = true
			out = append(out, t.PID)
		}
	}
	return out
}

const outFlagModesProvided = 0x2

// OpenerAccess returns the access the opener asked for, when Windows says.
func (g *Guard) OpenerAccess() (uint32, bool) {
	if g.out.Flags&outFlagModesProvided == 0 {
		return 0, false
	}
	return g.out.AccessMode, true
}

// WantsContents reports whether an access mask can read the file's data.
func WantsContents(access uint32) bool {
	const (
		fileReadData   = 0x00000001
		fileExecute    = 0x00000020
		maximumAllowed = 0x02000000
		genericAll     = 0x10000000
		genericExecute = 0x20000000
		genericRead    = 0x80000000
	)
	return access&(fileReadData|fileExecute|maximumAllowed|genericAll|genericExecute|genericRead) != 0
}
