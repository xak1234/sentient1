// Package procinfo inspects and controls processes: image path, command line,
// parent chain, process trees, suspend/resume/kill, hashes and open connections.
package procinfo

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Entry is one row of a process snapshot.
type Entry struct {
	PID        uint32
	PPID       uint32
	Exe        string // file name only
	CreateTime int64  // 0 if unavailable
}

// Snapshot lists all processes.
func Snapshot() (map[uint32]Entry, error) {
	h, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)
	out := map[uint32]Entry{}
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	for err = windows.Process32First(h, &pe); err == nil; err = windows.Process32Next(h, &pe) {
		e := Entry{PID: pe.ProcessID, PPID: pe.ParentProcessID, Exe: windows.UTF16ToString(pe.ExeFile[:])}
		e.CreateTime, _ = CreateTime(pe.ProcessID)
		out[pe.ProcessID] = e
	}
	return out, nil
}

func open(pid uint32, access uint32) (windows.Handle, error) {
	return windows.OpenProcess(access, false, pid)
}

// CreateTime returns the process creation FILETIME as int64.
func CreateTime(pid uint32) (int64, error) {
	h, err := open(pid, windows.PROCESS_QUERY_LIMITED_INFORMATION)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(h)
	var c, e, k, u windows.Filetime
	if err := windows.GetProcessTimes(h, &c, &e, &k, &u); err != nil {
		return 0, err
	}
	return int64(c.HighDateTime)<<32 | int64(c.LowDateTime), nil
}

// ImagePath returns the full path of the process executable.
func ImagePath(pid uint32) (string, error) {
	h, err := open(pid, windows.PROCESS_QUERY_LIMITED_INFORMATION)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return "", err
	}
	return windows.UTF16ToString(buf[:n]), nil
}

// CommandLine returns the process command line (Windows 8.1+).
func CommandLine(pid uint32) (string, error) {
	h, err := open(pid, windows.PROCESS_QUERY_LIMITED_INFORMATION)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	var need uint32
	buf := make([]byte, 4096)
	for i := 0; i < 3; i++ {
		err = windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation, unsafe.Pointer(&buf[0]), uint32(len(buf)), &need)
		if err == nil {
			break
		}
		if need > uint32(len(buf)) {
			buf = make([]byte, need)
			continue
		}
		return "", err
	}
	if err != nil {
		return "", err
	}
	us := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0]))
	if us.Buffer == nil || us.Length == 0 {
		return "", nil
	}
	return windows.UTF16ToString(unsafe.Slice(us.Buffer, us.Length/2)), nil
}

// Parent describes one ancestor.
type Parent struct {
	PID         uint32 `json:"pid"`
	Image       string `json:"image,omitempty"`
	CommandLine string `json:"commandLine,omitempty"`
	Exited      bool   `json:"exited,omitempty"`
}

// ParentChain walks up to depth ancestors, stopping at PID reuse.
func ParentChain(snap map[uint32]Entry, pid uint32, depth int) []Parent {
	var out []Parent
	cur, ok := snap[pid]
	if !ok {
		return nil
	}
	for i := 0; i < depth; i++ {
		pp, ok := snap[cur.PPID]
		if !ok || cur.PPID == 0 || cur.PPID == cur.PID {
			if cur.PPID != 0 {
				out = append(out, Parent{PID: cur.PPID, Exited: true})
			}
			break
		}
		// A parent created after the child means the PID was reused.
		if pp.CreateTime != 0 && cur.CreateTime != 0 && pp.CreateTime > cur.CreateTime {
			out = append(out, Parent{PID: cur.PPID, Exited: true})
			break
		}
		p := Parent{PID: pp.PID, Image: pp.Exe}
		if img, err := ImagePath(pp.PID); err == nil {
			p.Image = img
		}
		p.CommandLine, _ = CommandLine(pp.PID)
		out = append(out, p)
		cur = pp
	}
	return out
}

// Tree returns pid and all its descendants (parents first), guarding against PID reuse.
func Tree(snap map[uint32]Entry, pid uint32) []uint32 {
	children := map[uint32][]uint32{}
	for _, e := range snap {
		if e.PID != e.PPID {
			children[e.PPID] = append(children[e.PPID], e.PID)
		}
	}
	for k := range children {
		sort.Slice(children[k], func(i, j int) bool { return children[k][i] < children[k][j] })
	}
	seen := map[uint32]bool{}
	out := []uint32{}
	var walk func(uint32)
	walk = func(p uint32) {
		if seen[p] {
			return
		}
		seen[p] = true
		out = append(out, p)
		parent := snap[p]
		for _, c := range children[p] {
			ce := snap[c]
			if parent.CreateTime != 0 && ce.CreateTime != 0 && ce.CreateTime < parent.CreateTime {
				continue // older than "parent": PID reuse, not a real child
			}
			walk(c)
		}
	}
	walk(pid)
	return out
}

var (
	ntdll             = windows.NewLazySystemDLL("ntdll.dll")
	procNtSuspendProc = ntdll.NewProc("NtSuspendProcess")
	procNtResumeProc  = ntdll.NewProc("NtResumeProcess")
)

const processSuspendResume = 0x0800

func ntCall(p *windows.LazyProc, pid uint32) error {
	h, err := open(pid, processSuspendResume)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	r, _, _ := p.Call(uintptr(h))
	if r != 0 {
		return fmt.Errorf("%s: NTSTATUS 0x%08x", p.Name, uint32(r))
	}
	return nil
}

func Suspend(pid uint32) error { return ntCall(procNtSuspendProc, pid) }
func Resume(pid uint32) error  { return ntCall(procNtResumeProc, pid) }

// Kill terminates a process.
func Kill(pid uint32) error {
	h, err := open(pid, windows.PROCESS_TERMINATE)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	return windows.TerminateProcess(h, 0xF1)
}

// Alive reports whether pid exists and (if createTime != 0) is the same process.
func Alive(pid uint32, createTime int64) bool {
	ct, err := CreateTime(pid)
	if err != nil {
		return false
	}
	if createTime != 0 && ct != createTime {
		return false
	}
	h, err := open(pid, windows.PROCESS_QUERY_LIMITED_INFORMATION)
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)
	var code uint32
	if err := windows.GetExitCodeProcess(h, &code); err != nil {
		return false
	}
	return code == 259 // STILL_ACTIVE
}

// SuspendTree freezes pid and its descendants. It re-snapshots once to catch
// children spawned while we were freezing. Returns the PIDs frozen.
func SuspendTree(pid uint32) ([]uint32, error) {
	var frozen []uint32
	done := map[uint32]bool{}
	var firstErr error
	// Freeze the reader itself immediately: every millisecond counts, and the
	// process snapshot below takes a while on a busy machine.
	if pid != 0 && pid != 4 && pid != uint32(os.Getpid()) {
		done[pid] = true
		if err := Suspend(pid); err != nil {
			firstErr = err
		} else {
			frozen = append(frozen, pid)
		}
	}
	for pass := 0; pass < 2; pass++ {
		snap, err := Snapshot()
		if err != nil {
			return frozen, err
		}
		for _, p := range Tree(snap, pid) {
			if done[p] || p == 0 || p == 4 || p == uint32(os.Getpid()) {
				continue
			}
			done[p] = true
			if err := Suspend(p); err != nil {
				if firstErr == nil && p == pid {
					firstErr = err
				}
				continue
			}
			frozen = append(frozen, p)
		}
	}
	return frozen, firstErr
}

// KillTree terminates pid and its descendants (children first).
func KillTree(pid uint32) error {
	snap, err := Snapshot()
	if err != nil {
		return err
	}
	tree := Tree(snap, pid)
	var firstErr error
	for i := len(tree) - 1; i >= 0; i-- {
		if tree[i] == uint32(os.Getpid()) {
			continue
		}
		if err := Kill(tree[i]); err != nil && firstErr == nil && tree[i] == pid {
			firstErr = err
		}
	}
	return firstErr
}

// FileSHA256 hashes a file (used on the reader's executable, never on baits).
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// BaseName is a case-preserving file name of a Windows path.
func BaseName(p string) string {
	if p == "" {
		return ""
	}
	return filepath.Base(strings.ReplaceAll(p, "/", `\`))
}

// Integrity levels (the RID of the token's mandatory label).
const (
	IntegrityLow    = 0x1000
	IntegrityMedium = 0x2000
	IntegrityHigh   = 0x3000
	IntegritySystem = 0x4000
)

// IntegrityLevel returns the process token's integrity RID.
func IntegrityLevel(pid uint32) (uint32, error) {
	h, err := open(pid, windows.PROCESS_QUERY_LIMITED_INFORMATION)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(h)
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return 0, err
	}
	defer tok.Close()
	var n uint32
	windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, nil, 0, &n)
	if n == 0 {
		return 0, fmt.Errorf("no integrity level")
	}
	buf := make([]byte, n)
	if err := windows.GetTokenInformation(tok, windows.TokenIntegrityLevel, &buf[0], n, &n); err != nil {
		return 0, err
	}
	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&buf[0]))
	sid := label.Label.Sid
	c := sid.SubAuthorityCount()
	if c == 0 {
		return 0, fmt.Errorf("bad integrity SID")
	}
	return sid.SubAuthority(uint32(c) - 1), nil
}
