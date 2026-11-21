package procinfo

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	memPrivate = 0x20000
	execMask   = windows.PAGE_EXECUTE | windows.PAGE_EXECUTE_READ | windows.PAGE_EXECUTE_READWRITE | windows.PAGE_EXECUTE_WRITECOPY

	// Hooks, trampolines and thunks that other software (overlays, shell
	// extensions, security tools) puts into processes are small: a page here,
	// a 64 KB block there. An injected stealer is a whole program, typically
	// hundreds of KB in one block, so judge per allocation, not in total.
	injectedMin = 256 << 10
)

// jitModules mark processes that legitimately generate code at run time
// (.NET, Java, script engines): their private executable memory proves nothing.
var jitModules = map[string]bool{
	"clr.dll": true, "coreclr.dll": true, "clrjit.dll": true, "mscorwks.dll": true, "mscorjit.dll": true,
	"jvm.dll": true, "mono-2.0-bdwgc.dll": true, "mono.dll": true, "libcef.dll": true, "v8.dll": true,
	"chakra.dll": true, "jscript9.dll": true, "edgehtml.dll": true, "luajit.dll": true,
}

// InjectedCode looks inside a running process for executable memory that
// isn't backed by any file on disk: the footprint of injected or "hollowed"
// code (a stealer running inside a legitimate program). It reports a short
// description when it finds some. Processes that host a JIT compiler are
// skipped (ok=false), since generating code is their normal behaviour.
func InjectedCode(pid uint32) (detail string, found bool) {
	h, err := open(pid, windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ)
	if err != nil {
		return "", false
	}
	defer windows.CloseHandle(h)
	if jit := hostsJIT(h); jit != "" {
		return "", false
	}

	blocks := map[uintptr]uintptr{} // allocation base -> executable bytes
	withPE := 0
	var mbi windows.MemoryBasicInformation
	for addr := uintptr(0); ; {
		if err := windows.VirtualQueryEx(h, addr, &mbi, unsafe.Sizeof(mbi)); err != nil {
			break
		}
		if mbi.State == windows.MEM_COMMIT && mbi.Type == memPrivate &&
			mbi.Protect&execMask != 0 && mbi.Protect&windows.PAGE_GUARD == 0 {
			blocks[mbi.AllocationBase] += mbi.RegionSize
			var hdr [2]byte
			var n uintptr
			if windows.ReadProcessMemory(h, mbi.BaseAddress, &hdr[0], 2, &n) == nil && n == 2 && hdr[0] == 'M' && hdr[1] == 'Z' {
				withPE++
			}
		}
		next := mbi.BaseAddress + mbi.RegionSize
		if next <= addr {
			break
		}
		addr = next
	}
	var biggest uintptr
	for _, size := range blocks {
		if size > biggest {
			biggest = size
		}
	}
	if withPE == 0 && biggest < injectedMin {
		return "", false
	}
	if withPE > 0 {
		return fmt.Sprintf("it's running a whole program from memory that isn't backed by any file on disk (%d KB): code was injected into it", biggest>>10), true
	}
	return fmt.Sprintf("it's running %d KB of code that isn't from any file on disk: code was injected into it", biggest>>10), true
}

// hostsJIT returns the name of a JIT module loaded in the process, if any.
func hostsJIT(h windows.Handle) string {
	mods := make([]windows.Handle, 1024)
	var need uint32
	if err := windows.EnumProcessModulesEx(h, &mods[0], uint32(len(mods))*uint32(unsafe.Sizeof(mods[0])), &need, windows.LIST_MODULES_ALL); err != nil {
		return ""
	}
	n := int(need / uint32(unsafe.Sizeof(mods[0])))
	if n > len(mods) {
		n = len(mods)
	}
	buf := make([]uint16, 260)
	for _, m := range mods[:n] {
		if windows.GetModuleBaseName(h, m, &buf[0], uint32(len(buf))) != nil {
			continue
		}
		if name := strings.ToLower(windows.UTF16ToString(buf)); jitModules[name] {
			return name
		}
	}
	return ""
}
