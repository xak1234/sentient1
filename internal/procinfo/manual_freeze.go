package procinfo

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var isProcessCritical = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessCritical")

// ManualFreezeProtected covers Windows desktop infrastructure and this monitor.
// The native critical-process check and session check provide additional guards.
func ManualFreezeProtected(image string) bool {
	switch strings.ToLower(BaseName(image)) {
	case "system", "registry", "memory compression", "secure system",
		"csrss.exe", "lsass.exe", "wininit.exe", "winlogon.exe", "services.exe",
		"smss.exe", "svchost.exe", "explorer.exe", "dwm.exe", "msmpeng.exe",
		"fontdrvhost.exe", "lsaiso.exe", "sihost.exe", "ctfmon.exe", "audiodg.exe",
		"conhost.exe", "runtimebroker.exe", "searchhost.exe", "sentient1.exe",
		"sentient1svc.exe", "sentient1-desktop.exe":
		return true
	}
	return false
}

// OpenManualFreezeTarget returns a held reference to the exact recorded process.
// The caller must keep it open through suspension and state persistence: an open
// process handle prevents Windows from reusing that PID even if the process exits.
// Read-only availability checks do not request suspension access.
func OpenManualFreezeTarget(pid uint32, created int64, image string, suspend bool) (windows.Handle, error) {
	if pid == 0 || pid == 4 || pid == uint32(os.Getpid()) || ManualFreezeProtected(image) {
		return 0, fmt.Errorf("this Windows or monitor process is protected from manual freezing")
	}
	if created == 0 || image == "" {
		return 0, fmt.Errorf("this alert has no recorded process creation time; its PID cannot be identified safely")
	}
	access := uint32(windows.PROCESS_QUERY_LIMITED_INFORMATION | windows.SYNCHRONIZE)
	if suspend {
		access |= processSuspendResume
	}
	h, err := open(pid, access)
	if err != nil {
		return 0, fmt.Errorf("process unavailable or Windows denied access: %w", err)
	}
	fail := func(err error) (windows.Handle, error) { windows.CloseHandle(h); return 0, err }
	var start, end, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &start, &end, &kernel, &user); err != nil {
		return fail(fmt.Errorf("cannot verify process creation time: %w", err))
	}
	actual := int64(start.HighDateTime)<<32 | int64(start.LowDateTime)
	if actual != created {
		return fail(fmt.Errorf("the recorded process has exited and its PID now belongs to another process"))
	}
	status, err := windows.WaitForSingleObject(h, 0)
	if err != nil || status != uint32(windows.WAIT_TIMEOUT) {
		return fail(fmt.Errorf("the recorded process is no longer running"))
	}
	path := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(path))
	if err := windows.QueryFullProcessImageName(h, 0, &path[0], &n); err != nil {
		return fail(fmt.Errorf("cannot verify process executable: %w", err))
	}
	if !strings.EqualFold(windows.UTF16ToString(path[:n]), image) {
		return fail(fmt.Errorf("the executable does not match the recorded alert"))
	}
	var session uint32
	if err := windows.ProcessIdToSessionId(pid, &session); err != nil || session == 0 {
		return fail(fmt.Errorf("system-service processes are excluded from manual freezing"))
	}
	if err := isProcessCritical.Find(); err != nil {
		return fail(fmt.Errorf("Windows critical-process checks are unavailable: %w", err))
	}
	var critical int32
	ok, _, callErr := isProcessCritical.Call(uintptr(h), uintptr(unsafe.Pointer(&critical)))
	if ok == 0 {
		return fail(fmt.Errorf("cannot check whether Windows requires this process: %v", callErr))
	}
	if critical != 0 {
		return fail(fmt.Errorf("Windows marks this process as critical"))
	}
	return h, nil
}
