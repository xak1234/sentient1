package cli

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/xak1234/sentient1/internal/procinfo"
	"github.com/xak1234/sentient1/internal/ui"
	"github.com/xak1234/sentient1/internal/winsec"
)

// pauseFlag is added when we relaunch ourselves elevated, so the new console
// window stays open long enough to read the result.
const pauseFlag = "--elevated-pause"

type shellExecuteInfo struct {
	cbSize       uint32
	fMask        uint32
	hwnd         uintptr
	lpVerb       *uint16
	lpFile       *uint16
	lpParameters *uint16
	lpDirectory  *uint16
	nShow        int32
	hInstApp     uintptr
	lpIDList     uintptr
	lpClass      *uint16
	hkeyClass    uintptr
	dwHotKey     uint32
	hIcon        uintptr
	hProcess     windows.Handle
}

var procShellExecuteEx = windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW")

var errRelaunched = errors.New("continued in the administrator window")

// requireAdmin returns nil if elevated. Otherwise it relaunches the same
// command through UAC, waits for it, and returns errRelaunched.
func requireAdmin() error {
	if winsec.IsElevated() {
		return nil
	}
	exe, _ := os.Executable()
	var args []string
	for _, a := range os.Args[1:] {
		if a != pauseFlag {
			args = append(args, syscall.EscapeArg(a))
		}
	}
	args = append(args, pauseFlag)
	fmt.Println()
	fmt.Println(" " + ui.Warn.Bold(true).Render("!") + " " + ui.Plain.Render("This needs administrator rights.") +
		ui.Dim.Render(" Approve the Windows prompt and it carries on in a new window."))

	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(strings.Join(args, " "))
	cwd, _ := os.Getwd()
	dir, _ := windows.UTF16PtrFromString(cwd)
	sei := shellExecuteInfo{fMask: 0x40 /* SEE_MASK_NOCLOSEPROCESS */, lpVerb: verb, lpFile: file, lpParameters: params, lpDirectory: dir, nShow: windows.SW_SHOWNORMAL}
	sei.cbSize = uint32(unsafe.Sizeof(sei))
	if r, _, e := procShellExecuteEx.Call(uintptr(unsafe.Pointer(&sei))); r == 0 {
		if errors.Is(e, windows.ERROR_CANCELLED) {
			return errors.New("administrator permission was declined")
		}
		return fmt.Errorf("could not elevate: %v", e)
	}
	if sei.hProcess != 0 {
		windows.WaitForSingleObject(sei.hProcess, windows.INFINITE)
		var code uint32
		windows.GetExitCodeProcess(sei.hProcess, &code)
		windows.CloseHandle(sei.hProcess)
		if code != 0 {
			return fmt.Errorf("the administrator window reported an error (exit code %d)", code)
		}
	}
	fmt.Println(" " + ui.Good.Render(ui.IconOK) + " " + ui.Plain.Render("Done") + ui.Dim.Render(" (in the administrator window)."))
	return errRelaunched
}

// shouldPause: keep the window open when we were relaunched elevated or
// double-clicked from Explorer (the console would vanish instantly otherwise).
func shouldPause() bool {
	for _, a := range os.Args {
		if a == pauseFlag {
			return true
		}
	}
	snap, err := procinfo.Snapshot()
	if err != nil {
		return false
	}
	me, ok := snap[uint32(os.Getpid())]
	if !ok {
		return false
	}
	return strings.EqualFold(snap[me.PPID].Exe, "explorer.exe")
}

func pause() {
	fmt.Print("\n " + ui.Fainter.Render("Press Enter to close this window…"))
	bufio.NewReader(os.Stdin).ReadString('\n')
}
