// Package session starts a process on the desktop of every logged-in user.
// The service runs as SYSTEM in session 0, which has no desktop, so popups
// must be launched into the users' sessions with their own tokens.
package session

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const wtsActive = 0

// LaunchInActiveSessions runs exe with args as each active user (not elevated).
// It returns the number of sessions it launched into.
func LaunchInActiveSessions(exe string, args ...string) (int, error) {
	var info *windows.WTS_SESSION_INFO
	var count uint32
	if err := windows.WTSEnumerateSessions(0, 0, 1, &info, &count); err != nil {
		return 0, err
	}
	defer windows.WTSFreeMemory(uintptr(unsafe.Pointer(info)))
	sessions := unsafe.Slice(info, count)
	n := 0
	var firstErr error
	for _, s := range sessions {
		if s.State != wtsActive || s.SessionID == 0 {
			continue
		}
		if err := launch(s.SessionID, exe, args); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("session %d: %w", s.SessionID, err)
			}
			continue
		}
		n++
	}
	return n, firstErr
}

func launch(sessionID uint32, exe string, args []string) error {
	var tok windows.Token
	if err := windows.WTSQueryUserToken(sessionID, &tok); err != nil {
		return err
	}
	defer tok.Close()
	var env *uint16
	if err := windows.CreateEnvironmentBlock(&env, tok, false); err != nil {
		return err
	}
	defer windows.DestroyEnvironmentBlock(env)

	parts := []string{syscall.EscapeArg(exe)}
	for _, a := range args {
		parts = append(parts, syscall.EscapeArg(a))
	}
	cmd, _ := windows.UTF16PtrFromString(strings.Join(parts, " "))
	app, _ := windows.UTF16PtrFromString(exe)
	desk, _ := windows.UTF16PtrFromString(`winsta0\default`)
	si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{})), Desktop: desk}
	var pi windows.ProcessInformation
	err := windows.CreateProcessAsUser(tok, app, cmd, nil, nil, false,
		windows.CREATE_UNICODE_ENVIRONMENT|windows.CREATE_NO_WINDOW, env, nil, &si, &pi)
	if err != nil {
		return err
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	return nil
}
