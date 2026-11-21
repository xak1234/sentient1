// Command medium launches a program at medium integrity, i.e. as an ordinary,
// non-admin process, from an elevated shell, and prints its PID.
//
// CI-only helper: GitHub's runners run everything as administrator, but real
// stealers run as the normal user. The e2e test uses this to launch its fake
// stealers realistically. Not part of SENTIENT1.
//
//	medium.exe "C:\path\to\program.exe" args...
package main

import (
	"fmt"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func main() {
	// medium -raw <program> <command line>: the command line is passed as is,
	// with single quotes turned into double quotes (for programs like find.exe
	// that insist on quotes, which PowerShell 5 mangles).
	if len(os.Args) == 4 && os.Args[1] == "-raw" {
		if err := run(os.Args[2], strings.ReplaceAll(os.Args[3], "'", "\"")); err != nil {
			fmt.Fprintln(os.Stderr, "medium:", err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: medium <program> [args...]")
		os.Exit(2)
	}
	parts := make([]string, len(os.Args)-1)
	for i, a := range os.Args[1:] {
		parts[i] = syscall.EscapeArg(a)
	}
	if err := run(os.Args[1], strings.Join(parts, " ")); err != nil {
		fmt.Fprintln(os.Stderr, "medium:", err)
		os.Exit(1)
	}
}

func run(app, cmdline string) error {
	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ADJUST_DEFAULT|windows.TOKEN_ASSIGN_PRIMARY, &tok); err != nil {
		return fmt.Errorf("open token: %w", err)
	}
	defer tok.Close()
	var dup windows.Token
	if err := windows.DuplicateTokenEx(tok, windows.MAXIMUM_ALLOWED, nil, windows.SecurityImpersonation, windows.TokenPrimary, &dup); err != nil {
		return fmt.Errorf("duplicate token: %w", err)
	}
	defer dup.Close()

	medium, err := windows.StringToSid("S-1-16-8192") // Mandatory Label\Medium
	if err != nil {
		return err
	}
	label := windows.Tokenmandatorylabel{Label: windows.SIDAndAttributes{Sid: medium, Attributes: windows.SE_GROUP_INTEGRITY}}
	if err := windows.SetTokenInformation(dup, windows.TokenIntegrityLevel,
		(*byte)(unsafe.Pointer(&label)), uint32(unsafe.Sizeof(label))+windows.GetLengthSid(medium)); err != nil {
		return fmt.Errorf("lower integrity: %w", err)
	}

	appp, _ := windows.UTF16PtrFromString(app)
	cmd, _ := windows.UTF16PtrFromString(cmdline)
	si := windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfo{}))}
	var pi windows.ProcessInformation
	if err := windows.CreateProcessAsUser(dup, appp, cmd, nil, nil, false, windows.CREATE_NO_WINDOW, nil, nil, &si, &pi); err != nil {
		return fmt.Errorf("create process: %w", err)
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(pi.Process)
	fmt.Println(pi.ProcessId)
	return nil
}
