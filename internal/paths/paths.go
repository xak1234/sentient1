// Package paths centralises every on-disk location and name SENTIENT1 uses.
//
// The installed footprint deliberately uses neutral names ("sentient1 Monitor")
// so that a stealer enumerating services or Program Files does not immediately
// spot a honeypot tool and skip its file-grabbing stage. This is low-profile,
// not hidden: everything is documented and visible to an administrator.
package paths

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

const (
	ProductName = "sentient1"

	ServiceName        = "sentient1Monitor"
	ServiceDisplayName = "sentient1 Monitor"
	ServiceDescription = "Watches decoy files and reacts when something reads them (sentient1)."

	installDirName = "sentient1 Monitor"
	dataDirName    = "sentient1Monitor"

	CLIExe     = "sentient1.exe"    // what users type; on PATH
	ServiceExe = "sentient1svc.exe" // identical copy the service runs from
)

// InstallDir is admin-write-only (Program Files), so the SYSTEM service can
// never be made to run attacker-controlled code.
func InstallDir() string {
	return filepath.Join(programFiles(), installDirName)
}

func InstalledCLI() string     { return filepath.Join(InstallDir(), CLIExe) }
func InstalledService() string { return filepath.Join(InstallDir(), ServiceExe) }

// DataDir holds config, state and alerts. SYSTEM/Administrators can write,
// Users can read (so the notifier and `sentient1 status` work unelevated).
func DataDir() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, dataDirName)
}

func ConfigFile() string  { return filepath.Join(DataDir(), "config.json") }
func StateFile() string   { return filepath.Join(DataDir(), "state.json") }
func SecretsFile() string { return filepath.Join(DataDir(), "secrets.json") } // admin-only ACL + DPAPI
func AlertsDir() string   { return filepath.Join(DataDir(), "alerts") }
func LogFile() string     { return filepath.Join(DataDir(), "service.log") }
func TestFile() string    { return filepath.Join(DataDir(), "pending-test.json") }

func programFiles() string {
	if p, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0); err == nil && p != "" {
		return p
	}
	if p := os.Getenv("ProgramFiles"); p != "" {
		return p
	}
	return `C:\Program Files`
}

// Clean normalises a path for case-insensitive comparison.
func Clean(p string) string {
	return strings.ToLower(filepath.Clean(p))
}

// Same reports whether two paths refer to the same location (case-insensitive).
func Same(a, b string) bool { return Clean(a) == Clean(b) }

// Under reports whether p is inside dir (case-insensitive).
func Under(p, dir string) bool {
	if dir == "" {
		return false
	}
	p, dir = Clean(p), Clean(dir)
	if !strings.HasSuffix(dir, `\`) {
		dir += `\`
	}
	return strings.HasPrefix(p, dir)
}

// Long expands 8.3 short names (C:\Users\VULNIX~1 -> C:\Users\vulnix0x4) so
// the same file always compares equal. It only queries directory entries,
// never file contents, so it's safe to call on baits. Paths that don't exist
// are returned unchanged.
func Long(p string) string {
	if !strings.Contains(p, "~") {
		return p
	}
	u, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return p
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := windows.GetLongPathName(u, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || int(n) > len(buf) {
		return p
	}
	return windows.UTF16ToString(buf[:n])
}

// Key is the canonical form used to look paths up in maps.
func Key(p string) string { return Clean(Long(p)) }
