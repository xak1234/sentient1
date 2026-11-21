package update

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/xak1234/sentient1/internal/install"
	"github.com/xak1234/sentient1/internal/paths"
	"github.com/xak1234/sentient1/internal/svcctl"
)

// Dir holds downloaded updates and the rollback copy. It lives under
// Program Files, so only administrators and SYSTEM can write to it.
func Dir() string { return filepath.Join(paths.InstallDir(), "updates") }

// Apply installs the verified exe at src as the CLI and the service binary,
// then restarts the service. If the new service doesn't come up, the
// previous binaries are put back and restarted.
func Apply(src string, logf func(string, ...any)) error {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	if !paths.Under(src, Dir()) {
		return fmt.Errorf("refusing to install %s: updates must come from %s", src, Dir())
	}
	backup := filepath.Join(Dir(), "rollback.exe")
	if _, err := os.Stat(paths.InstalledService()); err == nil {
		if err := install.CopyFile(paths.InstalledService(), backup); err != nil {
			return fmt.Errorf("back up the current version: %w", err)
		}
	}
	swap := func(from string) error {
		for _, dst := range []string{paths.InstalledCLI(), paths.InstalledService()} {
			if err := install.CopyFile(from, dst); err != nil {
				return fmt.Errorf("%s: %w", dst, err)
			}
		}
		return nil
	}
	if err := svcctl.Stop(); err != nil {
		return fmt.Errorf("stop the service: %w", err)
	}
	if err := swap(src); err != nil {
		logf("update: install failed (%v); restoring the previous version", err)
		swap(backup)
		svcctl.Start()
		return err
	}
	if err := svcctl.Start(); err != nil {
		logf("update: new version did not start (%v); rolling back", err)
		if e := swap(backup); e != nil {
			logf("update: rollback copy failed: %v", e)
		}
		if e := svcctl.Start(); e != nil {
			logf("update: previous version did not start either: %v", e)
		}
		return fmt.Errorf("the new version failed to start, so the previous one was restored: %w", err)
	}
	return nil
}

// Cleanup removes old downloads, keeping keep (the file in use, if any) and
// the rollback copy.
func Cleanup(keep string) {
	files, _ := filepath.Glob(filepath.Join(Dir(), "sentient1-*.exe*"))
	for _, f := range files {
		if keep != "" && paths.Same(f, keep) {
			continue
		}
		if strings.HasSuffix(strings.ToLower(f), "rollback.exe") {
			continue
		}
		os.Remove(f)
	}
}
