package service

import (
	"context"
	"math/rand/v2"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"github.com/xak1234/sentient1/internal/config"
	"github.com/xak1234/sentient1/internal/session"
	"github.com/xak1234/sentient1/internal/update"
)

// updateLoop checks for a new signed release a few minutes after start, then
// about once a day, when the user turned automatic updates on.
func (s *server) updateLoop(ctx context.Context) {
	wait := 5*time.Minute + rand.N(15*time.Minute)
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		s.safe("update check", func() { s.checkForUpdate(ctx) })
		wait = 24*time.Hour + rand.N(2*time.Hour)
	}
}

// learningCheck announces, once, that learning mode has ended (only when it
// actually changes something, i.e. non-critical readers have responses).
func (s *server) learningCheck() {
	s.mu.Lock()
	cfg := s.cfg
	s.mu.Unlock()
	if cfg == nil || cfg.LearningUntil.IsZero() || cfg.Learning(time.Now()) || !cfg.LearningMatters() {
		return
	}
	st, err := config.LoadState()
	if err != nil || st.LearningNotice.Equal(cfg.LearningUntil) {
		return
	}
	if time.Since(cfg.LearningUntil) > 7*24*time.Hour {
		// Ended long ago (service was off): just record it, no stale toast.
	} else if n, err := session.LaunchInActiveSessions(s.cliExe, "notify", "--learning-ended"); err != nil || n == 0 {
		return // nobody signed in yet: try again at the next check
	}
	until := cfg.LearningUntil
	config.UpdateState(func(st *config.State) error { st.LearningNotice = until; return nil })
	s.log.Printf("learning mode ended (%s); user notified", until.Format(time.RFC3339))
}

func recordUpdate(latest, result string) {
	config.UpdateState(func(st *config.State) error {
		if st.Update == nil {
			st.Update = &config.UpdateStatus{}
		}
		st.Update.LastCheck = time.Now()
		if latest != "" {
			st.Update.Latest = latest
		}
		st.Update.LastResult = result
		return nil
	})
}

func (s *server) checkForUpdate(ctx context.Context) {
	s.mu.Lock()
	on := s.cfg != nil && s.cfg.AutoUpdate
	s.mu.Unlock()
	if !on || !update.Enabled() || !update.Updatable(Version) {
		return
	}
	// Never touch the install while something is frozen or the PC is isolated:
	// a restart in the middle of an incident is the last thing you want.
	if st, err := config.LoadState(); err == nil && (st.Isolation != nil || len(st.Frozen) > 0) {
		s.log.Printf("update check skipped: an incident is in progress")
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	rel, err := update.Latest(ctx)
	if err != nil {
		s.log.Printf("update check: %v", err)
		recordUpdate("", "check failed: "+err.Error())
		return
	}
	if !update.Newer(Version, rel.Tag) {
		recordUpdate(rel.Tag, "up to date")
		return
	}
	s.log.Printf("update: %s is available (running %s); downloading", rel.Tag, Version)
	exe, err := update.Download(ctx, rel, update.Dir())
	if err != nil {
		s.log.Printf("update: %v", err)
		recordUpdate(rel.Tag, "not installed: "+err.Error())
		return
	}
	update.Cleanup(exe)
	s.log.Printf("update: %s verified (signature + checksum); handing over to it", rel.Tag)
	recordUpdate(rel.Tag, "installing "+rel.Tag)

	// The new binary stops this service, swaps the files and starts itself.
	// It must outlive us, so it runs detached.
	cmd := exec.Command(exe, "update", "apply", "--file", exe, "--from", Version)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NEW_PROCESS_GROUP | windows.DETACHED_PROCESS,
	}
	if err := cmd.Start(); err != nil {
		s.log.Printf("update: could not start the installer: %v", err)
		recordUpdate(rel.Tag, "not installed: "+err.Error())
		return
	}
	cmd.Process.Release()
}
