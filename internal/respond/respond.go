// Package respond undoes or finishes responses: release isolation, resume or
// kill frozen processes, unblock programs. Used by the elevated CLI.
package respond

import (
	"errors"
	"fmt"
	"strings"

	"github.com/xak1234/sentient1/internal/alerts"
	"github.com/xak1234/sentient1/internal/config"
	"github.com/xak1234/sentient1/internal/netguard"
	"github.com/xak1234/sentient1/internal/procinfo"
)

// Report lists what was done.
type Report struct {
	Lines  []string
	Errors []string
}

func (r *Report) ok(f string, a ...any)  { r.Lines = append(r.Lines, fmt.Sprintf(f, a...)) }
func (r *Report) bad(f string, a ...any) { r.Errors = append(r.Errors, fmt.Sprintf(f, a...)) }

// Err makes partial failures visible to scripts and the desktop application.
func (r *Report) Err() error {
	if len(r.Errors) == 0 {
		return nil
	}
	return errors.New(strings.Join(r.Errors, "; "))
}

// Release restores the network and resumes/unblocks everything (alertID ""),
// or only what belongs to one alert.
func Release(alertID string) (*Report, error) {
	rep := &Report{}

	// 1. Network first, without the state lock. Getting the user back online
	// must never depend on the service being responsive: if it's busy or
	// stuck holding the lock, isolation would otherwise stay in place.
	snap, _ := config.LoadState() // lock-free read (writes are atomic renames)
	ours := alertID == "" || (snap != nil && snap.Isolation != nil && snap.Isolation.AlertID == alertID)
	wfpOK, adaptersOK := false, false
	if ours {
		if err := netguard.Unisolate(); err != nil {
			rep.bad("remove isolation: %v", err)
		} else {
			wfpOK = true
			if snap == nil || snap.Isolation != nil || alertID == "" {
				rep.ok("network isolation removed")
			}
		}
		if snap != nil && len(snap.DisabledAdapters) > 0 {
			if err := netguard.EnableAdapters(snap.DisabledAdapters); err != nil {
				rep.bad("re-enable adapters: %v", err)
			} else {
				adaptersOK = true
				rep.ok("re-enabled adapters: %s", strings.Join(snap.DisabledAdapters, ", "))
			}
		}
	}

	// 2. Unfreeze and unblock, and record it all, under the lock.
	err := config.UpdateState(func(st *config.State) error {
		if ours {
			clearRecoveredNetwork(st, snap, wfpOK, adaptersOK)
		}
		st.Frozen = resumeWhere(st.Frozen, alertID, rep)
		st.Blocked = unblockWhere(st.Blocked, alertID, rep)
		return nil
	})
	if err != nil {
		// Still undo what we can without the bookkeeping.
		if snap != nil {
			resumeWhere(snap.Frozen, alertID, rep)
			unblockWhere(snap.Blocked, alertID, rep)
		}
		rep.bad("could not update sentient1 records: %v; inspect the operation results above", err)
		return rep, rep.Err()
	}
	if rep.Err() == nil {
		if err := markResolved(alertID, "released"); err != nil {
			rep.bad("save resolved alerts: %v", err)
		}
	}
	return rep, rep.Err()
}

func resumeWhere(frozen []config.FrozenProcess, alertID string, rep *Report) []config.FrozenProcess {
	var keep []config.FrozenProcess
	for _, f := range frozen {
		if alertID != "" && f.AlertID != alertID {
			keep = append(keep, f)
			continue
		}
		if f.CreateTime == 0 {
			rep.bad("cannot safely identify pid %d; creation time is unavailable", f.PID)
			keep = append(keep, f)
			continue
		}
		if !procinfo.Alive(f.PID, f.CreateTime) {
			continue
		}
		if err := procinfo.Resume(f.PID); err != nil {
			rep.bad("resume pid %d: %v", f.PID, err)
			keep = append(keep, f)
		} else {
			rep.ok("resumed %s (pid %d)", procinfo.BaseName(f.Image), f.PID)
		}
	}
	return keep
}

func unblockWhere(blocked []config.BlockedProgram, alertID string, rep *Report) []config.BlockedProgram {
	var keep []config.BlockedProgram
	for _, b := range blocked {
		if alertID != "" && b.AlertID != alertID {
			keep = append(keep, b)
			continue
		}
		if err := netguard.UnblockProgram(b.Path); err != nil {
			rep.bad("unblock %s: %v", b.Path, err)
			keep = append(keep, b)
		} else {
			rep.ok("internet restored for %s", b.Path)
		}
	}
	return keep
}

// Kill terminates the processes frozen for an alert. The program stays blocked.
func Kill(alertID string) (*Report, error) {
	rep := &Report{}
	a, err := alerts.Load(alertID)
	if err != nil {
		return rep, err
	}
	err = config.UpdateState(func(st *config.State) error {
		var keep []config.FrozenProcess
		for _, f := range st.Frozen {
			if f.AlertID != a.ID {
				keep = append(keep, f)
				continue
			}
			if f.CreateTime == 0 {
				rep.bad("cannot safely identify pid %d; creation time is unavailable", f.PID)
				keep = append(keep, f)
				continue
			}
			if !procinfo.Alive(f.PID, f.CreateTime) {
				continue
			}
			if err := procinfo.Kill(f.PID); err != nil {
				rep.bad("kill pid %d: %v", f.PID, err)
				keep = append(keep, f)
			} else {
				rep.ok("killed %s (pid %d)", procinfo.BaseName(f.Image), f.PID)
			}
		}
		st.Frozen = keep
		return nil
	})
	if len(rep.Lines) == 0 && len(rep.Errors) == 0 {
		rep.ok("nothing frozen for this alert (already exited or released)")
	}
	if err != nil {
		rep.bad("save response state: %v", err)
	}
	_, saveErr := alerts.Update(a.ID, func(x *alerts.Alert) {
		x.AddAction(config.ActionKill, rep.Err(), "by you")
		if rep.Err() == nil {
			x.Status, x.Note = "resolved", "killed"
		}
	})
	if saveErr != nil {
		rep.bad("save alert: %v", saveErr)
	}
	return rep, rep.Err()
}

// Resume declares an alert a false positive: unfreeze and unblock its program.
func Resume(alertID string) (*Report, error) {
	a, err := alerts.Load(alertID)
	if err != nil {
		return &Report{}, err
	}
	rep := &Report{}
	err = config.UpdateState(func(st *config.State) error {
		st.Frozen = resumeWhere(st.Frozen, a.ID, rep)
		st.Blocked = unblockWhere(st.Blocked, a.ID, rep)
		return nil
	})
	if err != nil {
		rep.bad("save response state: %v", err)
	}
	if rep.Err() == nil {
		_, saveErr := alerts.Update(a.ID, func(x *alerts.Alert) { x.Status, x.Note = "resolved", "resumed once; no trust rule added" })
		if saveErr != nil {
			rep.bad("save alert: %v", saveErr)
		}
	}
	return rep, rep.Err()
}

func markResolved(alertID, note string) error {
	if alertID != "" {
		_, err := alerts.Update(alertID, func(a *alerts.Alert) { a.Status, a.Note = "resolved", note })
		return err
	}
	list, err := alerts.List(0)
	if err != nil {
		return err
	}
	var failures []error
	for _, a := range list {
		if a.Status == "open" && (a.Did(config.ActionFreeze) || a.Did(config.ActionIsolate) || a.Did(config.ActionBlockProgram) || a.Did(config.ActionDisableAdapters)) {
			if _, err := alerts.Update(a.ID, func(x *alerts.Alert) { x.Status, x.Note = "resolved", note }); err != nil {
				failures = append(failures, err)
			}
		}
	}
	return errors.Join(failures...)
}
