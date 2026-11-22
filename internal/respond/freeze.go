package respond

import (
	"fmt"
	"time"

	"github.com/xak1234/sentient1/internal/alerts"
	"github.com/xak1234/sentient1/internal/config"
	"github.com/xak1234/sentient1/internal/procinfo"
	"golang.org/x/sys/windows"
)

// Freeze pauses only the reader recorded in an alert. It neither changes the
// automatic response policy nor trusts the executable nor blocks the network.
// Manual calls share the state mutex with resume, kill and release. A held
// process handle prevents a stale PID from ever selecting a replacement process.
func Freeze(alertID string) (*Report, error) {
	rep := &Report{}
	a, err := alerts.Load(alertID)
	if err != nil {
		return rep, err
	}
	if a.Process == nil || a.Process.Exited {
		return rep, fmt.Errorf("this alert has no running reader to freeze")
	}
	p := a.Process
	h, err := procinfo.OpenManualFreezeTarget(p.PID, p.CreateTime, p.Image, true)
	if err != nil {
		return rep, err
	}
	defer windows.CloseHandle(h)
	suspended, already := false, false
	err = config.UpdateState(func(st *config.State) error {
		for _, f := range st.Frozen {
			if f.PID == p.PID && f.CreateTime == p.CreateTime {
				already = true
				rep.ok("already frozen under alert %s; no additional suspension applied", f.AlertID)
				return nil
			}
		}
		status, waitErr := windows.WaitForSingleObject(h, 0)
		if waitErr != nil || status != uint32(windows.WAIT_TIMEOUT) {
			return fmt.Errorf("the reader exited before it could be frozen")
		}
		if err := procinfo.Suspend(p.PID); err != nil {
			return fmt.Errorf("Windows could not suspend the reader: %w", err)
		}
		suspended = true
		st.Frozen = append(st.Frozen, config.FrozenProcess{PID: p.PID, CreateTime: p.CreateTime,
			Image: p.Image, AlertID: a.ID, Since: time.Now()})
		return nil
	})
	if err != nil {
		rep.bad("freeze was not recorded: %v", err)
		if suspended {
			if undo := procinfo.Resume(p.PID); undo != nil {
				rep.bad("automatic rollback could not resume PID %d: %v", p.PID, undo)
			} else {
				rep.ok("resumed the reader because its recovery record could not be saved")
			}
		}
		return rep, rep.Err()
	}
	if already {
		return rep, nil
	}
	rep.ok("froze %s (pid %d); use Resume once to let it run again", a.ReaderName(), p.PID)
	_, err = alerts.Update(a.ID, func(current *alerts.Alert) {
		current.AddAction(config.ActionFreeze, nil, "manually paused the reader process; resume when ready")
		current.Status, current.Note = "open", "manually frozen once; no trust rule or automatic policy changed"
	})
	if err != nil {
		rep.bad("reader is frozen and tracked, but alert history could not be updated: %v", err)
	}
	return rep, rep.Err()
}
