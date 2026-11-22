package alerts

import (
	"fmt"

	"github.com/xak1234/sentient1/internal/config"
	"github.com/xak1234/sentient1/internal/procinfo"
	"golang.org/x/sys/windows"
)

// Controls is a live UI hint, not authorization. The elevated operation checks
// process identity and response state again immediately before changing anything.
type Controls struct {
	CanFreeze    bool   `json:"canFreeze"`
	FreezeReason string `json:"freezeReason"`
	Frozen       bool   `json:"frozen"`
}

func (a *Alert) RefreshControls(st *config.State) {
	a.Controls = &Controls{}
	c := a.Controls
	if st == nil {
		c.FreezeReason = "Response state is unavailable; refresh before acting."
		return
	}
	c.Frozen = st.IsFrozen(a.ID)
	if c.Frozen {
		c.FreezeReason = "Already frozen for this alert. Use Resume once to let it run."
		return
	}
	if a.Process == nil || a.Process.Exited {
		c.FreezeReason = "No running reader is recorded for this alert."
		return
	}
	p := a.Process
	for _, f := range st.Frozen {
		if f.PID == p.PID && f.CreateTime == p.CreateTime {
			c.FreezeReason = fmt.Sprintf("Already frozen under alert %s; review that alert to resume it.", f.AlertID)
			return
		}
	}
	h, err := procinfo.OpenManualFreezeTarget(p.PID, p.CreateTime, p.Image, false)
	if err != nil {
		c.FreezeReason = err.Error()
		return
	}
	windows.CloseHandle(h)
	c.CanFreeze = true
	c.FreezeReason = "Pause this reader process until Resume once. Every component inside this process will pause."
}
