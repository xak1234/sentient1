// Package protection provides the same conservative health verdict to every UI.
package protection

import (
	"fmt"
	"time"

	"github.com/xak1234/sentient1/internal/config"
	"github.com/xak1234/sentient1/internal/svcctl"
)

type Assessment struct {
	Level           string   `json:"level"`
	Title           string   `json:"title"`
	Reasons         []string `json:"reasons"`
	Healthy         int      `json:"healthy"`
	Total           int      `json:"total"`
	ActiveResponses int      `json:"activeResponses"`
}

func Assess(installed bool, service svcctl.State, st *config.State, now time.Time) Assessment {
	a := Assessment{Level: "attention", Title: "Needs attention", Reasons: []string{}}
	if !installed {
		a.Level, a.Title = "inactive", "Not installed"
		a.Reasons = append(a.Reasons, "Install the monitor to arm the decoys.")
		return a
	}
	if service != svcctl.Running {
		a.Reasons = append(a.Reasons, "Monitor service: "+string(service))
	}
	if st == nil {
		a.Reasons = append(a.Reasons, "Monitor state is unavailable.")
		return a
	}
	if st.Heartbeat.IsZero() || now.Sub(st.Heartbeat) > 3*time.Minute || st.Heartbeat.After(now.Add(time.Minute)) {
		a.Reasons = append(a.Reasons, "No recent, valid service heartbeat.")
	}
	auditVerified := false
	for _, h := range st.Health {
		if h.Name == "File auditing" && h.OK {
			auditVerified = true
		}
		if !h.OK {
			a.Reasons = append(a.Reasons, h.Name+": "+h.Detail)
		}
	}
	if !auditVerified {
		a.Reasons = append(a.Reasons, "Successful file auditing has not been confirmed.")
	}
	for _, b := range st.Baits {
		if b == nil || b.Status == "retired" {
			continue
		}
		a.Total++
		armed := b.Status == "ok" && len(b.Files) > 0
		audited := false
		for _, f := range b.Files {
			audited = audited || f.Audit
		}
		if armed && audited {
			a.Healthy++
		}
	}
	if a.Total == 0 || a.Healthy != a.Total {
		a.Reasons = append(a.Reasons, fmt.Sprintf("%d of %d decoys are healthy and audited.", a.Healthy, a.Total))
	}
	a.ActiveResponses = len(st.Frozen) + len(st.Blocked) + len(st.DisabledAdapters)
	if st.Isolation != nil {
		a.ActiveResponses++
	}
	if a.ActiveResponses > 0 {
		a.Level, a.Title = "response", "Containment active"
		a.Reasons = append(a.Reasons, "Review the evidence before releasing containment.")
	} else if len(a.Reasons) == 0 {
		a.Level, a.Title = "healthy", "Monitoring active"
	} else if service != svcctl.Running {
		a.Level, a.Title = "inactive", "Monitor not running"
	}
	return a
}
