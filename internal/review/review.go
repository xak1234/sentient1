// Package review supplies read-only dashboard snapshots and portable reports.
package review

import (
	"encoding/json"
	"errors"
	"io"
	"sort"
	"time"

	"github.com/xak1234/sentient1/internal/alerts"
	"github.com/xak1234/sentient1/internal/config"
	"github.com/xak1234/sentient1/internal/protection"
	"github.com/xak1234/sentient1/internal/svcctl"
)

type Decoy struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Kind   string   `json:"kind"`
	Status string   `json:"status"`
	Note   string   `json:"note"`
	Paths  []string `json:"paths"`
}

type Snapshot struct {
	Product              string                `json:"product"`
	Version              string                `json:"version"`
	Generated            time.Time             `json:"generated"`
	Installed            bool                  `json:"installed"`
	Service              svcctl.State          `json:"service"`
	Policy               string                `json:"policy"`
	Instant              bool                  `json:"instant"`
	Heartbeat            time.Time             `json:"heartbeat"`
	Assessment           protection.Assessment `json:"assessment"`
	Health               []config.HealthItem   `json:"health"`
	Baits                []Decoy               `json:"baits"`
	Alerts               []*alerts.Alert       `json:"alerts"`
	Problems             []string              `json:"problems"`
	CommandLinesIncluded bool                  `json:"commandLinesIncluded"`
}

func Load(version string, limit int) Snapshot {
	d := Snapshot{Product: "sentient1", CommandLinesIncluded: true, Version: version, Generated: time.Now(), Baits: []Decoy{}, Alerts: []*alerts.Alert{}, Health: []config.HealthItem{}, Problems: []string{}}
	cfg, err := config.LoadConfig()
	if err != nil && !errors.Is(err, config.ErrNotInstalled) {
		d.Problems = append(d.Problems, err.Error())
	}
	d.Installed = err == nil
	d.Service, err = svcctl.Status()
	if err != nil {
		d.Problems = append(d.Problems, err.Error())
	}
	st, err := config.LoadState()
	if err != nil {
		d.Problems = append(d.Problems, err.Error())
	}
	if cfg != nil {
		d.Policy, d.Instant = cfg.Preset, cfg.InstantFreeze
	}
	if st != nil {
		d.Heartbeat = st.Heartbeat
		if st.Health != nil {
			d.Health = st.Health
		}
		for id, b := range st.Baits {
			if b == nil {
				continue
			}
			x := Decoy{ID: id, Name: b.Name, Kind: b.Kind, Status: b.Status, Note: b.StatusNote, Paths: []string{}}
			for _, f := range b.Files {
				x.Paths = append(x.Paths, f.Path)
			}
			d.Baits = append(d.Baits, x)
		}
	}
	sort.Slice(d.Baits, func(i, j int) bool { return d.Baits[i].Name < d.Baits[j].Name })
	d.Assessment = protection.Assess(d.Installed, d.Service, st, d.Generated)
	list, err := alerts.List(limit)
	if err != nil {
		d.Problems = append(d.Problems, err.Error())
	}
	if list != nil {
		d.Alerts = list
	}
	if len(d.Problems) > 0 && d.Assessment.Level == "healthy" {
		d.Assessment.Level, d.Assessment.Title = "attention", "Needs attention"
		d.Assessment.Reasons = append(d.Assessment.Reasons, d.Problems...)
	}
	return d
}

// ForExport deep-copies the snapshot before removing command lines, which can
// contain tokens or passwords. Decoy contents and notification secrets are
// never part of a snapshot. Local paths and IP evidence remain in the report.
func ForExport(d Snapshot, includeCommands bool) (Snapshot, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return Snapshot{}, err
	}
	var out Snapshot
	if err = json.Unmarshal(b, &out); err != nil {
		return Snapshot{}, err
	}
	out.CommandLinesIncluded = includeCommands
	if !includeCommands {
		for _, a := range out.Alerts {
			if a.Process == nil {
				continue
			}
			a.Process.CommandLine = ""
			for i := range a.Process.Parents {
				a.Process.Parents[i].CommandLine = ""
			}
		}
	}
	return out, nil
}

func WriteJSON(w io.Writer, d Snapshot) error {
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	return e.Encode(d)
}
