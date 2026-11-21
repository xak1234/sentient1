package protection

import (
	"github.com/xak1234/sentient1/internal/config"
	"github.com/xak1234/sentient1/internal/svcctl"
	"testing"
	"time"
)

func TestHealthRequiresAuditHeartbeatAndDecoys(t *testing.T) {
	now := time.Now()
	s := config.NewState()
	s.Heartbeat = now
	s.Health = []config.HealthItem{{Name: "File auditing", OK: true}}
	s.Baits["file"] = &config.BaitState{Status: "ok", Files: []config.BaitFile{{Audit: true}}}
	if a := Assess(true, svcctl.Running, s, now); a.Level != "healthy" {
		t.Fatal(a)
	}
	s.Health[0].OK = false
	if a := Assess(true, svcctl.Running, s, now); a.Level == "healthy" {
		t.Fatal("disabled auditing reported healthy")
	}
	s.Health[0].OK = true
	s.Heartbeat = now.Add(-4 * time.Minute)
	if a := Assess(true, svcctl.Running, s, now); a.Level == "healthy" {
		t.Fatal("stale service reported healthy")
	}
	s.Heartbeat = now
	s.Baits["file"].Files[0].Audit = false
	if a := Assess(true, svcctl.Running, s, now); a.Level == "healthy" {
		t.Fatal("unaudited bait reported healthy")
	}
	if a := Assess(false, svcctl.NotInstalled, nil, now); a.Level != "inactive" {
		t.Fatal(a)
	}
}
