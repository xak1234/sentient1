package respond

import (
	"github.com/xak1234/sentient1/internal/config"
	"testing"
	"time"
)

func TestFailedRecoveryKeepsRetryState(t *testing.T) {
	i := &config.Isolation{AlertID: "test", Method: "wfp", Since: time.Now()}
	snapshot := &config.State{Isolation: i, DisabledAdapters: []string{"Ethernet"}}
	st := &config.State{Isolation: i, DisabledAdapters: []string{"Ethernet"}}
	clearRecoveredNetwork(st, snapshot, false, false)
	if st.Isolation == nil || len(st.DisabledAdapters) != 1 {
		t.Fatal("failed operation erased state")
	}
	clearRecoveredNetwork(st, snapshot, true, false)
	if st.Isolation != nil || len(st.DisabledAdapters) != 1 {
		t.Fatal("partial success lost adapter state")
	}
	clearRecoveredNetwork(st, snapshot, true, true)
	if len(st.DisabledAdapters) != 0 {
		t.Fatal("successful operation not cleared")
	}
}

func TestConcurrentIncidentIsPreserved(t *testing.T) {
	snapshot := &config.State{Isolation: &config.Isolation{AlertID: "old", Method: "wfp"}}
	st := &config.State{Isolation: &config.Isolation{AlertID: "new", Method: "wfp"}}
	clearRecoveredNetwork(st, snapshot, true, true)
	if st.Isolation == nil || st.Isolation.AlertID != "new" {
		t.Fatal("new incident was cleared")
	}
	if (&Report{Errors: []string{"failed"}}).Err() == nil {
		t.Fatal("partial failure did not return an error")
	}
}
