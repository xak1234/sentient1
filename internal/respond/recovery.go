package respond

import "github.com/xak1234/sentient1/internal/config"

// clearRecoveredNetwork only forgets responses observed in the snapshot and
// successfully undone. A concurrent, newer incident keeps its bookkeeping.
func clearRecoveredNetwork(st, snapshot *config.State, wfpOK, adaptersOK bool) {
	if snapshot == nil {
		return
	}
	if adaptersOK {
		recovered := map[string]bool{}
		for _, name := range snapshot.DisabledAdapters {
			recovered[name] = true
		}
		var keep []string
		for _, name := range st.DisabledAdapters {
			if !recovered[name] {
				keep = append(keep, name)
			}
		}
		st.DisabledAdapters = keep
	}
	current, previous := st.Isolation, snapshot.Isolation
	if current == nil || previous == nil || *current != *previous {
		return
	}
	if (current.Method == "wfp" && wfpOK) || (current.Method == "adapters" && adaptersOK && len(st.DisabledAdapters) == 0) {
		st.Isolation = nil
	}
}
