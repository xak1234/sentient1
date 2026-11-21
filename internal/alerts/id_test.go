package alerts

import "testing"

func TestAlertIDsRejectPaths(t *testing.T) {
	for _, id := range []string{"", "..", "../config", `..\config`, `C:\temp\a`, "a.json", "a:secret", "/a", " a", "a\x00"} {
		if ValidID(id) {
			t.Errorf("accepted unsafe ID %q", id)
		}
		if _, err := Load(id); err == nil {
			t.Errorf("Load accepted %q", id)
		}
	}
	for _, id := range []string{"20261121-123456-0123456789abcdef", "abcdef", "20261121-", "test_id"} {
		if !ValidID(id) {
			t.Errorf("rejected ID %q", id)
		}
	}
}
