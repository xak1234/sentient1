package config

import "testing"

func TestIndependentSafeDefaults(t *testing.T) {
	c := Default()
	if c.AutoUpdate {
		t.Fatal("unconfigured automatic updates enabled")
	}
	if c.InstantFreeze {
		t.Fatal("timing-based attribution should require opt-in")
	}
	if Has(c.Responses[TierCritical], ActionIsolate) || Has(c.Responses[TierCritical], ActionDisableAdapters) {
		t.Fatal("default policy isolates the whole computer")
	}
	if !Has(c.Responses[TierCritical], ActionFreeze) || !Has(c.Responses[TierCritical], ActionBlockProgram) {
		t.Fatal("balanced containment missing")
	}
}
