package cli

import (
	"strings"
	"testing"
)

func TestSetupValidationProtectsSelections(t *testing.T) {
	p := setupPlan{Revision: "one", UserSID: "user", Baits: []setupBait{{ID: "browser", Available: true}, {ID: "wallet", Available: true, RequiresAny: []string{"browser"}}, {ID: "real-app", Available: false}}}
	r := setupRequest{Revision: "one", UserSID: "user", Policy: "balanced", PhoneMode: "keep", Baits: []string{"browser", "wallet"}}
	if err := validateSetup(r, p); err != nil {
		t.Fatal(err)
	}
	r.Revision = "old"
	if validateSetup(r, p) == nil {
		t.Fatal("stale setup accepted")
	}
	r.Revision = "one"
	r.UserSID = "other"
	if validateSetup(r, p) == nil {
		t.Fatal("different elevated account accepted")
	}
	r.UserSID = "user"
	r.Baits = []string{"real-app"}
	if validateSetup(r, p) == nil {
		t.Fatal("real app overwrite accepted")
	}
	r.Baits = []string{"wallet"}
	if validateSetup(r, p) == nil {
		t.Fatal("missing browser dependency accepted")
	}
	r.Baits = nil
	if validateSetup(r, p) == nil {
		t.Fatal("empty selection silently became defaults")
	}
	r.Baits = []string{"browser"}
	r.LearningDays = -1
	if validateSetup(r, p) == nil {
		t.Fatal("negative learning days accepted")
	}
}

func TestSetupInputIsBoundedAndStrict(t *testing.T) {
	for _, input := range []string{`{"unknown":true}`, `{} {}`, strings.Repeat(" ", 65537)} {
		if _, err := readSetupRequest(strings.NewReader(input)); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
	if _, err := readSetupRequest(strings.NewReader(`{"policy":"balanced"}`)); err != nil {
		t.Fatal(err)
	}
}
