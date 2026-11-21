package ui

import (
	"io"
	"testing"
	"time"

	"github.com/charmbracelet/huh"

	"github.com/xak1234/sentient1/internal/baits"
	"github.com/xak1234/sentient1/internal/config"
	"github.com/xak1234/sentient1/internal/install"
)

// Keys as a terminal sends them.
const (
	enter = "\r"
	down  = "\x1b[B"
	esc   = "\x1b"
)

func wizardInput() WizardInput {
	u := config.UserInfo{Name: `PC\bob`, Profile: `C:\Users\bob`, Desktop: `C:\Users\bob\Desktop`, Documents: `C:\Users\bob\Documents`,
		Downloads: `C:\Users\bob\Downloads`, LocalAppData: `C:\Users\bob\AppData\Local`, RoamingAppData: `C:\Users\bob\AppData\Roaming`}
	plan := baits.Plan(u, nil)
	for i := range plan {
		plan[i].Available = true
	}
	return WizardInput{User: u, Plan: plan}
}

// drive runs the real setup form, typing keys one at a time the way a person
// would (each key waits for the screen to settle), and returns its result.
func drive(t *testing.T, in WizardInput, keys ...string) (install.Options, bool, error) {
	t.Helper()
	w := newWizard(in)
	r, wr := io.Pipe()
	f := w.form.WithInput(r).WithOutput(io.Discard)
	errc := make(chan error, 1)
	go func() { errc <- f.Run() }()
	go func() {
		for _, k := range keys {
			time.Sleep(120 * time.Millisecond)
			if _, err := wr.Write([]byte(k)); err != nil {
				return
			}
		}
	}()
	select {
	case err := <-errc:
		wr.Close()
		if err == huh.ErrUserAborted {
			return install.Options{}, false, nil
		}
		if err != nil {
			return install.Options{}, false, err
		}
		o, ok := w.finish()
		return o, ok, nil
	case <-time.After(time.Duration(len(keys))*120*time.Millisecond + 5*time.Second):
		wr.Close()
		t.Fatalf("setup didn't finish after %d keys (stuck on a screen?)", len(keys))
		return install.Options{}, false, nil
	}
}

func TestSetupRecommendedJustEnter(t *testing.T) {
	// Recommended → phone: not now → Install (the review text needs no key).
	o, ok, err := drive(t, wizardInput(), enter, enter, enter)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if o.Preset != "balanced" || o.Phone.Enabled() || o.AutoUpdate || o.LearningDays != 0 || o.CanaryEmail != "" || !o.CleanRecent {
		t.Fatalf("recommended defaults: %+v", o)
	}
	want := 0
	for _, a := range wizardInput().Plan {
		if a.Spec.Default {
			want++
		}
	}
	if len(o.Baits) != want {
		t.Fatalf("baits: got %d, want the %d recommended", len(o.Baits), want)
	}
}

func TestSetupRecommendedWithNtfyNoUpdates(t *testing.T) {
	// Recommended → phone: ntfy → topic, server, token (the steps above them need no key) → Install (updates are unavailable in this build).
	o, ok, err := drive(t, wizardInput(), enter, down, enter, enter, enter, enter, enter)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if o.Phone.Kind != "ntfy" || o.Phone.Ntfy.Server != "https://ntfy.sh" || len(o.Phone.Ntfy.Topic) < 8 {
		t.Fatalf("ntfy: %+v", o.Phone)
	}
	if o.AutoUpdate {
		t.Fatal("manual-release build unexpectedly enabled automatic updates")
	}
}

func TestSetupCustomizeStrictWithLearning(t *testing.T) {
	// Customize → baits (keep) → response: Strict → learning: 3 days → phone: not now
	// → canary: No → recent files: Yes → Install.
	o, ok, err := drive(t, wizardInput(), down, enter, enter, down, enter, enter, enter, enter, enter, enter, enter)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if o.Preset != "strict" || o.LearningDays != 3 || o.KeepLearning {
		t.Fatalf("strict + learning: preset=%s learning=%d keep=%v", o.Preset, o.LearningDays, o.KeepLearning)
	}
}

func TestSetupCancelAtReview(t *testing.T) {
	_, ok, err := drive(t, wizardInput(), enter, enter, "n")
	if err != nil || ok {
		t.Fatalf("Cancel must not install: ok=%v err=%v", ok, err)
	}
}

func TestSetupEscapeQuits(t *testing.T) {
	_, ok, err := drive(t, wizardInput(), "\x03")
	if err != nil || ok {
		t.Fatalf("ctrl+c must not install: ok=%v err=%v", ok, err)
	}
}

func TestSetupRerunKeepSettings(t *testing.T) {
	in := wizardInput()
	ex := config.Default()
	ex.ApplyPreset("strict")
	ex.AutoUpdate = false
	ex.Version = config.CurrentConfigVersion
	ex.Baits = []config.BaitConfig{{ID: "desktop-passwords"}, {ID: "discord"}, {ID: "custom-1234", Path: `D:\secret.txt`}}
	in.Existing = ex
	in.Secrets = &config.Secrets{Phone: config.PhoneConfig{Kind: "discord", Discord: config.DiscordConfig{WebhookURL: "https://discord.com/api/webhooks/1/x"}}}
	// Keep my settings → review → Apply.
	o, ok, err := drive(t, in, enter, enter)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if o.Preset != "strict" || o.AutoUpdate || o.Phone.Kind != "discord" || len(o.CustomBaits) != 1 || len(o.Baits) != 2 || !o.KeepLearning {
		t.Fatalf("keep must keep everything: %+v", o)
	}
}

func TestSetupGoBackAndChangeYourMind(t *testing.T) {
	// Recommended → phone: ntfy → shift+tab back → up to "Not now" → auto-update → Install.
	const back, up = "\x1b[Z", "\x1b[A"
	o, ok, err := drive(t, wizardInput(), enter, down, enter, back, up, enter, enter, enter)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if o.Phone.Enabled() {
		t.Fatalf("went back and chose Not now, got %+v", o.Phone)
	}
}
