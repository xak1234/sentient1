package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/xak1234/sentient1/internal/baits"
	"github.com/xak1234/sentient1/internal/config"
	"github.com/xak1234/sentient1/internal/install"
	"github.com/xak1234/sentient1/internal/paths"
	"github.com/xak1234/sentient1/internal/svcctl"
	"github.com/xak1234/sentient1/internal/winsec"
)

type setupBait struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	Description string   `json:"description"`
	Available   bool     `json:"available"`
	Selected    bool     `json:"selected"`
	Recommended bool     `json:"recommended"`
	Reason      string   `json:"reason"`
	RequiresAny []string `json:"requiresAny"`
}

type setupPlan struct {
	Installed    bool        `json:"installed"`
	Revision     string      `json:"revision"`
	UserSID      string      `json:"userSid"`
	User         string      `json:"user"`
	Policy       string      `json:"policy"`
	LearningDays int         `json:"learningDays"`
	CleanRecent  bool        `json:"cleanRecent"`
	Instant      bool        `json:"instant"`
	CustomCount  int         `json:"customCount"`
	Baits        []setupBait `json:"baits"`
}

type setupRequest struct {
	Revision     string             `json:"revision"`
	UserSID      string             `json:"userSid"`
	Policy       string             `json:"policy"`
	LearningDays int                `json:"learningDays"`
	KeepLearning bool               `json:"keepLearning"`
	CleanRecent  bool               `json:"cleanRecent"`
	Instant      bool               `json:"instant"`
	Baits        []string           `json:"baits"`
	PhoneMode    string             `json:"phoneMode"` // keep | none | replace
	Phone        config.PhoneConfig `json:"phone"`
	CanaryEmail  string             `json:"canaryEmail"` // empty preserves existing canaries
}

func desktopCmd() *cobra.Command {
	c := &cobra.Command{Use: "desktop", Short: "Structured setup for the native desktop", Hidden: true}
	c.AddCommand(&cobra.Command{Use: "plan", Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
		p, _, err := loadSetupPlan()
		if err != nil {
			return err
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(p)
	}})
	for _, name := range []string{"validate", "apply"} {
		operation := name
		c.AddCommand(&cobra.Command{Use: operation, Args: cobra.NoArgs, RunE: func(cmd *cobra.Command, args []string) error {
			r, err := readSetupRequest(cmd.InOrStdin())
			if err != nil {
				return err
			}
			p, old, err := loadSetupPlan()
			if err != nil {
				return err
			}
			if err = validateSetup(r, p); err != nil {
				return err
			}
			if operation == "validate" {
				fmt.Fprintf(cmd.OutOrStdout(), "Setup validated: %s policy, %d catalog decoys; %d existing custom decoys preserved.\n", r.Policy, len(r.Baits), p.CustomCount)
				return nil
			}
			if !winsec.IsElevated() {
				return errors.New("setup requires the desktop's administrator helper")
			}
			st, err := config.LoadState()
			if err != nil {
				return err
			}
			if len(st.Frozen) > 0 || len(st.Blocked) > 0 || st.Isolation != nil || len(st.DisabledAdapters) > 0 {
				return errors.New("review and release active containment before changing setup")
			}
			o := install.Options{Baits: r.Baits, Preset: r.Policy, LearningDays: r.LearningDays, KeepLearning: r.KeepLearning, CleanRecent: r.CleanRecent, PhoneMinTier: config.TierWarn, InstantFreeze: &r.Instant, CanaryEmail: r.CanaryEmail}
			if old != nil {
				o.PhoneMinTier = old.PhoneMinTier
				for _, b := range old.Baits {
					if b.Path != "" {
						o.CustomBaits = append(o.CustomBaits, b.Path)
					}
				}
				if r.Policy == "custom" {
					o.Responses = old.Responses
				}
			}
			switch r.PhoneMode {
			case "keep":
				sec, err := config.LoadSecrets()
				if err != nil {
					return fmt.Errorf("cannot preserve notification settings: %w", err)
				}
				o.Phone = sec.Phone
			case "replace":
				o.Phone = r.Phone
			}
			wasRunning, _ := svcctl.Status()
			for i, step := range install.Steps(o) {
				fmt.Fprintf(cmd.OutOrStdout(), "[%02d] %s...\n", i+1, step.Name)
				detail, err := step.Run()
				if err != nil {
					if step.Soft {
						fmt.Fprintf(cmd.OutOrStdout(), "[WARN] %s\n", err)
						continue
					}
					if wasRunning == svcctl.Running {
						if restartErr := svcctl.Start(); restartErr != nil {
							fmt.Fprintf(cmd.OutOrStdout(), "[ERROR] Monitor restart: %v\n", restartErr)
						}
					}
					return fmt.Errorf("%s: %w", step.Name, err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "[OK] %s\n", detail)
			}
			fmt.Fprintln(cmd.OutOrStdout(), "[OK] Setup applied. Refreshing live monitor status.")
			return nil
		}})
	}
	return c
}

func configRevision() (string, error) {
	b, err := os.ReadFile(paths.ConfigFile())
	if errors.Is(err, os.ErrNotExist) {
		return "not-installed", nil
	}
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func loadSetupPlan() (setupPlan, *config.Config, error) {
	p := setupPlan{Policy: "balanced", CleanRecent: true, Baits: []setupBait{}}
	u, err := install.CurrentUser()
	if err != nil {
		return p, nil, err
	}
	p.UserSID, p.User = u.SID, u.Name
	p.Revision, err = configRevision()
	if err != nil {
		return p, nil, err
	}
	cfg, err := config.LoadConfig()
	if err != nil && !errors.Is(err, config.ErrNotInstalled) {
		return p, nil, err
	}
	selected := map[string]bool{}
	ours := map[string]bool{}
	st, err := config.LoadState()
	if err != nil {
		return p, nil, err
	}
	for id, b := range st.Baits {
		if b != nil && b.Status != "retired" {
			ours[id] = true
		}
	}
	if cfg != nil {
		if cfg.User.SID != u.SID {
			return p, nil, errors.New("this monitor belongs to a different Windows account; open sentient1 as its protected user")
		}
		p.Installed, p.Policy, p.CleanRecent, p.Instant = true, cfg.Preset, cfg.CleanRecent, cfg.InstantFreeze
		if cfg.Learning(time.Now()) {
			p.LearningDays = int(time.Until(cfg.LearningUntil).Hours()/24) + 1
		}
		for _, b := range cfg.Baits {
			selected[b.ID] = true
			if b.Path != "" {
				p.CustomCount++
			}
		}
	}
	for _, a := range baits.Plan(u, ours) {
		chosen := selected[a.Spec.ID]
		if cfg == nil {
			chosen = a.Spec.Default && a.Available
		}
		p.Baits = append(p.Baits, setupBait{ID: a.Spec.ID, Name: a.Spec.Name, Category: a.Spec.Category, Description: a.Spec.Description, Available: a.Available, Selected: chosen && a.Available, Recommended: a.Spec.Default, Reason: a.Reason, RequiresAny: a.Spec.RequiresAny})
	}
	// Detect a settings change while constructing the plan, instead of blessing
	// an old selection with a newer revision token.
	revision, err := configRevision()
	if err != nil {
		return p, nil, err
	}
	if revision != p.Revision {
		return p, nil, errors.New("settings changed while loading; reload setup")
	}
	return p, cfg, nil
}

func readSetupRequest(reader io.Reader) (setupRequest, error) {
	var r setupRequest
	b, err := io.ReadAll(io.LimitReader(reader, 65537))
	if err != nil {
		return r, err
	}
	if len(b) > 65536 {
		return r, errors.New("setup request is too large")
	}
	d := json.NewDecoder(strings.NewReader(string(b)))
	d.DisallowUnknownFields()
	if err = d.Decode(&r); err != nil {
		return r, fmt.Errorf("invalid setup request: %w", err)
	}
	var extra any
	if err = d.Decode(&extra); err != io.EOF {
		return r, errors.New("setup requires exactly one JSON object")
	}
	return r, nil
}

func validateSetup(r setupRequest, p setupPlan) error {
	if r.Revision != p.Revision {
		return errors.New("settings changed since setup was opened; reload before applying")
	}
	if r.UserSID != p.UserSID {
		return errors.New("the administrator must be the same Windows account as the protected user")
	}
	if _, ok := config.PresetByID(r.Policy); !ok && !(r.Policy == "custom" && p.Policy == "custom") {
		return errors.New("choose Alert only, Balanced or Strict")
	}
	if r.LearningDays < 0 || r.LearningDays > 30 {
		return errors.New("learning period must be 0 to 30 days")
	}
	if len(r.Baits) == 0 && p.CustomCount == 0 {
		return errors.New("select at least one available decoy")
	}
	available := map[string]setupBait{}
	for _, b := range p.Baits {
		available[b.ID] = b
	}
	selected := map[string]bool{}
	for _, id := range r.Baits {
		b, ok := available[id]
		if !ok || !b.Available {
			return fmt.Errorf("decoy %q is unavailable; reload setup", id)
		}
		if selected[id] {
			return errors.New("duplicate decoy selection")
		}
		selected[id] = true
	}
	for id := range selected {
		if required := available[id].RequiresAny; len(required) > 0 {
			ok := false
			for _, host := range required {
				ok = ok || selected[host]
			}
			if !ok {
				return fmt.Errorf("%s needs one of its browser decoys selected", available[id].Name)
			}
		}
	}
	if r.CanaryEmail != "" {
		if _, err := mail.ParseAddress(r.CanaryEmail); err != nil {
			return errors.New("enter a valid canary email address")
		}
	}
	switch r.PhoneMode {
	case "keep", "none":
		return nil
	case "replace":
		return validatePhone(r.Phone)
	default:
		return errors.New("invalid notification selection")
	}
}

func validatePhone(p config.PhoneConfig) error {
	https := func(s string) bool {
		u, err := url.Parse(s)
		return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil
	}
	switch p.Kind {
	case "ntfy":
		if !https(p.Ntfy.Server) || strings.TrimSpace(p.Ntfy.Topic) == "" || strings.ContainsAny(p.Ntfy.Topic, "/\\?#\r\n") {
			return errors.New("ntfy requires an HTTPS server and a topic name")
		}
	case "discord":
		if !https(p.Discord.WebhookURL) {
			return errors.New("Discord requires an HTTPS webhook URL")
		}
	case "pushover":
		if p.Pushover.AppToken == "" || p.Pushover.UserKey == "" {
			return errors.New("Pushover requires an app token and user key")
		}
	case "email":
		if p.Email.Host == "" || p.Email.Port < 1 || p.Email.Port > 65535 {
			return errors.New("email requires a host and port between 1 and 65535")
		}
		for _, s := range []string{p.Email.From, p.Email.To} {
			if _, err := mail.ParseAddress(s); err != nil {
				return errors.New("email requires valid From and To addresses")
			}
		}
	default:
		return errors.New("choose a supported notification provider")
	}
	return nil
}
