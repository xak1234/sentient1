package cli

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/xak1234/sentient1/internal/baits"
	"github.com/xak1234/sentient1/internal/config"
	"github.com/xak1234/sentient1/internal/install"
	"github.com/xak1234/sentient1/internal/ui"
	"github.com/xak1234/sentient1/internal/update"
)

type installFlags struct {
	yes         bool
	preset      string
	learning    int
	canaryEmail string
	ntfyTopic   string
	baits       []string
	autoUpdate  bool
}

func theme() *huh.Theme { return ui.Theme() }

func installCmd() *cobra.Command {
	var f installFlags
	c := &cobra.Command{
		Use:   "install",
		Short: "Set it up, or repair it",
		Long:  "Installs sentient1 with a guided setup. Run it again any time to repair or change settings.",
		Example: "  sentient1 install\n" +
			"  sentient1 install --yes --preset balanced\n" +
			"  sentient1 install --yes --preset strict --learning 3 --ntfy-topic my-secret-topic\n" +
			"  sentient1 install --yes --auto-update=false",
		RunE: func(cmd *cobra.Command, args []string) error { return runInstall(false, f) },
	}
	c.Flags().BoolVarP(&f.yes, "yes", "y", false, "non-interactive: use defaults and flags")
	c.Flags().StringVar(&f.preset, "preset", "balanced", "alert | balanced | strict")
	c.Flags().IntVar(&f.learning, "learning", 3, "learning mode days, 0 = respond fully right away (only changes something with strict)")
	c.Flags().StringVar(&f.canaryEmail, "canary-email", "", "create canary tokens that email this address")
	c.Flags().StringVar(&f.ntfyTopic, "ntfy-topic", "", "send phone alerts to this ntfy.sh topic")
	c.Flags().StringSliceVar(&f.baits, "baits", nil, "bait IDs to plant (default: recommended); see `sentient1 bait catalog`")
	c.Flags().BoolVar(&f.autoUpdate, "auto-update", false, "install new signed releases automatically (--auto-update=false to turn off)")
	return c
}

func configureCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "configure",
		Short: "Change baits, response, phone alerts, updates",
		RunE:  func(cmd *cobra.Command, args []string) error { return runInstall(true, installFlags{}) },
	}
}

func runInstall(reconfigure bool, f installFlags) error {
	if f.autoUpdate && !update.Enabled() {
		return exitf("signed updates are not configured for sentient1")
	}
	if err := requireAdmin(); err != nil {
		return err
	}
	u, err := install.CurrentUser()
	if err != nil {
		return err
	}
	existing, _ := config.LoadConfig()
	ours := map[string]bool{}
	if st, err := config.LoadState(); err == nil {
		for id, b := range st.Baits {
			if b.Status != "retired" {
				ours[id] = true
			}
		}
	}
	plan := baits.Plan(u, ours)

	fmt.Println()
	fmt.Println(ui.Banner("setup"))
	fmt.Println()

	var o install.Options
	if f.yes {
		o = install.Options{Preset: f.preset, LearningDays: f.learning, CanaryEmail: f.canaryEmail, CleanRecent: true, PhoneMinTier: config.TierWarn, AutoUpdate: f.autoUpdate}
		if f.ntfyTopic != "" {
			o.Phone = config.PhoneConfig{Kind: "ntfy", Ntfy: config.NtfyConfig{Server: "https://ntfy.sh", Topic: f.ntfyTopic}}
		} else if sec, err := config.LoadSecrets(); err == nil {
			o.Phone = sec.Phone
		}
		want := map[string]bool{}
		for _, id := range f.baits {
			want[strings.TrimSpace(id)] = true
		}
		for _, a := range plan {
			if a.Available && ((len(want) == 0 && a.Spec.Default) || want[a.Spec.ID]) {
				o.Baits = append(o.Baits, a.Spec.ID)
			}
		}
		if existing != nil {
			for _, b := range existing.Baits {
				if b.Path != "" {
					o.CustomBaits = append(o.CustomBaits, b.Path)
				}
			}
		}
	} else {
		if !ui.IsTTY() {
			return exitf("no terminal for the interactive setup; use `sentient1 install --yes`")
		}
		sec, _ := config.LoadSecrets()
		var ok bool
		o, ok, err = ui.RunWizard(ui.WizardInput{User: u, Plan: plan, Existing: existing, Secrets: sec, Change: reconfigure})
		if err != nil {
			return err
		}
		if !ok {
			fmt.Println(ui.Dim.Render("Cancelled. Nothing was changed."))
			return nil
		}
	}

	fmt.Println()
	title := "Setting up sentient1"
	if existing != nil {
		title = "Updating your setup"
	}
	if err := ui.RunSteps(title, install.Steps(o)); err != nil {
		return err
	}
	fmt.Println()
	fmt.Println(doneCard(existing == nil))
	if f.yes || !ui.IsTTY() {
		return nil
	}
	fmt.Println()
	run := true
	if err := huh.NewConfirm().Title("Want to see it catch something?").
		Description("A harmless copy of SENTIENT1 in your Temp folder reads a bait, the way a stealer would.\n" +
			"You'll watch it get frozen and see the alert popup. Nothing leaves your PC.").
		Affirmative("Run the safe test").Negative("Not now").Value(&run).WithTheme(theme()).Run(); err != nil || !run {
		fmt.Println(ui.Hint("Any time:", "sentient1 test"))
		return nil
	}
	fmt.Println()
	return runTest()
}

// doneCard is the "you're protected" summary at the end of setup, built from
// what was actually saved.
func doneCard(first bool) string {
	cfg, err := config.LoadConfig()
	if err != nil {
		return ui.Good.Render(ui.IconOK) + " sentient1 is installed."
	}
	st, _ := config.LoadState()
	sec, _ := config.LoadSecrets()
	return renderDoneCard(cfg, st, sec, first)
}

func renderDoneCard(cfg *config.Config, st *config.State, sec *config.Secrets, first bool) string {
	w := min(ui.Width()-2, 84)
	inner := w - 6

	active := 0
	if st != nil {
		for _, b := range st.Baits {
			if b.Status != "retired" {
				active++
			}
		}
	}
	head := "You're protected."
	if !first {
		head = "All set. You're protected."
	}
	rows := [][2]string{
		{"Baits", fmt.Sprintf("%d planted, watched by Windows' own file auditing", active)},
		{"Response", cfg.PresetName() + ui.Fainter.Render("  ·  "+responseLine(cfg))},
	}
	if cfg.Learning(timeNow()) && cfg.LearningMatters() {
		rows = append(rows, [2]string{"Learning", ui.Until(cfg.LearningUntil) + ui.Fainter.Render("  ·  critical threats are stopped meanwhile")})
	}
	if sec != nil && sec.Phone.Enabled() {
		rows = append(rows, [2]string{"Phone", sec.Phone.Describe()})
	} else {
		rows = append(rows, [2]string{"Phone", ui.Fainter.Render("off  ·  ") + ui.Code.Render("sentient1 configure")})
	}
	if cfg.AutoUpdate {
		rows = append(rows, [2]string{"Updates", "automatic" + ui.Fainter.Render("  ·  signed releases only")})
	} else {
		rows = append(rows, [2]string{"Updates", "manual" + ui.Fainter.Render("  ·  ") + ui.Code.Render("sentient1 update")})
	}

	body := []string{
		ui.Good.Bold(true).Render(ui.IconOK+" ") + ui.Bold.Render(head),
		"",
		ui.KV(rows),
		"",
		ui.Cmd([][2]string{
			{"sentient1 test", "watch it catch a harmless fake stealer"},
			{"sentient1", "live dashboard: health and alerts"},
			{"sentient1 doctor", "check that everything is armed"},
		}),
		"",
		ui.Callout("Don't open the bait files yourself: that counts as a read. To look at one safely: "+ui.Code.Render("sentient1 bait show <id>"), inner),
	}
	card := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(ui.Leaf).Padding(1, 2).Width(w)
	return card.Render(strings.Join(body, "\n")) + "\n" + ui.Fainter.Render("  New terminal windows have the sentient1 command on their PATH.")
}

// responseLine says in a few words what happens to a critical reader.
func responseLine(cfg *config.Config) string {
	acts := cfg.Responses[config.TierCritical]
	switch {
	case len(acts) == 0:
		return "alerts only, never acts"
	case config.Has(acts, config.ActionIsolate):
		return "critical: frozen, PC cut off the network"
	case config.Has(acts, config.ActionKill):
		return "critical: killed"
	case config.Has(acts, config.ActionFreeze) && config.Has(acts, config.ActionBlockProgram):
		return "critical: frozen and cut off the internet"
	case config.Has(acts, config.ActionFreeze):
		return "critical: frozen"
	}
	return "critical: blocked"
}

func uninstallCmd() *cobra.Command {
	var purge, yes bool
	c := &cobra.Command{
		Use:   "uninstall",
		Short: "Remove it and every bait, restoring Windows",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			fmt.Println()
			fmt.Println(ui.Banner("uninstall"))
			fmt.Println()
			if !yes && ui.IsTTY() {
				ok := false
				desc := "Removes the service, every bait and any network blocks, and puts Windows' audit setting\nback the way it was."
				if !purge {
					desc += "\nYour alert history is kept (add --purge to delete it too)."
				}
				huh.NewConfirm().Title("Uninstall sentient1?").Description(desc).Affirmative("Uninstall").Negative("Cancel").Value(&ok).WithTheme(theme()).Run()
				if !ok {
					fmt.Println(ui.Dim.Render("Cancelled. Nothing was changed."))
					return nil
				}
				fmt.Println()
			}
			if err := ui.RunSteps("Removing sentient1", install.UninstallSteps(purge)); err != nil {
				return err
			}
			fmt.Println("\n" + ui.Good.Render(ui.IconOK) + " " + ui.Bold.Render("sentient1 is uninstalled.") + ui.Dim.Render(" Windows' settings are back to how they were."))
			return nil
		},
	}
	c.Flags().BoolVar(&purge, "purge", false, "also delete alert history and logs")
	c.Flags().BoolVarP(&yes, "yes", "y", false, "don't ask for confirmation")
	return c
}
