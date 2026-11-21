package cli

import (
	"context"
	"fmt"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/xak1234/sentient1/internal/config"
	"github.com/xak1234/sentient1/internal/install"
	"github.com/xak1234/sentient1/internal/logx"
	"github.com/xak1234/sentient1/internal/paths"
	"github.com/xak1234/sentient1/internal/ui"
	"github.com/xak1234/sentient1/internal/update"
)

func updateCmd() *cobra.Command {
	var check, yes bool
	c := &cobra.Command{
		Use:   "update",
		Short: "Install the latest signed version",
		Long: "Checks GitHub for a newer release. Updates are only installed if the release is signed\n" +
			"with sentient1' release key and the download matches its signed checksum.\n" +
			"Automatic updates can be turned on or off with `sentient1 configure`.",
		Example: "  sentient1 update\n  sentient1 update --check",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !update.Enabled() {
				fmt.Println("sentient1 updates are manual. No release server or signing key is configured; no network request was made.")
				return nil
			}
			if !check {
				if err := requireAdmin(); err != nil {
					return err
				}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
			defer cancel()
			fmt.Println(ui.Dim.Render("Checking for a new version…"))
			rel, err := update.Latest(ctx)
			if err != nil {
				return err
			}
			cfg, _ := config.LoadConfig()
			autoLine := func() {
				if cfg == nil {
					return
				}
				if cfg.AutoUpdate {
					fmt.Println(ui.Dim.Render("Automatic updates are on."))
				} else {
					fmt.Println(ui.Dim.Render("Automatic updates are off. Turn them on with ") + ui.Code.Render("sentient1 configure"))
				}
			}
			if !update.Updatable(Version) {
				fmt.Printf("This is a %s build, which doesn't update itself. The latest release is %s.\n", Version, rel.Tag)
				return nil
			}
			if !update.Newer(Version, rel.Tag) {
				fmt.Println(ui.Good.Render(ui.IconOK) + " You're on the latest version (" + Version + ").")
				autoLine()
				return nil
			}
			fmt.Printf("%s %s is available (you have %s)\n  %s\n", ui.Warn.Render(ui.IconArr), ui.Bold.Render(rel.Tag), Version, ui.Dim.Render(rel.HTMLURL))
			if check {
				fmt.Println(ui.Hint("Install it with", "sentient1 update"))
				return nil
			}
			if !yes && ui.IsTTY() {
				ok := true
				huh.NewConfirm().Title("Install " + rel.Tag + " now?").
					Description("Protection pauses for a few seconds while the service restarts.").
					Affirmative("Update").Negative("Not now").Value(&ok).WithTheme(theme()).Run()
				if !ok {
					return nil
				}
			}
			var exe string
			steps := []install.Step{
				{Name: "Downloading " + rel.Tag, Run: func() (string, error) {
					var err error
					exe, err = update.Download(ctx, rel, update.Dir())
					if err != nil {
						return "", err
					}
					update.Cleanup(exe)
					return "signature and checksum verified", nil
				}},
				{Name: "Installing and restarting the service", Run: func() (string, error) {
					log := logx.New(paths.LogFile(), false)
					if err := update.Apply(exe, log.Printf); err != nil {
						return "", err
					}
					log.Printf("update: %s -> %s (sentient1 update)", Version, rel.Tag)
					recordUpdated(Version, rel.Tag)
					return "", nil
				}},
			}
			fmt.Println()
			if err := ui.RunSteps("Updating sentient1", steps); err != nil {
				return err
			}
			fmt.Println("\n" + ui.Good.Render(ui.IconOK) + " Updated to " + rel.Tag + ".")
			autoLine()
			return nil
		},
	}
	c.Flags().BoolVar(&check, "check", false, "only check, don't install")
	c.Flags().BoolVarP(&yes, "yes", "y", false, "don't ask for confirmation")
	c.AddCommand(updateApplyCmd())
	return c
}

// updateApplyCmd is run by the service, as the new (already verified) binary:
// it stops the service, swaps the files and starts the new version.
func updateApplyCmd() *cobra.Command {
	var file, from string
	c := &cobra.Command{
		Use:    "apply",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !update.Enabled() {
				fmt.Println("sentient1 updates are manual. No release server or signing key is configured; no network request was made.")
				return nil
			}
			log := logx.New(paths.LogFile(), false)
			time.Sleep(time.Second) // let the service finish logging the hand-over
			if err := update.Apply(file, log.Printf); err != nil {
				log.Printf("update to %s failed: %v", Version, err)
				config.UpdateState(func(st *config.State) error {
					if st.Update == nil {
						st.Update = &config.UpdateStatus{}
					}
					st.Update.LastResult = "update to " + Version + " failed: " + err.Error()
					return nil
				})
				return err
			}
			log.Printf("update: %s -> %s (automatic)", from, Version)
			recordUpdated(from, Version)
			return nil
		},
	}
	c.Flags().StringVar(&file, "file", "", "verified update to install")
	c.Flags().StringVar(&from, "from", "", "version being replaced")
	return c
}

func recordUpdated(from, to string) {
	config.UpdateState(func(st *config.State) error {
		if st.Update == nil {
			st.Update = &config.UpdateStatus{}
		}
		st.Update.UpdatedAt = time.Now()
		st.Update.UpdatedTo = to
		st.Update.Latest = to
		st.Update.LastResult = "updated from " + from + " to " + to
		return nil
	})
}
