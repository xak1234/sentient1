package cli

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/xak1234/sentient1/internal/config"
	"github.com/xak1234/sentient1/internal/review"
	"github.com/xak1234/sentient1/internal/svcctl"
	"golang.org/x/sys/windows/svc"
)

func reportCmd() *cobra.Command {
	var output, format string
	var includeCommands, overwrite bool
	var limit int
	c := &cobra.Command{Use: "report", Short: "Export a local HTML or JSON incident report", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if format != "html" && format != "json" {
				return exitf("format must be html or json")
			}
			if limit < 1 || limit > 10000 {
				return exitf("limit must be between 1 and 10000")
			}
			if output == "" {
				output = "sentient1-report-" + time.Now().Format("20060102-150405") + "." + format
			}
			d, err := review.ForExport(review.Load(Version, limit), includeCommands)
			if err != nil {
				return err
			}
			flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
			if overwrite {
				flags = os.O_WRONLY | os.O_CREATE | os.O_TRUNC
			}
			f, err := os.OpenFile(output, flags, 0o600)
			if err != nil {
				return err
			}
			if format == "html" {
				err = review.WriteHTML(f, d)
			} else {
				err = review.WriteJSON(f, d)
			}
			closeErr := f.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Report saved: "+output)
			return nil
		}}
	c.Flags().StringVarP(&output, "output", "o", "", "destination file")
	c.Flags().StringVar(&format, "format", "html", "html | json")
	c.Flags().IntVar(&limit, "limit", 500, "maximum recent alerts (1-10000)")
	c.Flags().BoolVar(&includeCommands, "include-command-lines", false, "include commands, which may contain secrets")
	c.Flags().BoolVar(&overwrite, "overwrite", false, "replace the destination if it already exists")
	return c
}

func policyCmd() *cobra.Command {
	return &cobra.Command{Use: "policy <alert|balanced|strict>", Short: "Change the response policy without replanting decoys", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := strings.ToLower(args[0])
			if _, ok := config.PresetByID(id); !ok {
				return exitf("unknown policy %q", id)
			}
			if err := requireAdmin(); err != nil {
				return err
			}
			cfg, err := mustConfig()
			if err != nil {
				return err
			}
			if err = cfg.ApplyPreset(id); err != nil {
				return err
			}
			if err = config.SaveConfig(cfg); err != nil {
				return err
			}
			state, err := svcctl.Status()
			if err != nil {
				return err
			}
			if state == svcctl.Running {
				if err = svcctl.Control(svc.ParamChange); err != nil {
					return fmt.Errorf("policy saved, but service reload failed: %w", err)
				}
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Policy saved: "+id+". Existing containment remains active until explicitly released.")
			return nil
		}}
}
