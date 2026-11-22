package cli

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/spf13/cobra"
	"github.com/xak1234/sentient1/internal/alerts"
	"github.com/xak1234/sentient1/internal/authenticode"
	"github.com/xak1234/sentient1/internal/engine"
	"github.com/xak1234/sentient1/internal/procinfo"
)

func inspectCmd() *cobra.Command {
	var jsonOutput bool
	cmd := &cobra.Command{
		Use: "inspect <pid>", Short: "Identify a running process and its hosted components (read-only)", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			n, err := strconv.ParseUint(args[0], 10, 32)
			if err != nil || n == 0 {
				return fmt.Errorf("provide a nonzero numeric process ID")
			}
			pid := uint32(n)
			created, err := procinfo.CreateTime(pid)
			if err != nil {
				return err
			}
			image, err := procinfo.ImagePath(pid)
			if err != nil {
				return err
			}
			p := &alerts.Process{PID: pid, Image: image, CreateTime: created, Signature: authenticode.Verify(image)}
			engine.ProcessDetails(pid, p)
			a := &alerts.Alert{Process: p}
			a.SetReaderName()
			if jsonOutput {
				encoder := json.NewEncoder(cmd.OutOrStdout())
				encoder.SetIndent("", "  ")
				return encoder.Encode(p)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s (PID %d)\n%s\nSignature: %s\n", a.ReaderName(), pid, image, p.Signature)
			if p.Hosted != nil {
				fmt.Fprint(cmd.OutOrStdout(), p.Hosted.Details())
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&jsonOutput, "json", false, "print the process and component evidence as JSON")
	return cmd
}
