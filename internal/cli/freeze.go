package cli

import (
	"github.com/spf13/cobra"
	"github.com/xak1234/sentient1/internal/respond"
)

func freezeCmd() *cobra.Command {
	return &cobra.Command{Use: "freeze <alert-id>", Short: "Pause an alert's reader until you resume it", Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := requireAdmin(); err != nil {
				return err
			}
			rep, err := respond.Freeze(args[0])
			printReport(rep)
			return err
		}}
}
