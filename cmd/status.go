// SPDX-License-Identifier: AGPL-3.0-or-later
package cmd

import (
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show daemon state, folder, queue depth (M2+)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return notImplemented(cmd, "status")
	},
}

func init() {
	statusCmd.Flags().Bool("json", false, "Machine-readable output")
	statusCmd.Flags().String("folder", "", "Limit to a specific folder")
}
