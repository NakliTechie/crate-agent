// SPDX-License-Identifier: AGPL-3.0-or-later
package cmd

import (
	"github.com/spf13/cobra"
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Self-check config, identity, transport, state, watcher (M7)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return notImplemented(cmd, "doctor")
	},
}

func init() {
	doctorCmd.Flags().Bool("json", false, "Machine-readable output")
}
