// SPDX-License-Identifier: AGPL-3.0-or-later
package cmd

import (
	"github.com/spf13/cobra"
)

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Run the daemon (M2+: real watcher + syncer)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return notImplemented(cmd, "start")
	},
}

func init() {
	startCmd.Flags().Bool("detach", false, "Fork and write a pidfile")
}
