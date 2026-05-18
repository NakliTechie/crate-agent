// SPDX-License-Identifier: AGPL-3.0-or-later
package cmd

import (
	"github.com/spf13/cobra"
)

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Signal the running daemon to terminate (M2+)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return notImplemented(cmd, "stop")
	},
}
