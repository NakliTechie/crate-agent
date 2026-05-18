// SPDX-License-Identifier: AGPL-3.0-or-later
package cmd

import (
	"github.com/spf13/cobra"
)

var uninstallServiceCmd = &cobra.Command{
	Use:   "uninstall-service",
	Short: "Stop, disable, and remove the user-level service (M6)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return notImplemented(cmd, "uninstall-service")
	},
}
