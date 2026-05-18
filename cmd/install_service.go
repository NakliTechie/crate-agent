// SPDX-License-Identifier: AGPL-3.0-or-later
package cmd

import (
	"github.com/spf13/cobra"
)

var installServiceCmd = &cobra.Command{
	Use:   "install-service",
	Short: "Install launchd plist (macOS) or systemd unit (Linux) — user-level (M6)",
	RunE: func(cmd *cobra.Command, args []string) error {
		return notImplemented(cmd, "install-service")
	},
}
