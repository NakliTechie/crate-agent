// SPDX-License-Identifier: AGPL-3.0-or-later
package cmd

import (
	"github.com/spf13/cobra"
)

var (
	binaryVersion = "0.0.0-m0"

	rootCmd = &cobra.Command{
		Use:   "crate-agent",
		Short: "Sync ~/crate with your Crate cloud folder",
		Long: `crate-agent watches a local folder and keeps it in sync with your Crate.
The daemon does NOT hold bucket credentials — it authenticates to a transport
(nakli-hub or nakli-cf-worker) using a pairing token issued by the browser
Crate. See https://github.com/NakliTechie/private-mesh docs/specs/
crate-daemon-handoff-v1.0.md.`,
	}
)

func init() {
	rootCmd.AddCommand(startCmd, stopCmd, statusCmd, pairCmd, doctorCmd, reconfigureCmd, installServiceCmd, uninstallServiceCmd, versionCmd)
}

func SetVersion(v string) { binaryVersion = v }

func Root() *cobra.Command { return rootCmd }
