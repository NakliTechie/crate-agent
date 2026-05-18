// SPDX-License-Identifier: AGPL-3.0-or-later
package cmd

import (
	"github.com/spf13/cobra"
)

var pairCmd = &cobra.Command{
	Use:   "pair",
	Short: "Redeem a CRATE-PAIR-… token from the browser (M2)",
	Long: `Phase 3 of crate-pairing-protocol-v1.0. The daemon decodes the token,
generates an ephemeral Ed25519 keypair, prompts for the folder passphrase,
posts to {transport_endpoint}/v1/pairing/redeem, receives a long-lived
capability, writes config TOML + identity key (0600), and runs doctor.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return notImplemented(cmd, "pair")
	},
}
