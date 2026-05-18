// SPDX-License-Identifier: AGPL-3.0-or-later
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func notImplemented(cmd *cobra.Command, name string) error {
	return fmt.Errorf("%s: not implemented (M0 skeleton — see crate-daemon-handoff-v1.0.md for the milestone schedule)", name)
}
