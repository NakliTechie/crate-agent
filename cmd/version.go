// SPDX-License-Identifier: AGPL-3.0-or-later
package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version, Go runtime, and OS/arch",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("crate-agent %s (%s %s/%s)\n", binaryVersion, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	},
}
