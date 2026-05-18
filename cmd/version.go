// SPDX-License-Identifier: AGPL-3.0-or-later
package cmd

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version, build date, git SHA, Go runtime, OS/arch",
	Long: `Per crate-daemon-handoff-v1.0.md §"CLI commands", version output
is structured so the onboarding mock can scrape build metadata as the M1
verification step. Format is human-readable; --json comes at M2.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("crate-agent version", binaryVersion)
		fmt.Println("  Go runtime:", runtime.Version())
		fmt.Println("  OS/arch:   ", runtime.GOOS+"/"+runtime.GOARCH)
		if info, ok := debug.ReadBuildInfo(); ok {
			var vcsRev, vcsTime, vcsModified string
			for _, s := range info.Settings {
				switch s.Key {
				case "vcs.revision":
					vcsRev = s.Value
				case "vcs.time":
					vcsTime = s.Value
				case "vcs.modified":
					vcsModified = s.Value
				}
			}
			if vcsRev != "" {
				dirty := ""
				if vcsModified == "true" {
					dirty = " (dirty)"
				}
				fmt.Printf("  Git SHA:    %s%s\n", vcsRev, dirty)
			}
			if vcsTime != "" {
				fmt.Println("  Build date:", vcsTime)
			}
		}
	},
}
