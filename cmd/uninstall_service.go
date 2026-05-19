// SPDX-License-Identifier: AGPL-3.0-or-later
package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/NakliTechie/crate-agent/internal/service"
)

var uninstallServiceCmd = &cobra.Command{
	Use:   "uninstall-service",
	Short: "Remove the user-level supervisor unit installed by install-service",
	Long: `Removes the launchd plist (macOS) or systemd user unit (Linux) installed
by install-service. Does NOT call launchctl bootout / systemctl disable for
you — run those first to stop the daemon. uninstall-service just deletes
the unit file.

Exit codes: 0 = removed (or already absent); 1 = generic.`,
	RunE: runUninstallService,
}

func init() {
	uninstallServiceCmd.Flags().String("label", service.DefaultLabel,
		"Service label to remove (default: com.naklitechie.crate-agent)")
}

func runUninstallService(cmd *cobra.Command, _ []string) error {
	label, _ := cmd.Flags().GetString("label")
	path, absent, err := service.Uninstall(label)
	if err != nil {
		return exitErr(exitGeneric, err)
	}
	if absent {
		fmt.Printf("✓ no service file at %s (already absent)\n", path)
		return nil
	}
	fmt.Printf("✓ removed %s\n", path)
	hint := "  (You may want to run `launchctl bootout gui/$(id -u)/" + label + "` first to unload.)"
	if runtime.GOOS == "linux" {
		hint = "  (You may want to run `systemctl --user disable --now " + label + ".service` first.)"
	}
	fmt.Println(hint)
	return nil
}
