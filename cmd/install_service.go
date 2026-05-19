// SPDX-License-Identifier: AGPL-3.0-or-later
package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/NakliTechie/crate-agent/internal/service"
)

var installServiceCmd = &cobra.Command{
	Use:   "install-service",
	Short: "Install a user-level supervisor unit (launchd on macOS, systemd-user on Linux)",
	Long: `Generates and installs a service file so crate-agent starts at login and
restarts on crash.

macOS: writes ~/Library/LaunchAgents/{label}.plist with KeepAlive=true and
       RunAtLoad=true. Activate with:
         launchctl bootstrap gui/$(id -u) <plist>
         launchctl kickstart -k gui/$(id -u)/<label>

Linux: writes $XDG_CONFIG_HOME/systemd/user/{label}.service (default
       ~/.config/systemd/user/) with Type=simple, Restart=always. Activate
       with:
         systemctl --user daemon-reload
         systemctl --user enable --now <label>.service

The folder passphrase is NOT embedded in the service file. The unit
references an env var (default: CRATE_AGENT_PASSPHRASE); set it via
launchctl setenv (macOS) or a systemd EnvironmentFile (Linux).

Exit codes: 0 = installed; 1 = generic; 2 = config error.`,
	RunE: runInstallService,
}

func init() {
	installServiceCmd.Flags().StringP("config", "c", "", "Path to crate-agent.toml")
	installServiceCmd.Flags().String("label", service.DefaultLabel,
		"Service label (default: com.naklitechie.crate-agent)")
	installServiceCmd.Flags().String("passphrase-env", "CRATE_AGENT_PASSPHRASE",
		"Env var the unit will read the folder passphrase from")
	installServiceCmd.Flags().String("log-path", "",
		"Optional log file (default: supervisor's journal/null)")
}

func runInstallService(cmd *cobra.Command, _ []string) error {
	cfgPath, _ := cmd.Flags().GetString("config")
	if cfgPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return exitErr(exitConfigError, err)
		}
		cfgPath = filepath.Join(home, ".config", "nakli", "crate-agent.toml")
	}
	// Validate config can be loaded — installing a service that points at a
	// missing or unpaired config wastes the user's time later when they try
	// to start it.
	if _, err := os.Stat(cfgPath); err != nil {
		fmt.Fprintln(os.Stderr, "✗ Config not found:", cfgPath)
		fmt.Fprintln(os.Stderr, "  Run `crate-agent pair` first.")
		return exitErr(exitConfigError, err)
	}

	binaryPath, err := os.Executable()
	if err != nil {
		return exitErr(exitGeneric, fmt.Errorf("resolve own binary path: %w", err))
	}
	binaryPath, err = filepath.EvalSymlinks(binaryPath)
	if err != nil {
		return exitErr(exitGeneric, fmt.Errorf("resolve symlinks: %w", err))
	}

	cfgPathAbs, err := filepath.Abs(cfgPath)
	if err != nil {
		return exitErr(exitConfigError, err)
	}

	label, _ := cmd.Flags().GetString("label")
	passEnv, _ := cmd.Flags().GetString("passphrase-env")
	logPath, _ := cmd.Flags().GetString("log-path")

	path, next, err := service.Install(service.Config{
		BinaryPath:    binaryPath,
		ConfigPath:    cfgPathAbs,
		PassphraseEnv: passEnv,
		Label:         label,
		LogPath:       logPath,
	})
	if err != nil {
		return exitErr(exitGeneric, err)
	}
	fmt.Printf("✓ installed service file at %s\n", path)
	fmt.Println()
	fmt.Println(next)
	return nil
}
