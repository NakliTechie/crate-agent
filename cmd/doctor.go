// SPDX-License-Identifier: AGPL-3.0-or-later
package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/NakliTechie/crate-agent/internal/config"
	"github.com/NakliTechie/crate-agent/internal/httpc"
	"github.com/NakliTechie/crate-agent/internal/identity"
)

// Exit codes per crate-daemon-handoff-v1.0.md §"CLI commands":
//   0 = success     1 = generic     2 = config     3 = transport unreachable
//   4 = already running     5 = not running

const (
	exitOK              = 0
	exitGeneric         = 1
	exitConfigError     = 2
	exitTransportDown   = 3
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Self-check config, identity, transport, state, watcher",
	Long: `Run a series of checks: config validity, identity key present
and readable, transport reachable, state.db readable, watcher functional.

M1: the first three checks are real. State + watcher are stubbed and
marked deferred until M2 (state) and M3 (watcher).

Exit codes: 0 = all pass; 1 = generic; 2 = config; 3 = transport.`,
	RunE: runDoctor,
}

func init() {
	doctorCmd.Flags().StringP("config", "c", "", "Path to crate-agent.toml (default: ~/.config/nakli/crate-agent.toml)")
	doctorCmd.Flags().String("passphrase-env", "CRATE_AGENT_PASSPHRASE", "Env var holding the FIF passphrase (no interactive prompt at M1)")
	doctorCmd.Flags().Bool("json", false, "Machine-readable output (M2+)")
}

func runDoctor(cmd *cobra.Command, _ []string) error {
	cfgPath, _ := cmd.Flags().GetString("config")
	if cfgPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, "✗ Config: cannot resolve home directory:", err)
			return exitErr(exitConfigError, err)
		}
		cfgPath = home + "/.config/nakli/crate-agent.toml"
	}

	// Check 1 — config validity.
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "✗ Config:", err)
		return exitErr(exitConfigError, err)
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(os.Stderr, "✗ Config:", err)
		return exitErr(exitConfigError, err)
	}
	fmt.Println("✓ Config valid")

	// Check 2 — identity present + readable + unlockable.
	passEnv, _ := cmd.Flags().GetString("passphrase-env")
	pass := os.Getenv(passEnv)
	if pass == "" {
		err := fmt.Errorf("identity: %s env var is empty; set it to the FIF passphrase", passEnv)
		fmt.Fprintln(os.Stderr, "✗ Identity:", err)
		return exitErr(exitGeneric, err)
	}
	fif, err := identity.Load(cfg.Identity.Path, pass)
	if err != nil {
		fmt.Fprintln(os.Stderr, "✗ Identity:", err)
		return exitErr(exitGeneric, err)
	}
	_ = fif // M1 just verifies unlocking succeeded; further use comes at M2+
	fmt.Println("✓ Identity loaded + unlocked")

	// Check 3 — transport reachable.
	ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
	defer cancel()
	client := httpc.New(cfg.Crate.TransportEndpoint)
	resp, err := client.Health(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, "✗ Transport:", err)
		return exitErr(exitTransportDown, err)
	}
	if resp.Status < 200 || resp.Status >= 300 {
		err := fmt.Errorf("transport returned HTTP %d", resp.Status)
		if resp.Envelope.Error != nil {
			err = fmt.Errorf("transport returned HTTP %d: %s (%s)", resp.Status, resp.Envelope.Error.Code, resp.Envelope.Error.Message)
		}
		fmt.Fprintln(os.Stderr, "✗ Transport:", err)
		return exitErr(exitTransportDown, err)
	}
	if !resp.Envelope.OK {
		err := errors.New("transport responded but envelope ok=false")
		fmt.Fprintln(os.Stderr, "✗ Transport:", err)
		return exitErr(exitTransportDown, err)
	}
	fmt.Printf("✓ Transport reachable (%s, HTTP %d)\n", cfg.Crate.TransportEndpoint, resp.Status)

	// Check 4 — state.db (deferred; M2+).
	fmt.Println("⚠ State DB: deferred to M2 (no daemon state at M1)")

	// Check 5 — watcher (deferred; M3+).
	fmt.Println("⚠ Watcher: deferred to M3 (no daemon loop at M1)")

	return nil
}

// exitErr lets RunE return both an error (so cobra surfaces a non-zero
// exit) and a specific code. Cobra's default RunE handler exits 1 on any
// non-nil error; the spec wants 0/1/2/3 distinctions, so we os.Exit
// directly with the right code.
func exitErr(code int, _ error) error {
	os.Exit(code)
	return nil
}
