// SPDX-License-Identifier: AGPL-3.0-or-later
package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/NakliTechie/crate-agent/internal/config"
	"github.com/NakliTechie/crate-agent/internal/httpc"
	"github.com/NakliTechie/crate-agent/internal/identity"
	"github.com/NakliTechie/crate-agent/internal/state"
	"github.com/NakliTechie/crate-agent/internal/watcher"
)

// Exit codes per crate-daemon-handoff-v1.0.md §"CLI commands":
//   0 = success     1 = generic     2 = config     3 = transport unreachable
//   4 = already running     5 = not running

const (
	exitOK             = 0
	exitGeneric        = 1
	exitConfigError    = 2
	exitTransportDown  = 3
	exitAlreadyRunning = 4
	exitNotRunning     = 5
)

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Self-check config, identity, transport, state, watcher",
	Long: `Run a series of checks: config validity, identity key present
and readable, transport reachable, state.db readable, watcher functional.

M3: all five checks real. State DB opens the local SQLite at agent.state_db
(default: <local_path>/.crate/state.db) and runs migrations + a pending-uploads
query. Watcher verifies fsnotify + the .crateignore parse + that local_path is
watchable.

Exit codes: 0 = all pass; 1 = generic; 2 = config; 3 = transport.`,
	RunE: runDoctor,
}

func init() {
	doctorCmd.Flags().StringP("config", "c", "", "Path to crate-agent.toml (default: ~/.config/nakli/crate-agent.toml)")
	doctorCmd.Flags().String("passphrase-env", "CRATE_AGENT_PASSPHRASE", "Env var holding the FIF passphrase (cobra entry; pair invokes RunChecks directly)")
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
	passEnv, _ := cmd.Flags().GetString("passphrase-env")
	pass := os.Getenv(passEnv)
	if err := RunChecks(cmd.Context(), os.Stdout, os.Stderr, cfgPath, pass); err != nil {
		code := exitCodeFor(err)
		return exitErr(code, err)
	}
	return nil
}

// RunChecks executes the three real checks (config / identity / transport)
// + the two stubs (state / watcher). Returns a typed error so callers can
// map it to a specific exit code via exitCodeFor. Used by `crate-agent
// doctor` standalone AND by `crate-agent pair`'s auto-doctor step.
//
// Output is written to `stdout` for ✓/⚠ lines and `stderr` for ✗ failures.
// Passing nil for either writer suppresses that stream.
func RunChecks(ctx context.Context, stdout, stderr io.Writer, cfgPath, passphrase string) error {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}

	// Check 1 — config validity.
	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintln(stderr, "✗ Config:", err)
		return &checkErr{kind: checkConfig, err: err}
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(stderr, "✗ Config:", err)
		return &checkErr{kind: checkConfig, err: err}
	}
	fmt.Fprintln(stdout, "✓ Config valid")

	// Check 2 — identity present + readable + unlockable.
	if passphrase == "" {
		err := errors.New("identity: passphrase is empty; set CRATE_AGENT_PASSPHRASE or pass via pair's in-process call")
		fmt.Fprintln(stderr, "✗ Identity:", err)
		return &checkErr{kind: checkGeneric, err: err}
	}
	fif, err := identity.Load(cfg.Identity.Path, passphrase)
	if err != nil {
		fmt.Fprintln(stderr, "✗ Identity:", err)
		return &checkErr{kind: checkGeneric, err: err}
	}
	_ = fif // verifying unlock succeeded is enough at M2; M3+ uses it for sync
	fmt.Fprintln(stdout, "✓ Identity loaded + unlocked")

	// Check 3 — transport reachable.
	timeoutCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	client := httpc.NewFor(cfg.Crate.TransportType, cfg.Crate.TransportEndpoint, "")
	resp, err := client.Health(timeoutCtx)
	if err != nil {
		fmt.Fprintln(stderr, "✗ Transport:", err)
		return &checkErr{kind: checkTransport, err: err}
	}
	if resp.Status < 200 || resp.Status >= 300 {
		err := fmt.Errorf("transport returned HTTP %d", resp.Status)
		if resp.Envelope.Error != nil {
			err = fmt.Errorf("transport returned HTTP %d: %s (%s)", resp.Status, resp.Envelope.Error.Code, resp.Envelope.Error.Message)
		}
		fmt.Fprintln(stderr, "✗ Transport:", err)
		return &checkErr{kind: checkTransport, err: err}
	}
	if !resp.Envelope.OK {
		err := errors.New("transport responded but envelope ok=false")
		fmt.Fprintln(stderr, "✗ Transport:", err)
		return &checkErr{kind: checkTransport, err: err}
	}
	fmt.Fprintf(stdout, "✓ Transport reachable (%s, HTTP %d)\n", cfg.Crate.TransportEndpoint, resp.Status)

	// Check 4 — state.db (M3+).
	statePath := cfg.Agent.StateDB
	if statePath == "" {
		statePath = state.DefaultPath(cfg.Crate.LocalPath)
	}
	if err := os.MkdirAll(filepath.Dir(statePath), 0o700); err != nil {
		fmt.Fprintln(stderr, "✗ State DB:", err)
		return &checkErr{kind: checkGeneric, err: err}
	}
	store, err := state.Open(statePath)
	if err != nil {
		fmt.Fprintln(stderr, "✗ State DB:", err)
		return &checkErr{kind: checkGeneric, err: err}
	}
	defer store.Close()
	if pending, err := store.PendingUploadCount(ctx); err != nil {
		fmt.Fprintln(stderr, "✗ State DB query:", err)
		return &checkErr{kind: checkGeneric, err: err}
	} else {
		fmt.Fprintf(stdout, "✓ State DB ready (%s, %d pending uploads)\n", statePath, pending)
	}

	// Check 5 — watcher (M3+). Verifies fsnotify + .crateignore parse + the
	// crate root is watchable. We construct + immediately close — actually
	// running the watcher is a job for `start`.
	if cfg.Crate.LocalPath == "" {
		fmt.Fprintln(stderr, "✗ Watcher: crate.local_path is empty")
		return &checkErr{kind: checkConfig, err: errors.New("crate.local_path is empty")}
	}
	if err := os.MkdirAll(cfg.Crate.LocalPath, 0o700); err != nil {
		fmt.Fprintln(stderr, "✗ Watcher: cannot create local_path:", err)
		return &checkErr{kind: checkGeneric, err: err}
	}
	ignorePath := filepath.Join(cfg.Crate.LocalPath, ".crateignore")
	w, err := watcher.New(watcher.Options{
		Root:       cfg.Crate.LocalPath,
		IgnoreFile: ignorePath,
	})
	if err != nil {
		fmt.Fprintln(stderr, "✗ Watcher:", err)
		return &checkErr{kind: checkGeneric, err: err}
	}
	_ = w.Close()
	fmt.Fprintf(stdout, "✓ Watcher operational (root: %s)\n", cfg.Crate.LocalPath)

	return nil
}

// --- typed check error -------------------------------------------------

type checkKind int

const (
	checkGeneric checkKind = iota
	checkConfig
	checkTransport
)

type checkErr struct {
	kind checkKind
	err  error
}

func (e *checkErr) Error() string { return e.err.Error() }
func (e *checkErr) Unwrap() error { return e.err }

func exitCodeFor(err error) int {
	var ce *checkErr
	if errors.As(err, &ce) {
		switch ce.kind {
		case checkConfig:
			return exitConfigError
		case checkTransport:
			return exitTransportDown
		}
	}
	return exitGeneric
}

// exitErr lets RunE return both an error (so cobra surfaces a non-zero
// exit) and a specific code. Cobra's default RunE handler exits 1 on any
// non-nil error; the spec wants 0/1/2/3 distinctions, so we os.Exit
// directly with the right code.
func exitErr(code int, _ error) error {
	os.Exit(code)
	return nil
}
