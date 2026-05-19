// SPDX-License-Identifier: AGPL-3.0-or-later
package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/NakliTechie/crate-agent/internal/config"
	"github.com/NakliTechie/crate-agent/internal/pidfile"
	"github.com/NakliTechie/crate-agent/internal/state"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show daemon process state, queue depth, recent conflicts",
	Long: `Reports whether the daemon is currently running, where the local
state lives, the depth of the pending-upload queue, and the most recent
conflict events.

The status check does NOT require the folder passphrase — it only reads
state.db (no decryption of the capability needed). Useful for supervisor
health-probes that should not see the passphrase.

Exit codes: 0 = report printed; 1 = generic error; 2 = config error.`,
	RunE: runStatus,
}

func init() {
	statusCmd.Flags().StringP("config", "c", "", "Path to crate-agent.toml")
	statusCmd.Flags().Bool("json", false, "Machine-readable JSON output")
	statusCmd.Flags().String("pidfile", "",
		"PID-file path (default: $XDG_STATE_HOME/nakli/crate-agent.pid)")
}

// StatusReport is the data structure for both --json output and the
// human-readable rendering.
type StatusReport struct {
	Running          bool   `json:"running"`
	PID              int    `json:"pid,omitempty"`
	PIDFile          string `json:"pidfile"`
	LocalPath        string `json:"local_path"`
	BucketID         string `json:"bucket_id"`
	Transport        string `json:"transport_endpoint"`
	StateDB          string `json:"state_db"`
	PendingUploads   int    `json:"pending_uploads"`
	RecentConflicts  []ConflictReport `json:"recent_conflicts,omitempty"`
	CapabilityExpiry string `json:"capability_expires,omitempty"`
}

// ConflictReport is one row from conflict_log surfaced in the status output.
type ConflictReport struct {
	DetectedAt           string `json:"detected_at"`
	RemotePath           string `json:"remote_path"`
	ConflictingLocalPath string `json:"conflicting_local_path"`
	Resolution           string `json:"resolution,omitempty"`
}

func runStatus(cmd *cobra.Command, _ []string) error {
	cfgPath, _ := cmd.Flags().GetString("config")
	if cfgPath == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return exitErr(exitConfigError, fmt.Errorf("home: %w", err))
		}
		cfgPath = filepath.Join(home, ".config", "nakli", "crate-agent.toml")
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return exitErr(exitConfigError, err)
	}

	pidPath, _ := cmd.Flags().GetString("pidfile")
	if pidPath == "" {
		p, err := pidfile.DefaultPath()
		if err != nil {
			return exitErr(exitConfigError, err)
		}
		pidPath = p
	}

	statePath := cfg.Agent.StateDB
	if statePath == "" {
		statePath = state.DefaultPath(cfg.Crate.LocalPath)
	}

	rep := StatusReport{
		PIDFile:   pidPath,
		LocalPath: cfg.Crate.LocalPath,
		BucketID:  cfg.Crate.BucketID,
		Transport: cfg.Crate.TransportEndpoint,
		StateDB:   statePath,
	}
	if cfg.Crate.CapabilityExpires > 0 {
		rep.CapabilityExpiry = time.Unix(cfg.Crate.CapabilityExpires, 0).UTC().Format(time.RFC3339)
	}

	if pid, err := pidfile.ReadAndValidate(pidPath); err == nil {
		rep.Running = true
		rep.PID = pid
	}

	// Read state.db, but tolerate its absence — a daemon that has never
	// been started yet still gets a useful status report.
	if _, serr := os.Stat(statePath); serr == nil {
		store, err := state.Open(statePath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "warning: cannot open state DB:", err)
		} else {
			defer func() { _ = store.Close() }()
			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
			defer cancel()
			if n, qerr := store.PendingUploadCount(ctx); qerr == nil {
				rep.PendingUploads = n
			}
			if cs, qerr := store.RecentConflicts(ctx, 5); qerr == nil {
				for _, c := range cs {
					rep.RecentConflicts = append(rep.RecentConflicts, ConflictReport{
						DetectedAt:           c.DetectedAt.UTC().Format(time.RFC3339),
						RemotePath:           c.RemotePath,
						ConflictingLocalPath: c.ConflictingLocalPath,
						Resolution:           c.Resolution,
					})
				}
			}
		}
	} else if !errors.Is(serr, os.ErrNotExist) {
		fmt.Fprintln(os.Stderr, "warning: stat state DB:", serr)
	}

	if jsonOut, _ := cmd.Flags().GetBool("json"); jsonOut {
		return writeJSON(os.Stdout, rep)
	}
	return writeHuman(os.Stdout, rep)
}

func writeJSON(w io.Writer, rep StatusReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}

func writeHuman(w io.Writer, rep StatusReport) error {
	state := "stopped"
	if rep.Running {
		state = fmt.Sprintf("running (pid %d)", rep.PID)
	}
	fmt.Fprintf(w, "Daemon:           %s\n", state)
	fmt.Fprintf(w, "PID file:         %s\n", rep.PIDFile)
	fmt.Fprintf(w, "Folder:           %s\n", rep.LocalPath)
	fmt.Fprintf(w, "Bucket:           %s\n", rep.BucketID)
	fmt.Fprintf(w, "Transport:        %s\n", rep.Transport)
	fmt.Fprintf(w, "State DB:         %s\n", rep.StateDB)
	if rep.CapabilityExpiry != "" {
		fmt.Fprintf(w, "Capability until: %s\n", rep.CapabilityExpiry)
	}
	fmt.Fprintf(w, "Pending uploads:  %d\n", rep.PendingUploads)
	if len(rep.RecentConflicts) > 0 {
		fmt.Fprintln(w, "Recent conflicts:")
		for _, c := range rep.RecentConflicts {
			fmt.Fprintf(w, "  %s  %s  → %s  (%s)\n",
				c.DetectedAt, c.RemotePath, c.ConflictingLocalPath, c.Resolution)
		}
	}
	return nil
}
