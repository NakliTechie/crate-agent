// SPDX-License-Identifier: AGPL-3.0-or-later
package cmd

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/NakliTechie/crate-agent/internal/pidfile"
)

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Signal the running daemon to terminate",
	Long: `Sends SIGTERM to the daemon recorded in the pidfile and waits up
to --timeout for it to exit (default 10s). The daemon drains its in-flight
work — current upload, manifest write, debounce buffer — before exiting.

Exit codes: 0 = stopped cleanly; 1 = generic; 5 = not running.`,
	RunE: runStop,
}

func init() {
	stopCmd.Flags().String("pidfile", "",
		"PID-file path (default: $XDG_STATE_HOME/nakli/crate-agent.pid)")
	stopCmd.Flags().Duration("timeout", 10*time.Second,
		"How long to wait for the daemon to exit before reporting failure")
}

func runStop(cmd *cobra.Command, _ []string) error {
	pidPath, _ := cmd.Flags().GetString("pidfile")
	if pidPath == "" {
		p, err := pidfile.DefaultPath()
		if err != nil {
			return exitErr(exitConfigError, err)
		}
		pidPath = p
	}

	pid, err := pidfile.ReadAndValidate(pidPath)
	if err != nil {
		if errors.Is(err, pidfile.ErrNotRunning) {
			fmt.Fprintln(os.Stderr, "✗ no running daemon")
			return exitErr(exitNotRunning, err)
		}
		return exitErr(exitGeneric, err)
	}

	proc, err := os.FindProcess(pid)
	if err != nil {
		return exitErr(exitGeneric, fmt.Errorf("find pid %d: %w", pid, err))
	}
	if err := proc.Signal(syscall.SIGTERM); err != nil {
		return exitErr(exitGeneric, fmt.Errorf("signal pid %d: %w", pid, err))
	}
	fmt.Printf("✓ sent SIGTERM to pid %d\n", pid)

	// Poll the pidfile until it's gone OR timeout.
	timeout, _ := cmd.Flags().GetDuration("timeout")
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := pidfile.ReadAndValidate(pidPath); errors.Is(err, pidfile.ErrNotRunning) {
			fmt.Println("✓ daemon stopped")
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Fprintf(os.Stderr,
		"✗ daemon did not exit within %s; pidfile still references pid %d\n", timeout, pid)
	return exitErr(exitGeneric, errors.New("stop timeout"))
}
