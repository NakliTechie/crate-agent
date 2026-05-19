// SPDX-License-Identifier: AGPL-3.0-or-later
// Package pidfile manages the daemon's PID-file lifecycle: atomic create on
// `start`, read on `stop`/`status`, stale-file detection (process no longer
// exists), and clean removal on graceful shutdown.
//
// Location follows the XDG-state spec: `$XDG_STATE_HOME/nakli/crate-agent.pid`
// (default `~/.local/state/nakli/crate-agent.pid`). Per crate-daemon-handoff-
// v1.0.md §"Daemon loop shape" / plan/pending.md M3 piece 8.
package pidfile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// DefaultPath returns the canonical PID-file path under XDG_STATE_HOME.
// Falls back to `~/.local/state/nakli/crate-agent.pid` when the env var
// is unset (the XDG spec's documented default).
func DefaultPath() (string, error) {
	if s := os.Getenv("XDG_STATE_HOME"); s != "" {
		return filepath.Join(s, "nakli", "crate-agent.pid"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("pidfile: resolve home: %w", err)
	}
	return filepath.Join(home, ".local", "state", "nakli", "crate-agent.pid"), nil
}

// ErrAlreadyRunning is returned by Create when a pidfile exists AND the
// referenced process is still alive.
var ErrAlreadyRunning = errors.New("pidfile: another crate-agent is already running")

// ErrNotRunning is returned by ReadAndValidate when the pidfile is absent OR
// refers to a process that no longer exists (stale file).
var ErrNotRunning = errors.New("pidfile: no running daemon")

// Create writes the current process's PID to path, creating parent dirs
// (mode 0700). If a pidfile exists AND the recorded PID is still running,
// returns ErrAlreadyRunning. Stale files (process gone) are silently
// overwritten.
func Create(path string) error {
	if path == "" {
		return errors.New("pidfile: path is required")
	}
	if pid, err := readPID(path); err == nil {
		if processAlive(pid) {
			return fmt.Errorf("%w (pid %d at %s)", ErrAlreadyRunning, pid, path)
		}
		// Stale — fall through and overwrite.
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("pidfile: mkdir %s: %w", filepath.Dir(path), err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		return fmt.Errorf("pidfile: write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("pidfile: rename %s → %s: %w", tmp, path, err)
	}
	return nil
}

// Remove deletes the pidfile. Missing file is not an error — graceful
// shutdown calls Remove from a defer, and we don't want it to mask real
// errors if a panic already removed the file.
func Remove(path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("pidfile: remove %s: %w", path, err)
	}
	return nil
}

// ReadAndValidate returns the PID stored in the pidfile, but ONLY if the
// referenced process is still alive. Returns ErrNotRunning otherwise
// (covers both "no pidfile" and "stale pidfile" cases — callers don't need
// to distinguish).
func ReadAndValidate(path string) (int, error) {
	pid, err := readPID(path)
	if err != nil {
		return 0, ErrNotRunning
	}
	if !processAlive(pid) {
		return 0, ErrNotRunning
	}
	return pid, nil
}

// readPID parses an integer from the pidfile. Returns an error if the
// file is missing OR the content is not a valid integer.
func readPID(path string) (int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(b))
	pid, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("pidfile: parse %q: %w", s, err)
	}
	if pid <= 0 {
		return 0, fmt.Errorf("pidfile: invalid pid %d", pid)
	}
	return pid, nil
}

// processAlive returns true if a process with the given PID is alive.
// Uses signal 0 (the "test whether you can signal this process" no-op),
// which is portable across macOS + Linux. On Windows the answer is
// always true and we live with the false positive (v1.0 doesn't ship
// Windows binaries).
func processAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// Signal 0: test for existence without actually signalling.
	if err := p.Signal(syscall.Signal(0)); err != nil {
		// EPERM ⇒ process exists but we can't signal it — still "alive."
		if errors.Is(err, os.ErrPermission) {
			return true
		}
		return false
	}
	return true
}
