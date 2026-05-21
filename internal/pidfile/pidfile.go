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
// returns ErrAlreadyRunning. Stale files (process gone) are removed +
// the call retries.
//
// The atomic-create pattern (O_CREATE|O_EXCL) closes a TOCTOU race where
// two simultaneous starts could both pass stale-detection on the
// previous version of this code (read-then-write-then-rename) and end
// up running concurrently. With O_EXCL, only the first to open wins;
// the loser observes ErrAlreadyRunning. See 2026-05 security audit L2.
func Create(path string) error {
	if path == "" {
		return errors.New("pidfile: path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("pidfile: mkdir %s: %w", filepath.Dir(path), err)
	}

	// We try at most twice: first attempt expects no existing file; on
	// failure we check whether the existing file is stale, remove it,
	// and try once more. A second-time failure means a concurrent
	// starter beat us — return ErrAlreadyRunning.
	for attempt := 0; attempt < 2; attempt++ {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		if err == nil {
			_, writeErr := f.WriteString(strconv.Itoa(os.Getpid()) + "\n")
			closeErr := f.Close()
			if writeErr != nil {
				_ = os.Remove(path)
				return fmt.Errorf("pidfile: write %s: %w", path, writeErr)
			}
			if closeErr != nil {
				return fmt.Errorf("pidfile: close %s: %w", path, closeErr)
			}
			return nil
		}
		if !os.IsExist(err) {
			return fmt.Errorf("pidfile: open %s: %w", path, err)
		}
		// File exists. Check stale-ness; if stale, remove + retry once.
		// If live, refuse.
		pid, readErr := readPID(path)
		if readErr == nil && processAlive(pid) {
			return fmt.Errorf("%w (pid %d at %s)", ErrAlreadyRunning, pid, path)
		}
		// Stale (or unreadable — same treatment, we own this path).
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("pidfile: remove stale %s: %w", path, err)
		}
		// Loop to try the O_EXCL create again. If a second starter
		// races us to the create call, they win and we return
		// ErrAlreadyRunning on the next iteration.
	}
	// Two consecutive O_EXCL failures means a concurrent starter beat
	// us to the create. Treat as already-running.
	pid, _ := readPID(path)
	return fmt.Errorf("%w (concurrent start, pid %d at %s)", ErrAlreadyRunning, pid, path)
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
