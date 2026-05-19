// SPDX-License-Identifier: AGPL-3.0-or-later
package pidfile

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestCreateAndReadAndValidate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.pid")

	// Empty → not running.
	if _, err := ReadAndValidate(path); !errors.Is(err, ErrNotRunning) {
		t.Errorf("expected ErrNotRunning for missing file, got %v", err)
	}

	// Create + validate.
	if err := Create(path); err != nil {
		t.Fatal(err)
	}
	pid, err := ReadAndValidate(path)
	if err != nil {
		t.Fatal(err)
	}
	if pid != os.Getpid() {
		t.Errorf("ReadAndValidate pid = %d, want %d", pid, os.Getpid())
	}

	// File on disk holds the PID.
	b, _ := os.ReadFile(path)
	if got, _ := strconv.Atoi(string(b[:len(b)-1])); got != os.Getpid() {
		t.Errorf("on-disk pid = %d, want %d", got, os.Getpid())
	}

	// Remove cleans up.
	if err := Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("Remove did not delete file: %v", err)
	}
	// Remove of already-gone file is not an error.
	if err := Remove(path); err != nil {
		t.Errorf("idempotent Remove failed: %v", err)
	}
}

func TestCreateRejectsRunningProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "running.pid")
	// Seed with this test's PID — the process IS running.
	if err := Create(path); err != nil {
		t.Fatal(err)
	}
	// Second Create should fail with ErrAlreadyRunning.
	err := Create(path)
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("expected ErrAlreadyRunning, got %v", err)
	}
}

func TestCreateOverwritesStaleFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stale.pid")
	// PID 999999 is essentially guaranteed not to exist on any normal box.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("999999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Stale file → Create overwrites silently.
	if err := Create(path); err != nil {
		t.Errorf("Create should overwrite stale file; got %v", err)
	}
	pid, err := ReadAndValidate(path)
	if err != nil {
		t.Fatal(err)
	}
	if pid != os.Getpid() {
		t.Errorf("post-overwrite pid = %d, want %d", pid, os.Getpid())
	}
}

func TestReadAndValidateRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "garbage.pid")
	_ = os.WriteFile(path, []byte("not-a-number\n"), 0o600)
	if _, err := ReadAndValidate(path); !errors.Is(err, ErrNotRunning) {
		t.Errorf("expected ErrNotRunning for garbage content, got %v", err)
	}
}

func TestDefaultPath(t *testing.T) {
	// XDG_STATE_HOME set → use it verbatim.
	t.Setenv("XDG_STATE_HOME", "/custom/state")
	p, err := DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	want := "/custom/state/nakli/crate-agent.pid"
	if p != want {
		t.Errorf("DefaultPath(XDG_STATE_HOME=/custom/state) = %q, want %q", p, want)
	}

	// XDG_STATE_HOME unset → fallback to ~/.local/state.
	t.Setenv("XDG_STATE_HOME", "")
	p, err = DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	want = filepath.Join(home, ".local", "state", "nakli", "crate-agent.pid")
	if p != want {
		t.Errorf("DefaultPath(unset) = %q, want %q", p, want)
	}
}
