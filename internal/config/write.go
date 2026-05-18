// SPDX-License-Identifier: AGPL-3.0-or-later
// Atomic TOML writer for crate-agent.toml. `crate-agent pair` (M2)
// writes the config once per pair; `crate-agent reconfigure` (M3) will
// re-read it.

package config

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// Write serializes c to TOML and atomic-writes it to path at mode 0600.
// Pattern matches identity.Write (temp file under same dir + fchmod +
// fsync + rename). Crash-safe: either the new file is in place fully,
// or the old file (if any) is untouched.
func Write(path string, c *Config) error {
	if path == "" {
		return fmt.Errorf("config.Write: path is required")
	}
	if c == nil {
		return fmt.Errorf("config.Write: config is nil")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("config.Write: mkdir parent: %w", err)
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("config.Write: open tmp %s: %w", tmp, err)
	}
	enc := toml.NewEncoder(f)
	if err := enc.Encode(c); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("config.Write: encode: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("config.Write: fsync: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("config.Write: close: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("config.Write: rename: %w", err)
	}
	return nil
}
