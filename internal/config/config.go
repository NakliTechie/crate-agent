// SPDX-License-Identifier: AGPL-3.0-or-later
// Package config loads `~/.config/nakli/crate-agent.toml` (or platform
// equivalent — see paths.go). Schema per crate-daemon-handoff-v1.0.md
// §"Config file format".
//
// At M1 the loader covers the read path only: open + parse + tilde-expand.
// `crate-agent pair` (M2) writes this file; M1 only reads it for `doctor`.

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config mirrors the schema in crate-daemon-handoff-v1.0.md §"Config file
// format". Field tags use TOML's lowercase-with-underscores convention.
type Config struct {
	Agent    AgentSection    `toml:"agent"`
	Identity IdentitySection `toml:"identity"`
	Crate    CrateSection    `toml:"crate"`
}

// AgentSection holds runtime + observability settings.
type AgentSection struct {
	LogLevel string `toml:"log_level"` // debug | info | warn | error
	LogPath  string `toml:"log_path"`
	StateDB  string `toml:"state_db"`
}

// IdentitySection points at the FIF (Fabric Identity File) on disk.
type IdentitySection struct {
	Path string `toml:"path"` // absolute or tilde-prefixed
}

// CrateSection describes the single folder being synced (v1.0 is one-folder;
// v1.3 makes this an array).
type CrateSection struct {
	Name              string `toml:"name"`
	LocalPath         string `toml:"local_path"`
	TransportEndpoint string `toml:"transport_endpoint"`
	TransportType     string `toml:"transport_type"`  // cf-worker | hub | managed
	PairingToken      string `toml:"pairing_token"`   // encrypted blob, opaque
	BucketID          string `toml:"bucket_id"`
	EncryptAtRest     bool   `toml:"encrypt_at_rest"`
}

// Defaults supplies sensible values for optional fields. Callers merge
// these into a freshly-decoded Config before validation.
func Defaults() Config {
	return Config{
		Agent: AgentSection{
			LogLevel: "info",
		},
	}
}

// Load reads a TOML config from `path`. Tilde-prefixed paths inside the
// config (e.g. `~/.config/nakli/identity.key`) are expanded so callers
// can use the values directly without re-doing path resolution.
func Load(path string) (*Config, error) {
	if path == "" {
		return nil, errors.New("config: path is required")
	}
	cfg := Defaults()
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("config: decode %s: %w", path, err)
	}
	if err := expandTildes(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks the M1 minimum: agent.log_level is a known value, the
// identity path is set, the transport endpoint parses as a URL, local_path
// is set. M2+ adds more fields (pairing token format, bucket id shape, etc.).
func (c *Config) Validate() error {
	if c.Agent.LogLevel != "" {
		switch c.Agent.LogLevel {
		case "debug", "info", "warn", "error":
		default:
			return fmt.Errorf("config: agent.log_level must be debug|info|warn|error, got %q", c.Agent.LogLevel)
		}
	}
	if c.Identity.Path == "" {
		return errors.New("config: identity.path is required")
	}
	if c.Crate.LocalPath == "" {
		return errors.New("config: crate.local_path is required")
	}
	if c.Crate.TransportEndpoint == "" {
		return errors.New("config: crate.transport_endpoint is required")
	}
	return nil
}

func expandTildes(c *Config) error {
	for _, p := range []*string{
		&c.Agent.LogPath,
		&c.Agent.StateDB,
		&c.Identity.Path,
		&c.Crate.LocalPath,
	} {
		v, err := expand(*p)
		if err != nil {
			return err
		}
		*p = v
	}
	return nil
}

func expand(p string) (string, error) {
	if p == "" || !strings.HasPrefix(p, "~") {
		return p, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("config: resolve ~ in %q: %w", p, err)
	}
	return filepath.Join(home, strings.TrimPrefix(p, "~")), nil
}
