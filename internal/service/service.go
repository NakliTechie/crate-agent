// SPDX-License-Identifier: AGPL-3.0-or-later
// Package service generates and installs platform-specific user-level
// service files for crate-agent. macOS uses launchd plists at
// ~/Library/LaunchAgents/, Linux uses systemd user units at
// ~/.config/systemd/user/. The daemon ALWAYS runs in the foreground
// (KeepAlive on macOS, Type=simple on Linux); the supervisor handles
// restart on exit.
//
// User-level only — no sudo, no /etc/, no root daemons. v1.0 ships
// macOS + Linux; Windows is v1.1+.
//
// Per crate-agent/plan/pending.md M3 piece 10 + crate-daemon-handoff-
// v1.0.md §"Process model" / §"install-service".
package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Platform identifies the supervisor we're targeting.
type Platform int

const (
	// PlatformDarwin = launchd plist.
	PlatformDarwin Platform = iota + 1
	// PlatformLinux = systemd user unit.
	PlatformLinux
)

// String returns a short label for logs + the doctor command.
func (p Platform) String() string {
	switch p {
	case PlatformDarwin:
		return "launchd"
	case PlatformLinux:
		return "systemd-user"
	default:
		return "unknown"
	}
}

// ErrUnsupportedPlatform is returned when the runtime is not macOS or Linux.
var ErrUnsupportedPlatform = errors.New("service: only macOS (launchd) and Linux (systemd-user) are supported in v1.0")

// DetectPlatform returns the supervisor for the current process's GOOS.
// Returns ErrUnsupportedPlatform on Windows / other.
func DetectPlatform() (Platform, error) {
	switch runtime.GOOS {
	case "darwin":
		return PlatformDarwin, nil
	case "linux":
		return PlatformLinux, nil
	default:
		return 0, fmt.Errorf("%w (got %q)", ErrUnsupportedPlatform, runtime.GOOS)
	}
}

// Config bundles the substitution values for a service-file template.
type Config struct {
	// BinaryPath is the absolute path to the crate-agent binary.
	BinaryPath string
	// ConfigPath is the absolute path to crate-agent.toml.
	ConfigPath string
	// PassphraseEnv is the env-var name holding the folder passphrase.
	// Set to "" to omit — but the daemon won't start without it, so this
	// is normally required for an unattended supervisor.
	PassphraseEnv string
	// Label is the launchd / systemd unit identifier. Default: "com.naklitechie.crate-agent".
	Label string
	// LogPath optionally writes daemon stdout/stderr to a file. Empty =
	// supervisor's default (launchd: /dev/null; systemd: journal).
	LogPath string
}

// DefaultLabel is the canonical launchd/systemd identifier.
const DefaultLabel = "com.naklitechie.crate-agent"

// Validate checks Config invariants.
func (c *Config) Validate() error {
	if c.BinaryPath == "" {
		return errors.New("service: BinaryPath required")
	}
	if c.ConfigPath == "" {
		return errors.New("service: ConfigPath required")
	}
	if !filepath.IsAbs(c.BinaryPath) {
		return fmt.Errorf("service: BinaryPath must be absolute (got %q)", c.BinaryPath)
	}
	if !filepath.IsAbs(c.ConfigPath) {
		return fmt.Errorf("service: ConfigPath must be absolute (got %q)", c.ConfigPath)
	}
	if c.Label == "" {
		c.Label = DefaultLabel
	}
	return nil
}

// --- launchd (macOS) ---------------------------------------------------------

// LaunchdPath returns the path to the LaunchAgents plist for this user.
// ~/Library/LaunchAgents/{label}.plist
func LaunchdPath(label string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("service: resolve home: %w", err)
	}
	if label == "" {
		label = DefaultLabel
	}
	return filepath.Join(home, "Library", "LaunchAgents", label+".plist"), nil
}

// RenderLaunchdPlist returns the plist XML for c. KeepAlive=true so the
// supervisor restarts the daemon on crash; RunAtLoad=true so it starts on
// login.
func RenderLaunchdPlist(c Config) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">` + "\n")
	b.WriteString(`<plist version="1.0">` + "\n")
	b.WriteString(`<dict>` + "\n")
	plistKV(&b, "Label", c.Label)
	b.WriteString("  <key>ProgramArguments</key>\n  <array>\n")
	plistArrayString(&b, c.BinaryPath)
	plistArrayString(&b, "start")
	plistArrayString(&b, "--config")
	plistArrayString(&b, c.ConfigPath)
	b.WriteString("  </array>\n")
	plistKVBool(&b, "RunAtLoad", true)
	plistKVBool(&b, "KeepAlive", true)
	// ProcessType=Background lowers our timer-throttle priority — fine
	// since the syncer is event-driven and doesn't need real-time wake-ups.
	plistKV(&b, "ProcessType", "Background")
	if c.PassphraseEnv != "" {
		b.WriteString("  <key>EnvironmentVariables</key>\n  <dict>\n")
		b.WriteString("    <key>" + xmlEscape(c.PassphraseEnv) + "</key>\n")
		// The passphrase value MUST come from a user-managed secret store;
		// plists are world-readable, so we embed a placeholder. The user
		// edits the plist OR sets the env at launchctl-load time.
		plistArrayString(&b, "REPLACE-WITH-PASSPHRASE-OR-USE-LAUNCHCTL-SETENV")
		b.WriteString("  </dict>\n")
	}
	if c.LogPath != "" {
		plistKV(&b, "StandardOutPath", c.LogPath)
		plistKV(&b, "StandardErrorPath", c.LogPath)
	}
	b.WriteString(`</dict>` + "\n")
	b.WriteString(`</plist>` + "\n")
	return b.String(), nil
}

func plistKV(b *strings.Builder, k, v string) {
	b.WriteString("  <key>" + xmlEscape(k) + "</key>\n")
	b.WriteString("  <string>" + xmlEscape(v) + "</string>\n")
}

func plistKVBool(b *strings.Builder, k string, v bool) {
	b.WriteString("  <key>" + xmlEscape(k) + "</key>\n")
	if v {
		b.WriteString("  <true/>\n")
	} else {
		b.WriteString("  <false/>\n")
	}
}

func plistArrayString(b *strings.Builder, s string) {
	b.WriteString("    <string>" + xmlEscape(s) + "</string>\n")
}

func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}

// --- systemd (Linux) ---------------------------------------------------------

// SystemdPath returns the path to the user-level systemd unit for this user.
// $XDG_CONFIG_HOME/systemd/user/{label}.service or
// ~/.config/systemd/user/{label}.service.
func SystemdPath(label string) (string, error) {
	if label == "" {
		label = DefaultLabel
	}
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "systemd", "user", label+".service"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("service: resolve home: %w", err)
	}
	return filepath.Join(home, ".config", "systemd", "user", label+".service"), nil
}

// RenderSystemdUnit returns the systemd .service file body for c.
// Type=simple (foreground); Restart=always (matches launchd KeepAlive).
func RenderSystemdUnit(c Config) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString("Description=NakliTechie Crate sync agent\n")
	b.WriteString("Documentation=https://github.com/NakliTechie/crate-agent\n")
	b.WriteString("After=network-online.target\n")
	b.WriteString("Wants=network-online.target\n")
	b.WriteString("\n[Service]\n")
	b.WriteString("Type=simple\n")
	fmt.Fprintf(&b, "ExecStart=%s start --config %s\n",
		shellQuoteForSystemd(c.BinaryPath), shellQuoteForSystemd(c.ConfigPath))
	if c.PassphraseEnv != "" {
		// systemd EnvironmentFile is the recommended way to ship a secret —
		// the file is mode 0600, owned by the user, not in the unit itself.
		fmt.Fprintf(&b, "# Set %s via an EnvironmentFile, e.g.:\n", c.PassphraseEnv)
		fmt.Fprintf(&b, "# EnvironmentFile=%s\n",
			filepath.Join("~", ".config", "nakli", "crate-agent.env"))
	}
	b.WriteString("Restart=always\n")
	b.WriteString("RestartSec=5\n")
	if c.LogPath != "" {
		fmt.Fprintf(&b, "StandardOutput=append:%s\n", shellQuoteForSystemd(c.LogPath))
		fmt.Fprintf(&b, "StandardError=append:%s\n", shellQuoteForSystemd(c.LogPath))
	}
	b.WriteString("\n[Install]\n")
	b.WriteString("WantedBy=default.target\n")
	return b.String(), nil
}

// shellQuoteForSystemd quotes a path for systemd's ExecStart line.
// systemd uses simple shell-quoting; spaces require double-quotes. Existing
// double-quotes need escaping, but in practice paths under user $HOME never
// contain them — defensive belt-and-braces.
func shellQuoteForSystemd(s string) string {
	if !strings.ContainsAny(s, ` "\\`) {
		return s
	}
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

// --- file install/remove -----------------------------------------------------

// Install writes the rendered service file for the current platform at the
// canonical path (atomic temp+rename). Returns the path written and the
// human-readable next-step instructions (launchctl load … / systemctl
// --user daemon-reload && systemctl --user enable --now …) for the caller
// to surface.
func Install(c Config) (path, nextSteps string, err error) {
	plat, err := DetectPlatform()
	if err != nil {
		return "", "", err
	}
	if err := c.Validate(); err != nil {
		return "", "", err
	}
	switch plat {
	case PlatformDarwin:
		body, err := RenderLaunchdPlist(c)
		if err != nil {
			return "", "", err
		}
		path, err := LaunchdPath(c.Label)
		if err != nil {
			return "", "", err
		}
		if err := writeAtomic(path, []byte(body), 0o644); err != nil {
			return "", "", err
		}
		next := fmt.Sprintf(
			"Next:\n  launchctl bootstrap gui/$(id -u) %s\n  launchctl kickstart -k gui/$(id -u)/%s",
			path, c.Label)
		return path, next, nil
	case PlatformLinux:
		body, err := RenderSystemdUnit(c)
		if err != nil {
			return "", "", err
		}
		path, err := SystemdPath(c.Label)
		if err != nil {
			return "", "", err
		}
		if err := writeAtomic(path, []byte(body), 0o644); err != nil {
			return "", "", err
		}
		next := fmt.Sprintf(
			"Next:\n  systemctl --user daemon-reload\n  systemctl --user enable --now %s.service",
			c.Label)
		return path, next, nil
	}
	return "", "", ErrUnsupportedPlatform
}

// Uninstall removes the service file for the current platform if it exists.
// Returns (path, alreadyAbsent, error). The caller should also instruct the
// user to run `launchctl bootout … / systemctl --user disable …` BEFORE
// invoking this — we can't safely call those for them.
func Uninstall(label string) (path string, alreadyAbsent bool, err error) {
	plat, err := DetectPlatform()
	if err != nil {
		return "", false, err
	}
	switch plat {
	case PlatformDarwin:
		p, err := LaunchdPath(label)
		if err != nil {
			return "", false, err
		}
		path = p
	case PlatformLinux:
		p, err := SystemdPath(label)
		if err != nil {
			return "", false, err
		}
		path = p
	default:
		return "", false, ErrUnsupportedPlatform
	}
	if _, statErr := os.Stat(path); errors.Is(statErr, os.ErrNotExist) {
		return path, true, nil
	}
	if rerr := os.Remove(path); rerr != nil {
		return path, false, fmt.Errorf("remove %s: %w", path, rerr)
	}
	return path, false, nil
}

// writeAtomic writes data to path via temp+rename with the given perms.
// Parent dir is created with 0o700 if missing.
func writeAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s → %s: %w", tmp, path, err)
	}
	return nil
}
