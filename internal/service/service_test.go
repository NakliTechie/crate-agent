// SPDX-License-Identifier: AGPL-3.0-or-later
package service

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRenderLaunchdPlist(t *testing.T) {
	c := Config{
		BinaryPath:    "/usr/local/bin/crate-agent",
		ConfigPath:    "/Users/me/.config/nakli/crate-agent.toml",
		PassphraseEnv: "CRATE_AGENT_PASSPHRASE",
		Label:         "com.test.crate-agent",
		LogPath:       "/Users/me/Library/Logs/crate-agent.log",
	}
	body, err := RenderLaunchdPlist(c)
	if err != nil {
		t.Fatal(err)
	}
	// Sanity-check the structural pieces.
	checks := []string{
		`<plist version="1.0">`,
		`<key>Label</key>`,
		`<string>com.test.crate-agent</string>`,
		`<key>ProgramArguments</key>`,
		`<string>/usr/local/bin/crate-agent</string>`,
		`<string>start</string>`,
		`<string>--config</string>`,
		`<key>RunAtLoad</key>`,
		`<true/>`,
		`<key>KeepAlive</key>`,
		`<key>EnvironmentVariables</key>`,
		`<key>CRATE_AGENT_PASSPHRASE</key>`,
		`<key>StandardOutPath</key>`,
		`<string>/Users/me/Library/Logs/crate-agent.log</string>`,
	}
	for _, want := range checks {
		if !strings.Contains(body, want) {
			t.Errorf("plist missing %q. Body:\n%s", want, body)
		}
	}
}

func TestRenderLaunchdPlist_DefaultLabel(t *testing.T) {
	c := Config{
		BinaryPath: "/abs/bin",
		ConfigPath: "/abs/cfg.toml",
	}
	body, err := RenderLaunchdPlist(c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, "<string>com.naklitechie.crate-agent</string>") {
		t.Errorf("default label not applied; body:\n%s", body)
	}
}

func TestRenderLaunchdPlist_RejectsRelativePaths(t *testing.T) {
	c := Config{BinaryPath: "relative/bin", ConfigPath: "/abs/cfg.toml"}
	if _, err := RenderLaunchdPlist(c); err == nil {
		t.Errorf("relative BinaryPath should error")
	}
	c = Config{BinaryPath: "/abs/bin", ConfigPath: "relative/cfg"}
	if _, err := RenderLaunchdPlist(c); err == nil {
		t.Errorf("relative ConfigPath should error")
	}
}

func TestRenderLaunchdPlist_RequiresPaths(t *testing.T) {
	if _, err := RenderLaunchdPlist(Config{}); err == nil {
		t.Errorf("empty config should error")
	}
}

func TestRenderLaunchdPlist_EscapesXML(t *testing.T) {
	c := Config{
		BinaryPath: "/path/with<chars>&\"quotes",
		ConfigPath: "/abs/cfg.toml",
	}
	body, err := RenderLaunchdPlist(c)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(body, "<chars>") {
		t.Errorf("XML not escaped: %s", body)
	}
	if !strings.Contains(body, "&lt;chars&gt;") {
		t.Errorf("expected &lt;chars&gt; in escaped output")
	}
	if !strings.Contains(body, "&quot;quotes") {
		t.Errorf("expected escaped quotes")
	}
}

func TestRenderSystemdUnit(t *testing.T) {
	c := Config{
		BinaryPath:    "/usr/local/bin/crate-agent",
		ConfigPath:    "/home/me/.config/nakli/crate-agent.toml",
		PassphraseEnv: "CRATE_AGENT_PASSPHRASE",
		Label:         "com.test.crate-agent",
	}
	body, err := RenderSystemdUnit(c)
	if err != nil {
		t.Fatal(err)
	}
	checks := []string{
		"[Unit]",
		"Description=NakliTechie Crate sync agent",
		"After=network-online.target",
		"[Service]",
		"Type=simple",
		"ExecStart=/usr/local/bin/crate-agent start --config /home/me/.config/nakli/crate-agent.toml",
		"Restart=always",
		"# Set CRATE_AGENT_PASSPHRASE via an EnvironmentFile",
		"[Install]",
		"WantedBy=default.target",
	}
	for _, want := range checks {
		if !strings.Contains(body, want) {
			t.Errorf("unit missing %q. Body:\n%s", want, body)
		}
	}
}

func TestRenderSystemdUnit_QuotesPathsWithSpaces(t *testing.T) {
	c := Config{
		BinaryPath: "/path with space/crate-agent",
		ConfigPath: "/cfg/x.toml",
	}
	body, err := RenderSystemdUnit(c)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(body, `ExecStart="/path with space/crate-agent" start --config /cfg/x.toml`) {
		t.Errorf("space-quoting wrong:\n%s", body)
	}
}

func TestLaunchdPath(t *testing.T) {
	p, err := LaunchdPath("com.x.y")
	if err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	want := filepath.Join(home, "Library", "LaunchAgents", "com.x.y.plist")
	if p != want {
		t.Errorf("LaunchdPath = %q, want %q", p, want)
	}
}

func TestLaunchdPath_DefaultLabel(t *testing.T) {
	p, err := LaunchdPath("")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p, DefaultLabel+".plist") {
		t.Errorf("default label not applied: %s", p)
	}
}

func TestSystemdPath_XDGOverride(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/x/config")
	p, err := SystemdPath("com.x.y")
	if err != nil {
		t.Fatal(err)
	}
	if p != "/x/config/systemd/user/com.x.y.service" {
		t.Errorf("XDG path wrong: %s", p)
	}
}

func TestSystemdPath_Fallback(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "")
	p, err := SystemdPath("com.x.y")
	if err != nil {
		t.Fatal(err)
	}
	home, _ := os.UserHomeDir()
	want := filepath.Join(home, ".config", "systemd", "user", "com.x.y.service")
	if p != want {
		t.Errorf("fallback wrong: got %q want %q", p, want)
	}
}

func TestDetectPlatform(t *testing.T) {
	p, err := DetectPlatform()
	switch runtime.GOOS {
	case "darwin":
		if err != nil || p != PlatformDarwin {
			t.Errorf("darwin detect: %v %v", p, err)
		}
	case "linux":
		if err != nil || p != PlatformLinux {
			t.Errorf("linux detect: %v %v", p, err)
		}
	default:
		if err == nil {
			t.Errorf("expected ErrUnsupportedPlatform on %s", runtime.GOOS)
		}
	}
}

func TestPlatformString(t *testing.T) {
	for p, want := range map[Platform]string{
		PlatformDarwin: "launchd",
		PlatformLinux:  "systemd-user",
		Platform(99):   "unknown",
	} {
		if got := p.String(); got != want {
			t.Errorf("Platform(%d).String() = %q, want %q", p, got, want)
		}
	}
}

// Install + Uninstall round-trip — only runs on a platform we support.
func TestInstallUninstall(t *testing.T) {
	if _, err := DetectPlatform(); err != nil {
		t.Skip(err)
	}
	tmp := t.TempDir()
	// Redirect the install path into the temp dir by overriding HOME +
	// XDG_CONFIG_HOME — both platforms key off these.
	t.Setenv("HOME", tmp)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(tmp, ".config"))

	c := Config{
		BinaryPath:    filepath.Join(tmp, "crate-agent"),
		ConfigPath:    filepath.Join(tmp, ".config", "nakli", "crate-agent.toml"),
		PassphraseEnv: "CRATE_AGENT_PASSPHRASE",
		Label:         "com.test.crate-agent-install",
	}
	path, next, err := Install(c)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("installed file missing: %v", err)
	}
	if next == "" {
		t.Errorf("next-steps message is empty")
	}

	// Second install overwrites (atomic rename) — should succeed.
	if _, _, err := Install(c); err != nil {
		t.Errorf("re-install failed: %v", err)
	}

	// Uninstall.
	removed, absent, err := Uninstall(c.Label)
	if err != nil {
		t.Fatalf("Uninstall: %v", err)
	}
	if absent {
		t.Errorf("Uninstall reported absent when file existed")
	}
	if removed != path {
		t.Errorf("Uninstall path mismatch")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("Uninstall left the file behind: %v", err)
	}

	// Second Uninstall reports absent.
	_, absent, err = Uninstall(c.Label)
	if err != nil {
		t.Errorf("second Uninstall errored: %v", err)
	}
	if !absent {
		t.Errorf("expected absent=true on second Uninstall")
	}
}
