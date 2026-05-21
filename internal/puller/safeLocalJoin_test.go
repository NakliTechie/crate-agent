// SPDX-License-Identifier: AGPL-3.0-or-later
package puller

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestSafeLocalJoin guards the path-containment check in safeLocalJoin
// against the attack class flagged by the 2026-05 security audit: a
// malicious transport feeding a manifest with a crafted `path` that
// escapes the crate root when joined to LocalPath. Each case here is a
// real attack vector that MUST be rejected.
func TestSafeLocalJoin(t *testing.T) {
	root := t.TempDir()
	absRoot, _ := filepath.Abs(root)

	cases := []struct {
		name      string
		input     string
		wantOK    bool
		wantUnder bool // expected to live under root if wantOK
	}{
		// HAPPY PATH — these are legitimate manifest paths
		{name: "simple file", input: "/notes.md", wantOK: true, wantUnder: true},
		{name: "nested file", input: "/notes/today.md", wantOK: true, wantUnder: true},
		{name: "deeply nested", input: "/a/b/c/d/e.md", wantOK: true, wantUnder: true},
		{name: "no leading slash", input: "notes.md", wantOK: true, wantUnder: true},

		// ATTACK VECTORS — all must be rejected
		{name: "parent traversal", input: "/../etc/passwd", wantOK: false},
		{name: "double parent", input: "/../../etc/passwd", wantOK: false},
		{name: "deep parent traversal", input: "/notes/../../../etc/passwd", wantOK: false},
		{name: "ssh authorized_keys exploit", input: "/../../.ssh/authorized_keys", wantOK: false},
		{name: "absolute path inside path", input: "//etc/passwd", wantOK: false},
		{name: "single dot segment", input: "/./notes.md", wantOK: false},
		{name: "trailing dot-dot", input: "/notes/..", wantOK: false},
		{name: "backslash smuggling (windows-style)", input: "..\\..\\etc\\passwd", wantOK: false},
		{name: "empty path", input: "", wantOK: false},
		{name: "just slash", input: "/", wantOK: false},
		{name: "embedded double-slash", input: "/notes//../etc", wantOK: false},
		// Tilde is just a directory name to our resolver — no shell expansion. Permitted.
		{name: "tilde directory name", input: "/~/notes.md", wantOK: true, wantUnder: true},
		// But tilde combined with .. is still rejected by the .. check.
		{name: "tilde with traversal", input: "/~/../etc/passwd", wantOK: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := safeLocalJoin(root, tc.input)
			if tc.wantOK {
				if err != nil {
					t.Fatalf("expected accept, got error: %v", err)
				}
				absGot, _ := filepath.Abs(got)
				if tc.wantUnder && !strings.HasPrefix(absGot, absRoot+string(filepath.Separator)) && absGot != absRoot {
					t.Errorf("path %q resolved to %q, escapes root %q", tc.input, absGot, absRoot)
				}
			} else {
				if err == nil {
					t.Fatalf("expected reject for %q, got accept: %q", tc.input, got)
				}
			}
		})
	}
}
