// SPDX-License-Identifier: AGPL-3.0-or-later
package ignore

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBuiltins(t *testing.T) {
	m := New()
	cases := []struct {
		path  string
		isDir bool
		want  bool
		label string
	}{
		{".DS_Store", false, true, "macOS metadata"},
		{"folder/.DS_Store", false, true, ".DS_Store in subdir"},
		{"Thumbs.db", false, true, "Windows thumbnails"},
		{"foo.swp", false, true, "vim swap"},
		{".git/HEAD", false, true, ".git contents"},
		{".git", true, true, ".git dir itself"},
		{"node_modules/foo/index.js", false, true, "node_modules deep"},
		{"~$foo.docx", false, true, "Office lock file"},
		{"docs/README.md", false, false, "regular file"},
		{"src/main.go", false, false, "regular file 2"},
	}
	for _, c := range cases {
		got := m.Match(c.path, c.isDir)
		if got != c.want {
			t.Errorf("Match(%q, isDir=%v) = %v, want %v (%s)",
				c.path, c.isDir, got, c.want, c.label)
		}
	}
}

func TestAnchoredPatterns(t *testing.T) {
	m := New()
	if err := m.AddPattern("/build"); err != nil {
		t.Fatal(err)
	}
	if !m.Match("build/output.bin", false) {
		t.Errorf("anchored /build should match root-level build/")
	}
	if m.Match("docs/build/output.bin", false) {
		t.Errorf("anchored /build should NOT match docs/build/")
	}
}

func TestNegations(t *testing.T) {
	m := New()
	_ = m.AddPattern("*.log")
	_ = m.AddPattern("!important.log")
	if !m.Match("debug.log", false) {
		t.Errorf("*.log should match debug.log")
	}
	if m.Match("important.log", false) {
		t.Errorf("!important.log should override *.log")
	}
}

func TestGlobStar(t *testing.T) {
	m := New()
	_ = m.AddPattern("docs/**/draft-*.md")
	if !m.Match("docs/2026/05/draft-x.md", false) {
		t.Errorf("** should cross slashes")
	}
	if m.Match("docs/published.md", false) {
		t.Errorf("docs/published.md should not match draft-* pattern")
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".crateignore")
	content := "# user-specified\n*.tmp\nbuild/\n# comment\n\n!keep.tmp\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	m := New()
	if err := m.LoadFile(path); err != nil {
		t.Fatal(err)
	}
	if !m.Match("scratch.tmp", false) {
		t.Errorf("*.tmp should match scratch.tmp")
	}
	if m.Match("keep.tmp", false) {
		t.Errorf("!keep.tmp negation should override *.tmp")
	}
	if !m.Match("build/output.bin", false) {
		t.Errorf("build/ should match build/output.bin")
	}
}

func TestLoadFileMissingIsOK(t *testing.T) {
	m := New()
	if err := m.LoadFile("/does/not/exist/.crateignore"); err != nil {
		t.Errorf("LoadFile missing should return nil, got %v", err)
	}
}

func TestAddPatternRejectsEmpty(t *testing.T) {
	m := New()
	if err := m.AddPattern(""); err == nil {
		t.Errorf("AddPattern(\"\") should error")
	}
	if err := m.AddPattern("!"); err == nil {
		t.Errorf("AddPattern(\"!\") should error")
	}
}

func TestEmptyPathDoesNotMatch(t *testing.T) {
	m := New()
	if m.Match("", false) {
		t.Errorf("empty relPath should never match")
	}
	if m.Match(".", false) {
		t.Errorf("\".\" should never match")
	}
}
