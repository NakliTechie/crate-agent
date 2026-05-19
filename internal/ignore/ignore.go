// SPDX-License-Identifier: AGPL-3.0-or-later
// Package ignore filters filesystem events using built-in patterns
// (.DS_Store, Thumbs.db, ~$*, *.swp, .git/, node_modules/) plus the user's
// .crateignore (gitignore-style: line-per-pattern, `#` comments, `!`
// negations, `**` globs).
//
// Used by the watcher to drop events before they reach the upload queue.
// The matcher is path-relative to the crate's local_path root.
//
// Reference: https://git-scm.com/docs/gitignore
package ignore

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Matcher tests paths against a compiled rule set.
//
// Empty Matcher (zero value) matches the built-in always-ignore set only.
// LoadFile + AddPattern extend it with user rules. Concurrent reads are safe
// (Match is goroutine-safe); concurrent writes are NOT — call all
// AddPattern / LoadFile before sharing.
type Matcher struct {
	rules []rule
}

// rule is one compiled .gitignore-style pattern.
type rule struct {
	original string
	pattern  string
	negate   bool
	dirOnly  bool
	anchored bool
	hasSlash bool
}

// builtinPatterns are always-ignored, regardless of .crateignore content.
// Per crate-daemon-handoff-v1.0.md §"Watcher behavior" + the M3 decision in
// crate-agent/plan/pending.md.
var builtinPatterns = []string{
	".DS_Store",
	"Thumbs.db",
	"*.swp",
	".git/",
	"node_modules/",
	// Editor scratch files. These can flood the watcher when the user is
	// editing in vim/emacs/VS Code.
	"*.swo",
	"*.swn",
	".#*",
	"#*#",
	"~$*",
}

// New returns a Matcher pre-loaded with the built-in always-ignore patterns.
// Call AddPattern / LoadFile to extend.
func New() *Matcher {
	m := &Matcher{}
	for _, p := range builtinPatterns {
		_ = m.AddPattern(p)
	}
	return m
}

// LoadFile reads a .crateignore from disk and appends its rules. Missing file
// returns nil (no rules added). Each non-comment non-empty line is one pattern.
func (m *Matcher) LoadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("ignore: open %s: %w", path, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := m.AddPattern(line); err != nil {
			return fmt.Errorf("ignore: %s: %w", path, err)
		}
	}
	return scanner.Err()
}

// AddPattern adds one gitignore-style pattern.
func (m *Matcher) AddPattern(p string) error {
	p = strings.TrimSpace(p)
	if p == "" {
		return errors.New("ignore: empty pattern")
	}
	r := rule{original: p}
	if strings.HasPrefix(p, "!") {
		r.negate = true
		p = p[1:]
		if p == "" {
			return errors.New("ignore: \"!\" without pattern")
		}
	}
	if strings.HasSuffix(p, "/") {
		r.dirOnly = true
		p = strings.TrimSuffix(p, "/")
	}
	if strings.HasPrefix(p, "/") {
		r.anchored = true
		p = strings.TrimPrefix(p, "/")
	}
	r.hasSlash = strings.Contains(p, "/")
	r.pattern = p
	m.rules = append(m.rules, r)
	return nil
}

// Match returns true if relPath should be ignored. relPath MUST be
// forward-slash-separated and relative to the crate root (e.g. "docs/foo.md",
// not "/Users/x/crate/docs/foo.md").
//
// isDir hints that the path is a directory — affects dirOnly rules.
//
// The matcher walks rules in order; the LAST matching rule wins, allowing
// negations to override earlier matches (gitignore semantics).
func (m *Matcher) Match(relPath string, isDir bool) bool {
	if relPath == "" || relPath == "." {
		return false
	}
	relPath = filepath.ToSlash(relPath)
	relPath = strings.TrimPrefix(relPath, "./")

	matched := false
	for _, r := range m.rules {
		if !r.dirOnly {
			// Non-dirOnly rule: test relPath + any prefix at slash boundaries
			// (gitignore's "if a dir matches, everything under it is matched").
			if r.matches(relPath, isDir) || r.matchesAnyPrefix(relPath) {
				matched = !r.negate
			}
			continue
		}
		// dirOnly rule matches if the path is itself a dir (rare for file
		// events) OR if any path component equals the pattern.
		if isDir && r.matches(relPath, true) {
			matched = !r.negate
			continue
		}
		if pathHasComponent(relPath, r.pattern) {
			matched = !r.negate
		}
	}
	return matched
}

// matchesAnyPrefix tests whether the rule matches any path prefix at slash
// boundaries — gitignore's "matched dir → everything under it is matched"
// behaviour. e.g. rule "/build" should match "build/output.bin" because
// "build" itself would match. Skips the full path (already tested).
func (r rule) matchesAnyPrefix(relPath string) bool {
	for i := strings.IndexByte(relPath, '/'); i >= 0; i = nextSlash(relPath, i+1) {
		if r.matches(relPath[:i], true) {
			return true
		}
	}
	return false
}

func nextSlash(s string, from int) int {
	if from >= len(s) {
		return -1
	}
	i := strings.IndexByte(s[from:], '/')
	if i < 0 {
		return -1
	}
	return from + i
}

// matches tests one rule against relPath.
func (r rule) matches(relPath string, _ bool) bool {
	if r.anchored {
		return globMatch(r.pattern, relPath, r.hasSlash)
	}
	if !r.hasSlash {
		base := relPath
		if i := strings.LastIndex(relPath, "/"); i >= 0 {
			base = relPath[i+1:]
		}
		return globMatch(r.pattern, base, false)
	}
	return globMatch(r.pattern, relPath, true)
}

// pathHasComponent returns true if any segment of relPath matches the
// (dir-pattern) `pattern`. Used for dirOnly rules: "node_modules/" should
// ignore "node_modules/foo/bar.js" too.
func pathHasComponent(relPath, pattern string) bool {
	for _, s := range strings.Split(relPath, "/") {
		if globMatch(pattern, s, false) {
			return true
		}
	}
	return false
}

// globMatch does shell-glob matching with `*`, `?`, `**`. `*` matches any
// run of non-slash characters when allowSlash=false; `**` matches across
// slash boundaries. `?` matches one non-slash character.
func globMatch(pattern, name string, allowSlash bool) bool {
	if !strings.ContainsAny(pattern, "*?[") {
		return pattern == name
	}
	return globMatchInner(pattern, name, allowSlash)
}

func globMatchInner(pat, name string, allowSlash bool) bool {
	for len(pat) > 0 {
		switch {
		case strings.HasPrefix(pat, "**"):
			rest := strings.TrimPrefix(pat, "**")
			rest = strings.TrimPrefix(rest, "/")
			for i := 0; i <= len(name); i++ {
				if globMatchInner(rest, name[i:], allowSlash) {
					return true
				}
			}
			return false
		case strings.HasPrefix(pat, "*"):
			rest := pat[1:]
			for i := 0; i <= len(name); i++ {
				if i < len(name) && !allowSlash && name[i] == '/' {
					break
				}
				if globMatchInner(rest, name[i:], allowSlash) {
					return true
				}
			}
			return false
		case strings.HasPrefix(pat, "?"):
			if len(name) == 0 {
				return false
			}
			if !allowSlash && name[0] == '/' {
				return false
			}
			pat = pat[1:]
			name = name[1:]
		default:
			if len(name) == 0 || pat[0] != name[0] {
				return false
			}
			pat = pat[1:]
			name = name[1:]
		}
	}
	return len(name) == 0
}
