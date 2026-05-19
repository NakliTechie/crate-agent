// SPDX-License-Identifier: AGPL-3.0-or-later
// Package watcher wraps fsnotify with .crateignore filtering + per-path
// debouncing. macOS routes through FSEvents (via fsnotify's `_kqueue`-on-Darwin
// path); Linux uses inotify; Windows (v1.1) uses ReadDirectoryChangesW. The
// public surface is platform-agnostic.
//
// Per crate-agent/plan/pending.md M3 decisions: 500ms debounce window;
// .crateignore uses .gitignore syntax (handled by internal/ignore).
//
// Event flow:
//
//   FS event → fsnotify.Event → relPath(root,event.Name) → ignore.Match? → drop
//                                                       └→ debounce buffer
//                                                              └→ 500ms idle
//                                                                  └→ emit
//
// The debouncer coalesces multiple events for the same path within the
// debounce window into one emission with the LATEST op. A file being
// written-many-times-quickly produces exactly one Event downstream.

package watcher

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"

	"github.com/NakliTechie/crate-agent/internal/ignore"
)

// DefaultDebounce is the per-path coalescing window. 500ms matches the M3
// decision (see crate-agent/plan/pending.md).
const DefaultDebounce = 500 * time.Millisecond

// Op describes what happened to a path.
type Op int

const (
	// OpCreate — file was created (or moved into the tree).
	OpCreate Op = iota + 1
	// OpWrite — file content was modified.
	OpWrite
	// OpRemove — file was removed (or moved out of the tree).
	OpRemove
	// OpRename — file was renamed within the tree.
	OpRename
)

func (o Op) String() string {
	switch o {
	case OpCreate:
		return "create"
	case OpWrite:
		return "write"
	case OpRemove:
		return "remove"
	case OpRename:
		return "rename"
	default:
		return "unknown"
	}
}

// Event is one coalesced filesystem change ready for the upload queue.
//
// RelPath is forward-slash-separated and relative to the watched root.
// IsDir is true if the path was a directory at the moment of the event.
type Event struct {
	RelPath string
	Op      Op
	IsDir   bool
}

// Watcher streams coalesced events from a directory tree.
//
//   w, _ := New(Options{Root: "/home/me/crate"})
//   defer w.Close()
//   go w.Run(ctx)
//   for ev := range w.Events() { ... }
//
// Errors() exposes a buffered error channel for non-fatal warnings (e.g.
// EACCES on a subdir); fatal errors close Events() and surface on Err().
type Watcher struct {
	root     string
	debounce time.Duration
	matcher  *ignore.Matcher

	fsw  *fsnotify.Watcher
	out  chan Event
	errs chan error

	mu      sync.Mutex
	pending map[string]*pendingEvent
	timer   *time.Timer
	closed  bool
	runErr  error
}

type pendingEvent struct {
	op       Op
	isDir    bool
	deadline time.Time
}

// Options configures a new Watcher.
type Options struct {
	// Root is the directory to watch (absolute path).
	Root string

	// Debounce overrides DefaultDebounce — testing only.
	Debounce time.Duration

	// IgnoreFile is the path to a .crateignore file. Empty = no user-defined
	// patterns (builtin always-ignore still applies). Missing file is OK.
	IgnoreFile string

	// Matcher overrides the default ignore.New() — testing only. If set,
	// IgnoreFile is ignored.
	Matcher *ignore.Matcher
}

// New creates a Watcher but does NOT start it. Call Run() to begin streaming
// events; Close() to stop. The watcher walks Root once at start to register
// every subdirectory with fsnotify (fsnotify watches dirs, not trees).
func New(opts Options) (*Watcher, error) {
	if opts.Root == "" {
		return nil, errors.New("watcher: Root is required")
	}
	abs, err := filepath.Abs(opts.Root)
	if err != nil {
		return nil, fmt.Errorf("watcher: abs Root: %w", err)
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("watcher: stat Root: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("watcher: Root %q is not a directory", abs)
	}

	debounce := opts.Debounce
	if debounce <= 0 {
		debounce = DefaultDebounce
	}

	matcher := opts.Matcher
	if matcher == nil {
		matcher = ignore.New()
		if opts.IgnoreFile != "" {
			if err := matcher.LoadFile(opts.IgnoreFile); err != nil {
				return nil, fmt.Errorf("watcher: load %s: %w", opts.IgnoreFile, err)
			}
		}
	}

	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("watcher: fsnotify.NewWatcher: %w", err)
	}

	w := &Watcher{
		root:     abs,
		debounce: debounce,
		matcher:  matcher,
		fsw:      fsw,
		out:      make(chan Event, 256),
		errs:     make(chan error, 32),
		pending:  map[string]*pendingEvent{},
	}
	return w, nil
}

// Events returns the channel of coalesced events. The channel is closed when
// the watcher exits (either via Close() or fatal error).
func (w *Watcher) Events() <-chan Event { return w.out }

// Errors returns non-fatal warning errors (e.g. dir-add EACCES). Drains at
// the receiver's rate; full buffer = warning is dropped on the floor.
func (w *Watcher) Errors() <-chan error { return w.errs }

// Err returns the fatal error that caused Run() to exit, if any. Safe to
// call after Events() closes.
func (w *Watcher) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.runErr
}

// Run walks the tree, registers every directory with fsnotify, then processes
// events until ctx is cancelled or fsnotify errors fatally. Blocks the caller.
// Run is idempotent on multiple ctx-cancels but not on multiple calls.
func (w *Watcher) Run(ctx context.Context) error {
	defer w.close()

	// Walk + register every directory.
	if err := w.walkAndWatch(); err != nil {
		w.setRunErr(err)
		return err
	}

	tickInterval := 50 * time.Millisecond
	tick := time.NewTicker(tickInterval)
	defer tick.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-w.fsw.Events:
			if !ok {
				return nil
			}
			w.handleFSEvent(ev)
		case err, ok := <-w.fsw.Errors:
			if !ok {
				return nil
			}
			// fsnotify error channel surfaces fatal-ish issues; we treat them
			// as warnings unless they reflect a closed underlying watcher.
			select {
			case w.errs <- err:
			default:
			}
		case <-tick.C:
			// Drain pending events whose debounce window has elapsed.
			w.flushExpired()
		}
	}
}

// Close stops the watcher and releases resources. Safe to call multiple
// times; safe to call from any goroutine.
func (w *Watcher) Close() error {
	w.close()
	return nil
}

func (w *Watcher) close() {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return
	}
	w.closed = true
	if w.timer != nil {
		w.timer.Stop()
		w.timer = nil
	}
	w.mu.Unlock()
	_ = w.fsw.Close()
	close(w.out)
	close(w.errs)
}

func (w *Watcher) setRunErr(err error) {
	w.mu.Lock()
	w.runErr = err
	w.mu.Unlock()
}

// walkAndWatch registers every directory under w.root with fsnotify, skipping
// dirs that match the ignore matcher.
func (w *Watcher) walkAndWatch() error {
	return filepath.WalkDir(w.root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			// Surface as a warning; keep walking the rest of the tree.
			select {
			case w.errs <- fmt.Errorf("walk %s: %w", path, err):
			default:
			}
			return nil
		}
		if !d.IsDir() {
			return nil
		}
		rel := w.relPath(path)
		if rel != "" && w.matcher.Match(rel, true) {
			return filepath.SkipDir
		}
		if err := w.fsw.Add(path); err != nil {
			select {
			case w.errs <- fmt.Errorf("fsnotify.Add %s: %w", path, err):
			default:
			}
		}
		return nil
	})
}

// handleFSEvent classifies the fsnotify event and enqueues it in the
// debounce buffer (or drops it if .crateignore says so).
func (w *Watcher) handleFSEvent(ev fsnotify.Event) {
	rel := w.relPath(ev.Name)
	if rel == "" {
		return
	}
	isDir := false
	if info, err := os.Stat(ev.Name); err == nil {
		isDir = info.IsDir()
	}
	if w.matcher.Match(rel, isDir) {
		return
	}

	// If a directory was just created and is not ignored, walk and add it.
	if isDir && ev.Has(fsnotify.Create) {
		_ = w.fsw.Add(ev.Name)
	}

	op := translateOp(ev.Op)
	if op == 0 {
		return
	}

	w.mu.Lock()
	w.pending[rel] = &pendingEvent{
		op:       op,
		isDir:    isDir,
		deadline: time.Now().Add(w.debounce),
	}
	w.mu.Unlock()
}

// flushExpired drains pending events whose debounce window has elapsed and
// pushes them to w.out.
func (w *Watcher) flushExpired() {
	now := time.Now()
	type ready struct {
		rel string
		ev  pendingEvent
	}
	var ready_events []ready
	w.mu.Lock()
	for rel, p := range w.pending {
		if !now.Before(p.deadline) {
			ready_events = append(ready_events, ready{rel: rel, ev: *p})
			delete(w.pending, rel)
		}
	}
	w.mu.Unlock()

	for _, r := range ready_events {
		select {
		case w.out <- Event{
			RelPath: r.rel,
			Op:      r.ev.op,
			IsDir:   r.ev.isDir,
		}:
		default:
			// out is full; surface as a non-fatal warning and DROP the event.
			// In production this should never happen — buffer is 256 and the
			// syncer drains continuously. If it does, drops are recoverable
			// (next change to the same path will surface it).
			select {
			case w.errs <- fmt.Errorf("watcher: output buffer full; dropped %s", r.rel):
			default:
			}
		}
	}
}

// relPath returns the forward-slash path of absPath relative to w.root, or
// "" if absPath is outside w.root.
func (w *Watcher) relPath(absPath string) string {
	rel, err := filepath.Rel(w.root, absPath)
	if err != nil || rel == "." || rel == "" {
		return ""
	}
	if filepath.IsAbs(rel) {
		return ""
	}
	return filepath.ToSlash(rel)
}

// translateOp maps fsnotify's bitset op to our enum. Multi-bit ops (e.g.
// Create|Write) collapse to the higher-signal one — Write wins over Create
// because by the time we observe Create the file's content has often arrived.
func translateOp(op fsnotify.Op) Op {
	switch {
	case op.Has(fsnotify.Remove):
		return OpRemove
	case op.Has(fsnotify.Rename):
		return OpRename
	case op.Has(fsnotify.Write):
		return OpWrite
	case op.Has(fsnotify.Create):
		return OpCreate
	default:
		return 0
	}
}
