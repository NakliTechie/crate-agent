// SPDX-License-Identifier: AGPL-3.0-or-later
package watcher

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NakliTechie/crate-agent/internal/ignore"
)

// drainFor returns all events received within d, or until the channel closes.
func drainFor(t *testing.T, ch <-chan Event, d time.Duration) []Event {
	t.Helper()
	deadline := time.NewTimer(d)
	defer deadline.Stop()
	var out []Event
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return out
			}
			out = append(out, ev)
		case <-deadline.C:
			return out
		}
	}
}

func TestWatcher_CreateAndWriteCoalesce(t *testing.T) {
	dir := t.TempDir()
	w, err := New(Options{Root: dir, Debounce: 100 * time.Millisecond})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runDone := make(chan error, 1)
	go func() { runDone <- w.Run(ctx) }()
	defer w.Close()
	// Give Run a beat to register.
	time.Sleep(50 * time.Millisecond)

	path := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Multiple rapid writes — should coalesce into a single emitted event.
	for i := 0; i < 5; i++ {
		if err := os.WriteFile(path, []byte("v"+string(rune('0'+i))), 0o644); err != nil {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	events := drainFor(t, w.Events(), 500*time.Millisecond)
	if len(events) == 0 {
		t.Fatalf("no events received")
	}
	if events[0].RelPath != "a.txt" {
		t.Errorf("first event rel = %q, want a.txt", events[0].RelPath)
	}
	// Expect at most 2 events (one for create+writes, maybe a final write).
	if len(events) > 2 {
		t.Errorf("expected ≤2 coalesced events; got %d: %+v", len(events), events)
	}
}

func TestWatcher_IgnoresBuiltinPatterns(t *testing.T) {
	dir := t.TempDir()
	w, err := New(Options{Root: dir, Debounce: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	defer w.Close()
	time.Sleep(50 * time.Millisecond)

	// .DS_Store and *.swp should be silently dropped.
	if err := os.WriteFile(filepath.Join(dir, ".DS_Store"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "doc.swp"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	// A non-ignored file should still come through.
	if err := os.WriteFile(filepath.Join(dir, "real.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	events := drainFor(t, w.Events(), 250*time.Millisecond)
	for _, ev := range events {
		if ev.RelPath == ".DS_Store" || ev.RelPath == "doc.swp" {
			t.Errorf("ignored file leaked through: %+v", ev)
		}
	}
	saw := false
	for _, ev := range events {
		if ev.RelPath == "real.txt" {
			saw = true
		}
	}
	if !saw {
		t.Errorf("expected real.txt event; got %+v", events)
	}
}

func TestWatcher_CustomMatcher(t *testing.T) {
	dir := t.TempDir()
	m := ignore.New()
	_ = m.AddPattern("*.log")
	w, err := New(Options{
		Root:     dir,
		Debounce: 50 * time.Millisecond,
		Matcher:  m,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	defer w.Close()
	time.Sleep(50 * time.Millisecond)

	_ = os.WriteFile(filepath.Join(dir, "debug.log"), []byte("x"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "data.json"), []byte("x"), 0o644)

	events := drainFor(t, w.Events(), 250*time.Millisecond)
	for _, ev := range events {
		if ev.RelPath == "debug.log" {
			t.Errorf("*.log should be ignored: %+v", ev)
		}
	}
}

func TestWatcher_RemoveEvent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "doomed.txt")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	w, err := New(Options{Root: dir, Debounce: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	defer w.Close()
	time.Sleep(50 * time.Millisecond)

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}

	events := drainFor(t, w.Events(), 250*time.Millisecond)
	if len(events) == 0 {
		t.Fatalf("expected at least one event for remove; got none")
	}
	gotRemove := false
	for _, ev := range events {
		if ev.RelPath == "doomed.txt" && ev.Op == OpRemove {
			gotRemove = true
		}
	}
	if !gotRemove {
		t.Errorf("expected OpRemove on doomed.txt; got %+v", events)
	}
}

func TestWatcher_NewRejectsBadRoot(t *testing.T) {
	if _, err := New(Options{Root: ""}); err == nil {
		t.Errorf("empty Root should error")
	}
	if _, err := New(Options{Root: "/does/not/exist/probably"}); err == nil {
		t.Errorf("missing Root should error")
	}
	// Root that exists but is not a directory.
	tmp := t.TempDir()
	path := filepath.Join(tmp, "regular-file.txt")
	_ = os.WriteFile(path, []byte("x"), 0o644)
	if _, err := New(Options{Root: path}); err == nil {
		t.Errorf("file Root should error")
	}
}

func TestWatcher_CloseIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	w, err := New(Options{Root: dir})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestOpString(t *testing.T) {
	for op, want := range map[Op]string{
		OpCreate: "create",
		OpWrite:  "write",
		OpRemove: "remove",
		OpRename: "rename",
		Op(99):   "unknown",
	} {
		if got := op.String(); got != want {
			t.Errorf("Op(%d).String() = %q, want %q", op, got, want)
		}
	}
}
