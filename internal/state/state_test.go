// SPDX-License-Identifier: AGPL-3.0-or-later
package state

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestOpenCreatesAndMigrates(t *testing.T) {
	s := newStore(t)
	var v int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		t.Fatalf("read user_version: %v", err)
	}
	if v != len(Migrations) {
		t.Errorf("user_version = %d, want %d", v, len(Migrations))
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	s1, err := Open(path)
	if err != nil {
		t.Fatalf("Open #1: %v", err)
	}
	_ = s1.Close()
	s2, err := Open(path)
	if err != nil {
		t.Fatalf("Open #2: %v", err)
	}
	defer s2.Close()
	var v int
	if err := s2.db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		t.Fatal(err)
	}
	if v != len(Migrations) {
		t.Errorf("re-open user_version = %d, want %d", v, len(Migrations))
	}
}

func TestManifestCacheRoundTrip(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	want := ManifestEntry{
		RemotePath:   "docs/README.md",
		ETag:         "etag-abc",
		SHA256:       "deadbeef",
		SizeBytes:    1234,
		LastModified: time.Now().Add(-time.Hour).UTC().Truncate(time.Nanosecond),
		LocalMtimeNS: 1700000000000000000,
	}
	if err := s.UpsertManifestEntry(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, err := s.LookupManifestEntry(ctx, "docs/README.md")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("LookupManifestEntry returned nil; want a row")
	}
	if got.ETag != "etag-abc" || got.SHA256 != "deadbeef" || got.SizeBytes != 1234 {
		t.Errorf("round-trip mismatch: %+v", got)
	}

	// Re-upsert with different etag — should update, not error.
	want.ETag = "etag-xyz"
	if err := s.UpsertManifestEntry(ctx, want); err != nil {
		t.Fatal(err)
	}
	got, _ = s.LookupManifestEntry(ctx, "docs/README.md")
	if got.ETag != "etag-xyz" {
		t.Errorf("upsert did not update: ETag=%s", got.ETag)
	}

	// Delete.
	if err := s.DeleteManifestEntry(ctx, "docs/README.md"); err != nil {
		t.Fatal(err)
	}
	got, err = s.LookupManifestEntry(ctx, "docs/README.md")
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Errorf("post-delete lookup returned non-nil: %+v", got)
	}
}

func TestUploadQueue(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	// Empty queue.
	if next, _ := s.NextDueUpload(ctx); next != nil {
		t.Errorf("empty queue should return nil")
	}
	if n, _ := s.PendingUploadCount(ctx); n != 0 {
		t.Errorf("empty queue count = %d", n)
	}

	if err := s.EnqueueUpload(ctx, QueueEntry{
		QueueID:    "q1",
		RemotePath: "foo.txt",
		LocalPath:  "/tmp/foo.txt",
		Operation:  "put",
	}); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.PendingUploadCount(ctx); n != 1 {
		t.Errorf("post-enqueue count = %d, want 1", n)
	}
	next, err := s.NextDueUpload(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if next == nil || next.QueueID != "q1" {
		t.Fatalf("NextDueUpload = %v", next)
	}

	// Mark a retry — should advance next_attempt_at and stay pending.
	retryAt := time.Now().Add(2 * time.Minute).UTC()
	if err := s.MarkUploadAttempt(ctx, "q1", "transient network error", retryAt); err != nil {
		t.Fatal(err)
	}
	if next, _ := s.NextDueUpload(ctx); next != nil {
		t.Errorf("retry should defer next_attempt_at past now; got: %+v", next)
	}
	if n, _ := s.PendingUploadCount(ctx); n != 1 {
		t.Errorf("pending after retry = %d, want 1", n)
	}

	// Mark success — completed_at set, count drops.
	if err := s.MarkUploadAttempt(ctx, "q1", "", time.Time{}); err != nil {
		t.Fatal(err)
	}
	if n, _ := s.PendingUploadCount(ctx); n != 0 {
		t.Errorf("pending after success = %d, want 0", n)
	}
}

func TestConflictLog(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	if err := s.LogConflict(ctx, ConflictEntry{
		ConflictID:           "c1",
		RemotePath:           "foo.txt",
		LocalPath:            "/u/me/crate/foo.txt",
		ConflictingLocalPath: "/u/me/crate/foo.txt.conflict-2026-05-19T12-00-00.local",
		Resolution:           "conflicting-rename",
	}); err != nil {
		t.Fatal(err)
	}
	cs, err := s.RecentConflicts(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 1 {
		t.Fatalf("RecentConflicts = %d, want 1", len(cs))
	}
	if cs[0].ConflictingLocalPath == "" || cs[0].Resolution != "conflicting-rename" {
		t.Errorf("conflict row truncated: %+v", cs[0])
	}
}

func TestWatcherState(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	// Missing key returns "" + nil error.
	v, err := s.GetWatcherState(ctx, "cursor")
	if err != nil {
		t.Fatal(err)
	}
	if v != "" {
		t.Errorf("missing key returned %q", v)
	}

	// Round-trip + overwrite.
	if err := s.PutWatcherState(ctx, "cursor", "abc"); err != nil {
		t.Fatal(err)
	}
	if err := s.PutWatcherState(ctx, "cursor", "xyz"); err != nil {
		t.Fatal(err)
	}
	v, _ = s.GetWatcherState(ctx, "cursor")
	if v != "xyz" {
		t.Errorf("overwrite: got %q, want xyz", v)
	}
}

func TestDefaultPath(t *testing.T) {
	got := DefaultPath("/home/user/crate")
	want := "/home/user/crate/.crate/state.db"
	if got != want {
		t.Errorf("DefaultPath = %q, want %q", got, want)
	}
}

// TestManifestAnchor exercises the v3 migration's manifest_anchor table:
// missing-row returns (nil, nil), round-trip, upsert advances the count.
func TestManifestAnchor(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()

	// Missing row → (nil, nil), no error (TOFU signal).
	got, err := s.GetManifestAnchor(ctx, "bucket-A")
	if err != nil {
		t.Fatalf("GetManifestAnchor missing: %v", err)
	}
	if got != nil {
		t.Errorf("missing bucket returned non-nil anchor: %+v", got)
	}

	// Insert baseline.
	if err := s.SetManifestAnchor(ctx, "bucket-A", ManifestAnchor{
		Count: 3, LastSig: "sig-of-event-3",
	}); err != nil {
		t.Fatalf("SetManifestAnchor: %v", err)
	}
	got, err = s.GetManifestAnchor(ctx, "bucket-A")
	if err != nil {
		t.Fatalf("Get after Set: %v", err)
	}
	if got == nil {
		t.Fatal("Get after Set returned nil")
	}
	if got.Count != 3 || got.LastSig != "sig-of-event-3" {
		t.Errorf("round-trip: got %+v, want count=3 sig=sig-of-event-3", got)
	}
	if got.UpdatedAt.IsZero() {
		t.Error("UpdatedAt unset after Set")
	}

	// Overwrite (advance).
	if err := s.SetManifestAnchor(ctx, "bucket-A", ManifestAnchor{
		Count: 7, LastSig: "sig-of-event-7",
	}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetManifestAnchor(ctx, "bucket-A")
	if got.Count != 7 || got.LastSig != "sig-of-event-7" {
		t.Errorf("after advance: got %+v, want count=7", got)
	}

	// Independence across buckets.
	if err := s.SetManifestAnchor(ctx, "bucket-B", ManifestAnchor{
		Count: 1, LastSig: "sig-B",
	}); err != nil {
		t.Fatal(err)
	}
	a, _ := s.GetManifestAnchor(ctx, "bucket-A")
	b, _ := s.GetManifestAnchor(ctx, "bucket-B")
	if a.Count != 7 || b.Count != 1 {
		t.Errorf("bucket independence broken: A=%d B=%d", a.Count, b.Count)
	}

	// Empty bucket id rejected on both Get + Set.
	if _, err := s.GetManifestAnchor(ctx, ""); err == nil {
		t.Error("GetManifestAnchor empty bucket: expected error, got nil")
	}
	if err := s.SetManifestAnchor(ctx, "", ManifestAnchor{Count: 1}); err == nil {
		t.Error("SetManifestAnchor empty bucket: expected error, got nil")
	}
}

// TestManifestAnchorClockOverride verifies WithClock is honoured for the
// UpdatedAt field.
func TestManifestAnchorClockOverride(t *testing.T) {
	s := newStore(t)
	fixed := time.Date(2026, 5, 21, 12, 0, 0, 0, time.UTC)
	s.WithClock(func() time.Time { return fixed })
	ctx := context.Background()
	if err := s.SetManifestAnchor(ctx, "bucket-T", ManifestAnchor{Count: 1, LastSig: "x"}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetManifestAnchor(ctx, "bucket-T")
	if !got.UpdatedAt.Equal(fixed) {
		t.Errorf("UpdatedAt = %v, want %v", got.UpdatedAt, fixed)
	}
}
