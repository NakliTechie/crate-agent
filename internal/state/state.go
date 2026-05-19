// SPDX-License-Identifier: AGPL-3.0-or-later
// Package state owns the daemon's local SQLite store. Tables:
//
//   - manifest_cache  — local mirror of the cloud manifest (one row per
//                       remote path; ETag + sha256 + mtime + version).
//   - upload_queue    — pending uploads with retry counters.
//   - conflict_log    — divergent-write events surfaced in `status`.
//   - watcher_state   — last-processed FS cursor + pending debounce buffers
//                       (used to resume on restart without rescanning).
//
// Driver: modernc.org/sqlite (pure-Go; no CGO). Single open store per
// daemon process; migrations applied on open.
package state

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// Migrations is the ordered list of forward-only schema versions. Tracked
// via SQLite's `user_version` pragma. ALWAYS APPEND — never edit existing
// rows in production data.
var Migrations = []string{
	// 1: M3 piece 3 — initial daemon state schema.
	`
CREATE TABLE manifest_cache (
    remote_path TEXT PRIMARY KEY,
    etag TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    last_modified TEXT NOT NULL,
    local_mtime_ns INTEGER NOT NULL,
    cached_at TEXT NOT NULL
);
CREATE INDEX idx_manifest_modified ON manifest_cache(last_modified);

CREATE TABLE upload_queue (
    queue_id TEXT PRIMARY KEY,
    remote_path TEXT NOT NULL,
    local_path TEXT NOT NULL,
    operation TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_attempt_at TEXT,
    next_attempt_at TEXT NOT NULL,
    last_error TEXT,
    enqueued_at TEXT NOT NULL,
    completed_at TEXT
);
CREATE INDEX idx_upload_queue_next ON upload_queue(next_attempt_at) WHERE completed_at IS NULL;
CREATE INDEX idx_upload_queue_path ON upload_queue(remote_path);

CREATE TABLE conflict_log (
    conflict_id TEXT PRIMARY KEY,
    remote_path TEXT NOT NULL,
    local_path TEXT NOT NULL,
    conflicting_local_path TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    resolution TEXT,
    resolved_at TEXT
);
CREATE INDEX idx_conflict_detected ON conflict_log(detected_at);

CREATE TABLE watcher_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
`,
}

// Store is the open SQLite connection + a clock for testable timestamps.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// Open opens (or creates) the SQLite file at path, applies migrations, and
// returns a Store. The parent directory must already exist; callers
// (`pair`, `start`) create it.
func Open(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("state: path is required")
	}
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("state: open %s: %w", path, err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("state: ping %s: %w", path, err)
	}
	s := &Store{db: db, now: time.Now}
	if err := s.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the SQLite handle.
func (s *Store) Close() error { return s.db.Close() }

// DB returns the underlying *sql.DB. Used by tests that inspect rows
// directly; production callers use the typed methods below.
func (s *Store) DB() *sql.DB { return s.db }

// WithClock overrides the timestamp source — testing only.
func (s *Store) WithClock(now func() time.Time) *Store {
	s.now = now
	return s
}

// migrate applies any not-yet-applied migrations. Idempotent.
func (s *Store) migrate() error {
	var current int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&current); err != nil {
		return fmt.Errorf("state: read user_version: %w", err)
	}
	for v := current; v < len(Migrations); v++ {
		tx, err := s.db.Begin()
		if err != nil {
			return fmt.Errorf("state: begin migrate v%d: %w", v+1, err)
		}
		if _, err := tx.Exec(Migrations[v]); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("state: apply migrate v%d: %w", v+1, err)
		}
		if _, err := tx.Exec(fmt.Sprintf("PRAGMA user_version = %d", v+1)); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("state: bump user_version: %w", err)
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("state: commit migrate v%d: %w", v+1, err)
		}
	}
	return nil
}

// DefaultPath returns the canonical absolute path the daemon should use for
// the state DB when the user did not configure agent.state_db explicitly.
// Default: <crate_local_path>/.crate/state.db (kept inside the crate folder
// so removing the folder also removes the daemon's local state).
func DefaultPath(crateLocalPath string) string {
	return filepath.Join(crateLocalPath, ".crate", "state.db")
}

// --- manifest_cache --------------------------------------------------------

// ManifestEntry is one row in manifest_cache.
type ManifestEntry struct {
	RemotePath   string
	ETag         string
	SHA256       string
	SizeBytes    int64
	LastModified time.Time
	LocalMtimeNS int64
	CachedAt     time.Time
}

// UpsertManifestEntry inserts or updates the row keyed by remote_path.
func (s *Store) UpsertManifestEntry(ctx context.Context, e ManifestEntry) error {
	if e.RemotePath == "" {
		return errors.New("UpsertManifestEntry: RemotePath is empty")
	}
	if e.CachedAt.IsZero() {
		e.CachedAt = s.now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO manifest_cache (remote_path, etag, sha256, size_bytes,
                                    last_modified, local_mtime_ns, cached_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(remote_path) DO UPDATE SET
            etag           = excluded.etag,
            sha256         = excluded.sha256,
            size_bytes     = excluded.size_bytes,
            last_modified  = excluded.last_modified,
            local_mtime_ns = excluded.local_mtime_ns,
            cached_at      = excluded.cached_at`,
		e.RemotePath, e.ETag, e.SHA256, e.SizeBytes,
		e.LastModified.UTC().Format(time.RFC3339Nano),
		e.LocalMtimeNS,
		e.CachedAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("UpsertManifestEntry: %w", err)
	}
	return nil
}

// LookupManifestEntry returns the row for remote_path or (nil, nil) if absent.
// (nil, nil) is the "not-yet-synced" signal — callers should NOT treat it
// as an error.
func (s *Store) LookupManifestEntry(ctx context.Context, remotePath string) (*ManifestEntry, error) {
	var (
		e            ManifestEntry
		lastModified string
		cachedAt     string
	)
	err := s.db.QueryRowContext(ctx, `
        SELECT remote_path, etag, sha256, size_bytes, last_modified,
               local_mtime_ns, cached_at
        FROM manifest_cache WHERE remote_path = ?`, remotePath,
	).Scan(&e.RemotePath, &e.ETag, &e.SHA256, &e.SizeBytes,
		&lastModified, &e.LocalMtimeNS, &cachedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("LookupManifestEntry: %w", err)
	}
	if t, perr := time.Parse(time.RFC3339Nano, lastModified); perr == nil {
		e.LastModified = t
	}
	if t, perr := time.Parse(time.RFC3339Nano, cachedAt); perr == nil {
		e.CachedAt = t
	}
	return &e, nil
}

// DeleteManifestEntry removes the row for remote_path. No-op if absent.
func (s *Store) DeleteManifestEntry(ctx context.Context, remotePath string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM manifest_cache WHERE remote_path = ?`, remotePath)
	if err != nil {
		return fmt.Errorf("DeleteManifestEntry: %w", err)
	}
	return nil
}

// --- upload_queue ----------------------------------------------------------

// QueueEntry is one row in upload_queue.
type QueueEntry struct {
	QueueID       string
	RemotePath    string
	LocalPath     string
	Operation     string // "put" | "delete"
	Attempts      int
	LastAttemptAt *time.Time
	NextAttemptAt time.Time
	LastError     string
	EnqueuedAt    time.Time
	CompletedAt   *time.Time
}

// EnqueueUpload appends a new pending row. queueID must be unique — caller
// generates it (ULID convention).
func (s *Store) EnqueueUpload(ctx context.Context, e QueueEntry) error {
	if e.QueueID == "" {
		return errors.New("EnqueueUpload: QueueID is empty")
	}
	if e.RemotePath == "" || e.Operation == "" {
		return errors.New("EnqueueUpload: RemotePath + Operation required")
	}
	if e.EnqueuedAt.IsZero() {
		e.EnqueuedAt = s.now().UTC()
	}
	if e.NextAttemptAt.IsZero() {
		e.NextAttemptAt = e.EnqueuedAt
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO upload_queue (queue_id, remote_path, local_path,
                                  operation, attempts, next_attempt_at,
                                  enqueued_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)`,
		e.QueueID, e.RemotePath, e.LocalPath, e.Operation, e.Attempts,
		e.NextAttemptAt.UTC().Format(time.RFC3339Nano),
		e.EnqueuedAt.Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("EnqueueUpload: %w", err)
	}
	return nil
}

// NextDueUpload returns the next pending row whose next_attempt_at has
// elapsed, or (nil, nil) when the queue is empty.
func (s *Store) NextDueUpload(ctx context.Context) (*QueueEntry, error) {
	var (
		e             QueueEntry
		lastAttemptAt sql.NullString
		nextAttemptAt string
		lastError     sql.NullString
		enqueuedAt    string
		localPath     sql.NullString
	)
	err := s.db.QueryRowContext(ctx, `
        SELECT queue_id, remote_path, local_path, operation, attempts,
               last_attempt_at, next_attempt_at, last_error, enqueued_at
        FROM upload_queue
        WHERE completed_at IS NULL AND next_attempt_at <= ?
        ORDER BY next_attempt_at ASC
        LIMIT 1`, s.now().UTC().Format(time.RFC3339Nano),
	).Scan(&e.QueueID, &e.RemotePath, &localPath, &e.Operation, &e.Attempts,
		&lastAttemptAt, &nextAttemptAt, &lastError, &enqueuedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("NextDueUpload: %w", err)
	}
	if localPath.Valid {
		e.LocalPath = localPath.String
	}
	if lastAttemptAt.Valid {
		if t, perr := time.Parse(time.RFC3339Nano, lastAttemptAt.String); perr == nil {
			e.LastAttemptAt = &t
		}
	}
	if lastError.Valid {
		e.LastError = lastError.String
	}
	if t, perr := time.Parse(time.RFC3339Nano, nextAttemptAt); perr == nil {
		e.NextAttemptAt = t
	}
	if t, perr := time.Parse(time.RFC3339Nano, enqueuedAt); perr == nil {
		e.EnqueuedAt = t
	}
	return &e, nil
}

// MarkUploadAttempt records an attempt's result. errMsg=="" + nextAttempt
// zero ⇒ success (completed_at set, last_error cleared).
func (s *Store) MarkUploadAttempt(ctx context.Context, queueID, errMsg string, nextAttempt time.Time) error {
	now := s.now().UTC().Format(time.RFC3339Nano)
	if errMsg == "" && nextAttempt.IsZero() {
		_, err := s.db.ExecContext(ctx, `
            UPDATE upload_queue
            SET attempts        = attempts + 1,
                last_attempt_at = ?,
                last_error      = NULL,
                completed_at    = ?
            WHERE queue_id = ? AND completed_at IS NULL`,
			now, now, queueID,
		)
		if err != nil {
			return fmt.Errorf("MarkUploadAttempt success: %w", err)
		}
		return nil
	}
	_, err := s.db.ExecContext(ctx, `
        UPDATE upload_queue
        SET attempts        = attempts + 1,
            last_attempt_at = ?,
            last_error      = ?,
            next_attempt_at = ?
        WHERE queue_id = ? AND completed_at IS NULL`,
		now, errMsg, nextAttempt.UTC().Format(time.RFC3339Nano), queueID,
	)
	if err != nil {
		return fmt.Errorf("MarkUploadAttempt retry: %w", err)
	}
	return nil
}

// PendingUploadCount returns how many rows are still un-completed. Used by
// `crate-agent status`.
func (s *Store) PendingUploadCount(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
        SELECT COUNT(1) FROM upload_queue WHERE completed_at IS NULL`,
	).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("PendingUploadCount: %w", err)
	}
	return n, nil
}

// --- conflict_log ----------------------------------------------------------

// ConflictEntry is one row in conflict_log.
type ConflictEntry struct {
	ConflictID           string
	RemotePath           string
	LocalPath            string
	ConflictingLocalPath string
	DetectedAt           time.Time
	Resolution           string
	ResolvedAt           *time.Time
}

// LogConflict appends a conflict row. conflictID must be unique.
func (s *Store) LogConflict(ctx context.Context, e ConflictEntry) error {
	if e.ConflictID == "" {
		return errors.New("LogConflict: ConflictID is empty")
	}
	if e.DetectedAt.IsZero() {
		e.DetectedAt = s.now().UTC()
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO conflict_log (conflict_id, remote_path, local_path,
                                  conflicting_local_path, detected_at, resolution)
        VALUES (?, ?, ?, ?, ?, ?)`,
		e.ConflictID, e.RemotePath, e.LocalPath, e.ConflictingLocalPath,
		e.DetectedAt.Format(time.RFC3339Nano), e.Resolution,
	)
	if err != nil {
		return fmt.Errorf("LogConflict: %w", err)
	}
	return nil
}

// RecentConflicts returns the last N conflicts, most-recent-first.
func (s *Store) RecentConflicts(ctx context.Context, limit int) ([]ConflictEntry, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := s.db.QueryContext(ctx, `
        SELECT conflict_id, remote_path, local_path, conflicting_local_path,
               detected_at, resolution, resolved_at
        FROM conflict_log
        ORDER BY detected_at DESC
        LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("RecentConflicts: %w", err)
	}
	defer rows.Close()

	var out []ConflictEntry
	for rows.Next() {
		var (
			e          ConflictEntry
			resolution sql.NullString
			resolvedAt sql.NullString
			detectedAt string
		)
		if err := rows.Scan(&e.ConflictID, &e.RemotePath, &e.LocalPath,
			&e.ConflictingLocalPath, &detectedAt, &resolution, &resolvedAt); err != nil {
			return nil, fmt.Errorf("RecentConflicts scan: %w", err)
		}
		if resolution.Valid {
			e.Resolution = resolution.String
		}
		if t, perr := time.Parse(time.RFC3339Nano, detectedAt); perr == nil {
			e.DetectedAt = t
		}
		if resolvedAt.Valid {
			if t, perr := time.Parse(time.RFC3339Nano, resolvedAt.String); perr == nil {
				e.ResolvedAt = &t
			}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// --- watcher_state ---------------------------------------------------------

// PutWatcherState upserts a key/value pair into the watcher_state table.
// Used to persist the last-processed FS cursor + similar small bits of
// daemon-loop state that must survive a restart.
func (s *Store) PutWatcherState(ctx context.Context, key, value string) error {
	if key == "" {
		return errors.New("PutWatcherState: key is empty")
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO watcher_state (key, value, updated_at) VALUES (?, ?, ?)
        ON CONFLICT(key) DO UPDATE SET
            value      = excluded.value,
            updated_at = excluded.updated_at`,
		key, value, s.now().UTC().Format(time.RFC3339Nano),
	)
	if err != nil {
		return fmt.Errorf("PutWatcherState: %w", err)
	}
	return nil
}

// GetWatcherState returns the value for key, or "" if absent (no error).
func (s *Store) GetWatcherState(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM watcher_state WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("GetWatcherState: %w", err)
	}
	return v, nil
}
