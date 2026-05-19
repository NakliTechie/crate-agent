// SPDX-License-Identifier: AGPL-3.0-or-later
// Package syncer binds the watcher + the local state DB + the Hub bucket-proxy
// into a one-direction upload loop. Watcher events enter the upload_queue;
// a worker drains the queue by streaming the file to the Hub.
//
// M3 piece 5 — push only. Pull-side (subscribe to the bucket's manifest,
// resolve conflicts via conflicting-rename) lands at piece 5b / M4.
//
// Architecture:
//
//   watcher.Events() ─→ dispatcher ─→ upload_queue ─→ worker ─→ Hub PUT/DELETE
//                                          │            │
//                                       (state.db)   manifest_cache (success)
//                                                       │
//                                                    backoff (failure)
//
// Crash safety:
//   - Every watcher event is persisted to upload_queue before the worker
//     touches it. A crash mid-upload re-runs the upload on restart.
//   - manifest_cache is updated AFTER the upload succeeds — local truth
//     follows remote truth.
//
// The syncer does NOT do encryption yet. M3 ships plaintext upload to a
// trusted Hub; payload encryption (the "browser-side master key wraps file
// keys" path per the vision doc) lands at crate M3 (browser). The daemon
// inherits that scheme via crate-agent M4.
package syncer

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/NakliTechie/crate-agent/internal/httpc"
	"github.com/NakliTechie/crate-agent/internal/state"
	"github.com/NakliTechie/crate-agent/internal/watcher"
)

// Config configures a Syncer.
type Config struct {
	// LocalPath is the absolute path to the crate folder root.
	LocalPath string

	// BucketID is the daemon's bucket reference (returned by pair).
	BucketID string

	// Capability is the daemon's base64-encoded macaroon, used as the
	// X-Fabric-Grant header on every Hub call.
	Capability string

	// Hub is the HTTP client pointed at the daemon's transport.
	Hub *httpc.Client

	// Watcher streams coalesced fs events. Caller starts/closes it.
	Watcher *watcher.Watcher

	// State is the open SQLite store.
	State *state.Store

	// Logger optionally collects structured logs. nil = slog.Default().
	Logger *slog.Logger

	// PollInterval is how often the worker checks for due uploads. Default
	// 250ms — tight enough to feel responsive after a quiet period; loose
	// enough not to thrash the DB.
	PollInterval time.Duration

	// BackoffBase + BackoffCap shape the exponential retry schedule for
	// failed uploads. attempts=N delays N → min(BackoffBase * 2^(N-1), BackoffCap).
	// Defaults: 1s base, 60s cap.
	BackoffBase time.Duration
	BackoffCap  time.Duration

	// Now overrides time.Now — testing only.
	Now func() time.Time
}

// Syncer runs the push-direction sync loop. Construct via New; call Run to
// start; cancel ctx (or call Close) to stop.
type Syncer struct {
	cfg Config

	logger *slog.Logger
	now    func() time.Time

	wg sync.WaitGroup
}

// New validates Config and constructs a Syncer.
func New(cfg Config) (*Syncer, error) {
	if cfg.LocalPath == "" {
		return nil, errors.New("syncer: LocalPath is required")
	}
	if cfg.BucketID == "" {
		return nil, errors.New("syncer: BucketID is required")
	}
	if cfg.Capability == "" {
		return nil, errors.New("syncer: Capability is required")
	}
	if cfg.Hub == nil {
		return nil, errors.New("syncer: Hub client is required")
	}
	if cfg.Watcher == nil {
		return nil, errors.New("syncer: Watcher is required")
	}
	if cfg.State == nil {
		return nil, errors.New("syncer: State is required")
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = 250 * time.Millisecond
	}
	if cfg.BackoffBase <= 0 {
		cfg.BackoffBase = 1 * time.Second
	}
	if cfg.BackoffCap <= 0 {
		cfg.BackoffCap = 60 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Syncer{cfg: cfg, logger: logger, now: cfg.Now}, nil
}

// Run starts the dispatcher + worker goroutines and blocks until ctx is
// cancelled. Both goroutines drain their work before returning.
func (s *Syncer) Run(ctx context.Context) error {
	s.wg.Add(2)
	go func() {
		defer s.wg.Done()
		s.runDispatcher(ctx)
	}()
	go func() {
		defer s.wg.Done()
		s.runWorker(ctx)
	}()
	s.wg.Wait()
	return nil
}

// runDispatcher reads watcher.Events() forever, enqueueing rows into
// upload_queue. Exits when ctx is done OR the watcher's event channel
// closes.
func (s *Syncer) runDispatcher(ctx context.Context) {
	events := s.cfg.Watcher.Events()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-events:
			if !ok {
				return
			}
			if ev.IsDir {
				// Directories are not first-class objects in S3-API; their
				// presence is implied by their contents. Recursive walks
				// happen on dir-create via the watcher's auto-Add, so we
				// can safely skip dir events here.
				continue
			}
			op := translateOp(ev.Op)
			if op == "" {
				continue
			}
			absPath := filepath.Join(s.cfg.LocalPath, ev.RelPath)
			row := state.QueueEntry{
				QueueID:    "q_" + newULID(),
				RemotePath: ev.RelPath,
				LocalPath:  absPath,
				Operation:  op,
			}
			if err := s.cfg.State.EnqueueUpload(ctx, row); err != nil {
				s.logger.Error("EnqueueUpload failed",
					"rel", ev.RelPath, "op", op, "err", err)
			} else {
				s.logger.Debug("enqueued", "rel", ev.RelPath, "op", op, "queue_id", row.QueueID)
			}
		}
	}
}

// translateOp maps watcher ops to upload_queue operations. Create + Write +
// Rename(target) all become "put"; Remove + Rename(source) become "delete".
// Rename(target) means "a file appeared via rename" — looks like a create
// from S3's perspective.
//
// Note: fsnotify emits Rename for the OLD path on rename. For a within-tree
// move, we get [Rename(old), Create(new)]; the OLD path becomes "delete"
// and the NEW path becomes "put". A move OUT of the tree is just
// Rename(old) → "delete". Both cases are correct.
func translateOp(op watcher.Op) string {
	switch op {
	case watcher.OpCreate, watcher.OpWrite:
		return "put"
	case watcher.OpRemove, watcher.OpRename:
		return "delete"
	default:
		return ""
	}
}

// runWorker polls upload_queue at PollInterval and runs each due row.
func (s *Syncer) runWorker(ctx context.Context) {
	tick := time.NewTicker(s.cfg.PollInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			// Drain as many due rows as we can in one tick — bounded by
			// a per-tick limit so one extremely-full queue doesn't starve
			// other tasks. 32 is generous; the bottleneck in practice is
			// network, not the DB.
			for i := 0; i < 32; i++ {
				if !s.workOneDue(ctx) {
					break
				}
			}
		}
	}
}

// workOneDue pulls the next due row and processes it. Returns true if a row
// was processed (i.e. the worker should immediately look for another),
// false otherwise.
func (s *Syncer) workOneDue(ctx context.Context) bool {
	row, err := s.cfg.State.NextDueUpload(ctx)
	if err != nil {
		s.logger.Error("NextDueUpload failed", "err", err)
		return false
	}
	if row == nil {
		return false
	}
	if err := s.executeRow(ctx, row); err != nil {
		// On a context cancel, don't update DB — the cancel is the signal
		// to stop, and we want the row to be retried next run.
		if errors.Is(err, context.Canceled) {
			return false
		}
		next := s.computeBackoff(row.Attempts + 1)
		if mErr := s.cfg.State.MarkUploadAttempt(ctx, row.QueueID, err.Error(), s.now().Add(next)); mErr != nil {
			s.logger.Error("MarkUploadAttempt(retry) failed", "queue_id", row.QueueID, "err", mErr)
		}
		s.logger.Warn("upload failed; scheduled retry",
			"queue_id", row.QueueID, "rel", row.RemotePath,
			"op", row.Operation, "attempts", row.Attempts+1,
			"next_in", next, "err", err)
		return true
	}
	if err := s.cfg.State.MarkUploadAttempt(ctx, row.QueueID, "", time.Time{}); err != nil {
		s.logger.Error("MarkUploadAttempt(success) failed", "queue_id", row.QueueID, "err", err)
	}
	s.logger.Info("uploaded",
		"queue_id", row.QueueID, "rel", row.RemotePath, "op", row.Operation,
		"attempts", row.Attempts+1)
	return true
}

// executeRow dispatches to the per-operation handler. Updates manifest_cache
// on success.
func (s *Syncer) executeRow(ctx context.Context, row *state.QueueEntry) error {
	switch row.Operation {
	case "put":
		return s.executePut(ctx, row)
	case "delete":
		return s.executeDelete(ctx, row)
	default:
		return fmt.Errorf("syncer: unknown operation %q", row.Operation)
	}
}

func (s *Syncer) executePut(ctx context.Context, row *state.QueueEntry) error {
	// Open the local file. If it's gone, treat as a delete (someone deleted
	// the file between the Watcher event and now). Re-enqueue isn't needed
	// because the delete event would have been emitted separately if the
	// file was actually removed via the FS API.
	f, err := os.Open(row.LocalPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Silently treat missing file as success — the next sync pass
			// will pick up the actual delete event from the watcher.
			s.logger.Debug("PUT target missing (likely deleted); skipping", "rel", row.RemotePath)
			return nil
		}
		return fmt.Errorf("open %s: %w", row.LocalPath, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", row.LocalPath, err)
	}
	if info.IsDir() {
		// Watcher should have filtered this; defensive skip.
		return nil
	}

	// Compute SHA-256 + size by streaming once through a TeeReader. We need
	// the SHA in manifest_cache; we also need to ship the bytes. Avoids a
	// second open + read.
	hasher := sha256.New()
	rd := io.TeeReader(f, hasher)

	resp, err := s.cfg.Hub.PutObject(ctx, s.cfg.BucketID, row.RemotePath,
		rd, info.Size(), "", s.cfg.Capability)
	if err != nil {
		return fmt.Errorf("PUT %s: %w", row.RemotePath, err)
	}
	if resp.Status < 200 || resp.Status >= 300 {
		return fmt.Errorf("PUT %s: upstream HTTP %d (%s)",
			row.RemotePath, resp.Status, envelopeMsg(resp))
	}

	if err := s.cfg.State.UpsertManifestEntry(ctx, state.ManifestEntry{
		RemotePath:   row.RemotePath,
		ETag:         resp.ETag,
		SHA256:       hex.EncodeToString(hasher.Sum(nil)),
		SizeBytes:    info.Size(),
		LastModified: s.now().UTC(),
		LocalMtimeNS: info.ModTime().UnixNano(),
	}); err != nil {
		s.logger.Error("UpsertManifestEntry failed (upload succeeded)", "err", err)
	}
	return nil
}

func (s *Syncer) executeDelete(ctx context.Context, row *state.QueueEntry) error {
	resp, err := s.cfg.Hub.DeleteObject(ctx, s.cfg.BucketID, row.RemotePath, s.cfg.Capability)
	if err != nil {
		return fmt.Errorf("DELETE %s: %w", row.RemotePath, err)
	}
	// 204 (success) and 404 (already gone) both count as "the desired state
	// is achieved." Anything else is a real error.
	if resp.Status != 204 && resp.Status != 200 && resp.Status != 404 {
		return fmt.Errorf("DELETE %s: upstream HTTP %d (%s)",
			row.RemotePath, resp.Status, envelopeMsg(resp))
	}
	if err := s.cfg.State.DeleteManifestEntry(ctx, row.RemotePath); err != nil {
		s.logger.Error("DeleteManifestEntry failed (delete succeeded)", "err", err)
	}
	return nil
}

// computeBackoff returns the next-attempt delay for an upload that has been
// tried `attempts` times (1-indexed). Exponential with cap.
func (s *Syncer) computeBackoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	mult := math.Pow(2, float64(attempts-1))
	d := time.Duration(float64(s.cfg.BackoffBase) * mult)
	if d > s.cfg.BackoffCap {
		d = s.cfg.BackoffCap
	}
	return d
}

// envelopeMsg extracts a human-readable error message from a Hub response,
// preferring the envelope's error code+message when present.
func envelopeMsg(resp *httpc.Response) string {
	if resp.Envelope.Error != nil {
		return resp.Envelope.Error.Code + ": " + resp.Envelope.Error.Message
	}
	if len(resp.Body) > 0 && len(resp.Body) < 200 {
		return string(resp.Body)
	}
	return "no error envelope"
}

// newULID returns a fresh lexicographically-orderable id. crypto-rand
// source so the id is unguessable.
func newULID() string {
	id, err := ulid.New(ulid.Now(), rand.Reader)
	if err != nil {
		// Fall back to a timestamp string — collisions are vanishingly
		// unlikely since we're appending nanoseconds.
		return base64.RawURLEncoding.EncodeToString([]byte(time.Now().UTC().Format("20060102T150405.000000000Z")))
	}
	return id.String()
}
