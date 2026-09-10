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
//	watcher.Events() ─→ dispatcher ─→ upload_queue ─→ worker ─→ Hub PUT/DELETE
//	                                       │            │
//	                                    (state.db)   manifest_cache (success)
//	                                                    │
//	                                                 backoff (failure)
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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/NakliTechie/crate-agent/internal/httpc"
	"github.com/NakliTechie/crate-agent/internal/manifest"
	"github.com/NakliTechie/crate-agent/internal/payload"
	"github.com/NakliTechie/crate-agent/internal/state"
	"github.com/NakliTechie/crate-agent/internal/watcher"
)

// --- small helpers used by executePut / executeDelete --------------------

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }

// errUnchanged is returned by executePut when the file's bytes are exactly
// what manifest_cache recorded as last synced — nothing to upload. The
// worker treats it as success and logs it as a skip, not an upload.
var errUnchanged = errors.New("syncer: bytes unchanged since last sync")

func decodeB64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// decodeB64Must is used in tight paths where we BUILT the b64 ourselves and
// know it's valid; panic indicates a programmer error not a runtime issue.
func decodeB64Must(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		panic("syncer.decodeB64Must: " + err.Error())
	}
	return b
}

func mimeFromName(name string) string {
	ext := filepath.Ext(name)
	if ext == "" {
		return "application/octet-stream"
	}
	if m := mime.TypeByExtension(ext); m != "" {
		return m
	}
	return "application/octet-stream"
}

// Config configures a Syncer.
type Config struct {
	// LocalPath is the absolute path to the crate folder root.
	LocalPath string

	// BucketID is the daemon's bucket reference (returned by pair).
	BucketID string

	// CapabilityRef is dereferenced on each upload; refresh runner mutates
	// the pointee in place when the capability rotates. CapabilityMu
	// guards reads + writes (security audit 2026-05 M1).
	CapabilityRef *string
	CapabilityMu  *sync.RWMutex

	// MasterKeyRef is dereferenced on each upload. Salt reconciliation
	// may have replaced the master key after pair-time.
	MasterKeyRef *[]byte

	// ManifestRef is the shared in-memory manifest (also held by the
	// puller). Syncer appends events on push; reads back on push of
	// modifications. Mutex-guarded — every read or mutation MUST hold
	// ManifestMu.
	ManifestRef *manifest.Manifest
	ManifestMu  *sync.Mutex

	// ManifestETagRef tracks the last-known R2 ETag of the encrypted
	// manifest. Pointer so the puller can update the same pointee.
	// Pass &"" to start unconditional (the first PUT establishes the
	// initial ETag). Mutex-guarded via ManifestMu.
	ManifestETagRef *string

	// LastFlushedEventCountRef tracks how many events were successfully
	// flushed last time, so executePut's replay path knows which events
	// are "ours" to re-append onto a fresh remote manifest after a 412.
	// Mutex-guarded via ManifestMu.
	LastFlushedEventCountRef *int

	// Hub is the HTTP client pointed at the daemon's transport.
	Hub *httpc.Client

	// Watcher streams coalesced fs events. Caller starts/closes it.
	Watcher *watcher.Watcher

	// State is the open SQLite store.
	State *state.Store

	// Logger optionally collects structured logs. nil = slog.Default().
	Logger *slog.Logger

	// PollInterval is how often the worker checks for due uploads. Default
	// 250ms.
	PollInterval time.Duration

	// BackoffBase + BackoffCap shape the exponential retry schedule.
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
	if cfg.CapabilityRef == nil {
		return nil, errors.New("syncer: CapabilityRef is required")
	}
	if cfg.MasterKeyRef == nil {
		return nil, errors.New("syncer: MasterKeyRef is required")
	}
	if cfg.ManifestRef == nil {
		return nil, errors.New("syncer: ManifestRef is required")
	}
	if cfg.ManifestMu == nil {
		return nil, errors.New("syncer: ManifestMu is required")
	}
	if cfg.ManifestETagRef == nil {
		return nil, errors.New("syncer: ManifestETagRef is required")
	}
	if cfg.LastFlushedEventCountRef == nil {
		return nil, errors.New("syncer: LastFlushedEventCountRef is required")
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
	err = s.executeRow(ctx, row)
	if errors.Is(err, errUnchanged) {
		if mErr := s.cfg.State.MarkUploadAttempt(ctx, row.QueueID, "", time.Time{}); mErr != nil {
			s.logger.Error("MarkUploadAttempt(skip) failed", "queue_id", row.QueueID, "err", mErr)
		}
		s.logger.Info("skipped: bytes unchanged since last sync", "queue_id", row.QueueID, "rel", row.RemotePath)
		return true
	}
	if err != nil {
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

// executePut reads the local file, encrypts with a per-file data key
// wrapped under the master key, PUTs the ciphertext to objects/{uuid},
// appends a create-or-update event to the shared manifest, re-encrypts +
// PUTs the manifest. All wire shapes match the browser's M3 lib/crate.js.
func (s *Syncer) executePut(ctx context.Context, row *state.QueueEntry) error {
	plain, err := os.ReadFile(row.LocalPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// File vanished between watcher event and now. The matching
			// delete event from the watcher will land separately.
			s.logger.Debug("PUT target missing (likely deleted); skipping", "rel", row.RemotePath)
			return nil
		}
		return fmt.Errorf("read %s: %w", row.LocalPath, err)
	}
	info, err := os.Stat(row.LocalPath)
	if err != nil {
		return fmt.Errorf("stat %s: %w", row.LocalPath, err)
	}
	if info.IsDir() {
		return nil
	}

	// Echo guard. The puller lands a remote file by writing a temp file and
	// renaming it into place; the watcher sees that rename as a local
	// change and queues a put. If the bytes on disk are exactly what
	// manifest_cache recorded as last synced for this path (pulled or
	// pushed), there is nothing to upload — re-encrypting identical bytes
	// would only add a redundant version to the manifest. Refresh the
	// cached mtime so the puller's mtime-based conflict check stays quiet.
	sum := sha256.Sum256(plain)
	sumHex := hex.EncodeToString(sum[:])
	if cached, lerr := s.cfg.State.LookupManifestEntry(ctx, row.RemotePath); lerr == nil && cached != nil && cached.UUID != "" && cached.SHA256 == sumHex {
		cached.LocalMtimeNS = info.ModTime().UnixNano()
		cached.CachedAt = s.now().UTC()
		if uerr := s.cfg.State.UpsertManifestEntry(ctx, *cached); uerr != nil {
			s.logger.Warn("manifest_cache mtime refresh failed", "rel", row.RemotePath, "err", uerr)
		}
		return errUnchanged
	}

	cap := s.readCapability()
	masterKey := *s.cfg.MasterKeyRef
	if cap == "" || len(masterKey) == 0 {
		return errors.New("syncer: daemon not ready (capability or master key empty)")
	}

	// Manifest path is the row.RemotePath with a leading slash (matching
	// the browser's convention). The manifest_cache stores rows without
	// the leading slash; reconcile both.
	manifestPath := "/" + row.RemotePath

	// Decide create vs update under the manifest lock.
	s.cfg.ManifestMu.Lock()
	tree := s.cfg.ManifestRef.Materialise()
	existing := tree[manifestPath]
	s.cfg.ManifestMu.Unlock()

	var uuid, dataKeyIVB64, dataKeyCTB64 string
	var dataKey []byte
	if existing != nil && !existing.IsDir && existing.UUID != "" {
		// Update: reuse data key by unwrapping.
		uuid = existing.UUID
		ivBytes, err := decodeB64(existing.DataKeyIV)
		if err != nil {
			return fmt.Errorf("decode data_key_iv: %w", err)
		}
		ctBytes, err := decodeB64(existing.DataKeyCT)
		if err != nil {
			return fmt.Errorf("decode data_key_ct: %w", err)
		}
		dataKey, err = payload.UnwrapDataKey(masterKey, ivBytes, ctBytes, uuid)
		if err != nil {
			return fmt.Errorf("unwrap data key: %w", err)
		}
		dataKeyIVB64 = existing.DataKeyIV
		dataKeyCTB64 = existing.DataKeyCT
	} else {
		// Create: fresh uuid + data key.
		uuid = "01" + newULID()[:24]
		dataKey, err = payload.RandomDataKey()
		if err != nil {
			return fmt.Errorf("random data key: %w", err)
		}
		var dataKeyIV, dataKeyCT []byte
		dataKeyIV, dataKeyCT, err = payload.WrapDataKey(masterKey, dataKey, uuid)
		if err != nil {
			return fmt.Errorf("wrap data key: %w", err)
		}
		dataKeyIVB64 = base64.StdEncoding.EncodeToString(dataKeyIV)
		dataKeyCTB64 = base64.StdEncoding.EncodeToString(dataKeyCT)
	}
	defer payload.Zero(dataKey)

	// Encrypt the payload — v2 chunked framing (payload.SealObject).
	contentIV, body, err := payload.SealObject(dataKey, plain, uuid, payload.ChunkSize)
	if err != nil {
		return fmt.Errorf("seal payload: %w", err)
	}

	// PUT objects/{uuid}
	resp, err := s.cfg.Hub.PutObject(ctx, s.cfg.BucketID,
		"objects/"+uuid, bytesReader(body), int64(len(body)),
		"application/octet-stream", cap)
	if err != nil {
		return fmt.Errorf("PUT %s: %w", uuid, err)
	}
	if resp.Status < 200 || resp.Status >= 300 {
		return fmt.Errorf("PUT %s: upstream HTTP %d (%s)",
			uuid, resp.Status, envelopeMsg(resp))
	}

	// Append manifest event + flush.
	s.cfg.ManifestMu.Lock()
	// Re-check the current manifest state UNDER the lock — the puller
	// may have replaced or mutated the manifest between our pre-encrypt
	// snapshot above and now. If the path's situation changed (the
	// UUID we picked is no longer the current one for this path, or
	// the path got deleted entirely), the append we'd produce here
	// could silently lose a remote update. Re-resolve from the live
	// manifest and decide create-vs-update again. See 2026-05 security
	// audit, H4.
	currentTree := s.cfg.ManifestRef.Materialise()
	currentEntry := currentTree[manifestPath]
	createPath := existing == nil || existing.IsDir || existing.UUID == ""
	if createPath {
		// We thought this was a create. If the puller just landed a
		// remote create for the same path with a different UUID,
		// appending another create silently loses the remote one. Abort
		// + return; the watcher will re-queue this row, the conflict
		// rename path will catch up. Better to drop the local write
		// than clobber the user's remote.
		if currentEntry != nil && !currentEntry.IsDir && currentEntry.UUID != "" && currentEntry.UUID != uuid {
			s.cfg.ManifestMu.Unlock()
			return fmt.Errorf("syncer: race with puller — %s now has UUID %s remotely, abort local upload (will retry)",
				manifestPath, currentEntry.UUID)
		}
	} else {
		// We thought this was an update of `existing.UUID`. If the
		// current UUID at this path is different, the remote raced us.
		// Same conservative response.
		if currentEntry == nil || currentEntry.IsDir || currentEntry.UUID == "" {
			s.cfg.ManifestMu.Unlock()
			return fmt.Errorf("syncer: race — %s no longer exists in manifest, abort update of %s (will retry)",
				manifestPath, uuid)
		}
		if currentEntry.UUID != existing.UUID {
			s.cfg.ManifestMu.Unlock()
			return fmt.Errorf("syncer: race — %s UUID rotated under us (%s → %s), abort update (will retry)",
				manifestPath, existing.UUID, currentEntry.UUID)
		}
	}

	var evtErr error
	if !createPath {
		_, evtErr = s.cfg.ManifestRef.Append(
			manifest.WithChunkSize(manifest.UpdateEvent(uuid, int64(len(plain)), contentIV), payload.ChunkSize),
			masterKey,
		)
	} else {
		_, evtErr = s.cfg.ManifestRef.Append(
			manifest.WithChunkSize(manifest.CreateEvent(uuid, manifestPath, int64(len(plain)),
				mimeFromName(row.RemotePath),
				decodeB64Must(dataKeyIVB64),
				decodeB64Must(dataKeyCTB64),
				contentIV,
			), payload.ChunkSize),
			masterKey,
		)
	}
	if evtErr != nil {
		s.cfg.ManifestMu.Unlock()
		return fmt.Errorf("manifest append: %w", evtErr)
	}
	manifestBytes, err := s.cfg.ManifestRef.EncryptToBytes(masterKey)
	appendedCount := len(s.cfg.ManifestRef.Events())
	s.cfg.ManifestMu.Unlock()
	if err != nil {
		return fmt.Errorf("manifest encrypt: %w", err)
	}
	if err := s.putManifest(ctx, manifestBytes, cap, appendedCount); err != nil {
		return err
	}

	// Update local cache.
	if err := s.cfg.State.UpsertManifestEntry(ctx, state.ManifestEntry{
		RemotePath:   row.RemotePath,
		UUID:         uuid,
		ContentIV:    base64.StdEncoding.EncodeToString(contentIV),
		ETag:         uuid + ":" + base64.StdEncoding.EncodeToString(contentIV),
		SHA256:       hex.EncodeToString(sum[:]),
		SizeBytes:    int64(len(plain)),
		LastModified: s.now().UTC(),
		LocalMtimeNS: info.ModTime().UnixNano(),
	}); err != nil {
		s.logger.Error("UpsertManifestEntry failed (upload succeeded)", "err", err)
	}
	return nil
}

func (s *Syncer) executeDelete(ctx context.Context, row *state.QueueEntry) error {
	cap := s.readCapability()
	masterKey := *s.cfg.MasterKeyRef
	if cap == "" || len(masterKey) == 0 {
		return errors.New("syncer: daemon not ready")
	}

	manifestPath := "/" + row.RemotePath

	// Find uuid under manifest lock.
	s.cfg.ManifestMu.Lock()
	tree := s.cfg.ManifestRef.Materialise()
	existing := tree[manifestPath]
	s.cfg.ManifestMu.Unlock()

	if existing == nil || existing.IsDir || existing.UUID == "" {
		// Nothing to delete remotely — clear cache (if any) and move on.
		if err := s.cfg.State.DeleteManifestEntry(ctx, row.RemotePath); err != nil {
			s.logger.Warn("DeleteManifestEntry failed", "err", err)
		}
		return nil
	}

	// DELETE objects/{uuid}
	resp, err := s.cfg.Hub.DeleteObject(ctx, s.cfg.BucketID, "objects/"+existing.UUID, cap)
	if err != nil {
		return fmt.Errorf("DELETE %s: %w", existing.UUID, err)
	}
	if resp.Status != 204 && resp.Status != 200 && resp.Status != 404 {
		return fmt.Errorf("DELETE %s: upstream HTTP %d (%s)",
			existing.UUID, resp.Status, envelopeMsg(resp))
	}

	// Append manifest delete + flush.
	s.cfg.ManifestMu.Lock()
	_, evtErr := s.cfg.ManifestRef.Append(manifest.DeleteEvent(existing.UUID), masterKey)
	if evtErr != nil {
		s.cfg.ManifestMu.Unlock()
		return fmt.Errorf("manifest append delete: %w", evtErr)
	}
	manifestBytes, err := s.cfg.ManifestRef.EncryptToBytes(masterKey)
	appendedCount := len(s.cfg.ManifestRef.Events())
	s.cfg.ManifestMu.Unlock()
	if err != nil {
		return fmt.Errorf("manifest encrypt: %w", err)
	}
	if err := s.putManifest(ctx, manifestBytes, cap, appendedCount); err != nil {
		return err
	}

	if err := s.cfg.State.DeleteManifestEntry(ctx, row.RemotePath); err != nil {
		s.logger.Error("DeleteManifestEntry failed (delete succeeded)", "err", err)
	}
	return nil
}

// putManifest is shared by executePut + executeDelete after they append
// to the in-memory manifest. M6.x: PUTs with If-Match against the
// last-known ETag; on 412 (a peer wrote between our snapshot and our
// PUT) re-fetches the manifest, replays our local events on top, and
// retries. Up to 3 retries before giving up.
//
// Caller passes `appendedEventCount` — the value of len(ManifestRef.events)
// AFTER appending the local event(s) but BEFORE this call. We use this
// to figure out which events are "ours to replay" in the event of a 412.
func (s *Syncer) putManifest(ctx context.Context, body []byte, cap string, appendedEventCount int) error {
	const maxRetries = 3
	masterKey := *s.cfg.MasterKeyRef

	for attempt := 0; attempt <= maxRetries; attempt++ {
		s.cfg.ManifestMu.Lock()
		ifMatch := *s.cfg.ManifestETagRef
		s.cfg.ManifestMu.Unlock()

		resp, err := s.cfg.Hub.PutObjectIfMatch(ctx, s.cfg.BucketID, manifest.Path,
			bytesReader(body), int64(len(body)),
			"application/octet-stream", ifMatch, cap)
		if err != nil {
			return fmt.Errorf("PUT manifest: %w", err)
		}
		if resp.Status >= 200 && resp.Status < 300 {
			// Success — record the new ETag + bump the flushed-count.
			s.cfg.ManifestMu.Lock()
			*s.cfg.ManifestETagRef = strings.Trim(resp.ETag, `"`)
			*s.cfg.LastFlushedEventCountRef = appendedEventCount
			s.cfg.ManifestMu.Unlock()
			return nil
		}
		if resp.Status == 412 && attempt < maxRetries {
			s.logger.Info("manifest PUT 412; refetching + replaying local events",
				"attempt", attempt+1)
			// Re-GET + replay. Hold the lock for the whole replay so the
			// puller (which also touches ManifestRef) can't race.
			s.cfg.ManifestMu.Lock()
			lastFlushed := *s.cfg.LastFlushedEventCountRef
			// Snapshot the events we appended locally since the last flush.
			localPending := make([]manifest.Event, 0, len(s.cfg.ManifestRef.Events())-lastFlushed)
			for i := lastFlushed; i < len(s.cfg.ManifestRef.Events()); i++ {
				e := s.cfg.ManifestRef.Events()[i]
				clone := make(manifest.Event, len(e))
				for k, v := range e {
					if k == "v" || k == "ts" || k == "prev_sig" || k == "sig" {
						continue
					}
					clone[k] = v
				}
				localPending = append(localPending, clone)
			}
			s.cfg.ManifestMu.Unlock()

			got, err := s.cfg.Hub.GetObject(ctx, s.cfg.BucketID, manifest.Path, cap)
			if err != nil {
				return fmt.Errorf("re-GET manifest after 412: %w", err)
			}
			if got.Status < 200 || got.Status >= 300 {
				return fmt.Errorf("re-GET manifest after 412: HTTP %d", got.Status)
			}
			fresh, err := manifest.LoadFromBytes(got.Body, masterKey)
			if err != nil {
				return fmt.Errorf("re-GET manifest after 412: decode: %w", err)
			}
			// Replace shared manifest + replay local events under lock.
			s.cfg.ManifestMu.Lock()
			// Mutate in place via setter methods. internal/manifest doesn't
			// expose direct field writes; rebuild events through Append() so
			// every replayed event has a fresh prev_sig chain.
			*s.cfg.ManifestRef = *fresh
			for _, partial := range localPending {
				if _, aErr := s.cfg.ManifestRef.Append(partial, masterKey); aErr != nil {
					s.cfg.ManifestMu.Unlock()
					return fmt.Errorf("replay event: %w", aErr)
				}
			}
			// Re-encrypt the merged manifest for next PUT.
			newBody, err := s.cfg.ManifestRef.EncryptToBytes(masterKey)
			if err != nil {
				s.cfg.ManifestMu.Unlock()
				return fmt.Errorf("re-encrypt manifest after replay: %w", err)
			}
			*s.cfg.ManifestETagRef = strings.Trim(got.ETag, `"`)
			appendedEventCount = len(s.cfg.ManifestRef.Events())
			s.cfg.ManifestMu.Unlock()
			body = newBody
			continue
		}
		return fmt.Errorf("PUT manifest: upstream HTTP %d (%s)",
			resp.Status, envelopeMsg(resp))
	}
	return fmt.Errorf("PUT manifest: too many ETag-conflict retries")
}

// computeBackoff returns the next-attempt delay for an upload that has been
// tried `attempts` times (1-indexed). Exponential with cap.
// readCapability returns the current capability under the shared
// RWMutex. Refresh runner holds the write side; this is the read side.
// Falls through to a plain deref if no mutex was configured (the
// daemon was wired without the refresh runner — only in tests).
func (s *Syncer) readCapability() string {
	if s.cfg.CapabilityMu == nil {
		return *s.cfg.CapabilityRef
	}
	s.cfg.CapabilityMu.RLock()
	defer s.cfg.CapabilityMu.RUnlock()
	return *s.cfg.CapabilityRef
}

func (s *Syncer) computeBackoff(attempts int) time.Duration {
	if attempts < 1 {
		attempts = 1
	}
	delay := s.cfg.BackoffBase
	if delay >= s.cfg.BackoffCap {
		return s.cfg.BackoffCap
	}
	for attempt := 1; attempt < attempts; attempt++ {
		// Cap before doubling so large attempt counts cannot overflow
		// time.Duration. Float-to-int overflow differs across platforms.
		if delay > s.cfg.BackoffCap/2 {
			return s.cfg.BackoffCap
		}
		delay *= 2
	}
	return delay
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
