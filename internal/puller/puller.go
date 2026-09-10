// SPDX-License-Identifier: AGPL-3.0-or-later
// Package puller implements the pull side of crate-agent's sync loop in
// the M3 (encrypted) wire format. The bucket holds:
//
//	.crate/crate.json                — salt + version metadata (cleartext)
//	.crate/manifest.jsonl.enc        — encrypted signed JSONL event log
//	objects/{uuid}                   — encrypted file payloads
//
// Manifest is the source of truth — the puller no longer LISTs the
// bucket. Every tick:
//
//  1. GET .crate/manifest.jsonl.enc
//  2. AES-GCM-decrypt + parse JSONL
//  3. Verify the prev_sig chain
//  4. Materialise the tree
//  5. For each entry: compare against manifest_cache (uuid + content_iv);
//     mismatch ⇒ GET objects/{uuid}, unwrap data key, decrypt payload,
//     atomic-write to disk at the canonical path
//  6. For each cached row NOT in the materialised tree ⇒ remote tombstone;
//     remove the local copy (unless local was modified since last sync,
//     in which case keep local + log conflict)
//
// Conflict-rename + remote-deleted-local-kept logic carries over from the
// pre-M3 puller; only the source-of-truth comparison changed.
package puller

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	b64 "encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/NakliTechie/crate-agent/internal/cratejson"
	"github.com/NakliTechie/crate-agent/internal/httpc"
	"github.com/NakliTechie/crate-agent/internal/manifest"
	"github.com/NakliTechie/crate-agent/internal/payload"
	"github.com/NakliTechie/crate-agent/internal/state"
)

const DefaultPollInterval = 15 * time.Second

const ObjectsPrefix = "objects/"

// Config configures a Puller. MasterKeyRef is shared with the syncer +
// refresh runner so all three see the same master key (refresh may
// rotate it during reconciliation).
type Config struct {
	LocalPath string
	BucketID  string

	// CapabilityRef is dereferenced on each tick — refresh runner mutates
	// the pointee on capability rotation. CapabilityMu guards reads +
	// writes (security audit 2026-05 M1).
	CapabilityRef *string
	CapabilityMu  *sync.RWMutex

	// MasterKeyRef is dereferenced on each tick — salt reconciliation
	// may have replaced the master key after pair-time.
	MasterKeyRef *[]byte

	// ManifestRef is the shared in-memory manifest. The syncer mutates
	// it on push; the puller replaces it on pull. Mutex-guarded.
	ManifestRef *manifest.Manifest
	ManifestMu  *sync.Mutex

	// ManifestETagRef + LastFlushedEventCountRef are shared with the
	// syncer for M6.x If-Match conditional PUTs. The puller updates
	// these on every successful manifest pull — bookkeeping for the
	// syncer's next write.
	ManifestETagRef          *string
	LastFlushedEventCountRef *int

	Hub   *httpc.Client
	State *state.Store

	PollInterval time.Duration
	Logger       *slog.Logger
	Now          func() time.Time

	// LastSyncSlackNs — see pre-M3 docstring.
	LastSyncSlackNs int64
}

// Puller drives the periodic pull-side reconciliation loop.
type Puller struct {
	cfg          Config
	logger       *slog.Logger
	now          func() time.Time
	pollInterval time.Duration
	slackNs      int64

	// Stats for `status`.
	listCalls    atomic.Int64
	downloaded   atomic.Int64
	conflicts    atomic.Int64
	deletedLocal atomic.Int64
}

func New(cfg Config) (*Puller, error) {
	if cfg.LocalPath == "" {
		return nil, errors.New("puller: LocalPath required")
	}
	if cfg.BucketID == "" {
		return nil, errors.New("puller: BucketID required")
	}
	if cfg.CapabilityRef == nil {
		return nil, errors.New("puller: CapabilityRef required")
	}
	if cfg.MasterKeyRef == nil {
		return nil, errors.New("puller: MasterKeyRef required")
	}
	if cfg.ManifestRef == nil {
		return nil, errors.New("puller: ManifestRef required")
	}
	if cfg.ManifestMu == nil {
		return nil, errors.New("puller: ManifestMu required")
	}
	if cfg.ManifestETagRef == nil {
		return nil, errors.New("puller: ManifestETagRef required")
	}
	if cfg.LastFlushedEventCountRef == nil {
		return nil, errors.New("puller: LastFlushedEventCountRef required")
	}
	if cfg.Hub == nil {
		return nil, errors.New("puller: Hub required")
	}
	if cfg.State == nil {
		return nil, errors.New("puller: State required")
	}
	p := &Puller{
		cfg:          cfg,
		logger:       cfg.Logger,
		now:          cfg.Now,
		pollInterval: cfg.PollInterval,
		slackNs:      cfg.LastSyncSlackNs,
	}
	if p.logger == nil {
		p.logger = slog.Default()
	}
	if p.now == nil {
		p.now = time.Now
	}
	if p.pollInterval <= 0 {
		p.pollInterval = DefaultPollInterval
	}
	if p.slackNs <= 0 {
		p.slackNs = int64(time.Second)
	}
	return p, nil
}

func (p *Puller) Run(ctx context.Context) {
	tick := time.NewTicker(p.pollInterval)
	defer tick.Stop()
	p.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			p.tick(ctx)
		}
	}
}

type Stats struct {
	ListCalls    int64
	Downloaded   int64
	Conflicts    int64
	DeletedLocal int64
}

func (p *Puller) Stats() Stats {
	return Stats{
		ListCalls:    p.listCalls.Load(),
		Downloaded:   p.downloaded.Load(),
		Conflicts:    p.conflicts.Load(),
		DeletedLocal: p.deletedLocal.Load(),
	}
}

// tick is one reconciliation pass: GET manifest, materialise, reconcile.
func (p *Puller) tick(ctx context.Context) {
	cap := p.readCapability()
	mk := *p.cfg.MasterKeyRef
	if cap == "" || len(mk) == 0 {
		// Daemon not ready (capability unset / master key not yet derived).
		// Skip silently; next tick retries.
		return
	}

	// 1. GET manifest.
	resp, err := p.cfg.Hub.GetObject(ctx, p.cfg.BucketID, manifest.Path, cap)
	if err != nil {
		p.logger.Warn("manifest GET failed", "err", err)
		return
	}
	p.listCalls.Add(1)
	var fresh *manifest.Manifest
	if resp.Status == http.StatusNotFound {
		// Manifest absent — treat as empty (browser hasn't done first-time
		// setup yet OR daemon is the first writer).
		fresh = manifest.New()
	} else if resp.Status >= 200 && resp.Status < 300 {
		fresh, err = manifest.LoadFromBytes(resp.Body, mk)
		if err != nil {
			p.logger.Warn("manifest decrypt/parse failed", "err", err)
			return
		}
	} else {
		p.logger.Warn("manifest GET non-2xx", "status", resp.Status)
		return
	}

	// 2. Verify sig chain (defence-in-depth; rejects tampered manifests
	// even if the AES-GCM auth tag was valid for some reason).
	if ok, idx, reason := fresh.Verify(mk); !ok {
		p.logger.Warn("manifest sig chain invalid; refusing to apply",
			"idx", idx, "reason", reason)
		return
	}

	// 2b. Rollback anchor check. A bucket-only attacker can serve an
	// older valid encrypted manifest — AES-GCM authenticates with the
	// unchanged master key, prev_sig chain over the older prefix is
	// still valid. The anchor refuses any manifest that doesn't extend
	// (or match) the highest-count chain we've ever accepted on this
	// device. First load TOFUs (anchor is nil → accept + record).
	// See 2026-05 security audit, finding H1.
	if ok, reason := p.validateAndAdvanceAnchor(ctx, fresh); !ok {
		p.logger.Warn("manifest rollback detected; refusing to apply",
			"reason", reason)
		return
	}

	// 3. Replace the shared in-memory manifest under the lock + update
	// the M6.x bookkeeping fields the syncer's putManifest depends on.
	p.cfg.ManifestMu.Lock()
	*p.cfg.ManifestRef = *fresh
	*p.cfg.ManifestETagRef = strings.Trim(resp.ETag, `"`)
	*p.cfg.LastFlushedEventCountRef = len(fresh.Events())
	p.cfg.ManifestMu.Unlock()

	// 4. Materialise + reconcile each entry.
	tree := fresh.Materialise()
	// seenPaths uses the same no-leading-slash form as manifest_cache.RemotePath
	// so tombstone detection compares apples-to-apples.
	seenPaths := make(map[string]struct{}, len(tree))
	for path, entry := range tree {
		seenPaths[stripLeadingSlash(path)] = struct{}{}
		if path == cratejson.CratePath || path == manifest.Path {
			continue // skip metadata paths
		}
		if err := p.reconcileOne(ctx, path, entry, mk, cap); err != nil {
			p.logger.Warn("reconcile failed", "path", path, "err", err)
		}
	}

	// 5. Tombstone detection: any manifest_cache row whose path isn't in
	// the new manifest means the remote has deleted (or never had) it.
	allCached, err := p.allCachedKeys(ctx)
	if err != nil {
		p.logger.Warn("walk manifest_cache failed", "err", err)
		return
	}
	for _, key := range allCached {
		if _, present := seenPaths[key]; present {
			continue
		}
		if err := p.handleRemoteDelete(ctx, key); err != nil {
			p.logger.Warn("remote-delete handling failed", "key", key, "err", err)
		}
	}
}

// reconcileOne decides "no-op," "download," or "conflict + download" for
// one materialised manifest entry.
func (p *Puller) reconcileOne(ctx context.Context, remotePath string, entry *manifest.Entry, masterKey []byte, cap string) error {
	if entry.IsDir {
		// Folders are virtual — make sure the directory exists locally,
		// then move on. No content to download.
		localAbs, err := safeLocalJoin(p.cfg.LocalPath, remotePath)
		if err != nil {
			return fmt.Errorf("unsafe folder path from manifest: %w", err)
		}
		if err := os.MkdirAll(localAbs, 0o755); err != nil {
			return fmt.Errorf("mkdir folder: %w", err)
		}
		return nil
	}

	// manifest_cache stores paths WITHOUT leading slash; the manifest's
	// `path` field carries it. Normalise on lookup so the no-op fast path
	// actually fires on the second tick.
	cacheKey := stripLeadingSlash(remotePath)
	cached, err := p.cfg.State.LookupManifestEntry(ctx, cacheKey)
	if err != nil {
		return fmt.Errorf("lookup cache: %w", err)
	}
	// 99% fast path: same uuid + same content_iv ⇒ no-op.
	if cached != nil && cached.UUID == entry.UUID && cached.ContentIV == entry.ContentIV {
		return nil
	}

	localAbs, err := safeLocalJoin(p.cfg.LocalPath, remotePath)
	if err != nil {
		return fmt.Errorf("unsafe file path from manifest: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(localAbs), 0o755); err != nil {
		return fmt.Errorf("mkdir parent: %w", err)
	}

	// Conflict check: if the local mtime is ahead of what we last synced,
	// user modified locally while remote also changed → conflicting-rename.
	if cached != nil {
		if conflicted, err := p.localChangedSinceSync(localAbs, cached); err != nil {
			return fmt.Errorf("conflict check: %w", err)
		} else if conflicted {
			if err := p.conflictingRename(ctx, localAbs, remotePath); err != nil {
				return fmt.Errorf("conflicting-rename: %w", err)
			}
		}
	}

	return p.downloadAndDecrypt(ctx, entry, localAbs, masterKey, cap)
}

// downloadAndDecrypt does the work: GET objects/{uuid}, unwrap data key,
// decrypt payload, atomic-write to disk, update manifest_cache.
func (p *Puller) downloadAndDecrypt(ctx context.Context, entry *manifest.Entry, localAbs string, masterKey []byte, cap string) error {
	got, err := p.cfg.Hub.GetObject(ctx, p.cfg.BucketID, ObjectsPrefix+entry.UUID, cap)
	if err != nil {
		return fmt.Errorf("GET object: %w", err)
	}
	if got.Status == http.StatusNotFound {
		// Object missing on bucket; the manifest referred to it but it's
		// gone. Treat as a no-op this tick — next tick may see it.
		p.logger.Warn("manifest references missing object", "uuid", entry.UUID)
		return nil
	}
	if got.Status < 200 || got.Status >= 300 {
		return fmt.Errorf("GET object HTTP %d", got.Status)
	}

	// Decrypt the data key (sealed under master key, AAD = uuid).
	dataKeyIV, err := decodeB64(entry.DataKeyIV)
	if err != nil {
		return fmt.Errorf("decode data_key_iv: %w", err)
	}
	dataKeyCT, err := decodeB64(entry.DataKeyCT)
	if err != nil {
		return fmt.Errorf("decode data_key_ct: %w", err)
	}
	dataKey, err := payload.UnwrapDataKey(masterKey, dataKeyIV, dataKeyCT, entry.UUID)
	if err != nil {
		return fmt.Errorf("unwrap data key: %w", err)
	}
	defer payload.Zero(dataKey)

	// Decrypt the file payload. OpenObject dispatches v1 blob vs v2
	// chunked on entry.ChunkSize and pins the body's leading IV to the
	// manifest-signed content_iv, so a bucket-only replay of an older
	// object body for the same UUID is rejected instead of mirrored to
	// disk as stale plaintext (matches the browser's 2026-05 audit H1).
	var contentIV []byte
	if entry.ContentIV != "" {
		if contentIV, err = decodeB64(entry.ContentIV); err != nil {
			return fmt.Errorf("decode content_iv: %w", err)
		}
	}
	plain, err := payload.OpenObject(dataKey, got.Body, entry.UUID, entry.Size, contentIV, entry.ChunkSize)
	if err != nil {
		return fmt.Errorf("open object: %w", err)
	}

	// Atomic write: temp file in same dir, rename.
	tmp := localAbs + ".tmp." + newULID()
	if err := os.MkdirAll(filepath.Dir(tmp), 0o755); err != nil {
		return fmt.Errorf("mkdir tmp parent: %w", err)
	}
	if err := os.WriteFile(tmp, plain, 0o644); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, localAbs); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s → %s: %w", tmp, localAbs, err)
	}
	info, err := os.Stat(localAbs)
	if err != nil {
		return fmt.Errorf("post-write stat: %w", err)
	}

	sum := sha256.Sum256(plain)
	cached := state.ManifestEntry{
		RemotePath:   stripLeadingSlash(entry.Path),
		UUID:         entry.UUID,
		ContentIV:    entry.ContentIV,
		ETag:         entry.UUID + ":" + entry.ContentIV, // compose stable etag-equivalent
		SHA256:       hex.EncodeToString(sum[:]),
		SizeBytes:    int64(len(plain)),
		LastModified: time.UnixMilli(entry.TSUnixMs),
		LocalMtimeNS: info.ModTime().UnixNano(),
		CachedAt:     p.now().UTC(),
	}
	if err := p.cfg.State.UpsertManifestEntry(ctx, cached); err != nil {
		p.logger.Warn("manifest upsert failed (download succeeded)", "err", err)
	}
	p.downloaded.Add(1)
	p.logger.Info("downloaded",
		"path", entry.Path, "uuid", entry.UUID, "size", info.Size())
	return nil
}

// localChangedSinceSync — same logic as pre-M3.
func (p *Puller) localChangedSinceSync(localAbs string, cached *state.ManifestEntry) (bool, error) {
	info, err := os.Stat(localAbs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if info.IsDir() {
		return false, nil
	}
	return info.ModTime().UnixNano() > cached.LocalMtimeNS+p.slackNs, nil
}

func (p *Puller) conflictingRename(ctx context.Context, localAbs, remotePath string) error {
	ts := p.now().UTC().Format("2006-01-02T15-04-05")
	conflicted := localAbs + ".conflict-" + ts + ".local"
	if err := os.Rename(localAbs, conflicted); err != nil {
		return err
	}
	if err := p.cfg.State.LogConflict(ctx, state.ConflictEntry{
		ConflictID:           "c_" + newULID(),
		RemotePath:           remotePath,
		LocalPath:            localAbs,
		ConflictingLocalPath: conflicted,
		Resolution:           "conflicting-rename",
	}); err != nil {
		p.logger.Warn("LogConflict failed (rename succeeded)", "err", err)
	}
	p.conflicts.Add(1)
	p.logger.Info("conflicting-rename", "local", localAbs, "moved_to", conflicted, "remote", remotePath)
	return nil
}

// allCachedKeys returns every remote_path in manifest_cache.
func (p *Puller) allCachedKeys(ctx context.Context) ([]string, error) {
	rows, err := p.cfg.State.DB().QueryContext(ctx, `SELECT remote_path FROM manifest_cache`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		if err := rows.Scan(&k); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// handleRemoteDelete is called for every manifest_cache row whose key is
// missing from the latest manifest tree. Same semantics as pre-M3.
func (p *Puller) handleRemoteDelete(ctx context.Context, key string) error {
	cached, err := p.cfg.State.LookupManifestEntry(ctx, key)
	if err != nil {
		return fmt.Errorf("lookup: %w", err)
	}
	if cached == nil {
		return nil
	}
	localAbs, err := safeLocalJoin(p.cfg.LocalPath, key)
	if err != nil {
		return fmt.Errorf("unsafe remote-delete path: %w", err)
	}
	info, statErr := os.Stat(localAbs)
	switch {
	case errors.Is(statErr, os.ErrNotExist):
		// Local already gone.
	case statErr != nil:
		return fmt.Errorf("stat: %w", statErr)
	default:
		if info.ModTime().UnixNano() > cached.LocalMtimeNS+p.slackNs {
			if err := p.cfg.State.LogConflict(ctx, state.ConflictEntry{
				ConflictID:           "c_" + newULID(),
				RemotePath:           key,
				LocalPath:            localAbs,
				ConflictingLocalPath: localAbs,
				Resolution:           "remote-deleted-local-kept",
			}); err != nil {
				p.logger.Warn("LogConflict failed", "err", err)
			}
			p.conflicts.Add(1)
			p.logger.Info("remote deleted, local modified — keeping local",
				"key", key, "local", localAbs)
			if err := p.cfg.State.DeleteManifestEntry(ctx, key); err != nil {
				return err
			}
			return nil
		}
		if err := os.Remove(localAbs); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove local: %w", err)
		}
		p.deletedLocal.Add(1)
		p.logger.Info("removed local (remote deleted)", "key", key, "local", localAbs)
	}
	return p.cfg.State.DeleteManifestEntry(ctx, key)
}

// validateAndAdvanceAnchor checks `fresh` against the persisted rollback
// anchor (state.manifest_anchor row keyed by bucket_id). Returns
// (true, "") on accept (and writes the new anchor); returns (false, reason)
// on rejection, in which case the caller must skip the apply.
//
// First-load semantics (no anchor row): trust-on-first-use, log at info
// level, save the current state as the baseline. Subsequent loads MUST
// extend (count grows + chain matches at the anchor point) OR match
// (idempotent re-load of the same manifest). A shorter count or a
// diverging chain at the anchor point is rejected.
func (p *Puller) validateAndAdvanceAnchor(ctx context.Context, fresh *manifest.Manifest) (bool, string) {
	events := fresh.Events()
	loadedCount := len(events)
	loadedLastSig := ""
	if loadedCount > 0 {
		if s, ok := events[loadedCount-1]["sig"].(string); ok {
			loadedLastSig = s
		}
	}

	prior, err := p.cfg.State.GetManifestAnchor(ctx, p.cfg.BucketID)
	if err != nil {
		// Anchor lookup failed — fail closed: better to skip a tick than
		// silently lose the rollback protection.
		return false, fmt.Sprintf("anchor lookup failed: %v", err)
	}
	if prior == nil {
		// TOFU: first ever load on this device for this bucket.
		p.logger.Info("anchoring manifest to current state (first load)",
			"bucket_id", p.cfg.BucketID,
			"count", loadedCount)
		if werr := p.cfg.State.SetManifestAnchor(ctx, p.cfg.BucketID, state.ManifestAnchor{
			Count:   loadedCount,
			LastSig: loadedLastSig,
		}); werr != nil {
			// Don't fail the tick — the anchor write is best-effort.
			// Next tick re-TOFUs at the same or higher count.
			p.logger.Warn("anchor write failed (will retry next tick)", "err", werr)
		}
		return true, ""
	}

	if loadedCount < prior.Count {
		return false, fmt.Sprintf("truncation: loaded count %d < anchor count %d",
			loadedCount, prior.Count)
	}
	// loadedCount >= prior.Count — verify chain continuity at the anchor.
	// (If prior.Count == 0, the anchor was empty; any first event extends.)
	if prior.Count > 0 {
		anchorEvt := events[prior.Count-1]
		anchorSig, _ := anchorEvt["sig"].(string)
		if anchorSig != prior.LastSig {
			return false, fmt.Sprintf("fork: event[%d].sig differs from anchor.lastSig",
				prior.Count-1)
		}
	}
	// Advance (or keep) the anchor.
	if werr := p.cfg.State.SetManifestAnchor(ctx, p.cfg.BucketID, state.ManifestAnchor{
		Count:   loadedCount,
		LastSig: loadedLastSig,
	}); werr != nil {
		p.logger.Warn("anchor advance failed (will retry next tick)", "err", werr)
	}
	return true, ""
}

// --- helpers --------------------------------------------------------------

// readCapability reads the current capability under the shared
// RWMutex when wired. The refresh runner holds the write side.
func (p *Puller) readCapability() string {
	if p.cfg.CapabilityMu == nil {
		return *p.cfg.CapabilityRef
	}
	p.cfg.CapabilityMu.RLock()
	defer p.cfg.CapabilityMu.RUnlock()
	return *p.cfg.CapabilityRef
}

func stripLeadingSlash(s string) string {
	if len(s) > 0 && s[0] == '/' {
		return s[1:]
	}
	return s
}

// safeLocalJoin resolves a manifest path to an absolute on-disk path
// guaranteed to live under root. Rejects:
//   - absolute paths inside the manifest entry (e.g. "/etc/passwd")
//   - any path containing ".." after normalisation
//   - any final path that escapes root via symlinks (caught by EvalSymlinks
//     of the parent dir; the file itself need not exist)
//   - empty paths
//
// A malicious transport that serves a manifest with path
// "../../.ssh/authorized_keys" would otherwise let the daemon write
// outside ~/crate/. This is the only chokepoint between an attacker
// who controls the manifest and arbitrary file writes on the user's
// disk, so the check fails closed on any ambiguity.
func safeLocalJoin(root, manifestPath string) (string, error) {
	if manifestPath == "" {
		return "", fmt.Errorf("manifest path is empty")
	}
	clean := stripLeadingSlash(manifestPath)
	if clean == "" {
		return "", fmt.Errorf("manifest path resolves to empty")
	}
	// Reject "..", ".", and any segment that escapes via path-clean
	// rewriting. We do this on the slash-form before converting to OS
	// separators so Windows paths don't smuggle ".." past us.
	if strings.HasPrefix(clean, "/") || strings.Contains(clean, `\`) {
		return "", fmt.Errorf("manifest path must be a relative slash-path: %q", manifestPath)
	}
	for _, seg := range strings.Split(clean, "/") {
		if seg == ".." || seg == "." || seg == "" {
			return "", fmt.Errorf("manifest path has unsafe segment %q in %q", seg, manifestPath)
		}
	}

	joined := filepath.Join(root, filepath.FromSlash(clean))
	// Re-clean and verify the result is still under root. filepath.Join
	// already runs Clean, but we verify the prefix explicitly so a future
	// refactor doesn't silently break this.
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve root: %w", err)
	}
	absJoined, err := filepath.Abs(joined)
	if err != nil {
		return "", fmt.Errorf("resolve joined: %w", err)
	}
	// Use Rel + check for "..\..\" prefix to be cross-platform-safe.
	rel, err := filepath.Rel(absRoot, absJoined)
	if err != nil {
		return "", fmt.Errorf("rel check: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("manifest path escapes root: %q", manifestPath)
	}
	return absJoined, nil
}

func decodeB64(s string) ([]byte, error) {
	// Manifest writes base64-std; tolerate URL-safe on read for forward-compat.
	b, err := stdB64Decode(s)
	if err == nil {
		return b, nil
	}
	return urlB64Decode(s)
}

func newULID() string {
	id, err := ulid.New(ulid.Now(), rand.Reader)
	if err != nil {
		return time.Now().UTC().Format("20060102T150405.000000000Z")
	}
	return id.String()
}

// Local b64 helpers — avoid importing encoding/base64 twice with different
// names; keep callers honest.
func stdB64Decode(s string) ([]byte, error) { return b64.StdEncoding.DecodeString(s) }
func urlB64Decode(s string) ([]byte, error) { return b64.RawURLEncoding.DecodeString(s) }
