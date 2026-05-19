// SPDX-License-Identifier: AGPL-3.0-or-later
// Package puller implements the pull side of crate-agent's sync loop.
// It periodically LISTs the bucket via the Hub bucket-proxy and reconciles
// remote state into the local folder:
//
//   - Remote object missing locally  → download
//   - Remote ETag differs from cache → download (unless local was modified
//                                       since last sync → conflict-rename)
//   - Locally-tracked path NOT in latest LIST → remote deletion; remove
//                                       the local file (unless modified
//                                       locally since last sync → conflict)
//
// Conflict resolution (Dropbox-style): the cloud version is canonical at
// the original path; the divergent local copy is renamed to
// `<file>.conflict-<rfc3339>.local`. A row is appended to conflict_log
// and surfaced in `crate-agent status`. Never silently destroys work.
//
// Push-side echo suppression: when the syncer just PUT a file, that file
// will show up in the next LIST with a matching ETag. The puller compares
// ETag-vs-manifest_cache so it correctly identifies "no change needed."
// No special-case echo logic is required.
package puller

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/NakliTechie/crate-agent/internal/cratejson"
	"github.com/NakliTechie/crate-agent/internal/httpc"
	"github.com/NakliTechie/crate-agent/internal/state"
)

// DefaultPollInterval is how often the puller LISTs the bucket. 15s is the
// balance the M3 plan landed on: tight enough that a change made elsewhere
// shows up within a minute; loose enough not to thrash the bucket-proxy.
const DefaultPollInterval = 15 * time.Second

// Config configures a Puller. CapabilityRef is shared with the syncer +
// refresh runner so all three see the same capability after a refresh.
type Config struct {
	LocalPath string
	BucketID  string

	// CapabilityRef is a pointer the puller dereferences on each LIST so it
	// always uses the freshest capability (the refresh runner mutates the
	// pointee in place). Caller is responsible for the pointer's lifetime.
	CapabilityRef *string

	Hub   *httpc.Client
	State *state.Store

	PollInterval time.Duration
	Logger       *slog.Logger
	Now          func() time.Time

	// LastSyncSlackNs is the "treat local mtime as ahead of cache by this
	// many ns or less" tolerance. Default: 1 second. Filesystems have
	// quantised mtimes (HFS+ has 1s resolution; ext4 ns; APFS ns) and we
	// don't want false-positive conflicts from sub-second jitter when the
	// daemon's own PUT path raced with a touch.
	LastSyncSlackNs int64
}

// Puller drives the periodic LIST + reconciliation loop.
type Puller struct {
	cfg          Config
	logger       *slog.Logger
	now          func() time.Time
	pollInterval time.Duration
	slackNs      int64

	// Stats for `status` visibility (atomic).
	listCalls   atomic.Int64
	downloaded  atomic.Int64
	conflicts   atomic.Int64
	deletedLocal atomic.Int64
}

// New validates Config and returns a Puller.
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

// Run polls until ctx is cancelled. Each tick: LIST the bucket, reconcile
// each entry, then check tombstones (locally-tracked paths NOT in the LIST
// result). Errors are logged but don't crash the loop — the next tick retries.
func (p *Puller) Run(ctx context.Context) {
	tick := time.NewTicker(p.pollInterval)
	defer tick.Stop()
	// Fire once immediately so a freshly-started daemon converges before
	// the first poll interval elapses.
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

// Stats returns counters useful for `status`.
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

func (p *Puller) tick(ctx context.Context) {
	remote, err := p.listAll(ctx)
	if err != nil {
		p.logger.Warn("LIST failed; will retry", "err", err)
		return
	}
	p.listCalls.Add(1)

	// Build a set for tombstone detection.
	seen := make(map[string]struct{}, len(remote))
	for _, e := range remote {
		seen[e.Key] = struct{}{}
		// Skip the metadata blob — that's the browser's territory.
		if e.Key == cratejson.CratePath {
			continue
		}
		if err := p.reconcileOne(ctx, e); err != nil {
			p.logger.Warn("reconcile failed",
				"key", e.Key, "err", err)
		}
	}

	// Tombstone pass: any manifest_cache row NOT in `seen` means the remote
	// has deleted that key.
	allCached, err := p.allCachedKeys(ctx)
	if err != nil {
		p.logger.Warn("walk manifest_cache failed", "err", err)
		return
	}
	for _, key := range allCached {
		if _, present := seen[key]; present {
			continue
		}
		if err := p.handleRemoteDelete(ctx, key); err != nil {
			p.logger.Warn("remote-delete handling failed",
				"key", key, "err", err)
		}
	}
}

// listAll walks the full LIST result via continuation_token pagination.
func (p *Puller) listAll(ctx context.Context) ([]listEntry, error) {
	var out []listEntry
	cap := *p.cfg.CapabilityRef
	if cap == "" {
		return nil, errors.New("CapabilityRef is empty (daemon not ready)")
	}
	continuation := ""
	for {
		resp, err := p.cfg.Hub.ListObjects(ctx, p.cfg.BucketID, "", continuation, cap)
		if err != nil {
			return nil, fmt.Errorf("LIST: %w", err)
		}
		if resp.Status < 200 || resp.Status >= 300 {
			return nil, fmt.Errorf("LIST: HTTP %d", resp.Status)
		}
		parsed, err := parseListXML(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("LIST: parse: %w", err)
		}
		out = append(out, parsed.Contents...)
		if !parsed.IsTruncated || parsed.NextContinuationToken == "" {
			return out, nil
		}
		continuation = parsed.NextContinuationToken
	}
}

// allCachedKeys returns every remote_path in manifest_cache. Used for
// tombstone detection.
func (p *Puller) allCachedKeys(ctx context.Context) ([]string, error) {
	rows, err := p.cfg.State.DB().QueryContext(ctx,
		`SELECT remote_path FROM manifest_cache`)
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

// reconcileOne processes one remote entry: deciding "no-op," "download,"
// or "conflict + download."
func (p *Puller) reconcileOne(ctx context.Context, e listEntry) error {
	cached, err := p.cfg.State.LookupManifestEntry(ctx, e.Key)
	if err != nil {
		return fmt.Errorf("lookup cache: %w", err)
	}
	// Cache hit + ETag match ⇒ nothing to do. This is the steady-state
	// 99%+ path; the puller spends most of its time in this branch.
	if cached != nil && cached.ETag == e.ETag {
		return nil
	}

	// Need to download. First check for a conflict: is the local file
	// modified since the last sync? If so, the user changed it locally
	// while the remote also changed → conflicting-rename before download.
	localAbs := filepath.Join(p.cfg.LocalPath, filepath.FromSlash(e.Key))
	if err := os.MkdirAll(filepath.Dir(localAbs), 0o700); err != nil {
		return fmt.Errorf("mkdir parent: %w", err)
	}
	if cached != nil {
		if conflicted, err := p.localChangedSinceSync(localAbs, cached); err != nil {
			return fmt.Errorf("conflict check: %w", err)
		} else if conflicted {
			if err := p.conflictingRename(ctx, localAbs, e.Key); err != nil {
				return fmt.Errorf("conflicting-rename: %w", err)
			}
		}
	}

	return p.downloadTo(ctx, e, localAbs)
}

// localChangedSinceSync returns true if the local file's mtime is newer
// than the cached LocalMtimeNS by more than slackNs.
func (p *Puller) localChangedSinceSync(localAbs string, cached *state.ManifestEntry) (bool, error) {
	info, err := os.Stat(localAbs)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Local already gone — no conflict, just download.
			return false, nil
		}
		return false, err
	}
	if info.IsDir() {
		// Defensive: don't conflict-rename a directory.
		return false, nil
	}
	return info.ModTime().UnixNano() > cached.LocalMtimeNS+p.slackNs, nil
}

// conflictingRename moves localAbs aside to <localAbs>.conflict-<rfc3339>.local
// and logs the move to conflict_log.
func (p *Puller) conflictingRename(ctx context.Context, localAbs, remotePath string) error {
	ts := p.now().UTC().Format("2006-01-02T15-04-05")
	conflicted := localAbs + ".conflict-" + ts + ".local"
	if err := os.Rename(localAbs, conflicted); err != nil {
		return err
	}
	conflictID := "c_" + newULID()
	if err := p.cfg.State.LogConflict(ctx, state.ConflictEntry{
		ConflictID:           conflictID,
		RemotePath:           remotePath,
		LocalPath:            localAbs,
		ConflictingLocalPath: conflicted,
		Resolution:           "conflicting-rename",
	}); err != nil {
		// Best-effort: the rename succeeded; don't fail the whole op.
		p.logger.Warn("LogConflict failed (rename succeeded)",
			"local", conflicted, "err", err)
	}
	p.conflicts.Add(1)
	p.logger.Info("conflicting-rename",
		"local", localAbs, "moved_to", conflicted, "remote", remotePath)
	return nil
}

// downloadTo streams the remote object to localAbs via temp+rename, updates
// manifest_cache on success.
func (p *Puller) downloadTo(ctx context.Context, e listEntry, localAbs string) error {
	resp, err := p.cfg.Hub.GetObject(ctx, p.cfg.BucketID, e.Key, *p.cfg.CapabilityRef)
	if err != nil {
		return fmt.Errorf("GET: %w", err)
	}
	if resp.Status == http.StatusNotFound {
		// Object disappeared between LIST and GET — treat as a tombstone
		// the next tick will pick up. No action this round.
		return nil
	}
	if resp.Status < 200 || resp.Status >= 300 {
		return fmt.Errorf("GET HTTP %d", resp.Status)
	}

	// Atomic write: temp file in same dir, fsync, rename.
	tmp := localAbs + ".tmp." + newULID()
	if err := os.MkdirAll(filepath.Dir(tmp), 0o700); err != nil {
		return fmt.Errorf("mkdir tmp parent: %w", err)
	}
	if err := os.WriteFile(tmp, resp.Body, 0o644); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	// fsync the tmp file to make the rename durable.
	if f, err := os.OpenFile(tmp, os.O_RDONLY, 0); err == nil {
		_ = f.Sync()
		_ = f.Close()
	}
	if err := os.Rename(tmp, localAbs); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s → %s: %w", tmp, localAbs, err)
	}
	info, err := os.Stat(localAbs)
	if err != nil {
		return fmt.Errorf("post-write stat: %w", err)
	}

	// Update manifest_cache. SHA256 we computed from the downloaded bytes
	// for cheap; the next push won't need to recompute.
	sum := sha256.Sum256(resp.Body)
	if err := p.cfg.State.UpsertManifestEntry(ctx, state.ManifestEntry{
		RemotePath:   e.Key,
		ETag:         e.ETag,
		SHA256:       hex.EncodeToString(sum[:]),
		SizeBytes:    int64(len(resp.Body)),
		LastModified: parseLastModified(e.LastModified),
		LocalMtimeNS: info.ModTime().UnixNano(),
		CachedAt:     p.now().UTC(),
	}); err != nil {
		// Worst case: we downloaded the file but didn't record the row.
		// Next tick re-downloads (idempotent). Don't fail.
		p.logger.Warn("manifest upsert failed (download succeeded)", "err", err)
	}
	p.downloaded.Add(1)
	p.logger.Info("downloaded", "rel", e.Key, "size", info.Size(), "etag", e.ETag)
	return nil
}

// handleRemoteDelete is called for every manifest_cache row whose key is
// missing from the latest LIST result. Removes the local file unless it
// was modified since last sync (in which case we keep the local copy and
// log a conflict).
func (p *Puller) handleRemoteDelete(ctx context.Context, key string) error {
	cached, err := p.cfg.State.LookupManifestEntry(ctx, key)
	if err != nil {
		return fmt.Errorf("lookup: %w", err)
	}
	if cached == nil {
		return nil // race: row deleted between query + this lookup
	}
	localAbs := filepath.Join(p.cfg.LocalPath, filepath.FromSlash(key))
	info, statErr := os.Stat(localAbs)
	switch {
	case errors.Is(statErr, os.ErrNotExist):
		// Local already gone — just clear the cache row.
	case statErr != nil:
		return fmt.Errorf("stat: %w", statErr)
	default:
		// Local file exists. Conflict if user modified it since last sync.
		if info.ModTime().UnixNano() > cached.LocalMtimeNS+p.slackNs {
			conflictID := "c_" + newULID()
			if err := p.cfg.State.LogConflict(ctx, state.ConflictEntry{
				ConflictID:           conflictID,
				RemotePath:           key,
				LocalPath:            localAbs,
				ConflictingLocalPath: localAbs, // local kept in place
				Resolution:           "remote-deleted-local-kept",
			}); err != nil {
				p.logger.Warn("LogConflict failed", "err", err)
			}
			p.conflicts.Add(1)
			p.logger.Info("remote deleted, local modified — keeping local",
				"key", key, "local", localAbs)
			// Clear the cache row so the next push reuploads the local file
			// (the user's intent).
			if err := p.cfg.State.DeleteManifestEntry(ctx, key); err != nil {
				return err
			}
			return nil
		}
		// Local unchanged since last sync ⇒ honour the remote delete.
		if err := os.Remove(localAbs); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove local: %w", err)
		}
		p.deletedLocal.Add(1)
		p.logger.Info("removed local (remote deleted)", "key", key, "local", localAbs)
	}

	return p.cfg.State.DeleteManifestEntry(ctx, key)
}

// --- LIST XML parsing -------------------------------------------------------

type listResult struct {
	XMLName               xml.Name    `xml:"ListBucketResult"`
	IsTruncated           bool        `xml:"IsTruncated"`
	Contents              []listEntry `xml:"Contents"`
	NextContinuationToken string      `xml:"NextContinuationToken"`
}

type listEntry struct {
	Key          string `xml:"Key"`
	Size         int64  `xml:"Size"`
	ETag         string `xml:"ETag"`
	LastModified string `xml:"LastModified"`
}

func parseListXML(b []byte) (*listResult, error) {
	if len(b) == 0 {
		return nil, errors.New("empty body")
	}
	var r listResult
	if err := xml.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	// S3 returns ETag wrapped in quotes ("etag-abc"). Strip for comparison.
	for i := range r.Contents {
		r.Contents[i].ETag = strings.Trim(r.Contents[i].ETag, `"`)
	}
	return &r, nil
}

// parseLastModified parses S3's ISO-8601 timestamp. Returns zero time on
// any parse error (callers don't crash on bad LastModified — it's a hint,
// not a primary key).
func parseLastModified(s string) time.Time {
	for _, fmt := range []string{
		time.RFC3339,
		time.RFC3339Nano,
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
	} {
		if t, err := time.Parse(fmt, s); err == nil {
			return t
		}
	}
	return time.Time{}
}

// newULID returns a fresh lexicographic id. Used for conflict_id +
// download temp-file suffixes.
func newULID() string {
	id, err := ulid.New(ulid.Now(), rand.Reader)
	if err != nil {
		return time.Now().UTC().Format("20060102T150405.000000000Z")
	}
	return id.String()
}
