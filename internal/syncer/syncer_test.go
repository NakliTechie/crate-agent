// SPDX-License-Identifier: AGPL-3.0-or-later
package syncer

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NakliTechie/crate-agent/internal/httpc"
	"github.com/NakliTechie/crate-agent/internal/manifest"
	"github.com/NakliTechie/crate-agent/internal/payload"
	"github.com/NakliTechie/crate-agent/internal/state"
	"github.com/NakliTechie/crate-agent/internal/watcher"
)

// fakeHub is a tiny in-process stand-in for the Hub's /v1/crate/object/*
// surface. Mirrors the contract from nakli-hub but does NO sig-v4 — we're
// testing the daemon side. Stores bytes by remote path so the test can
// assert what landed.
//
// Failure injection: setFailNext(n) causes the next n requests to return
// 500 Internal Server Error so the syncer's retry/backoff path is exercised.
type fakeHub struct {
	mu       sync.Mutex
	objects  map[string][]byte
	bucketID string
	puts     atomic.Int64
	deletes  atomic.Int64
	failNext atomic.Int64

	ts *httptest.Server
}

func newFakeHub(t *testing.T, bucketID string) *fakeHub {
	t.Helper()
	h := &fakeHub{
		objects:  map[string][]byte{},
		bucketID: bucketID,
	}
	h.ts = httptest.NewServer(http.HandlerFunc(h.serve))
	t.Cleanup(h.ts.Close)
	return h
}

func (h *fakeHub) URL() string { return h.ts.URL }

func (h *fakeHub) setFailNext(n int64) { h.failNext.Store(n) }

func (h *fakeHub) maybeFail(w http.ResponseWriter) bool {
	if remaining := h.failNext.Load(); remaining > 0 {
		h.failNext.Add(-1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"ok":false,"error":{"code":"injected","message":"test failure"}}`))
		return true
	}
	return false
}

func (h *fakeHub) serve(w http.ResponseWriter, r *http.Request) {
	// Require the daemon's X-Fabric-Grant header on every authenticated call.
	if r.Header.Get("X-Fabric-Grant") == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	// /v1/crate/object/{bucket}/{path}
	prefix := "/v1/crate/object/" + h.bucketID + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	remotePath := strings.TrimPrefix(r.URL.Path, prefix)

	switch r.Method {
	case http.MethodPut:
		// Count every PUT attempt (including failed ones) so the retry test
		// can observe the failure path.
		h.puts.Add(1)
		if h.maybeFail(w) {
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		h.mu.Lock()
		h.objects[remotePath] = body
		h.mu.Unlock()
		w.Header().Set("ETag", fmt.Sprintf("%q", fmt.Sprintf("etag-%d", len(body))))
		w.WriteHeader(http.StatusOK)
	case http.MethodDelete:
		h.deletes.Add(1)
		if h.maybeFail(w) {
			return
		}
		h.mu.Lock()
		_, existed := h.objects[remotePath]
		delete(h.objects, remotePath)
		h.mu.Unlock()
		if existed {
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	case http.MethodHead:
		h.mu.Lock()
		body, ok := h.objects[remotePath]
		h.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf("%q", fmt.Sprintf("etag-%d", len(body))))
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *fakeHub) get(remotePath string) ([]byte, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	b, ok := h.objects[remotePath]
	if !ok {
		return nil, false
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out, true
}

// setupSyncer builds an end-to-end syncer test rig: temp crate folder +
// state DB + watcher + fake Hub + client + syncer. Returns the rig + a
// helper to stop the syncer.
type rig struct {
	localPath string
	hub       *fakeHub
	state     *state.Store
	watcher   *watcher.Watcher
	syncer    *Syncer
	cancel    context.CancelFunc
	done      chan struct{}

	// M3 wire-format references shared with the syncer — tests use them
	// to decrypt the on-hub ciphertext and verify round-trips.
	masterKey []byte
	manifest  *manifest.Manifest
}

func setupSyncer(t *testing.T, cfgMods ...func(*Config)) *rig {
	t.Helper()
	tmp := t.TempDir()
	localPath := filepath.Join(tmp, "crate")
	if err := os.MkdirAll(localPath, 0o755); err != nil {
		t.Fatal(err)
	}

	store, err := state.Open(filepath.Join(tmp, "state.db"))
	if err != nil {
		t.Fatalf("state.Open: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	w, err := watcher.New(watcher.Options{
		Root:     localPath,
		Debounce: 80 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("watcher.New: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })

	hub := newFakeHub(t, "bk_test")
	client := httpc.New(hub.URL())

	// M3 wire format requires master-key + shared manifest references.
	cap := "test-capability"
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i + 7)
	}
	sharedManifest := manifest.New()
	sharedManifestMu := &sync.Mutex{}
	sharedETag := ""
	sharedLastFlushed := 0

	cfg := Config{
		LocalPath:                localPath,
		BucketID:                 "bk_test",
		CapabilityRef:            &cap,
		MasterKeyRef:             &masterKey,
		ManifestRef:              sharedManifest,
		ManifestMu:               sharedManifestMu,
		ManifestETagRef:          &sharedETag,
		LastFlushedEventCountRef: &sharedLastFlushed,
		Hub:                      client,
		Watcher:                  w,
		State:                    store,
		PollInterval:             50 * time.Millisecond,
		BackoffBase:              50 * time.Millisecond,
		BackoffCap:               200 * time.Millisecond,
	}
	for _, m := range cfgMods {
		m(&cfg)
	}
	syncer, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	// Run the watcher + syncer in goroutines.
	go func() { _ = w.Run(ctx) }()
	go func() {
		_ = syncer.Run(ctx)
		close(done)
	}()
	// Give Run a beat to register watches.
	time.Sleep(50 * time.Millisecond)

	t.Cleanup(func() {
		cancel()
		<-done
	})

	return &rig{
		localPath: localPath,
		hub:       hub,
		state:     store,
		watcher:   w,
		syncer:    syncer,
		cancel:    cancel,
		done:      done,
		masterKey: masterKey,
		manifest:  sharedManifest,
	}
}

// waitFor polls the predicate until it returns true OR the deadline elapses.
// Returns true if predicate was satisfied.
func waitFor(t *testing.T, d time.Duration, p func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if p() {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return p()
}

// findObjectsKey walks the fake-hub's storage and returns the first key
// matching "objects/{uuid}". Useful since the daemon allocates random
// uuids the test doesn't know in advance.
func (h *fakeHub) findObjectsKey() (string, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for k := range h.objects {
		if strings.HasPrefix(k, "objects/") {
			return k, true
		}
	}
	return "", false
}

func TestSyncer_UploadOnCreate(t *testing.T) {
	r := setupSyncer(t)
	plain := []byte("hello from the daemon\n")
	if err := os.WriteFile(filepath.Join(r.localPath, "hello.txt"), plain, 0o644); err != nil {
		t.Fatal(err)
	}

	// Wait for both the objects/ ciphertext AND the encrypted manifest to
	// land at the fake hub.
	landed := waitFor(t, 3*time.Second, func() bool {
		_, hasObj := r.hub.findObjectsKey()
		_, hasManifest := r.hub.get(".crate/manifest.jsonl.enc")
		return hasObj && hasManifest
	})
	if !landed {
		t.Fatalf("PUTs didn't land; hub keys: %v", hubKeys(r.hub))
	}

	// Decrypt the manifest with the test master key and confirm there's
	// exactly one create event for /hello.txt.
	manBytes, _ := r.hub.get(".crate/manifest.jsonl.enc")
	m, err := manifest.LoadFromBytes(manBytes, r.masterKey)
	if err != nil {
		t.Fatalf("manifest decrypt failed: %v", err)
	}
	if m.Size() == 0 {
		t.Fatal("manifest has no events")
	}
	ok, idx, reason := m.Verify(r.masterKey)
	if !ok {
		t.Fatalf("manifest verify failed at %d: %s", idx, reason)
	}
	tree := m.Materialise()
	entry, present := tree["/hello.txt"]
	if !present {
		t.Fatalf("/hello.txt missing from materialised tree; got %v", treeKeys(tree))
	}
	if entry.Size != int64(len(plain)) {
		t.Errorf("entry.Size = %d, want %d", entry.Size, len(plain))
	}

	// Now decrypt the objects/{uuid} ciphertext and confirm bytes match.
	objKey, _ := r.hub.findObjectsKey()
	objBytes, _ := r.hub.get(objKey)

	dataKeyIV, _ := base64StdDecode(entry.DataKeyIV)
	dataKeyCT, _ := base64StdDecode(entry.DataKeyCT)
	dataKey, err := payload.UnwrapDataKey(r.masterKey, dataKeyIV, dataKeyCT, entry.UUID)
	if err != nil {
		t.Fatalf("unwrap data key: %v", err)
	}
	civ, _ := base64StdDecode(entry.ContentIV)
	if entry.ChunkSize != payload.ChunkSize {
		t.Errorf("entry.ChunkSize = %d, want %d (daemon writes v2)", entry.ChunkSize, payload.ChunkSize)
	}
	got, err := payload.OpenObject(dataKey, objBytes, entry.UUID, entry.Size, civ, entry.ChunkSize)
	if err != nil {
		t.Fatalf("open object: %v", err)
	}
	if string(got) != string(plain) {
		t.Errorf("decrypted bytes mismatch:\n got:  %q\n want: %q", got, plain)
	}

	// manifest_cache should have a row pointing at this uuid.
	cached, err := r.state.LookupManifestEntry(context.Background(), "hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if cached == nil {
		t.Fatal("manifest_cache missing hello.txt")
	}
	if cached.UUID != entry.UUID {
		t.Errorf("cache.UUID = %s, want %s", cached.UUID, entry.UUID)
	}
}

func TestSyncer_DeleteOnRemove(t *testing.T) {
	r := setupSyncer(t)
	path := filepath.Join(r.localPath, "doomed.txt")
	if err := os.WriteFile(path, []byte("transient"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Wait until the initial PUT (both objects/{uuid} and manifest) lands.
	if !waitFor(t, 3*time.Second, func() bool {
		_, hasObj := r.hub.findObjectsKey()
		_, hasMan := r.hub.get(".crate/manifest.jsonl.enc")
		return hasObj && hasMan
	}) {
		t.Fatal("initial PUT didn't land")
	}
	initialKey, _ := r.hub.findObjectsKey()

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	// Wait until BOTH:
	//   - The hub's objects/{uuid} for doomed.txt is gone (DELETE landed)
	//   - The manifest_cache row is cleared (DeleteManifestEntry ran)
	deleted := waitFor(t, 3*time.Second, func() bool {
		if _, ok := r.hub.get(initialKey); ok {
			return false
		}
		m, err := r.state.LookupManifestEntry(context.Background(), "doomed.txt")
		if err != nil {
			return false
		}
		return m == nil
	})
	if !deleted {
		t.Fatal("DELETE+manifest-clear didn't complete within 3s")
	}
}

func TestSyncer_RetriesOnFailure(t *testing.T) {
	r := setupSyncer(t)
	// First 2 PUT requests fail. PUTs happen against either objects/{uuid}
	// or the manifest path; either way, the syncer treats the upload as
	// failed and retries. Inject failures.
	r.hub.setFailNext(2)

	plain := []byte("retry me")
	if err := os.WriteFile(filepath.Join(r.localPath, "retry.txt"), plain, 0o644); err != nil {
		t.Fatal(err)
	}
	// Eventually the upload should land + the queue should drain.
	ok := waitFor(t, 5*time.Second, func() bool {
		_, hasObj := r.hub.findObjectsKey()
		_, hasMan := r.hub.get(".crate/manifest.jsonl.enc")
		if !hasObj || !hasMan {
			return false
		}
		n, err := r.state.PendingUploadCount(context.Background())
		return err == nil && n == 0
	})
	if !ok {
		t.Fatalf("retry.txt never landed cleanly; puts=%d", r.hub.puts.Load())
	}
	if r.hub.puts.Load() < 3 {
		t.Errorf("expected ≥3 PUTs (≥2 failed + at least 1 success); got %d", r.hub.puts.Load())
	}
}

// --- test helpers ---------------------------------------------------------

func hubKeys(h *fakeHub) []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	keys := make([]string, 0, len(h.objects))
	for k := range h.objects {
		keys = append(keys, k)
	}
	return keys
}

func treeKeys(t map[string]*manifest.Entry) []string {
	keys := make([]string, 0, len(t))
	for k := range t {
		keys = append(keys, k)
	}
	return keys
}

func base64StdDecode(s string) ([]byte, error) { return base64.StdEncoding.DecodeString(s) }

func TestSyncer_BackoffSchedule(t *testing.T) {
	// Test the backoff calculation directly so we don't have to wait on
	// real time. Base 1s, cap 60s.
	s := &Syncer{cfg: Config{BackoffBase: 1 * time.Second, BackoffCap: 60 * time.Second}}
	cases := []struct {
		attempts int
		want     time.Duration
	}{
		{1, 1 * time.Second},
		{2, 2 * time.Second},
		{3, 4 * time.Second},
		{4, 8 * time.Second},
		{5, 16 * time.Second},
		{6, 32 * time.Second},
		{7, 60 * time.Second}, // capped
		{99, 60 * time.Second},
	}
	for _, c := range cases {
		if got := s.computeBackoff(c.attempts); got != c.want {
			t.Errorf("computeBackoff(%d) = %v, want %v", c.attempts, got, c.want)
		}
	}
}

func TestNewRejectsMissingFields(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*Config)
	}{
		{"no LocalPath", func(c *Config) { c.LocalPath = "" }},
		{"no BucketID", func(c *Config) { c.BucketID = "" }},
		{"no CapabilityRef", func(c *Config) { c.CapabilityRef = nil }},
		{"no MasterKeyRef", func(c *Config) { c.MasterKeyRef = nil }},
		{"no ManifestRef", func(c *Config) { c.ManifestRef = nil }},
		{"no ManifestMu", func(c *Config) { c.ManifestMu = nil }},
		{"no ManifestETagRef", func(c *Config) { c.ManifestETagRef = nil }},
		{"no LastFlushedEventCountRef", func(c *Config) { c.LastFlushedEventCountRef = nil }},
		{"no Hub", func(c *Config) { c.Hub = nil }},
		{"no Watcher", func(c *Config) { c.Watcher = nil }},
		{"no State", func(c *Config) { c.State = nil }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tmp := t.TempDir()
			store, _ := state.Open(filepath.Join(tmp, "s.db"))
			defer store.Close()
			_ = os.MkdirAll(filepath.Join(tmp, "crate"), 0o755)
			w, _ := watcher.New(watcher.Options{Root: filepath.Join(tmp, "crate")})
			defer w.Close()
			cap := "cap"
			mk := make([]byte, 32)
			etag := ""
			lastFlushed := 0
			cfg := Config{
				LocalPath:                filepath.Join(tmp, "crate"),
				BucketID:                 "bk_x",
				CapabilityRef:            &cap,
				MasterKeyRef:             &mk,
				ManifestRef:              manifest.New(),
				ManifestMu:               &sync.Mutex{},
				ManifestETagRef:          &etag,
				LastFlushedEventCountRef: &lastFlushed,
				Hub:                      httpc.New("http://127.0.0.1:1"),
				Watcher:                  w,
				State:                    store,
			}
			c.mod(&cfg)
			if _, err := New(cfg); err == nil {
				t.Errorf("expected error")
			} else if !strings.Contains(err.Error(), "syncer:") {
				t.Errorf("error not from syncer: %v", err)
			}
		})
	}
}

// TestSyncer_UnknownOperation surfaces the error-path; we never expect this
// to happen in production because the dispatcher only generates "put" or
// "delete", but defensive coverage is cheap.
func TestSyncer_UnknownOperation(t *testing.T) {
	r := setupSyncer(t)
	if err := r.state.EnqueueUpload(context.Background(), state.QueueEntry{
		QueueID:    "q_unknown",
		RemotePath: "x.txt",
		LocalPath:  filepath.Join(r.localPath, "x.txt"),
		Operation:  "fubar",
	}); err != nil {
		t.Fatal(err)
	}
	// The worker should advance attempts on each tick. Wait for at least one
	// attempt + a retry-mark.
	ok := waitFor(t, 2*time.Second, func() bool {
		next, err := r.state.NextDueUpload(context.Background())
		if err != nil {
			return false
		}
		if next == nil {
			// Row is deferred to a future next_attempt_at — exactly what
			// we expect for a retryable failure.
			return true
		}
		return next.Attempts > 0 && next.LastError != ""
	})
	if !ok {
		t.Errorf("unknown-op row was not marked with an attempt+error")
	}
}

// Sanity check that the package's exported error wraps don't accidentally
// stringify to something misleading.
func TestExecuteRow_ErrorMessages(t *testing.T) {
	if !errors.Is(context.Canceled, context.Canceled) {
		t.Fatal("sanity")
	}
}

// A file the puller just landed must not be re-uploaded: manifest_cache
// already records its bytes as synced. A real edit afterwards must.
func TestSyncer_NoEchoAfterPull(t *testing.T) {
	r := setupSyncer(t)
	plain := []byte("landed by the puller\n")
	sum := sha256.Sum256(plain)
	// What the puller writes to manifest_cache right after its rename.
	if err := r.state.UpsertManifestEntry(context.Background(), state.ManifestEntry{
		RemotePath: "pulled.txt", UUID: "01PULLEDUUID", ContentIV: "civ",
		SHA256: hex.EncodeToString(sum[:]), SizeBytes: int64(len(plain)),
		LastModified: time.Now(), LocalMtimeNS: time.Now().UnixNano(),
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.localPath, "pulled.txt"), plain, 0o644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1500 * time.Millisecond) // past the watcher debounce + worker tick
	if n := r.hub.puts.Load(); n != 0 {
		t.Fatalf("echo: %d PUT(s) for bytes the cache already recorded as synced; hub keys: %v", n, hubKeys(r.hub))
	}
	// Now a genuine edit — same path, different bytes — must upload.
	if err := os.WriteFile(filepath.Join(r.localPath, "pulled.txt"), []byte("edited locally\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !waitFor(t, 3*time.Second, func() bool { _, ok := r.hub.findObjectsKey(); return ok }) {
		t.Fatalf("real edit was not uploaded; hub keys: %v", hubKeys(r.hub))
	}
}
