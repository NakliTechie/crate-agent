// SPDX-License-Identifier: AGPL-3.0-or-later
// M3 puller tests — exercises the manifest-as-source-of-truth reconcile
// path. The fake hub serves an encrypted manifest + objects/{uuid}
// payloads; the puller GETs both, decrypts, and writes plaintext to disk.
package puller

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NakliTechie/crate-agent/internal/httpc"
	"github.com/NakliTechie/crate-agent/internal/manifest"
	"github.com/NakliTechie/crate-agent/internal/payload"
	"github.com/NakliTechie/crate-agent/internal/state"
)

// --- fake hub for M3 ------------------------------------------------------

type fakeHub struct {
	mu       sync.Mutex
	objects  map[string][]byte
	bucketID string
	ts       *httptest.Server
}

func newFakeHub(t *testing.T, bucketID string) *fakeHub {
	t.Helper()
	h := &fakeHub{objects: map[string][]byte{}, bucketID: bucketID}
	h.ts = httptest.NewServer(http.HandlerFunc(h.serve))
	t.Cleanup(h.ts.Close)
	return h
}

func (h *fakeHub) put(key string, body []byte) {
	h.mu.Lock()
	h.objects[key] = append([]byte(nil), body...)
	h.mu.Unlock()
}

func (h *fakeHub) del(key string) {
	h.mu.Lock()
	delete(h.objects, key)
	h.mu.Unlock()
}

func (h *fakeHub) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Fabric-Grant") == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	prefix := "/v1/crate/object/" + h.bucketID + "/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	key := strings.TrimPrefix(r.URL.Path, prefix)
	switch r.Method {
	case http.MethodGet:
		h.mu.Lock()
		body, ok := h.objects[key]
		h.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("ETag", fmt.Sprintf("%q", fmt.Sprintf("etag-%d", len(body))))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// --- rig -----------------------------------------------------------------

type rig struct {
	localPath string
	hub       *fakeHub
	state     *state.Store
	puller    *Puller
	masterKey []byte
	manifest  *manifest.Manifest
	manMu     *sync.Mutex
}

func setupPuller(t *testing.T) *rig {
	t.Helper()
	tmp := t.TempDir()
	localPath := filepath.Join(tmp, "crate")
	_ = os.MkdirAll(localPath, 0o755)

	store, err := state.Open(filepath.Join(tmp, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })

	hub := newFakeHub(t, "bk_test")
	client := httpc.New(hub.ts.URL)
	cap := "test-cap"

	mk := make([]byte, 32)
	for i := range mk {
		mk[i] = byte(i + 13)
	}
	man := manifest.New()
	mu := &sync.Mutex{}
	etag := ""
	lastFlushed := 0

	p, err := New(Config{
		LocalPath:                localPath,
		BucketID:                 "bk_test",
		CapabilityRef:            &cap,
		MasterKeyRef:             &mk,
		ManifestRef:              man,
		ManifestMu:               mu,
		ManifestETagRef:          &etag,
		LastFlushedEventCountRef: &lastFlushed,
		Hub:                      client,
		State:                    store,
		PollInterval:             50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &rig{localPath: localPath, hub: hub, state: store, puller: p,
		masterKey: mk, manifest: man, manMu: mu}
}

// publishFile builds a single-event manifest containing one file, encrypts
// the payload + manifest, and seeds the fake hub with both. Returns the
// uuid the file was stored under.
func (r *rig) publishFile(t *testing.T, path string, content []byte) string {
	t.Helper()
	uuid := "01TESTFILE000000000000000" + fmt.Sprintf("%01d", time.Now().UnixNano()&0xf)
	dataKey, _ := payload.RandomDataKey()
	dataKeyIV, dataKeyCT, err := payload.WrapDataKey(r.masterKey, dataKey, uuid)
	if err != nil {
		t.Fatal(err)
	}
	contentIV, body, err := payload.SealFilePayload(dataKey, content, uuid)
	if err != nil {
		t.Fatal(err)
	}
	r.hub.put("objects/"+uuid, body)

	r.manMu.Lock()
	_, err = r.manifest.Append(
		manifest.CreateEvent(uuid, path, int64(len(content)),
			"application/octet-stream", dataKeyIV, dataKeyCT, contentIV),
		r.masterKey,
	)
	if err != nil {
		r.manMu.Unlock()
		t.Fatal(err)
	}
	manBytes, err := r.manifest.EncryptToBytes(r.masterKey)
	r.manMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	r.hub.put(".crate/manifest.jsonl.enc", manBytes)
	_ = base64.StdEncoding // silence import if unused
	return uuid
}

// publishManifest re-encrypts the current in-memory manifest and PUTs.
// Useful after appending a delete or move event externally.
func (r *rig) publishManifest(t *testing.T) {
	t.Helper()
	r.manMu.Lock()
	manBytes, err := r.manifest.EncryptToBytes(r.masterKey)
	r.manMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	r.hub.put(".crate/manifest.jsonl.enc", manBytes)
}

func runTick(t *testing.T, r *rig) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r.puller.tick(ctx)
}

// --- tests ----------------------------------------------------------------

func TestPuller_DownloadsNewRemoteFile(t *testing.T) {
	r := setupPuller(t)
	plain := []byte("hello from remote\n")
	r.publishFile(t, "/hello.txt", plain)

	runTick(t, r)

	got, err := os.ReadFile(filepath.Join(r.localPath, "hello.txt"))
	if err != nil {
		t.Fatalf("expected hello.txt downloaded: %v", err)
	}
	if string(got) != string(plain) {
		t.Errorf("downloaded mismatch:\n got:  %q\n want: %q", got, plain)
	}

	m, err := r.state.LookupManifestEntry(context.Background(), "hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if m == nil || m.UUID == "" {
		t.Errorf("manifest_cache missing or no uuid: %+v", m)
	}
}

func TestPuller_NoOpWhenUnchanged(t *testing.T) {
	r := setupPuller(t)
	r.publishFile(t, "/steady.txt", []byte("body"))
	runTick(t, r)
	// Capture state.
	stat1, _ := os.Stat(filepath.Join(r.localPath, "steady.txt"))
	t1 := stat1.ModTime().UnixNano()

	// Re-tick — file shouldn't be re-downloaded.
	runTick(t, r)
	stat2, _ := os.Stat(filepath.Join(r.localPath, "steady.txt"))
	if stat2.ModTime().UnixNano() != t1 {
		t.Errorf("file was re-written when no change expected")
	}
}

func TestPuller_DownloadsOnUpdate(t *testing.T) {
	r := setupPuller(t)
	r.publishFile(t, "/changing.txt", []byte("v1"))
	runTick(t, r)
	if b, _ := os.ReadFile(filepath.Join(r.localPath, "changing.txt")); string(b) != "v1" {
		t.Fatal("v1 didn't land")
	}

	// Update remotely (same uuid would be ideal but we simulate the simpler
	// "delete + recreate at same path" path which the puller sees as a
	// content_iv change).
	r.publishFile(t, "/changing.txt", []byte("v2-newer"))
	runTick(t, r)
	got, _ := os.ReadFile(filepath.Join(r.localPath, "changing.txt"))
	if string(got) != "v2-newer" {
		t.Errorf("v2 didn't land; got %q", got)
	}
}

func TestPuller_TombstoneRemovesLocal(t *testing.T) {
	r := setupPuller(t)
	uuid := r.publishFile(t, "/ephemeral.txt", []byte("here today"))
	runTick(t, r)
	if _, err := os.Stat(filepath.Join(r.localPath, "ephemeral.txt")); err != nil {
		t.Fatal("initial download didn't land")
	}

	// Append a delete event to the manifest + republish.
	r.manMu.Lock()
	_, _ = r.manifest.Append(manifest.DeleteEvent(uuid), r.masterKey)
	r.manMu.Unlock()
	r.publishManifest(t)
	// Also remove the object from the hub (the puller doesn't require it
	// to be absent — the manifest delete is what tombstones — but a clean
	// fake matches real-world).
	r.hub.del("objects/" + uuid)

	runTick(t, r)
	if _, err := os.Stat(filepath.Join(r.localPath, "ephemeral.txt")); !os.IsNotExist(err) {
		t.Errorf("local file should be removed on remote tombstone, got %v", err)
	}
	if r.puller.deletedLocal.Load() != 1 {
		t.Errorf("deletedLocal counter = %d, want 1", r.puller.deletedLocal.Load())
	}
}

func TestPuller_NewRejectsBadConfig(t *testing.T) {
	tmp := t.TempDir()
	store, _ := state.Open(filepath.Join(tmp, "s.db"))
	defer store.Close()
	cap := "x"
	mk := make([]byte, 32)
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
		{"no State", func(c *Config) { c.State = nil }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			etag := ""
			lastFlushed := 0
			cfg := Config{
				LocalPath:                filepath.Join(tmp, "f"),
				BucketID:                 "bk_x",
				CapabilityRef:            &cap,
				MasterKeyRef:             &mk,
				ManifestRef:              manifest.New(),
				ManifestMu:               &sync.Mutex{},
				ManifestETagRef:          &etag,
				LastFlushedEventCountRef: &lastFlushed,
				Hub:                      httpc.New("http://x"),
				State:                    store,
			}
			c.mod(&cfg)
			if _, err := New(cfg); err == nil {
				t.Errorf("expected error")
			}
		})
	}
}

func TestStats(t *testing.T) {
	p := &Puller{}
	p.listCalls.Store(5)
	p.downloaded.Store(3)
	p.conflicts.Store(1)
	p.deletedLocal.Store(2)
	s := p.Stats()
	if s.ListCalls != 5 || s.Downloaded != 3 || s.Conflicts != 1 || s.DeletedLocal != 2 {
		t.Errorf("Stats: %+v", s)
	}
}

// A vault entry under .crate/ (a state DB leaked by a pre-1.3 daemon) must
// never be written into the local folder, where .crate/ holds this
// daemon's own SQLite files.
func TestPuller_SkipsIgnoredVaultPaths(t *testing.T) {
	r := setupPuller(t)
	r.publishFile(t, "/.crate/state.db-wal", []byte("not a wal"))
	r.publishFile(t, "/real.txt", []byte("real"))
	r.puller.tick(context.Background())
	if _, err := os.Stat(filepath.Join(r.localPath, ".crate", "state.db-wal")); err == nil {
		t.Fatal("leaked .crate/state.db-wal was mirrored over the daemon's own state dir")
	}
	if _, err := os.Stat(filepath.Join(r.localPath, "real.txt")); err != nil {
		t.Fatalf("real file not mirrored: %v", err)
	}
}
