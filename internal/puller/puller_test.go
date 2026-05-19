// SPDX-License-Identifier: AGPL-3.0-or-later
package puller

import (
	"context"
	"encoding/xml"
	"fmt"
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
	"github.com/NakliTechie/crate-agent/internal/state"
)

// fakeHub serves the minimal /v1/crate/{list,object}/{bucket} surface the
// puller needs. Stores objects by key in a map; LIST returns the current
// snapshot.
type fakeHub struct {
	mu       sync.Mutex
	objects  map[string]fakeObj
	bucketID string
	ts       *httptest.Server

	listCalls atomic.Int64
	getCalls  atomic.Int64
}

type fakeObj struct {
	body         []byte
	etag         string
	lastModified time.Time
}

func newFakeHub(t *testing.T, bucketID string) *fakeHub {
	t.Helper()
	h := &fakeHub{objects: map[string]fakeObj{}, bucketID: bucketID}
	h.ts = httptest.NewServer(http.HandlerFunc(h.serve))
	t.Cleanup(h.ts.Close)
	return h
}

// put / del / get are test helpers that mutate the fake bucket state without
// going through the proxy. Used by the test bodies to set up "remote made
// this change" scenarios.

func (h *fakeHub) put(key string, body []byte, etag string) {
	h.mu.Lock()
	h.objects[key] = fakeObj{body: body, etag: etag, lastModified: time.Now().UTC()}
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
	listPrefix := "/v1/crate/list/" + h.bucketID
	objPrefix := "/v1/crate/object/" + h.bucketID + "/"
	switch {
	case r.URL.Path == listPrefix && r.Method == http.MethodGet:
		h.listCalls.Add(1)
		h.handleList(w, r)
	case strings.HasPrefix(r.URL.Path, objPrefix) && r.Method == http.MethodGet:
		h.getCalls.Add(1)
		key := strings.TrimPrefix(r.URL.Path, objPrefix)
		h.handleGet(w, key)
	default:
		http.NotFound(w, r)
	}
}

func (h *fakeHub) handleList(w http.ResponseWriter, r *http.Request) {
	prefix := r.URL.Query().Get("prefix")
	h.mu.Lock()
	defer h.mu.Unlock()
	type entry struct {
		XMLName      xml.Name `xml:"Contents"`
		Key          string   `xml:"Key"`
		Size         int      `xml:"Size"`
		ETag         string   `xml:"ETag"`
		LastModified string   `xml:"LastModified"`
	}
	type result struct {
		XMLName     xml.Name `xml:"ListBucketResult"`
		IsTruncated bool     `xml:"IsTruncated"`
		Contents    []entry  `xml:"Contents"`
	}
	res := result{}
	for k, o := range h.objects {
		if prefix != "" && !strings.HasPrefix(k, prefix) {
			continue
		}
		res.Contents = append(res.Contents, entry{
			Key:          k,
			Size:         len(o.body),
			ETag:         fmt.Sprintf(`%q`, o.etag),
			LastModified: o.lastModified.UTC().Format(time.RFC3339),
		})
	}
	w.Header().Set("Content-Type", "application/xml")
	_ = xml.NewEncoder(w).Encode(res)
}

func (h *fakeHub) handleGet(w http.ResponseWriter, key string) {
	h.mu.Lock()
	obj, ok := h.objects[key]
	h.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("ETag", fmt.Sprintf(`%q`, obj.etag))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(obj.body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(obj.body)
}

// rig wires the puller to a fake hub + temp local folder + state.db.
type rig struct {
	localPath string
	hub       *fakeHub
	state     *state.Store
	puller    *Puller
	capRef    string
}

func setupPuller(t *testing.T, mods ...func(*Config)) *rig {
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

	cfg := Config{
		LocalPath:     localPath,
		BucketID:      "bk_test",
		CapabilityRef: &cap,
		Hub:           client,
		State:         store,
		PollInterval:  20 * time.Millisecond,
	}
	for _, m := range mods {
		m(&cfg)
	}
	p, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &rig{localPath: localPath, hub: hub, state: store, puller: p, capRef: cap}
}

// runOneTick blocks the test goroutine until exactly one tick has happened.
func runOneTick(t *testing.T, r *rig) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r.puller.tick(ctx)
}

func TestPuller_DownloadsNewRemoteFile(t *testing.T) {
	r := setupPuller(t)
	r.hub.put("hello.txt", []byte("hello from remote\n"), "etag-1")

	runOneTick(t, r)

	got, err := os.ReadFile(filepath.Join(r.localPath, "hello.txt"))
	if err != nil {
		t.Fatalf("expected hello.txt to be downloaded: %v", err)
	}
	if string(got) != "hello from remote\n" {
		t.Errorf("downloaded body mismatch: %q", got)
	}

	// manifest_cache should have a row.
	m, err := r.state.LookupManifestEntry(context.Background(), "hello.txt")
	if err != nil {
		t.Fatal(err)
	}
	if m == nil || m.ETag != "etag-1" {
		t.Errorf("manifest row missing or wrong etag: %+v", m)
	}
}

func TestPuller_NoOpWhenETagMatches(t *testing.T) {
	r := setupPuller(t)
	r.hub.put("steady.txt", []byte("body"), "etag-x")
	runOneTick(t, r)

	getsBefore := r.hub.getCalls.Load()
	runOneTick(t, r) // ETag matches now → no GET expected
	getsAfter := r.hub.getCalls.Load()
	if getsAfter != getsBefore {
		t.Errorf("second tick made %d additional GETs; want 0",
			getsAfter-getsBefore)
	}
}

func TestPuller_DownloadsOnETagChange(t *testing.T) {
	r := setupPuller(t)
	r.hub.put("changing.txt", []byte("v1"), "etag-1")
	runOneTick(t, r)
	// Verify v1 landed.
	if b, _ := os.ReadFile(filepath.Join(r.localPath, "changing.txt")); string(b) != "v1" {
		t.Fatalf("v1 didn't land")
	}

	// Remote updated.
	r.hub.put("changing.txt", []byte("v2-newer"), "etag-2")
	runOneTick(t, r)
	got, _ := os.ReadFile(filepath.Join(r.localPath, "changing.txt"))
	if string(got) != "v2-newer" {
		t.Errorf("v2 didn't land; got %q", got)
	}
}

func TestPuller_TombstoneRemovesLocal(t *testing.T) {
	r := setupPuller(t)
	r.hub.put("ephemeral.txt", []byte("here today"), "etag-1")
	runOneTick(t, r) // sync down

	r.hub.del("ephemeral.txt") // remote deletes
	runOneTick(t, r)           // tombstone

	if _, err := os.Stat(filepath.Join(r.localPath, "ephemeral.txt")); !os.IsNotExist(err) {
		t.Errorf("local file should be removed on remote tombstone, got %v", err)
	}
	m, _ := r.state.LookupManifestEntry(context.Background(), "ephemeral.txt")
	if m != nil {
		t.Errorf("manifest_cache row should be cleared on tombstone")
	}
	if r.puller.deletedLocal.Load() != 1 {
		t.Errorf("deletedLocal counter = %d, want 1", r.puller.deletedLocal.Load())
	}
}

func TestPuller_ConflictingRenameOnDivergentUpdate(t *testing.T) {
	r := setupPuller(t)
	r.hub.put("notes.md", []byte("# v1 remote"), "etag-1")
	runOneTick(t, r)

	// User edits the local copy AFTER the sync — bump mtime well past
	// LastSyncSlackNs.
	local := filepath.Join(r.localPath, "notes.md")
	if err := os.WriteFile(local, []byte("# I changed it locally"), 0o644); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(local, future, future); err != nil {
		t.Fatal(err)
	}

	// Meanwhile the remote ALSO changed.
	r.hub.put("notes.md", []byte("# v2 remote"), "etag-2")
	runOneTick(t, r)

	// Local at canonical path should now hold remote's v2.
	got, _ := os.ReadFile(local)
	if string(got) != "# v2 remote" {
		t.Errorf("canonical path should hold remote v2; got %q", got)
	}

	// User's edit should be preserved under a .conflict-<ts>.local sibling.
	entries, _ := os.ReadDir(r.localPath)
	foundConflict := false
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "notes.md.conflict-") && strings.HasSuffix(e.Name(), ".local") {
			b, _ := os.ReadFile(filepath.Join(r.localPath, e.Name()))
			if string(b) == "# I changed it locally" {
				foundConflict = true
			}
		}
	}
	if !foundConflict {
		t.Errorf("expected .conflict-*.local sibling with user's edit. dir entries: %v",
			dirNames(entries))
	}

	// conflict_log should have a row.
	cs, _ := r.state.RecentConflicts(context.Background(), 10)
	if len(cs) != 1 || cs[0].RemotePath != "notes.md" || cs[0].Resolution != "conflicting-rename" {
		t.Errorf("conflict_log row missing or wrong: %+v", cs)
	}
}

func TestPuller_RemoteDeletedButLocalModified_KeepsLocal(t *testing.T) {
	r := setupPuller(t)
	r.hub.put("notes.md", []byte("remote v1"), "etag-1")
	runOneTick(t, r)

	local := filepath.Join(r.localPath, "notes.md")
	// User edits locally.
	_ = os.WriteFile(local, []byte("local edits the user cares about"), 0o644)
	future := time.Now().Add(2 * time.Second)
	_ = os.Chtimes(local, future, future)

	r.hub.del("notes.md")
	runOneTick(t, r)

	// Local kept.
	got, err := os.ReadFile(local)
	if err != nil {
		t.Fatalf("local should be kept: %v", err)
	}
	if string(got) != "local edits the user cares about" {
		t.Errorf("local body changed unexpectedly: %q", got)
	}
	// manifest_cache row cleared so the next push re-uploads.
	m, _ := r.state.LookupManifestEntry(context.Background(), "notes.md")
	if m != nil {
		t.Errorf("manifest row should be cleared after remote-deleted-local-kept")
	}
	cs, _ := r.state.RecentConflicts(context.Background(), 10)
	if len(cs) != 1 || cs[0].Resolution != "remote-deleted-local-kept" {
		t.Errorf("conflict_log row wrong: %+v", cs)
	}
}

func TestPuller_SkipsCrateJsonMetadata(t *testing.T) {
	r := setupPuller(t)
	r.hub.put(".crate/crate.json", []byte(`{"v":1}`), "etag-meta")
	r.hub.put("real.txt", []byte("real"), "etag-r")
	runOneTick(t, r)

	if _, err := os.Stat(filepath.Join(r.localPath, ".crate", "crate.json")); !os.IsNotExist(err) {
		t.Errorf(".crate/crate.json should NOT be downloaded by the puller")
	}
	if _, err := os.Stat(filepath.Join(r.localPath, "real.txt")); err != nil {
		t.Errorf("real.txt should have downloaded")
	}
}

func TestPuller_NewRejectsBadConfig(t *testing.T) {
	cap := "x"
	tmp := t.TempDir()
	store, _ := state.Open(filepath.Join(tmp, "s.db"))
	defer store.Close()
	cli := httpc.New("http://x")
	cases := []struct {
		name string
		mod  func(*Config)
	}{
		{"no LocalPath", func(c *Config) { c.LocalPath = "" }},
		{"no BucketID", func(c *Config) { c.BucketID = "" }},
		{"no CapabilityRef", func(c *Config) { c.CapabilityRef = nil }},
		{"no Hub", func(c *Config) { c.Hub = nil }},
		{"no State", func(c *Config) { c.State = nil }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := Config{
				LocalPath:     filepath.Join(tmp, "f"),
				BucketID:      "bk_x",
				CapabilityRef: &cap,
				Hub:           cli,
				State:         store,
			}
			c.mod(&cfg)
			if _, err := New(cfg); err == nil {
				t.Errorf("expected error")
			}
		})
	}
}

func TestParseListXML(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>a.txt</Key>
    <Size>5</Size>
    <ETag>"abc"</ETag>
    <LastModified>2026-05-19T12:00:00Z</LastModified>
  </Contents>
</ListBucketResult>`)
	res, err := parseListXML(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Contents) != 1 || res.Contents[0].Key != "a.txt" {
		t.Errorf("parse wrong: %+v", res)
	}
	if res.Contents[0].ETag != "abc" {
		t.Errorf("ETag quotes not stripped: %q", res.Contents[0].ETag)
	}
}

func TestStatsAndPlatformString(t *testing.T) {
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

func dirNames(es []os.DirEntry) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.Name())
	}
	return out
}
