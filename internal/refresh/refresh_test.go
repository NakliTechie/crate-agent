// SPDX-License-Identifier: AGPL-3.0-or-later
package refresh

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	sdkcrypto "github.com/NakliTechie/private-mesh/fabric-sdk-go/crypto"

	"github.com/NakliTechie/crate-agent/internal/config"
	"github.com/NakliTechie/crate-agent/internal/httpc"
)

// newMasterKey returns a random 32-byte key for tests.
func newMasterKey(t *testing.T) []byte {
	t.Helper()
	k, err := sdkcrypto.RandomBytes(sdkcrypto.KeySize)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// fakeHub minimally implements /v1/capability/refresh.
type fakeHub struct {
	ts        *httptest.Server
	calls     atomic.Int64
	nextCap   string
	nextExp   int64
	failNext  atomic.Int64
	failCode  int
	requireAuth string
}

func newFakeHub(t *testing.T) *fakeHub {
	t.Helper()
	h := &fakeHub{
		nextCap: base64.StdEncoding.EncodeToString([]byte("REFRESHED-CAPABILITY-BYTES-v1")),
		nextExp: time.Now().Add(365 * 24 * time.Hour).Unix(),
	}
	h.ts = httptest.NewServer(http.HandlerFunc(h.serve))
	t.Cleanup(h.ts.Close)
	return h
}

func (h *fakeHub) serve(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/v1/capability/refresh" {
		http.NotFound(w, r)
		return
	}
	h.calls.Add(1)
	if h.requireAuth != "" && r.Header.Get("X-Fabric-Grant") != h.requireAuth {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"ok":false,"error":{"code":"grant_missing","message":"X-Fabric-Grant required"}}`))
		return
	}
	if remaining := h.failNext.Load(); remaining > 0 {
		h.failNext.Add(-1)
		code := h.failCode
		if code == 0 {
			code = http.StatusInternalServerError
		}
		w.WriteHeader(code)
		_, _ = w.Write([]byte(`{"ok":false,"error":{"code":"unavailable","message":"injected"}}`))
		return
	}
	resp := map[string]interface{}{
		"ok": true,
		"data": map[string]interface{}{
			"v":          1,
			"capability": h.nextCap,
			"expires_at": h.nextExp,
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// seedConfig builds a Config + on-disk file representing a "paired" daemon.
// expiresIn controls how far in the future the current capability's expiry sits.
func seedConfig(t *testing.T, dir string, masterKey []byte, expiresIn time.Duration) (string, *config.Config, string) {
	t.Helper()
	// Encrypt a placeholder current capability under masterKey.
	currentCap := []byte("CURRENT-CAPABILITY-BYTES-v1")
	nonce, err := sdkcrypto.RandomNonce()
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := sdkcrypto.Seal(masterKey, nonce, currentCap, nil)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Agent: config.AgentSection{LogLevel: "info"},
		Identity: config.IdentitySection{Path: filepath.Join(dir, "identity.key")},
		Crate: config.CrateSection{
			Name:              "test",
			LocalPath:         filepath.Join(dir, "crate-folder"),
			TransportEndpoint: "http://placeholder",
			TransportType:     "hub",
			PairingToken:      base64.StdEncoding.EncodeToString(sealed),
			BucketID:          "01HBUCKETID00000000000000",
			Salt:              base64.StdEncoding.EncodeToString(make([]byte, 16)),
			CapabilityNonce:   base64.StdEncoding.EncodeToString(nonce),
			CapabilityExpires: time.Now().Add(expiresIn).Unix(),
			EncryptAtRest:     false,
		},
	}
	cfgPath := filepath.Join(dir, "crate-agent.toml")
	if err := config.Write(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	// The plaintext "live" capability the syncer would hold in memory.
	plaintextCapB64 := base64.StdEncoding.EncodeToString(currentCap)
	return cfgPath, cfg, plaintextCapB64
}

func TestNeedsRefresh(t *testing.T) {
	dir := t.TempDir()
	mk := newMasterKey(t)
	cases := []struct {
		name      string
		expiresIn time.Duration
		want      bool
	}{
		{"fresh (1 year left)", 365 * 24 * time.Hour, false},
		{"half-life (180 days)", 180 * 24 * time.Hour, false},
		{"just-under-threshold (70 days)", 70 * 24 * time.Hour, true},
		{"near-expiry (1 day)", 1 * 24 * time.Hour, true},
		{"past-expiry", -1 * time.Hour, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, cfg, _ := seedConfig(t, dir, mk, c.expiresIn)
			cap := "x"
			r, err := New(Config{
				CfgPath:       filepath.Join(dir, "n.toml"),
				Cfg:           cfg,
				MasterKey:     mk,
				Hub:           httpc.New("http://x"),
				CapabilityRef: &cap,
			})
			if err != nil {
				t.Fatal(err)
			}
			if got := r.needsRefresh(); got != c.want {
				t.Errorf("needsRefresh(remaining=%v) = %v, want %v", c.expiresIn, got, c.want)
			}
		})
	}
}

func TestNeedsRefresh_ZeroExpiryIgnored(t *testing.T) {
	dir := t.TempDir()
	mk := newMasterKey(t)
	_, cfg, _ := seedConfig(t, dir, mk, time.Hour)
	cfg.Crate.CapabilityExpires = 0 // simulate pre-pair / cleared state
	cap := "x"
	r, _ := New(Config{
		CfgPath:       filepath.Join(dir, "n.toml"),
		Cfg:           cfg,
		MasterKey:     mk,
		Hub:           httpc.New("http://x"),
		CapabilityRef: &cap,
	})
	if r.needsRefresh() {
		t.Errorf("zero CapabilityExpires should NOT trigger refresh")
	}
}

func TestDoRefresh_HappyPath(t *testing.T) {
	dir := t.TempDir()
	mk := newMasterKey(t)
	cfgPath, cfg, cap := seedConfig(t, dir, mk, 30*24*time.Hour /* needs refresh */)

	hub := newFakeHub(t)
	hub.requireAuth = cap // assert the daemon presents the CURRENT cap as auth
	client := httpc.New(hub.ts.URL)

	r, err := New(Config{
		CfgPath:       cfgPath,
		Cfg:           cfg,
		MasterKey:     mk,
		Hub:           client,
		CapabilityRef: &cap,
		PollInterval:  50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := r.doRefresh(context.Background()); err != nil {
		t.Fatalf("doRefresh: %v", err)
	}
	if hub.calls.Load() != 1 {
		t.Errorf("expected 1 hub call, got %d", hub.calls.Load())
	}
	if cap == "" {
		t.Errorf("CapabilityRef was not updated")
	}
	// Decode the new sealed capability from cfg and confirm it decrypts.
	sealed, _ := base64.StdEncoding.DecodeString(cfg.Crate.PairingToken)
	nonce, _ := base64.StdEncoding.DecodeString(cfg.Crate.CapabilityNonce)
	plain, err := sdkcrypto.Open(mk, nonce, sealed, nil)
	if err != nil {
		t.Fatalf("re-encrypted capability does not Open: %v", err)
	}
	if string(plain) != "REFRESHED-CAPABILITY-BYTES-v1" {
		t.Errorf("re-encrypted plaintext = %q, want REFRESHED-CAPABILITY-BYTES-v1", plain)
	}
	if cfg.Crate.CapabilityExpires != hub.nextExp {
		t.Errorf("CapabilityExpires = %d, want %d", cfg.Crate.CapabilityExpires, hub.nextExp)
	}
	// Confirm the on-disk file got rewritten.
	if reloaded, err := config.Load(cfgPath); err != nil {
		t.Fatal(err)
	} else if reloaded.Crate.CapabilityExpires != hub.nextExp {
		t.Errorf("on-disk CapabilityExpires = %d, want %d",
			reloaded.Crate.CapabilityExpires, hub.nextExp)
	}
}

func TestDoRefresh_FailurePreservesState(t *testing.T) {
	dir := t.TempDir()
	mk := newMasterKey(t)
	cfgPath, cfg, cap := seedConfig(t, dir, mk, 30*24*time.Hour)
	origToken := cfg.Crate.PairingToken
	origExpires := cfg.Crate.CapabilityExpires

	hub := newFakeHub(t)
	hub.failNext.Store(1)
	client := httpc.New(hub.ts.URL)

	r, _ := New(Config{
		CfgPath:       cfgPath,
		Cfg:           cfg,
		MasterKey:     mk,
		Hub:           client,
		CapabilityRef: &cap,
	})
	if err := r.doRefresh(context.Background()); err == nil {
		t.Fatal("expected error on failing refresh")
	}
	if cfg.Crate.PairingToken != origToken {
		t.Errorf("config PairingToken changed on failure")
	}
	if cfg.Crate.CapabilityExpires != origExpires {
		t.Errorf("config CapabilityExpires changed on failure")
	}
}

func TestNew_RejectsBadConfig(t *testing.T) {
	dir := t.TempDir()
	mk := newMasterKey(t)
	_, cfg, cap := seedConfig(t, dir, mk, time.Hour)
	cases := []struct {
		name string
		mod  func(*Config)
	}{
		{"no CfgPath", func(c *Config) { c.CfgPath = "" }},
		{"no Cfg", func(c *Config) { c.Cfg = nil }},
		{"wrong MasterKey size", func(c *Config) { c.MasterKey = []byte{1, 2, 3} }},
		{"no Hub", func(c *Config) { c.Hub = nil }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfgC := Config{
				CfgPath:       filepath.Join(dir, "x.toml"),
				Cfg:           cfg,
				MasterKey:     mk,
				Hub:           httpc.New("http://x"),
				CapabilityRef: &cap,
			}
			c.mod(&cfgC)
			if _, err := New(cfgC); err == nil {
				t.Errorf("expected error")
			}
		})
	}
}

func TestRun_TriggersOnImmediateExpiry(t *testing.T) {
	dir := t.TempDir()
	mk := newMasterKey(t)
	cfgPath, cfg, cap := seedConfig(t, dir, mk, 1*time.Hour)

	hub := newFakeHub(t)
	hub.requireAuth = cap
	client := httpc.New(hub.ts.URL)

	r, _ := New(Config{
		CfgPath:       cfgPath,
		Cfg:           cfg,
		MasterKey:     mk,
		Hub:           client,
		CapabilityRef: &cap,
		PollInterval:  10 * time.Millisecond,
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go r.Run(ctx)
	// First tick is immediate; give it a beat.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if hub.calls.Load() >= 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("Run did not trigger refresh; hub.calls=%d", hub.calls.Load())
}
