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
	"github.com/NakliTechie/private-mesh/fabric-sdk-go/grant"

	"github.com/NakliTechie/crate-agent/internal/config"
	"github.com/NakliTechie/crate-agent/internal/httpc"
)

// mintTestMacaroon builds a real fabric-spec-v1 macaroon for the test
// fixtures. Returns the wire bytes (suitable for base64 + use as a
// capability). Caller passes the principal/primitive/namespace/operations
// they want to bind into the scope.
func mintTestMacaroon(t *testing.T, principal, primitive, namespace string, ops []string) []byte {
	t.Helper()
	g, err := grant.Mint(grant.MintSpec{
		RootKey:  make([]byte, 32), // tests don't verify signatures
		Location: "*",
		Identifier: grant.Identifier{
			GrantID:           "01TESTGRANT0000000000000",
			IssuedAt:          time.Now().UTC(),
			IssuedByPrincipal: principal,
			IssuedByKeypair:   make([]byte, 32),
			Scope: grant.Scope{
				Primitive:  grant.Primitive(primitive),
				Namespace:  namespace,
				Operations: append([]string(nil), ops...),
			},
		},
		Caveats: []string{"time < 2027-01-01T00:00:00Z"},
	})
	if err != nil {
		t.Fatalf("mintTestMacaroon: %v", err)
	}
	return g.Macaroon
}

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
	// Default: mint a refreshed cap with the SAME scope as the current
	// (test fixture issues both with principal="hub", primitive=sync,
	// namespace="01HBUCKETID00000000000000", ops=[read,write]). Tests
	// that exercise scope expansion override h.nextCap before invoking.
	defaultRefreshed := mintTestMacaroon(t,
		"hub", "sync", "01HBUCKETID00000000000000",
		[]string{"read", "write"})
	h := &fakeHub{
		nextCap: base64.StdEncoding.EncodeToString(defaultRefreshed),
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
// The minted capability has scope (sync, "01HBUCKETID00000000000000", [read,write])
// issued by principal "hub" — same scope the default newFakeHub returns, so
// the happy-path refresh validates as a subset (equal scope).
func seedConfig(t *testing.T, dir string, masterKey []byte, expiresIn time.Duration) (string, *config.Config, string) {
	t.Helper()
	// Mint a real macaroon for the current capability (scope-validation in
	// validateRefreshedCapability requires both current + new to be parseable).
	currentCap := mintTestMacaroon(t,
		"hub", "sync", "01HBUCKETID00000000000000",
		[]string{"read", "write"})
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
	// Decode the new sealed capability from cfg and confirm it decrypts +
	// matches what the hub served (modulo base64). We can't compare to a
	// literal string anymore because the refreshed capability is now a
	// real macaroon (binary).
	sealed, _ := base64.StdEncoding.DecodeString(cfg.Crate.PairingToken)
	nonce, _ := base64.StdEncoding.DecodeString(cfg.Crate.CapabilityNonce)
	plain, err := sdkcrypto.Open(mk, nonce, sealed, nil)
	if err != nil {
		t.Fatalf("re-encrypted capability does not Open: %v", err)
	}
	wantBytes, _ := base64.StdEncoding.DecodeString(hub.nextCap)
	if base64.StdEncoding.EncodeToString(plain) != base64.StdEncoding.EncodeToString(wantBytes) {
		t.Errorf("re-encrypted plaintext does not match hub.nextCap")
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

// --- Scope-subset validation tests (v1.0.1 / audit H3 full) -----------

// validationCase parameterises rejection scenarios for
// validateRefreshedCapability. The current capability is always
// (principal=hub, primitive=sync, namespace=01HBUCKETID..., ops=[read,write]).
type validationCase struct {
	name        string
	newCap      func(t *testing.T) []byte
	newExpires  int64
	wantErrSub  string // substring expected in error message
}

func runValidationCase(t *testing.T, c validationCase) {
	dir := t.TempDir()
	mk := newMasterKey(t)
	_, cfg, cap := seedConfig(t, dir, mk, 30*24*time.Hour)
	r, err := New(Config{
		CfgPath:       filepath.Join(dir, "p.toml"),
		Cfg:           cfg,
		MasterKey:     mk,
		Hub:           httpc.New("http://x"),
		CapabilityRef: &cap,
	})
	if err != nil {
		t.Fatal(err)
	}
	exp := c.newExpires
	if exp == 0 {
		exp = time.Now().Add(365 * 24 * time.Hour).Unix()
	}
	err = r.validateRefreshedCapability(cap, c.newCap(t), exp)
	if err == nil {
		t.Fatalf("expected rejection (%s); got accept", c.name)
	}
	if c.wantErrSub != "" && !contains(err.Error(), c.wantErrSub) {
		t.Errorf("error %q does not contain %q", err.Error(), c.wantErrSub)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestValidate_RejectsDifferentIssuer(t *testing.T) {
	runValidationCase(t, validationCase{
		name: "different issuer",
		newCap: func(t *testing.T) []byte {
			return mintTestMacaroon(t, "rogue", "sync", "01HBUCKETID00000000000000",
				[]string{"read", "write"})
		},
		wantErrSub: "issuer",
	})
}

func TestValidate_RejectsDifferentPrimitive(t *testing.T) {
	runValidationCase(t, validationCase{
		name: "different primitive",
		newCap: func(t *testing.T) []byte {
			return mintTestMacaroon(t, "hub", "vault", "01HBUCKETID00000000000000",
				[]string{"read", "write"})
		},
		wantErrSub: "primitive",
	})
}

func TestValidate_RejectsDifferentNamespace(t *testing.T) {
	runValidationCase(t, validationCase{
		name: "different namespace",
		newCap: func(t *testing.T) []byte {
			return mintTestMacaroon(t, "hub", "sync", "OTHERBUCKETID000000000000",
				[]string{"read", "write"})
		},
		wantErrSub: "namespace",
	})
}

func TestValidate_RejectsExpandedOperations(t *testing.T) {
	runValidationCase(t, validationCase{
		name: "expanded operations",
		newCap: func(t *testing.T) []byte {
			return mintTestMacaroon(t, "hub", "sync", "01HBUCKETID00000000000000",
				[]string{"read", "write", "delete"})
		},
		wantErrSub: `"delete"`,
	})
}

func TestValidate_AcceptsNarrowedOperations(t *testing.T) {
	// Narrowing (subset) MUST be accepted — the daemon would be losing
	// authority, not gaining it. Refresh dropping a permission is rare
	// in practice but structurally fine.
	dir := t.TempDir()
	mk := newMasterKey(t)
	_, cfg, cap := seedConfig(t, dir, mk, 30*24*time.Hour)
	r, _ := New(Config{
		CfgPath:       filepath.Join(dir, "p.toml"),
		Cfg:           cfg,
		MasterKey:     mk,
		Hub:           httpc.New("http://x"),
		CapabilityRef: &cap,
	})
	narrower := mintTestMacaroon(t, "hub", "sync", "01HBUCKETID00000000000000",
		[]string{"read"}) // dropped "write"
	err := r.validateRefreshedCapability(cap,
		narrower, time.Now().Add(365*24*time.Hour).Unix())
	if err != nil {
		t.Errorf("narrowed-scope refresh should be accepted; got %v", err)
	}
}

func TestValidate_RejectsUnparseableNewCap(t *testing.T) {
	runValidationCase(t, validationCase{
		name: "garbage new cap",
		newCap: func(t *testing.T) []byte {
			return []byte("not a macaroon")
		},
		wantErrSub: "parse refreshed",
	})
}
