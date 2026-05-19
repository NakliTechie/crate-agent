// SPDX-License-Identifier: AGPL-3.0-or-later
package cratejson

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	sdkcrypto "github.com/NakliTechie/private-mesh/fabric-sdk-go/crypto"

	"github.com/NakliTechie/crate-agent/internal/config"
	"github.com/NakliTechie/crate-agent/internal/httpc"
	"github.com/NakliTechie/crate-agent/internal/kdf"
)

// fakeHub serves a single /v1/crate/object/{bucket}/.crate/crate.json route.
type fakeHub struct {
	ts        *httptest.Server
	bucketID  string
	body      []byte    // when nil, return 404
	statusOK  int       // override 200; 0 = 200
	auth      string    // expected X-Fabric-Grant
}

func newFakeHub(t *testing.T, bucketID string) *fakeHub {
	t.Helper()
	h := &fakeHub{bucketID: bucketID}
	h.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if h.auth != "" && r.Header.Get("X-Fabric-Grant") != h.auth {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		want := "/v1/crate/object/" + h.bucketID + "/.crate/crate.json"
		if r.URL.Path != want {
			http.NotFound(w, r)
			return
		}
		if h.body == nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		code := h.statusOK
		if code == 0 {
			code = http.StatusOK
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(code)
		_, _ = w.Write(h.body)
	}))
	t.Cleanup(h.ts.Close)
	return h
}

func TestFetch_HappyPath(t *testing.T) {
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	doc := Doc{
		V:    1,
		Salt: base64.StdEncoding.EncodeToString(salt),
	}
	body, _ := json.Marshal(doc)

	h := newFakeHub(t, "bk_test")
	h.body = body
	h.auth = "test-cap"

	client := httpc.New(h.ts.URL)
	got, err := Fetch(context.Background(), client, "bk_test", "test-cap")
	if err != nil {
		t.Fatal(err)
	}
	if got.V != 1 {
		t.Errorf("V = %d, want 1", got.V)
	}
	gotSalt, err := got.SaltBytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(gotSalt) != string(salt) {
		t.Errorf("salt mismatch")
	}
}

func TestFetch_404_IsErrAbsent(t *testing.T) {
	h := newFakeHub(t, "bk_test")
	// h.body left nil ⇒ 404.
	client := httpc.New(h.ts.URL)
	_, err := Fetch(context.Background(), client, "bk_test", "x")
	if !errors.Is(err, ErrAbsent) {
		t.Errorf("expected ErrAbsent, got %v", err)
	}
}

func TestFetch_UnsupportedVersion(t *testing.T) {
	body, _ := json.Marshal(Doc{V: 99, Salt: base64.StdEncoding.EncodeToString(make([]byte, 16))})
	h := newFakeHub(t, "bk_test")
	h.body = body
	client := httpc.New(h.ts.URL)
	_, err := Fetch(context.Background(), client, "bk_test", "x")
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Errorf("expected ErrUnsupportedVersion, got %v", err)
	}
}

func TestFetch_MalformedJSON(t *testing.T) {
	h := newFakeHub(t, "bk_test")
	h.body = []byte("not json")
	client := httpc.New(h.ts.URL)
	_, err := Fetch(context.Background(), client, "bk_test", "x")
	if err == nil || !strings.Contains(err.Error(), "parse") {
		t.Errorf("expected parse error, got %v", err)
	}
}

func TestFetch_EmptyBody(t *testing.T) {
	h := newFakeHub(t, "bk_test")
	h.body = []byte{}
	// Override: nil-vs-empty would still hit the body==nil 404 branch.
	// Re-wire the handler instead.
	h.ts.Close()
	h.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer h.ts.Close()
	client := httpc.New(h.ts.URL)
	_, err := Fetch(context.Background(), client, "bk_test", "x")
	if err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("expected empty-body error, got %v", err)
	}
}

func TestSaltBytes_LengthGuard(t *testing.T) {
	d := &Doc{Salt: base64.StdEncoding.EncodeToString([]byte{1, 2, 3})}
	if _, err := d.SaltBytes(); err == nil {
		t.Errorf("expected length-mismatch error")
	}
}

func TestSaltBytes_AcceptsURLSafe(t *testing.T) {
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i)
	}
	d := &Doc{Salt: base64.RawURLEncoding.EncodeToString(salt)}
	got, err := d.SaltBytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(salt) {
		t.Errorf("URL-safe round-trip mismatch")
	}
}

// --- Reconcile tests ------------------------------------------------------

func seedCfg(t *testing.T, dir string, masterKey, salt, capability []byte) (string, *config.Config) {
	t.Helper()
	nonce, _ := sdkcrypto.RandomNonce()
	sealed, _ := sdkcrypto.Seal(masterKey, nonce, capability, nil)
	cfg := &config.Config{
		Agent: config.AgentSection{LogLevel: "info"},
		Identity: config.IdentitySection{Path: filepath.Join(dir, "id.key")},
		Crate: config.CrateSection{
			Name:              "test",
			LocalPath:         filepath.Join(dir, "crate"),
			TransportEndpoint: "http://x",
			TransportType:     "hub",
			PairingToken:      base64.StdEncoding.EncodeToString(sealed),
			BucketID:          "bk_test",
			Salt:              base64.StdEncoding.EncodeToString(salt),
			CapabilityNonce:   base64.StdEncoding.EncodeToString(nonce),
		},
	}
	cfgPath := filepath.Join(dir, "crate-agent.toml")
	if err := config.Write(cfgPath, cfg); err != nil {
		t.Fatal(err)
	}
	return cfgPath, cfg
}

func TestReconcile_Absent(t *testing.T) {
	dir := t.TempDir()
	salt := make([]byte, 16)
	pass := "test-passphrase"
	masterKey := kdf.DeriveMasterKey(pass, salt)
	cap := []byte("CAPABILITY-BYTES")
	cfgPath, cfg := seedCfg(t, dir, masterKey, salt, cap)

	h := newFakeHub(t, "bk_test")
	// h.body nil ⇒ 404 ⇒ ErrAbsent ⇒ ActionAbsent
	client := httpc.New(h.ts.URL)

	res := Reconcile(context.Background(), ReconcileInput{
		CfgPath:          cfgPath,
		Cfg:              cfg,
		Passphrase:       pass,
		CurrentMasterKey: masterKey,
		CapabilityBytes:  cap,
		Hub:              client,
		Capability:       "x",
	})
	if res.Action != ActionAbsent {
		t.Errorf("Action = %v, want ActionAbsent", res.Action)
	}
}

func TestReconcile_AlreadyCanonical(t *testing.T) {
	dir := t.TempDir()
	salt := make([]byte, 16)
	for i := range salt {
		salt[i] = byte(i + 7)
	}
	pass := "test"
	masterKey := kdf.DeriveMasterKey(pass, salt)
	cap := []byte("CAP")
	cfgPath, cfg := seedCfg(t, dir, masterKey, salt, cap)

	// Bucket serves the SAME salt as cfg.
	body, _ := json.Marshal(Doc{V: 1, Salt: base64.StdEncoding.EncodeToString(salt)})
	h := newFakeHub(t, "bk_test")
	h.body = body
	client := httpc.New(h.ts.URL)

	res := Reconcile(context.Background(), ReconcileInput{
		CfgPath:          cfgPath,
		Cfg:              cfg,
		Passphrase:       pass,
		CurrentMasterKey: masterKey,
		CapabilityBytes:  cap,
		Hub:              client,
		Capability:       "x",
	})
	if res.Action != ActionAlreadyCanonical {
		t.Errorf("Action = %v, want ActionAlreadyCanonical", res.Action)
	}
}

func TestReconcile_Reconciled(t *testing.T) {
	dir := t.TempDir()
	localSalt := make([]byte, 16)
	for i := range localSalt {
		localSalt[i] = 0x11
	}
	canonicalSalt := make([]byte, 16)
	for i := range canonicalSalt {
		canonicalSalt[i] = 0x22
	}
	pass := "test"
	masterKey := kdf.DeriveMasterKey(pass, localSalt)
	cap := []byte("CAP-PLAINTEXT")
	cfgPath, cfg := seedCfg(t, dir, masterKey, localSalt, cap)

	body, _ := json.Marshal(Doc{V: 1, Salt: base64.StdEncoding.EncodeToString(canonicalSalt)})
	h := newFakeHub(t, "bk_test")
	h.body = body
	client := httpc.New(h.ts.URL)

	res := Reconcile(context.Background(), ReconcileInput{
		CfgPath:          cfgPath,
		Cfg:              cfg,
		Passphrase:       pass,
		CurrentMasterKey: masterKey,
		CapabilityBytes:  cap,
		Hub:              client,
		Capability:       "x",
	})
	if res.Action != ActionReconciled {
		t.Fatalf("Action = %v, want ActionReconciled", res.Action)
	}
	if len(res.NewMasterKey) != sdkcrypto.KeySize {
		t.Fatalf("NewMasterKey length = %d, want %d", len(res.NewMasterKey), sdkcrypto.KeySize)
	}
	// Re-derive with canonical salt; should match.
	want := kdf.DeriveMasterKey(pass, canonicalSalt)
	if string(want) != string(res.NewMasterKey) {
		t.Errorf("NewMasterKey != PBKDF2(pass, canonicalSalt)")
	}
	// Verify on-disk + in-memory cfg now hold the canonical salt.
	gotSalt, _ := base64.StdEncoding.DecodeString(cfg.Crate.Salt)
	if string(gotSalt) != string(canonicalSalt) {
		t.Errorf("cfg.Salt was not updated to canonical")
	}
	// Verify the new sealed capability decrypts under the new master key.
	sealed, _ := base64.StdEncoding.DecodeString(cfg.Crate.PairingToken)
	nonce, _ := base64.StdEncoding.DecodeString(cfg.Crate.CapabilityNonce)
	plain, err := sdkcrypto.Open(res.NewMasterKey, nonce, sealed, nil)
	if err != nil {
		t.Fatalf("Open with NewMasterKey: %v", err)
	}
	if string(plain) != string(cap) {
		t.Errorf("decrypted plain != original capability")
	}
	// And on disk.
	reloaded, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	gotSalt2, _ := base64.StdEncoding.DecodeString(reloaded.Crate.Salt)
	if string(gotSalt2) != string(canonicalSalt) {
		t.Errorf("on-disk Salt was not updated")
	}
}

func TestReconcile_FetchFailureIsNonFatal(t *testing.T) {
	dir := t.TempDir()
	salt := make([]byte, 16)
	pass := "test"
	masterKey := kdf.DeriveMasterKey(pass, salt)
	cap := []byte("CAP")
	cfgPath, cfg := seedCfg(t, dir, masterKey, salt, cap)

	h := newFakeHub(t, "bk_test")
	h.body = []byte("garbage") // not JSON → ActionFailed
	client := httpc.New(h.ts.URL)

	res := Reconcile(context.Background(), ReconcileInput{
		CfgPath:          cfgPath,
		Cfg:              cfg,
		Passphrase:       pass,
		CurrentMasterKey: masterKey,
		CapabilityBytes:  cap,
		Hub:              client,
		Capability:       "x",
	})
	if res.Action != ActionFailed {
		t.Errorf("Action = %v, want ActionFailed", res.Action)
	}
	// On-disk Salt unchanged.
	reloaded, _ := config.Load(cfgPath)
	gotSalt, _ := base64.StdEncoding.DecodeString(reloaded.Crate.Salt)
	if string(gotSalt) != string(salt) {
		t.Errorf("on-disk Salt was mutated despite failure")
	}
}

func TestActionString(t *testing.T) {
	for a, want := range map[Action]string{
		ActionAbsent:           "absent",
		ActionAlreadyCanonical: "already-canonical",
		ActionReconciled:       "reconciled",
		ActionFailed:           "failed",
		Action(99):             "unknown",
	} {
		if got := a.String(); got != want {
			t.Errorf("Action(%d).String() = %q, want %q", a, got, want)
		}
	}
}

func TestCanonicalSaltEqual(t *testing.T) {
	salt := make([]byte, 16)
	a := base64.StdEncoding.EncodeToString(salt)
	if !CanonicalSaltEqual(a, a) {
		t.Errorf("self-compare should be equal")
	}
	other := make([]byte, 16)
	other[0] = 1
	if CanonicalSaltEqual(a, base64.StdEncoding.EncodeToString(other)) {
		t.Errorf("different salts compared equal")
	}
	if CanonicalSaltEqual("not-b64", a) {
		t.Errorf("malformed b64 compared equal")
	}
}
