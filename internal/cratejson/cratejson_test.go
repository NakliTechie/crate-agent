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
	"github.com/NakliTechie/crate-agent/internal/payload"
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

// --- v1.1 schema tests ----------------------------------------------------

// makeV11Doc constructs a v1.1 doc body with a single passphrase_wrap.
// Returns the JSON bytes, the canonical salt, and the content key (caller
// uses the content key to verify Reconcile unwrapped correctly).
func makeV11Doc(t *testing.T, pass string) (body, saltBytes, contentKey []byte) {
	t.Helper()
	saltBytes = make([]byte, 16)
	for i := range saltBytes {
		saltBytes[i] = byte(0x30 + i)
	}
	iter := 600_000
	kek := kdf.DerivePassphraseKEK(pass, saltBytes, iter)
	contentKey, _ = payload.RandomBytes(payload.KeySize)
	iv, ct, err := payload.WrapKey(kek, contentKey)
	if err != nil {
		t.Fatal(err)
	}
	doc := Doc{
		V:       1,
		Version: "1.1",
		PassphraseWrap: &Wrap{
			KDF:  "PBKDF2-SHA256",
			Iter: iter,
			Salt: base64.StdEncoding.EncodeToString(saltBytes),
			IV:   base64.StdEncoding.EncodeToString(iv),
			CT:   base64.StdEncoding.EncodeToString(ct),
		},
	}
	body, _ = json.Marshal(doc)
	return body, saltBytes, contentKey
}

func TestFetch_V11_HappyPath(t *testing.T) {
	body, _, _ := makeV11Doc(t, "test-passphrase")
	h := newFakeHub(t, "bk_test")
	h.body = body
	client := httpc.New(h.ts.URL)
	got, err := Fetch(context.Background(), client, "bk_test", "x")
	if err != nil {
		t.Fatal(err)
	}
	if !got.IsV11() {
		t.Errorf("IsV11() = false; want true")
	}
	if got.PassphraseWrap == nil {
		t.Fatal("PassphraseWrap is nil")
	}
	if _, err := got.PassphraseWrap.SaltBytes(); err != nil {
		t.Errorf("SaltBytes: %v", err)
	}
	if _, err := got.PassphraseWrap.IVBytes(); err != nil {
		t.Errorf("IVBytes: %v", err)
	}
	if _, err := got.PassphraseWrap.CTBytes(); err != nil {
		t.Errorf("CTBytes: %v", err)
	}
	if _, err := got.SaltBytes(); err == nil {
		t.Errorf("Doc.SaltBytes() on a v1.1 doc should error (use PassphraseWrap.SaltBytes())")
	}
}

func TestFetch_V11_WithRecoveryWrap(t *testing.T) {
	body, _, _ := makeV11Doc(t, "tp")
	var raw map[string]any
	_ = json.Unmarshal(body, &raw)
	raw["recovery_wrap"] = map[string]any{
		"kdf":  "PBKDF2-SHA256",
		"iter": 600000,
		"salt": base64.StdEncoding.EncodeToString(make([]byte, 16)),
		"iv":   base64.StdEncoding.EncodeToString(make([]byte, 12)),
		"ct":   base64.StdEncoding.EncodeToString(make([]byte, 48)),
	}
	body2, _ := json.Marshal(raw)
	h := newFakeHub(t, "bk_test")
	h.body = body2
	client := httpc.New(h.ts.URL)
	got, err := Fetch(context.Background(), client, "bk_test", "x")
	if err != nil {
		t.Fatal(err)
	}
	if got.RecoveryWrap == nil {
		t.Fatal("RecoveryWrap not populated")
	}
	if _, err := got.RecoveryWrap.SaltBytes(); err != nil {
		t.Errorf("RecoveryWrap.SaltBytes: %v", err)
	}
}

func TestFetch_V11_VersionMismatch_Rejected(t *testing.T) {
	body, _, _ := makeV11Doc(t, "tp")
	var raw map[string]any
	_ = json.Unmarshal(body, &raw)
	raw["version"] = "1.0"
	body2, _ := json.Marshal(raw)
	h := newFakeHub(t, "bk_test")
	h.body = body2
	client := httpc.New(h.ts.URL)
	_, err := Fetch(context.Background(), client, "bk_test", "x")
	if err == nil {
		t.Errorf("Fetch should reject v1.1 doc with version=1.0")
	} else if !strings.Contains(err.Error(), "1.1") {
		t.Errorf("error should mention expected version 1.1; got: %v", err)
	}
}

func TestFetch_V11_LowIter_Rejected(t *testing.T) {
	body, _, _ := makeV11Doc(t, "tp")
	var raw map[string]any
	_ = json.Unmarshal(body, &raw)
	raw["passphrase_wrap"].(map[string]any)["iter"] = float64(1000)
	body2, _ := json.Marshal(raw)
	h := newFakeHub(t, "bk_test")
	h.body = body2
	client := httpc.New(h.ts.URL)
	_, err := Fetch(context.Background(), client, "bk_test", "x")
	if err == nil {
		t.Errorf("Fetch should reject low iter count")
	}
}

func TestFetch_NeitherSaltNorWrap_Rejected(t *testing.T) {
	body, _ := json.Marshal(Doc{V: 1})
	h := newFakeHub(t, "bk_test")
	h.body = body
	client := httpc.New(h.ts.URL)
	_, err := Fetch(context.Background(), client, "bk_test", "x")
	if err == nil {
		t.Errorf("Fetch should reject doc with neither salt nor passphrase_wrap")
	}
}

func TestWrap_Validate_RejectsBadFields(t *testing.T) {
	good := &Wrap{
		KDF: "PBKDF2-SHA256", Iter: 600000,
		Salt: base64.StdEncoding.EncodeToString(make([]byte, 16)),
		IV:   base64.StdEncoding.EncodeToString(make([]byte, 12)),
		CT:   base64.StdEncoding.EncodeToString(make([]byte, 48)),
	}
	if err := good.Validate(); err != nil {
		t.Fatalf("Good wrap should validate: %v", err)
	}
	cases := []struct {
		name   string
		mutate func(w *Wrap)
	}{
		{"wrong kdf", func(w *Wrap) { w.KDF = "scrypt" }},
		{"iter too low", func(w *Wrap) { w.Iter = 1000 }},
		{"salt wrong length", func(w *Wrap) { w.Salt = base64.StdEncoding.EncodeToString(make([]byte, 8)) }},
		{"iv wrong length", func(w *Wrap) { w.IV = base64.StdEncoding.EncodeToString(make([]byte, 8)) }},
		{"ct wrong length", func(w *Wrap) { w.CT = base64.StdEncoding.EncodeToString(make([]byte, 32)) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bad := *good
			tc.mutate(&bad)
			if err := bad.Validate(); err == nil {
				t.Errorf("expected validation error for: %s", tc.name)
			}
		})
	}
}

// --- v1.1 reconcile tests -------------------------------------------------

func TestReconcile_V11_SameSalt_UnwrapsContentKey(t *testing.T) {
	pass := "test-passphrase"
	dir := t.TempDir()
	body, saltBytes, contentKey := makeV11Doc(t, pass)

	// Local capability is sealed under the passphrase-KEK (= same salt as
	// canonical, simulating an already-reconciled v1.1 daemon restart).
	capabilityKEK := kdf.DerivePassphraseKEK(pass, saltBytes, 600_000)
	cap := []byte("CAPABILITY-PLAINTEXT")
	cfgPath, cfg := seedCfg(t, dir, capabilityKEK, saltBytes, cap)

	h := newFakeHub(t, "bk_test")
	h.body = body
	client := httpc.New(h.ts.URL)

	res := Reconcile(context.Background(), ReconcileInput{
		CfgPath:          cfgPath,
		Cfg:              cfg,
		Passphrase:       pass,
		CurrentMasterKey: capabilityKEK,
		CapabilityBytes:  cap,
		Hub:              client,
		Capability:       "x",
	})
	if res.Action != ActionReconciled {
		t.Fatalf("Action = %v, want ActionReconciled (v1.1 always reconciles)", res.Action)
	}
	if len(res.NewPayloadMasterKey) != payload.KeySize {
		t.Fatalf("NewPayloadMasterKey length = %d, want %d", len(res.NewPayloadMasterKey), payload.KeySize)
	}
	if string(res.NewPayloadMasterKey) != string(contentKey) {
		t.Errorf("NewPayloadMasterKey != content key from passphrase_wrap")
	}
	if len(res.NewMasterKey) != payload.KeySize {
		t.Errorf("NewMasterKey (capability KEK) length = %d", len(res.NewMasterKey))
	}
}

func TestReconcile_V11_SaltRotation_ReencryptsCapability(t *testing.T) {
	pass := "test"
	dir := t.TempDir()
	body, canonicalSalt, contentKey := makeV11Doc(t, pass)

	// Local salt is DIFFERENT from canonical → reconciler must re-encrypt
	// capability under the new KEK.
	localSalt := make([]byte, 16)
	for i := range localSalt {
		localSalt[i] = 0xAA
	}
	localKEK := kdf.DerivePassphraseKEK(pass, localSalt, 600_000)
	cap := []byte("CAP")
	cfgPath, cfg := seedCfg(t, dir, localKEK, localSalt, cap)

	h := newFakeHub(t, "bk_test")
	h.body = body
	client := httpc.New(h.ts.URL)

	res := Reconcile(context.Background(), ReconcileInput{
		CfgPath:          cfgPath,
		Cfg:              cfg,
		Passphrase:       pass,
		CurrentMasterKey: localKEK,
		CapabilityBytes:  cap,
		Hub:              client,
		Capability:       "x",
	})
	if res.Action != ActionReconciled {
		t.Fatalf("Action = %v, want ActionReconciled", res.Action)
	}
	if string(res.NewPayloadMasterKey) != string(contentKey) {
		t.Errorf("content key mismatch")
	}
	got, _ := base64.StdEncoding.DecodeString(cfg.Crate.Salt)
	if string(got) != string(canonicalSalt) {
		t.Errorf("cfg.Salt not updated to canonical")
	}
	// New sealed capability must decrypt under the canonical-KEK (NewMasterKey).
	sealed, _ := base64.StdEncoding.DecodeString(cfg.Crate.PairingToken)
	nonce, _ := base64.StdEncoding.DecodeString(cfg.Crate.CapabilityNonce)
	plain, err := sdkcrypto.Open(res.NewMasterKey, nonce, sealed, nil)
	if err != nil {
		t.Fatalf("Open re-sealed capability: %v", err)
	}
	if string(plain) != string(cap) {
		t.Errorf("re-sealed capability != original")
	}
}

func TestReconcile_V11_WrongPassphrase_Fails(t *testing.T) {
	body, saltBytes, _ := makeV11Doc(t, "the-right-passphrase")
	dir := t.TempDir()
	wrongPass := "wrong-passphrase"
	junkKEK := make([]byte, payload.KeySize)
	cap := []byte("CAP")
	cfgPath, cfg := seedCfg(t, dir, junkKEK, saltBytes, cap)

	h := newFakeHub(t, "bk_test")
	h.body = body
	client := httpc.New(h.ts.URL)

	res := Reconcile(context.Background(), ReconcileInput{
		CfgPath:          cfgPath,
		Cfg:              cfg,
		Passphrase:       wrongPass,
		CurrentMasterKey: junkKEK,
		CapabilityBytes:  cap,
		Hub:              client,
		Capability:       "x",
	})
	if res.Action != ActionFailed {
		t.Errorf("Action = %v, want ActionFailed (wrong passphrase should fail unwrap)", res.Action)
	}
}
