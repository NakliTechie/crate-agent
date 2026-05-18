// SPDX-License-Identifier: AGPL-3.0-or-later
package pairing

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NakliTechie/crate-agent/internal/httpc"
)

// Test vectors live in the sibling private-mesh repo. Locate via the
// post-reorg layout; tests skip gracefully if the file isn't reachable
// (e.g. CI environment without the sibling repo checked out).
var testVectorsCandidates = []string{
	"../../../private-mesh/docs/test-vectors/crate-pairing/test-vectors.json",
}

type vector struct {
	Name          string  `json:"name"`
	Token         string  `json:"token"`
	ExpectedError *string `json:"expected_error"`
	Note          string  `json:"note"`
}

type fixture struct {
	SchemaVersion string   `json:"$schema_version"`
	SourceSpec    string   `json:"source_spec"`
	Vectors       []vector `json:"vectors"`
}

func loadFixture(t *testing.T) *fixture {
	t.Helper()
	var lastErr error
	for _, p := range testVectorsCandidates {
		abs, err := filepath.Abs(p)
		if err != nil {
			continue
		}
		b, err := os.ReadFile(abs)
		if err != nil {
			lastErr = err
			continue
		}
		var fx fixture
		if err := json.Unmarshal(b, &fx); err != nil {
			t.Fatalf("parse test vectors at %s: %v", abs, err)
		}
		return &fx
	}
	t.Skipf("test vectors not found at any of %v (lastErr=%v)", testVectorsCandidates, lastErr)
	return nil
}

// TestVectors_DecodeAndValidate exercises every vector at the daemon-side
// parse boundary. Each vector's expected_error from the fixture must
// match what Decode (or Validate, for the expired case) returns.
func TestVectors_DecodeAndValidate(t *testing.T) {
	fx := loadFixture(t)
	for _, v := range fx.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			tok, err := Decode(v.Token)
			// Decode returns either:
			//   - an *Err with CodeTokenFormat | CodeProtocolVersion (parse-side)
			//   - nil, *Token (decode OK; validate is a separate step)
			expected := ""
			if v.ExpectedError != nil {
				expected = *v.ExpectedError
			}
			switch expected {
			case "":
				// Valid: Decode succeeds; Validate may reject for expiry.
				if err != nil {
					t.Fatalf("Decode returned %v; expected success", err)
				}
				if tok == nil {
					t.Fatal("Decode returned nil token without error")
				}
				// The valid-v1 vector has an expires_at from May 2025 —
				// expect Validate to surface E_TOKEN_EXPIRED at this date.
				vErr := Validate(tok, time.Now())
				if vErr != nil && !IsCode(vErr, CodeTokenExpired) {
					t.Errorf("Validate on valid-v1 returned %v; expected nil or E_TOKEN_EXPIRED", vErr)
				}
			case "E_TOKEN_FORMAT":
				if !IsCode(err, CodeTokenFormat) {
					t.Errorf("got %v; expected CodeTokenFormat", err)
				}
			case "E_PROTOCOL_VERSION":
				if !IsCode(err, CodeProtocolVersion) {
					t.Errorf("got %v; expected CodeProtocolVersion", err)
				}
			case "E_TOKEN_EXPIRED":
				// invalid-expired vector: Decode passes, Validate rejects.
				if err != nil {
					t.Fatalf("Decode returned %v; expected to surface expiry at Validate", err)
				}
				if tok == nil {
					t.Fatal("Decode returned nil token without error")
				}
				vErr := Validate(tok, time.Now())
				if !IsCode(vErr, CodeTokenExpired) {
					t.Errorf("Validate returned %v; expected CodeTokenExpired", vErr)
				}
			default:
				t.Fatalf("test fixture has unknown expected_error %q", expected)
			}
		})
	}
}

// TestPhase3_Success verifies Phase3 builds the request body correctly
// and decodes a well-formed redeem response.
func TestPhase3_Success(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/pairing/redeem", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("got method %s; want POST", r.Method)
		}
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if req["v"].(float64) != 1 {
			t.Errorf("body.v = %v; want 1", req["v"])
		}
		if req["secret"] != "synthetic-secret-32-bytes-test" {
			t.Errorf("body.secret = %v", req["secret"])
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": true,
			"data": map[string]any{
				"v":                1,
				"capability":       "Q0FQQUJJTElUWUJZVEVT", // base64("CAPABILITYBYTES")
				"bucket_reference": "01HBUCKETID",
				"transport_pubkey": "VFJBTlNQT1JUUFVCS0VZ", // base64("TRANSPORTPUBKEY")
				"expires_at":      time.Now().Add(time.Hour).Unix(),
			},
		})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := httpc.New(srv.URL)
	result, err := Phase3(context.Background(), client,
		"synthetic-secret-32-bytes-test",
		"DAEMON-PUBKEY-BASE64URL",
		Fingerprint{Platform: "darwin", Arch: "arm64", Hostname: "test", AgentVersion: "0.0.0-test"},
	)
	if err != nil {
		t.Fatalf("Phase3: %v", err)
	}
	if string(result.Capability) != "CAPABILITYBYTES" {
		t.Errorf("Capability decoded wrong: %q", result.Capability)
	}
	if result.BucketReference != "01HBUCKETID" {
		t.Errorf("BucketReference: %q", result.BucketReference)
	}
	if string(result.TransportPubkey) != "TRANSPORTPUBKEY" {
		t.Errorf("TransportPubkey decoded wrong: %q", result.TransportPubkey)
	}
}

// TestPhase3_ErrorMapping confirms each Hub error code surfaces as the
// right typed *Err code.
func TestPhase3_ErrorMapping(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       map[string]any
		wantCode   Code
	}{
		{"unknown_secret", http.StatusNotFound,
			map[string]any{"ok": false, "error": map[string]any{"code": "token_not_found", "message": "token not recognised"}},
			CodeTokenNotFound},
		{"already_redeemed", http.StatusConflict,
			map[string]any{"ok": false, "error": map[string]any{"code": "token_already_redeemed", "message": "already redeemed"}},
			CodeTokenRedeemed},
		{"expired", http.StatusGone,
			map[string]any{"ok": false, "error": map[string]any{"code": "token_expired", "message": "expired"}},
			CodeTokenExpired},
		{"version", http.StatusUpgradeRequired,
			map[string]any{"ok": false, "error": map[string]any{"code": "protocol_version", "message": "v mismatch"}},
			CodeProtocolVersion},
		{"cancelled", http.StatusNotFound,
			map[string]any{"ok": false, "error": map[string]any{"code": "token_cancelled", "message": "cancelled"}},
			CodeTokenCancelled},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := http.NewServeMux()
			mux.HandleFunc("/v1/pairing/redeem", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(tc.body)
			})
			srv := httptest.NewServer(mux)
			defer srv.Close()

			client := httpc.New(srv.URL)
			_, err := Phase3(context.Background(), client, "secret", "pubkey", Fingerprint{})
			if !IsCode(err, tc.wantCode) {
				t.Errorf("got %v; want code %s", err, tc.wantCode)
			}
		})
	}
}

// TestPhase3_TransportFailure surfaces network-level failures as
// E_TRANSPORT_UNREACHABLE rather than letting them bubble raw.
func TestPhase3_TransportFailure(t *testing.T) {
	// Point the client at a closed port.
	client := httpc.New("http://127.0.0.1:1") // reserved/closed
	_, err := Phase3(context.Background(), client, "secret", "pubkey", Fingerprint{})
	if !IsCode(err, CodeTransportFailure) {
		t.Errorf("got %v; want CodeTransportFailure", err)
	}
}
