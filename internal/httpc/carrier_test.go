// SPDX-License-Identifier: AGPL-3.0-or-later
package httpc

import (
	"net/http"
	"net/url"
	"testing"
)

// The signature vector below was produced by the browser's lib/bucket.js
// carrierHeaders() for the same inputs; the daemon must reproduce it.
const browserSig = "4e3a9612339c55ad3b8d626d8d0aff148af6a87f5d6b9202356f276a121146f3"

func TestCarrierSignMatchesBrowser(t *testing.T) {
	u, _ := url.Parse("https://w.example.workers.dev/o/objects/01ABC?mpu=part&uploadId=u1&n=3")
	h := carrierSign("test-secret", "PUT", u.EscapedPath(), u.Query(), "1700000000000", "n1")
	if h["x-crate-sig"] != browserSig {
		t.Fatalf("sig %s, browser produced %s", h["x-crate-sig"], browserSig)
	}
	if got := carrierCanonical("put", "/o/a", url.Values{"b": {"2"}, "a": {"1"}}, "5", "z"); got != "PUT\n/o/a\na=1&b=2\n5\nz" {
		t.Fatalf("canonical %q", got)
	}
}

func TestCarrierClientPathsAndHeaders(t *testing.T) {
	c := NewCarrier("https://w.example.workers.dev/", "s")
	if !c.IsCarrier() || c.objectPath("ignored", ".crate/manifest.jsonl.enc") != "/o/.crate/manifest.jsonl.enc" {
		t.Fatalf("objectPath: %s", c.objectPath("ignored", ".crate/manifest.jsonl.enc"))
	}
	req, _ := http.NewRequest(http.MethodGet, "https://w.example.workers.dev/o/objects/01X", nil)
	c.setAuthHeaders(req, "capability-ignored")
	for _, k := range []string{"x-crate-ts", "x-crate-nonce", "x-crate-sig"} {
		if req.Header.Get(k) == "" {
			t.Errorf("missing %s", k)
		}
	}
	if req.Header.Get("X-Fabric-Grant") != "" {
		t.Error("carrier client must not send X-Fabric-Grant")
	}
	hub := New("http://127.0.0.1:1")
	if hub.IsCarrier() || hub.objectPath("b1", "k") != "/v1/crate/object/b1/k" {
		t.Fatalf("hub objectPath: %s", hub.objectPath("b1", "k"))
	}
	if NewFor(TransportCarrier, "https://x", "s").IsCarrier() != true || NewFor("hub", "https://x", "").IsCarrier() {
		t.Fatal("NewFor")
	}
}

func TestEnvelopeErrorAcceptsString(t *testing.T) {
	var e Envelope
	if err := jsonUnmarshal([]byte(`{"ok":false,"error":"unauthorized: bad signature"}`), &e); err != nil {
		t.Fatal(err)
	}
	if e.OK || e.Error == nil || e.Error.Message != "unauthorized: bad signature" || e.Error.Code != "carrier" {
		t.Fatalf("%+v", e)
	}
	var h Envelope
	if err := jsonUnmarshal([]byte(`{"ok":false,"error":{"code":"E1","message":"m"}}`), &h); err != nil || h.Error.Code != "E1" {
		t.Fatalf("hub shape: %v %+v", err, h)
	}
}

func TestCarrierWithoutSecretStillRoutesAsCarrier(t *testing.T) {
	c := NewFor(TransportCarrier, "https://w.example.workers.dev", "")
	if !c.IsCarrier() {
		t.Fatal("transport type, not secret presence, decides carrier routing (doctor health check)")
	}
	req, _ := http.NewRequest(http.MethodGet, "https://w.example.workers.dev/health", nil)
	c.setAuthHeaders(req, "")
	if req.Header.Get("x-crate-sig") != "" || req.Header.Get("X-Fabric-Grant") != "" {
		t.Fatal("no secret ⇒ no auth headers of either kind")
	}
}
