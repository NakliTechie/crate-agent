// SPDX-License-Identifier: AGPL-3.0-or-later
package manifest

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/NakliTechie/crate-agent/internal/payload"
)

func newMasterKey(t *testing.T) []byte {
	t.Helper()
	b, err := payload.RandomBytes(payload.KeySize)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestAppendAndVerifyRoundTrip(t *testing.T) {
	mk := newMasterKey(t)
	m := New()

	if _, err := m.Append(CreateEvent("u1", "/a.txt", 100, "text/plain",
		[]byte("iv-aaaa-aaaa"), []byte("ct----------------"), []byte("civ-bbbb-bbb")), mk); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Append(UpdateEvent("u1", 200, []byte("civ-cccc-cccc")), mk); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Append(MoveEvent("u1", "/b.txt"), mk); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Append(MkdirEvent("/folder/"), mk); err != nil {
		t.Fatal(err)
	}
	if m.Size() != 4 {
		t.Fatalf("Size = %d, want 4", m.Size())
	}
	ok, idx, reason := m.Verify(mk)
	if !ok {
		t.Fatalf("Verify failed at %d: %s", idx, reason)
	}
}

func TestVerifyRejectsTamperedSig(t *testing.T) {
	mk := newMasterKey(t)
	m := New()
	_, _ = m.Append(CreateEvent("u1", "/a.txt", 1, "", []byte("iv-aaaa-aaaa"), []byte("ct----------------"), []byte("civ-bbbb-bbb")), mk)
	// Tamper with the sig.
	sig, _ := m.events[0]["sig"].(string)
	m.events[0]["sig"] = base64.StdEncoding.EncodeToString([]byte("wrong-sig-bytes-xx"))
	_ = sig
	ok, _, reason := m.Verify(mk)
	if ok {
		t.Errorf("Verify should reject tampered sig")
	}
	if reason == "" {
		t.Errorf("expected non-empty reason")
	}
}

func TestVerifyRejectsBrokenChain(t *testing.T) {
	mk := newMasterKey(t)
	m := New()
	_, _ = m.Append(CreateEvent("u1", "/a.txt", 1, "", []byte("iv-aaaa-aaaa"), []byte("ct----------------"), []byte("civ-bbbb-bbb")), mk)
	_, _ = m.Append(DeleteEvent("u1"), mk)
	// Break the chain.
	m.events[1]["prev_sig"] = "deadbeef"
	ok, idx, _ := m.Verify(mk)
	if ok || idx != 1 {
		t.Errorf("expected chain break at idx 1; got ok=%v idx=%d", ok, idx)
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	mk := newMasterKey(t)
	m := New()
	_, _ = m.Append(CreateEvent("u1", "/a.txt", 1, "text/plain",
		[]byte("iv-aaaa-aaaa"), []byte("ct----------------"), []byte("civ-bbbb-bbb")), mk)
	_, _ = m.Append(CreateEvent("u2", "/folder/b.md", 200, "text/markdown",
		[]byte("iv-ccc-cccc-"), []byte("ct----------------"), []byte("civ-ddddddd-")), mk)
	ct, err := m.EncryptToBytes(mk)
	if err != nil {
		t.Fatal(err)
	}
	m2, err := LoadFromBytes(ct, mk)
	if err != nil {
		t.Fatal(err)
	}
	if m2.Size() != 2 {
		t.Fatalf("decoded Size = %d, want 2", m2.Size())
	}
	ok, _, reason := m2.Verify(mk)
	if !ok {
		t.Errorf("Verify after round-trip failed: %s", reason)
	}
}

func TestDecryptRejectsWrongKey(t *testing.T) {
	mk1 := newMasterKey(t)
	mk2 := newMasterKey(t)
	m := New()
	_, _ = m.Append(DeleteEvent("u1"), mk1)
	ct, _ := m.EncryptToBytes(mk1)
	if _, err := LoadFromBytes(ct, mk2); err == nil {
		t.Errorf("LoadFromBytes with wrong key should fail")
	}
}

func TestDecryptRejectsTruncated(t *testing.T) {
	mk := newMasterKey(t)
	m := New()
	_, _ = m.Append(DeleteEvent("u1"), mk)
	ct, _ := m.EncryptToBytes(mk)
	// Truncate.
	if _, err := LoadFromBytes(ct[:5], mk); err == nil {
		t.Errorf("LoadFromBytes truncated should fail")
	}
}

func TestMaterialise(t *testing.T) {
	mk := newMasterKey(t)
	m := New()
	_, _ = m.Append(CreateEvent("u1", "/a.txt", 100, "text/plain",
		[]byte("iv-aaaa-aaaa"), []byte("ct----------------"), []byte("civ-bbbb-bbb")), mk)
	_, _ = m.Append(CreateEvent("u2", "/notes/b.md", 200, "text/markdown",
		[]byte("iv-ccc-cccc-"), []byte("ct----------------"), []byte("civ-ddddddd-")), mk)
	_, _ = m.Append(UpdateEvent("u1", 150, []byte("civ-newer-..")), mk)
	_, _ = m.Append(MoveEvent("u1", "/a-renamed.txt"), mk)
	_, _ = m.Append(MkdirEvent("/empty/"), mk)

	tree := m.Materialise()
	if e, ok := tree["/a.txt"]; ok {
		t.Errorf("/a.txt should be moved away; got %+v", e)
	}
	a, ok := tree["/a-renamed.txt"]
	if !ok || a.Size != 150 {
		t.Errorf("/a-renamed.txt expected at size 150; got %+v", a)
	}
	b, ok := tree["/notes/b.md"]
	if !ok || b.Size != 200 || b.Mime != "text/markdown" {
		t.Errorf("/notes/b.md missing or wrong: %+v", b)
	}
	d, ok := tree["/empty/"]
	if !ok || !d.IsDir {
		t.Errorf("/empty/ folder missing or not IsDir: %+v", d)
	}
}

func TestMaterialiseDelete(t *testing.T) {
	mk := newMasterKey(t)
	m := New()
	_, _ = m.Append(CreateEvent("u1", "/x.txt", 1, "", []byte("iv-aaaa-aaaa"), []byte("ct----------------"), []byte("civ-bbbb-bbb")), mk)
	_, _ = m.Append(DeleteEvent("u1"), mk)
	tree := m.Materialise()
	if _, ok := tree["/x.txt"]; ok {
		t.Errorf("/x.txt should be deleted")
	}
}

func TestForwardCompatTolerateUnknownOp(t *testing.T) {
	mk := newMasterKey(t)
	m := New()
	// Smuggle an unknown op past Append by direct append (Append would
	// validateShape away from unknowns — but Verify + Materialise should
	// tolerate them).
	evt := Event{
		"v":        float64(EventV),
		"ts":       float64(123),
		"op":       "future-op-not-yet-spec'd",
		"prev_sig": "",
	}
	sig, err := signEvent(evt, mk)
	if err != nil {
		t.Fatal(err)
	}
	evt["sig"] = sig
	m.events = append(m.events, evt)
	m.lastSig = sig
	ok, _, reason := m.Verify(mk)
	if !ok {
		t.Errorf("Verify should tolerate unknown op: %s", reason)
	}
	tree := m.Materialise()
	if len(tree) != 0 {
		t.Errorf("unknown op should not surface in tree")
	}
}

func TestEmptyManifest(t *testing.T) {
	mk := newMasterKey(t)
	m := New()
	ct, err := m.EncryptToBytes(mk)
	if err != nil {
		t.Fatal(err)
	}
	m2, err := LoadFromBytes(ct, mk)
	if err != nil {
		t.Fatal(err)
	}
	if m2.Size() != 0 {
		t.Errorf("empty manifest round-trip Size = %d, want 0", m2.Size())
	}
	if _, err := LoadFromBytes(nil, mk); err != nil {
		t.Errorf("LoadFromBytes(nil) should not error: %v", err)
	}
}

func TestPathConstant(t *testing.T) {
	if Path != ".crate/manifest.jsonl.enc" {
		t.Errorf("Path drift: %q", Path)
	}
	// Defensive: confirm package can be re-imported through bytes-roundtrip-test
	_ = bytes.Equal
}
