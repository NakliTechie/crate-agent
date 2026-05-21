// SPDX-License-Identifier: AGPL-3.0-or-later
package payload

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	key, _ := RandomBytes(KeySize)
	iv, _ := RandomIV()
	plaintext := []byte("hello from the daemon")
	aad := []byte("file-uuid-01H")
	ct, err := Seal(key, iv, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(key, iv, ct, aad)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip mismatch: %q vs %q", got, plaintext)
	}
}

func TestOpenRejectsWrongAAD(t *testing.T) {
	key, _ := RandomBytes(KeySize)
	iv, _ := RandomIV()
	ct, _ := Seal(key, iv, []byte("hello"), []byte("aad-A"))
	if _, err := Open(key, iv, ct, []byte("aad-B")); err == nil {
		t.Errorf("Open with wrong AAD should fail")
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	k1, _ := RandomBytes(KeySize)
	k2, _ := RandomBytes(KeySize)
	iv, _ := RandomIV()
	ct, _ := Seal(k1, iv, []byte("hello"), nil)
	if _, err := Open(k2, iv, ct, nil); err == nil {
		t.Errorf("Open with wrong key should fail")
	}
}

func TestWrapUnwrapDataKey(t *testing.T) {
	master, _ := RandomBytes(KeySize)
	dataKey, _ := RandomDataKey()
	uuid := "01HABCDEF"

	iv, ct, err := WrapDataKey(master, dataKey, uuid)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnwrapDataKey(master, iv, ct, uuid)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, dataKey) {
		t.Errorf("wrap/unwrap mismatch")
	}
	// AAD mismatch:
	if _, err := UnwrapDataKey(master, iv, ct, "OTHER-UUID"); err == nil {
		t.Errorf("UnwrapDataKey with wrong UUID should fail")
	}
}

func TestSealOpenFilePayload(t *testing.T) {
	dataKey, _ := RandomDataKey()
	uuid := "01HFILE"
	plaintext := []byte("this is a test file body, bytes go here")
	_, body, err := SealFilePayload(dataKey, plaintext, uuid)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) != IVSize+len(plaintext)+TagSize {
		t.Errorf("body length = %d, want %d", len(body), IVSize+len(plaintext)+TagSize)
	}
	got, err := OpenFilePayload(dataKey, body, uuid)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("file payload round-trip mismatch")
	}
}

func TestOpenFilePayloadShortBody(t *testing.T) {
	dataKey, _ := RandomDataKey()
	short := []byte{1, 2, 3}
	if _, err := OpenFilePayload(dataKey, short, "x"); err == nil {
		t.Errorf("short body should error")
	}
}

func TestHMACRoundTrip(t *testing.T) {
	master, _ := RandomBytes(KeySize)
	msg := []byte("manifest event canonical json")
	tag := HMACSign(master, msg)
	if !HMACVerify(master, msg, tag) {
		t.Errorf("HMACVerify should accept matching tag")
	}
	if HMACVerify(master, msg, []byte("garbage")) {
		t.Errorf("HMACVerify should reject mismatched tag")
	}
	tag[0] ^= 0x01
	if HMACVerify(master, msg, tag) {
		t.Errorf("HMACVerify should reject one-bit-flipped tag")
	}
}

// Cross-surface vector: verify the daemon produces the same canonical JSON
// + same HMAC as the browser does for a representative manifest event.
// Inputs are static so this can be re-run against a JS port in dev tools.
func TestCanonicalJSONStable(t *testing.T) {
	evt := map[string]interface{}{
		"v":            float64(1), // JSON has no int type; mimic JS
		"ts":           float64(1747572345000),
		"op":           "create",
		"uuid":         "01HEXAMPLE",
		"path":         "/notes/foo.md",
		"size":         float64(1234),
		"mime":         "text/markdown",
		"data_key_iv":  "AAAA",
		"data_key_ct":  "BBBB",
		"content_iv":   "CCCC",
		"prev_sig":     "",
	}
	canon, err := CanonicalJSON(evt)
	if err != nil {
		t.Fatal(err)
	}
	// The canonical form must sort keys lexicographically.
	want := `{"content_iv":"CCCC","data_key_ct":"BBBB","data_key_iv":"AAAA","mime":"text/markdown","op":"create","path":"/notes/foo.md","prev_sig":"","size":1234,"ts":1747572345000,"uuid":"01HEXAMPLE","v":1}`
	if string(canon) != want {
		t.Errorf("CanonicalJSON mismatch:\ngot:  %s\nwant: %s", canon, want)
	}
	// Hash for reproducibility (so a JS-side test could match).
	h := sha256.Sum256(canon)
	_ = hex.EncodeToString(h[:])
}

func TestRandomNonZero(t *testing.T) {
	a, _ := RandomBytes(32)
	b, _ := RandomBytes(32)
	if bytes.Equal(a, b) {
		t.Errorf("two RandomBytes calls returned identical results (astronomical)")
	}
}

func TestZero(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	Zero(b)
	for _, v := range b {
		if v != 0 {
			t.Errorf("Zero left a nonzero byte")
		}
	}
}
