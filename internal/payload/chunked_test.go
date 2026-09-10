// SPDX-License-Identifier: AGPL-3.0-or-later
package payload

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

const cs int64 = 1024 // small chunk so multi-chunk cases stay fast

func pattern(n int, seed byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(i*31) + seed
	}
	return out
}

func mustKey(t *testing.T) []byte {
	t.Helper()
	k, err := RandomDataKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestChunkCount(t *testing.T) {
	cases := []struct{ size, want int64 }{{0, 1}, {1, 1}, {cs, 1}, {cs + 1, 2}, {5 * cs, 5}}
	for _, c := range cases {
		got, err := ChunkCount(c.size, cs)
		if err != nil || got != c.want {
			t.Errorf("ChunkCount(%d) = %d, %v; want %d", c.size, got, err, c.want)
		}
	}
	if _, err := ChunkCount(-1, cs); err == nil {
		t.Error("negative size accepted")
	}
	if _, err := ChunkCount(1, 0); err == nil {
		t.Error("zero chunk size accepted")
	}
	if ChunkSize < 5<<20 {
		t.Errorf("ChunkSize %d below R2's 5 MiB minimum part size", ChunkSize)
	}
}

func TestSealOpenObjectRoundTrips(t *testing.T) {
	key := mustKey(t)
	for _, n := range []int64{0, 1, cs - 1, cs, cs + 1, 3 * cs, 3*cs + 17} {
		uuid := "01ROUNDTRIP"
		pt := pattern(int(n), 7)
		civ, body, err := SealObject(key, pt, uuid, cs)
		if err != nil {
			t.Fatalf("n=%d seal: %v", n, err)
		}
		total, _ := ChunkCount(n, cs)
		if want := n + total*(IVSize+TagSize); int64(len(body)) != want {
			t.Errorf("n=%d body len %d, want %d", n, len(body), want)
		}
		if !bytes.Equal(body[:IVSize], civ) {
			t.Errorf("n=%d leading IV is not contentIV", n)
		}
		got, err := OpenObject(key, body, uuid, n, civ, cs)
		if err != nil {
			t.Fatalf("n=%d open: %v", n, err)
		}
		if !bytes.Equal(got, pt) {
			t.Errorf("n=%d round-trip mismatch", n)
		}
	}
}

func TestOpenObjectRejectsTamper(t *testing.T) {
	key, key2 := mustKey(t), mustKey(t)
	const uuid = "01TAMPER"
	n := 4 * cs
	stride := cs + IVSize + TagSize
	pt := pattern(int(n), 7)
	civ, body, err := SealObject(key, pt, uuid, cs)
	if err != nil {
		t.Fatal(err)
	}
	chunk := func(b []byte, i int64) []byte { return b[i*stride : (i+1)*stride] }
	open := func(b []byte, u string, size int64, iv []byte, c int64) error {
		_, err := OpenObject(key, b, u, size, iv, c)
		return err
	}
	expect := func(name string, err error, substr string) {
		t.Helper()
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if !strings.Contains(err.Error(), substr) {
			t.Errorf("%s: %v (want %q)", name, err, substr)
		}
	}

	// reorder chunks 1 and 2
	b := append([]byte(nil), body...)
	c1, c2 := append([]byte(nil), chunk(body, 1)...), append([]byte(nil), chunk(body, 2)...)
	copy(b[1*stride:], c2)
	copy(b[2*stride:], c1)
	expect("reorder", open(b, uuid, n, civ, cs), "chunk 1 of 4 failed")

	// truncate — length check fires before any decryption
	expect("truncate", open(body[:3*stride], uuid, n, civ, cs), "does not match manifest")

	// extend
	expect("extend", open(append(append([]byte(nil), body...), 0), uuid, n, civ, cs), "does not match manifest")

	// bit flip in chunk 2
	b = append([]byte(nil), body...)
	b[2*stride+IVSize+5] ^= 1
	expect("bit flip", open(b, uuid, n, civ, cs), "chunk 2 of 4 failed")

	// cross-file splice: chunk 1 from another file at the same index
	_, other, _ := SealObject(key, pattern(int(n), 99), "01OTHER", cs)
	b = append([]byte(nil), body...)
	copy(b[1*stride:], chunk(other, 1))
	expect("cross-file splice", open(b, uuid, n, civ, cs), "chunk 1 of 4 failed")

	// cross-VERSION splice: same uuid, same key, same index, older write.
	// The case single-blob AAD=uuid never had to defend; IV_0 in the AAD is
	// what rejects it.
	_, older, _ := SealObject(key, pattern(int(n), 3), uuid, cs)
	b = append([]byte(nil), body...)
	copy(b[2*stride:], chunk(older, 2))
	expect("cross-version splice", open(b, uuid, n, civ, cs), "chunk 2 of 4 failed")

	// full rollback: entire older body under the current entry
	expect("rollback anchor", open(older, uuid, n, civ, cs), "does not match manifest content_iv")

	// total is bound: 3 chunks sealed under n=3, grafted to 4 and presented as size 4*cs
	civ3, three, _ := SealObject(key, pattern(int(3*cs), 5), uuid, cs)
	grafted := append(append([]byte(nil), three...), chunk(body, 3)...)
	expect("total bound", open(grafted, uuid, n, civ3, cs), "chunk 0 of 4 failed")

	// wrong key / uuid / chunk_size / malformed
	if _, err := OpenObject(key2, body, uuid, n, civ, cs); err == nil {
		t.Error("wrong key accepted")
	}
	expect("wrong uuid", open(body, "01ELSE", n, civ, cs), "failed authentication")
	expect("wrong chunk_size", open(body, uuid, n, civ, 2*cs), "does not match manifest")
	expect("missing content_iv", open(body, uuid, n, nil, cs), "requires a 12-byte content_iv")
	expect("negative chunk_size", open(body, uuid, n, civ, -1), "chunk_size -1 invalid")
	expect("short body", open([]byte{1, 2, 3}, uuid, n, civ, cs), "too short")
}

func TestOpenObjectV1Compat(t *testing.T) {
	key := mustKey(t)
	const uuid = "01LEGACY"
	pt := pattern(3000, 1)
	iv, body, err := SealFilePayload(key, pt, uuid)
	if err != nil {
		t.Fatal(err)
	}
	got, err := OpenObject(key, body, uuid, int64(len(pt)), iv, 0)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("v1 with content_iv: %v", err)
	}
	// pre-audit v1 entry without content_iv still opens
	if got, err := OpenObject(key, body, uuid, int64(len(pt)), nil, 0); err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("v1 without content_iv: %v", err)
	}
	// v1 rollback: a different write of the same uuid under this entry's IV
	_, body2, _ := SealFilePayload(key, pt, uuid)
	if _, err := OpenObject(key, body2, uuid, int64(len(pt)), iv, 0); err == nil {
		t.Error("v1 rollback accepted — puller previously had no anchor at all")
	}
	// a v1 body presented as v2 fails the length check
	if _, err := OpenObject(key, body, uuid, int64(len(pt)), iv, cs); err == nil {
		t.Error("v1 body under v2 entry accepted")
	}
}

func TestChunkAADCanonicalForm(t *testing.T) {
	iv, _ := RandomIV()
	want := "01ABC:" + base64.StdEncoding.EncodeToString(iv) + ":3:7"
	if got := string(ChunkAAD("01ABC", iv, 3, 7)); got != want {
		t.Errorf("ChunkAAD = %q, want %q", got, want)
	}
}
