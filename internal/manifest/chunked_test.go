// SPDX-License-Identifier: AGPL-3.0-or-later
package manifest

import "testing"

func TestChunkSizeCarriedPerVersion(t *testing.T) {
	mk := newMasterKey(t)
	m := New()
	iv, ct, civ := []byte("iv-aaaa-aaaa"), []byte("ct----------------"), []byte("civ-bbbb-bbb")

	// v1 events never carry the key
	if _, ok := CreateEvent("x", "/x", 1, "", iv, ct, civ)["chunk_size"]; ok {
		t.Fatal("CreateEvent emitted chunk_size without WithChunkSize")
	}
	if _, ok := WithChunkSize(UpdateEvent("x", 1, civ), 0)["chunk_size"]; ok {
		t.Fatal("WithChunkSize(0) emitted chunk_size")
	}

	_, _ = m.Append(WithChunkSize(CreateEvent("v2", "/big.bin", 10, "", iv, ct, civ), 8), mk)
	_, _ = m.Append(CreateEvent("v1", "/old.bin", 10, "", iv, ct, civ), mk)

	loaded, err := LoadFromBytes(mustEncrypt(t, m, mk), mk)
	if err != nil {
		t.Fatal(err)
	}
	tree := loaded.Materialise()
	if tree["/big.bin"].ChunkSize != 8 {
		t.Errorf("v2 ChunkSize = %d, want 8", tree["/big.bin"].ChunkSize)
	}
	if tree["/old.bin"].ChunkSize != 0 {
		t.Errorf("v1 ChunkSize = %d, want 0", tree["/old.bin"].ChunkSize)
	}

	// per-version: v1 update reverts, v2 update promotes
	_, _ = loaded.Append(UpdateEvent("v2", 12, civ), mk)
	_, _ = loaded.Append(WithChunkSize(UpdateEvent("v1", 12, civ), 4), mk)
	tree = loaded.Materialise()
	if tree["/big.bin"].ChunkSize != 0 {
		t.Errorf("update without chunk_size did not revert to v1: %d", tree["/big.bin"].ChunkSize)
	}
	if tree["/old.bin"].ChunkSize != 4 {
		t.Errorf("update with chunk_size did not promote: %d", tree["/old.bin"].ChunkSize)
	}
}

func TestChunkSizeValidated(t *testing.T) {
	mk := newMasterKey(t)
	iv, ct, civ := []byte("iv-aaaa-aaaa"), []byte("ct----------------"), []byte("civ-bbbb-bbb")
	for _, bad := range []interface{}{float64(0), float64(-1), 1.5, "8"} {
		m := New()
		evt := CreateEvent("x", "/x", 1, "", iv, ct, civ)
		evt["chunk_size"] = bad
		if _, err := m.Append(evt, mk); err == nil {
			t.Errorf("chunk_size=%v accepted at append", bad)
		}
	}
}

func mustEncrypt(t *testing.T, m *Manifest, mk []byte) []byte {
	t.Helper()
	b, err := m.EncryptToBytes(mk)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
