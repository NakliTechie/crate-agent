// SPDX-License-Identifier: AGPL-3.0-or-later
// Package payload implements the AES-256-GCM payload encryption +
// HMAC-SHA256 manifest signing used by Crate at M3.
//
// MATCHES the browser's lib/crypto.js byte-for-byte:
//   - AES-256-GCM with 12-byte random IV (NOT the XChaCha20-Poly1305 with
//     24-byte nonce used elsewhere in fabric-sdk-go; the browser surface
//     uses AES-GCM via SubtleCrypto, so cross-surface interop dictates
//     AES-GCM here).
//   - Per-file random data key (32 bytes) wrapped under master key via
//     AES-GCM with the file UUID as AAD.
//   - HMAC-SHA256 over canonical-JSON (lex-sorted keys) for manifest sig.
//
// Object body layouts (both readable; v2 is what every write produces):
//
//	v1 (single blob):  IV(12) || AES-GCM(dataKey, plaintext, AAD=uuid)
//	v2 (chunked):      chunk_0 || chunk_1 || … || chunk_{n-1}
//	                   chunk_i = IV_i(12) || AES-GCM(dataKey, plaintext_i, AAD_i)
//	                   AAD_i   = "<uuid>:<base64(IV_0)>:<i>:<n>"
//	                   n       = ceil(size / chunk_size), minimum 1
//
// A manifest entry is v2 iff it carries chunk_size (inside the HMAC-signed
// event). See SealObject / OpenObject below and the browser's
// lib/crypto.js, which this file MATCHES byte-for-byte.
//
// (Go's AEAD interface appends the tag to ciphertext automatically; the
// browser's SubtleCrypto does the same. Layouts are identical.)
package payload

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

const (
	KeySize    = 32 // 256-bit AES-GCM key
	IVSize     = 12 // AES-GCM nonce
	TagSize    = 16 // GCM auth tag
	DataKeyLen = 32
)

// --- random ----------------------------------------------------------------

func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("payload: random: %w", err)
	}
	return b, nil
}

func RandomIV() ([]byte, error)      { return RandomBytes(IVSize) }
func RandomDataKey() ([]byte, error) { return RandomBytes(DataKeyLen) }

// Zero wipes a byte slice. Use after a key is no longer needed.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// --- AES-256-GCM seal/open -------------------------------------------------

// Seal encrypts plaintext with AES-256-GCM. aad may be nil. Returns the
// ciphertext (auth tag appended; matches the browser's SubtleCrypto layout).
func Seal(key, iv, plaintext, aad []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("payload: key length %d, want %d", len(key), KeySize)
	}
	if len(iv) != IVSize {
		return nil, fmt.Errorf("payload: iv length %d, want %d", len(iv), IVSize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("payload: aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("payload: NewGCM: %w", err)
	}
	return aead.Seal(nil, iv, plaintext, aad), nil
}

// Open decrypts ciphertext produced by Seal. aad MUST match what Seal
// received. Returns an error on auth-tag mismatch (wrong key, tamper,
// wrong aad, wrong iv).
func Open(key, iv, ciphertext, aad []byte) ([]byte, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("payload: key length %d, want %d", len(key), KeySize)
	}
	if len(iv) != IVSize {
		return nil, fmt.Errorf("payload: iv length %d, want %d", len(iv), IVSize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("payload: aes.NewCipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("payload: NewGCM: %w", err)
	}
	return aead.Open(nil, iv, ciphertext, aad)
}

// --- per-file data-key wrapping --------------------------------------------

// WrapDataKey seals dataKey under masterKey with a fresh IV. fileUUID is
// bound as AAD. Returns (iv, ciphertext).
func WrapDataKey(masterKey, dataKey []byte, fileUUID string) ([]byte, []byte, error) {
	if len(dataKey) == 0 {
		return nil, nil, errors.New("payload: empty dataKey")
	}
	if fileUUID == "" {
		return nil, nil, errors.New("payload: empty fileUUID (AAD required)")
	}
	iv, err := RandomIV()
	if err != nil {
		return nil, nil, err
	}
	ct, err := Seal(masterKey, iv, dataKey, []byte(fileUUID))
	if err != nil {
		return nil, nil, err
	}
	return iv, ct, nil
}

// UnwrapDataKey is the inverse of WrapDataKey.
func UnwrapDataKey(masterKey, iv, ciphertext []byte, fileUUID string) ([]byte, error) {
	if fileUUID == "" {
		return nil, errors.New("payload: empty fileUUID (AAD required)")
	}
	return Open(masterKey, iv, ciphertext, []byte(fileUUID))
}

// --- v1.1 content-key wrap (KEK → master key) ------------------------------
//
// In v1.1, the master/content key is RANDOM (not derived) and stored
// AES-256-GCM-wrapped under one or more KEKs in .crate/crate.json. The
// wrap is self-contained — no AAD — so any KEK can unwrap independently.
// Matches the browser's lib/crypto.js::wrapKey/unwrapKey byte-for-byte.
//
// Wrapped ciphertext layout: 32-byte wrapped key + 16-byte GCM auth tag
// (48 bytes total). IV is 12 bytes, stored alongside in the wrap slot.

// WrapKey seals a 32-byte content key under a KEK with a fresh IV. No AAD.
// Returns (iv, ciphertext). ciphertext is exactly 48 bytes.
func WrapKey(kek, contentKey []byte) ([]byte, []byte, error) {
	if len(kek) != KeySize {
		return nil, nil, fmt.Errorf("payload.WrapKey: kek length %d, want %d", len(kek), KeySize)
	}
	if len(contentKey) != KeySize {
		return nil, nil, fmt.Errorf("payload.WrapKey: contentKey length %d, want %d", len(contentKey), KeySize)
	}
	iv, err := RandomIV()
	if err != nil {
		return nil, nil, err
	}
	ct, err := Seal(kek, iv, contentKey, nil)
	if err != nil {
		return nil, nil, err
	}
	return iv, ct, nil
}

// UnwrapKey opens a v1.1 wrap slot. Returns the 32-byte content key on
// success. Errors on AES-GCM auth-tag mismatch (wrong KEK or tampered
// ciphertext) — callers treating that as "wrong passphrase" should map
// the error appropriately.
func UnwrapKey(kek, iv, ciphertext []byte) ([]byte, error) {
	if len(kek) != KeySize {
		return nil, fmt.Errorf("payload.UnwrapKey: kek length %d, want %d", len(kek), KeySize)
	}
	if len(ciphertext) != KeySize+TagSize {
		return nil, fmt.Errorf("payload.UnwrapKey: ciphertext length %d, want %d (key + GCM tag)", len(ciphertext), KeySize+TagSize)
	}
	out, err := Open(kek, iv, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	if len(out) != KeySize {
		return nil, fmt.Errorf("payload.UnwrapKey: unwrapped length %d, want %d", len(out), KeySize)
	}
	return out, nil
}

// SealFilePayload produces the LEGACY v1 single-blob body. Writers use
// SealObject; this remains so tests can fabricate v1 objects for the
// read-compat path.
func SealFilePayload(dataKey, plaintext []byte, fileUUID string) ([]byte, []byte, error) {
	iv, err := RandomIV()
	if err != nil {
		return nil, nil, err
	}
	ct, err := Seal(dataKey, iv, plaintext, []byte(fileUUID))
	if err != nil {
		return nil, nil, err
	}
	body := make([]byte, len(iv)+len(ct))
	copy(body, iv)
	copy(body[len(iv):], ct)
	return iv, body, nil
}

// OpenFilePayload decrypts a v1 single-blob body. Callers should go
// through OpenObject, which adds the content_iv anchor and v2 dispatch.
func OpenFilePayload(dataKey, body []byte, fileUUID string) ([]byte, error) {
	if len(body) < IVSize+TagSize {
		return nil, fmt.Errorf("payload: body too short (%d < %d)", len(body), IVSize+TagSize)
	}
	iv := body[:IVSize]
	ct := body[IVSize:]
	return Open(dataKey, iv, ct, []byte(fileUUID))
}

// --- v2 chunked object framing ----------------------------------------------
//
// Why every AAD field is load-bearing (mirrors lib/crypto.js):
//   uuid  — a chunk from another file at the same index fails.
//   IV_0  — a chunk from an OLDER VERSION of the same file at the same
//           index fails. IV_0 is random per write and is the manifest-signed
//           content_iv, so every chunk is bound to the version it was
//           written in. Single-blob AAD=uuid never needed this; per-chunk
//           framing does.
//   i     — reorder fails.
//   n     — truncation / extension fails, and so does a chunk sealed under
//           a different total.
// Chunk 0's own IV is IV_0, so content_iv keeps meaning "the object's
// leading 12 bytes" for both formats and the rollback anchor (browser
// 2026-05 audit H1) reads identically.

// ChunkSize is the plaintext bytes per chunk for objects this daemon
// writes. The value is recorded in the manifest, never assumed on read,
// so the browser and daemon may differ.
const ChunkSize int64 = 8 << 20

// ChunkCount is ceil(size / chunkSize), minimum 1. An empty file is one
// authenticated empty chunk, so "zero chunks" is never a valid object.
func ChunkCount(size, chunkSize int64) (int64, error) {
	if size < 0 {
		return 0, fmt.Errorf("payload: size %d must be non-negative", size)
	}
	if chunkSize <= 0 {
		return 0, fmt.Errorf("payload: chunk size %d must be positive", chunkSize)
	}
	n := (size + chunkSize - 1) / chunkSize
	if n < 1 {
		n = 1
	}
	return n, nil
}

// ChunkAAD is the canonical per-chunk AAD. Plain ASCII, standard padded
// base64 — identical bytes to the browser's chunkAAD.
func ChunkAAD(uuid string, contentIV []byte, index, total int64) []byte {
	return []byte(fmt.Sprintf("%s:%s:%d:%d", uuid, base64.StdEncoding.EncodeToString(contentIV), index, total))
}

// SealObject encrypts plaintext into a v2 object body. Returns
// (contentIV, body); contentIV is chunk 0's IV and must be recorded in the
// manifest as content_iv alongside chunkSize.
func SealObject(dataKey, plaintext []byte, uuid string, chunkSize int64) ([]byte, []byte, error) {
	if uuid == "" {
		return nil, nil, errors.New("payload: SealObject requires uuid")
	}
	total, err := ChunkCount(int64(len(plaintext)), chunkSize)
	if err != nil {
		return nil, nil, err
	}
	aead, err := newGCM(dataKey)
	if err != nil {
		return nil, nil, err
	}
	contentIV, err := RandomIV()
	if err != nil {
		return nil, nil, err
	}
	body := make([]byte, 0, int64(len(plaintext))+total*(IVSize+TagSize))
	for i := int64(0); i < total; i++ {
		iv := contentIV
		if i > 0 {
			if iv, err = RandomIV(); err != nil {
				return nil, nil, err
			}
		}
		lo := i * chunkSize
		hi := lo + chunkSize
		if hi > int64(len(plaintext)) {
			hi = int64(len(plaintext))
		}
		body = append(body, iv...)
		body = aead.Seal(body, iv, plaintext[lo:hi], ChunkAAD(uuid, contentIV, i, total))
	}
	return contentIV, body, nil
}

// OpenObject decrypts an object body using its manifest entry, dispatching
// on chunkSize: 0 means the legacy v1 single-blob layout. Before any
// decryption it enforces that the body's leading IV equals the
// manifest-signed contentIV (the rollback anchor) and, for v2, that the
// body length is exactly what size and chunkSize predict. contentIV may
// be nil only for v1 entries written before the browser's 2026-05 audit
// added the field; it is mandatory for v2.
func OpenObject(dataKey, body []byte, uuid string, size int64, contentIV []byte, chunkSize int64) ([]byte, error) {
	if uuid == "" {
		return nil, errors.New("payload: OpenObject requires uuid")
	}
	if len(body) < IVSize {
		return nil, fmt.Errorf("payload: body too short (%d < %d)", len(body), IVSize)
	}
	leading := body[:IVSize]

	if chunkSize == 0 {
		if contentIV != nil && !hmac.Equal(leading, contentIV) {
			return nil, errors.New("payload: object IV does not match manifest content_iv (rollback or tamper)")
		}
		return OpenFilePayload(dataKey, body, uuid)
	}

	if chunkSize < 0 {
		return nil, fmt.Errorf("payload: manifest chunk_size %d invalid", chunkSize)
	}
	if size < 0 {
		return nil, fmt.Errorf("payload: manifest size %d invalid", size)
	}
	if len(contentIV) != IVSize {
		return nil, errors.New("payload: chunked entry requires a 12-byte content_iv")
	}
	if !hmac.Equal(leading, contentIV) {
		return nil, errors.New("payload: object IV does not match manifest content_iv (rollback or tamper)")
	}
	total, err := ChunkCount(size, chunkSize)
	if err != nil {
		return nil, err
	}
	if want := size + total*(IVSize+TagSize); int64(len(body)) != want {
		return nil, fmt.Errorf("payload: object length %d does not match manifest (size %d, %d chunks ⇒ %d)", len(body), size, total, want)
	}
	aead, err := newGCM(dataKey)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, size)
	off := int64(0)
	for i := int64(0); i < total; i++ {
		ptLen := chunkSize
		if rem := size - int64(len(out)); rem < ptLen {
			ptLen = rem
		}
		iv := body[off : off+IVSize]
		off += IVSize
		ct := body[off : off+ptLen+TagSize]
		off += ptLen + TagSize
		pt, err := aead.Open(nil, iv, ct, ChunkAAD(uuid, contentIV, i, total))
		if err != nil {
			return nil, fmt.Errorf("payload: chunk %d of %d failed authentication", i, total)
		}
		if int64(len(pt)) != ptLen {
			return nil, fmt.Errorf("payload: chunk %d decrypted to %d bytes, expected %d", i, len(pt), ptLen)
		}
		out = append(out, pt...)
	}
	return out, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("payload: key length %d, want %d", len(key), KeySize)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("payload: aes.NewCipher: %w", err)
	}
	return cipher.NewGCM(block)
}

// --- HMAC-SHA256 (manifest signing) ----------------------------------------

func HMACSign(masterKey, message []byte) []byte {
	h := hmac.New(sha256.New, masterKey)
	h.Write(message)
	return h.Sum(nil)
}

func HMACVerify(masterKey, message, tag []byte) bool {
	want := HMACSign(masterKey, message)
	return hmac.Equal(want, tag)
}

// --- canonical JSON -------------------------------------------------------

// CanonicalJSON produces a deterministic byte string for a JSON-encodable
// value. Sorts map keys lexicographically at every level. Subset of
// RFC 8785 — matches the browser's lib/crypto.js::canonicalJSON exactly
// for the flat objects we use in manifest events.
func CanonicalJSON(v interface{}) ([]byte, error) {
	switch t := v.(type) {
	case nil:
		return []byte("null"), nil
	case bool:
		if t {
			return []byte("true"), nil
		}
		return []byte("false"), nil
	case string:
		return json.Marshal(t)
	case float64:
		return json.Marshal(t)
	case int:
		return json.Marshal(t)
	case int64:
		return json.Marshal(t)
	case json.Number:
		return []byte(t.String()), nil
	case []interface{}:
		var buf []byte
		buf = append(buf, '[')
		for i, e := range t {
			if i > 0 {
				buf = append(buf, ',')
			}
			b, err := CanonicalJSON(e)
			if err != nil {
				return nil, err
			}
			buf = append(buf, b...)
		}
		buf = append(buf, ']')
		return buf, nil
	case map[string]interface{}:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var buf []byte
		buf = append(buf, '{')
		for i, k := range keys {
			if i > 0 {
				buf = append(buf, ',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return nil, err
			}
			buf = append(buf, kb...)
			buf = append(buf, ':')
			vb, err := CanonicalJSON(t[k])
			if err != nil {
				return nil, err
			}
			buf = append(buf, vb...)
		}
		buf = append(buf, '}')
		return buf, nil
	default:
		// Round-trip via encoding/json to normalise structs into the
		// map[string]interface{} branch.
		raw, err := json.Marshal(v)
		if err != nil {
			return nil, err
		}
		var generic interface{}
		if err := json.Unmarshal(raw, &generic); err != nil {
			return nil, err
		}
		return CanonicalJSON(generic)
	}
}
