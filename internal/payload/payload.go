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
// Object body layout: 12-byte IV || ciphertext || 16-byte GCM auth tag.
// (Go's AEAD interface appends the tag to ciphertext automatically; the
// browser's SubtleCrypto does the same. Layouts are identical.)
package payload

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
)

const (
	KeySize  = 32 // 256-bit AES-GCM key
	IVSize   = 12 // AES-GCM nonce
	TagSize  = 16 // GCM auth tag
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

func RandomIV() ([]byte, error)       { return RandomBytes(IVSize) }
func RandomDataKey() ([]byte, error)  { return RandomBytes(DataKeyLen) }

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

// SealFilePayload encrypts a file's plaintext bytes under dataKey + a
// fresh IV. fileUUID bound as AAD. Returns the on-bucket object body:
// 12-byte IV || ciphertext || 16-byte tag.
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

// OpenFilePayload decrypts an on-bucket object body. body MUST be at least
// IVSize+TagSize bytes; the first 12 are the IV, the rest is ciphertext+tag.
func OpenFilePayload(dataKey, body []byte, fileUUID string) ([]byte, error) {
	if len(body) < IVSize+TagSize {
		return nil, fmt.Errorf("payload: body too short (%d < %d)", len(body), IVSize+TagSize)
	}
	iv := body[:IVSize]
	ct := body[IVSize:]
	return Open(dataKey, iv, ct, []byte(fileUUID))
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
