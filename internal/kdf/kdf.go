// SPDX-License-Identifier: AGPL-3.0-or-later
// Package kdf wraps PBKDF2-SHA256 with the parameters
// crate-pairing-protocol-v1.0.md §"Phase 3" step 7 mandates:
//   600,000 iterations, 32-byte output (matching the browser's
//   Web Crypto derivation so daemon + browser produce the same master
//   key — once the salt is shared).
//
// M2 uses a locally-generated salt (the M3 reconciliation work will
// switch to fetching the canonical salt from the bucket's .crate/crate.json
// via the Hub proxy, per plan/pending.md).

package kdf

import "golang.org/x/crypto/pbkdf2"

import "crypto/sha256"

// Iterations is the spec-mandated PBKDF2 iteration count.
const Iterations = 600_000

// KeyLen is the master-key length in bytes (32 = 256 bits = matches
// AES-256 / XChaCha20-Poly1305 key sizes).
const KeyLen = 32

// SaltLen is the salt length the daemon generates at pair time. The
// browser uses 16 bytes per crate-browser-handoff-v1.0.md §"Encryption
// details"; matching here so the M3 reconciliation drop-in is trivial.
const SaltLen = 16

// DeriveMasterKey runs PBKDF2-SHA256(passphrase, salt, 600k, 32) and
// returns the derived key. Both inputs are zeroed by the caller after
// the returned key is used.
//
// Used by the v1.0 schema path where master key = PBKDF2(passphrase, salt)
// directly. v1.1 separates KEK derivation from the content/master key —
// see DeriveKEK / DerivePassphraseKEK below.
func DeriveMasterKey(passphrase string, salt []byte) []byte {
	return pbkdf2.Key([]byte(passphrase), salt, Iterations, KeyLen, sha256.New)
}

// DeriveKEK runs PBKDF2-SHA256 over arbitrary input bytes and returns 32
// raw bytes. `secret` is the caller's choice of UTF-8(passphrase) or raw
// entropy (e.g. BIP-39 mnemonic-to-entropy output).
//
// `iter` is taken explicitly (not a constant) so the caller can honour
// the iteration count stored in .crate/crate.json's wrap slot — future
// wraps may use a higher count, and v1.1 readers should not silently
// downgrade.
func DeriveKEK(secret, salt []byte, iter int) []byte {
	return pbkdf2.Key(secret, salt, iter, KeyLen, sha256.New)
}

// DerivePassphraseKEK is a convenience wrapper around DeriveKEK for the
// passphrase-KEK case — UTF-8-encodes the passphrase + delegates. Bytes-
// for-bytes equivalent to DeriveMasterKey(passphrase, salt) when iter ==
// Iterations.
func DerivePassphraseKEK(passphrase string, salt []byte, iter int) []byte {
	return DeriveKEK([]byte(passphrase), salt, iter)
}
