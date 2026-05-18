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
func DeriveMasterKey(passphrase string, salt []byte) []byte {
	return pbkdf2.Key([]byte(passphrase), salt, Iterations, KeyLen, sha256.New)
}
