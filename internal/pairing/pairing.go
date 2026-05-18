// SPDX-License-Identifier: AGPL-3.0-or-later
// Package pairing implements Phase 3 of crate-pairing-protocol-v1.0:
// decode/validate CRATE-PAIR-… tokens, generate ephemeral Ed25519 keypair,
// POST to {transport}/v1/pairing/redeem, persist the returned capability.
// Lands at M2. Verified against test vectors in
// private-mesh/docs/test-vectors/crate-pairing/.
package pairing
