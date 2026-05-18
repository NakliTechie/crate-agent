# crate-agent

A small Go binary that watches `~/crate/` and keeps it in sync with the user's Crate. Cloud is canonical, the daemon is a cache. **The daemon does not hold bucket credentials** — it authenticates to a transport (`nakli-hub` or `nakli-cf-worker`) via a pairing token issued by the browser Crate. This is a security property, not a layering accident.

Build target: single statically-linked Go binary per OS. v1.0 ships macOS + Linux; Windows is v1.1.

## Status

**M2** — `pair` command end-to-end. Phase 3 of [`crate-pairing-protocol-v1.0.md`](../private-mesh/docs/specs/crate-pairing-protocol-v1.0.md) implemented against `nakli-hub`'s CRATE-PAIR endpoints. `crate-agent pair` decodes the token, generates an ephemeral Ed25519 keypair, POSTs to `/v1/pairing/redeem`, derives a master key (PBKDF2-SHA256 600k iterations) with a locally-generated salt (cross-surface salt reconciliation deferred to M3 per `plan/pending.md`), encrypts the capability via XChaCha20-Poly1305, atomic-writes the FIF + config at mode 0600, and auto-runs `doctor`. The 7 test vectors at [`private-mesh/docs/test-vectors/crate-pairing/`](../private-mesh/docs/test-vectors/crate-pairing/) are exercised in `internal/pairing/token_test.go`. One-direction upload + bidirectional sync land at M3. See [`docs/specs/crate-daemon-handoff-v1.0.md`](docs/specs/crate-daemon-handoff-v1.0.md), [`docs/wire-protocol-audit.md`](docs/wire-protocol-audit.md), and the [vision doc](../private-mesh/docs/specs/crate-vision-and-roadmap-v1.0.md) (in `private-mesh`).

## Build

```sh
make all          # cross-compile to darwin amd64+arm64 + linux amd64+arm64
./smoke.sh        # Full gate: builds nakli-hub + nakli-cli from ../private-mesh,
                  # spins up Hub, mints a FIF, runs doctor (M1), then mints an
                  # intent + runs `pair --token-stdin --passphrase-stdin` and
                  # verifies the post-pair doctor is green (M2).
                  # SKIP_M2=1 ./smoke.sh runs M0+M1 only.
                  # SKIP_M1=1 ./smoke.sh runs M0 only.
```

## Pair flow

```sh
# Interactive (default):
crate-agent pair
# Paste pairing token: CRATE-PAIR-...
# Folder passphrase: ********

# Non-interactive (testing):
printf '%s\n%s\n' "$TOKEN" "$PASS" | crate-agent pair --token-stdin --passphrase-stdin
```

After a successful pair:
- `~/.config/nakli/identity.key` (FIF, 0600) — daemon's ephemeral Ed25519 keypair, encrypted under the passphrase.
- `~/.config/nakli/crate-agent.toml` (0600) — config with `pairing_token` = base64(XChaCha20-Poly1305(capability, master_key, nonce)), plus `salt`, `capability_nonce`, `transport_pubkey`, `capability_expires`.

## Licence

AGPL-3.0-or-later. See [`LICENSE`](LICENSE).
