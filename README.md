# crate-agent

A small Go binary that watches `~/crate/` and keeps it in sync with the user's Crate. Cloud is canonical, the daemon is a cache. **The daemon does not hold bucket credentials** — it authenticates to a transport (`nakli-hub` or `nakli-cf-worker`) via a pairing token issued by the browser Crate. This is a security property, not a layering accident.

Build target: single statically-linked Go binary per OS. v1.0 ships macOS + Linux; Windows is v1.1.

## Status

**M3 piece 5 — sync loop (push direction).** The daemon now propagates local changes to the bucket. Architecture: [`internal/syncer/`](internal/syncer/) runs a dispatcher goroutine that reads `watcher.Events()` and persists each event into `upload_queue` (crash-safe — a daemon restart resumes from the queue), and a worker goroutine that drains the queue by streaming files to the Hub's bucket-proxy via the new authenticated [`internal/httpc/`](internal/httpc/) methods (`PutObject` / `DeleteObject` / `HeadObject` / `GetObject` / `ListObjects` — all carry `X-Fabric-Grant: <capability>`). Successful uploads write to `manifest_cache` (ETag + SHA-256 + size + mtime); failures schedule an exponential-backoff retry (1s base, 60s cap; capped at attempt 7). Pull-side (subscribe to bucket changes + conflicting-rename on divergent writes) lands at piece 5b / M4. End-to-end syncer tests against an in-process fake Hub: create-then-upload, remove-then-delete, transient-failure retry, scope-rejection, missing-fields. 51 unit tests passing across `state` / `watcher` / `ignore` / `pairing` / `syncer`.

**Earlier**: M3 piece 2 (state DB + watcher + .crateignore — [`7d1e200`](https://github.com/NakliTechie/crate-agent/commit/7d1e200)), M2 (`pair` command end-to-end — [`9582743`](https://github.com/NakliTechie/crate-agent/commit/9582743)), M1 (wire audit + SDK binding + doctor — [`4748f01`](https://github.com/NakliTechie/crate-agent/commit/4748f01)), M0 (skeleton). Pieces 6+ of M3 (capability refresh at 80% TTL, salt reconciliation, `start`/`stop`/`status` real commands, service-file generators) land next. Stacked on the Hub-side bucket-proxy that shipped at [`private-mesh@dbec7e8`](https://github.com/NakliTechie/private-mesh/commit/dbec7e8). See [`docs/specs/crate-daemon-handoff-v1.0.md`](docs/specs/crate-daemon-handoff-v1.0.md), [`docs/wire-protocol-audit.md`](docs/wire-protocol-audit.md), and the [vision doc](../private-mesh/docs/specs/crate-vision-and-roadmap-v1.0.md) (in `private-mesh`).

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
