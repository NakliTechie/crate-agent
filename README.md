# crate-agent

A small Go binary that watches `~/crate/` and keeps it in sync with the user's Crate. Cloud is canonical, the daemon is a cache. **The daemon does not hold bucket credentials** — it authenticates to a transport (`nakli-hub` or `nakli-cf-worker`) via a pairing token issued by the browser Crate. This is a security property, not a layering accident.

Build target: single statically-linked Go binary per OS. v1.0 ships macOS + Linux; Windows is v1.1.

## Status

**M3 pieces 6 + 8 — the daemon is now a real daemon.** [`crate-agent start`](cmd/start.go) decrypts the configured capability with the folder passphrase, opens the SQLite state DB, starts the watcher on `local_path`, and runs the [sync loop](internal/syncer/) plus a [capability-refresh goroutine](internal/refresh/) until SIGINT/SIGTERM. The refresh runner POSTs `/v1/capability/refresh` when <20% of TTL remains, re-encrypts the new capability under the in-memory master key, and atomic-rewrites the config. [`crate-agent stop`](cmd/stop.go) reads the XDG pidfile (`$XDG_STATE_HOME/nakli/crate-agent.pid`), sends SIGTERM, and waits for graceful drain. [`crate-agent status`](cmd/status.go) reports running/stopped + queue depth + recent conflicts + capability expiry; `--json` for machine-readable output (no passphrase required — status reads state.db only). Crash-safe via [`internal/pidfile/`](internal/pidfile/) (atomic create with stale-file detection; refuses to start a second daemon over a live one with exit 4). 71 unit tests passing across `state` / `watcher` / `ignore` / `pairing` / `syncer` / `refresh` / `pidfile`. Smoke gate exercises a full start → status (running) → stop (graceful) → stop again (exit 5) → status (stopped) → `--json` round-trip in <2s.

**Earlier**: M3 piece 5 (sync loop, push — [`890f25f`](https://github.com/NakliTechie/crate-agent/commit/890f25f)), M3 piece 2 (state DB + watcher + .crateignore — [`7d1e200`](https://github.com/NakliTechie/crate-agent/commit/7d1e200)), M2 (`pair` command end-to-end — [`9582743`](https://github.com/NakliTechie/crate-agent/commit/9582743)), M1 (wire audit + SDK binding + doctor — [`4748f01`](https://github.com/NakliTechie/crate-agent/commit/4748f01)). Remaining M3 pieces: 5b (pull-side + conflicting-rename) → M4, 7 (salt reconciliation), 10 (service-file generators). Stacked on the Hub-side bucket-proxy at [`private-mesh@dbec7e8`](https://github.com/NakliTechie/private-mesh/commit/dbec7e8). See [`docs/specs/crate-daemon-handoff-v1.0.md`](docs/specs/crate-daemon-handoff-v1.0.md), [`docs/wire-protocol-audit.md`](docs/wire-protocol-audit.md), and the [vision doc](../private-mesh/docs/specs/crate-vision-and-roadmap-v1.0.md) (in `private-mesh`).

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
