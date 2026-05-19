# crate-agent

A small Go binary that watches `~/crate/` and keeps it in sync with the user's Crate. Cloud is canonical, the daemon is a cache. **The daemon does not hold bucket credentials** — it authenticates to a transport (`nakli-hub` or `nakli-cf-worker`) via a pairing token issued by the browser Crate. This is a security property, not a layering accident.

Build target: single statically-linked Go binary per OS. v1.0 ships macOS + Linux; Windows is v1.1.

## Status

**M3 piece 2 — daemon storage + watcher.** SQLite state DB ([`internal/state/`](internal/state/) — `modernc.org/sqlite`, no CGO) with tables `manifest_cache` / `upload_queue` / `conflict_log` / `watcher_state` and full CRUD methods. Filesystem watcher ([`internal/watcher/`](internal/watcher/) — `fsnotify` + 500 ms per-path debounce) coalesces rapid edits into single events. `.crateignore` matcher ([`internal/ignore/`](internal/ignore/)) with `.gitignore` syntax + built-in always-ignore set (`.DS_Store`, `Thumbs.db`, `*.swp`, `.git/`, `node_modules/`, editor scratch files). `doctor` now flips both checks from deferred-stub to real: opens the state DB, runs migrations, queries pending uploads, constructs an fsnotify handle against `crate.local_path`. State DB defaults to `<local_path>/.crate/state.db` (the `pair` command now writes this path) so removing the crate folder also removes the daemon's local state. Cross-compiles to darwin amd64+arm64 + linux amd64+arm64 with `CGO_ENABLED=0`. 22 unit tests passing across `state` / `watcher` / `ignore`.

**Earlier**: M2 (`pair` command end-to-end), M1 (wire audit + SDK binding + doctor), M0 (skeleton). Pieces 5+ of M3 (sync loop, capability refresh, salt reconciliation) land next; they stack on the Hub-side bucket-proxy that shipped at [`private-mesh@dbec7e8`](https://github.com/NakliTechie/private-mesh/commit/dbec7e8). See [`docs/specs/crate-daemon-handoff-v1.0.md`](docs/specs/crate-daemon-handoff-v1.0.md), [`docs/wire-protocol-audit.md`](docs/wire-protocol-audit.md), and the [vision doc](../private-mesh/docs/specs/crate-vision-and-roadmap-v1.0.md) (in `private-mesh`).

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
