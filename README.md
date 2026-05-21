# crate-agent

A small Go daemon that keeps a local folder (`~/crate/` by default) in sync with your [Crate](https://crate.naklios.dev/) cloud folder. Cloud is canonical; the daemon is a continuously-updated local mirror. macOS + Linux today; Windows is on the v1.x roadmap.

**The daemon never holds your bucket credentials.** It authenticates to a transport (`nakli-hub` or `nakli-cf-worker`) via a pairing token issued by the browser Crate. That's a security property, not a layering accident — losing the daemon doesn't expose your R2 access keys.

## Install

The simplest path: download a prebuilt binary for your OS from the latest [release](https://github.com/NakliTechie/crate-agent/releases/latest).

```sh
# macOS (Apple Silicon)
curl -L -o crate-agent https://github.com/NakliTechie/crate-agent/releases/latest/download/crate-agent-darwin-arm64
chmod +x crate-agent
sudo mv crate-agent /usr/local/bin/

# macOS (Intel)
curl -L -o crate-agent https://github.com/NakliTechie/crate-agent/releases/latest/download/crate-agent-darwin-amd64
chmod +x crate-agent && sudo mv crate-agent /usr/local/bin/

# Linux (x86_64)
curl -L -o crate-agent https://github.com/NakliTechie/crate-agent/releases/latest/download/crate-agent-linux-amd64
chmod +x crate-agent && sudo mv crate-agent /usr/local/bin/

# Linux (ARM64)
curl -L -o crate-agent https://github.com/NakliTechie/crate-agent/releases/latest/download/crate-agent-linux-arm64
chmod +x crate-agent && sudo mv crate-agent /usr/local/bin/
```

Confirm the install:

```sh
crate-agent version
```

Or build from source — single statically-linked binary, no CGO, no runtime dependencies:

```sh
make build              # current host only → dist/crate-agent
make all                # cross-compile all four targets → dist/
```

## Quick start

```sh
# 1. Open your Crate in the browser (https://crate.naklios.dev/), unlock the
#    folder, click "Pair an agent". The modal shows a CRATE-PAIR-… token.
#    Copy it.

# 2. Pair the daemon to that folder. You'll be prompted for the token
#    + your folder passphrase.
crate-agent pair
# Paste pairing token: CRATE-PAIR-…
# Folder passphrase: ********
# ✓ Paired with crate-<bucket-name>

# 3. Verify the install is healthy.
crate-agent doctor

# 4. Start syncing. Foreground first — Ctrl-C to stop.
crate-agent start
# Watching ~/crate, syncing to <bucket>…
```

Drop a file into `~/crate/`, it encrypts + uploads. Edit a file in the browser, it downloads + decrypts to `~/crate/` within ~15 s. Bidirectional, byte-identical wire format on both sides.

When you're happy with foreground behaviour, install as a long-running service:

```sh
crate-agent install-service      # launchd on macOS, systemd-user on Linux
crate-agent status               # confirm it's running
crate-agent uninstall-service    # remove the unit
```

## Commands

| Command | What |
|---|---|
| `crate-agent pair` | Redeem a CRATE-PAIR-… token from the browser. Writes config + identity key. |
| `crate-agent start` | Run the watcher + sync loop + capability-refresh runner. Ctrl-C to stop gracefully. |
| `crate-agent stop` | Signal the running daemon to terminate (reads `$XDG_STATE_HOME/nakli/crate-agent.pid`, sends SIGTERM, waits for drain). |
| `crate-agent status` | Process state + queue depth + recent conflicts + capability expiry. `--json` for machine-readable output. |
| `crate-agent doctor` | Self-check: config valid, identity readable, transport reachable, state DB readable, watcher functional. |
| `crate-agent install-service` | Generate + load a user-level supervisor unit. |
| `crate-agent uninstall-service` | Remove the unit. |
| `crate-agent version` | Version + build date + git SHA + Go runtime + OS/arch. |
| `crate-agent --help` | Full command reference. |

`status` doesn't need the folder passphrase — it reads daemon state only. Everything that touches encrypted bytes (`pair`, `start`, `doctor`) needs the passphrase.

## How it works

```
              ┌──────────────┐                 ┌─────────────┐
~/crate/  ◄──►│ crate-agent  │◄──── token ────►│  transport  │◄──── ciphertext ────► R2 / B2 / …
              │ (Go daemon)  │                 │ (Hub or CF) │
              └──────────────┘                 └─────────────┘
                  ▲
                  │  same encrypted bytes
                  ▼
        ┌────────────────────┐
        │ browser Crate tab  │
        │ at crate.naklios.dev │
        └────────────────────┘
```

- **Watcher** (`internal/watcher/`) monitors `~/crate/` for changes via fsnotify; ignores files matching `.crateignore` patterns.
- **Syncer** (`internal/syncer/`) walks the change queue, encrypts new/modified files under the master key, appends a signed manifest event, PUTs the ciphertext + the new manifest. ETag-conditional with replay-on-412 so concurrent writes from the browser don't clobber.
- **Puller** (`internal/puller/`) polls the manifest every ~15 s, diffs against the local state, downloads + decrypts changed objects, writes to disk atomically.
- **Refresh runner** (`internal/refresh/`) re-mints the daemon's transport capability when <20 % of TTL remains, re-encrypts under the in-memory master key, atomic-rewrites config.
- **State DB** (`internal/state/`, SQLite via `mattn/go-sqlite3`) tracks per-file content hashes, the last-synced manifest UUID, the daemon's pending change queue. Crash-resumable.

The wire format on the bucket is byte-identical to what the [browser Crate](https://github.com/NakliTechie/crate) reads and writes. The daemon has no way to read a folder the browser hasn't first set up; the browser has no need for the daemon. They're independent, interoperable surfaces over the same cryptographic invariant.

## Files on disk

| Path | Mode | What |
|---|---|---|
| `~/.config/nakli/crate-agent.toml` | 0600 | Config: encrypted capability + salt + nonce + transport endpoint |
| `~/.config/nakli/identity.key` | 0600 | FIF-wrapped ephemeral Ed25519 keypair (unlocks with the folder passphrase) |
| `$XDG_STATE_HOME/nakli/state.db` | 0600 | SQLite — change queue, content hashes, manifest cache |
| `$XDG_STATE_HOME/nakli/crate-agent.pid` | 0644 | Pidfile (atomic create; stale-file detection) |
| `~/crate/` | 0700 | The synced folder. Contents follow your bucket; ignore patterns in `.crateignore`. |

Configurable via the TOML — the wizard's defaults work for most users.

## Security model

- **No bucket credentials on disk.** The daemon holds an encrypted transport capability — a macaroon scoped to your bucket's sync primitive. Losing the daemon leaks the capability (encrypted under your passphrase) but never your R2 access keys.
- **Passphrase + identity key required to start.** `crate-agent start` decrypts the capability with the passphrase you set at pairing. No passphrase, no daemon. The master key lives only in the daemon process's memory.
- **Capability refresh, not capability storage.** Capabilities have a 1-year TTL with auto-refresh at 80 %. Stolen capabilities can be revoked from the browser ("Pair an agent" → revoke device).
- **AGPL-3.0-or-later.** The whole code path is auditable; transport contract is documented in [`docs/specs/`](docs/specs/) and the [crate-agent wire-protocol audit](docs/wire-protocol-audit.md).

## Repos

| | |
|---|---|
| Daemon (this) | [`NakliTechie/crate-agent`](https://github.com/NakliTechie/crate-agent) |
| Browser surface | [`NakliTechie/crate`](https://github.com/NakliTechie/crate) — live at [crate.naklios.dev](https://crate.naklios.dev/) |
| Transports + Hub | [`NakliTechie/private-mesh`](https://github.com/NakliTechie/private-mesh) |

## Licence

AGPL-3.0-or-later. See [`LICENSE`](LICENSE).
