# crate-agent (Daemon) — Coding Agent Handoff v1.0

**Audience:** Coding agent (Claude Code) building the crate-agent daemon, v1.0
**Repo:** `NakliTechie/crate-agent` (NEW repo — create at build start)
**Sibling references:**
- `NakliTechie/private-mesh/nakli-hub/` (Go binary, transport — the canonical structural template)
- `NakliTechie/private-mesh/nakli-local-bridge/` (Go binary, mDNS bridge — secondary structural template)
- `NakliTechie/private-mesh/fabric-sdk-go/` (SDK to bind against)
- `NakliTechie/crate/` (browser surface — the daemon pairs with this)
**Spec source of truth:** `crate-vision-and-roadmap-v1.0.md`
**Pairing protocol (cross-surface contract):** `crate-pairing-protocol-v1.0.md`

Read the vision doc first. Read `nakli-hub/` and `nakli-local-bridge/` source second — they are the structural templates. Read the pairing protocol doc before implementing M2 — that's the binding spec, not the prose in this doc. This handoff covers daemon-specific non-spec gaps.

---

## What this is

A small Go binary that watches a folder on the user's computer and keeps it in sync with their Crate. It does NOT talk to R2 directly. It does NOT hold bucket credentials. It talks to a *transport* (a Cloudflare Worker or self-hosted Hub) using a pairing token, and the transport handles the bucket. This is a security property, not a layering accident — the daemon binary on disk cannot leak Cloudflare keys it doesn't have.

The user already has a working browser Crate at `crate.naklitechie.com` before they install this. They generate a pairing token from the browser UI, run `crate-agent pair`, paste the token, and the daemon is wired up. From then on, files in `~/crate/` stay in sync with the cloud.

## What this is not

- Not a standalone Dropbox client. Without a paired browser Crate, the daemon has nothing to talk to.
- Not a tool that talks to R2 directly. That's intentional.
- Not a virtual filesystem. Plaintext files on real disk in v1.0.
- Not a GUI app. CLI only in v1.0 and v1.1. A future `crate-agent-tray` could exist, separate product.
- Not a mobile thing. macOS, Linux, Windows desktop. iOS and Android are different product families.

## Licence

**AGPL-3.0**, same as the browser surface.

- Every Go file gets the SPDX header: `// SPDX-License-Identifier: AGPL-3.0-or-later`
- `LICENSE` file at repo root with full AGPL-3.0 text
- `README.md` includes a Licence section
- Do not introduce dependencies with licences incompatible with AGPL-3.0
  - Acceptable: MIT, BSD, Apache-2.0, MPL-2.0, ISC, AGPL-3.0, GPL-3.0, LGPL-3.0
  - Not acceptable: GPL-2.0-only (no "or later"), CDDL, EPL-1.0, proprietary
  - When in doubt, ask before adding

## Build target

Single statically-linked Go binary per OS. Cross-compiled from one developer machine.

- macOS: universal binary (amd64 + arm64), notarisation deferred to v1.1
- Linux: amd64 + arm64, static linkage (`CGO_ENABLED=0` where possible)
- Windows: amd64, signing deferred to v1.1

v1.0 ships macOS + Linux. Windows is v1.1. No CGO if at all avoidable.

## Pre-build audit (REQUIRED — do not skip)

Before writing any crate-agent code, complete the wire-protocol audit from the vision doc and produce `docs/wire-protocol-audit.md` in this repo, covering:

1. Does `fabric-spec-001` assume WebSocket framing, or work over plain HTTP/HTTP2/QUIC/TCP?
2. Does Sync's session model assume tab-scoped lifetimes (open/close events tied to UI presence)?
3. Are SDK calls in `fabric-sdk-go` callable from a non-browser long-running process today, or is the SDK currently shaped around browser patterns?
4. Are auth tokens / Identity proofs in `fabric-sdk-go` scoped in a way that breaks for a daemon with a long-lived pairing token?
5. Does the pairing-token model (browser issues, daemon redeems) exist in the fabric, or do we need to add it?

If any answer surfaces a problem, stop and surface to Chirag with a proposed protocol revision. Do not work around at the binary layer.

If all clear, proceed to M0.

## Repository layout

```
crate-agent/
  main.go
  cmd/                            # cobra commands
    start.go                      # `crate-agent start`
    stop.go                       # `crate-agent stop`
    status.go                     # `crate-agent status`
    pair.go                       # `crate-agent pair`
    doctor.go                     # `crate-agent doctor`
    reconfigure.go                # `crate-agent reconfigure`
    install_service.go            # `crate-agent install-service`
    uninstall_service.go          # `crate-agent uninstall-service`
    version.go                    # `crate-agent version`
    root.go                       # cobra root, global flags
  internal/
    watcher/                      # platform-specific fsnotify wrappers
      watcher.go                  # shared interface
      watcher_darwin.go
      watcher_linux.go
      watcher_windows.go          # v1.1, stub in v1.0
    syncer/                       # binds to fabric-sdk-go, drives sync loop
      syncer.go
      events.go
      conflict.go
    manifest/                     # local manifest cache (mirrors cloud)
      manifest.go
      jsonl.go
    config/                       # TOML loader, default paths
      config.go
      paths.go                    # XDG / %APPDATA% resolution
    pairing/                      # pairing token redemption
      pairing.go
      token.go
    state/                        # SQLite local state
      state.go
      schema.sql
    service/                      # service file generators
      launchd.go                  # darwin
      systemd.go                  # linux
      windows.go                  # v1.1
    ignore/                       # .crateignore + built-in patterns
      ignore.go
  service-templates/
    launchd.plist.tmpl
    systemd.service.tmpl
  docs/
    README.md                     # what it is, install, use
    wire-protocol-audit.md        # the pre-build audit doc
    config-reference.md           # TOML schema, all fields
    troubleshooting.md            # common failure modes + fixes
  LICENSE                         # AGPL-3.0
  Makefile                        # cross-compile targets
  go.mod
  go.sum
  smoke.sh                        # M0 placeholder
```

Use `nakli-hub/` as the structural reference for `cmd/` and `internal/` layout. The pattern is already established in the monorepo.

## Dependencies

**Allowed:**
- Standard library (preferred for everything possible)
- `github.com/NakliTechie/private-mesh/fabric-sdk-go` (Apache-2.0) — primary SDK binding
- `github.com/fsnotify/fsnotify` (BSD-3-Clause) — filesystem watching
- `github.com/BurntSushi/toml` (MIT) — config parsing
- `github.com/spf13/cobra` (Apache-2.0) — CLI; align with whatever `nakli-cli/` uses, share via `go.work` if possible
- `modernc.org/sqlite` (BSD-3-Clause + others) OR `github.com/mattn/go-sqlite3` (MIT, but uses CGO) — pick the no-CGO option (`modernc.org/sqlite`) to keep static linkage clean
- `github.com/kardianos/service` (zlib) — cross-platform service installer; if its shape doesn't fit, write per-OS service code instead

**Forbidden:**
- Any direct R2 / AWS / S3 SDK — the daemon does not speak S3 directly
- Any HTTP-server framework — daemon doesn't accept inbound HTTP in v1.0
- Any GUI framework
- Any telemetry, analytics, error-reporting SaaS
- Any dependency requiring CGO (we want static linkage; CGO breaks that)
- Any GPL-2.0-only dependency

Document every dependency's licence in `docs/dependencies.md`.

## Config file format

`~/.config/nakli/crate-agent.toml` on Linux/macOS (XDG-respecting), `%APPDATA%\nakli\crate-agent.toml` on Windows. Resolution logic in `internal/config/paths.go`.

Schema:

```toml
[agent]
log_level = "info"                       # debug | info | warn | error
log_path = "~/.local/share/nakli/crate-agent.log"  # or platform equivalent
state_db = "~/.local/share/nakli/crate-agent.db"   # SQLite state

[identity]
path = "~/.config/nakli/identity.key"    # private key file, 0600 permissions
# created during `crate-agent pair`

[crate]
name = "personal"                        # display name, user-chosen
local_path = "~/crate"                   # the folder being synced
transport_endpoint = "https://my-account.workers.dev"  # populated by pair
transport_type = "cf-worker"             # cf-worker | hub | managed
pairing_token = "encrypted-blob"         # encrypted with identity key, opaque
bucket_id = "01H..."                     # opaque bucket reference (not credentials)
encrypt_at_rest = false                  # plaintext locally by default
```

v1.0 supports exactly one `[crate]` section (one folder). v1.3 makes this an array `[[crate]]` for multi-folder.

The user does not hand-write this. `crate-agent pair` creates it. `crate-agent reconfigure` re-reads it. Document the schema in `docs/config-reference.md` for users who want to inspect or edit.

## Local state (SQLite)

`state.db` schema (in `internal/state/schema.sql`):

```sql
CREATE TABLE IF NOT EXISTS manifest_cache (
  uuid TEXT PRIMARY KEY,
  path TEXT NOT NULL,
  size INTEGER NOT NULL,
  mtime INTEGER NOT NULL,
  mime TEXT,
  local_hash TEXT,                       -- sha256 of local file
  remote_hash TEXT,                      -- sha256 of last-synced version
  last_synced_at INTEGER
);

CREATE TABLE IF NOT EXISTS sync_cursor (
  k TEXT PRIMARY KEY,
  v TEXT NOT NULL
);
-- e.g. ('last_event_id', '01H...'), ('last_sync_ts', '1747...')

CREATE TABLE IF NOT EXISTS upload_queue (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  path TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  last_attempt_at INTEGER,
  last_error TEXT,
  enqueued_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_manifest_path ON manifest_cache(path);
```

Why SQLite and not flat files: atomic writes, concurrent reads (status command while syncer is running), structured queries. `modernc.org/sqlite` keeps us CGO-free.

## Filesystem watching

Per-platform backend via `fsnotify`:
- **macOS:** FSEvents (handled by fsnotify)
- **Linux:** inotify (handled by fsnotify)
- **Windows (v1.1):** ReadDirectoryChangesW (handled by fsnotify)

**Debouncing:** batch events within a 250ms window per file. A `mv` becomes one rename event, not delete + create. Editor save patterns (write to `.swp` then rename) become one update event. Implement in `internal/watcher/`.

**Built-in ignore patterns** (always on, not configurable):
- `.DS_Store`, `Thumbs.db`, `desktop.ini`
- `~$*`, `.~*` (Office lock files)
- `*.swp`, `*.swo`, `4913` (vim)
- `.git/`, `node_modules/`, `__pycache__/`, `.venv/`, `target/`

**User-configurable ignore:** `.crateignore` file in folder root, gitignore-style syntax. Lives at `internal/ignore/`.

## Sync loop

Pseudocode (implement in `internal/syncer/`):

```
on local filesystem event (debounced):
  if event matches ignore pattern: skip
  read manifest_cache for this path
  if event is add/modify:
    compute local hash
    if hash != remote_hash:
      enqueue upload
  if event is delete:
    enqueue tombstone event
  if event is rename:
    enqueue move event

on Sync primitive event from cloud (via fabric-sdk-go):
  if event is local-originated (echo): skip (use event ID, not timestamp)
  apply to filesystem:
    - create/update: download, decrypt, write atomically (write to tmp, rename)
    - delete: rm
    - move: rename
  update manifest_cache

upload worker (every 2s while queue non-empty):
  dequeue next item
  read file, encrypt, upload via Sync primitive
  on success: update remote_hash in manifest_cache, remove from queue
  on retriable failure: re-enqueue with exponential backoff
  on permanent failure (e.g. file too big, permission denied): log, surface in status

on conflict (both sides modified between sync points):
  identify "loser" by manifest event timestamp (newer wins)
  write loser to _conflicts/{path}-{ISO-timestamp}-{shorthash}.{ext}
  log warning
  apply winner to canonical path
```

Conflict resolution must be deterministic. Tiebreaker for identical timestamps: lexicographic ordering of event signature.

## CLI commands

All output: human-readable by default. `--json` flag on `status` and `doctor` for scripting.

```
crate-agent start [--detach]
  Run the daemon. --detach forks and writes pidfile.
  Reads config, opens state.db, starts watcher + syncer, runs until SIGTERM.

crate-agent stop
  Send SIGTERM to the running daemon (find via pidfile).

crate-agent status [--json]
  Show: running? PID, uptime, folder, sync state (idle/syncing), last activity,
  file count, total size, upload queue depth.

crate-agent status --folder NAME [--json]
  Same but per-folder (preparing for v1.3 multi-folder).

crate-agent pair
  Interactive: prompt for pairing token from browser Crate (paste), prompt for
  passphrase, redeem token against transport, write config, write identity key
  (0600), exit. Token-redeem is one-shot; tokens expire 15 min from issuance.

crate-agent reconfigure
  Reload config, reconcile state (re-scan local folder if local_path changed,
  re-verify transport reachability). No daemon restart required.

crate-agent doctor
  Run a series of checks: config validity, identity key present and readable,
  transport reachable, state.db readable, watcher functional on a tmp file.
  Print pass/fail per check. Exit non-zero on any failure.

crate-agent install-service
  Generate the appropriate service file (launchd plist on macOS, systemd unit
  on Linux), install to user-level location, enable. Print path and status.
  Idempotent: re-running doesn't break existing install.

crate-agent uninstall-service
  Stop service, disable, remove service file. Idempotent.

crate-agent version
  Print version string, build date, git SHA, Go runtime version, OS/arch.
  Used in the onboarding mock as the M1 verification step.
```

Exit codes: 0 = success, 1 = generic error, 2 = config error, 3 = transport unreachable, 4 = already running (where it shouldn't be), 5 = not running (where it should be).

## Pairing flow

The pairing protocol is defined in `crate-pairing-protocol-v1.0.md`. **That document is the binding spec.** This section summarises the daemon-side responsibilities to orient the reader; if anything below conflicts with the protocol doc, the protocol doc wins.

The user has a working browser Crate at `crate.naklitechie.com`. They want to pair a daemon.

- **Browser side (Phase 1 of the protocol)** runs in the Crate browser; daemon doesn't implement it.
- **Token transfer (Phase 2)** is out-of-band — the user copies the token into the terminal.
- **Daemon side (Phase 3 of the protocol)** is what `crate-agent pair` implements.

Daemon's Phase 3 responsibilities, at a glance:
1. Prompt for the `CRATE-PAIR-...` token
2. Decode and validate token per protocol spec (return appropriate error codes from the protocol's "Error codes" table)
3. Generate an ephemeral Ed25519 keypair for the daemon
4. Prompt for the folder passphrase
5. POST to `{transport_endpoint}/v1/pairing/redeem` with the secret + daemon pubkey + fingerprint
6. Receive the capability + bucket reference + transport pubkey
7. Derive the master encryption key from the passphrase (PBKDF2-SHA256, 600k iterations, salt fetched from bucket's `.crate/crate.json` via the just-issued capability) — matching the browser's derivation exactly
8. Write config TOML and identity key (mode 0600)
9. Run `crate-agent doctor` automatically as final verification
10. Clear the passphrase from memory; retain only the derived master key for runtime

The **key security property** to preserve: the daemon never sees the bucket's S3 credentials. Those live in the transport. Worst-case daemon compromise = "attacker can read/write the encrypted blobs via the transport using the user's capability" — bad but bounded, and revocable from any device.

Implement the protocol's error codes exactly. Use the test vectors in `private-mesh/docs/test-vectors/crate-pairing/` to verify your implementation before declaring M2 done.

## Design tokens (for CLI output)

Use ANSI escapes for status output. Match NakliTechie portfolio palette in spirit (clean, restrained):

- ✓ in green for success (`\033[32m`)
- ✗ in red for failure (`\033[31m`)
- ⚠ in yellow for warnings
- Plain text for neutral status
- Bold for emphasis sparingly
- Respect `NO_COLOR` env variable (https://no-color.org/) — disable all ANSI when set
- Respect non-TTY output (when piped) — disable ANSI automatically

## Service file templates

`service-templates/launchd.plist.tmpl`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>dev.naklitechie.crate-agent</string>
    <key>ProgramArguments</key>
    <array>
        <string>{{.BinaryPath}}</string>
        <string>start</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>{{.LogPath}}</string>
    <key>StandardErrorPath</key>
    <string>{{.LogPath}}</string>
</dict>
</plist>
```

`service-templates/systemd.service.tmpl`:

```ini
[Unit]
Description=Crate Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={{.BinaryPath}} start
Restart=on-failure
RestartSec=10
StandardOutput=append:{{.LogPath}}
StandardError=append:{{.LogPath}}

[Install]
WantedBy=default.target
```

Install location:
- macOS: `~/Library/LaunchAgents/dev.naklitechie.crate-agent.plist`
- Linux: `~/.config/systemd/user/crate-agent.service`

No root required. User-level services only in v1.0.

## Hard rules — do NOT

- Do **not** speak S3 directly. The daemon talks to a transport, never to R2/B2/S3 endpoints.
- Do **not** persist bucket credentials. The daemon should not even be able to know them.
- Do **not** add a web UI. CLI is the only interface in v1.0.
- Do **not** add Dropbox/iCloud/OneDrive compatibility. Wrong shape.
- Do **not** install kexts, kernel modules, or anything requiring root by default.
- Do **not** auto-update. User pulls a new binary deliberately.
- Do **not** open inbound network ports. Daemon connects out only.
- Do **not** sync folders outside the user's home directory by default. Make it possible to override, obnoxiously.
- Do **not** log file contents, paths, or filenames at info level. Path hashes only at debug level.
- Do **not** bypass `fabric-spec-001`. If there's a faster path, route through the fabric anyway.
- Do **not** introduce dependencies with licences incompatible with AGPL-3.0.
- Do **not** add CGO if at all avoidable. Static linkage is a property worth fighting for.

## Escalation — when to stop and ask Chirag

Stop and surface to Chirag if:

- The wire-protocol audit surfaces problems requiring `fabric-spec-001` revisions.
- A platform's filesystem semantics (case sensitivity, max path length, reserved characters) make round-tripping with the cloud manifest lossy.
- Conflict resolution can't be deterministic without a tiebreaker not in the manifest format.
- Service installation requires elevated privileges to be useful.
- The pairing-token protocol needs the browser surface to implement something it currently can't.
- A required dependency has licence questions.

Don't stop for: choice of SQLite driver (modernc.org/sqlite is the call), log format, exit codes (use the ones above), error message wording, pidfile location, ignore pattern syntax details.

## Gate artifacts per milestone

**M0 — skeleton.** Repo created at `NakliTechie/crate-agent`, LICENSE (AGPL-3.0), README stub, Makefile that cross-compiles to macOS + Linux producing static binaries, main.go that prints help, smoke.sh.
- Gate: `make all` produces working binaries that print help. `./smoke.sh` prints OK.

**M1 — wire audit + SDK binding.** Wire-protocol audit doc complete and signed off. `fabric-sdk-go` usable from long-running Go process. Identity load + transport ping works.
- Gate: A test program in `internal/syncer/cmd_test/` authenticates to a test hub transport and calls ping using `fabric-sdk-go`.

**M2 — pair command.** `crate-agent pair` implements Phase 3 of `crate-pairing-protocol-v1.0.md` end-to-end against a test pairing token. Config written. Identity key written (mode 0600). Master encryption key derived from passphrase. All error codes from the protocol's error table handled correctly.
- Gate: Run pair against the valid v1 test vector — config file written correctly, identity key at 0600. Run against each invalid test vector — daemon returns the correct error code and message, exits non-zero, leaves no partial state. Browser-side issuance (Phase 1) can be stubbed for this milestone with a mock transport.

**M3 — one-direction upload.** Watch a folder, detect adds/modifies, upload to transport, update manifest cache. Local SQLite state persists across daemon restarts.
- Gate: `touch ~/crate/test/foo.txt`, observe upload in logs, see file via browser Crate.

**M4 — bidirectional sync.** Receive Sync events from cloud, materialise files locally. Echo suppression works (don't ping-pong).
- Gate: Upload a file via browser Crate, see it appear in `~/crate/test/` within 10s.

**M5 — full ops.** Delete, rename, move, mkdir round-trip. Conflict folder works.
- Gate: Force a conflict (write same file from browser and CLI within 1s), confirm one winner and one `_conflicts/` entry. Move and rename round-trip with no data loss.

**M6 — service install.** launchd + systemd templates work. `install-service` / `uninstall-service` are idempotent.
- Gate: After install, daemon auto-starts on login (macOS) and on boot (Linux user session). Survives reboot. Uninstall removes everything.

**M7 — status + doctor + docs.** `status` and `doctor` produce useful output (both human and `--json`). README covers install via the onboarding wizard, troubleshooting doc covers the top 10 failure modes.
- Gate: Chirag's M4 Pro runs the daemon for one week against his real Crate, no manual intervention, status shows clean sync state for the duration.

**M8 — ship.** Polish, GitHub release with checksums, integration with the onboarding mock's deep links.
- Gate: A second person (not Chirag) installs the daemon following the wizard, runs it for a day, reports back. No critical issues.

After M8: v1.0 daemon is shipped. v1.1 (Windows binary, signing, multi-folder) is a separate spec.

## What "done" looks like

Chirag's M4 Pro has a folder `~/crate/notes/`. He edits a file in vim. Within 10 seconds it's visible in the browser Crate on his iPad's Safari tab. He edits the same file there. Within 10 seconds the daemon writes the change to disk. He opens a terminal and runs `rg "$query" ~/crate/notes/` and it finds matches across all his synced content. No NakliTechie server is on the path. Same primitives, two surfaces, one folder, one user-owned bucket, AGPL-3.0 keeping it that way.


---

*This document is licensed CC BY-SA 4.0.*
