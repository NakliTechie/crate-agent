# Changelog

All notable changes to crate-agent. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning follows [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added — chunked object framing (v2), matching crate browser `b9c5f87`

- `payload.SealObject` / `payload.OpenObject`: files are sealed as
  independent 8 MiB AES-256-GCM chunks, per-chunk AAD
  `uuid:base64(IV_0):index:total`. Binding `IV_0` (the manifest-signed
  `content_iv`) closes the cross-version splice per-chunk framing would
  otherwise open; index and total close reorder and truncation; body
  length is checked against the signed `size` before any decryption.
- Manifest `create`/`update` events accept an optional `chunk_size`
  (`manifest.WithChunkSize`); it is the v1/v2 discriminator, lives inside
  the HMAC-signed event, and is per-version — an update without it
  reverts the entry to v1. v1 events are emitted byte-identically.
- The syncer writes v2. The puller reads both; v1 objects written by
  older browsers or daemons remain readable.
- Cross-surface test: `internal/payload/testdata/browser-v2.json` is an
  object sealed by the browser's `lib/crypto.js`; the daemon must open
  it. Regenerate with `node test/gen-cross-surface-fixture.mjs` in the
  crate repo.

### Fixed — puller now enforces the content_iv rollback anchor

`OpenObject` refuses an object whose leading IV differs from the
manifest-signed `content_iv`. Previously the puller decrypted whatever
body the bucket returned for a UUID, so a bucket-only attacker could
replay an older object and have it mirrored to `~/crate/` as stale
plaintext. The browser closed this in its 2026-05 audit (H1); the daemon
had not.

**Compatibility:** this release is required to sync any file written by
crate browser `b9c5f87` or later. Older daemons fail closed on v2 objects
(auth error, not silent).

## [1.1.0] — 2026-07-27

### Added — v1.1 dual-wrap vault support

- Read and validate the browser's v1.1 `.crate/crate.json` schema, including
  strict `passphrase_wrap` and optional `recovery_wrap` validation.
- Derive a passphrase KEK separately from the random content key, then unwrap
  that content key for payload encryption and manifest signing.
- Reconcile both v1.0 and v1.1 vaults without changing the established v1.0
  path. Existing vaults continue to sync unchanged.
- Re-encrypt the local transport capability when the browser rotates the
  passphrase-wrap salt while keeping the vault's content key stable.
- Cover v1.1 schema parsing, validation, reconciliation, key wrapping,
  wrong-passphrase rejection, and tamper rejection with new tests.

This release is the daemon prerequisite for browser-created v1.1 recovery
vaults. Older crate-agent releases cannot sync those vaults.

### Fixed

- Cap exponential upload backoff before multiplying `time.Duration`, avoiding
  platform-dependent overflow after very large retry counts.

## [1.0.1] — 2026-05-21

### Security — second round (manifest rollback + full scope-subset)

The two architecturally-deferred findings from the 2026-05 audit have now landed in a single follow-up release. Both required real new code, not one-line patches; they're broken out from the v1.0.0 "quick fixes" so the changelog reflects the work.

- **H1 — manifest rollback / truncation detection** ([`<pending>`](https://github.com/NakliTechie/crate-agent/commit/HEAD)). A bucket-only attacker can serve an older valid encrypted manifest — AES-GCM and the prev_sig chain both pass on the prefix, so the daemon previously accepted it silently. Fix: per-bucket `{count, lastSig}` anchor persisted in `state.db` (new migration v3: `manifest_anchor` table). On every puller tick after the AES-GCM + chain verification, the loaded manifest is validated against the anchor — **truncation** (loaded count < anchor count) and **fork** (chain diverges at the anchor point) both fail closed and skip the apply. First-load is TOFU + `slog.Info` log; subsequent loads enforce monotonic growth. 4 puller tests + 2 state tests cover TOFU, accept-extension, reject-truncation, reject-fork.

- **H3 (full) — capability scope-subset validation** ([`<pending>`](https://github.com/NakliTechie/crate-agent/commit/HEAD)). `validateRefreshedCapability` previously only checked the expiry bounds (`now < expires ≤ now + 2×TotalTTL`). Now it imports `fabric-sdk-go/grant.Parse` to decode both the current and refreshed macaroon and enforce: issued_by_principal unchanged, primitive unchanged (`sync`), namespace unchanged (`bucket_id`), operations ⊆ current. Narrowed scope (e.g. drop `write`, keep `read`) is accepted; widening is rejected. 6 new tests in `internal/refresh/refresh_test.go` cover each rejection case + narrowing acceptance.

### Security — patches from the 2026-05 audit (from v1.0.0; recap)

OpenAI Codex (gpt-5.5) reviewed the daemon's encryption, sync, capability-handling, and lifecycle paths under a defined threat model. Four High + one Medium + two Low findings; quick fixes landed:

- **H2 — Path traversal in the puller** ([`73a37d7`](https://github.com/NakliTechie/crate-agent/commit/73a37d7)). The puller joined manifest paths directly to `LocalPath` after only stripping one leading slash. A malicious transport feeding `path: "../../.ssh/authorized_keys"` could escape `~/crate/` and write arbitrary files. New `safeLocalJoin` helper canonicalises + rejects `..`, `.`, absolute paths, and any path escaping root via `filepath.Rel`. Covers `reconcileOne` (folder + file) and `handleRemoteDelete`. 17 unit tests for the attack vectors.
- **H3 — Capability refresh expiry bound** ([`3e20892`](https://github.com/NakliTechie/crate-agent/commit/3e20892)). `doRefresh` was accepting whatever expiry the transport returned. A malicious transport could return "valid for 100 years" and persist an effectively unrevokable credential. New `validateRefreshedCapability` requires the new expiry to be in the future AND ≤ `now + 2*TotalTTL`. Closes the unrevokable-credential attack.
- **H4 — Syncer race with puller** ([`3e20892`](https://github.com/NakliTechie/crate-agent/commit/3e20892)). `executePut` snapshotted `existing` under the manifest mutex, released it for encrypt+upload, then appended an update/create using the stale snapshot. If the puller replaced the manifest in between, the syncer could append for a UUID no longer present or clobber a remote update. Fix: re-check current manifest state under the mutex immediately before append; if the (path → UUID) basis changed, abort + return for re-queue.
- **M1 — CapabilityRef data race** ([`3e20892`](https://github.com/NakliTechie/crate-agent/commit/3e20892)). Refresh wrote, puller + syncer read, no synchronisation. Plain Go data race. New `CapabilityMu *sync.RWMutex` shared across all three Configs, matching the existing `ManifestMu` pattern.
- **L1 — Non-constant-time HMAC compare in `manifest.Verify`** ([`3e20892`](https://github.com/NakliTechie/crate-agent/commit/3e20892)). Replaced `want != sigB64` with `subtle.ConstantTimeCompare`. Small timing-side-channel closed.
- **L2 — Pidfile O_EXCL atomic create** ([`3e20892`](https://github.com/NakliTechie/crate-agent/commit/3e20892)). Old code: read-then-write-then-rename. Two simultaneous starts could both pass stale-detection and run concurrently. New code: `os.OpenFile(O_CREATE|O_EXCL)` with stale-detection retry-once. Only first writer wins; loser observes `ErrAlreadyRunning`.

Full report: [`docs/security-review-2026-05-codex.md`](docs/security-review-2026-05-codex.md).

### Previously deferred — now landed in v1.0.1

H1 (manifest rollback) and the full H3 (scope-subset validation) were both deferred from v1.0.0 with the rationale that they needed real new code (persistent state for H1, macaroon-decoder import for H3). Both landed in v1.0.1 above. No outstanding audit items.

## [1.0.0] — 2026-05-21

First binary release. See [README](README.md) + the corresponding GitHub Release for the full set.
