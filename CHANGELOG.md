# Changelog

All notable changes to crate-agent. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versioning follows [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security — patches from the 2026-05 audit

OpenAI Codex (gpt-5.5) reviewed the daemon's encryption, sync, capability-handling, and lifecycle paths under a defined threat model. Four High + one Medium + two Low findings; quick fixes landed:

- **H2 — Path traversal in the puller** ([`73a37d7`](https://github.com/NakliTechie/crate-agent/commit/73a37d7)). The puller joined manifest paths directly to `LocalPath` after only stripping one leading slash. A malicious transport feeding `path: "../../.ssh/authorized_keys"` could escape `~/crate/` and write arbitrary files. New `safeLocalJoin` helper canonicalises + rejects `..`, `.`, absolute paths, and any path escaping root via `filepath.Rel`. Covers `reconcileOne` (folder + file) and `handleRemoteDelete`. 17 unit tests for the attack vectors.
- **H3 — Capability refresh expiry bound** ([`3e20892`](https://github.com/NakliTechie/crate-agent/commit/3e20892)). `doRefresh` was accepting whatever expiry the transport returned. A malicious transport could return "valid for 100 years" and persist an effectively unrevokable credential. New `validateRefreshedCapability` requires the new expiry to be in the future AND ≤ `now + 2*TotalTTL`. Closes the unrevokable-credential attack.
- **H4 — Syncer race with puller** ([`3e20892`](https://github.com/NakliTechie/crate-agent/commit/3e20892)). `executePut` snapshotted `existing` under the manifest mutex, released it for encrypt+upload, then appended an update/create using the stale snapshot. If the puller replaced the manifest in between, the syncer could append for a UUID no longer present or clobber a remote update. Fix: re-check current manifest state under the mutex immediately before append; if the (path → UUID) basis changed, abort + return for re-queue.
- **M1 — CapabilityRef data race** ([`3e20892`](https://github.com/NakliTechie/crate-agent/commit/3e20892)). Refresh wrote, puller + syncer read, no synchronisation. Plain Go data race. New `CapabilityMu *sync.RWMutex` shared across all three Configs, matching the existing `ManifestMu` pattern.
- **L1 — Non-constant-time HMAC compare in `manifest.Verify`** ([`3e20892`](https://github.com/NakliTechie/crate-agent/commit/3e20892)). Replaced `want != sigB64` with `subtle.ConstantTimeCompare`. Small timing-side-channel closed.
- **L2 — Pidfile O_EXCL atomic create** ([`3e20892`](https://github.com/NakliTechie/crate-agent/commit/3e20892)). Old code: read-then-write-then-rename. Two simultaneous starts could both pass stale-detection and run concurrently. New code: `os.OpenFile(O_CREATE|O_EXCL)` with stale-detection retry-once. Only first writer wins; loser observes `ErrAlreadyRunning`.

Full report: [`docs/security-review-2026-05-codex.md`](docs/security-review-2026-05-codex.md).

### Deferred — H1 (manifest rollback) + full H3 (scope-subset validation)

- **H1**: a malicious transport can serve an older valid encrypted manifest. AES-GCM + prev_sig chain both still pass — the older prefix really was valid once. Fix requires persistent state (last-seen tail anchor in `state.db`) coordinated with the browser side's tab-scoped anchor. v1.x work, tracked.
- **H3 (full scope-subset validation)**: the refreshed capability is currently only checked for expiry bounds. Full scope-subset validation (issuer, primitive, namespace, operations) requires importing the `fabric-sdk-go` macaroon decoder and matching test fixtures. The macaroon format is opaque to the daemon by design (the Hub verifies with the root key); adding daemon-side parsing is real work. v1.x. The expiry bound closes the highest-impact concrete attack (unrevokable credential), which is the meaningful payload here.

## [1.0.0] — 2026-05-21

First binary release. See [README](README.md) + the corresponding GitHub Release for the full set.
