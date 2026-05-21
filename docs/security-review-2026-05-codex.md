# crate-agent (daemon) — security review (Codex, 2026-05)

**Status as of 2026-05-21**:
- v1.0.0 quick fixes: H2 (path traversal) patched in [`73a37d7`](https://github.com/NakliTechie/crate-agent/commit/73a37d7); H3 expiry bound + H4 + M1 + L1 + L2 in [`3e20892`](https://github.com/NakliTechie/crate-agent/commit/3e20892).
- v1.0.1 (architectural patches): H1 (manifest rollback) + full H3 (scope-subset via `fabric-sdk-go/grant.Parse`) landed in v1.0.1. New `state.manifest_anchor` table (migration v3); puller validates against the anchor on every tick. Refresh runner now decodes both current + refreshed macaroons and enforces issuer / primitive / namespace / operations-subset.
- **No outstanding audit items.**

The body below is the raw audit output, unedited.

---

## Critical
(none found)

## High

1. **File:** `internal/puller/puller.go:203-240`, `internal/puller/puller.go:257-270`  
   **What:** The puller accepts a transport-reported `404` as an empty manifest and accepts older valid encrypted manifests without any persisted head/count rollback check.  
   **Why it matters:** A malicious transport can make synced files look remotely deleted, or replay an older signed manifest, causing the daemon to remove or roll back local files even though it cannot forge AES-GCM/HMAC.  
   **Fix:** Persist the last accepted manifest head, event count, or monotonic version locally and reject absent/older/truncated manifests unless the user explicitly chooses recovery.

2. **File:** `internal/puller/puller.go:276-303`, `internal/puller/puller.go:358-369`  
   **What:** Manifest paths are joined directly to `LocalPath` after only stripping one leading slash, with no containment check.  
   **Why it matters:** A signed manifest entry such as `../../.ssh/authorized_keys` can materialise outside the crate root and be atomically written as the daemon user.  
   **Fix:** Canonicalise manifest paths as crate-relative paths, reject absolute paths and `..` components, and verify the final path remains under the crate root before mkdir/write/rename.

3. **File:** `internal/refresh/refresh.go:214-261`  
   **What:** Capability refresh blindly trusts the returned capability and expiry, and ignores response version/scope validation.  
   **Why it matters:** A malicious transport can return a wider-scope capability, which the daemon then encrypts to disk and sends on future requests, increasing the impact of later config theft or transport abuse.  
   **Fix:** Decode and validate the refreshed macaroon locally, requiring version match, expected bucket/audience, expiry bounds, and scope subset of the current capability before persisting it.

4. **File:** `internal/syncer/syncer.go:393-397`, `internal/syncer/syncer.go:453-470`  
   **What:** `executePut` snapshots `existing` under the manifest mutex, releases the lock for encryption/upload, then appends an update/create based on that stale snapshot.  
   **Why it matters:** If the puller replaces the manifest in between, the syncer can append an update for a UUID no longer present, mark the upload successful, and lose the user’s local change.  
   **Fix:** Re-check the current manifest state under the mutex immediately before append, and abort/retry the row if the UUID/path basis changed.

## Medium

1. **File:** `internal/refresh/refresh.go:261`, `internal/syncer/syncer.go:382-383`, `internal/puller/puller.go:195-196`  
   **What:** `CapabilityRef` is read and written from multiple goroutines without a mutex or atomic value.  
   **Why it matters:** This is a Go data race; under refresh load it can produce undefined behavior, malformed auth headers, or stale capability use.  
   **Fix:** Store the capability in `atomic.Value` or protect all reads/writes with a shared mutex.

## Low / Informational

1. **File:** `internal/manifest/manifest.go:124-129`  
   **What:** Manifest verification compares base64 HMAC strings with `!=` instead of constant-time byte comparison.  
   **Why it matters:** The primitive helper uses `hmac.Equal`, but this path reintroduces a timing side channel if an attacker can observe fine-grained verification timing.  
   **Fix:** Decode `sig` and compare raw HMAC bytes with `hmac.Equal` or route verification through `payload.HMACVerify`.

2. **File:** `internal/pidfile/pidfile.go:51-67`  
   **What:** PID-file creation uses read-then-write-then-rename rather than an exclusive create/lock.  
   **Why it matters:** Two simultaneous starts can both pass stale detection and run concurrently, undermining the single-writer assumption.  
   **Fix:** Use an advisory lock or `O_CREATE|O_EXCL` lockfile pattern, with stale cleanup guarded by re-checking ownership.

## Wire-format compatibility check

Compared `internal/payload/payload.go` with `../crate/lib/crypto.js`, plus `internal/manifest/manifest.go` with `../crate/lib/manifest.js`, and `internal/kdf/kdf.go` with JS `deriveMasterKey`.

Aligned: AES-256-GCM, 12-byte IVs, `IV || ciphertext || tag` layout, file UUID AAD, manifest AAD `.crate/manifest.jsonl.enc:v1`, PBKDF2-SHA256 with 600,000 iterations and 32-byte output, standard base64 event fields, and lexicographic canonical JSON for the event shapes in use.

Divergent but not currently exploitable in normal calls: Go rejects empty file UUID AAD for data-key wrapping while JS would omit AAD if `fileUuid` is falsey. Manifest verification in Go also uses a non-constant-time string compare.

## Confirmed-safe areas

No bucket credentials or passphrase are written to the Go daemon config or state DB. The config stores the capability encrypted under the derived master key, and `config.Write` and `identity.Write` create parent directories as `0700` and files as `0600`.

Payload encryption checks `crypto/rand` errors, uses fresh random IVs, binds file UUIDs as AAD, and authenticates before plaintext use. SQL access in `internal/state` uses placeholders for user-controlled values. The HTTP client does not disable TLS verification and consistently passes the capability in `X-Fabric-Grant`.