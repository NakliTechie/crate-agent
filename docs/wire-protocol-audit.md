# Wire-protocol audit

Date: 2026-05-18
Scope: pre-build audit required by `docs/specs/crate-daemon-handoff-v1.0.md` §"Pre-build audit (REQUIRED — do not skip)" before any crate-agent code lands.

Method: read [`fabric-spec-001-v1.0.md`](../../private-mesh/docs/specs/fabric-spec-001-v1.0.md), [`crate-pairing-protocol-v1.0.md`](../../private-mesh/docs/specs/crate-pairing-protocol-v1.0.md), the `fabric-sdk-go` source, and `nakli-hub`'s handler source against the daemon's 5 pre-build questions.

## Summary

| # | Question | Finding | Action |
|---|---|---|---|
| 1 | WebSocket vs HTTP transport? | HTTP/1.1 or HTTP/2 + JSON; SSE for `vault.subscribe` | None |
| 2 | Sync = tab-scoped? | No, peer-based; daemon is just another peer | None |
| 3 | SDK callable from daemon? | Partially — primitives only; no Transport/Client type | Daemon-side workaround: thin HTTP wrapper in `internal/httpc/` |
| 4 | Token scoping issues? | No browser-session caveat exists; macaroon catalogue supports long-lived daemon credentials | None |
| 5 | CRATE-PAIR endpoints exist? | Device-pair endpoints exist; CRATE-PAIR endpoints DO NOT — that's the deferred Unit C | None for M1; **Unit C is an M2 blocker** |

**Result**: M1 may proceed. M2 is gated on Unit C (Hub-side CRATE-PAIR endpoints in `nakli-hub` + `nakli-cf-worker`). No fabric-protocol revisions required.

---

## 1. WebSocket vs HTTP/HTTP2/QUIC/TCP

**Question**: Does `fabric-spec-001` assume WebSocket framing, or work over plain HTTP/HTTP2/QUIC/TCP?

**Finding**: **HTTP/1.1 or HTTP/2 + JSON throughout. SSE for streaming. No WebSocket.**

**Evidence**:
- `private-mesh/docs/specs/fabric-spec-001-v1.0.md:63` — "All requests and responses are HTTP/1.1 or HTTP/2 with JSON bodies. UTF-8 throughout."
- `private-mesh/docs/specs/fabric-spec-001-v1.0.md:68` — wire-format template uses `POST /fabric/v1/<endpoint> HTTP/1.1`.
- `private-mesh/nakli-hub/internal/server/handlers_vault_more.go:64–150` — `vault.subscribe` implements Server-Sent Events over HTTP (`Content-Type: text/event-stream`, 500ms poll ticker, 15s heartbeat). No WebSocket upgrade anywhere.
- History, Identity, Grant, Bridge, LLM endpoints — all plain HTTP POST/GET with JSON bodies. Confirmed by sweep of `private-mesh/nakli-hub/internal/server/handlers_*.go`.

**Implication**: Daemon uses Go's `net/http`. For `vault.subscribe` (lands at M4+), the daemon will hold a long-lived response body and parse line-delimited events — well-supported by `net/http`.

**Action**: None.

## 2. Sync session model — tab-scoped or peer-based?

**Question**: Does Sync's session model assume tab-scoped lifetimes (open/close events tied to UI presence)?

**Finding**: **No.** Sync is peer-based; the protocol has no "session open/close" semantics. The daemon is just another peer with a persistent `peer_id`.

**Evidence**:
- `private-mesh/docs/specs/crate-vision-and-roadmap-v1.0.md:24` — Browser vs daemon row explicitly distinguishes: "When syncing: Tab open | Daemon running". Daemon is a *valid* peer shape.
- `private-mesh/docs/specs/crate-vision-and-roadmap-v1.0.md:44` — "Tab-scoped sync is correct, not a limitation." (Phrased about browser surface; doesn't constrain daemon presence.)
- `private-mesh/docs/specs/fabric-spec-001-v1.0.md:541–566` — `/sync/peers`, `/sync/push`, `/sync/pull`, `/sync/conflict-ack` are stateless HTTP. Peers identified by `peer_id` (opaque ULID) + `last_seen` + `freshness_ms` — no session token, no "tab close" event.
- `private-mesh/nakli-hub/internal/server/handlers_vault_more.go:106–150` — the SSE stream closes when the client closes the connection. No session bookkeeping on top.

**Implication**: Daemon implements its sync loop as a long-lived background goroutine: subscribe via SSE (M4+), `/sync/pull` periodically, `/sync/push` on local change. Standard HTTP-client retry-on-disconnect handles transient network blips.

**Action**: None.

## 3. SDK callability from a long-running Go process

**Question**: Are SDK calls in `fabric-sdk-go` callable from a non-browser long-running process today, or is the SDK currently shaped around browser patterns?

**Finding**: **Partially. Primitives are usable today (crypto, identity, grant). There is no top-level Transport / Client type that wraps HTTP requests — the daemon must build its own thin wrapper.**

**Evidence**:
- `private-mesh/fabric-sdk-go/README.md` — roadmap notes "transports and primitive clients land at M2–M5.5". The Go SDK is intentionally primitives-only at fabric M1.
- `private-mesh/fabric-sdk-go/identity/fif.go` — `ParseFIF(io.Reader) (*FIF, error)`, `FIF.Unlock(passphrase string) error`. Pure crypto + parsing; no network code.
- `private-mesh/fabric-sdk-go/grant/macaroon.go` — `Mint(spec)`, `Parse(bytes)`, `VerifySignature(key, checkFunc)`. No HTTP layer.
- `private-mesh/fabric-sdk-go/crypto/` — XChaCha20-Poly1305, HKDF, Argon2id. Pure crypto.
- `private-mesh/fabric-sdk-go/conformance/client.go` — there *is* an HTTP client here, but it lives inside the conformance suite (designed for testing the Hub, not for general client use); it's not the SDK's public client surface.
- `private-mesh/nakli-cli/internal/httpc/` — the reference CLI's HTTP client lives in `internal/`, which means it's not importable across modules (Go's `internal/` packaging rules block cross-module imports).

**Implication**: For M1, the daemon needs to GET `/fabric/v1/health` — an unauthenticated endpoint. A minimal `net/http` wrapper (~40 LOC) in `crate-agent/internal/httpc/httpc.go` covers it. M2 adds authenticated requests bearing the daemon's capability macaroon (issued during pairing); same wrapper grows to support it. Consolidating a richer client into `fabric-sdk-go/client/` is a candidate task at the fabric's M5.5 milestone — out of scope here.

**Action**: Daemon-side workaround acceptable. Build `crate-agent/internal/httpc/` per the design in the M1 plan.

## 4. Token scoping for a long-lived daemon

**Question**: Are auth tokens / Identity proofs in `fabric-sdk-go` scoped in a way that breaks for a daemon with a long-lived pairing token?

**Finding**: **No.** The macaroon caveat catalogue has no browser-session-scoped caveats. Daemon credentials can be long-lived and refreshable as the pairing protocol specifies.

**Evidence**:
- `private-mesh/docs/specs/fabric-spec-001-v1.0.md:341–358` — v1.0 first-party caveat catalogue: `time`, `principal-type`, `agent-id`, `device-id`, `operation`, `namespace`, `rate`, `max-amount`, `only-domain`, `requires-human-approval`, `nondelegatable`, `idempotency-required`, `discharge-from`. **No `browser_session_id`, `tab_id`, or similar.**
- `private-mesh/docs/specs/crate-pairing-protocol-v1.0.md` §"Capability lifecycle" — daemon capability has a 1-year TTL, refresh permitted from 80% TTL onward. The Identity binding is via `device_id` / `agent_id` caveats, both of which are well-suited to a persistent daemon.
- `private-mesh/nakli-hub/internal/server/handlers_identity.go` — device-pair flow issues an enrollment grant with a `device_id` caveat; no session binding.

**Implication**: Daemon's capability (issued during M2 pairing) sits as a long-lived bearer credential. No special handling needed for "session expiry" — only the 1-year capability TTL plus optional refresh.

**Action**: None.

## 5. CRATE-PAIR pairing-token model in the fabric

**Question**: Does the pairing-token model (browser issues, daemon redeems) exist in the fabric, or do we need to add it?

**Finding**: **The protocol is fully specified. The endpoints DO NOT exist on the Hub or CF Worker yet.** This is the deferred **Unit C** work from the absorption plan, intended to land before crate-agent reaches M2.

**Important precision** — two separate pairing flows must not be confused:

| Flow | Source | Endpoints | Status |
|---|---|---|---|
| **Device pairing** (already-authenticated source device adds a new device to its Identity) | `fabric-spec-001-v1.0.md` §Identity | `POST /fabric/v1/identity/pair/initiate`, `POST /fabric/v1/identity/pair/complete` | **EXISTS** on `nakli-hub` (`internal/server/handlers_identity.go`) |
| **CRATE-PAIR** (browser Crate issues a one-shot token; non-browser daemon redeems it for a transport capability) | `crate-pairing-protocol-v1.0.md` | `POST /v1/pairing/initiate`, `POST /v1/pairing/redeem` | **DOES NOT EXIST** on any transport |

**Evidence for "device pairing exists"**:
- `private-mesh/nakli-hub/internal/server/handlers_identity.go` — routes `POST /fabric/v1/identity/pair/initiate` (authenticated) + `POST /fabric/v1/identity/pair/complete` (unauthenticated; the pairing_token IS the auth) wired with full handlers (`handlePairInitiate`, `handlePairComplete`).
- `private-mesh/nakli-hub/internal/storage/schema.go` — has `pairing_tokens` table with `expires_at` index.

**Evidence for "CRATE-PAIR doesn't exist"**:
- Repo-wide search for the path `/v1/pairing/redeem` (or `/v1/pairing/initiate`) in `private-mesh/nakli-hub/` and `private-mesh/nakli-cf-worker/` returns zero hits.
- The CRATE-PAIR spec at `crate-pairing-protocol-v1.0.md:117` mandates `POST /v1/pairing/redeem` on the transport. The transports haven't been extended to serve it.
- The reference test vectors at `private-mesh/docs/test-vectors/crate-pairing/test-vectors.json` exist (landed in the absorption commit) but nothing consumes them yet.

**Implication**:
- For **M1**: no impact. The audit + the SDK binding + the doctor command don't need any pair flow.
- For **M2**: **blocker**. The daemon's `crate-agent pair` command (Phase 3 of `crate-pairing-protocol-v1.0.md`) is supposed to POST to `/v1/pairing/redeem`. That endpoint must exist on at least one transport before M2 can be implemented end-to-end.

**Action**:
- M1: none.
- Before M2: complete **Unit C** — add `POST /v1/pairing/initiate` + `POST /v1/pairing/redeem` to `nakli-hub` (canonical reference) and `nakli-cf-worker` (zero-ops surface) per `crate-pairing-protocol-v1.0.md`. Wire them against the existing `pairing_tokens` storage (or extend it). Verify against the test vectors at `private-mesh/docs/test-vectors/crate-pairing/test-vectors.json`.

## Conclusion

The fabric protocol and `fabric-sdk-go` are compatible with the daemon's M1 requirements. One outstanding gap (Unit C) blocks M2 but not M1 — flagged here, tracked in `plan/pending.md`, and surfaced in the M1 commit message.

Proceeding to M1 code: SDK binding (replace directive), identity loader, minimal HTTP client, `doctor` command, smoke gate.
