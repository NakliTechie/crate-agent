# Wire-protocol audit

**Status:** Pending — completed at M1 before any sync code is written.

The vision and handoff docs require this audit before crate-agent build starts in earnest. The five questions:

1. Does `fabric-spec-001` assume WebSocket framing, or work over plain HTTP/HTTP2/QUIC/TCP?
2. Does Sync's session model assume tab-scoped lifetimes (open/close events tied to UI presence)?
3. Are SDK calls in `fabric-sdk-go` callable from a non-browser long-running process today, or is the SDK currently shaped around browser patterns?
4. Are auth tokens / Identity proofs in `fabric-sdk-go` scoped in a way that breaks for a daemon with a long-lived pairing token?
5. Does the pairing-token model (browser issues, daemon redeems) exist in the fabric, or do we need to add it?

A quick scan during M0 absorption found:
- Sync is defined as HTTP endpoints (no WebSocket assumption) → likely **no problem** for (1) and (2).
- (3) and (4) need real exercise: stand up a `nakli-hub`, run a long-lived Go program against it for an hour, confirm macaroons + caveats don't shed scope.
- (5) is the substantive finding: the pairing-token endpoints (`/v1/pairing/intent`, `/v1/pairing/redeem`, `/v1/pairing/intent/cancel`, `/v1/capability/refresh`, `DELETE /v1/capability/{id}`) **do not exist** in `nakli-hub` or `nakli-cf-worker` today. Adding them is in-scope for crate-agent M1.

Real audit happens at M1.
