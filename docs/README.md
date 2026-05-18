# crate-agent docs

See [`crate-daemon-handoff-v1.0.md`](../../private-mesh/docs/specs/crate-daemon-handoff-v1.0.md) (sibling `private-mesh` repo) for the full handoff: repository layout, dependency policy, config schema, sync-loop pseudocode, service-file install paths, error codes, and per-milestone gates.

## Milestones

| M | Theme |
|---|---|
| M0 | Skeleton (this commit) |
| M1 | Wire-protocol audit + SDK binding sanity check |
| M2 | `crate-agent pair` — Phase 3 of the pairing protocol end-to-end |
| M3 | One-direction upload — watch a folder, push to transport |
| M4 | Bidirectional sync — receive cloud events, materialise locally |
| M5 | Full ops — delete / rename / move / mkdir round-trip; conflicts |
| M6 | Service install — launchd + systemd |
| M7 | Status + doctor + docs |
| M8 | Ship — release binaries with SHA-256 checksums |
