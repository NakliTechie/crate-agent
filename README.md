# crate-agent

A small Go binary that watches `~/crate/` and keeps it in sync with the user's Crate. Cloud is canonical, the daemon is a cache. **The daemon does not hold bucket credentials** — it authenticates to a transport (`nakli-hub` or `nakli-cf-worker`) via a pairing token issued by the browser Crate. This is a security property, not a layering accident.

Build target: single statically-linked Go binary per OS. v1.0 ships macOS + Linux; Windows is v1.1.

## Status

**M1** — wire audit + SDK binding. [`docs/wire-protocol-audit.md`](docs/wire-protocol-audit.md) catalogues the 5 pre-build questions (per spec §"Pre-build audit") with file:line evidence. `fabric-sdk-go` is bound via a `replace` directive. `crate-agent doctor` performs three real checks against a live Hub: config validity, FIF unlock, transport health. The pairing flow lands at M2 (blocked on Unit C — see `plan/pending.md`); one-direction upload at M3; bidirectional sync at M4. See [`docs/specs/crate-daemon-handoff-v1.0.md`](docs/specs/crate-daemon-handoff-v1.0.md) for the full milestone plan and [`crate-pairing-protocol-v1.0.md`](../private-mesh/docs/specs/crate-pairing-protocol-v1.0.md) (in the sibling `private-mesh` repo) for the cross-surface contract. The vision doc lives in `private-mesh` too: [`crate-vision-and-roadmap-v1.0.md`](../private-mesh/docs/specs/crate-vision-and-roadmap-v1.0.md).

## Build

```sh
make all          # cross-compile to darwin amd64+arm64 + linux amd64+arm64
./smoke.sh        # M1 gate (builds nakli-hub + nakli-cli from ../private-mesh,
                  # spins up Hub, mints a FIF, runs doctor against it).
                  # SKIP_M1=1 ./smoke.sh runs only the M0 build + SPDX checks.
```

## Licence

AGPL-3.0-or-later. See [`LICENSE`](LICENSE).
