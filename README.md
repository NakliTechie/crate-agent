# crate-agent

A small Go binary that watches `~/crate/` and keeps it in sync with the user's Crate. Cloud is canonical, the daemon is a cache. **The daemon does not hold bucket credentials** — it authenticates to a transport (`nakli-hub` or `nakli-cf-worker`) via a pairing token issued by the browser Crate. This is a security property, not a layering accident.

Build target: single statically-linked Go binary per OS. v1.0 ships macOS + Linux; Windows is v1.1.

## Status

**M0** — skeleton. The pairing flow lands at M2; one-direction upload at M3; bidirectional sync at M4. See [`docs/specs/crate-daemon-handoff-v1.0.md`](docs/specs/crate-daemon-handoff-v1.0.md) for the full milestone plan and [`crate-pairing-protocol-v1.0.md`](../private-mesh/docs/specs/crate-pairing-protocol-v1.0.md) (in the sibling `private-mesh` repo) for the cross-surface contract. The vision doc lives in `private-mesh` too: [`crate-vision-and-roadmap-v1.0.md`](../private-mesh/docs/specs/crate-vision-and-roadmap-v1.0.md).

## Build

```sh
make all          # cross-compile to darwin amd64+arm64 + linux amd64+arm64
./smoke.sh        # M0 gate
```

## Licence

AGPL-3.0-or-later. See [`LICENSE`](LICENSE).
