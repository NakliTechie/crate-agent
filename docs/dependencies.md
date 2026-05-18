# Dependencies

Every runtime dependency is listed here with its source, version, and licence. AGPL-3.0-or-later compatibility is required per the spec §"Dependencies".

| Module | Version | Licence | Why |
|---|---|---|---|
| [`github.com/spf13/cobra`](https://github.com/spf13/cobra) | 1.10.2 | Apache-2.0 | CLI subcommand framework. Aligned with `nakli-cli`. |
| [`github.com/spf13/pflag`](https://github.com/spf13/pflag) | 1.0.10 | BSD-3-Clause | Cobra dep. |
| [`github.com/inconshreveable/mousetrap`](https://github.com/inconshreveable/mousetrap) | 1.1.0 | Apache-2.0 | Cobra dep (Windows-only). |
| [`github.com/BurntSushi/toml`](https://github.com/BurntSushi/toml) | 1.6.0 | MIT | Config-file parser per spec §"Config file format". |
| [`github.com/NakliTechie/private-mesh/fabric-sdk-go`](https://github.com/NakliTechie/private-mesh) | local (replace) | Apache-2.0 | Primary SDK binding — Identity / Grant / crypto primitives. |
| [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto) | 0.51.0 | BSD-3-Clause | Transitive via fabric-sdk-go. |
| [`golang.org/x/sys`](https://pkg.go.dev/golang.org/x/sys) | 0.44.0 | BSD-3-Clause | Transitive via fabric-sdk-go. |

All allowed under spec §"Dependencies — Allowed". No CGO deps (per spec, breaks static linkage). No GPL-2.0-only deps (incompatible with AGPL-3.0-or-later).

## Future additions (planned)

| Module | Milestone | Notes |
|---|---|---|
| `github.com/fsnotify/fsnotify` | M3 | Filesystem watcher per spec §"Filesystem watching". |
| `modernc.org/sqlite` | M3 | Pure-Go SQLite for local state. Chosen over `mattn/go-sqlite3` (CGO) per spec §"Dependencies". |
| `github.com/kardianos/service` | later | Cross-platform service installer (launchd / systemd). Per spec, write per-OS code instead if its shape doesn't fit. |

## Notes

- `fabric-sdk-go` is consumed via a `replace` directive in `go.mod` pointing at the sibling `private-mesh` repo (`../private-mesh/fabric-sdk-go`). Migration to a tagged published version is one line when one exists.
- The conformance package (`fabric-sdk-go/conformance/`) is *not* imported — the daemon brings its own thin HTTP client (`internal/httpc/`) to keep the conformance code unencumbered by daemon runtime concerns.
