# Config reference

Schema for `~/.config/nakli/crate-agent.toml` (Linux/macOS, XDG-respecting) or `%APPDATA%\nakli\crate-agent.toml` (Windows; v1.1).

The user does not hand-write this. `crate-agent pair` (M2) creates it; `crate-agent reconfigure` (M3) re-reads it; `crate-agent doctor` (M1) validates it.

## Sections

### `[agent]` — runtime + observability

| Field | Type | Default | Notes |
|---|---|---|---|
| `log_level` | string | `"info"` | One of `debug`, `info`, `warn`, `error` |
| `log_path` | string (path) | platform default | Tilde-prefixed paths allowed; expanded on load |
| `state_db` | string (path) | platform default | SQLite path for daemon state (M3+) |

### `[identity]` — Fabric Identity File pointer

| Field | Type | Notes |
|---|---|---|
| `path` | string (path) | Required. Tilde-prefixed paths allowed. File must exist on disk with mode 0600. Created by `pair` (M2). |

### `[crate]` — the folder being synced

v1.0 supports exactly one `[crate]` section. v1.3 promotes this to an array `[[crate]]` for multi-folder.

| Field | Type | Notes |
|---|---|---|
| `name` | string | Display name. User-chosen during `pair`. |
| `local_path` | string (path) | Required. The folder being synced. |
| `transport_endpoint` | string (URL) | Required. e.g. `https://my-account.workers.dev` or `http://127.0.0.1:7842` |
| `transport_type` | string | `cf-worker`, `hub`, `managed`, or `carrier` (a crate-carrier Worker; `transport_endpoint` is its URL). |
| `pairing_token` | string | Encrypted blob bound to the identity key. Opaque from the user's view. Populated by `pair`. For `carrier`, this is the Worker's `CARRIER_SECRET`, encrypted under the passphrase-derived key. |
| `bucket_id` | string (ULID) | Opaque reference to the bucket. Not credentials — the daemon never sees S3 keys. |
| `encrypt_at_rest` | bool | Default `false`. Plaintext locally is the default — encryption lands at M3. |

## Example

See [`internal/config/sample.toml`](../internal/config/sample.toml) for a working sample. Skeleton:

```toml
[agent]
log_level = "info"
log_path  = "~/.local/share/nakli/crate-agent.log"
state_db  = "~/.local/share/nakli/crate-agent.db"

[identity]
path = "~/.config/nakli/identity.key"

[crate]
name               = "personal"
local_path         = "~/crate"
transport_endpoint = "http://127.0.0.1:7842"
transport_type     = "hub"
pairing_token      = "REDACTED"
bucket_id          = "01H..."
encrypt_at_rest    = false
```

## Validation

`crate-agent doctor` validates at startup:

- `agent.log_level` is one of the four allowed values (or empty → defaults to `info`).
- `identity.path` is set.
- `crate.local_path` is set.
- `crate.transport_endpoint` is set.

Additional fields are validated as the corresponding milestones land (bucket_id format at M2, pairing_token decryption at M3, etc.).

## Tilde expansion

Paths in `agent.log_path`, `agent.state_db`, `identity.path`, and `crate.local_path` are tilde-expanded against `$HOME` (resolved via `os.UserHomeDir()`). Other path-like fields (`transport_endpoint`, `pairing_token`, `bucket_id`) are passed through verbatim.
