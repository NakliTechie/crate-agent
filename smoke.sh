#!/usr/bin/env bash
# Smoke test for crate-agent (Go daemon).
#
# M0 gates (always):
# - LICENSE present + AGPL-3.0
# - go build (host) succeeds
# - binary --help exits cleanly
# - every .go file under cmd/ + internal/ carries an SPDX header
#
# M1 gate (added when M1 lands):
# - Builds nakli-hub + nakli-cli from the sibling private-mesh repo
# - Spins up a Hub on a free port, mints a real FIF via nakli-cli init
# - Writes a crate-agent config.toml pointing at both
# - Runs `crate-agent doctor` and asserts exit 0
# - Tears down on exit
#
# Skip the M1 gate (M0-only mode) with: SKIP_M1=1 ./smoke.sh
set -euo pipefail
cd "$(dirname "$0")"

if [[ ! -f LICENSE ]]; then
  echo "FAIL: LICENSE missing"; exit 1
fi
if ! grep -q "AFFERO GENERAL PUBLIC LICENSE" LICENSE; then
  echo "FAIL: LICENSE is not AGPL-3.0"; exit 1
fi

tmp=$(mktemp -d -t crate-agent-smoke.XXXXXX)
trap '
  [[ -n "${hub_pid:-}" ]] && kill "$hub_pid" 2>/dev/null || true
  rm -rf "$tmp"
' EXIT

echo "==> go build (host)"
go build -o "$tmp/crate-agent" .

echo "==> --help"
"$tmp/crate-agent" --help > /dev/null

echo "==> SPDX headers"
missing=0
while IFS= read -r f; do
  if ! head -3 "$f" | grep -q "SPDX-License-Identifier"; then
    echo "FAIL: $f missing SPDX header"
    missing=1
  fi
done < <(find cmd internal main.go -type f -name "*.go" 2>/dev/null)
if (( missing )); then exit 1; fi

if [[ "${SKIP_M1:-}" == "1" ]]; then
  echo "OK: crate-agent (M0 only — SKIP_M1=1)"
  exit 0
fi

# --- M1 gate: doctor against a live Hub --------------------------------

# Locate the sibling private-mesh repo. Default = post-reorg layout
# (private-mesh-universe/private-mesh, sibling of crate-agent).
private_mesh="${PRIVATE_MESH:-../private-mesh}"
if [[ ! -d "$private_mesh/nakli-hub" || ! -d "$private_mesh/nakli-cli" ]]; then
  echo "FAIL: PRIVATE_MESH=$private_mesh does not contain nakli-hub + nakli-cli" >&2
  exit 1
fi

echo "==> Building nakli-hub + nakli-cli (from $private_mesh)"
(cd "$private_mesh/nakli-hub" && go build -o "$tmp/nakli-hub" ./cmd/nakli-hub)
(cd "$private_mesh/nakli-cli" && go build -o "$tmp/nakli-cli" ./cmd/nakli-cli)

hub_data="$tmp/hub-data"
cli_config="$tmp/cli/config.toml"
cli_fif="$tmp/cli/identity.fif"

port=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()' 2>/dev/null || echo 17944)
target="http://127.0.0.1:${port}"

echo "==> Initializing + starting Hub on $target"
"$tmp/nakli-hub" init --data-dir "$hub_data" > "$tmp/hub-init.log"
"$tmp/nakli-hub" serve \
  --config "$hub_data/config.json" \
  --listen "127.0.0.1:${port}" \
  > "$tmp/hub.log" 2>&1 &
hub_pid=$!
for _ in $(seq 1 50); do
  if curl -fsS "${target}/fabric/v1/health" >/dev/null 2>&1; then break; fi
  sleep 0.1
done

echo "==> Minting a FIF via nakli-cli init"
printf 'pass-crate-agent-smoke\n' | "$tmp/nakli-cli" \
  --config "$cli_config" \
  --passphrase-stdin \
  init --non-interactive \
       --display-name "crate-agent smoke" \
       --fif "$cli_fif" \
       --hub-url "$target" \
       --hub-data-dir "$hub_data" > /dev/null

echo "==> Writing crate-agent config.toml"
agent_cfg="$tmp/crate-agent.toml"
cat > "$agent_cfg" <<EOF
[agent]
log_level = "info"

[identity]
path = "$cli_fif"

[crate]
name               = "smoke"
local_path         = "$tmp/crate-folder"
transport_endpoint = "$target"
transport_type     = "hub"
pairing_token      = "n/a-at-M1"
bucket_id          = "n/a-at-M1"
encrypt_at_rest    = false
EOF
mkdir -p "$tmp/crate-folder"

echo "==> Running crate-agent doctor"
CRATE_AGENT_PASSPHRASE="pass-crate-agent-smoke" \
  "$tmp/crate-agent" doctor --config "$agent_cfg"

echo "OK: crate-agent (M1 — wire audit + SDK binding + doctor against live Hub)"
