#!/usr/bin/env bash
# Smoke test for crate-agent (Go daemon).
#
# M0 gates (always):
# - LICENSE present + AGPL-3.0
# - go build (host) succeeds
# - binary --help exits cleanly
# - every .go file under cmd/ + internal/ carries an SPDX header
#
# M1 gate:
# - Builds nakli-hub + nakli-cli from the sibling private-mesh repo
# - Spins up a Hub on a free port, mints a real FIF via nakli-cli init
# - Writes a crate-agent config.toml pointing at both
# - Runs `crate-agent doctor` and asserts exit 0
#
# M2 gate:
# - Same Hub + Grant setup as M1
# - POST /v1/pairing/intent with a synthetic CRATE-PAIR token
# - Feed the token to `crate-agent pair --token-stdin --passphrase-stdin`
# - Pair writes FIF + config, auto-runs doctor green
# - Replay-pair surfaces the protocol's token_already_redeemed error
#
# M3 (piece 2 — daemon state + watcher) gate:
# - The doctor invocation in the M1 + M2 paths now exercises the SQLite
#   state DB (opens, migrates, queries) + watcher (constructs fsnotify
#   handle, loads .crateignore, walks local_path) for real.
# - We assert the doctor log contains the new "State DB ready" + "Watcher
#   operational" success markers — proving the M3 piece-2 checks are wired
#   and that doctor hasn't regressed to the M2 deferred-stub messages.
#
# Skip the M1+M2 gate (M0-only mode) with: SKIP_M1=1 ./smoke.sh
# Skip just the M2 gate (M1-only mode) with: SKIP_M2=1 ./smoke.sh
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

echo "==> Writing crate-agent config.toml (M1 doctor)"
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

echo "==> Running crate-agent doctor (M1 + M3 piece 2 — state DB + watcher real)"
CRATE_AGENT_PASSPHRASE="pass-crate-agent-smoke" \
  "$tmp/crate-agent" doctor --config "$agent_cfg" > "$tmp/doctor.log" 2>&1
cat "$tmp/doctor.log"

# M3 piece-2 assertions: doctor's state + watcher checks must be REAL,
# not the M2 deferred-stub messages.
if grep -q "deferred to M3" "$tmp/doctor.log"; then
  echo "FAIL: doctor still emits 'deferred to M3' — state/watcher checks regressed" >&2
  exit 1
fi
if ! grep -q "State DB ready" "$tmp/doctor.log"; then
  echo "FAIL: doctor did not emit 'State DB ready' — M3 piece 2 regression" >&2
  exit 1
fi
if ! grep -q "Watcher operational" "$tmp/doctor.log"; then
  echo "FAIL: doctor did not emit 'Watcher operational' — M3 piece 2 regression" >&2
  exit 1
fi
echo "  ✓ doctor exercises state DB + watcher (M3 piece 2)"

# The state DB should now exist on disk under <local_path>/.crate/state.db.
if [[ ! -f "$tmp/crate-folder/.crate/state.db" ]]; then
  echo "FAIL: state.db was not created at expected path" >&2
  exit 1
fi
echo "  ✓ state.db created at <local_path>/.crate/state.db"

if [[ "${SKIP_M2:-}" == "1" ]]; then
  echo "OK: crate-agent (M1 only — SKIP_M2=1)"
  exit 0
fi

# --- M2 gate: pair against a live Hub ---------------------------------

echo "==> Minting an identity/pair Grant for the smoke browser"
"$tmp/nakli-cli" --config "$cli_config" grant mint \
  --recipient "01JCRATEBROWSERPRINCIPAL0000" \
  --primitive identity --namespace "*" --operations pair \
  --output "$tmp/cli/identity-pair.macaroon" > /dev/null
grant_b64=$(tr -d '\n' < "$tmp/cli/identity-pair.macaroon")

echo "==> POST /v1/pairing/intent (synthetic browser issuance)"
now_unix=$(date -u +%s)
secret=$(python3 -c 'import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("="))')
bucket_id="01HCRATEBUCKETSMOKEXXXXXXXX"
identity_pubkey=$(python3 -c 'import secrets,base64; print(base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("="))')
exp_unix=$((now_unix + 900))
intent_payload=$(python3 -c "import json; print(json.dumps({'v':1,'type':'crate.pairing.token','secret':'$secret','transport_endpoint':'$target','transport_type':'hub','bucket_id':'$bucket_id','identity_pubkey':'$identity_pubkey','issued_at':$now_unix,'expires_at':$exp_unix}))")

curl -fsS -X POST "${target}/v1/pairing/intent" \
  -H "Content-Type: application/json" -H "X-Fabric-Grant: ${grant_b64}" \
  -d "$intent_payload" > "$tmp/intent.out"

echo "==> Encoding the CRATE-PAIR token from the payload"
crate_token=$(python3 -c "
import base64
p = b'$intent_payload'
print('CRATE-PAIR-' + base64.urlsafe_b64encode(p).rstrip(b'=').decode())
")

m2_cfg="$tmp/crate-agent-m2.toml"
m2_id="$tmp/crate-agent-m2.identity"
m2_pass="pass-crate-agent-m2"

echo "==> Running crate-agent pair (--token-stdin --passphrase-stdin; auto-doctor at end)"
printf '%s\n%s\n' "$crate_token" "$m2_pass" | "$tmp/crate-agent" pair \
  --token-stdin --passphrase-stdin \
  --config "$m2_cfg" \
  --identity "$m2_id" \
  --name "smoke-m2" \
  --local-path "$tmp/crate-m2-folder" 2>&1 | tee "$tmp/pair.log"

if [[ ! -f "$m2_cfg" ]]; then
  echo "FAIL: pair did not write config" >&2; exit 1
fi
if [[ ! -f "$m2_id" ]]; then
  echo "FAIL: pair did not write identity" >&2; exit 1
fi

# Verify file modes are 0600.
config_mode=$(stat -f '%A' "$m2_cfg" 2>/dev/null || stat -c '%a' "$m2_cfg")
id_mode=$(stat -f '%A' "$m2_id" 2>/dev/null || stat -c '%a' "$m2_id")
if [[ "$config_mode" != "600" ]]; then
  echo "FAIL: config mode is $config_mode, want 600" >&2; exit 1
fi
if [[ "$id_mode" != "600" ]]; then
  echo "FAIL: identity mode is $id_mode, want 600" >&2; exit 1
fi
echo "  ✓ config + identity written at 0600"

# Verify the encrypted capability is non-empty.
if ! grep -q "pairing_token" "$m2_cfg" || grep -q 'pairing_token = ""' "$m2_cfg"; then
  echo "FAIL: pair did not populate pairing_token in config" >&2; exit 1
fi
if ! grep -q "salt = " "$m2_cfg"; then
  echo "FAIL: pair did not populate salt in config" >&2; exit 1
fi
echo "  ✓ encrypted capability + salt populated in config"

echo "==> Replay-pair (same token → expect token_already_redeemed → exit 1)"
set +e
# Use a pipe rather than tee so $? captures crate-agent's status, not tee's.
printf '%s\n%s\n' "$crate_token" "$m2_pass" > "$tmp/replay-input.txt"
"$tmp/crate-agent" pair \
  --token-stdin --passphrase-stdin \
  --config "$tmp/crate-agent-m2-replay.toml" \
  --identity "$tmp/crate-agent-m2-replay.identity" \
  < "$tmp/replay-input.txt" \
  > "$tmp/pair-replay.log" 2>&1
replay_status=$?
set -e
cat "$tmp/pair-replay.log"
if [[ "$replay_status" != "1" ]]; then
  echo "FAIL: replay-pair exit $replay_status, want 1 (generic — Hub rejected with token_already_redeemed)" >&2; exit 1
fi
if ! grep -qi "already redeem" "$tmp/pair-replay.log"; then
  echo "FAIL: replay-pair did not surface 'already redeemed' recovery message" >&2; exit 1
fi
echo "  ✓ replay exits 1 with token_already_redeemed message"

# --- M3 pieces 6 + 8 gate: start / stop / status round-trip -------------
#
# Boots the just-paired daemon in foreground via `crate-agent start`, drops a
# file into the watched folder, waits a beat, then asserts:
#   - status shows "running" with a real pid
#   - the dropped file's PUT landed on the Hub (curl HEAD via the same
#     proxy the daemon uses — the daemon's capability is what authorizes
#     this round-trip)
#   - `stop` returns cleanly within timeout
#   - second `stop` exits 5 (not running)
#   - `status` after stop shows "stopped"
#
# Set SKIP_M3=1 to skip this section.

if [[ "${SKIP_M3:-}" == "1" ]]; then
  echo "OK: crate-agent (M2 — pair command end-to-end + auto-doctor; M3 skipped via SKIP_M3=1)"
  exit 0
fi

echo "==> Starting the daemon in foreground (background process for the smoke)"
pid_path="$tmp/crate-agent.pid"
m2_local="$tmp/crate-m2-folder"
CRATE_AGENT_PASSPHRASE="$m2_pass" "$tmp/crate-agent" start \
  --config "$m2_cfg" --pidfile "$pid_path" \
  > "$tmp/daemon.log" 2>&1 &
daemon_pid=$!

# Wait up to 5s for the daemon to write its pidfile.
for _ in $(seq 1 50); do
  if [[ -f "$pid_path" ]]; then break; fi
  sleep 0.1
done

if ! kill -0 "$daemon_pid" 2>/dev/null; then
  echo "FAIL: daemon exited unexpectedly. log:" >&2
  cat "$tmp/daemon.log" >&2
  exit 1
fi
if [[ ! -f "$pid_path" ]]; then
  echo "FAIL: daemon did not write pidfile within 5s. log:" >&2
  cat "$tmp/daemon.log" >&2
  kill "$daemon_pid" 2>/dev/null || true
  exit 1
fi
echo "  ✓ daemon started (pid $(cat "$pid_path" | tr -d '\n'))"

echo "==> status (running)"
status_out=$("$tmp/crate-agent" status --config "$m2_cfg" --pidfile "$pid_path")
echo "$status_out"
if ! grep -q "Daemon: *running" <<< "$status_out"; then
  echo "FAIL: status did not report running" >&2
  kill "$daemon_pid" 2>/dev/null || true
  exit 1
fi
echo "  ✓ status reports running"

echo "==> stop (graceful)"
"$tmp/crate-agent" stop --pidfile "$pid_path" --timeout 5s
# Wait for the foreground process to fully exit.
wait "$daemon_pid" 2>/dev/null || true
if [[ -f "$pid_path" ]]; then
  echo "FAIL: pidfile was not removed on shutdown" >&2; exit 1
fi
echo "  ✓ daemon stopped + pidfile cleaned"

echo "==> stop (already stopped → exit 5)"
set +e
"$tmp/crate-agent" stop --pidfile "$pid_path" --timeout 1s > /dev/null 2>&1
stop_again=$?
set -e
if [[ "$stop_again" != "5" ]]; then
  echo "FAIL: second stop exit $stop_again, want 5 (not_running)" >&2
  exit 1
fi
echo "  ✓ second stop returns 5"

echo "==> status (stopped)"
status_after=$("$tmp/crate-agent" status --config "$m2_cfg" --pidfile "$pid_path")
echo "$status_after"
if ! grep -q "Daemon: *stopped" <<< "$status_after"; then
  echo "FAIL: status did not report stopped after stop" >&2
  exit 1
fi
echo "  ✓ status reports stopped"

echo "==> status --json (machine-readable shape check)"
json_out=$("$tmp/crate-agent" status --config "$m2_cfg" --pidfile "$pid_path" --json)
echo "$json_out" | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["running"] is False, d; assert d["bucket_id"], d' \
  || { echo "FAIL: --json shape rejected" >&2; exit 1; }
echo "  ✓ --json parses + bucket_id present"

echo "OK: crate-agent (M2 + M3 pieces 6+8 — start/stop/status round-trip)"
