#!/usr/bin/env bash
# Smoke test for crate-agent (Go daemon), M0:
# - Assert LICENSE present and is AGPL-3.0
# - go build for current host succeeds
# - binary --help exits cleanly
# - every .go file under cmd/ + internal/ carries an SPDX header
set -euo pipefail
cd "$(dirname "$0")"

if [[ ! -f LICENSE ]]; then
  echo "FAIL: LICENSE missing"; exit 1
fi
if ! grep -q "AFFERO GENERAL PUBLIC LICENSE" LICENSE; then
  echo "FAIL: LICENSE is not AGPL-3.0"; exit 1
fi

tmp=$(mktemp -d -t crate-agent-smoke.XXXXXX)
trap 'rm -rf "$tmp"' EXIT

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

echo "OK: crate-agent (M0 skeleton — LICENSE AGPL-3.0, host build green, SPDX headers everywhere)"
