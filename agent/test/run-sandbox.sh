#!/usr/bin/env bash
# The agent CLI end to end on the built wasm, one local node per protocol version, one at a time.
# Mock signer, made-up coins, no network. Results are labelled mock-signer and are not a gate.
#
#   agent/test/run-sandbox.sh [VERSION...]     default: 86 88
#
# Needs NEAR_SANDBOX_BIN_PATH and, for a sandbox binary that links an outside liblzma,
# UNDO_LIBLZMA_DIR. UNDO_WASM_DIR defaults to <target>/near. UNDO_SANDBOX_WORK moves the work
# folder, which keeps each run's transcript as transcript-<version>.txt.
set -uo pipefail
AGENT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
REPO="$(cd "$AGENT/.." && pwd -P)"
WASM_DIR="${UNDO_WASM_DIR:-${CARGO_TARGET_DIR:-$REPO/target}/near}"
WORK="${UNDO_SANDBOX_WORK:-$REPO/target/agent-sandbox}"
: "${NEAR_SANDBOX_BIN_PATH:?set NEAR_SANDBOX_BIN_PATH}"
[ -z "${UNDO_LIBLZMA_DIR:-}" ] || export DYLD_LIBRARY_PATH="$UNDO_LIBLZMA_DIR"
# Everything here is plain http on this machine. With the system CA store on, Node on macOS can hang at
# exit joining the thread that reads the keychain, after the last line is printed.
unset NODE_USE_SYSTEM_CA
for f in undo_vault mock_signer; do
  [ -s "$WASM_DIR/$f.wasm" ] || { echo "SANDBOX ERROR: no $f.wasm, run scripts/build.sh" >&2; exit 2; }
done

mkdir -p "$WORK"
node_pid=""
stop_node() { [ -z "$node_pid" ] || { kill "$node_pid" 2>/dev/null; wait "$node_pid" 2>/dev/null; node_pid=""; }; }
trap stop_node EXIT
free_port() { python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }

versions=("$@")
[ "${#versions[@]}" -gt 0 ] || versions=(86 88)
failed=0
for version in "${versions[@]}"; do
  home="$WORK/home-$version"
  rm -rf "$home"
  "$NEAR_SANDBOX_BIN_PATH" --home "$home" init --fast > "$WORK/init-$version.log" 2>&1 || { echo "SANDBOX ERROR: init failed"; exit 2; }
  python3 -I - "$home/genesis.json" "$version" <<'PY'
import json, sys
path, version = sys.argv[1], int(sys.argv[2])
genesis = json.load(open(path))
genesis["protocol_version"] = version
genesis["epoch_length"] = 100000
json.dump(genesis, open(path, "w"))
PY
  rpc="$(free_port)"; net="$(free_port)"
  "$NEAR_SANDBOX_BIN_PATH" --home "$home" run --rpc-addr "127.0.0.1:$rpc" --network-addr "127.0.0.1:$net" > "$WORK/node-$version.log" 2>&1 &
  node_pid=$!
  for _ in $(seq 1 60); do
    curl -s -m 2 "http://127.0.0.1:$rpc/status" | grep -q '"protocol_version":'"$version" && break
    sleep 1
  done
  curl -s -m 2 "http://127.0.0.1:$rpc/status" | grep -q '"protocol_version":'"$version" || { echo "SANDBOX FAIL: node not on protocol $version"; failed=1; stop_node; continue; }

  echo "== protocol $version: agent CLI against the real wasm, mock signer"
  UNDO_AGENT_WORK="$WORK" node "$AGENT/test/sandbox-e2e.mjs" --rpc "http://127.0.0.1:$rpc" --root-key "$home/validator_key.json" \
    --mock-wasm "$WASM_DIR/mock_signer.wasm" --wasm "$WASM_DIR/undo_vault.wasm" --out "$WORK/transcript-$version.txt" \
    || { echo "SANDBOX FAIL: agent CLI on $version"; failed=1; }
  stop_node
  rm -rf "$home"
done
[ "$failed" -eq 0 ] || exit 1
echo "AGENT SANDBOX OK: ${versions[*]} [mock-signer]"
