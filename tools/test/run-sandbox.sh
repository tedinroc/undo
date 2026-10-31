#!/usr/bin/env bash
# Runs the G1 driver and the intent checks against the built wasm on a local node pinned to each
# protocol version. Mock signer, no network. Results are labelled mock-signer and are not a gate.
#
#   tools/test/run-sandbox.sh [VERSION...]     default: 86 88
#
# Needs NEAR_SANDBOX_BIN_PATH and, for a sandbox binary that links an outside liblzma,
# UNDO_LIBLZMA_DIR. UNDO_WASM_DIR defaults to <target>/near. UNDO_TOOLS_CHECK_BIN enables the
# consensus check of every final transaction.
set -uo pipefail
TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
REPO="$(cd "$TOOLS/.." && pwd -P)"
WASM_DIR="${UNDO_WASM_DIR:-${CARGO_TARGET_DIR:-$REPO/target}/near}"
WORK="${UNDO_SANDBOX_WORK:-$REPO/target/tools-sandbox}"
: "${NEAR_SANDBOX_BIN_PATH:?set NEAR_SANDBOX_BIN_PATH}"
[ -z "${UNDO_LIBLZMA_DIR:-}" ] || export DYLD_LIBRARY_PATH="$UNDO_LIBLZMA_DIR"
for f in undo_vault mock_signer; do
  [ -s "$WASM_DIR/$f.wasm" ] || { echo "SANDBOX ERROR: no $f.wasm, run scripts/build.sh" >&2; exit 2; }
done

rm -rf "$WORK"
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
  url="http://127.0.0.1:$rpc"
  common=(--rpc "$url" --root-key "$home/validator_key.json" --mock-wasm "$WASM_DIR/mock_signer.wasm" --wasm "$WASM_DIR/undo_vault.wasm")

  echo "== protocol $version: G1 driver, mock signer"
  node "$TOOLS/g1.mjs" --network sandbox "${common[@]}" --out "$WORK/g1-$version.json"
  code=$?
  [ "$code" -eq 0 ] || { echo "SANDBOX FAIL: g1 exit $code on $version"; failed=1; }
  if [ -n "${UNDO_TOOLS_CHECK_BIN:-}" ]; then
    node "$TOOLS/test/check-g1-proof.mjs" "$WORK/g1-$version.json" || { echo "SANDBOX FAIL: proof check on $version"; failed=1; }
  fi

  echo "== protocol $version: negative control, signer returns garbage after activation"
  node "$TOOLS/g1.mjs" --network sandbox "${common[@]}" --stage ladder --test-garble --out "$WORK/g1-garble-$version.json"
  code=$?
  if [ "$code" -ne 1 ] || ! grep -q '"kill": true' "$WORK/g1-garble-$version.json"; then
    echo "SANDBOX FAIL: the driver did not report the garbage signer as a failure, exit $code"
    failed=1
  else
    echo "PASS the driver reports a dead signer as a kill line, exit 1"
  fi

  echo "== protocol $version: deploy on the payer's own account"
  node "$TOOLS/g1.mjs" --network sandbox "${common[@]}" --contract self --stage activation --out "$WORK/g1-self-$version.json"
  code=$?
  [ "$code" -eq 0 ] || { echo "SANDBOX FAIL: --contract self, exit $code"; failed=1; }

  echo "== protocol $version: intents against the real wasm"
  node "$TOOLS/test/sandbox-intents.mjs" "${common[@]}" || { echo "SANDBOX FAIL: intents on $version"; failed=1; }
  stop_node
done
[ "$failed" -eq 0 ] || exit 1
echo "SANDBOX OK: ${versions[*]} [mock-signer]"
