#!/usr/bin/env bash
# Runs the built wasm on local sandbox nodes pinned to each protocol version. Sandbox only, with
# the mock signer: no network, no live signer.
#
#   protocol-check.sh [VERSION...]            default: 86 88
#   protocol-check.sh --measure [VERSION...]  the gas and storage run, to <target>/measure-<v>.txt
#   protocol-check.sh --test NAME [VERSION...]  one test file, for working on it
#
# UNDO_TEST_FILTER, if set, narrows the run to test names containing it.
#
# Needs NEAR_SANDBOX_BIN_PATH. A sandbox binary that links an outside liblzma also needs
# UNDO_LIBLZMA_DIR: macOS drops DYLD_LIBRARY_PATH when a shell script starts, so it is set here.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$REPO"
TARGET="${CARGO_TARGET_DIR:-$REPO/target}"
export CARGO_TARGET_DIR="$TARGET" CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}"
# Host test code needs none of the wasm flags.
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS

tests=(protocol shell review_script review_contract review_relay review_fckey review1 review1_growth review2)
measure=0
case "${1:-}" in
  --measure) measure=1; tests=(measure); shift ;;
  --test) tests=("$2"); shift 2 ;;
esac
test_args=()
for t in "${tests[@]}"; do test_args+=(--test "$t"); done

versions=("$@")
[ "${#versions[@]}" -gt 0 ] || versions=(86 88)

: "${NEAR_SANDBOX_BIN_PATH:?set NEAR_SANDBOX_BIN_PATH}"
[ -z "${UNDO_LIBLZMA_DIR:-}" ] || export DYLD_LIBRARY_PATH="$UNDO_LIBLZMA_DIR"
for f in undo_vault mock_signer; do
  [ -s "$TARGET/near/$f.wasm" ] || { echo "PROTOCOL ERROR: run scripts/build.sh first" >&2; exit 2; }
done

work="$TARGET/protocol-check"
rm -rf "$work"
mkdir -p "$work"
wasm-opt --enable-bulk-memory "$REPO/tests/fixtures/link_control.wat" -o "$work/link_control.wasm" \
  || { echo "PROTOCOL ERROR: could not build the control" >&2; exit 2; }

export UNDO_WASM_DIR="$TARGET/near" UNDO_CONTROL_DIR="$work"
cargo test -q --locked -p sandbox-tests "${test_args[@]}" --no-run || { echo "PROTOCOL ERROR: tests do not compile" >&2; exit 2; }

node_pid=""
stop_node() {
  if [ -n "$node_pid" ]; then
    kill "$node_pid" 2>/dev/null
    wait "$node_pid" 2>/dev/null
    node_pid=""
  fi
}
trap stop_node EXIT

free_port() { python3 -I -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1])'; }

rpc_status() {
  curl -s -m 5 "http://127.0.0.1:$1/status" | python3 -I -c 'import sys,json; d=json.load(sys.stdin); print(d["protocol_version"], d["latest_protocol_version"], d["version"]["version"])'
}

failed=0
for version in "${versions[@]}"; do
  home="$work/home-$version"
  "$NEAR_SANDBOX_BIN_PATH" --home "$home" init --fast > "$work/init-$version.log" 2>&1 \
    || { echo "PROTOCOL ERROR: sandbox init failed, see $work/init-$version.log" >&2; exit 2; }
  # A long epoch stops the node from voting itself up to its latest version during the run. Tests that
  # jump the clock pass hundreds of thousands of blocks, and the check below fails if one ever crosses.
  python3 -I - "$home/genesis.json" "$version" <<'EOF'
import json, sys
path, version = sys.argv[1], int(sys.argv[2])
genesis = json.load(open(path))
genesis["protocol_version"] = version
genesis["epoch_length"] = 100000000
json.dump(genesis, open(path, "w"))
EOF
  rpc="$(free_port)"
  net="$(free_port)"
  "$NEAR_SANDBOX_BIN_PATH" --home "$home" run --rpc-addr "127.0.0.1:$rpc" --network-addr "127.0.0.1:$net" > "$work/node-$version.log" 2>&1 &
  node_pid=$!

  reported=""
  for _ in $(seq 1 60); do
    reported="$(rpc_status "$rpc" 2>/dev/null)" && [ -n "$reported" ] && break
    sleep 1
  done
  actual="${reported%% *}"
  if [ "$actual" != "$version" ]; then
    echo "PROTOCOL FAIL: asked for $version, node reports '${reported:-nothing}'"
    failed=1
    stop_node
    continue
  fi
  echo "node up: protocol_version latest_protocol_version build = $reported"

  log="$work/test-$version.log"
  UNDO_PROTOCOL="$version" UNDO_EXTERNAL_RPC="http://127.0.0.1:$rpc" UNDO_EXTERNAL_HOME="$home" \
    cargo test -q --locked -p sandbox-tests --no-fail-fast "${test_args[@]}" -- --test-threads=1 --nocapture ${UNDO_TEST_FILTER:-} > "$log" 2>&1
  code=$?
  [ "$measure" -eq 0 ] || grep -o 'MEASURE.*' "$log" > "$TARGET/measure-$version.txt"
  after="$(rpc_status "$rpc" 2>/dev/null)"
  stop_node
  grep -E '^test result:' "$log" | awk -v v="$version" '{ p += $4; f += $6 } END { printf "protocol %s: %d passed, %d failed\n", v, p, f }'
  if [ "$code" -ne 0 ] || [ "${after%% *}" != "$version" ]; then
    echo "PROTOCOL FAIL: $version, exit $code, node after the run: '${after:-nothing}', see $log"
    failed=1
  else
    echo "PROTOCOL OK: $version, node still on ${after%% *} after the run"
  fi
done

[ "$failed" -eq 0 ] || exit 1
echo "PROTOCOL OK: ${versions[*]}"
