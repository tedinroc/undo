#!/usr/bin/env bash
# Every check of the tools, in order. Offline except for the plan-only G1 run, which reads testnet.
#
#   tools/test/run-all.sh [--no-sandbox] [--no-mutants]
#
# Needs NEAR_SANDBOX_BIN_PATH, UNDO_NEAR_BIN and bitcoind (UNDO_BITCOIN_BIN). A sandbox binary that
# links an outside liblzma also needs UNDO_LIBLZMA_DIR. Keeps cargo at 3 jobs.
set -uo pipefail
TOOLS="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
REPO="$(cd "$TOOLS/.." && pwd -P)"
sandbox=1; mutants=1
for a in "$@"; do
  case "$a" in
    --no-sandbox) sandbox=0 ;;
    --no-mutants) mutants=0 ;;
    *) echo "unknown option" >&2; exit 2 ;;
  esac
done
export CARGO_BUILD_JOBS=3
status=0
step() { echo; echo "== $1"; shift; "$@" || { echo "STEP FAILED, exit $?"; status=1; }; }

( cd "$TOOLS/rust-check" && unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS && cargo build -q --locked ) || { echo "rust-check does not build"; exit 2; }
export UNDO_TOOLS_CHECK_BIN="${CARGO_TARGET_DIR:-$TOOLS/rust-check/target}/debug/undo-tools-check"

record="$(mktemp)"
trap 'rm -f "$record"' EXIT
step "vendored noble matches its manifest" node "$TOOLS/vendor/noble/vendor.mjs" --check
step "offline tests" node --test "$TOOLS/test/offline.test.mjs"
step "G2 checks, offline" node --test "$TOOLS/test/g2-units.test.mjs"
step "agent CLI, offline" node --test "$REPO/agent/test/offline.test.mjs"
step "watcher, offline" env -u NODE_USE_SYSTEM_CA node --test "$TOOLS/test/watch.test.mjs"
step "judge floor: verify lines, referee, README and CLAIMS, offline" env -u NODE_USE_SYSTEM_CA node --test "$TOOLS/test/judge-floor.test.mjs"
step "human scripts, under shims" env UNDO_NEAR_RECORD="$record" node --test "$TOOLS/test/human-scripts.test.mjs"
step "near-cli commands against --help, network denied" node "$TOOLS/test/near-cli-check.mjs" "$record"
step "escape.mjs on a regtest node" node "$TOOLS/test/regtest-escape.mjs"
step "mutation harnesses read a run correctly" sh -c "node '$TOOLS/test/mutants.mjs' --self-test && python3 -I '$REPO/scripts/shell-mutants.py' --self-test"
[ "$mutants" -eq 0 ] || step "mutants" node "$TOOLS/test/mutants.mjs"
[ "$sandbox" -eq 0 ] || step "G1 driver and intents on sandbox, protocols 86 and 88" "$TOOLS/test/run-sandbox.sh" 86 88
[ "$sandbox" -eq 0 ] || step "G2 driver rehearsal: regtest, local NEAR node, mock signer" node "$TOOLS/test/g2-rehearsal.mjs"
[ "$sandbox" -eq 0 ] || step "watcher on a local NEAR node: near-cli, relay and direct proposals" env -u NODE_USE_SYSTEM_CA UNDO_NEAR_BIN="${UNDO_NEAR_BIN:-}" node "$TOOLS/test/watch-sandbox.mjs"
step "identity and secrets in the tree" "$REPO/scripts/check-identity.sh" --tree
step "secret scan" "$REPO/scripts/secret-scan.sh"
step "secret scan knows this project's key formats" "$REPO/scripts/test-secret-scan.sh"

echo
[ "$status" -eq 0 ] && echo "TOOLS OK" || echo "TOOLS FAILED"
exit "$status"
