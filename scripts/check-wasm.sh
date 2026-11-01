#!/usr/bin/env bash
# Checks what the contract wasm exports and imports, and that its source stays on low-level promises.
#
#   check-wasm.sh              <target>/near/undo_vault.wasm
#   check-wasm.sh --file FILE  that file
#
# Exit 0 clean, 1 failed a rule, 2 could not run.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
TARGET="${CARGO_TARGET_DIR:-$REPO/target}"
file="$TARGET/near/undo_vault.wasm"
[ "${1:-}" = "--file" ] && file="${2:-}"

[ -s "$file" ] || { echo "WASM ERROR: no wasm at $(basename "$file")" >&2; exit 2; }
symbols="$(node "$REPO/scripts/wasm-symbols.mjs" "$file")" || { echo "WASM ERROR: could not parse $(basename "$file")" >&2; exit 2; }

bad=0
fail() { echo "WASM FAIL: $1"; bad=$((bad + 1)); }

# Base is out of scope: no EVM entry point in a default build.
printf '%s\n' "$symbols" | grep -q '^export function propose_evm$' && fail "exports propose_evm"

# A contract with this import fails to link on protocol 86.
printf '%s\n' "$symbols" | grep -q '^import env\.promise_batch_action_universal_state_init$' \
  && fail "imports promise_batch_action_universal_state_init"

# Cut by decision: `reclaim` after `T_stuck` covers a stuck coin.
printf '%s\n' "$symbols" | grep -q '^export function bump$' && fail "exports bump"

# The checks above pass on an empty file, so require the methods that must be there.
for method in new migrate create_vault deposit_storage propose_btc check_propose cancel cancel_all_and_rotate execute on_signed prune_signed reclaim \
  assess heartbeat clear_hold add_destination remove_destination set_policy set_guard apply_grant raise_fee_cap \
  freeze unfreeze veto_grant recover_begin recover_cancel recover_finish upgrade_propose upgrade_cancel upgrade_apply \
  status vault request delay_now final_tx script guard_prompt stats; do
  printf '%s\n' "$symbols" | grep -q "^export function $method\$" || fail "does not export $method"
done

# Low-level promises only: these forms pull in the import above.
if grep -rnE 'near_sdk::[{a-zA-Z_, ]*\bPromise\b|Promise::new|Self::ext|ext_contract' "$REPO/contracts/undo/src" "$REPO/contracts/mock-signer/src" >/dev/null; then
  fail "source uses the high-level Promise API"
fi

# No Bitcoin read through MPC, in source or in the wasm.
if grep -rnE 'verify_foreign' "$REPO/contracts/undo/src" "$REPO/crates/undo-core/src" "$REPO/crates/undo-btc/src" >/dev/null \
   || strings -a "$file" | grep -q 'verify_foreign'; then
  fail "reaches verify_foreign_transaction"
fi

if [ "$bad" -gt 0 ]; then
  echo "WASM FAIL: $bad rules"
  exit 1
fi
echo "WASM OK: $(basename "$file"): $(printf '%s\n' "$symbols" | grep -c '^export function') functions exported, $(printf '%s\n' "$symbols" | grep -c '^import') imports, no propose_evm, no universal state init"
