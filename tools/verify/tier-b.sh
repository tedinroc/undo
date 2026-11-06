#!/usr/bin/env bash
# verify.sh tier B: pure Rust, offline. Needs no key, no network once crates are fetched, no NEAR
# tooling and no Bitcoin node. Runs crates/undo-core/props (the state machine, with proptest) and
# crates/undo-btc (the script, the sighash and the recovery file, judged by libbitcoinconsensus).
#
# Each line names a claim in CLAIMS.md and the tests behind it, and passes only if every named test
# ran and passed. A name that matched no test is a FAIL, never a quiet pass.
#
# Labels: [unit] is pure Rust with no chain at all. [consensus-lib] is libbitcoinconsensus, through
# the rust-bitcoin crate, judging real signatures over real BIP-143 digests. Neither says anything
# about a live network, mempool policy or coin age on a chain.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
cd "$REPO"
# Host code needs none of the wasm flags, and scripts/build.sh's RUSTFLAGS would drop nothing here
# but would rebuild everything.
unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}" CARGO_TERM_COLOR=never

if ! command -v cargo >/dev/null 2>&1; then
  echo "SKIP tier-B [unit] cargo is not installed: install Rust (rustup.rs) to run tier B"
  exit 3
fi

logs="$(mktemp -d "${TMPDIR:-/tmp}/undo-tier-b.XXXXXX")"
trap 'rm -rf "$logs"' EXIT
fails=0

pass() { echo "PASS $*"; }
fail() { echo "FAIL $*"; fails=$((fails + 1)); }

run_suite() { # name, then the cargo arguments
  local name="$1"; shift
  local started=$SECONDS
  cargo test --locked "$@" >"$logs/$name.log" 2>&1
  echo $? >"$logs/$name.status"
  echo "$((SECONDS - started))" >"$logs/$name.secs"
}

# True if TEST ran and passed inside the section cargo printed for BINARY (tests/BINARY.rs, or
# "unittests" for a crate's own tests).
ran_ok() { # suite, binary, test
  awk -v bin="$2" -v want="test $3 ... ok" '
    /^ *Running / { insec = (bin == "unittests") ? (index($0, "unittests") > 0) : (index($0, "tests/" bin ".rs") > 0) }
    insec && $0 == want { found = 1 }
    END { exit found ? 0 : 1 }' "$logs/$1.log"
}

counts() { # suite: passed and failed totals over every binary cargo ran
  awk '/^test result:/ { for (i = 1; i <= NF; i++) { if ($(i) ~ /^passed;?$/) p += $(i-1); if ($(i) ~ /^failed;?$/) f += $(i-1); if ($(i) ~ /^ignored;?$/) g += $(i-1) } }
       END { printf "%d passed, %d failed, %d ignored", p, f, g }' "$logs/$1.log"
}

claim() { # suite, claim, label, text, then binary:test pairs
  local suite="$1" id="$2" label="$3" text="$4"; shift 4
  local missing=()
  for pair in "$@"; do
    ran_ok "$suite" "${pair%%:*}" "${pair#*:}" || missing+=("$pair")
  done
  if [ "${#missing[@]}" -eq 0 ]; then
    pass "$id $label $text ($# named tests: $(printf '%s ' "$@" | sed 's/ $//'))"
  else
    fail "$id $label $text: did not run and pass: ${missing[*]}"
  fi
}

suite_line() { # suite, label, what
  local s; s="$(cat "$logs/$1.status")"
  if [ "$s" = "0" ]; then
    pass "tier-B $2 $3: $(counts "$1") in $(cat "$logs/$1.secs") s"
  else
    fail "tier-B $2 $3: cargo test exit $s, $(counts "$1"). Last lines:"
    tail -25 "$logs/$1.log" | sed 's/^/    /'
  fi
}

echo "== tier B: undo-core state machine (crates/undo-core/props), offline"
run_suite core --manifest-path crates/undo-core/props/Cargo.toml
suite_line core "[unit]" "crates/undo-core/props, every test"
claim core C01 "[unit]" "no request gets a signature before its base unlock, property-tested over generated role and method sequences, not exhaustive" \
  no_unlock_before_base:no_unlock_before_base scenarios:clearing_a_hold_before_the_base_never_unlocks_early scenarios:execute_goes_through_the_moment_the_unlock_arrives
claim core C06 "[unit]" "a dead guard doubles the new-destination delay and blocks nothing" \
  scenarios:guard_death_delays_and_blocks_nothing
claim core C07 "[unit]" "a guard hold is bounded, once per request, and clearing it never goes below the base unlock" \
  scenarios:hold_is_bounded_once_and_clearing_returns_to_base_only scenarios:a_hold_cannot_be_added_at_or_after_unlock scenarios:an_assessment_is_recorded_both_ways_and_holds_at_most_once
claim core C09 "[unit]" "no pair of signing sessions over the same coins pays more real fee than the cap, model half, property-tested" \
  no_fee_combination:no_fee_combination no_fee_combination:the_model_detects_the_attack_when_given_both_sessions scenarios:reclaim_frees_a_griefed_coin_and_supersedes_the_old_request
claim core C09 "[consensus-lib]" "the same fee rule, consensus half: every pair of sessions judged by libbitcoinconsensus" \
  consensus:no_fee_combination_all_pairs_under_consensus consensus:fee_swap_through_undo_core_never_yields_a_valid_overpayment consensus:fee_swap_control_is_valid_when_a_signer_produces_both_sessions
claim core C10 "[unit]" "fee cap, fee budget charged at execute, input limits" \
  scenarios:fee_budget_is_charged_at_execute_not_at_propose scenarios:fee_rules_at_the_input_limits scenarios:fee_budget_refuses_when_exhausted_and_recovers_after_24_h
claim core C11 "[unit]" "upgrades wait longer than any withdrawal plus the reaction window, and an approved upgrade runs out" \
  scenarios:upgrade_rules_leave_the_stated_reaction_window_on_each_preset scenarios:an_upgrade_waits_and_then_runs_out
claim core C15 "[unit]" "a vault with a wrong K_m never activates" \
  scenarios:a_wrong_k_m_never_activates_and_inactive_vaults_refuse_propose
claim core C17 "[unit]" "one passkey rotation kills every pending request at once; a request already signing keeps signing" \
  scenarios:rotation_kills_every_pending_request_at_once scenarios:a_signing_request_survives_rotation_because_a_signature_may_be_public

echo
echo "== tier B: Bitcoin script and recovery file (crates/undo-btc), libbitcoinconsensus, offline"
run_suite btc -p undo-btc
suite_line btc "[consensus-lib]" "crates/undo-btc, every test; the ignored ones are the regtest tests, which need bitcoind (CLAIMS.md C04)"
claim btc C02 "[consensus-lib]" "the MPC key alone cannot spend" \
  consensus:mpc_alone_cannot_spend
claim btc C03 "[consensus-lib]" "the spend key alone cannot spend, before or after the timelock, and has no escape leaf" \
  consensus:k_u_alone_cannot_spend consensus:k_u_after_csv_cannot_escape
claim btc C04 "[consensus-lib]" "the cold key escapes at the CSV age and not one block before. This is the sequence rule only: coin age on a chain is a regtest and Mutinynet question" \
  consensus:escape_passes_at_csv_and_above consensus:k_e_before_csv_cannot_escape consensus:k_e_has_no_path_through_the_cosign_branch
claim btc C18 "[consensus-lib]" "the recovery file alone builds an escape the library accepts, and its controls fail" \
  recovery:built_escape_passes_the_library_from_the_file_alone recovery:dry_run_controls_fire_on_a_broken_judge recovery:checksum_catches_damage_to_any_field

echo
if [ "$fails" -eq 0 ]; then
  echo "TIER B PASS"
  exit 0
fi
echo "TIER B FAIL: $fails line(s)"
exit 1
