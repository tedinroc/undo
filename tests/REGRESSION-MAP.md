# Attack review: regression map

An attack review ran before this contract existed, against an earlier prototype and against the
design text. It produced 24 findings, numbered here from 0. Its scratch tests were ported into this
repo. This file says where each one went.

Run everything on protocols 86 and 88:

```
scripts/build.sh
scripts/protocol-check.sh
```

Every test here uses the mock signer or libbitcoinconsensus. None of them has touched a live network.

## Ported tests

The review's four scratch files, test by test. "Control" means the test shows the attack really is
valid to Bitcoin, so the check that stops it has to live elsewhere. A control passing is the expected
result, and its partner is the test that shows the refusal.

| Review test | Finding | Ported as | Result expected now |
|---|---:|---|---|
| `script.rs: branches` | 4 | `review_script: f4_two_branches_behave_as_drawn` | The two branches behave as drawn. `K_e` has no co-sign slot. |
| `script.rs: fee_swap_two_sessions` | 0 | `review_script: f0_fee_swap_two_sessions_valid` | Control. 999,500 sats of real fee at a declared 1,000. |
| `script.rs: fee_swap_many_inputs` | 0 | `review_script: f0_fee_swap_many_inputs_valid` | Control. |
| `script.rs: fee_swap_big_coin_plus_dust_is_bounded` | 0 | `review_script: f0_fee_swap_big_coin_plus_dust_valid` | Control. |
| `script.rs: csv_operand_abuse` | 15 | `review_script: f15_csv_operand_abuse`, `review_contract: f15_create_vault_refuses_csv_abuse` | The library accepts the operands. The crate and the contract refuse them. |
| `script.rs: consensus_lib_blind_spots` | 15 | `review_script: f15_consensus_lib_blind_spots` | The library accepts all four. The crate's bytes are the minimal, low-S forms. Coin age is left to regtest in `crates/undo-btc`. |
| `script.rs: key_collisions` | 1 | `review_script: f1_key_collisions_valid_but_cannot_be_built` | Control, plus the crate refusing to build them. |
| `contract.rs: contract_digests_compose_into_uncapped_fee` | 0 | `review_contract: f0_contract_digests_do_not_compose` | A second multi-input session is refused while held and after, by the pin. A lone re-declared signature cannot join the first session. The same test carries a control with the signature the contract refused. |
| `contract.rs: false_amount_pins_outpoint_forever` | 0 | `review_contract: f0_false_amount_no_longer_freezes_a_coin` | `reclaim` gets the coin back after `T_stuck`, and its spend passes consensus. |
| `contract.rs: cancel_keeps_storage_and_free_for_all_on_outpoint` | 5 | `review_contract: f5_cancel_cycle_keeps_no_storage` | Five cycles leave storage and credit exactly where they were. |
| `contract.rs: create_vault_accepts_foreign_or_junk_keys` | 1 | `review_contract: f1_create_vault_refuses_foreign_or_junk` | An attacker's `K_m` never activates and leaves no row. Junk keys, missing proofs and out-of-range delays are refused. |
| `contract.rs: public_relay_key_allowance_is_burned_by_failing_calls` | 10 | `review_relay: f10_griefed_general_key_cannot_stop_a_cancel_on_the_owner_key` | The burn still happens, because that is NEAR's behaviour. A cancel on a separate key still lands. |
| `contract.rs: contract_at_storage_floor_loses_on_signed` | 11 | `review_contract: f11_on_signed_stores_with_zero_credit_at_the_floor`, `f11_control_without_the_reservation_fails_on_storage` | With zero credit and only the reservation in the account, the signature is stored. With nothing kept, the same steps fail with `LackBalanceForState`. |
| `relay.rs: relay_burn` | 10 | `review_relay: f10_griefed_general_key_...`, `f10_measure_failing_call_cost_by_prepaid_gas` | Prints what a failing call holds and what it finally spends. |
| `fckey.rs: fc_key_deposit_and_large_gas` | 19 | `review_fckey: f19_function_call_key_proposes_against_credit`, `f19_measure_allowance_needed_for_execute` | A deposit through the key is refused by the protocol. A proposal with none passes on credit. Execute runs through the key at 8 inputs, and the needed allowance is printed. |

## Added for findings the scratch files did not exercise

| Test | Finding |
|---|---:|
| `review_contract: f5_thief_requests_die_with_rotation_and_decoys_are_capped` | 5 |
| `review_contract: f8_callback_checks_attempt_and_digest` | 8 |
| `review_contract: f8_reclaim_needs_fresh_half_signature` | 8 |
| `review_contract: f13_execute_takes_caller_gas_and_survives_a_junk_signer` | 13 |
| `review_contract: f14_sixteen_input_exit_through_the_named_override` | 14 |
| `review_contract: f17_webauthn_fixtures` | 17 |
| `review_contract: f18_request_expires` | 18 |
| `review_contract: f22_vault_id_cannot_be_squatted` | 22 |

## Added by the third review

| Finding | Test |
|---|---|
| A pre-signed chain gave N CSV restarts | `review2: chain_on_*`, `a_chain_built_backwards_*`, `reclaim_of_a_young_coin_*`, `change_is_born_*`, and in `crates/undo-core/props`: `chain_bound`, `a_signed_chain_grows_*`, `a_chain_built_backwards_*` |
| `raise_fee_cap` leaned on the contract's balance at zero credit | `review2: raise_fee_cap_at_zero_credit_leaks_nothing` |
| Reservation rules untested | `review2: a_request_lives_on_its_reservation_*`, `panic_button_and_cold_key_*`, `reclaim_is_refused_when_*`, with a mutant for each constant both ways in `scripts/shell-mutants.py` |
| Mutants that survived the suite | `review2: creation_proofs_bind_*`, `a_refused_vault_*`, `an_inactive_vault_*`, `only_the_account_*`, `too_little_gas_*`, `the_sign_deposit_*`, `malformed_*`, `on_signed_drops_*`, `the_free_views_*`, and `scenarios: reclaim_is_refused_while_the_slot_is_held` |

## All findings

| # | Severity | Finding, short | Where it is covered | Not yet covered |
|---:|---|---|---|---|
| 0 | critical | Fee swap across signing sessions | `review_script`, `review_contract`, proptests in `crates/undo-core/props` | - |
| 1 | high | `K_m` never verified | `review_script`, `review_contract` | Real signer callback gas. |
| 2 | high | Passkey thief locks the owner out | `crates/undo-core/props`, `review1: recovery_cap_*`, `freeze_and_unfreeze_on_the_wasm`, `veto_grant_on_the_wasm` | - |
| 3 | high | Self-spends reset CSV | Slot rule and chain wait in `crates/undo-core/props`, `review1: slot_covers_spends_with_change_on_the_wasm`, `review2: chain_on_*` | A chain of restarts on regtest. |
| 4 | high | Young-coin claims | `review_script`, `crates/undo-btc/tests`, `review1: recovery_cap_*` | - |
| 5 | high | Pending requests survive rotation, unlimited decoys | `review_contract` | Phone-page sorting. |
| 6 | high | Passkey is blind signing | Grant delay in `crates/undo-core/props`, BE and BS flags in `f17`, `review1: veto_grant_on_the_wasm` | Page hash. |
| 7 | high | Printed mainnet plan | Plan change, no test | - |
| 8 | high | `bump` and `reclaim` could not complete | `review_contract`, `crates/undo-core/props` | `bump` was cut 11/1. `reclaim` covers a stuck coin. |
| 9 | high | Bare `K_e` cannot escape | `crates/undo-btc/tests/recovery.rs` | Browser and Node tools. |
| 10 | high | Public relay key griefable | `review_relay` | The relay itself. |
| 11 | high | Sponsored storage, callback lost at floor | `review_contract` | Live relay ceiling. |
| 12 | high | Upgrade window and expiry | `surface: an_upgrade_lands_*`, `upgrade_authority_*`, `code_without_a_migrate_*`, `crates/undo-core/props: upgrade_rules_*`, `an_upgrade_waits_*` | A real operator passkey. |
| 13 | medium | Signer outage while the owner is away | `review_contract`, `surface: status_is_plain_*` | Canary. |
| 14 | medium | Fee cap strands exits | `review_contract`, `crates/undo-core/props` | Mainnet cap sizing. |
| 15 | medium | Consensus-lib overclaim, CSV operand | `review_script`, `review_contract`, `crates/undo-btc/tests/regtest.rs` | - |
| 16 | medium | `K_e` intents undefined | Intent format in `contracts/undo/src/auth.rs`, tested through `cold_key_cancel`, `review1`, and `tools/freeze.mjs` in `tools/test/sandbox-intents.mjs` | - |
| 17 | medium | WebAuthn checks incomplete | `review_contract` | A real phone assertion. Software authenticator only here. |
| 18 | medium | Request expiry undefined | `review_contract`, `crates/undo-core/props` | - |
| 19 | medium | Agent mode against protocol limits | `review_fckey` | Live allowance. |
| 20 | medium | Committed sentence as key material | No such key exists. Secret scan in `scripts/secret-scan.sh`. | - |
| 21 | medium | Guard claims overstate | Hold rule in `crates/undo-core/props`, `surface: assess_*`, `guard_prompt_*`, `memo_*` | A recorded `provider_tee` signature, gate G4. |
| 22 | medium | Vault id squat | `review_contract` | - |
| 23 | low | EVM path compiled by default | No EVM code in the contract, `scripts/check-wasm.sh` | - |

## Second review

A second review ran these as working attacks against the earlier shell, on the real wasm. Each is now
covered here, on protocols 86 and 88.

| Finding | Test | Result expected now |
|---|---|---|
| `on_signed` lost at spend 141, row grew 432 bytes a spend | `review1_growth: history_does_not_weigh_on_the_callback` | 150 completed spends, every signature kept, callback flat. Requests and ledger entries have their own storage keys. |
| Signed requests never left | `review1: prune_returns_the_bytes_and_keeps_the_transaction`, `pins_survive_in_their_own_storage_entries`, `crates/undo-core/props: signed_requests_prune_after_the_window_and_pins_stay` | The bytes come back, the log carries the transaction, the pin and `reclaim` still work. |
| A dead request's coin needs its ledger entry loaded | `review1: dead_requests_free_coins_the_sweeping_call_does_not_name` | The coin is free again even when the call names another coin. |
| Foreign or off-curve escape key activated | `review1: escape_key_needs_proof_of_possession` | Refused for a foreign key, a key above the field prime, an x with no point, and an untagged proof. |
| Rotate, fee override and reclaim had no negative tests | `review1: rotate_needs_*`, `raise_fee_cap_needs_*`, `reclaim_needs_*` | Wrong key, wrong args, stale nonce and past expiry are each refused, and replay after success. |
| A second `on_derived` could delete a live vault | `review1: second_on_derived_leaves_an_active_vault_alone`, `racing_activate_delivers_two_callbacks_and_keeps_the_vault` | The second callback does nothing. |
| Slot bypassed by a dust spend with change | `crates/undo-core/props: a_spend_with_change_needs_the_slot_like_a_self_spend`, `a_day_of_change_spends_is_bounded_by_the_slot`, `review1: slot_covers_spends_with_change_on_the_wasm` | Refused while the slot is taken, and one per `T_new` over a day when the budget does not bind first. |
| `freeze`, `unfreeze`, `veto_grant`, `recover_*` not in the wasm | `review1: freeze_and_unfreeze_on_the_wasm`, `veto_grant_on_the_wasm`, `recovery_needs_*`, `recovery_cap_on_the_test_coin_constants`, `recovery_cap_on_the_mainnet_proof_constants`, `cold_methods_need_no_credit`, `tools/test/sandbox-intents.mjs` | Exported and tested. Third cancel refused, and the owner is back within 3 x `T_recover` at each instance's constants. |
| Secret scan missed this project's key formats | `scripts/test-secret-scan.sh` | `cold_key`, `secret` and a bare seed line are hits. `proofs/vault-recovery.json` is ignored by git. |

`scripts/shell-mutants.py` carries the four mutants that survived, plus one for each new rule.

## Fourth review (round 3)

No loss of funds and no way past the delay. Its scratch attacks are kept in `tests/tests/review3.rs`, and the survivors have tests and mutants.

| Finding | Test | Result expected now |
|---|---|---|
| Fee budget burnt on fake coins blocks the exit to a new vault | `review3: budget_burnt_*`, `crates/undo-core/props: a_rotation_landing_*`, `a_vetoed_rotation_*` | Refused while the window is full, and the override does not reach it. Goes out once the rotation lands. |
| The escape is a fee race nobody stated | `crates/undo-btc/tests/regtest.rs: the_escape_is_a_fee_race_*`, `tools/test/offline.test.mjs` | 1,200 replaces 1,000. 2,500 loses to three stacked links of 1,000, and 3,500 wins. The tool prints it. A small coin needs no flag. |
| Instance rules not enforced | `review3: instance_rules_*`, `crates/undo-core/props: csv_stays_*` | `new` and `create_vault` refuse them. |
| Survivors: reclaim's fee ceiling, pending cap, dust and value checks, cancel's expiry, `raise_fee_cap` during a freeze, `recover_begin` over a running recovery, a freeze ending now, the outflow trim, the retry window, `loosens` per field, fee cap above budget, max money | One named test each at the end of `crates/undo-core/props/tests/scenarios.rs` | Each is a mutant in `crates/undo-core/props/mutation-check.py`. |
| A signer's answer of any size | `review3: oversized_signer_*`, mock mode `Padded` | A good signature inside too many bytes is not read. |
| Harnesses had no control | Both mutation scripts | An unmutated run comes first, and a red one stops the run. |
| Secret scan too narrow | `scripts/test-secret-scan.sh` | Generic names, `hex!` and a NEAR secp256k1 secret hit. A txid, a digest and a public key do not. |

Two of that review's mutants have no test on purpose, because no input can tell them from the real code. `apply_grant` committing with `Short::Reserved` is the same as `Short::Refuse`, because a landing grant never grows the vault. Dropping `btc::encodable` changes nothing, because `ecrecover` refuses every r and s it would.

Kept as they were: `escape branch`, `stale epoch`, `spoofed callbacks`, `wrong K_m variants`, `outpoint reuse`, `partial execute`, `storage griefing`, `passkey thief after recovery`, `small rules`, all in `review3`.

## Fifth review (round 4)

No critical or high finding. An owner lens and a spec lens, on the real wasm. A third lens, theft, died before it reported and was not run again. Tests are in `tests/tests/review4.rs` and at the end of `crates/undo-core/props/tests/scenarios.rs`.

| Finding | Test | Result expected now |
|---|---|---|
| A dead domain cannot recover a passkey | `review4: a_second_origin_named_at_new_recovers_a_dead_domain`, `with_one_origin_a_dead_domain_leaves_the_cold_key` | A second origin named at `new` recovers, and its assertions cancel. An unnamed one is refused, and `status` names the list. |
| A larger upgrade spends the vaults' credit | `review4: an_upgrade_that_would_spend_what_vaults_paid_in_is_refused`, `migrate_refuses_when_what_vaults_paid_in_is_gone`, `vault_funds_follows_every_vault` | Refused with the approval standing, the panic button still works, and a plain transfer lets it land. `migrate` refuses on a short balance. The total matches every vault through each way money moves. |
| Griefed gas was not the worst case, `apply_grant` had no row | `measure: gas_of_owner_methods_on_the_worst_row_and_queue`, `gas_of_the_landing_and_the_cold_key_on_the_largest_dead_queue`, `gas_of_assess_on_a_dead_queue` | Each row under what a relay attaches, `on_signed` under its 10 Tgas. Run by `protocol-check.sh --measure`. |
| `status` promises a rotation that is not waiting | `review4: status_says_when_no_new_key_is_coming`, `scenarios: status_says_when_no_new_key_is_waiting`, `only_a_rotation_grant_reads_as_a_key_waiting` | Veto, freeze and recovery each read as no key waiting. |
| A budget that refuses reads calm | `review4: status_warns_before_the_budget_refuses_a_spend`, `scenarios: the_budget_line_comes_on_when_a_capped_fee_no_longer_fits` | The line comes on once a fee at the cap no longer fits. |
| Poisoned coins push the exit past the reaction window | `review4: poisoned_coins_leave_by_reclaim_then_cancel` | A limit stated in SPEC 5, with its short way, which passes consensus. |
| A passkey thief leaves the delays at their maxima | `review4: a_passkey_thief_leaves_the_mainnet_delays_at_their_maxima` | A limit stated in SPEC 1.3. |
| `freeze` refused on a little clock skew | `review4: a_late_or_long_freeze_lands_and_is_cut_to_the_csv_period`, `scenarios: a_freeze_past_the_csv_period_is_cut_to_it`, `tools/test/offline.test.mjs` | It lands and is cut, and the log says what landed. The tool asks for past its own expiry. |
| A stranger lands someone's `create_vault` first | `review4: a_stranger_can_land_someone_elses_create_vault_and_a_top_up_repairs_it` | A limit the page has to handle: a top-up and a beat give the film's 5:00. |
| A pinned child blocks one exact self-paying transaction | `review4: a_pinned_child_blocks_one_exact_reclaim_and_cancel_is_the_way_out` | A limit, with its way out, which passes consensus. |
| After a late cancel, `status` and the page's rule read dead while the spend signs | `review4: a_rotation_after_execute_does_not_read_as_cancelled`, `scenarios: status_says_an_executed_request_can_still_be_signed_after_a_rotation`, `a_spend_after_the_new_key_landed_reads_calm` | `reads_cancelled` is false, the line says it can still be signed, inside the retry window round 5 added, and a day-long warning names the spend. The owner's own later spend reads calm. |
| The film's cancel is not counted | `review4: the_films_cancel_counts_and_the_model_can_read_it`, `scenarios: a_rotation_counts_what_it_stopped_as_cancels` | One count at zero credit, one in the next snapshot per live request, and none when nothing was live. |
| "Set per vault" is false on test coins | `review4: a_test_coin_vault_can_set_its_own_wait`, `scenarios: test_coin_floors_hold` | A chosen wait lands and a request waits it. One millisecond outside the range is refused, and the reaction window did not move. |
| `funds movable` beside a line saying nothing can move | `review4: status_says_funds_movable_only_when_they_are`, `scenarios: funds_movable_is_said_only_when_it_is_true` | Said only when active, not frozen and not suspended. |
| Calm after a real signature | `scenarios: status_says_an_executed_request_can_still_be_signed_after_a_rotation` | `last spend reached signing at <t>`. Calm on its own, since a contract cannot tell whose it was. |
| The signer and credit lines do not match behaviour | `review4: the_signer_line_promises_no_retry`, `the_credit_line_matches_what_a_proposal_costs` | No promise of retry. The credit line's two figures are checked against real refusals. |
| `check_propose` says yes to a suspended key | `review4: check_propose_refuses_a_suspended_key`, `scenarios: check_propose_refuses_a_suspended_key` | The same refusal `propose_btc` gives. |
| Stated rules with no test | `scenarios: test_coin_floors_hold`, `the_guarded_delay_cannot_pass_the_unguarded_one`, `a_taproot_output_needs_version_one`, `reclaim_pays_the_rate_floor`, `the_grant_list_holds_eight`, `a_lapsed_freeze_stops_reading_as_frozen`, `dead_requests_are_not_counted_as_pending`, `recover_cancel_with_none_running_burns_nothing`, `execute_needs_at_least_one_input`; `review4: the_model_signer_list_holds_eight`, `the_excluded_list_holds_thirty_two`, `assess_reads_the_first_choice`, `a_passkey_assertion_binds_its_vault_contract_tag_and_expiry` | One each, with a mutant in `mutation-check.py` or `shell-mutants.py`. The binding mutants change the contract and the harness's digest together, so only a digest made for something else can notice. |
| A harness reads an infrastructure failure as a kill | `scripts/shell-mutants.py --self-test`, `tools/test/mutants.mjs --self-test`, both in `tools/test/run-all.sh` | A kill needs a test that failed. Otherwise the run is retried, and then reported as not judged, which fails the run. |
| `raise_fee_cap`, other methods and lazy deletion missing from the spec | SPEC 1.1, 4.1, 11 | Text only. |

Two more mutants have no test on purpose, because no input can tell them from the real code. Dropping the test-coin floor on `t_new_unguarded_ms` changes nothing, because that delay may not be below `t_new_ms`, whose own floor is the same. Dropping the first `max_inputs == 0` check in `execute` changes nothing on the wasm, because the same error comes a few lines later and a panic rolls back what came between. The core harness rolls back an error the same way, so a core mutant of it lived too, and `execute_needs_at_least_one_input` stays as the rule's test.

## Authorization audit (round 5)

A defensive authorization audit of the contract and the core, two reviewers per finding. No high or medium finding in this lane. Core tests are in `crates/undo-core/props/tests/round5.rs`, sandbox tests in `tests/tests/review5.rs`, and each failed on the build before it. The first `review5` test runs the sandbox clock a little over a day: under a minute on the nodes `scripts/protocol-check.sh` starts, and about 50 minutes on near-workspaces' own sandbox.

| Finding | Test | Result expected now |
|---|---|---|
| C1, low: a known destination's 24 h cap counted from propose, so two full caps could reach signing five minutes apart on the proof preset | `round5: a_pending_request_holds_its_outflow_for_as_long_as_it_lives`, `an_executed_request_counts_for_a_day_from_its_signature_on_test_coins`, `a_hold_cannot_stretch_the_cap`, `a_week_long_expiry_cannot_queue_three_caps`, `a_half_signed_spend_counts_from_its_last_signature_request_and_closes_a_day_after_its_first`, `the_window_counts_from_the_last_signature_to_land`, `a_superseded_or_pruned_spend_still_counts_for_its_day`, `review5: outflow_counts_until_a_day_after_signing_on_the_wasm` | A pending request holds its outflow while it lives. After execute it counts for a day from the last signature request or the last signature. From a day after a paying request's first execute, execute asks the signer for nothing more for it, so a half-signed one cannot finish inside a later request's window, and `reclaim` is its way out. An answer to an earlier ask can still land after that, and moves the time when it completes the request. |
| C1, what the fix must not break | `round5: an_execute_moves_only_its_own_entry`, `a_self_spend_can_still_retry_after_a_day`, `a_rotation_or_freeze_releases_pending_outflow_and_keeps_what_is_signing`, `scenarios: the_outflow_window_leaves_the_row_after_a_day` | Self-spends retry as before. A rotation or freeze releases only pending reservations. The row still drops an entry after its day. |
| C2, low: the guard line said "doubled" whatever the policy | `round5: the_guard_line_names_the_real_delays`, `review5: status_prints_the_real_delays_and_the_freeze_rule` | Both delays are printed, and equal ones are called the same. |
| C3, low: the freeze line named only grants, and the recovery line counted cancels a freeze holds | `round5: the_freeze_line_says_exactly_what_is_blocked`, `the_recovery_line_says_a_freeze_holds_the_passkeys_cancels`, `review5: status_prints_the_real_delays_and_the_freeze_rule` | The line names proposals, reclaims, execute and every passkey action but cancel, and says cancel has nothing to stop. |
| C4, low, one of two reviewers: a reclaim deleted a Signed request with no log | `review5: reclaim_logs_the_signed_transaction_it_supersedes` | `undo:superseded request=<id> tx=<hex>`, the same bytes `final_tx` gave, at 16 inputs. The supersede itself is unchanged. |

Mutants: 15 more in `crates/undo-core/props/mutation-check.py` (`outflow:` and the new `status:` ones) and 2 in `scripts/shell-mutants.py` (the reclaim log).

### The confirmation's new problems

The two reviewers of round 5 found five more, all low. The `round5` tests in the first three rows failed on `76a886c`, the round-5 source before this, and pass now. The last two rows were wording: their behaviour was already as the new words say, so their tests pass on both.

| Problem | Test | Result expected now |
|---|---|---|
| The signer-failure line said a request still signing can retry, false for a paying request 24 h after its first execute | `round5: the_signer_line_names_the_retry_window_and_reclaim` (the reviewer's 25 h case), `review4: the_signer_line_promises_no_retry` | The line names the window, a self-spend with no time limit and a paying request for at most 24 h after its first execute, and the way out: reclaim, at most one per `T_new`, or with a new key while the spend key is suspended. |
| The suspended-key line said an executed request keeps signing | `round5: the_suspended_key_line_names_the_retry_window_and_reclaim_with_a_new_key` (the reviewer's rotation, veto and 25 h case), `scenarios: status_says_an_executed_request_can_still_be_signed_after_a_rotation`, `review4: a_rotation_after_execute_does_not_read_as_cancelled` | The same window, and reclaim with a new key. Reclaim is refused while the key is suspended and works once a new one lands. |
| A request executed before an upgrade kept its propose-time entry, which left a day after propose, and could still retry until a day after its first execute | `round5: a_request_executed_before_an_upgrade_stops_retrying_when_its_entry_leaves`, on a row whose entry is set back to propose, as an earlier build left it | A retry with no entry left is refused with `RetryWindowClosed`, closed a day after propose. One before the entry leaves works and moves it. |
| "Takes no signatures 24 h after its first execute" and "two days" were not exact | `round5: an_answer_asked_for_before_the_close_lands_after_it_and_counts_from_there` | An answer to a retry asked for before the close lands after it, completes the request, and counts for a day from its landing. |
| "Doubles" in `./verify.sh B`'s C06 line and in the spec's failure tables | C06 now also names `scenarios: the_guarded_delay_cannot_pass_the_unguarded_one` and `round5: the_guard_line_names_the_real_delays` | The line says the unguarded delay, which the bounds keep at or above the guarded one. |

Mutants: 7 more in `crates/undo-core/props/mutation-check.py`: the retry after an earlier build's entry has left, the close it reports, the window's length in the lines, the old wording of each line, the suspended key offered reclaim, and reclaims spaced by the wrong delay.

The same check found one in the relay, low: it sent `execute` for a Signing request the contract would refuse, and the thief tab sent it again every 30 s for as long as the request read Signing, so each call after the window closed was a failed transaction on the relay's general key. The tests failed on the code before the fix (the relay sent the call; the tab's loop had no stop) and pass now.

| Problem | Test | Result expected now |
|---|---|---|
| The relay sent `execute` for a Signing request whose retry window had closed, or whose sign call was still out | `site/test/relay.test.mjs: execute on a Signing request: refused before the general key pays when the contract would refuse it, sent when it might not`; on the real wasm in workerd, `site/test/relay.workerd.test.mjs: a sign call still out: …` | Refused before the key signs once a paying request is a day past its first execute, and while a sign call is out if its first execute is newer than the block 240 back. When neither can be shown from the views, the call goes and the contract decides. The contract refuses the same call with `InFlight`. |
| The thief tab resent `execute` after the window closed | `site/test/thief.test.mjs: while signing, execute goes again every interval, and stops once the request can no longer ask for signatures` | It stops, and says the contract asks the signer for nothing more. A self-spend keeps retrying. |

## Section 11, the last methods

Every method is on both protocols through `scripts/protocol-check.sh`, with a positive and a negative in `tests/tests/surface.rs`:

| Method | Tests |
|---|---|
| `add_destination` | `add_destination_waits_*`, `add_destination_negatives`, `removing_and_tightening_*` |
| `remove_destination` | `remove_destination_lands_*`, `removing_and_tightening_*` |
| `set_policy` | `tightening_is_at_once_*`, `set_policy_is_bounded_*`, `a_loosening_with_no_credit_*` |
| `set_guard` | `set_guard_waits_*` |
| `clear_hold` | `clear_hold_returns_*` |
| `heartbeat`, `delay_now` | `heartbeat_keeps_*`, `first_heartbeat_with_no_credit_*`, `a_guard_function_call_key_*` |
| `guard_prompt`, memo, snapshot | `guard_prompt_is_built_*`, `memo_is_bound_*` |
| `assess`, `add_model_signer`, `set_guard_model` | `assess_checks_*`, `assess_refuses_*`, `assess_needs_no_credit`, `model_signers_*` |
| `status` | `status_is_plain_*`, `status_says_*` |
| `stats`, `stats_exclude` | `stats_counts_*`, `cancel_at_zero_credit_*` |
| `upgrade_propose`, `upgrade_cancel`, `upgrade_apply`, `migrate` | `an_upgrade_lands_*`, `upgrade_authority_*`, `code_without_a_migrate_*`, `upgrade_apply_with_too_little_gas_*`, `migrate_is_private` |

What the film and the page read, each with its own test in `tests/tests/surface.rs`:

| Film needs | Test | Result expected |
|---|---|---|
| A new vault reads 5:00 | `film_a_new_vault_reads_five_minutes_*` | The relay is the guard the vault signed for and beats in the creating transaction. With no beat it reads 10:00, and a relay it did not name is refused |
| The thief tab fires at zero | `film_the_thief_tab_can_execute_*`, and `crates/undo-core/props: execute_goes_through_the_moment_*` | Any account, no deposit. One millisecond early is refused, the unlock's own millisecond is not |
| Cancel stops the clock | `film_the_phones_cancel_*` | Epochs differ from that block on while the status still reads `Pending`. Then the request reads null. Thief's execute reaches no signer, and the stolen key is refused before and after the new one lands |
| `+5:00` lands once | `film_a_hold_adds_exactly_*` | `unlock` moves by exactly 5 min, `hold_active` and `assess_reason` read back, and a rotation still kills it |

Found while building these: a full grant list stopped the panic button (`crates/undo-core/props: the_panic_button_fits_*`), and known destinations were unbounded (`known_destinations_are_bounded_*`). Found on the first full run: `upgrade_apply` reported success on the transaction when the deploy had rolled back, because nothing returned the batch, so it now returns it (`code_without_a_migrate_*`).
