# Gas, size and storage

Local sandbox, near-sandbox 2.14.0, on nodes pinned to protocols 86 and 88, with the mock signer. Nothing here is from a live network, and the live signer's own gas is not in these numbers. Regenerate with:

```
scripts/build.sh
scripts/protocol-check.sh --measure    # <target>/measure-<version>.txt
```

The two protocols agreed to within 0.04 Tgas per method and 0.16 Tgas per transaction, both at `execute` with 16 inputs.

## Last full run

11/1, on the wasm below, sandbox with the mock signer, regtest and the consensus library. Nothing here touched a live network.

| Check | Result |
|---|---|
| `scripts/protocol-check.sh` | 125 passed, 0 failed, on each of protocols 86 and 88 |
| `crates/undo-core/props` | 113 passed, including 105 scenarios |
| `crates/undo-core/props/mutation-check.py` | 139 of 139 killed, control green |
| `scripts/shell-mutants.py` | 164 of 164 killed, control green. One lived on the first pass, the view's request epoch, because a fresh vault's epoch is 0: `film_the_phones_cancel_*` now reads the next request's too, and that mutant was re-run alone, not the other 163 |
| `tools/test/run-all.sh` | Passed: 86 tool mutants killed, G1 driver on both protocols, G2 rehearsal 40 scenarios |
| `crates/undo-btc` regtest | 2 passed on real bitcoind, including the escape's fee race |

## Size

| Thing | Bytes | NEAR at 1e19 yocto per byte |
|---|---:|---:|
| `undo_vault.wasm` after wasm-opt, sha256 `1f0f7860…` | 371,025 | |
| Contract account storage, with state | 371,734 | 3.72 |
| `mock_signer.wasm`, tests only | 151,856 | |

This is the whole method list. `bump` was cut by decision, from the crate as well as the contract: `reclaim` after `T_stuck` covers a stuck coin. An upgrade needs a smaller deposit than this only if the code shrinks: the contract account holds the storage for its own code, so a larger wasm has to find the difference in its balance first.

## Gas, Tgas burnt

Signer attach 30 Tgas, callback attach 10 Tgas. "Method" is the contract's own receipt. "Tx" is the whole transaction, including the mock.

| Method | Inputs | Method | Each `on_signed`, max | Tx |
|---|---:|---:|---:|---:|
| `create_vault` | | 5.56 | `on_derived` 2.00 | 13.46 |
| `create_vault` and `heartbeat` in one transaction | | | | 15.45 |
| `propose_btc` | 1 | 2.97 | | 3.31 |
| `propose_btc` | 3 | 4.06 | | 4.42 |
| `propose_btc` | 8 | 6.80 | | 7.22 |
| `propose_btc` | 16 | 11.19 | | 11.70 |
| `execute` | 1 | 3.44 | 2.99 | 10.59 |
| `execute` | 3 | 5.49 | 3.50 | 26.45 |
| `execute` | 8 | 10.58 | 4.77 | 68.85 |
| `execute` | 16 | 18.72 | 6.82 | 144.98 |
| `cancel`, passkey | | 3.89 | | 4.23 |
| `cancel`, cold key | | 2.60 | | 2.92 |
| `cancel_all_and_rotate` | | 3.51 | | 3.85 |
| `reclaim` | | 3.17 | | 3.51 |
| `veto_grant` | | 2.63 | | 2.95 |
| `freeze` | | 2.26 | | 2.59 |
| `unfreeze` | | 2.26 | | 2.58 |
| `recover_begin` | | 3.73 | | 4.08 |
| `recover_cancel` | | 3.39 | | 3.72 |
| `recover_finish` | | 1.89 | | 2.20 |
| `prune_signed` | 1 | 2.35 | | 2.67 |
| `deposit_storage` | | | | 2.17 |
| `heartbeat` | | 1.90 | | 2.21 |
| `add_destination` | | 3.42 | | 3.77 |
| `remove_destination` | | 3.44 | | 3.78 |
| `set_policy` | | 3.43 | | 3.77 |
| `set_guard` | | 3.42 | | 3.76 |
| `clear_hold` | | 3.66 | | 4.00 |
| `assess`, a 1 KB answer | | 2.60 | | 2.95 |
| `assess`, the largest answer it reads, 16 KB | | 8.25 | | 10.13 |
| `upgrade_propose` | | 1.63 | | 1.94 |
| `upgrade_cancel` | | | | 3.42 |
| `upgrade_apply`, 371 KB of code as raw input, with its deploy and `migrate` | | 25.57 | | 62.12 |

The request body `guard_prompt` returns is 1,179 bytes with no memo.

## Griefed queue, and what a relay attaches

The rows above are best case. Here a thief has filled the queue with the largest requests the rules allow, 16 inputs and two of 8, and a stolen passkey has filled the grant list, so every owner method has them to load. The row is 1,372 bytes. `tests/tests/measure.rs: gas_of_owner_methods_on_a_griefed_queue`.

| Method | Tx, griefed | Best case |
|---:|---:|---:|
| `cancel`, passkey, 32 inputs waiting | 5.85 | 4.23 |
| `cancel`, cold key | 4.54 | 2.92 |
| `cancel_all_and_rotate`, live queue | 4.30 | 3.85 |
| `cancel_all_and_rotate`, sweeping the dead queue, full grant list | 10.12 | 3.85 |
| `freeze`, sweeping the dead queue | 7.48 | 2.59 |

**A relay attaches 30 Tgas to every `K_p` and `K_e` method**, `OWNER_ATTACH_TGAS` in `tools/lib/vault-client.mjs`: three times the worst row. The test runs each rotation at exactly that, and `tools/test/sandbox-intents.mjs` runs the passkey methods at it. Unused gas comes back, and a function-call key has the whole attach held against its allowance until it does. Not measured with 32 known destinations in the row, which would add about 700 bytes to read. A guard's key: 10 Tgas for `heartbeat`, and 20 Tgas clears the largest `assess`.

`upgrade_apply` burns 62 Tgas in all for this size of code, so attach well above that. A call with too little fails in its first receipt and leaves the approval standing, tried at 15, 30 and 45 Tgas (`surface: upgrade_apply_with_too_little_gas_*`).

The `on_signed` figure grows with the request's own inputs, because the answer that completes a request reads their ledger entries, and every answer rebuilds the digests. At the 16-input maximum it leaves 3.2 of the 10 Tgas attach. `execute` also computes the transaction's id and reads its child entries at first execute, about 0.2 Tgas here.

The mock's `derived_public_key` burned 5.07 Tgas, which says nothing about the real signer's view.

## Smallest prepaid gas for `execute`

Found by trying values in 2 Tgas steps. Below this the call is refused and nothing changes.

| Inputs | Attach at least | Over sign + callback |
|---:|---:|---:|
| 1 | 46 | 6 |
| 3 | 130 | 10 |
| 8 | 344 | 24 |
| 16 | 688 | 48 |

The per-transaction limit on both live networks was read as 1,000 Tgas earlier, so 16 inputs fit.

## Storage

The vault row holds neither requests nor ledger entries. Each request and each ledger entry is its own storage entry, which costs 40 bytes of overhead plus its key: 41 bytes for a request, 69 for a ledger entry.

| State | Row bytes | Reserved bytes |
|---|---:|---:|
| Empty vault | 958 | 226 |
| Pending request, 1 input, no change | 982 | 479 |
| Pending request, 16 inputs, no change | 982 | 1,859 |
| Signed request, any size | 982 | 152 |

An empty vault costs at least 0.01257 NEAR of attached deposit. A first `heartbeat` adds 8 bytes. The row is 292 bytes larger than before the last methods: the snapshot's three fixed rings, the four times it and `status` read, and one flag. A request grew by its snapshot, with its memo on top. The reservation's extra 74 bytes before a vault's first completed cancel or spend are the public count's entry.

A pending request reserves everything its execute and answers can add: 92 bytes per input, 40 for the request, and 121 for each coin it pays back to the vault, which gets a ledger entry at first execute. These rows were measured on self-spends with no change, one coin paid back. `review2` runs a whole life with the credit at zero, and the only bytes it finds over the growth are the ones that were transient: an in-flight entry per input, the pending entry and the slot's holder, plus an override if nobody asked for one.

A `prune_signed` of a signed 2-input request gave back 631 bytes.

## History does not weigh on the callback

`review1_growth` runs real completed self-spends, one coin each, with the named fee override so no day-long clock jump is needed. Before each request had its own storage entry, the same run lost its signature at spend 141: `on_signed` passed its 10 Tgas attach and the retry failed the same way.

| Spends | Row bytes | `on_signed` |
|---:|---:|---:|
| 25 | 1,374 | 2.89 |
| 50 | 1,774 | 2.94 |
| 100 | 2,574 | 3.05 |
| 150 | 3,374 | 3.16 |

The row still grows 16 bytes per spend in this run, which is the 24 h fee window. Entries leave after a day, and `first_execute` sweeps them, so this is bounded by spends per day. Without a passkey override the fee budget limits that to about 26 a day on the test-coin values. With an override, the slot limits a change-bearing or self-spend to one per `T_new`. This run's clock covered less than a day, so the shrink was not observed on the wasm. `crates/undo-core/props: the_fee_window_leaves_the_row_after_a_day` covers it in the core.

Credit per spend in that run, one input each: 0.00739 NEAR before pruning and 0.00274 NEAR after. What stays is the ledger entry with its pin, which the fee rules need forever, and the entry for the coin it paid back to the vault, which the chain wait needs.

Pins in their own entries do not move the other methods either, on a vault with 40 pins:

| Pins | Row bytes | `on_signed`, 8 inputs | `propose_btc`, 1 input | `cancel`, passkey |
|---:|---:|---:|---:|---:|
| 8 | 998 | 4.84 | | |
| 40 | 1,158 | 4.71 | 3.04 | 4.13 |

## A pre-signed chain of CSV restarts

A self-paying link can spend the coin the last one has not broadcast yet, so a thief can sign a chain and hold it. Each link is one CSV restart, and each one passes libbitcoinconsensus (`review2: chain_on_*`). The contract spaces them, by the longer of `T_new` and three quarters of CSV. `crates/undo-core/props/tests/scenarios.rs` walks the fastest chain the rules allow, and one millisecond sooner is refused at every step:

| Preset | Chain wait | Spacing | Links in 2 h | Restart time they buy, at one CSV each |
|---|---:|---:|---:|---:|
| Test coin | 2 min 15 s | 5 min | 24 | 72 min |
| Mainnet proof vault | 45 min | 45 min | 3 | 180 min |

Over a day the fee budget stops the test-coin chain first: 31 links at the lowest fee the rate floor allows, 161 sats. The link count is the core's. The clock is not Bitcoin's: CSV counts blocks, and this converts at 30 s and 10 min a block. No chain of restarts has been run on regtest or any Bitcoin network.

## Recovery at the deployed constants

`review1: recovery_cap_*`, with the thief cancelling at nine tenths of each wait. The third begin cannot be cancelled.

| Instance | `T_recover` | Owner back after |
|---|---:|---:|
| Test coin | 15 min | 2.80 x `T_recover` |
| Mainnet proof vault | 1 h | 2.80 x `T_recover` |

## Function-call keys

| What | Measured |
|---|---|
| One failing 30 Tgas call, after refund | 0.000192 NEAR of allowance |
| Same, held until the refund lands | 0.0309 NEAR at 30 Tgas, 0.1009 at 100, 0.2009 at 200 |
| Smallest allowance tried that ran `execute`, 1 input at 70 Tgas prepaid | 0.1 NEAR |
| Smallest allowance tried that ran `execute`, 8 inputs at 350 Tgas prepaid | 0.5 NEAR |

Tried values were 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1 and 2 NEAR. These are sandbox gas prices.

## Live on the testnet signer (11/1, Taipei)

This section and the next are the build before the last methods. The contract has changed since, and nothing below has been repeated on it. `tools/g1.mjs --live` against `v1.signer-prod.testnet` 3.18.0 on protocol 88. Proof: `proofs/g1.json`. Coins were made up: `execute` does not read Bitcoin, so nothing here moved a coin. `K_p` was a software authenticator.

| Stage | Result |
|---|---|
| Activation | A good vault activates. A vault with the wrong `K_m` is refused, leaves no row, and its 0.1 NEAR deposit comes back |
| Ladder | Signed at 15, 20 and 30 Tgas attached |
| One input | 10 of 10 at 30 Tgas. 6.2 to 8.6 s to the signature, median 6.8 s |
| Three inputs | 5 of 5, 7.6 to 8.5 s |
| Ten inputs | 1 of 1, 8.5 s |
| Function-call key | Execute through a function-call key signed, and vault credit paid |
| Final transactions | 20 accepted by libbitcoinconsensus, 20 wrong-value controls refused (`tools/test/check-g1-proof.mjs`) |

At 15 Tgas attached, one input: 15.04 Tgas total, `execute` 3.35, `on_signed` 2.72, signer 4.29.

What this taught the tools:

- near-cli 0.30.1 generates ML-DSA-65 keys when it creates an account. These tools sign ed25519 only, so the runs used ed25519 sub-accounts, `s.undo-btc.testnet` and `s.undo-relay.testnet`, signed into being by the near-cli keys.
- Since protocol 85 gas is bought up front, and refunds land in later blocks. A balance read right after a call shows a loss that is about to come back.
- A public RPC answers a rate limit as a JSON error with no cause. `tools/lib/near.mjs` now waits and retries it.

## Live on Mutinynet (11/1, Taipei)

`tools/g2.mjs --live`: real coins on Mutinynet, real signature from `v1.signer-prod.testnet` 3.18.0 on protocol 88, contract `g1.s.undo-btc.testnet`. Proof: `proofs/g2.json`. CSV 6 blocks, coins of 20,000 sats, 2 sat/vB.

| Step | Result |
|---|---|
| Co-signed spend | `66825f2c…`, 148 vB, mined at 3551937. Signer answered in 6.7 s after the 10 minute unlock. Strict DER and low S on both signatures. The signer's S was low, so normalising a high S is still shown only with the mock signer |
| Same spend without K_u's signature | Refused by the node: `mempool-script-verify-flag-failed (Script failed an OP_CHECKSIGVERIFY operation)` |
| Escape at 1 of 6 confirmations | Refused: `non-BIP68-final` |
| Escape signed for nSequence 5, on the mature coin | Refused by the node: `mempool-script-verify-flag-failed (Locktime requirement not satisfied)` |
| Escape, same bytes as the early try | `6fa75369…`, built by `tools/escape.mjs` from the recovery file and one Esplora entry, mined at 3551944, 6 blocks after the coin |
| Real POST from a browser page on another origin | Reached a node and its answer was readable: the mined escape again, `Transaction outputs already in utxo set`. Origin was `https://example.com`, not this project's page, so that page's own CSP is untested |

Cost: 1,168 sats of fees, exactly as planned. Nothing is left in the vault. A refusal costs nothing.

A young coin's refusal says nothing about the witness, since a node checks BIP-68 before the script. That is why the two refused controls exist: a script with `OP_CSV` or K_u's check removed takes them.

What this taught the tools:

- A mutation score means nothing until the tests pass on an unbroken copy. `tools/test/mutants.mjs` read every mutant as killed because a scratch copy with no `proofs/` failed one test. With a control, 4 real survivors appeared.
- Esplora answers every node refusal with a 400, and also uses 400 for a busy node. Only a script refusal of a correctly built spend is G2's kill line.
- On Mutinynet, `/tx/<unknown>/status` answers 200 `{"confirmed":false}` and `/tx/<unknown>/outspend/0` answers 200 `{"spent":false}`. Only `/tx/<unknown>` gives a 404, so a lost transaction has to be looked for there.
