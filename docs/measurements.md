# Gas, size and storage

Local sandbox, near-sandbox 2.14.0, on nodes pinned to protocols 86 and 88, with the mock signer. Nothing here is from a live network, and the live signer's own gas is not in these numbers. Regenerate with:

```
scripts/build.sh
scripts/protocol-check.sh --measure    # <target>/measure-<version>.txt
```

The two protocols agreed to within 0.03 Tgas per method and 0.08 Tgas per transaction.

## Size

| Thing | Bytes | NEAR at 1e19 yocto per byte |
|---|---:|---:|
| `undo_vault.wasm` after wasm-opt | 288,759 | |
| Contract account storage, with state | 289,346 | 2.89 |
| `mock_signer.wasm`, tests only | 140,499 | |

The contract does not yet hold `bump`, `assess`, `heartbeat`, `set_policy`, destinations or the upgrade queue, so the deployed size will be larger.

## Gas, Tgas burnt

Signer attach 30 Tgas, callback attach 10 Tgas. "Method" is the contract's own receipt. "Tx" is the whole transaction, including the mock.

| Method | Inputs | Method | Each `on_signed`, max | Tx |
|---|---:|---:|---:|---:|
| `create_vault` | | 5.41 | `on_derived` 1.85 | 13.15 |
| `propose_btc` | 1 | 2.81 | | 3.15 |
| `propose_btc` | 3 | 3.90 | | 4.26 |
| `propose_btc` | 8 | 6.64 | | 7.06 |
| `propose_btc` | 16 | 11.03 | | 11.53 |
| `execute` | 1 | 3.28 | 2.66 | 10.08 |
| `execute` | 3 | 5.33 | 3.17 | 25.57 |
| `execute` | 8 | 10.42 | 4.45 | 67.06 |
| `execute` | 16 | 18.56 | 6.50 | 141.75 |
| `cancel`, passkey | | 3.57 | | 3.90 |
| `cancel`, cold key | | 2.45 | | 2.77 |
| `cancel_all_and_rotate` | | 3.35 | | 3.69 |
| `reclaim` | | 3.01 | | 3.34 |
| `veto_grant` | | 2.47 | | 2.79 |
| `freeze` | | 2.11 | | 2.43 |
| `unfreeze` | | 2.10 | | 2.42 |
| `recover_begin` | | 3.57 | | 3.93 |
| `recover_cancel` | | 3.23 | | 3.57 |
| `recover_finish` | | 1.73 | | 2.05 |
| `prune_signed` | 1 | 2.20 | | 2.52 |
| `deposit_storage` | | | | 2.02 |

The `on_signed` figure grows with the request's own inputs, because the answer that completes a request reads their ledger entries, and every answer rebuilds the digests. At the 16-input maximum it leaves 3.5 of the 10 Tgas attach. `execute` also computes the transaction's id and reads its child entries at first execute, about 0.2 Tgas here.

The mock's `derived_public_key` burned 5.05 Tgas, which says nothing about the real signer's view.

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
| Empty vault | 666 | 152 |
| Pending request, 1 input, with change | 690 | 405 |
| Pending request, 16 inputs, with change | 690 | 1,785 |
| Signed request, any size | 690 | 152 |

A pending request reserves everything its execute and answers can add: 92 bytes per input, 40 for the request, and 121 for each coin it pays back to the vault, which gets a ledger entry at first execute. `review2` runs a whole life with the credit at zero, and the only bytes it finds over the growth are the ones that were transient: an in-flight entry per input, the pending entry and the slot's holder, plus an override if nobody asked for one.

A `prune_signed` of a signed 2-input request gave back 605 bytes.

## History does not weigh on the callback

`review1_growth` runs real completed self-spends, one coin each, with the named fee override so no day-long clock jump is needed. Before each request had its own storage entry, the same run lost its signature at spend 141: `on_signed` passed its 10 Tgas attach and the retry failed the same way.

| Spends | Row bytes | `on_signed` |
|---:|---:|---:|
| 25 | 1,082 | 2.77 |
| 50 | 1,482 | 2.82 |
| 100 | 2,282 | 2.93 |
| 150 | 3,082 | 3.04 |

The row still grows 16 bytes per spend in this run, which is the 24 h fee window. Entries leave after a day, and `first_execute` sweeps them, so this is bounded by spends per day. Without a passkey override the fee budget limits that to about 26 a day on the test-coin values. With an override, the slot limits a change-bearing or self-spend to one per `T_new`. This run's clock covered less than a day, so the shrink was not observed on the wasm. `crates/undo-core/props: the_fee_window_leaves_the_row_after_a_day` covers it in the core.

Credit per spend in that run, one input each: 0.00709 NEAR before pruning and 0.00274 NEAR after. What stays is the ledger entry with its pin, which the fee rules need forever, and the entry for the coin it paid back to the vault, which the chain wait needs.

Pins in their own entries do not move the other methods either, on a vault with 40 pins:

| Pins | Row bytes | `on_signed`, 8 inputs | `propose_btc`, 1 input | `cancel`, passkey |
|---:|---:|---:|---:|---:|
| 8 | 706 | 4.46 | | |
| 40 | 866 | 4.50 | 2.87 | 3.62 |

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
| One failing 30 Tgas call, after refund | 0.000180 NEAR of allowance |
| Same, held until the refund lands | 0.0309 NEAR at 30 Tgas, 0.1009 at 100, 0.2009 at 200 |
| Smallest allowance tried that ran `execute`, 1 input at 70 Tgas prepaid | 0.1 NEAR |
| Smallest allowance tried that ran `execute`, 8 inputs at 350 Tgas prepaid | 0.5 NEAR |

Tried values were 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1 and 2 NEAR. These are sandbox gas prices.

## Live on the testnet signer (11/1, Taipei)

`tools/g1.mjs --live` against `v1.signer-prod.testnet` 3.18.0 on protocol 88. Proof: `proofs/g1.json`. Coins were made up: `execute` does not read Bitcoin, so nothing here moved a coin. `K_p` was a software authenticator.

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
