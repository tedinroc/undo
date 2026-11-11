# Gas, size and storage

Local sandbox, near-sandbox 2.14.0, on nodes pinned to protocols 86 and 88, with the mock signer. Nothing here is from a live network, and the live signer's own gas is not in these numbers. Regenerate with:

```
scripts/build.sh
scripts/protocol-check.sh --measure    # <target>/measure-<version>.txt
```

The two protocols agreed to within 0.06 Tgas per method and 0.08 Tgas per transaction. The same wasm measured twice moved by up to 0.25 Tgas on the griefed rows, so read the last digit as noise.

## Last full run

2026-11-07 UTC, on the wasm below, sandbox with the mock signer, regtest and the consensus library. Nothing here touched a live network. Every check ran on the contract source of the final build, `358c63bf…`. Only docs changed after the run, and the build, the identity, secret and outward scans, the judge-floor test, the core suite and the sandbox files `review4.rs` and `review5.rs` ran again on it. The earlier build `39f70262…` ran the same checks earlier the same day.

| Check | Result |
|---|---|
| `scripts/build.sh` | `undo_vault.wasm` 381,119 bytes, sha256 `358c63bf…` |
| `scripts/check-wasm.sh`, `check-identity.sh`, `secret-scan.sh`, `test-secret-scan.sh`, `outward-check.sh` | OK |
| `scripts/protocol-check.sh` | 151 passed, 0 failed, on each of protocols 86 and 88, including `review5.rs`, which runs the sandbox clock about a day |
| `scripts/protocol-check.sh --measure` | 6 passed on each, the figures below |
| `crates/undo-core/props` | 148 passed, including 123 scenarios and the 17 in `props/tests/round5.rs` |
| `crates/undo-core/props/mutation-check.py` | 187 of 187 killed, control green |
| `scripts/shell-mutants.py`, protocol 88 | 200 of 200 killed, control green, none read as not judged |
| `tools/test/run-all.sh` | Passed: 87 tool mutants killed, none not judged, both harness self-tests, G1 driver on both protocols, G2 rehearsal 40 scenarios, the watcher on a local node 12 passed and 1 skipped (its relay case needs `site/`, which the tree did not hold yet) |
| `agent/test/run-sandbox.sh 86 88` | 49 of 49 on each |
| `./verify.sh A`, `./verify.sh B` | A: 35 PASS, 3 SKIP because nothing is deployed, 0 FAIL. B: 13 PASS |
| `crates/undo-btc` | 50 passed, and 2 on real bitcoind regtest, including the escape's fee race |

### Again, on the tree with the pages and the relay

2026-11-07 UTC, on the tree that adds `site/`, the relay and `worker/undo-cron/` to this contract source, which they leave unchanged. Same labels and limits as above, and Chrome was off, so no browser test ran.

| Check | Result |
|---|---|
| `scripts/build.sh` | the same `358c63bf…`, 381,119 bytes |
| `check-wasm.sh`, `check-identity.sh` (tree and wasm), `secret-scan.sh`, `test-secret-scan.sh`, `outward-check.sh` | OK |
| `scripts/protocol-check.sh` | 151 passed, 0 failed, on each of protocols 86 and 88 |
| `crates/undo-core/props`, and its mutants | 148 passed; 187 of 187 killed, control green |
| `crates/undo-btc` | 50 passed, and 2 on bitcoind regtest |
| `site/test/*.test.mjs` | 195 passed, 0 failed, 74 skipped: 53 need Chrome, and 21 are the workerd file, run on its own on the next line |
| `site/test/relay.workerd.test.mjs`, the relay in real workerd against the wasm | 21 of 21 |
| `tools/test/pages-output-check.sh` | 17 OK, 0 FAIL, 80 files |
| `scripts/go-live/test/golive.test.mjs`, local node and stub wrangler | 23 of 23 |
| `tools/test/run-all.sh` | Passed: 94 tool mutants killed, G1 driver on both protocols, G2 rehearsal 40 scenarios, the watcher on a local node 15 of 15 |
| `agent/test/run-sandbox.sh 86 88` | 49 of 49 on each |
| `./verify.sh B` | 13 PASS |
| `./verify.sh A` on a local stage, an instance of this build with no access key | 38 PASS, 0 SKIP, 0 FAIL |
| `./demo.sh` on that local stage | 5 PASS in 67 s |

Not run this time: the shell mutants and `--measure`, because `contracts/` did not change after the run above.

After that run the relay changed, and no contract file did: it now counts a vault as its own only once the chain shows its own `create_vault` made it. On that tree, 2026-11-07 UTC, Chrome still off: `site/test/*.test.mjs` 200 passed, 0 failed, 74 skipped (53 need Chrome, 21 are the workerd file); `site/test/relay.workerd.test.mjs` 21 of 21; `tools/test/pages-output-check.sh` 17 OK, 0 FAIL; `scripts/go-live/test/golive.test.mjs` 23 of 23; `tools/test/run-all.sh --no-mutants` passed (no file the tool mutants change was touched), with the watcher on a local node 15 of 15 and the agent CLI 49 of 49 on each protocol. The wasm is the same `358c63bf…`.

After that, and again with no contract file changed, the phone's "Copy the thief link" gained a destination (`thiefLink` in `site/pages/p/phone-fragment.mjs`, held by `site/test/thief-link.test.mjs`, which fails 3 of 3 on the earlier page), the landing page a link to `/p/`, and README and CLAIMS the NEAR testnet run of `./demo.sh`. On that tree, 2026-11-07 UTC, Chrome still off: `site/test/*.test.mjs` 203 passed, 0 failed, 74 skipped (53 need Chrome, 21 are the workerd file); `tools/test/pages-output-check.sh` 17 OK, 0 FAIL, 80 files; `tools/test/judge-floor.test.mjs` 16 of 16.

Then Chrome ran again, for the first time since round 4, on the same wasm `358c63bf…` and with no contract file changed, 2026-11-07 UTC: headless Chrome, the local stage, and the relay in real workerd. The first run of `site/test/*.test.mjs` with Chrome passed 319 of 328. Two failures were the test mode. `phone.test.mjs` still read the run's tries and operator passkey from the link, which `c2a445e` had moved into the tab's sessionStorage. And with them kept there, a link that names no vault, opened in a tab that holds a finished run, carried that run's tries and operator passkey into the new vault's report: `phone-h7.test.mjs`'s second test reached the old report instead of a try. `runH7` now takes the stored record only for the vault the link names, or the tries Start again kept, and `site/test/h7-link.test.mjs` holds that, failing on the earlier page. The other 7 were `phone.test.mjs` from attack 9 on: Chrome said the page did not have focus when the test made a passkey, and it did not happen again in four later runs. After the fix: `site/test/*.test.mjs` with Chrome 329 passed, 0 failed, 0 skipped; with Chrome off 247 passed, 0 failed, 53 skipped; `tools/test/film-e2e.mjs` 161 of 161 in 155 s; `tools/test/relay-mutants.mjs --no-stage` 165 of 165 killed.

Then, with no contract file changed and the same wasm `358c63bf…`, 2026-11-07 to 08 UTC: the address decoder in `tools/lib/btc.mjs` reads the whole string by BIP-173 and BIP-350 (it had read only the part after the last `1`, so junk in front of a valid address decoded to that address), `film-e2e` types the thief's address over the one the link fills in, and the phone and thief pages were fixed where a Chrome screenshot review found them wrong at 390x844 and 375x667 (an address off the side, Cancel and the passkey retry below the fold, a flag broken over two lines, a refusal said twice, two layouts for one cancelled state, a bare `TypeError`, the four-digit clock on its label), each now held by a Chrome assert. On that tree: `site/test/*.test.mjs` with Chrome 333 passed, 0 failed, 0 skipped, in 721 s; with Chrome off 248 passed, 0 failed, 55 skipped; `tools/test/film-e2e.mjs` 170 of 170 in 157 s; `tools/test/run-all.sh` with the sandbox and mutants TOOLS OK, its tools mutants 110 of 110 killed (16 of them new, one for each rule of the decoder) and the relay mutants with the stage 165 of 165; `tools/test/relay-mutants.mjs --no-stage` 165 of 165 killed; `agent/test/run-sandbox.sh 86 88` 50 of 50 on each; `tools/test/pages-output-check.sh` 17 OK, 0 FAIL, 80 files.

Then, with no contract file changed and the same wasm `358c63bf…`, 2026-11-08 UTC, the film's frames were read for what a viewer sees. The thief tab now decodes and prints addresses in the network the contract names, as the phone does, so the phone's "to" and the thief's "send to" and row are one string (`bcrt1…` on the local build, `tb1…` on Mutinynet), and the phone's thief link carries its destination in that form. Every refusal of the address decoder is a plain sentence, for another network's address ("it is a regtest address"), a `bitcoin:` link and base58 that fails, where some had read "not base58". Neither page shows a contract's panic, a node's JSON, a browser's error name or a code with underscores: `site/lib/plain-words.mjs` says each in one sentence, once, and logs the raw words to the console. The red bar still shows the node's own bytes. On a landscape thief tab, Try again no longer covers the relay sentence and "unlocks in" clears the chip; the phone's stamp no longer widens the page while its frame holds; the too-late address is in the request screen's mono. Each is held by a Chrome or Node assert that fails on the earlier pages. On that tree: `site/test/*.test.mjs` with Chrome 340 passed, 0 failed, 0 skipped, in 732 s; with Chrome off 254 passed, 0 failed, 56 skipped; `tools/test/film-e2e.mjs` 243 of 243 in 150 s, now with a check of every kept frame for raw words and repeats; `tools/test/run-all.sh` with the sandbox and mutants TOOLS OK, its tools mutants 114 of 114 killed and the relay mutants with the stage 179 of 179; `tools/test/relay-mutants.mjs --no-stage` 179 of 179 killed; `agent/test/run-sandbox.sh 86 88` 53 of 53 on each; `tools/test/pages-output-check.sh` 17 OK, 0 FAIL, 81 files.

Then, with no contract file changed and the same wasm `358c63bf…`, 2026-11-11 UTC: the agent CLI ran once on NEAR testnet against `v1.s.undo-btc.testnet` (`agent/test/testnet-c14.mjs --live`, 4 min 36 s, one vault and one test coin from the relay; record `proofs/c14-agent.json`), and `./verify.sh A` gained the lines that fetch that run's twelve transactions again, three at a time. On that tree: `./verify.sh A` 49 PASS, 0 SKIP, 1 FAIL (C11), 2 INFO, in 43 s with the referee built (60 s with those twelve fetched one at a time), four runs within 25 minutes and no SKIP; `tools/test/judge-floor.test.mjs` 20 of 20, 4 of them new, with the archival RPC's answers for those transactions served from `tools/test/fixtures/c14-archival.json`; `agent/test/offline.test.mjs` 15 of 15, 1 new. `agent/test/run-sandbox.sh` was not run again: no file it runs changed.

## Size

| Thing | Bytes | NEAR at 1e19 yocto per byte |
|---|---:|---:|
| `undo_vault.wasm` after wasm-opt, sha256 `358c63bf…` | 381,119 | |
| Contract account storage, with state | 381,852 | 3.82 |
| `mock_signer.wasm`, tests only | 151,856 | |

An upgrade needs a smaller deposit than this only if the code shrinks: the contract account holds the storage for its own code, so a larger wasm has to find the difference in its balance first, and not in what vaults have paid in (`upgrade_apply` and `migrate` refuse that). `instance.free_balance`, `upgrade_propose`'s log and `status` say how much is free. The final build is 2,805 bytes, 0.03 NEAR, larger than the earlier build `4632075a…`: 2,118 for the outflow rule, retry window, status wording and reclaim log, and 687 for the retry check after an upgrade and the two status lines.

## Gas, Tgas burnt

Signer attach 30 Tgas, callback attach 10 Tgas. "Method" is the contract's own receipt. "Tx" is the whole transaction, including the mock.

| Method | Inputs | Method | Each `on_signed`, max | Tx |
|---|---:|---:|---:|---:|
| `create_vault` | | 5.57 | `on_derived` 2.02 | 13.49 |
| `create_vault` and `heartbeat` in one transaction | | | | 15.51 to 15.57 |
| `propose_btc` | 1 | 2.98 | | 3.32 |
| `propose_btc` | 3 | 4.07 | | 4.44 |
| `propose_btc` | 8 | 6.80 | | 7.21 |
| `propose_btc` | 16 | 11.21 | | 11.71 |
| `execute` | 1 | 3.46 | 3.00 | 10.62 |
| `execute` | 3 | 5.51 | 3.52 | 26.52 |
| `execute` | 8 | 10.59 | 4.79 | 68.97 |
| `execute` | 16 | 18.73 | 6.83 | 145.22 |
| `cancel`, passkey | | 3.90 | | 4.24 |
| `cancel`, cold key | | 2.62 | | 2.94 |
| `cancel_all_and_rotate` | | 3.52 | | 3.86 |
| `reclaim`, superseding a Signed 1-input request, whose transaction it logs | | 3.49 | | 3.83 |
| `reclaim`, superseding a Signed 16-input request | | 8.52 | | 8.86 |
| `veto_grant` | | 2.64 | | 2.96 |
| `freeze` | | 2.28 | | 2.60 |
| `unfreeze` | | 2.27 | | 2.59 |
| `recover_begin` | | 3.74 | | 4.10 |
| `recover_cancel` | | 3.40 | | 3.74 |
| `recover_finish` | | 1.90 | | 2.21 |
| `prune_signed` | 1 | 2.37 | | 2.69 |
| `deposit_storage` | | | | 2.18 |
| `heartbeat` | | 1.91 | | 2.22 |
| `add_destination` | | 3.44 | | 3.78 |
| `remove_destination` | | 3.45 | | 3.79 |
| `set_policy` | | 3.44 | | 3.79 |
| `set_guard` | | 3.43 | | 3.77 |
| `clear_hold` | | 3.67 | | 4.01 |
| `assess`, a 1 KB answer | | 2.61 | | 2.96 |
| `assess`, the largest answer it reads, 16 KB | | 8.26 | | 10.14 |
| `upgrade_propose` | | 1.66 | | 1.98 |
| `upgrade_cancel` | | | | 3.43 |
| `upgrade_apply`, 381 KB of code as raw input, with its deploy and `migrate` | | 26.40 | | 63.89 |

This is the whole method list. `bump` was cut by decision, from the crate as well as the contract: `reclaim` after `T_stuck` covers a stuck coin.

The request body `guard_prompt` returns is 1,179 bytes with no memo.

## Griefed queue, and what a relay attaches

The rows above are best case. Here a thief holding `K_s`, `K_u` and `K_p` has built the worst row the rules allow without more rotations: 32 known destinations of the longest script, 8 grants with 64-character account names, the 24 h fee window full at the rate floor, and the outflow window holding two days of spends at that floor, 62 entries, 4,957 bytes. Two days because a request's outflow counts for a day after its last signature request, and a paying request's retries close a day after its first execute. The answer that completes a request can still land after that close and move its entry once more, so the bound is two days and the signer's answer time; the builder fills the two days. The test reaches that size inside one sandbox day: a landing rotation clears the fee window and not the outflow window, so a second day's budget fits. The earlier build `4632075a…` kept one day of outflow, and its row was 4,213 bytes. The queue is the largest there is: the slot lets one self-spend through per `T_new`, and a self-spend stays pending for over an hour, so three of 16 inputs wait at once, each with the longest memo. `tests/tests/measure.rs: gas_of_owner_methods_on_the_worst_row_and_queue`, `gas_of_the_landing_and_the_cold_key_on_the_largest_dead_queue`, `gas_of_assess_on_a_dead_queue`. Figures are protocol 88, and this run read the same griefed figures on 86. The run before it, on `39f70262…`, read up to 0.24 Tgas higher on 86, `recover_begin` 14.20 and `apply_grant` 12.20, within the noise above.

| Method | Tx, griefed | Best case |
|---:|---:|---:|
| `cancel`, passkey, 48 inputs waiting | 7.77 | 4.24 |
| `cancel`, cold key | 6.63 | 2.94 |
| `cancel_all_and_rotate`, live queue | 4.93 | 3.86 |
| `cancel_all_and_rotate`, sweeping the dead queue | 13.61 | 3.86 |
| `recover_begin`, sweeping the dead queue | 13.96 | 4.10 |
| `freeze`, sweeping the dead queue | 12.33 | 2.60 |
| `apply_grant`, sweeping the dead queue | 11.96 | about 2.6 |
| `assess`, 16 KB answer, eight signers, sweeping two dead requests of 24 inputs | 17.03 | 10.14 |
| `on_signed`, 16 inputs on that row, against its fixed 10 | 7.27 own | 6.83 own |

**A relay attaches 30 Tgas to every `K_p` and `K_e` method, and to `apply_grant` and `recover_finish`**, `OWNER_ATTACH_TGAS` in `tools/lib/vault-client.mjs`: over twice the worst row. `apply_grant` and `recover_finish` belong to neither key, but either can be the first state change after a queue dies. There the test tries `apply_grant` from 10 Tgas up, one at a time: 10 fails with `Exceeded the prepaid gas` and 11 clears it, on both protocols. The 11.96 in the table is what the whole transaction burnt, which is a different figure from the attach. `recover_finish` was not run on a dead queue, and loads what `apply_grant` loads. The tests run every other row at exactly the attach and assert it clears. Unused gas comes back, and a function-call key has the whole attach held against its allowance until it does. A guard's key: 10 Tgas for `heartbeat`, and 20 Tgas clears the largest `assess`. Not measured: a row grown further by fee windows that a passkey's override let past the budget, about 4.6 KB more, or by more rotations. Each landing rotation lets another day's budget into the outflow window, so a thief holding `K_s`, `K_u` and `K_p` can grow it past two days, paying the vault's credit for every spend and waiting `T_known` per rotation. The rows of `4632075a…` were already open to this, since an entry there lived a day from its propose. Here the second day's 744 bytes moved each griefed row by 0.09 to 0.13 Tgas on 88, inside the 0.25 the same wasm moves between runs. These sizes are sandbox gas with the mock signer, and the relay's real gas is its own measurement.

`upgrade_apply` burns 63 Tgas in all for this size of code, so attach well above that. A call with too little fails in its first receipt and leaves the approval standing, tried at 15, 30 and 45 Tgas (`surface: upgrade_apply_with_too_little_gas_*`).

The `on_signed` figure grows with the request's own inputs, because the answer that completes a request reads their ledger entries, and every answer rebuilds the digests. At the 16-input maximum it leaves 3.2 of the 10 Tgas attach, and 2.7 on the worst row above. `execute` also computes the transaction's id and reads its child entries at first execute, about 0.2 Tgas here.

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

An empty vault costs at least 0.01257 NEAR of attached deposit. A first `heartbeat` adds 8 bytes. The row is 292 bytes larger than on the G1/G2 build: the snapshot's three fixed rings, the four times it and `status` read, and one flag. A request grew by its snapshot, with its memo on top. The reservation's extra 74 bytes before a vault's first completed cancel or spend are the public count's entry.

A pending request reserves everything its execute and answers can add: 92 bytes per input, 40 for the request, and 121 for each coin it pays back to the vault, which gets a ledger entry at first execute. These rows were measured on self-spends with no change, one coin paid back. `review2` runs a whole life with the credit at zero, and the only bytes it finds over the growth are the ones that were transient: an in-flight entry per input, the pending entry and the slot's holder, plus an override if nobody asked for one.

A `prune_signed` of a signed 2-input request gave back 631 bytes.

## History does not weigh on the callback

`review1_growth` runs real completed self-spends, one coin each, with the named fee override so no day-long clock jump is needed. Before each request had its own storage entry, the same run lost its signature at spend 141: `on_signed` passed its 10 Tgas attach and the retry failed the same way.

| Spends | Row bytes | `on_signed` |
|---:|---:|---:|
| 25 | 1,374 | 2.94 |
| 50 | 1,774 | 2.99 |
| 100 | 2,574 | 3.10 |
| 150 | 3,374 | 3.21 |

The row still grows 16 bytes per spend in this run, which is the 24 h fee window. Entries leave after a day, and `first_execute` sweeps them, so this is bounded by spends per day. Without a passkey override the fee budget limits that to about 26 a day on the test-coin values. With an override, the slot limits a change-bearing or self-spend to one per `T_new`. This run's clock covered less than a day, so the shrink was not observed on the wasm. `crates/undo-core/props: the_fee_window_leaves_the_row_after_a_day` covers it in the core.

Credit per spend in that run, one input each: 0.00739 NEAR before pruning and 0.00274 NEAR after. What stays is the ledger entry with its pin, which the fee rules need forever, and the entry for the coin it paid back to the vault, which the chain wait needs.

Pins in their own entries do not move the other methods either, on a vault with 40 pins:

| Pins | Row bytes | `on_signed`, 8 inputs | `propose_btc`, 1 input | `cancel`, passkey |
|---:|---:|---:|---:|---:|
| 8 | 998 | 4.85 | | |
| 40 | 1,158 | 4.72 | 3.05 | 4.14 |

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

## Live on the testnet signer (2026-10-31 UTC)

This section and the next ran on the G1/G2 build, `4eafca45…`. The contract has changed since, and nothing below has been repeated on it. `tools/g1.mjs --live` against `v1.signer-prod.testnet` 3.18.0 on protocol 88. Proof: `proofs/g1.json`. Coins were made up: `execute` does not read Bitcoin, so nothing here moved a coin. `K_p` was a software authenticator.

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

## Live on Mutinynet (2026-10-31 UTC)

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
