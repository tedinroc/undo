# Undo tools

Node, no install step. The only dependency is `@noble/curves` and `@noble/hashes`, vendored in `vendor/noble` with their npm integrity hashes.

| Tool | What it does | Network |
|---|---|---|
| `escape.mjs` | The Bitcoin escape from a recovery file and a UTXO list | None |
| `freeze.mjs` | Signs one cold-key intent to a file: `freeze`, `unfreeze`, `veto_grant`, `cancel`. With no `--minutes` a freeze lands at the whole CSV period, however wrong this clock or late the relay | None |
| `cancel.mjs` | Sends one signed cancel from your own NEAR testnet account, with no relay: the file the phone page saves when its relay will not send a cancel, or a `freeze.mjs --method cancel` file. Only `cancel` and `cancel_all_and_rotate`, in the shape the contract takes. Reads the vault first, refuses mainnet, a used nonce, a request already gone and an expired call, and asks before it sends | NEAR RPC |
| `sign-intent.mjs` | Signs `propose_btc` or `reclaim` from a seed file and prints the arguments | None |
| `human-key.mjs` | Makes the dispenser and funding keys, for `scripts/human/02` and `03` | None |
| `watch.mjs` | Phone alerts: reads one vault's queue and pushes one ntfy alert per new Pending request, however it was proposed. Holds no key. Refuses mainnet. See `docs/watch.md` | NEAR RPC, ntfy |
| `verify/tier-a.mjs`, `verify/tier-b.sh` | What `./verify.sh A` and `B` run. A: the contract `deploy/testnet.json` names, and the real hashes in `proofs/` fetched again and re-verified. B: the state machine and the Bitcoin consensus tests, offline. `verify/rust.mjs` builds the Rust referees both use | NEAR RPC, archival RPC, Esplora (A); none (B) |
| `demo/demo.mjs` | What `./demo.sh` runs: a throwaway vault through the relay `deploy/testnet.json` names, with the page's own code from `site/lib`, then a proposal, a passkey cancel and a signed send. SKIP without `site/lib` or a deploy | The relay, NEAR RPC |
| `g1.mjs` | Gate G1 driver. Plan only unless `--live`. Refuses mainnet | NEAR RPC |
| `g2.mjs` | Gate G2 driver: real coins, the co-signed spend and the escape. Plan only unless `--live`, rehearses with `--regtest`, resumes after any stop. Refuses mainnet and any endpoint off its allow lists | NEAR RPC, Esplora |
| `s2-refusal.mjs` | The spend key alone, against a real node: funds a coin in a finished G2 run's vault, POSTs K_u's signature with nothing for K_m once, keeps the node's words, re-reads the coin, sends it back by the escape. Plan only unless `--live`. No NEAR write | NEAR RPC, Esplora |
| `replay-run.mjs` | Builds `site/pages/replay/run.json`, the replay page's only data, from `proofs/g2.json` and `proofs/s2-refusal.json`; `--check` exits 1 if the file is not what the proofs make. `site/test/landing.test.mjs` rebuilds it and compares | None |

`K_p` here is a software authenticator, and every result that rests on it says so. A real phone is gate G3.

`new` now takes `operator_passkey`. `g1.mjs` and the rehearsal deploy with `throwawayOperatorPasskey`, whose secret is dropped at once, so nobody can cancel an upgrade on those instances, and no upgrade is ever proposed there. A real instance takes the operator's real passkey. `g1.mjs` refuses to overwrite other code, so a redeploy needs a fresh `--contract`.

`propose_btc` now has a `memo`, which `K_s` signs. `signSpend.propose` takes it and sends null by default. `lib/intent.mjs` also has the encoders for `add_destination`, `remove_destination`, `set_policy`, `set_guard` and `clear_hold`, run against the real wasm in `test/sandbox-intents.mjs`. There is no command-line tool for those yet, because the phone page signs them.

A relay names itself as `guard` in the creation intent and calls `heartbeat`, in the `create_vault` transaction or right after, or the vault reads the unguarded 10:00 and not 5:00. A vault gets that beat at creation. After that `POST /api/relay` takes `heartbeat` only with the `x-undo-beat` header matching the `BEAT_TOKEN` binding, for a precheck before a take. With no binding set it is off the list: a stranger, or a thief, must not be able to make a vault read guard online, because that halves its wait. `create_vault` attaches a deposit, which a function-call key cannot, so that one call needs a full-access key on the relay account. `heartbeat` works from a function-call key. A relay attaches `OWNER_ATTACH_TGAS` from `lib/vault-client.mjs` to `K_p` and `K_e` methods, sized in `docs/measurements.md`.

The contract's code changed, so `g1.mjs` refuses `g1.s.undo-btc.testnet` ("holds other code"). A redeploy takes a fresh `--contract`. `g2.mjs` then also takes `--new-run`, which moves the earlier run's state aside, or it refuses the state file as "for another contract". It writes `proofs/g2.json` again, so keep the earlier proof if the new run should not replace it.

`escape.mjs` prints that an escape must out-pay every held link in absolute fee, summed over any stacked mempool chain, and asks for `--allow-high-fee` only above both 5% of the coins and 5,000 sats.

All four intents from `freeze.mjs` run against the real wasm in `test/sandbox-intents.mjs`, and their digests also go through an independent encoder in `rust-check/`. The mock signer stands in for MPC there. `recover_begin` and `recover_cancel` have encoders in `lib/intent.mjs` and sandbox tests in `tests/tests/review1.rs`, but no command-line tool yet.

`g2.mjs` keeps its recovery file, vault keys and state file under the gitignored `private/g2`. The state file holds no secret. It never writes over a cold key: with no state file naming it, it stops, and `--return-coins` then `--new-run` get past that. `--return-coins` works from the recovery files alone, needs no NEAR RPC, wasm or key file, and takes in every run `--new-run` moved aside.

A young coin's refusal says nothing about the witness, so `g2.mjs` also sends two transactions a sound script must refuse, and they pay nothing when refused: the co-signed spend without K_u's signature, and an escape signed for nSequence csv-1 on the mature coin. Only a script refusal of the correctly built spend is G2's kill line. Relay noise is resumable.

A finished proof says `pass` for the chain's part and `gate_complete: false` until a browser has tried the POST. The run writes the steps to `private/g2/browser-step.txt`, and `g2.mjs --record-browser FILE` adds the result to the proof. `test/check-g2-proof.mjs` refuses a proof whose label is not a live run or whose verdict goes past its contents, and `scripts/outward-check.sh` runs it.

`test/g2-rehearsal.mjs` runs `g2.mjs` on real bitcoind with standard relay policy, the real wasm on a local NEAR node and a mock signer, and breaks one thing at a time. Rehearsal results are labelled and can never land in `proofs/`.

`tools/test/run-all.sh` runs the tests in `tools/test` and `agent/test` that need no browser and build no Pages output; `site/test`, `scripts/go-live/test`, the film run and the two Pages checks below run on their own. `rust-check/` recomputes each result with other code, and `test/mutants.mjs` breaks the tools line by line to show the tests notice.

## The film, on a local chain

`tools/test/film-e2e.mjs` runs the film's sequence from the top with one command: one headless Chrome with two windows, the thief tab at 1080x1350 and the phone page at 390x844 with a CDP virtual authenticator, through the Pages Functions and `undo-cron` in real workerd, the real wasm on a local NEAR node, a mock signer, and bitcoind on regtest under standard relay policy. It reads every result from the screens and checks it against the contract and bitcoind. Everything is thrown away when it stops. It cannot reach a live host.

```
export NEAR_SANDBOX_BIN_PATH=<near-sandbox binary>
export UNDO_WASM_DIR=<folder with undo_vault.wasm and mock_signer.wasm>
export UNDO_BITCOIN_BIN=<folder with bitcoind>
export UNDO_WRANGLER_MODULES=<node_modules holding wrangler 3>
export UNDO_LIBLZMA_DIR=<liblzma folder, where the sandbox binary needs one>
node tools/test/film-e2e.mjs [--real-wait] [--shots DIR] [--report FILE] [--only 1,2,3]
```

- **Run 1.** The phone makes a vault through the relay and gets a coin. Send: refused, word for word. Proposal, one clock on both pages, phone cancels, both freeze, `CANCELLED` on both, coin unspent. The thief's key can't propose again, on a page or without one.
- **Run 2.** No cancel: the tab calls `execute` at zero, the contract signs, the spend is mined.
- **Run 3.** The general key is at its ceiling and being refused in a burst: the cancel still goes out on the owner key.

It prints one `PASS` or `FAIL` per check and exits 0 only if none failed. Allow about 2 minutes, or 7 with `--real-wait`. At most one at a time: it starts one Chrome, one NEAR node, one bitcoind and one workerd, and stops them on exit and on SIGINT or SIGTERM.

`T_new` on the test instance is 5:00, and the page makes every vault on the instance's deployed policy. The `TestCoin` preset lets a vault choose a shorter wait at creation, down to 1:00, but the film's is the deployed one. So the script moves the contract's clock with the sandbox's fast-forward to 40 s left, waits for both pages to read the jump, and the rest runs in real seconds. `--real-wait` makes run 2 count the whole 5:00.

What it says nothing about: MPC, a real phone or Face ID, public RPC, Mutinynet, Cloudflare's limits, a camera. Its labels are `[mock-signer]` and `[virtual authenticator]`.

Two more, which stop short of a deploy:

- `tools/test/pages-output-check.sh OUT_DIR` builds the Pages output and the Functions bundle the way `site/deploy.sh` does, then reads them for a local path, a key, a source map, an off-list handle and a host the config does not name.
- `node tools/test/pages-dev-check.mjs` serves the testnet output under `wrangler pages dev` with no secrets and every public host blocked in Chrome, for the folder redirects, `_headers`, the live chip and CSP, and what the pages say with the relay off.
