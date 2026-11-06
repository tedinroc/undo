# Undo tools

Node, no install step. The only dependency is `@noble/curves` and `@noble/hashes`, vendored in `vendor/noble` with their npm integrity hashes.

| Tool | What it does | Network |
|---|---|---|
| `escape.mjs` | The Bitcoin escape from a recovery file and a UTXO list | None |
| `freeze.mjs` | Signs one cold-key intent to a file: `freeze`, `unfreeze`, `veto_grant`, `cancel`. With no `--minutes` a freeze lands at the whole CSV period, however wrong this clock or late the relay | None |
| `sign-intent.mjs` | Signs `propose_btc` or `reclaim` from a seed file and prints the arguments | None |
| `human-key.mjs` | Makes the dispenser and funding keys, for `scripts/human/02` and `03` | None |
| `g1.mjs` | Gate G1 driver. Plan only unless `--live`. Refuses mainnet | NEAR RPC |
| `g2.mjs` | Gate G2 driver: real coins, the co-signed spend and the escape. Plan only unless `--live`, rehearses with `--regtest`, resumes after any stop. Refuses mainnet and any endpoint off its allow lists | NEAR RPC, Esplora |

`K_p` here is a software authenticator, and every result that rests on it says so. A real phone is gate G3.

`new` now takes `operator_passkey`. `g1.mjs` and the rehearsal deploy with `throwawayOperatorPasskey`, whose secret is dropped at once, so nobody can cancel an upgrade on those instances, and no upgrade is ever proposed there. A real instance takes the operator's real passkey. `g1.mjs` refuses to overwrite other code, so a redeploy needs a fresh `--contract`.

`propose_btc` now has a `memo`, which `K_s` signs. `signSpend.propose` takes it and sends null by default. `lib/intent.mjs` also has the encoders for `add_destination`, `remove_destination`, `set_policy`, `set_guard` and `clear_hold`, run against the real wasm in `test/sandbox-intents.mjs`. There is no command-line tool for those yet, because the phone page signs them.

A relay names itself as `guard` in the creation intent and calls `heartbeat`, in the `create_vault` transaction or right after, or the vault reads the unguarded 10:00 and not 5:00. `create_vault` attaches a deposit, which a function-call key cannot, so that one call needs a full-access key on the relay account. `heartbeat` works from a function-call key. A relay attaches `OWNER_ATTACH_TGAS` from `lib/vault-client.mjs` to `K_p` and `K_e` methods, sized in `docs/measurements.md`.

The contract's code changed, so `g1.mjs` refuses `g1.s.undo-btc.testnet` ("holds other code"). A redeploy takes a fresh `--contract`. `g2.mjs` then also takes `--new-run`, which moves the earlier run's state aside, or it refuses the state file as "for another contract". It writes `proofs/g2.json` again, so keep the earlier proof if the new run should not replace it.

`escape.mjs` prints that an escape must out-pay every held link in absolute fee, summed over any stacked mempool chain, and asks for `--allow-high-fee` only above both 5% of the coins and 5,000 sats.

All four intents from `freeze.mjs` run against the real wasm in `test/sandbox-intents.mjs`, and their digests also go through an independent encoder in `rust-check/`. The mock signer stands in for MPC there. `recover_begin` and `recover_cancel` have encoders in `lib/intent.mjs` and sandbox tests in `tests/tests/review1.rs`, but no command-line tool yet.

`g2.mjs` keeps its recovery file, vault keys and state file under the gitignored `private/g2`. The state file holds no secret. It never writes over a cold key: with no state file naming it, it stops, and `--return-coins` then `--new-run` get past that. `--return-coins` works from the recovery files alone, needs no NEAR RPC, wasm or key file, and takes in every run `--new-run` moved aside.

A young coin's refusal says nothing about the witness, so `g2.mjs` also sends two transactions a sound script must refuse, and they pay nothing when refused: the co-signed spend without K_u's signature, and an escape signed for nSequence csv-1 on the mature coin. Only a script refusal of the correctly built spend is G2's kill line. Relay noise is resumable.

A finished proof says `pass` for the chain's part and `gate_complete: false` until a browser has tried the POST. The run writes the steps to `private/g2/browser-step.txt`, and `g2.mjs --record-browser FILE` adds the result to the proof. `test/check-g2-proof.mjs` refuses a proof whose label is not a live run or whose verdict goes past its contents, and `scripts/outward-check.sh` runs it.

`test/g2-rehearsal.mjs` runs `g2.mjs` on real bitcoind with standard relay policy, the real wasm on a local NEAR node and a mock signer, and breaks one thing at a time. Rehearsal results are labelled and can never land in `proofs/`.

`tools/test/run-all.sh` runs every check. `rust-check/` recomputes each result with other code, and `test/mutants.mjs` breaks the tools line by line to show the tests notice.
