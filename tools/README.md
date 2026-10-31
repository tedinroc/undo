# Undo tools

Node, no install step. The only dependency is `@noble/curves` and `@noble/hashes`, vendored in `vendor/noble` with their npm integrity hashes.

| Tool | What it does | Network |
|---|---|---|
| `escape.mjs` | The Bitcoin escape from a recovery file and a UTXO list | None |
| `freeze.mjs` | Signs one cold-key intent to a file: `freeze`, `unfreeze`, `veto_grant`, `cancel` | None |
| `sign-intent.mjs` | Signs `propose_btc` or `reclaim` from a seed file and prints the arguments | None |
| `human-key.mjs` | Makes the dispenser and funding keys, for `scripts/human/02` and `03` | None |
| `g1.mjs` | Gate G1 driver. Plan only unless `--live`. Refuses mainnet | NEAR RPC |

`K_p` here is a software authenticator, and every result that rests on it says so. A real phone is gate G3.

All four intents from `freeze.mjs` run against the real wasm in `test/sandbox-intents.mjs`, and their digests also go through an independent encoder in `rust-check/`. The mock signer stands in for MPC there. `recover_begin` and `recover_cancel` have encoders in `lib/intent.mjs` and sandbox tests in `tests/tests/review1.rs`, but no command-line tool yet.

`tools/test/run-all.sh` runs every check. `rust-check/` recomputes each result with other code, and `test/mutants.mjs` breaks the tools line by line to show the tests notice.
