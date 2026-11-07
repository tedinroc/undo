# Undo for Bitcoin

A cancel button for Bitcoin: if your spend key is stolen, Bitcoin refuses that key alone, a public NEAR contract makes the thief wait in public, and your phone can cancel during the wait; NEAR alone cannot take the coins, and if NEAR goes away your cold key gets them out after a Bitcoin timelock.

## Try it

| Do | See |
|---|---|
| Open https://undo-btc.pages.dev | Today it shows "Coming soon". The self-test page goes up with the testnet deploy. |
| `./verify.sh` (no key, no wallet; Node 20+, Rust) | One line per check: `PASS`, `SKIP` or `FAIL`, a claim number from [CLAIMS.md](CLAIMS.md), and a label for where it ran. Tier A fetches the real transactions in `proofs/` again (every NEAR testnet call that got a signer's answer, the two G1 activations, and the Mutinynet co-signed spend and escape) and re-verifies their signatures here; tier B runs the state machine and the Bitcoin consensus tests offline. Until the deploy, the deployed-contract lines say `SKIP`, because `deploy/testnet.json` is a placeholder. |
| `agent/test/run-sandbox.sh 86 88` (a local NEAR sandbox node, see Build below) | The agent CLI ([agent/README.md](agent/README.md)) proposing with a NEAR function-call key, then NEAR refusing that key for `cancel`, `cancel_all_and_rotate`, `set_policy`, `clear_hold` and `add_destination` in its own words (`MethodNameMismatch`), and the contract refusing what the agent can sign for them. Ends `AGENT SANDBOX OK: 86 88 [mock-signer]`. |
| `./demo.sh` (no browser, no key; Node 20+, Rust) | Today: `SKIP (not deployed)`. After the deploy: a throwaway vault with a software passkey, a proposal to a new address, a passkey cancel, and a send to a known address that the signer signs after its wait, through the relay, printing `PASS demo-1` to `demo-5`. If the relay is down it prints `SKIP (relay)` and points to `./verify.sh A` and `B`. |

## Who can do what

| Party | Alone it can | Alone it cannot | If it is gone |
|---|---|---|---|
| Owner's phone (passkey, P-256, checked by the contract) | Cancel any pending spend at once. Cancel every one and swap the spend key. Tighten the rules at once; loosening them waits, and the cold key can veto it | Move a coin: it holds no Bitcoin key | Spending still works, only cancel is gone. The cold key starts passkey recovery |
| Spend key (one seed: a NEAR-side signing key and the Bitcoin key `K_u`) | Propose a spend. Every proposal waits in public: on this test vault 60 s to a known address and 5 min to a new one (10 min while the guard is offline), set per vault | Move a coin: Bitcoin also needs the signature the contract controls. Cancel, shorten a wait, change the rules | Coins leave through the cold key after the timelock |
| Agent key (an agent holding a vault's spend key, plus a NEAR function-call key for gas) | What the spend key can: propose, and pay for `execute` | Cancel, swap keys, shorten a wait, attach a deposit | Nothing locks: the phone path needs no agent |
| NEAR contract (public, on NEAR testnet) | Keep the rules and the clock. After the wait, ask Chain Signatures for Bitcoin's second signature. Refuse or stall | Spend: Bitcoin also needs the spend key's signature | The cold key gets the coins out after the timelock |
| Chain Signatures network (NEAR's MPC signers) | Sign what the contract asks. Refuse or stall. Colluding with a thief who has the spend key, skip the wait | Spend: Bitcoin also needs the spend key's signature | The cold key gets the coins out after the timelock |
| Cold key (offline recovery file) | Move any coin older than the timelock (6 blocks on this test vault) with no NEAR at all. Freeze the vault, cancel, start passkey recovery, veto a passkey change | Propose. Move a coin younger than the timelock | Nothing breaks now. Move the coins to a new vault. If it is stolen, aged coins are lost: keep it offline |
| Operator (deploys the contract, runs the relay and the page) | Propose new contract code, which waits in public longer than any withdrawal (1 h on this test instance). Withhold or delay relayed calls. A changed page could lie, or take a spend key it holds in your browser | Change code sooner, spend, or forge your cancel | The contract keeps running; any NEAR account can send the same calls |

**Why not 2-of-3?** If one key is stolen and nobody is watching, 2-of-3 is safer: that thief gets nothing, and Undo's thief gets the coins after the wait. Undo makes a different trade. Spending needs no second device or hardware, so people use it every day; a public contract holds the second signature, not a company; a phone can cancel during the wait; a cold key leaves alone if NEAR is gone. If you can keep two keys in reach for every spend, use 2-of-3.

**Privacy.** The queue is public: anyone can read each vault's pending amounts and destinations, its cancels and their timing, before Bitcoin moves. Vault ids are hashes, not names. This version claims no privacy.

**Test networks only.** NEAR testnet and Mutinynet test coins, addresses starting `tb1`. Nothing here runs on NEAR mainnet or holds real bitcoin. The code is unaudited.

**Labels** on every `verify.sh` and `demo.sh` line: `[live-testnet]` NEAR testnet, `[live-mutinynet]` Mutinynet (a Bitcoin signet), `[replay]` a real hash fetched again, `[consensus-lib]` libbitcoinconsensus, `[unit]` pure Rust with no chain, `[static]` a read of the source, `[mock-signer]` a local NEAR node with a mock signer. `INFO` lines are totals, or a record read from `proofs/` and not checked again. The terms (`K_u`, `K_m`, `K_e`, CSV, G1, G2) are explained at the end of [CLAIMS.md](CLAIMS.md).

## What was built in the window

This repository started on 2026-10-31, inside the hackathon window (from 2026-10-19), and all code in it was written in the window, except the vendored libraries listed under More (`tools/vendor/noble`). Labels say how far each part has run; [CLAIMS.md](CLAIMS.md) has the commands, dates and hashes.

| Part | What | Ran |
|---|---|---|
| `crates/undo-core` | The vault state machine: waits, cancel, rotation, fee budget, recovery, upgrades | `[unit]` with property tests |
| `crates/undo-btc` | The two-branch Bitcoin script, BIP-143 signing, the recovery file and its dry-run escape | `[consensus-lib]`, `[regtest]` |
| `contracts/undo` | The NEAR contract | `[mock-signer]`. An earlier build ran on NEAR testnet with the real signer and Mutinynet coins: `[live-testnet]`, `[live-mutinynet]`, in `proofs/` |
| `tools/` | Gate drivers, the offline escape and freeze tools, the referee in `tools/rust-check`, the phone-alert watcher `tools/watch.mjs` | `[regtest]`, `[live-testnet]`, `[live-mutinynet]`; the watcher `[mock-signer]`, and a read-only dry run on NEAR testnet |
| `agent/` | The agent CLI: `undo propose`, `check`, `status`, `keys`, with a function-call key that cannot cancel | `[mock-signer]` |
| `site/` | The pages and the relay | `[mock-signer]` on a local stage |
| `verify.sh`, `demo.sh`, `CLAIMS.md` | This judge's path | `demo.sh` on a local stage `[mock-signer]`; on testnet after the deploy |

Git tag `hackathon-submission` marks the judged commit once it exists.

## More

- Status with no server: the contract's `status` view over public RPC, in plain language. `<CONTRACT>` is `contract` in `deploy/testnet.json` once deployed. If the RPC refuses, the line prints its error instead:
  ```
  curl -s https://test.rpc.fastnear.com -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":"u","method":"query","params":{"request_type":"call_function","finality":"final","account_id":"<CONTRACT>","method_name":"status","args_base64":"e30="}}' | python3 -c 'import sys,json;r=json.load(sys.stdin);x=r.get("result") or {};print(bytes(x["result"]).decode() if "result" in x else "RPC refused: "+json.dumps(r.get("error") or x.get("error")))'
  ```
- Build: `scripts/build.sh`. It needs Rust with the `wasm32-unknown-unknown` target (`rustup target add wasm32-unknown-unknown`) and binaryen's `wasm-opt`. The hashes in CLAIMS.md came from rustc 1.98.1 and `wasm-opt` version 133; other versions may give other bytes, and the script prints whether its output is the wasm `deploy/testnet.json` records. A plain `cargo build --target wasm32-unknown-unknown` stops on purpose, because it would lose `--cfg near` and the path remapping. Sandbox suite: `scripts/protocol-check.sh`, after a build. It needs `NEAR_SANDBOX_BIN_PATH`, the near-sandbox binary, release 2.14.0 here (protocol 88); a macOS build of it may also need `UNDO_LIBLZMA_DIR`, a folder holding `liblzma.5.dylib`. `scripts/setup-repo.sh` is for the author's clone only. `tests/REGRESSION-MAP.md` maps each attack-review finding to its test; `docs/measurements.md` has gas and size.
- Phone alerts: `tools/watch.mjs` watches one vault over public RPC and pushes one ntfy alert for each new request, however it was proposed. [docs/watch.md](docs/watch.md) says what ntfy.sh and the phone's push service can see. Run on a local sandbox `[mock-signer]`; on a phone: **not yet run**.
- Baseline: the delay-and-cancel idea follows the author's earlier project Eleven Seconds (github.com/tedinroc/eleven-seconds, MIT), an upgrade cooling period in Solidity: design only, no code copied.
- Libraries: near-sdk, rust-bitcoin with libbitcoinconsensus (tests and tools), k256, p256, sha2, sha3, borsh, hex, bs58, proptest, near-workspaces (sandbox tests), and in Node `@noble/curves` 1.9.7 and `@noble/hashes` 1.8.0, vendored in `tools/vendor/noble`.

## Credits and license

Built by Ted Chen with AI coding assistance (Claude). MIT, see [LICENSE](LICENSE).
