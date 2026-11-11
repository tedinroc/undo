# Undo for Bitcoin: agent CLI

`undo` is the agent's side of an Undo for Bitcoin vault. An agent can propose a Bitcoin spend and read its state. The public NEAR contract makes every proposal wait, and the owner's phone can cancel it during the wait. The agent has no command that cancels, rotates or shortens anything. If it tried, the keys it holds could not authorise the call.

Test coins only. The CLI refuses NEAR mainnet and any contract that is not a test-coin instance.

```
undo propose --to <tb1 address> --amount <sats|all> [--memo TEXT]
undo check   --to <tb1 address> --amount <sats|all> [--memo TEXT]
undo status  [--request N]
undo keys    [--new]
undo init    --near-network testnet --contract ID --vault HEX --account ID --seed-file FILE
```

Each command reads `--file FILE`, or `$UNDO_AGENT_FILE`, or `./undo-agent.json`, and takes `--json` for machine output. Node 20 or later, no install step: it uses `tools/lib` and the noble copy vendored there. For a short name, `alias undo='node agent/undo.mjs'`.

| Command | What it does | Sends a transaction |
|---|---|---|
| `propose` | Picks free coins at the vault's address, asks `check_propose`, signs with `K_s` and `K_u`, and sends `propose_btc` from the agent's function-call key. Prints the request id, the tier, the wait the contract set, and `unlocks in M:SS` from the contract's unlock and the NEAR block time | Yes, one |
| `check` | The same plan, then the contract's free `check_propose` view: tier, wait, fee, or the contract's refusal in its own words | No |
| `status` | The contract's own `status` lines for the vault, each pending request and its countdown, and whether the vault's spend key is still this agent's | No |
| `keys` | Prints how the owner adds the agent's NEAR key, scoped to this contract and two methods, and reads back what is on chain | No |
| `init` | Writes the agent file from a seed file, after checking that the seed holds the vault's spend key | No |

Exit codes: 0 done, 1 refused (by the contract, by NEAR, or by a rule here), 2 bad usage or agent file, 3 a network read failed and nothing was sent. A refusal is printed verbatim, for example `refused by the contract: Smart contract panicked: SpendKeySuspended`.

## Give an agent a spend key

An agent vault is an ordinary vault whose spend seed sits with the agent. The seed gives two keys: `K_s`, which signs the NEAR intent, and `K_u`, which signs the user half of the Bitcoin spend. The agent gets nothing else.

| The agent holds | The agent never holds |
|---|---|
| The spend seed, so `K_s` and `K_u` | The passkey `K_p`, which stays on the owner's phone |
| One NEAR function-call key for `propose_btc` and `execute` on the Undo contract | The cold key `K_e` and the recovery file |
| | Any full-access NEAR key |

1. **Make the agent file.** Put the vault's spend seed in a file, one line of hex, mode 600. Then:

   ```
   undo init --near-network testnet --contract <undo contract> --vault <vault id> \
     --account <agent account> --seed-file <seed file>
   ```

   It reads the vault on chain and refuses a seed that does not give the vault's `K_s`. It writes `undo-agent.json` with mode 600 and makes a new NEAR key on this machine. The file holds the seed, that key and the names, and nothing else.

2. **Have the owner add the key.** `undo keys` prints the key and the near-cli-rs 0.30 command that adds it, for example:

   ```
   near account add-key <agent account> grant-function-call-access --allowance '0.25 NEAR' \
     --contract-account-id <undo contract> --function-names propose_btc,execute \
     use-manually-provided-public-key ed25519:<public key> network-config testnet sign-with-legacy-keychain send
   ```

   The owner runs it with the agent account's full-access key, which never goes to the agent. The allowance pays gas only. `propose_btc` charges the vault's prepaid storage credit, because a function-call key cannot attach a deposit. If the allowance runs out, the agent can no longer send, and the owner's cancel never used this key. Run `undo keys` again to read the key back from chain.

3. **Spend.** `undo check` is free. `undo propose` sends one transaction. Both read the same coins: confirmed coins at the vault's address from Mutinynet's Esplora, each one the contract reports `Free`.

4. **What the contract does with it.** It sets the wait from the tier, and nothing the agent signs can change it. The test-coin preset (`crates/undo-core/src/policy.rs`) sets 60 s back to the vault itself, 5:00 to a destination the owner has not approved while the guard is online, and 10:00 while the guard is offline. A destination becomes known only by the owner's passkey. During the wait the owner's phone can cancel the one request, or rotate the spend key, which kills every pending request at once. After a rotation the contract refuses this agent's proposals: `SpendKeySuspended` until the new key lands, then `bad K_s signature`.

**Why the agent cannot cancel, rotate or shorten.** There are two separate walls. NEAR refuses the agent's key for any method but `propose_btc` and `execute`, before the contract runs: `cancel` comes back as `MethodNameMismatch`. Behind that, every method that cancels, rotates, adds a destination, clears a hold or changes the policy needs the owner's passkey or cold key, and the contract checks that signature itself. `propose_btc` takes no delay argument. The sandbox test and the testnet run below send each of these from a full-access account with what an agent could sign, and the contract refuses them all: `webauthn: bad signature`, `bad K_e signature`.

**What the CLI refuses before signing.**
- An agent file with any field it does not know. A field that looks like owner material, such as `cold_key` or `passkey`, is named in the refusal.
- An agent file that other users on the machine can read.
- A full-access NEAR key, a function-call key for another contract, or one with an empty method list, which NEAR reads as every method.
- NEAR mainnet, an RPC or Esplora host off the testnet allow list, and any contract that is not a test-coin instance.

**What is public.** A proposal puts its amount and destination in the contract's public queue, before any Bitcoin moves. Anyone, a thief included, can read it. Vault ids are hashes, not names. `undo propose` and `undo status` both say this.

**Who looks.** Undo works only if someone looks during the wait. If the agent's seed leaks and nobody cancels, the thief's proposal goes through after the wait, the same as the agent's own.

## What has run

| Check | Network | Label |
|---|---|---|
| `node --test agent/test/offline.test.mjs`: the agent file's rules, coin choice, the printed words, and the near-cli command checked against near-cli-rs 0.30.1's `--help` with the network denied | none | `[static]` |
| `agent/test/run-sandbox.sh`: the whole flow above on the built wasm and a local NEAR node, protocols 86 and 88. Init, keys, check, propose, status, the agent's key refused by NEAR and by the contract, a passkey cancel, a rotation, and proposals refused after it | NEAR sandbox | `[mock-signer]` |
| `agent/test/testnet-c14.mjs --live`: the same flow once on the live contract `v1.s.undo-btc.testnet`, through its relay, with one Mutinynet test coin, 2026-11-11. Its record is `proofs/c14-agent.json`, and `./verify.sh A` fetches its twelve transactions again | NEAR testnet, Mutinynet | `[live-testnet]` `[live-mutinynet]` |

In the sandbox the mock signer stands in for MPC, the coins are made up and served by a local Esplora stand-in, and the passkey is a software authenticator.

**On NEAR testnet.** One run, with real transactions; [CLAIMS.md](../CLAIMS.md) C14 has every hash.

| Step | What the chain shows |
|---|---|
| The owner adds the agent's key | NEAR testnet tx `Ftv9m76YCKwm1AfyxNrJAx78sv66qcrS9sHP6GVjvPNN`: a function-call key on `agent1.s.undo-btc.testnet` for `v1.s.undo-btc.testnet`, methods `propose_btc` and `execute`, allowance 0.25 NEAR |
| `undo propose` | Tx `9dVdMDnhjk6ufuiQR6NPmKMdSNtHQo7FqRPVB1jGTTua`, signed by that key: request 0, tier New, unlock 5:00 later |
| The agent's key signs `cancel`, `cancel_all_and_rotate`, `set_policy`, `clear_hold`, `add_destination` | No transaction: the RPC refuses each before it is broadcast, for example `{"InvalidAccessKeyError":{"MethodNameMismatch":{"method_name":"cancel"}}}`. The key's nonce and allowance read the same before and after |
| The same key attaches 1 yoctoNEAR, or calls another account | No transaction: `{"InvalidAccessKeyError":"DepositWithFunctionCall"}`, and `ReceiverMismatch` |
| A full-access account sends what the agent can sign for those methods | Six transactions that landed and failed in the contract, for example tx `BXsQJVSMCjnMtj6HvKHHFe3xt5zci4ANzMDDe7MA625A` (`webauthn: bad signature`) and tx `2opkAh3PjHA57sTEuPGoSa8dET3FXmrxXdvj5ELhjQws` (`bad K_e signature`). The request, its unlock, the policy and the spend key read unchanged |
| The owner's passkey cancels through the relay | Tx `9719jZ7UB1MrVBj9djosokrwqJHQUHqNgCDzXLBjyJpt`, log `undo:cancelled request=0`, more than 4 minutes before the unlock |
| The owner's passkey rotates the spend key | Tx `8kECrgxaJiwZhosUMvLfgAjiJbicyyfEzzFPuAfHQwsK`. The agent's next `propose_btc` fails with `SpendKeySuspended` (tx `29Na2rXYyWTpEESerUSUzjb4V26zmNcf6CCS8f95ty9m`), and with `bad K_s signature` once the new key has landed (tx `Hpj7W2d13qsr8ibqccTLkYoW96N1mU4ebjxGDLkQXrMD`) |

What that run did not do. The owner's passkey was a software authenticator in the driver's process, not a phone: with a phone's passkey this has **not yet run**. The owner's step used `tools/lib/near.mjs` to add the same key, contract, methods and allowance that the printed near-cli command names; that near-cli command itself has **not yet run** on testnet, and is checked only against near-cli-rs 0.30.1's `--help`. No request was executed, so the signer was not asked for a Bitcoin signature, and the test coin stayed where it was. `undo propose` there printed:

```
Undo for Bitcoin  ·  agent spend key  ·  NEAR testnet  ·  Mutinynet signet test coins
proposed   1,000 sats to tb1qnw5z5t6wssq80k8hmsfj6zjdh4u00x00ccmqpn
request    #0
tier       New: a destination the owner has not approved
wait       5:00, set by the contract
unlocks in 5:00
The owner's phone can cancel it until then. This key cannot.
NEAR testnet tx 9dVdMDnhjk6ufuiQR6NPmKMdSNtHQo7FqRPVB1jGTTua
Public now: the amount and destination, in the contract's queue.
```

On a sandbox the labels read `NEAR sandbox` and `made-up coins, mock signer`.

**If a command hangs on macOS.** With `NODE_USE_SYSTEM_CA=1` set, Node can hang on its first HTTPS call while it reads the keychain. The testnet hosts use public certificates, so `env -u NODE_USE_SYSTEM_CA node agent/undo.mjs status` works around it.
