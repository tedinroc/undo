#!/usr/bin/env node
// G1 driver: does a real signature from the MPC network reach this contract's on_signed?
//
//   node tools/g1.mjs --network testnet                plan only: reads the chain, writes nothing
//   node tools/g1.mjs --network testnet --live         the first live write of the project
//   node tools/g1.mjs --network sandbox --rpc URL --root-key FILE --mock-wasm FILE
//
// Coins are made up: execute does not read Bitcoin, so G1 needs no test coins. Vault keys live in
// memory for one run. Proof goes to proofs/g1.json on testnet. It holds hashes and public keys only.
//
// Never runs on mainnet, whatever the flags say. Before any write on testnet it runs
// scripts/outward-check.sh on the exact wasm, and stops on any hit.
//
// Read request state, not transaction status: status says success even when a callback ran out of
// gas. And never block on a transaction waiting on the signer: `execute` returns at inclusion.
//
// Exit 0: every G1 line passed. 1: at least one failed. 2: bad usage. 3: refused before any write.
// 4: plan only, something is missing.
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs, UsageError } from './lib/args.mjs';
import { base58Encode, fromHex, toHex } from './lib/bytes.mjs';
import { parseTx } from './lib/btc.mjs';
import { randomBytes, sha256 } from './lib/crypto.mjs';
import { action, credentialsPath, failureOf, keyFromSecret, loadCredentials, loadKeyFile, logsOf, milliNear, NEAR, Near, TGAS } from './lib/near.mjs';
import { fakeCoins, feeFor, newOwnerKeys, PATH_PREFIX, VaultClient } from './lib/vault-client.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '..');

const USAGE = `usage: g1.mjs --network testnet|sandbox [--live] [--stage all|ladder|reliability|concurrent|activation|fckey]
  [--rpc URL] [--wasm FILE] [--payer ACCOUNT] [--relay ACCOUNT] [--contract ACCOUNT|self] [--signer ACCOUNT] [--origin URL] [--rp-id HOST]
  [--fund-near N] [--runs-1 N] [--runs-3 N] [--sign-timeout-sec N] [--out FILE]
  sandbox only: --root-key FILE --mock-wasm FILE --test-garble`;

const DEFAULTS = {
  testnet: {
    chain: 'testnet',
    rpc: ['https://test.rpc.fastnear.com', 'https://rpc.testnet.near.org'],
    signer: 'v1.signer-prod.testnet',
    payer: 'undo-btc.testnet',
    relay: 'undo-relay.testnet',
    out: join(REPO, 'proofs', 'g1.json'),
    label: 'live-testnet',
  },
  sandbox: {
    chain: null,
    rpc: null,
    signer: null,
    payer: null,
    relay: null,
    out: join(REPO, 'target', 'g1-sandbox.json'),
    label: 'mock-signer',
  },
};

const LADDER = [15, 20, 30];
const LADDER_MORE = [50, 100, 200, 300];
const STANDARD_ATTACH = 30;
const CALLBACK_TGAS = 10;
const OWN_WORK_TGAS = 30;
const TX_GAS_LIMIT_TGAS = 1000;
const COIN_VALUE = 100_000;

const log = (...parts) => console.log(...parts);

function prepaidFor(inputs, attach) {
  const wanted = inputs * (attach + CALLBACK_TGAS) + OWN_WORK_TGAS;
  return BigInt(Math.min(wanted, TX_GAS_LIMIT_TGAS));
}

/** What each stage will cost, for the plan and the balance check. Credit stays in the vault rows. */
function plannedRuns(cfg) {
  const vaults = LADDER.length + cfg.runs1 + cfg.runs3 + 1 + 2;
  // The last 1 NEAR is a float: prepaid gas is held until its refund, about 0.43 NEAR at 10 inputs.
  return { vaults, approxNear: (vaults * (depositMilli(1) + 5)) / 1000 + cfg.fundNear + 1 };
}

const depositMilli = (inputs) => 30 + 5 * inputs;

// ---------------------------------------------------------------- one signing run

class Run {
  constructor({ near, client, payer, relay, cfg, proof, save, mock }) {
    Object.assign(this, { near, client, payer, relay, cfg, proof, save, mock });
  }

  async vaultFor(inputs) {
    const keys = newOwnerKeys();
    const vault = await this.client.create(this.payer, keys, { csv: 6, depositMilli: depositMilli(inputs) });
    if (!vault.view?.active) {
      throw new Error(`a good vault did not activate. tx ${vault.tx}, failure: ${failureOf(vault.result) ?? 'none'}, row: ${vault.view ? 'inactive' : 'gone'}`);
    }
    return vault;
  }

  async propose(vault, inputs, sender) {
    const coins = fakeCoins(inputs, COIN_VALUE);
    const fee = feeFor(inputs);
    const args = await this.client.selfSpendArgs(vault, coins, fee);
    const before = BigInt((await this.client.viewVault(vault.id)).storage_credit);
    const proposed = await this.client.propose(sender, vault, args, 40n + BigInt(inputs));
    const view = await this.client.viewVault(vault.id);
    const request = await this.client.viewRequest(vault, proposed.request);
    if (fee > view.policy.fee_cap_tx) await this.client.raiseFeeCap(this.payer, vault, proposed.request, fee);
    return {
      vault, coins, fee, id: proposed.request, tx: proposed.tx, unlock: request.unlock,
      amount: COIN_VALUE * inputs - fee, creditBefore: before, creditAfter: BigInt(view.storage_credit),
    };
  }

  async waitForUnlocks(items) {
    const target = Math.max(...items.map((i) => i.unlock)) + 1;
    await this.client.waitUntil(target, { fastForward: this.cfg.network === 'sandbox', log });
  }

  /** Sends execute at inclusion, then watches contract state. Latency runs from broadcast to the view. */
  async execute(item, attach, sender = this.payer) {
    const { vault, id } = item;
    const inputs = item.coins.length;
    const prepaid = prepaidFor(inputs, attach);
    const started = Date.now();
    const sent = await this.near.send(sender, this.client.contract, [
      action.call('execute', { vault: vault.hex, request: id, sign_tgas: attach }, prepaid * TGAS, 0n),
    ]);
    const out = { inputs, attach_tgas: attach, prepaid_tgas: Number(prepaid), vault: vault.hex, request: id, propose_tx: item.tx, execute_tx: sent.hash, outcome: 'timeout' };
    const deadline = started + this.cfg.signTimeoutSec * 1000;
    let view = null;
    let pollCount = 0;
    while (Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, this.cfg.network === 'sandbox' ? 200 : 1000));
      pollCount += 1;
      view = await this.client.viewRequest(vault, id).catch(() => view);
      if (!view) continue;
      const signed = view.sigs.filter(Boolean).length;
      if (signed > 0 && out.first_signature_ms === undefined) out.first_signature_ms = Date.now() - started;
      if (view.status === 'Signed') {
        out.outcome = 'signed';
        out.all_signatures_ms = Date.now() - started;
        break;
      }
      if (view.status === 'Signing' && view.in_flight === 0) {
        out.outcome = 'callback_without_signature';
        break;
      }
      // A refused execute leaves the request Pending. Ask the chain about this hash now and then.
      if (view.status === 'Pending' && pollCount % 5 === 0) {
        const status = await this.near.txStatus(sent.hash, sender.accountId).catch(() => null);
        const failure = failureOf(status);
        if (failure) {
          out.outcome = 'execute_refused';
          out.failure = failure;
          break;
        }
      }
    }
    out.signatures = view ? view.sigs.filter(Boolean).length : 0;
    Object.assign(out, await this.receiptFacts(sent.hash, sender.accountId));
    if (out.outcome === 'signed') Object.assign(out, await this.finalTxFacts(item));
    return out;
  }

  /** Gas and the signer's raw answer, for the record. Missing facts are noted, never a failure. */
  async receiptFacts(hash, sender) {
    const signer = this.client.signer;
    try {
      const status = await this.near.txStatus(hash, sender, 'EXECUTED_OPTIMISTIC');
      const contract = this.client.contract;
      const burnt = (filter) => status.receipts_outcome.filter(filter).map((r) => r.outcome.gas_burnt);
      const own = (needle) => burnt((r) => r.outcome.executor_id === contract && r.outcome.logs.some((l) => l.includes(needle)));
      const signerAnswers = status.receipts_outcome
        .filter((r) => r.outcome.executor_id === signer && r.outcome.status?.SuccessValue)
        .map((r) => {
          try {
            return JSON.parse(Buffer.from(r.outcome.status.SuccessValue, 'base64').toString('utf8'));
          } catch {
            return null;
          }
        })
        .filter((v) => v && typeof v === 'object');
      return {
        gas: {
          tx_total_tgas: tgas(status.receipts_outcome.reduce((sum, r) => sum + r.outcome.gas_burnt, status.transaction_outcome.outcome.gas_burnt)),
          execute_tgas: tgas(Math.max(0, ...own('undo:executing'))),
          on_signed_max_tgas: tgas(Math.max(0, ...own('undo:signed'), ...own('undo:on_signed'))),
          signer_max_tgas: tgas(Math.max(0, ...burnt((r) => r.outcome.executor_id === signer))),
        },
        contract_logs: logsOf(status).filter((l) => l.startsWith('undo:')),
        signer_answer_fields: signerAnswers.length ? Object.keys(signerAnswers[0]).sort() : [],
        signer_answer: signerAnswers[0] ?? null,
      };
    } catch (err) {
      return { receipt_note: `could not read receipts: ${err.message}` };
    }
  }

  async finalTxFacts(item) {
    const { vault, id, coins, amount } = item;
    const hex = await this.near.view(this.client.contract, 'final_tx', { vault: vault.hex, request: id });
    if (!hex) return { final_tx_problem: 'final_tx returned nothing for a Signed request' };
    const payloads = await this.near.view(this.client.contract, 'payloads', { vault: vault.hex, request: id });
    const problem = this.client.checkFinalTx({ vault, coins, parsed: parseTx(fromHex(hex)), to: vault.spk, amount });
    return { final_tx: hex, script_pubkey: toHex(vault.spk), input_values: coins.map((c) => c.value), payloads, final_tx_problem: problem };
  }
}

const tgas = (gas) => Math.round((Number(gas) / 1e12) * 100) / 100;

// ---------------------------------------------------------------- stages

async function ladder(run) {
  const results = [];
  const attempt = async (attaches) => {
    const items = [];
    if (run.mock) await run.mock.honest();
    for (const attach of attaches) {
      const vault = await run.vaultFor(1);
      items.push({ attach, item: await run.propose(vault, 1, run.payer) });
    }
    await run.waitForUnlocks(items.map((i) => i.item));
    if (run.mock) await run.mock.garble();
    for (const { attach, item } of items) {
      const out = await run.execute(item, attach);
      results.push(out);
      log(`  attach ${attach} Tgas: ${out.outcome}${out.first_signature_ms ? ` in ${out.first_signature_ms} ms` : ''}`);
    }
  };
  await attempt(LADDER);
  // The kill line is no real signature at any gas up to 300 Tgas, so climb only if all three failed.
  if (!results.some((r) => r.outcome === 'signed')) {
    log('  no signature at the planned attach values, climbing to the hard-stop value');
    await attempt(LADDER_MORE);
  }
  return {
    runs: results,
    reached_on_signed: results.filter((r) => r.outcome === 'signed').map((r) => r.attach_tgas),
    pass: LADDER.every((a) => results.some((r) => r.attach_tgas === a && r.outcome === 'signed' && !r.final_tx_problem)),
    kill: !results.some((r) => r.outcome === 'signed'),
  };
}

async function repeated(run, { label, inputs, runs, need }) {
  const items = [];
  for (let i = 0; i < runs; i += 1) items.push(await run.propose(await run.vaultFor(inputs), inputs, run.payer));
  await run.waitForUnlocks(items);
  const results = [];
  for (const item of items) {
    const out = await run.execute(item, STANDARD_ATTACH);
    results.push(out);
    log(`  ${label} run ${results.length}: ${out.outcome}, ${out.signatures}/${inputs}${out.all_signatures_ms ? ` in ${out.all_signatures_ms} ms` : ''}`);
  }
  const good = results.filter((r) => r.outcome === 'signed' && !r.final_tx_problem).length;
  return { runs: results, good, need, of: runs, pass: need === null ? null : good >= need };
}

async function activation(run) {
  const good = await run.vaultFor(1);
  const before = BigInt((await run.near.account(run.payer.accountId)).amount);
  const keys = newOwnerKeys();
  const wrong = newOwnerKeys().ku.pub;
  const deposit = 100;
  const bad = await run.client.create(run.payer, keys, { csv: 6, km: wrong, depositMilli: deposit });
  const after = BigInt((await run.near.account(run.payer.accountId)).amount);
  const spent = before - after;
  const refunded = spent < milliNear(deposit) / 2n;
  return {
    good_vault: { vault: good.hex, active: good.view.active, tx: good.tx, gas: createGas(good.result, run.client) },
    bad_vault: {
      vault: bad.hex,
      tx: bad.tx,
      row_after: bad.view,
      refused_log: logsOf(bad.result).some((l) => l.startsWith('undo:refused')),
      deposit_milli_near: deposit,
      refunded,
    },
    pass: good.view.active === true && bad.view === null && refunded,
  };
}

function createGas(result, client) {
  const by = (executor) => result.receipts_outcome.filter((r) => r.outcome.executor_id === executor).map((r) => r.outcome.gas_burnt);
  return { contract_receipts_tgas: by(client.contract).map(tgas), signer_view_tgas: by(client.signer).map(tgas) };
}

async function fckey(run) {
  const fc = keyFromSecret(randomBytes(32));
  const relay = run.relay;
  const agent = { ...fc, accountId: relay.accountId };
  const add = await run.near.sendAndWait(relay, relay.accountId, [
    action.addCallKey(fc.pub, run.client.contract, ['propose_btc', 'execute'], NEAR / 2n),
  ]);
  const addFailure = failureOf(add.result);
  if (addFailure) throw new Error(`could not add the function-call key: ${addFailure}`);
  try {
    const vault = await run.vaultFor(1);
    const item = await run.propose(vault, 1, agent);
    await run.waitForUnlocks([item]);
    const executed = await run.execute(item, STANDARD_ATTACH, agent);
    return {
      add_key_tx: add.hash,
      propose_tx: item.tx,
      credit_before: item.creditBefore.toString(),
      credit_after: item.creditAfter.toString(),
      credit_paid: item.creditAfter < item.creditBefore,
      execute: executed,
      pass: item.creditAfter < item.creditBefore,
    };
  } finally {
    await run.near.sendAndWait(relay, relay.accountId, [action.deleteKey(fc.pub)]).catch((err) => log(`  could not remove the test key: ${err.message}`));
  }
}

// ---------------------------------------------------------------- setup

function outwardCheck(wasm) {
  const result = spawnSync(join(REPO, 'scripts', 'outward-check.sh'), ['--wasm', wasm], { encoding: 'utf8' });
  process.stdout.write(result.stdout ?? '');
  process.stderr.write(result.stderr ?? '');
  return result.status === 0;
}

async function deployIfNeeded({ near, cfg, payer, wasmBytes, codeHash }) {
  const contract = cfg.contract;
  const existing = await near.account(contract);
  const init = {
    preset: 'TestCoin', operator: payer.accountId, restrict_create: false, signer: cfg.signer, domain_id: 0,
    sign_tgas: LADDER[0], callback_tgas: CALLBACK_TGAS, derive_tgas: 30, network: 'mutinynet', origins: [cfg.origin], outflow_cap_24h: 1_000_000,
  };
  const initCall = action.call('new', init, 100n * TGAS, 0n);
  if (existing && existing.code_hash !== '11111111111111111111111111111111') {
    if (existing.code_hash !== codeHash) throw new Error(`${contract} holds other code. Refusing to overwrite it. Use a fresh --contract`);
    return { deployed: false };
  }
  if (existing) {
    // An empty account: a fresh name, or a sub-account left by a run that stopped before deploying.
    const own = contract === payer.accountId || contract.endsWith(`.${payer.accountId}`) ? { ...payer, accountId: contract } : loadCredentials(cfg.network, contract);
    const sent = await near.sendAndWait(own, contract, [action.deploy(wasmBytes), initCall]);
    if (failureOf(sent.result)) throw new Error(`deploy failed: ${failureOf(sent.result)}`);
    return { deployed: true, tx: sent.hash };
  }
  // `new` is private, so the contract's own account has to call it. So this takes two transactions:
  // the parent makes the account and gives it the parent's key, then that account deploys itself.
  if (!contract.endsWith(`.${payer.accountId}`)) throw new Error(`${contract} does not exist and is not under ${payer.accountId}`);
  const made = await near.sendAndWait(payer, contract, [
    action.createAccount(),
    action.transfer(BigInt(Math.round(cfg.fundNear * 1000)) * (NEAR / 1000n)),
    action.addFullKey(payer.pub),
  ]);
  if (failureOf(made.result)) throw new Error(`could not create ${contract}: ${failureOf(made.result)}`);
  const own = { ...payer, accountId: contract };
  const sent = await near.sendAndWait(own, contract, [action.deploy(wasmBytes), initCall]);
  if (failureOf(sent.result)) throw new Error(`deploy failed: ${failureOf(sent.result)}`);
  return { deployed: true, created_subaccount: true, create_tx: made.hash, deploy_tx: sent.hash };
}

function writeProof(path, proof) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(`${path}.tmp`, `${JSON.stringify(proof, null, 2)}\n`);
  renameSync(`${path}.tmp`, path);
}

async function sandboxAccounts({ near, a }) {
  const root = loadKeyFile(a['root-key']);
  const makeAccount = async (name, balanceNear) => {
    const accountId = `${name}.${root.accountId}`;
    const key = keyFromSecret(randomBytes(32));
    const sent = await near.sendAndWait(root, accountId, [
      action.createAccount(), action.transfer(BigInt(balanceNear) * NEAR), action.addFullKey(key.pub),
    ]);
    if (failureOf(sent.result)) throw new Error(`could not create ${accountId}: ${failureOf(sent.result)}`);
    return { ...key, accountId };
  };
  const tag = toHex(randomBytes(3));
  const mock = await makeAccount(`mock${tag}`, 50);
  const secret = sha256(new TextEncoder().encode(`undo-test-only:mock-root:${tag}`));
  const mockInit = action.call('new', { secret_hex: toHex(secret), mode: 'Yield' }, 100n * TGAS, 0n);
  const deployed = await near.sendAndWait(mock, mock.accountId, [action.deploy(readFileSync(a['mock-wasm'])), mockInit]);
  if (failureOf(deployed.result)) throw new Error(`mock deploy failed: ${failureOf(deployed.result)}`);
  return {
    root,
    mock,
    secret,
    payer: await makeAccount(`payer${tag}`, 200),
    relay: await makeAccount(`relay${tag}`, 50),
    responder: await makeAccount(`node${tag}`, 50),
  };
}

// ---------------------------------------------------------------- main

async function main() {
  const a = parseArgs(process.argv.slice(2), {
    network: 'text', live: 'flag', stage: 'text', rpc: 'text', wasm: 'text', payer: 'text', relay: 'text', contract: 'text', signer: 'text',
    origin: 'text', 'rp-id': 'text', 'fund-near': 'int', 'runs-1': 'int', 'runs-3': 'int', 'sign-timeout-sec': 'int', out: 'text',
    'root-key': 'text', 'mock-wasm': 'text', 'test-garble': 'flag',
  });
  if (a.network !== 'testnet' && a.network !== 'sandbox') throw new UsageError(USAGE);
  const d = DEFAULTS[a.network];
  if (a.network === 'sandbox' && (!a.rpc || !a['root-key'] || !a['mock-wasm'])) throw new UsageError(USAGE);
  if (a.network === 'testnet' && (a['root-key'] || a['mock-wasm'] || a['test-garble'])) throw new UsageError('those flags are for a sandbox');
  const stage = a.stage ?? 'all';
  if (!['all', 'ladder', 'reliability', 'concurrent', 'activation', 'fckey'].includes(stage)) throw new UsageError(USAGE);

  const cfg = {
    network: a.network,
    live: Boolean(a.live) || a.network === 'sandbox',
    signer: a.signer ?? d.signer,
    origin: a.origin ?? 'https://undo-btc.pages.dev',
    rpId: a['rp-id'] ?? 'undo-btc.pages.dev',
    fundNear: a['fund-near'] ?? 4,
    runs1: a['runs-1'] ?? 10,
    runs3: a['runs-3'] ?? 5,
    signTimeoutSec: a['sign-timeout-sec'] ?? 300,
    out: resolve(a.out ?? d.out),
  };
  const wasmPath = resolve(a.wasm ?? join(process.env.CARGO_TARGET_DIR ?? join(REPO, 'target'), 'near', 'undo_vault.wasm'));
  if (!existsSync(wasmPath)) throw new Error('no wasm to deploy. Run scripts/build.sh first');
  const wasmBytes = readFileSync(wasmPath);
  const wasmHash = sha256(wasmBytes);
  const codeHash = base58Encode(wasmHash);

  const near = new Near(a.rpc ? [a.rpc] : d.rpc);
  const status = await near.status();
  if (status.chain_id === 'mainnet') throw new Error('this driver never runs on mainnet');
  if (a.network === 'testnet' && status.chain_id !== 'testnet') throw new Error(`expected testnet, the RPC says ${status.chain_id}`);
  if (a.network === 'sandbox' && (status.chain_id === 'testnet')) throw new Error('--network sandbox pointed at testnet');
  const protocol = status.protocol_version;

  const proof = {
    schema: 'undo-g1-v1',
    label: d.label,
    gate: a.network === 'testnet' ? 'G1' : 'not a gate result: mock signer on a local node',
    chain_id: status.chain_id,
    protocol_version: protocol,
    node_version: status.version?.version,
    wasm: { sha256: toHex(wasmHash), bytes: wasmBytes.length },
    coins: 'made up: execute does not read Bitcoin, so nothing here moved a coin',
    passkey: '[software authenticator]: a real phone is G3',
    stages: {},
  };

  // ------------------------------------------------------------ outward check
  if (a.network === 'testnet') {
    log('Outward check on the exact wasm:');
    if (!outwardCheck(wasmPath)) {
      console.error('Refused: the outward check failed, so nothing was sent.');
      process.exit(3);
    }
    proof.outward_check = 'passed on this wasm, before any write';
  } else {
    proof.outward_check = 'not run: a local node is not outward';
  }

  // ------------------------------------------------------------ accounts
  let payer;
  let relay;
  let sandbox = null;
  if (a.network === 'sandbox') {
    sandbox = await sandboxAccounts({ near, a });
    ({ payer, relay } = sandbox);
    cfg.signer = sandbox.mock.accountId;
  }
  const payerName = payer?.accountId ?? a.payer ?? d.payer;
  const relayName = relay?.accountId ?? a.relay ?? d.relay;
  // `self` deploys on the payer's own account. Config has no setter, so the sign gas floor of 15 and
  // the origin list stay on whatever account this runs on. The default keeps the real name clean.
  cfg.contract = a.contract === 'self' ? payerName : a.contract ?? `g1.${payerName}`;
  proof.contract = { account: cfg.contract, code_hash: codeHash };
  proof.signer = { account: cfg.signer };

  const signerVersion = await near.view(cfg.signer, 'version').catch(() => null);
  proof.signer.version = signerVersion;

  // A sample path as long as the real ones. Read-only, and it answers whether the signer takes it.
  const samplePath = `${PATH_PREFIX}${'0'.repeat(64)}`;
  proof.signer.path_length = samplePath.length;
  proof.signer.derived_view_ok = await near
    .view(cfg.signer, 'derived_public_key', { path: samplePath, predecessor: cfg.contract, domain_id: 0 })
    .then(() => true)
    .catch(() => false);

  if (!cfg.live) {
    await printPlan({ near, cfg, payerName, relayName, codeHash, wasmBytes, protocol, signerVersion, proof });
    return;
  }

  if (a.network === 'testnet') {
    payer = loadCredentials(a.network, payerName);
    relay = loadCredentials(a.network, relayName);
    const held = Number((await near.account(payerName))?.amount ?? 0) / 1e24;
    const hasContract = await near.account(cfg.contract);
    const needed = plannedRuns(cfg).approxNear - (hasContract ? cfg.fundNear : 0);
    if (held < needed) {
      console.error(`Refused: ${payerName} holds ${held.toFixed(2)} NEAR and this run needs about ${needed.toFixed(1)}. Nothing was sent.`);
      process.exit(3);
    }
  }

  // ------------------------------------------------------------ deploy
  log(`Contract ${cfg.contract}, ${wasmBytes.length} bytes, signer ${cfg.signer}, label ${d.label}`);
  proof.deploy = await deployIfNeeded({ near, cfg, payer, wasmBytes, codeHash });
  const instance = await near.view(cfg.contract, 'instance');
  if (instance.signer !== cfg.signer) throw new Error(`this contract's signer is ${instance.signer}, expected ${cfg.signer}`);
  if (instance.sign_tgas > LADDER[0]) throw new Error(`this contract's sign gas floor is ${instance.sign_tgas}, so the ladder cannot run`);
  proof.instance = { preset: instance.preset, sign_tgas_floor: instance.sign_tgas, callback_tgas: instance.callback_tgas, derive_tgas: instance.derive_tgas, network: instance.network };
  const client = new VaultClient({ near, contract: cfg.contract, signer: cfg.signer, instance, origin: cfg.origin, rpId: cfg.rpId });
  // A re-run of one stage against the same contract and code keeps the other stages' results.
  if (existsSync(cfg.out)) {
    const earlier = JSON.parse(readFileSync(cfg.out, 'utf8'));
    if (earlier.contract?.account === cfg.contract && earlier.contract?.code_hash === codeHash) proof.stages = earlier.stages ?? {};
  }
  const save = () => writeProof(cfg.out, proof);
  save();

  let mock = null;
  let stopMock = () => {};
  if (sandbox) {
    const { startMockNode } = await import('./test/mock-node.mjs');
    const node = startMockNode({ near, mock: sandbox.mock, responder: sandbox.responder, secret: sandbox.secret });
    stopMock = node.stop;
    if (a['test-garble']) {
      // The negative control: vaults activate honestly, then every signature comes back as junk.
      const setMode = (mode) => near.sendAndWait(sandbox.mock, sandbox.mock.accountId, [action.call('set_mode', { mode }, 30n * TGAS, 0n)]);
      mock = { honest: () => setMode('Yield'), garble: () => setMode('Garbage') };
    }
  }

  const run = new Run({ near, client, payer, relay, cfg, proof, save, mock });
  const stages = {
    activation: () => activation(run),
    ladder: () => ladder(run),
    reliability: () => repeated(run, { label: '1 input', inputs: 1, runs: cfg.runs1, need: Math.ceil((cfg.runs1 * 9) / 10) }),
    concurrent_3: () => repeated(run, { label: '3 inputs', inputs: 3, runs: cfg.runs3, need: Math.ceil((cfg.runs3 * 4) / 5) }),
    concurrent_10: () => repeated(run, { label: '10 inputs', inputs: 10, runs: 1, need: null }),
    fckey: () => fckey(run),
  };
  const chosen = {
    all: Object.keys(stages), ladder: ['ladder'], reliability: ['reliability'], concurrent: ['concurrent_3', 'concurrent_10'], activation: ['activation'], fckey: ['fckey'],
  }[stage];

  try {
    for (const name of chosen) {
      log(`Stage ${name}`);
      const startedAt = new Date().toISOString();
      try {
        proof.stages[name] = { started_at: startedAt, ...(await stages[name]()) };
      } catch (err) {
        proof.stages[name] = { started_at: startedAt, pass: false, error: err.message };
        log(`  failed: ${err.message}`);
      }
      save();
    }
  } finally {
    stopMock();
  }

  // ------------------------------------------------------------ verdict
  const lines = Object.entries(proof.stages).map(([name, s]) => ({ name, pass: s.pass }));
  proof.summary = {
    real_signature_reached_on_signed: a.network === 'testnet' ? proof.stages.ladder?.reached_on_signed?.length > 0 : false,
    signature_reached_on_signed_any_signer: proof.stages.ladder?.reached_on_signed?.length > 0,
    lines,
    all_measured_lines_pass: lines.every((l) => l.pass !== false),
  };
  save();
  for (const l of lines) log(`${l.pass === null ? 'MEASURED' : l.pass ? 'PASS' : 'FAIL'} ${l.name} [${d.label}]`);
  log(`Proof written. Label: ${d.label}. ${a.network === 'sandbox' ? 'This is a mock signer on a local node, not a G1 result.' : ''}`);
  if (!proof.summary.all_measured_lines_pass) process.exit(1);
}

async function printPlan({ near, cfg, payerName, relayName, codeHash, wasmBytes, protocol, signerVersion, proof }) {
  const planned = plannedRuns(cfg);
  const existing = await near.account(cfg.contract);
  const payerAccount = await near.account(payerName);
  const relayAccount = await near.account(relayName);
  const hasCreds = (name) => existsSync(credentialsPath(cfg.network, name));
  const storageNear = (wasmBytes.length * 1e19) / 1e24;
  log('');
  log('PLAN ONLY. Nothing was sent. Add --live to run it, once the owner has approved it and the accounts exist.');
  log(`  network          ${cfg.network}, protocol ${protocol}`);
  log(`  signer           ${cfg.signer}${signerVersion ? `, version ${JSON.stringify(signerVersion)}` : ''}`);
  log(`  69-char path     derived_public_key ${proof.signer.derived_view_ok ? 'answered' : 'DID NOT ANSWER'}`);
  log(`  contract         ${cfg.contract} ${existing ? (existing.code_hash === codeHash ? '(already this code)' : '(EXISTS with other code or none)') : '(will be created under the payer)'}`);
  log(`  wasm             ${wasmBytes.length} bytes, ${storageNear.toFixed(2)} NEAR of storage, code hash ${codeHash}`);
  log(`  payer            ${payerName}: ${payerAccount ? `${(Number(payerAccount.amount) / 1e24).toFixed(2)} NEAR` : 'NOT CREATED'}, key file ${hasCreds(payerName) ? 'present' : 'MISSING'}`);
  log(`  relay            ${relayName}: ${relayAccount ? `${(Number(relayAccount.amount) / 1e24).toFixed(2)} NEAR` : 'NOT CREATED'}, key file ${hasCreds(relayName) ? 'present' : 'MISSING'}`);
  log(`  will create      about ${planned.vaults} vaults over made-up coins, and fund the contract with ${cfg.fundNear} NEAR`);
  log(`  will cost        about ${planned.approxNear.toFixed(1)} NEAR from the payer. Credit stays in vault rows: no method withdraws it.`);
  log(`  sign calls       attach ${LADDER.join(', ')} Tgas, then ${cfg.runs1} x 1 input, ${cfg.runs3} x 3 inputs, 1 x 10 inputs at ${STANDARD_ATTACH} Tgas, 1 through a function-call key`);
  log(`  proof            ${cfg.out.startsWith(REPO) ? cfg.out.slice(REPO.length + 1) : 'the --out file'}`);
  const ready = payerAccount && relayAccount && hasCreds(payerName) && hasCreds(relayName)
    && Number(payerAccount.amount) / 1e24 >= planned.approxNear && proof.signer.derived_view_ok;
  log(ready ? 'READY.' : 'NOT READY: see the lines above.');
  if (!ready) process.exit(4);
}

main().catch((err) => {
  if (err instanceof UsageError) {
    console.error(err.message);
    process.exit(2);
  }
  console.error(`g1 stopped: ${err.message}`);
  process.exit(1);
});
