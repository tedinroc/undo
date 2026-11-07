// The relay for real on this machine: the Functions and undo-cron as wrangler 3 bundles them, in workerd, with the
// Durable Object bound across by script name, against the real wasm on a local NEAR node, a mock signer, and regtest.
// All keys are throwaway. Nothing here can reach a live host. Skipped, and it says so, without both the stage
// (NEAR_SANDBOX_BIN_PATH, UNDO_WASM_DIR, UNDO_BITCOIN_BIN) and UNDO_WRANGLER_MODULES.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { base58Encode, fromHex, toHex, utf8 } from '../../tools/lib/bytes.mjs';
import { signColdIntent } from '../../tools/lib/cold-intent.mjs';
import { ed25519, sha256 } from '../../tools/lib/crypto.mjs';
import { action, failureOf, keyFromSecret, Near, NEAR, TGAS } from '../../tools/lib/near.mjs';
import { sendEverything } from '../lib/bitcoin.mjs';
import { buildCreateArgs, buildPropose, cancelArgs, cancelDigest, newVaultKeys, rotateArgs, rotateDigest, rpIdHashOf, vaultIdOf } from '../lib/intents.mjs';
import { NearReader } from '../lib/near-read.mjs';
import { checkPow, fundsPowTarget, solvePow } from '../lib/pow.mjs';
import { CREATE_DEPOSIT_MILLI, executeTgas, OWNER_FLOOR_YOCTO, RELAY_METHODS } from '../lib/relay-table.mjs';
import { requestState } from '../lib/request-state.mjs';
import { softCredentials } from '../lib/soft-authenticator.mjs';
import { contractViews, derivedKey } from '../lib/views.mjs';
import { createPasskey, getAssertion } from '../lib/webauthn.mjs';
import { stageAvailable, startStage } from './stage.mjs';
import { bundleBoth, loadMiniflare, startWorkerd, workerdAvailable } from './workerd.mjs';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const skip = stageAvailable() && workerdAvailable() ? false : 'set the stage\'s variables and UNDO_WRANGLER_MODULES to run the relay in real workerd against the real wasm';
const label = (t) => sha256(utf8(`undo-test-only:relay-workerd:${t}`));
const textOf = (k) => `ed25519:${base58Encode(k)}`;
const SITE = 'http://relay.test';
const POW_BITS = 8;
const OWNER_METHODS = ['cancel', 'cancel_all_and_rotate', 'clear_hold', 'raise_fee_cap', 'remove_destination', 'add_destination', 'set_policy', 'set_guard', 'recover_cancel', 'freeze', 'unfreeze', 'veto_grant', 'recover_begin'];

let stage;
let mf;
let bundles;
let reader;
let views;
let instance;
let ownerKey;
let cronKey;
let canary;
let reserveCeiling;
let nextIp = 1;
const gas = {};

const freshIp = () => `10.0.${Math.floor(nextIp / 250)}.${(nextIp += 1) % 250}`;

/** A vault as the phone builds it, with the args the page would POST. */
async function buildVault(name) {
  const soft = softCredentials({ secret: label(`${name}-passkey`), origin: stage.origin, rpId: stage.rpId });
  const made = await createPasskey({ credentials: soft, rpId: stage.rpId });
  const keys = newVaultKeys({ seed: label(`${name}-seed`), cold: label(`${name}-cold`) });
  const vaultHex = toHex(vaultIdOf({ contract: stage.contract, keys, passkeyPub: made.pubkey, csv: 6 }));
  const km = await derivedKey(reader, { signer: instance.signer, domainId: instance.domain_id, contract: stage.contract, vaultHex });
  const chainNow = (await reader.blockTime()).blockMs;
  const built = await buildCreateArgs({
    contract: stage.contract, keys, passkeyPub: made.pubkey, rpIdHash: rpIdHashOf(stage.rpId), km, guard: stage.relay.accountId, policy: instance.policy, csv: 6, expiresAt: chainNow + 30 * 60_000,
    assert: async (digest) => (await getAssertion({ credentials: soft, digest, rpId: stage.rpId, credentialId: made.credentialId })).args,
  });
  return { name, soft, made, keys, vaultHex, cold: label(`${name}-cold`), args: built.args };
}

const worker = (name) => mf.getWorker(name);

const BEAT = 'undo-test-only:beat';

async function post(name, path, body, { ip = freshIp(), origin = null, beat = BEAT } = {}) {
  const headers = { 'content-type': 'application/json', 'cf-connecting-ip': ip };
  if (origin) headers.origin = origin;
  if (beat) headers['x-undo-beat'] = beat;
  const res = await (await worker(name)).fetch(`${SITE}${path}`, { method: 'POST', headers, body: JSON.stringify(body) });
  const text = await res.text();
  return { status: res.status, body: JSON.parse(text), text };
}

const relay = (name, method, args, opts = {}) => post(name, '/api/relay', opts.pow === undefined ? { method, args } : { method, args, pow: opts.pow }, opts);
const funds = async (name, vault, opts) => post(name, '/api/funds', { vault, pow: await solvePow(fundsPowTarget(vault), POW_BITS) }, opts);
const status = async (name) => (await (await worker(name)).fetch(`${SITE}/api/relay`)).json();

async function makeVault(name, on = 'main', opts = {}) {
  const v = await buildVault(name);
  const pow = await solvePow(v.vaultHex, POW_BITS);
  const out = await relay(on, 'create_vault', v.args, { pow, ...opts });
  assert.equal(out.body.ok, true, out.text);
  v.tx = out.body.hash;
  // The relay answers at inclusion. The contract has run it only when its receipts have.
  v.result = await settled(v.tx);
  return v;
}

/**
 * The relay `on` keeps its own state store. Its create share here is too small for a vault, so a vault made on main
 * is written into its store, as its own create_vault would have done: the row, then the hash of the create it signed.
 * Every relay here signs as the same account, so `on` checks that hash against the chain itself. Production has one
 * relay and one store.
 */
async function adopt(on, v) {
  const ns = await mf.getDurableObjectNamespace('UNDO_STATE', 'undo-cron');
  const op = async (name, body) => (await ns.get(ns.idFromName(on)).fetch(`https://do/${name}`, { method: 'POST', body: JSON.stringify(body) })).json();
  assert.equal((await op('made', { vault: v.vaultHex, passkey: v.args.passkey.pubkey, k_e_intent: v.args.k_e_intent, now: Date.now() })).ok, true);
  assert.equal((await op('madeSent', { vault: v.vaultHex, hash: v.tx })).ok, true);
}

/** A vault made straight on the contract, not through this relay, naming the relay as its guard, paid by the payer. */
async function makeDirect(name) {
  const v = await buildVault(name);
  const sent = await stage.near.sendAndWait(stage.payer, stage.contract, [action.call('create_vault', { args: v.args }, 120n * TGAS, stage.milliNear(CREATE_DEPOSIT_MILLI))]);
  assert.equal(failureOf(sent.result), null);
  for (let i = 0; i < 40 && !(await views.vault(v.vaultHex))?.active; i += 1) await new Promise((r) => setTimeout(r, 250));
  assert.equal((await views.vault(v.vaultHex)).active, true);
  return v;
}

async function proposeBody(v) {
  const vault = await views.vault(v.vaultHex);
  const script = fromHex(await views.script(v.vaultHex));
  const coin = v.coinFrom?.inputs[0] ?? { txid: toHex(label(`coin-${v.vaultHex}-${vault.spend_nonce}`)), vout: 0, value: 2000 };
  const to = fromHex(`0014${toHex(label('thief')).slice(0, 40)}`);
  const spend = sendEverything({ coins: [coin], to, script, feeRate: 2 });
  const chainNow = (await reader.blockTime()).blockMs;
  return buildPropose({ contract: stage.contract, vault, script, seed: v.keys.seed, inputs: spend.inputs, to, amount: spend.amount, nonce: vault.spend_nonce, expiresAt: chainNow + 30 * 60_000 });
}

async function propose(v, on = 'main') {
  const out = await relay(on, 'propose_btc', await proposeBody(v));
  assert.equal(out.body.ok, true, out.text);
  const seen = await settled(out.body.hash);
  assert.equal(failureOf(seen), null);
  const vault = await views.vault(v.vaultHex);
  return { tx: out.body.hash, request: Math.max(...vault.pending) };
}

async function rotateBody(v) {
  const vault = await views.vault(v.vaultHex);
  const newKs = ed25519.getPublicKey(label(`${v.name}-new-ks-${vault.passkey_nonce}`));
  const expiresAt = (await reader.blockTime()).blockMs + 10 * 60_000;
  const digest = rotateDigest({ contract: stage.contract, vaultHex: v.vaultHex, newKs, nonce: vault.passkey_nonce, expiresAt });
  const { args: assertion } = await getAssertion({ credentials: v.soft, digest, rpId: stage.rpId, credentialId: v.made.credentialId });
  return rotateArgs({ vaultHex: v.vaultHex, newKs, nonce: vault.passkey_nonce, expiresAt, assertion });
}

/** The whole receipt tree of a transaction the relay only waited to see included. */
async function settled(hash) {
  for (let i = 0; i < 60; i += 1) {
    try {
      const out = await stage.near.txStatus(hash, stage.relay.accountId, 'EXECUTED_OPTIMISTIC');
      if (out?.receipts_outcome) return out;
    } catch {
      // Not there yet.
    }
    await new Promise((r) => setTimeout(r, 250));
  }
  throw new Error('transaction never settled');
}

const attached = (result) => result.transaction.actions.map((a) => [a.FunctionCall.method_name, a.FunctionCall.gas / 1e12]);
const burnt = (result) => (result.receipts_outcome.reduce((sum, r) => sum + r.outcome.gas_burnt, result.transaction_outcome.outcome.gas_burnt) / 1e12).toFixed(2);

function noteGas(method, result) {
  gas[method] = `${burnt(result)} Tgas burnt of ${attached(result).map(([, g]) => g).join(' + ')} attached${failureOf(result) ? ', refused by the contract' : ''}`;
}

const keyNonce = async (publicKey) => (await stage.near.rpc('query', { request_type: 'view_access_key', account_id: stage.relay.accountId, public_key: publicKey, finality: 'optimistic' })).nonce;

before(async () => {
  if (skip) return;
  stage = await startStage({ miner: true });
  reader = new NearReader({ urls: stage.config.rpc, timeoutMs: 15_000 });
  views = contractViews(reader, stage.contract);
  instance = await views.instance();

  // The owner and cron keys are function-call keys, as they are live, on the relay's own account.
  ownerKey = keyFromSecret(label('owner-key'));
  cronKey = keyFromSecret(label('cron-key'));
  const added = await stage.near.sendAndWait(stage.relay, stage.relay.accountId, [
    action.addCallKey(ownerKey.pub, stage.contract, OWNER_METHODS, 2n * NEAR),
    action.addCallKey(cronKey.pub, stage.contract, ['heartbeat'], NEAR / 2n),
  ]);
  assert.equal(failureOf(added.result), null);

  // A canary made before workerd starts, because its id goes into the cron's environment. Sent directly.
  canary = await buildVault('canary');
  const made = await stage.near.sendAndWait(stage.relay, stage.contract, [
    action.call('create_vault', { args: canary.args }, 120n * TGAS, stage.milliNear(CREATE_DEPOSIT_MILLI)),
    action.call('heartbeat', { vault: canary.vaultHex }, 10n * TGAS, 0n),
  ]);
  assert.equal(failureOf(made.result), null);

  // A relay whose owner ceiling asks it to keep more than its whole balance for cancels: general traffic must stop.
  const relayAccount = await stage.near.account(stage.relay.accountId);
  const free = BigInt(relayAccount.amount) - BigInt(relayAccount.storage_usage) * 10n ** 19n;
  reserveCeiling = String((free - OWNER_FLOOR_YOCTO) / 10n ** 18n + 1n);

  bundles = bundleBoth();
  const dispenser = JSON.parse(readFileSync(stage.rig.info.dispenser, 'utf8')).secret;
  const poor = JSON.parse(readFileSync(stage.rig.poorDispenser().path, 'utf8')).secret;
  const common = {
    CONTRACT_ID: stage.contract,
    NEAR_RPC_URLS: stage.config.rpc.join(','),
    ESPLORA_URL: stage.config.esplora,
    RELAY_ACCOUNT: stage.relay.accountId,
    RELAY_GENERAL_KEY: textOf(stage.relay.secret),
    RELAY_OWNER_KEY: textOf(ownerKey.secret),
    DISPENSER_SECRET: dispenser,
    DISPENSER_NETWORK: 'regtest',
    IP_SALT: 'undo-test-only:workerd',
    POW_BITS: String(POW_BITS),
    STATUS_CACHE_MS: '0',
    KEY_CACHE_MS: '0',
    BEAT_TOKEN: BEAT,
  };
  const { Miniflare } = loadMiniflare();
  mf = startWorkerd({ Miniflare }, {
    bundles,
    cronEnv: { CONTRACT_ID: stage.contract, NEAR_RPC_URLS: stage.config.rpc.join(','), RELAY_ACCOUNT: stage.relay.accountId, RELAY_CRON_KEY: textOf(cronKey.secret), CANARY_VAULT: canary.vaultHex, UNDO_STATE_NAME: 'cron' },
    pages: {
      // This file makes more vaults than the default ceiling's 18.
      main: { bindings: { ...common, UNDO_STATE_NAME: 'main', CEILING_GENERAL_MICRO: '100000000' } },
      // Just room for one proposal and two heartbeats, on a vault made elsewhere. One funding, one dispenser with nothing in it.
      low: { bindings: { ...common, UNDO_STATE_NAME: 'low', CEILING_GENERAL_MICRO: '2000', CEILING_FUNDS_SATS: '2000' } },
      poor: { bindings: { ...common, UNDO_STATE_NAME: 'poor', DISPENSER_SECRET: poor } },
      broken: { bindings: { ...common }, state: { className: 'Broken', scriptName: 'broken-state' } },
      reserved: { bindings: { ...common, UNDO_STATE_NAME: 'reserved', CEILING_OWNER_MICRO: reserveCeiling } },
    },
    extra: [{
      name: 'broken-state',
      modules: true,
      script: 'export class Broken { fetch() { throw new Error("over its limit"); } } export default { fetch: () => new Response("x") };',
      compatibilityDate: '2025-01-15',
      durableObjects: { BROKEN: { className: 'Broken', useSQLite: true } },
    }],
  });
  await mf.ready;
}, { timeout: 240_000 });

after(async () => {
  await mf?.dispose();
  bundles?.remove();
  await stage?.stop();
});

test('bundles: wrangler 3 builds both from this tree, with no source map, no local path and no warning about the config', { skip }, () => {
  assert.doesNotMatch(bundles.dry, /Unexpected fields|preview_urls.*not|workers_dev.*not/i, bundles.dry);
  const files = [bundles.pages, bundles.cron];
  for (const file of files) {
    const text = readFileSync(file, 'utf8');
    assert.doesNotMatch(text, /sourceMappingURL/);
    assert.ok(!text.includes(REPO), 'no absolute path of this checkout');
  }
  const scan = spawnSync('bash', [join(REPO, 'scripts/check-identity.sh'), '--files', ...files], { encoding: 'utf8' });
  assert.equal(scan.status, 0, scan.stdout + scan.stderr);
});

test('GET /api/relay: the shape the page reads, from the real Durable Object by script name', { skip }, async () => {
  const s = await status('main');
  assert.deepEqual(Object.keys(s), ['ok', 'relay_account', 'contract', 'pow_bits', 'owner', 'general', 'owner_runway_days', 'funds']);
  assert.ok(typeof s.owner_runway_days === 'number' && s.owner_runway_days > 3, `the stage relay's runway: ${s.owner_runway_days} days`);
  assert.equal(s.contract, stage.contract);
  assert.equal(s.relay_account, stage.relay.accountId);
  assert.equal(s.pow_bits, POW_BITS);
  assert.deepEqual(s.owner, { up: true, why: null, degraded: false, resets_at: null });
  assert.deepEqual(s.general, { up: true, why: null, resets_at: null });
  assert.deepEqual(s.funds, { up: true, why: null, sats: 2000, resets_at: null });
});

test('create_vault through the relay: a real vault at 5:00, exact gas and deposit, and no coin pays out', { skip, timeout: 60_000 }, async () => {
  const v = await makeVault('first');
  const vault = await views.vault(v.vaultHex);
  assert.equal(vault.active, true);
  assert.equal(vault.guard, stage.relay.accountId);
  assert.equal(vault.guard_online, true);
  assert.equal(await views.delayNow(v.vaultHex), 300_000);
  const result = await settled(v.tx);
  assert.equal(failureOf(result), null);
  assert.deepEqual(attached(result), [['create_vault', 120], ['heartbeat', 10]]);
  assert.equal(result.transaction.actions[0].FunctionCall.deposit, (stage.milliNear(CREATE_DEPOSIT_MILLI)).toString());
  assert.equal(result.transaction.public_key, stage.relay.publicKey, 'on the general key');
  assert.equal(result.transaction.receiver_id, stage.contract);
  noteGas('create_vault + heartbeat', result);
  const coins = await (await fetch(`${stage.config.esplora}/address/${vault.address}/utxo`)).json();
  assert.deepEqual(coins, [], 'creating a vault pays nothing');
});

// Before any test moves the sandbox clock, so every height the in-flight check may read is a block the node has.
test('a sign call still out: a second execute is refused before the key signs, as the contract refuses it, and the answer then signs', { skip, timeout: 180_000 }, async () => {
  const v = await makeVault('in-flight');
  const vault = await views.vault(v.vaultHex);
  const spend = sendEverything({ coins: [{ txid: toHex(label('in-flight-coin')), vout: 0, value: 2000 }], to: fromHex(vault.script_pubkey), script: fromHex(await views.script(v.vaultHex)), feeRate: 2 });
  const chainNow = (await reader.blockTime()).blockMs;
  const body = buildPropose({ contract: stage.contract, vault, script: fromHex(await views.script(v.vaultHex)), seed: v.keys.seed, inputs: spend.inputs, to: fromHex(vault.script_pubkey), amount: spend.amount, nonce: vault.spend_nonce, expiresAt: chainNow + 30 * 60_000 });
  const proposed = await relay('main', 'propose_btc', body);
  assert.equal(proposed.body.ok, true, proposed.text);
  assert.equal(failureOf(await settled(proposed.body.hash)), null);
  const request = Math.max(...(await views.vault(v.vaultHex)).pending);
  const r0 = await views.request(v.vaultHex, request);
  assert.equal(r0.tier, 'SelfSpend', 'a send to the vault itself, whose short wait passes in real time');
  while ((await reader.blockTime()).blockMs < r0.unlock) await new Promise((res) => setTimeout(res, 1000));

  stage.rig.setFault('signer-silent');
  try {
    const fired = await relay('main', 'execute', { vault: v.vaultHex, request });
    assert.equal(fired.body.ok, true, fired.text);
    let r = r0;
    for (let i = 0; i < 80 && !(r.status === 'Signing' && r.in_flight === 1); i += 1) {
      await new Promise((res) => setTimeout(res, 250));
      r = await views.request(v.vaultHex, request);
    }
    assert.deepEqual([r.status, r.in_flight, r.attempt], ['Signing', 1, 1], 'the signer holds the call');
    const nonceBefore = await keyNonce(stage.relay.publicKey);
    const again = await relay('main', 'execute', { vault: v.vaultHex, request });
    assert.deepEqual([again.status, again.body.code], [422, 'would_refuse'], again.text);
    assert.match(again.body.message, /still out/);
    assert.equal(await keyNonce(stage.relay.publicKey), nonceBefore, 'the general key sent nothing');
    const direct = await stage.near.sendAndWait(stage.payer, stage.contract, [action.call('execute', { vault: v.vaultHex, request }, 100n * TGAS, 0n)]);
    assert.match(failureOf(direct.result) ?? 'no failure', /InFlight/, 'the contract refuses the same call from anyone');
    assert.equal((await views.request(v.vaultHex, request)).attempt, 1, 'and asked the signer nothing more');
  } finally {
    stage.rig.setFault(null);
  }
  let r = await views.request(v.vaultHex, request);
  for (let i = 0; i < 120 && r.status !== 'Signed'; i += 1) {
    await new Promise((res) => setTimeout(res, 250));
    r = await views.request(v.vaultHex, request);
  }
  assert.equal(r.status, 'Signed', 'the held answer lands and signs');
});

test('propose, heartbeat, execute: the contract takes each, on the general key at the table\'s gas', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('flow');
  const { tx, request } = await propose(v);
  const proposed = await settled(tx);
  assert.deepEqual(attached(proposed), [['propose_btc', RELAY_METHODS.propose_btc.tgas]]);
  noteGas('propose_btc', proposed);

  const beat = await relay('main', 'heartbeat', { vault: v.vaultHex });
  assert.equal(beat.body.ok, true, beat.text);
  const beatResult = await settled(beat.body.hash);
  assert.deepEqual(attached(beatResult), [['heartbeat', 10]]);
  assert.equal(failureOf(beatResult), null);
  noteGas('heartbeat', beatResult);

  const nonceBefore = await keyNonce(stage.relay.publicKey);
  const again = await relay('main', 'activate', { vault: v.vaultHex });
  assert.deepEqual([again.status, again.body.code, again.body.message], [422, 'would_refuse', 'that vault is already active'], 'refused before the key signs');

  const r0 = await views.request(v.vaultHex, request);
  const early = await relay('main', 'execute', { vault: v.vaultHex, request });
  assert.deepEqual([early.status, early.body.code, early.body.message], [422, 'would_refuse', 'that request has not unlocked']);
  assert.ok(early.body.retry_after_s > 0);
  assert.equal(await keyNonce(stage.relay.publicKey), nonceBefore, 'neither was sent');

  // What the contract says to a stranger's stale or made-up proposal comes back in its own words, with no transaction.
  const busy = await relay('main', 'propose_btc', await proposeBody({ ...v, coinFrom: r0 }));
  assert.equal(busy.body.ok, false);
  assert.equal(busy.body.code, 'would_refuse');
  assert.match(busy.body.verbatim, /OutpointBusy|DoubleSpend|Busy/, busy.text);
  assert.equal(await keyNonce(stage.relay.publicKey), nonceBefore);
  const made = await relay('main', 'propose_btc', { ...(await proposeBody(v)), vault: 'ab'.repeat(32) });
  assert.equal(made.body.message, 'no such vault');

  for (let i = 0; i < 200; i += 1) {
    const now = (await reader.blockTime()).blockMs;
    if (now >= r0.unlock) break;
    await stage.near.sandboxFastForward(Math.min(Math.ceil((r0.unlock - now) / 500) + 5, 5000));
    await new Promise((res) => setTimeout(res, 300));
  }
  const fired = await relay('main', 'execute', { vault: v.vaultHex, request });
  assert.equal(fired.body.ok, true, fired.text);
  let r = r0;
  for (let i = 0; i < 120 && r.status !== 'Signed'; i += 1) {
    await new Promise((res) => setTimeout(res, 250));
    r = await views.request(v.vaultHex, request);
  }
  assert.equal(r.status, 'Signed', 'the contract signed through the mock signer');
  const executed = await settled(fired.body.hash);
  assert.deepEqual(attached(executed), [['execute', executeTgas(1, { signTgas: instance.sign_tgas, callbackTgas: instance.callback_tgas })]]);
  noteGas('execute (1 input, mock signer)', executed);
});

test('saturated general key: at its ceiling and refusing, a cancel_all_and_rotate still lands on the owner key, and the two states read differently', { skip, timeout: 90_000 }, async () => {
  const v = await makeVault('saturated');
  await adopt('low', v);
  const { request } = await propose(v, 'low');
  const s0 = await status('low');
  assert.deepEqual([s0.general.up, s0.general.why], [false, 'daily_ceiling'], 'a new vault no longer fits');
  assert.ok(s0.general.resets_at > Date.now());
  assert.deepEqual([s0.owner.up, s0.owner.why], [true, null]);
  for (let i = 0; i < 2; i += 1) {
    const beat = await relay('low', 'heartbeat', { vault: v.vaultHex });
    assert.equal(beat.body.ok, true);
    await settled(beat.body.hash);
  }
  const over = await relay('low', 'heartbeat', { vault: v.vaultHex });
  assert.equal(over.status, 429);
  assert.equal(over.body.code, 'daily_ceiling');
  assert.equal(over.body.bucket, 'general');
  assert.ok(over.body.resets_at > Date.now());
  const refusedCreate = await buildVault('never');
  assert.equal((await relay('low', 'create_vault', refusedCreate.args, { pow: await solvePow(refusedCreate.vaultHex, POW_BITS) })).body.code, 'daily_ceiling');

  const ownerBefore = await keyNonce(ownerKey.publicKey);
  const generalBefore = await keyNonce(stage.relay.publicKey);
  const burst = await Promise.all([
    relay('low', 'cancel_all_and_rotate', await rotateBody(v)),
    ...Array.from({ length: 12 }, () => relay('low', 'heartbeat', { vault: v.vaultHex })),
  ]);
  assert.equal(burst[0].body.ok, true, burst[0].text);
  assert.equal(burst[0].body.key, 'owner');
  assert.ok(burst.slice(1).every((o) => o.body.code === 'daily_ceiling'));
  assert.equal(await keyNonce(stage.relay.publicKey), generalBefore, 'the general key sent nothing');
  const result = await settled(burst[0].body.hash);
  assert.equal(failureOf(result), null);
  assert.deepEqual(attached(result), [['cancel_all_and_rotate', 30]]);
  assert.equal(result.transaction.public_key, ownerKey.publicKey);
  assert.ok(await keyNonce(ownerKey.publicKey) > ownerBefore);
  noteGas('cancel_all_and_rotate', result);
  const { vault, request: r } = await views.both(v.vaultHex, request);
  assert.equal(vault.k_s_suspended, true);
  const chainNow = (await reader.blockTime()).blockMs;
  assert.equal(requestState({ request: r, vault, chainNow, lastKnown: r }).kind, 'cancelled');
  const s1 = await status('low');
  assert.equal(s1.general.up, false);
  assert.equal(s1.owner.up, true);
});

test('a rate limit is its own answer: over the per-address limit, with a retry time and no bucket', { skip, timeout: 60_000 }, async () => {
  const ip = freshIp();
  const v = await buildVault('limited-1');
  for (let i = 0; i < RELAY_METHODS.heartbeat.perVaultMinute; i += 1) {
    assert.equal((await relay('main', 'heartbeat', { vault: canary.vaultHex }, { ip })).body.ok, true);
  }
  const byVault = await relay('main', 'heartbeat', { vault: canary.vaultHex }, { ip });
  assert.equal(byVault.status, 429);
  assert.equal(byVault.body.code, 'rate_limited');
  assert.equal(byVault.body.bucket, null);
  assert.ok(byVault.body.retry_after_s > 0 && byVault.body.retry_after_s <= 60);
  const ip2 = freshIp();
  for (let i = 0; i < RELAY_METHODS.create_vault.perIpHour; i += 1) {
    const each = await buildVault(`limited-${i + 2}`);
    const made = await relay('main', 'create_vault', each.args, { pow: await solvePow(each.vaultHex, POW_BITS), ip: ip2 });
    assert.equal(made.body.ok, true);
    await settled(made.body.hash);
  }
  const byIp = await relay('main', 'create_vault', v.args, { pow: await solvePow(v.vaultHex, POW_BITS), ip: ip2 });
  assert.equal(byIp.body.code, 'rate_limited');
  assert.ok(byIp.body.retry_after_s > 60);
  assert.equal((await relay('main', 'create_vault', v.args, { pow: await solvePow(v.vaultHex, POW_BITS) })).body.ok, true, 'another address goes through');
});

test('stale nonce: the key moved on the chain behind the relay\'s back. It re-signs and lands', { skip, timeout: 60_000 }, async () => {
  const v = await makeVault('stale');
  const fresh = new Near(stage.config.rpc, { timeoutMs: 30_000 });
  const before = await keyNonce(stage.relay.publicKey);
  for (let i = 0; i < 3; i += 1) {
    const out = await fresh.sendAndWait(stage.relay, stage.contract, [action.call('heartbeat', { vault: canary.vaultHex }, 10n * TGAS, 0n)]);
    assert.equal(failureOf(out.result), null);
  }
  assert.equal(await keyNonce(stage.relay.publicKey), before + 3);
  const out = await relay('main', 'heartbeat', { vault: v.vaultHex });
  assert.equal(out.body.ok, true, out.text);
  assert.ok(out.body.retries >= 1, `${out.text}: the first signature must have been refused`);
  const landed = await settled(out.body.hash);
  assert.equal(failureOf(landed), null);
  assert.ok(await keyNonce(stage.relay.publicKey) > before + 3);
});

test('concurrent general traffic: leases never repeat, and what arrives out of order re-signs and lands', { skip, timeout: 60_000 }, async (t) => {
  const vaults = await Promise.all([0, 1, 2, 3].map((i) => makeVault(`busy-${i}`)));
  const calls = vaults.flatMap((v) => [relay('main', 'heartbeat', { vault: v.vaultHex }), relay('main', 'heartbeat', { vault: v.vaultHex })]);
  const out = await Promise.all(calls);
  const retried = out.reduce((sum, o) => sum + (o.body.retries ?? 0), 0);
  t.diagnostic(`8 concurrent sends: ${out.filter((o) => o.body.ok).length} landed, ${retried} re-signs`);
  assert.ok(out.every((o) => o.body.ok === true), out.map((o) => o.text).join('\n'));
  assert.equal(new Set(out.map((o) => o.body.hash)).size, 8);
});

test('proof of work and guard are refused before the key signs', { skip, timeout: 60_000 }, async () => {
  const v = await buildVault('pow');
  const before = await keyNonce(stage.relay.publicKey);
  const none = await relay('main', 'create_vault', v.args);
  assert.equal(none.status, 400);
  assert.equal(none.body.code, 'pow_required');
  let bad = 0;
  while (checkPow(v.vaultHex, bad, POW_BITS)) bad += 1;
  const wrong = await relay('main', 'create_vault', v.args, { pow: bad });
  assert.equal(wrong.status, 400);
  assert.equal(wrong.body.code, 'pow_bad');
  const pow = await solvePow(v.vaultHex, POW_BITS);
  assert.equal((await relay('main', 'create_vault', { ...v.args, guard: stage.payer.accountId }, { pow })).body.code, 'wrong_guard');
  assert.equal(await keyNonce(stage.relay.publicKey), before);
  assert.equal(await views.vault(v.vaultHex), null);
});

test('off the list, or for another contract: refused, and the keys sign nothing', { skip, timeout: 30_000 }, async () => {
  const before = [await keyNonce(stage.relay.publicKey), await keyNonce(ownerKey.publicKey)];
  for (const method of ['set_policy', 'set_guard', 'add_destination', 'freeze', 'upgrade_propose', 'new', 'deposit_storage', '__proto__', 'constructor']) {
    const out = await relay('main', method, { vault: canary.vaultHex });
    assert.equal(out.status, 400);
    assert.equal(out.body.code, 'unknown_method', method);
  }
  const heartbeat = { method: 'heartbeat', args: { vault: canary.vaultHex } };
  for (const body of [
    { ...heartbeat, contract: stage.payer.accountId },
    { ...heartbeat, receiver_id: stage.payer.accountId },
    { ...heartbeat, receiverId: stage.payer.accountId },
    { ...heartbeat, gas: 300 },
    { ...heartbeat, deposit: '1' },
    { method: 'heartbeat', args: { vault: canary.vaultHex, contract: stage.payer.accountId } },
  ]) {
    const out = await post('main', '/api/relay', body);
    assert.equal(out.status, 400);
    assert.equal(out.body.code, 'bad_request', JSON.stringify(body));
  }
  const evil = await post('main', '/api/relay', heartbeat, { origin: 'https://evil.example' });
  assert.equal(evil.status, 403);
  assert.equal(evil.body.code, 'bad_origin');
  assert.deepEqual([await keyNonce(stage.relay.publicKey), await keyNonce(ownerKey.publicKey)], before);
});

test('junk cancels on a victim\'s vault: the owner key signs nothing, and the victim\'s real cancel goes straight through', { skip, timeout: 60_000 }, async () => {
  const v = await makeVault('victim');
  const { request } = await propose(v);
  const before = await keyNonce(ownerKey.publicKey);
  const good = await rotateBody(v);
  const stranger = softCredentials({ secret: label('stranger'), origin: stage.origin, rpId: stage.rpId });
  const digest = rotateDigest({ contract: stage.contract, vaultHex: v.vaultHex, newKs: fromHex(good.new_k_s), nonce: good.nonce, expiresAt: good.expires_at });
  const { args: forgedAssertion } = await getAssertion({ credentials: stranger, digest, rpId: stage.rpId });
  const forged = { ...good, assertion: forgedAssertion };
  for (let i = 0; i < 12; i += 1) {
    const out = await relay('main', 'cancel_all_and_rotate', forged);
    assert.equal(out.status, 422);
    assert.equal(out.body.code, 'assertion_refused');
  }
  assert.equal(await keyNonce(ownerKey.publicKey), before);
  const real = await relay('main', 'cancel_all_and_rotate', good);
  assert.equal(real.body.ok, true, real.text);
  assert.equal(failureOf(await settled(real.body.hash)), null);
  const replay = await relay('main', 'cancel_all_and_rotate', good);
  assert.equal(replay.body.code, 'assertion_refused', 'a used assertion is public on the chain, and is refused here');
  assert.equal(replay.body.message, 'passkey nonce already used');
  const { vault, request: r } = await views.both(v.vaultHex, request);
  assert.equal(requestState({ request: r, vault, chainNow: (await reader.blockTime()).blockMs, lastKnown: r }).kind, 'cancelled');
});

test('cancel: with the passkey, then with the cold key, both on the owner key', { skip, timeout: 60_000 }, async () => {
  const v = await makeVault('single');
  const { request } = await propose(v);
  const expiresAt = (await reader.blockTime()).blockMs + 10 * 60_000;
  const digest = cancelDigest({ contract: stage.contract, vaultHex: v.vaultHex, request, expiresAt });
  const { args: assertion } = await getAssertion({ credentials: v.soft, digest, rpId: stage.rpId, credentialId: v.made.credentialId });
  const out = await relay('main', 'cancel', cancelArgs({ vaultHex: v.vaultHex, request, expiresAt, assertion }));
  assert.equal(out.body.ok, true, out.text);
  const result = await settled(out.body.hash);
  assert.equal(failureOf(result), null);
  assert.equal(result.transaction.public_key, ownerKey.publicKey);
  noteGas('cancel (passkey)', result);
  assert.equal(await views.request(v.vaultHex, request), null);

  const second = await propose(v);
  const signed = signColdIntent({ cold: v.cold, contract: stage.contract, vault: v.vaultHex, method: 'cancel', fields: { request: second.request }, expiresAt });
  const cold = await relay('main', 'cancel', { vault: v.vaultHex, request: second.request, expires_at: expiresAt, auth: { Cold: signed.signature } });
  assert.equal(cold.body.ok, true, cold.text);
  const coldResult = await settled(cold.body.hash);
  assert.equal(failureOf(coldResult), null);
  noteGas('cancel (cold key)', coldResult);
  assert.equal(await views.request(v.vaultHex, second.request), null);
});

test('state store over its limit: a cancel still lands on a chain nonce and says degraded, general and funds say state_store_down', { skip, timeout: 60_000 }, async () => {
  const v = await makeVault('store-down');
  const { request } = await propose(v);
  const s = await status('broken');
  assert.deepEqual([s.owner.up, s.owner.degraded], [true, true]);
  assert.deepEqual([s.general.up, s.general.why], [false, 'state_store_down']);
  assert.deepEqual([s.funds.up, s.funds.why], [false, 'state_store_down']);
  const out = await relay('broken', 'cancel_all_and_rotate', await rotateBody(v));
  assert.equal(out.body.ok, true, out.text);
  assert.equal(out.body.degraded, true);
  assert.equal(failureOf(await settled(out.body.hash)), null);
  const { vault, request: r } = await views.both(v.vaultHex, request);
  assert.equal(requestState({ request: r, vault, chainNow: (await reader.blockTime()).blockMs, lastKnown: r }).kind, 'cancelled');
  const general = await relay('broken', 'heartbeat', { vault: v.vaultHex });
  assert.equal(general.status, 503);
  assert.equal(general.body.code, 'state_store_down');
  assert.equal((await funds('broken', v.vaultHex)).body.code, 'state_store_down');
});

test('funds: 2,000 sats on regtest to the contract\'s address, once. Limit, ceiling and empty each answer differently', { skip, timeout: 120_000 }, async (t) => {
  const v = await makeVault('funded');
  const vault = await views.vault(v.vaultHex);
  const ip = freshIp();
  const out = await funds('main', v.vaultHex, { ip });
  assert.equal(out.body.ok, true, out.text);
  assert.equal(out.body.value, 2000);
  assert.equal(out.body.broadcast.status, 200);
  assert.equal(out.body.broadcast.body, out.body.txid, 'the node\'s own answer');
  const coins = await (await fetch(`${stage.config.esplora}/address/${vault.address}/utxo`)).json();
  assert.deepEqual(coins.map((c) => [c.txid, c.vout, c.value]), [[out.body.txid, 0, 2000]]);
  const raw = await stage.rig.rpc('getrawtransaction', [out.body.txid, true]);
  t.diagnostic(`funding tx: ${raw.vsize} vB, ${raw.vout.length} outputs`);

  const again = await funds('main', v.vaultHex, { ip });
  assert.deepEqual([again.body.ok, again.body.txid, again.body.already], [true, out.body.txid, true]);
  assert.equal((await (await fetch(`${stage.config.esplora}/address/${vault.address}/utxo`)).json()).length, 1, 'no second coin');

  const second = await makeVault('funded-2');
  assert.equal((await funds('main', second.vaultHex, { ip })).body.ok, true);
  const third = await makeVault('funded-3');
  const limited = await funds('main', third.vaultHex, { ip });
  assert.equal(limited.status, 429);
  assert.equal(limited.body.code, 'rate_limited');
  assert.equal(limited.body.bucket, null);
  assert.ok(limited.body.retry_after_s > 0);
  assert.equal((await funds('main', third.vaultHex)).body.ok, true, 'another address goes through, on the change');

  // Same dispenser, another state store: it does not know main spent the coin, so a node refuses and it retries.
  const fourth = await makeVault('funded-4');
  await adopt('low', fourth);
  const low = await funds('low', fourth.vaultHex);
  assert.equal(low.body.ok, true, low.text);
  const fifth = await makeVault('funded-5');
  await adopt('low', fifth);
  const ceiling = await funds('low', fifth.vaultHex);
  assert.equal(ceiling.status, 429);
  assert.equal(ceiling.body.code, 'daily_ceiling');
  assert.equal(ceiling.body.bucket, 'funds');
  assert.ok(ceiling.body.resets_at > Date.now());
  assert.equal(ceiling.body.retry_after_s, null);
  assert.deepEqual([(await status('low')).funds.up, (await status('low')).funds.why], [false, 'daily_ceiling']);

  await adopt('poor', fifth);
  const empty = await funds('poor', fifth.vaultHex);
  assert.equal(empty.status, 503);
  assert.equal(empty.body.code, 'dispenser_empty');
  assert.deepEqual([(await status('poor')).funds.up, (await status('poor')).funds.why], [false, 'dispenser_empty']);
  assert.equal((await funds('main', 'ab'.repeat(32))).body.message, 'this relay only funds vaults it made');
  assert.equal((await post('main', '/api/funds', { vault: fifth.vaultHex, to: 'bcrt1qsomeoneelse' })).body.code, 'bad_request');

  stage.rig.setRule(({ method, path }) => (method === 'GET' && path.endsWith('/utxo') ? { status: 502, body: 'Bad Gateway' } : null));
  const sixth = await makeVault('funded-6');
  await adopt('poor', sixth);
  const down = await funds('poor', sixth.vaultHex);
  stage.rig.setRule(null);
  assert.equal(down.body.code, 'esplora_down');
  assert.equal(down.body.verbatim, 'Bad Gateway');
});

test('cron: the canary gets one heartbeat, on its own key, logged in the Durable Object', { skip, timeout: 60_000 }, async () => {
  const before = (await views.vault(canary.vaultHex)).last_heartbeat;
  const cron = await mf.getWorker('undo-cron');
  await cron.scheduled({ cron: '*/5 * * * *' });
  const ns = await mf.getDurableObjectNamespace('UNDO_STATE', 'undo-cron');
  const stub = ns.get(ns.idFromName('cron'));
  let beats = [];
  for (let i = 0; i < 60 && beats.length === 0; i += 1) {
    await new Promise((res) => setTimeout(res, 250));
    beats = (await (await stub.fetch('https://do/heartbeats', { method: 'POST', body: JSON.stringify({ vault: canary.vaultHex }) })).json()).beats;
  }
  assert.equal(beats.length, 1);
  const result = await settled(beats[0].hash);
  assert.equal(failureOf(result), null);
  assert.equal(result.transaction.public_key, cronKey.publicKey);
  assert.deepEqual(attached(result), [['heartbeat', 10]]);
  noteGas('heartbeat (cron)', result);
  for (let i = 0; i < 40 && (await views.vault(canary.vaultHex)).last_heartbeat === before; i += 1) await new Promise((res) => setTimeout(res, 250));
  assert.notEqual((await views.vault(canary.vaultHex)).last_heartbeat, before);
  const res = await cron.fetch('http://cron.test/heartbeats', { method: 'POST', body: '{}' });
  assert.equal(res.status, 404, 'the Worker answers nothing over HTTP');
  await res.text();
});

test('the stage serves the same relay class over its node:sqlite shim, so page tests get a real one', { skip, timeout: 30_000 }, async () => {
  const s = await (await fetch(`${stage.origin}/api/relay`)).json();
  assert.equal(s.ok, true);
  assert.equal(s.general.up, true);
  const v = await buildVault('via-stage');
  const res = await fetch(`${stage.origin}/api/relay`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', origin: stage.origin },
    body: JSON.stringify({ method: 'create_vault', args: v.args, pow: await solvePow(v.vaultHex, POW_BITS) }),
  });
  const out = await res.json();
  assert.equal(out.ok, true, JSON.stringify(out));
  assert.equal(failureOf(await settled(out.hash)), null);
  assert.equal((await views.vault(v.vaultHex)).active, true);
});

test('AUDIT-1, AUDIT-3: a vault made straight on the contract gets neither the owner key nor test coins, and its owner cancels from their own account with tools/cancel.mjs', { skip, timeout: 120_000 }, async () => {
  const v = await makeDirect('direct');
  const { request } = await propose(v);
  const ownerBefore = await keyNonce(ownerKey.publicKey);
  const body = await rotateBody(v);
  const refused = await relay('main', 'cancel_all_and_rotate', body);
  assert.deepEqual([refused.status, refused.body.code], [422, 'not_this_relays'], refused.text);
  assert.match(refused.body.message, /tools\/cancel\.mjs/);
  const cold = signColdIntent({ cold: v.cold, contract: stage.contract, vault: v.vaultHex, method: 'cancel', fields: { request }, expiresAt: body.expires_at });
  assert.equal((await relay('main', 'cancel', { vault: v.vaultHex, request, expires_at: body.expires_at, auth: { Cold: cold.signature } })).body.code, 'not_this_relays');
  assert.equal(await keyNonce(ownerKey.publicKey), ownerBefore, 'the owner key signed nothing');
  const coins = await funds('main', v.vaultHex);
  assert.deepEqual([coins.status, coins.body.code, coins.body.message], [422, 'would_refuse', 'this relay only funds vaults it made']);

  // The way that never needs the relay: the same signed body, from the payer's own account.
  const dir = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'undo-own-cancel-'));
  try {
    const file = join(dir, 'cancel.json');
    writeFileSync(file, JSON.stringify({ format: 'undo-owner-call-v1', contract: stage.contract, method: 'cancel_all_and_rotate', args: body }));
    const keyFile = join(stage.rig.info.creds, 'sandbox', `${stage.payer.accountId}.json`);
    const { NODE_USE_SYSTEM_CA: _unused, ...env } = process.env;
    const own = () => spawnSync(process.execPath, [join(REPO, 'tools/cancel.mjs'), '--file', file, '--account', stage.payer.accountId, '--key-file', keyFile, '--rpc', stage.config.rpc.join(','), '--yes'], { encoding: 'utf8', env, timeout: 60_000 });
    const run = own();
    assert.equal(run.status, 0, run.stdout + run.stderr);
    assert.match(run.stdout, /Sent\. The contract took it\./);
    assert.match(run.stdout, /The rotation landed/);
    const keyText = (({ private_key: a, secret_key: b }) => a ?? b)(JSON.parse(readFileSync(keyFile, 'utf8')));
    assert.ok(keyText && !(run.stdout + run.stderr).includes(keyText), 'it never prints the key');
    const again = own();
    assert.equal(again.status, 1, 'the same body twice is refused before it is sent');
    assert.match(again.stderr, /was used already/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  const { vault, request: r } = await views.both(v.vaultHex, request);
  assert.equal(vault.passkey_nonce, body.nonce + 1);
  assert.equal(requestState({ request: r, vault, chainNow: (await reader.blockTime()).blockMs, lastKnown: r }).kind, 'cancelled');
});

test('AUDIT-1: a body one nonce ahead goes once. The contract refuses it, and the relay will not send it again', { skip, timeout: 60_000 }, async () => {
  const v = await makeVault('ahead');
  const vault = await views.vault(v.vaultHex);
  const newKs = ed25519.getPublicKey(label('ahead-new-ks'));
  const expiresAt = (await reader.blockTime()).blockMs + 10 * 60_000;
  const nonce = vault.passkey_nonce + 1;
  const digest = rotateDigest({ contract: stage.contract, vaultHex: v.vaultHex, newKs, nonce, expiresAt });
  const { args: assertion } = await getAssertion({ credentials: v.soft, digest, rpId: stage.rpId, credentialId: v.made.credentialId });
  const body = rotateArgs({ vaultHex: v.vaultHex, newKs, nonce, expiresAt, assertion });
  const before = await keyNonce(ownerKey.publicKey);
  const first = await relay('main', 'cancel_all_and_rotate', body);
  assert.equal(first.body.ok, true, first.text);
  assert.match(String(failureOf(await settled(first.body.hash))), /nonce/i, 'the contract wants the exact nonce');
  for (let i = 0; i < 5; i += 1) assert.equal((await relay('main', 'cancel_all_and_rotate', body)).body.code, 'already_sent');
  assert.equal(await keyNonce(ownerKey.publicKey), before + 1, 'one send');
  const shaped = { ...body, assertion: { ...body.assertion, user_handle: '00' } };
  assert.equal((await relay('main', 'cancel_all_and_rotate', shaped)).body.code, 'bad_request', 'a field the contract lacks');
});

test('AUDIT-4: a relay that keeps its whole balance for cancels sends no general call, and the owner key still sends', { skip, timeout: 60_000 }, async () => {
  const v = await makeVault('reserve');
  await adopt('reserved', v);
  const s = await status('reserved');
  assert.deepEqual([s.general.up, s.general.why, s.owner.up], [false, 'relay_reserve', true]);
  const generalBefore = await keyNonce(stage.relay.publicKey);
  const beat = await relay('reserved', 'heartbeat', { vault: v.vaultHex });
  assert.deepEqual([beat.status, beat.body.code], [503, 'relay_reserve'], beat.text);
  assert.equal(await keyNonce(stage.relay.publicKey), generalBefore, 'the general key signed nothing');
  const { request } = await propose(v);
  const out = await relay('reserved', 'cancel_all_and_rotate', await rotateBody(v));
  assert.equal(out.body.ok, true, out.text);
  assert.equal(failureOf(await settled(out.body.hash)), null);
  const { vault, request: r } = await views.both(v.vaultHex, request);
  assert.equal(requestState({ request: r, vault, chainNow: (await reader.blockTime()).blockMs, lastKnown: r }).kind, 'cancelled');
});

test('measured gas, local, mock signer', { skip }, (t) => {
  for (const [method, line] of Object.entries(gas)) t.diagnostic(`${method}: ${line}`);
  assert.ok(Object.keys(gas).length >= 6);
});
