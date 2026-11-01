// The relay, offline: the same Durable Object class over node:sqlite, the same handler with a fake chain and a fake
// Esplora in place of fetch. relay.workerd.test.mjs runs it for real, in workerd against a local node.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { p2wpkhSpk } from '../../tools/lib/btc.mjs';
import { base58Encode, fromBase64, fromHex, toHex, utf8 } from '../../tools/lib/bytes.mjs';
import { signColdIntent } from '../../tools/lib/cold-intent.mjs';
import { ed25519, p256, secp256k1, sha256 } from '../../tools/lib/crypto.mjs';
import { buildFunding as originalFunding, parseDispenser } from '../../tools/lib/dispenser.mjs';
import { coldKeys } from '../../tools/lib/keys.mjs';
import { action, keyFromSecret, milliNear, signTransaction, TGAS } from '../../tools/lib/near.mjs';
import { canaryBeat } from '../../worker/undo-cron/src/index.mjs';
import { UndoState } from '../../worker/undo-cron/src/undo-state.mjs';
import { limitAddress, workerFetch } from '../functions/_relay/answer.mjs';
import { buildFunding, dispenserFromSecret } from '../functions/_relay/funding.mjs';
import { makeRelay } from '../functions/_relay/handler.mjs';
import { p256Uncompressed } from '../functions/_relay/owner-check.mjs';
import { StateClient } from '../functions/_relay/state-client.mjs';
import { cancelArgs, cancelDigest, rotateArgs, rotateDigest } from '../lib/intents.mjs';
import { CEILING_OWNER_DEFAULT_MICRO, CREATE_SHARE, OWNER_ALLOWANCE_NEAR, ownerAllowanceNeeded, RELAY_METHODS } from '../lib/relay-table.mjs';
import { RelayClient } from '../lib/relay-client.mjs';
import { softCredentials } from '../lib/soft-authenticator.mjs';
import { createPasskey, getAssertion } from '../lib/webauthn.mjs';
import { localStateNamespace, localStorage } from './do-shim.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const SITE = resolve(HERE, '..');
const REPO = resolve(SITE, '..');
const label = (t) => sha256(utf8(`undo-test-only:relay:${t}`));
const CONTRACT = 'film.test.near';
const ACCOUNT = 'relay.test.near';
const secretText = (t) => `ed25519:${base58Encode(label(t))}`;
const GENERAL = keyFromSecret(label('general'));
const OWNER = keyFromSecret(label('owner'));
const VAULT = toHex(label('vault'));
const NOW = Date.UTC(2026, 10, 1, 12, 0, 0);
const BLOCK = base58Encode(label('block'));
const ESPLORA = 'http://esplora.test';
const RPC = 'http://rpc.test';
const POLICY = { t_known_ms: 60_000, t_new_ms: 300_000, t_new_unguarded_ms: 600_000, hold_ms: 300_000, t_stuck_ms: 900_000, fee_cap_tx: 1000, fee_budget_24h: 2000, outflow_cap_24h: 1_000_000 };
const BEAT = 'undo-test-only:beat';

// ---------------------------------------------------------------- what a signed transaction says

function decodeTx(base64) {
  const bytes = fromBase64(base64);
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let at = 0;
  const u32 = () => {
    at += 4;
    return view.getUint32(at - 4, true);
  };
  const u64 = () => {
    at += 8;
    return view.getBigUint64(at - 8, true);
  };
  const str = () => {
    const n = u32();
    at += n;
    return new TextDecoder().decode(bytes.slice(at - n, at));
  };
  const signerId = str();
  at += 1;
  const pub = bytes.slice(at, at + 32);
  at += 32;
  const nonce = u64();
  const receiverId = str();
  at += 32;
  const count = u32();
  const actions = [];
  for (let i = 0; i < count; i += 1) {
    assert.equal(bytes[at], 2, 'only function calls');
    at += 1;
    const method = str();
    const n = u32();
    const args = JSON.parse(new TextDecoder().decode(bytes.slice(at, at + n)));
    at += n;
    const gas = u64();
    at += 16;
    const deposit = view.getBigUint64(at - 16, true);
    actions.push({ method, args, tgas: Number(gas / TGAS), depositLow: deposit });
  }
  return { signerId, pub: toHex(pub), nonce: Number(nonce), receiverId, actions };
}

// ---------------------------------------------------------------- a fake chain and a fake Esplora

function fakeWorld({ vaults = {}, requests = {} } = {}) {
  const w = {
    nonces: new Map(),
    sent: [],
    included: new Set(),
    invalidNonceTimes: 0,
    expiredTimes: 0,
    dropSends: 0,
    landedButDropped: false,
    refuseWith: null,
    rpcDown: false,
    viewDown: false,
    utxos: [],
    vaultCoins: {},
    accessKeys: {},
    account: { amount: `${10n ** 25n}`, storage_usage: 182 },
    posts: [],
    postRule: null,
    utxoStatus: 200,
    reads: 0,
    sends: () => w.sent.map((s) => decodeTx(s)),
  };
  const nonceOf = (pub) => w.nonces.get(pub) ?? 100;
  const ok = (result) => new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }));
  const err = (error, status = 200) => new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, error }), { status });
  const invalid = (data) => err({ name: 'HANDLER_ERROR', code: -32000, message: 'Server error', cause: { name: 'INVALID_TRANSACTION', info: {} }, data: { TxExecutionError: { InvalidTxError: data } } });
  w.fetchFn = async (url, init = {}) => {
    if (String(url).startsWith(ESPLORA)) {
      const path = String(url).slice(ESPLORA.length);
      if (path === '/tx') {
        w.posts.push(init.body);
        const rule = w.postRule?.(init.body) ?? null;
        if (rule) return new Response(rule.body, { status: rule.status });
        const txid = w.lastBuiltTxid(init.body);
        return new Response(txid);
      }
      if (path.endsWith('/utxo')) {
        if (w.utxoStatus !== 200) return new Response('Bad Gateway', { status: w.utxoStatus });
        // A vault's own coins, as against the dispenser's.
        const vaultCoins = w.vaultCoins[path.split('/')[2]];
        return new Response(JSON.stringify(vaultCoins ?? (path.includes('vault-address') ? [] : w.utxos)));
      }
      return new Response('Transaction not found', { status: 404 });
    }
    if (w.rpcDown) throw new TypeError('network');
    const { method, params } = JSON.parse(init.body);
    if (method === 'block') return ok({ header: { hash: BLOCK, height: 1000, timestamp_nanosec: `${NOW}000000` } });
    if (method === 'query' && params.request_type === 'view_access_key') {
      const pub = params.public_key;
      return ok({ nonce: nonceOf(pub), block_height: 1000, permission: 'FullAccess', ...w.accessKeys[pub] });
    }
    if (method === 'query' && params.request_type === 'view_account') return ok({ block_height: 1000, ...w.account });
    if (method === 'query') {
      w.reads += 1;
      if (w.viewDown) throw new TypeError('network');
      const args = JSON.parse(new TextDecoder().decode(fromBase64(params.args_base64)));
      const value = params.method_name === 'vault' ? (vaults[args.vault] ?? null)
        : params.method_name === 'request' ? (requests[args.request] ?? null)
          : params.method_name === 'instance' ? { sign_tgas: 30, callback_tgas: 10, policy: POLICY }
            : params.method_name === 'check_propose' ? { tier: 'New', delay_ms: 300_000, fee: 300, unguarded: false } : null;
      if (w.viewRefuses?.[params.method_name]) return ok({ error: w.viewRefuses[params.method_name], logs: [], block_height: 1000 });
      return ok({ result: [...utf8(JSON.stringify(value))], block_height: 1000, logs: [] });
    }
    if (method === 'send_tx') {
      w.sent.push(params.signed_tx_base64);
      if (w.dropSends > 0) {
        w.dropSends -= 1;
        if (w.landedButDropped) w.included.add(params.signed_tx_base64);
        return err({ name: 'HANDLER_ERROR', cause: { name: 'TIMEOUT_ERROR' } }, 408);
      }
      if (w.refuseWith) return invalid(w.refuseWith);
      if (w.expiredTimes > 0) {
        w.expiredTimes -= 1;
        return invalid({ Expired: null });
      }
      const tx = decodeTx(params.signed_tx_base64);
      const pub = `ed25519:${base58Encode(fromHex(tx.pub))}`;
      if (w.invalidNonceTimes > 0 || tx.nonce <= nonceOf(pub)) {
        if (w.invalidNonceTimes > 0) w.invalidNonceTimes -= 1;
        w.nonces.set(pub, Math.max(nonceOf(pub), tx.nonce));
        return invalid({ InvalidNonce: { ak_nonce: nonceOf(pub), tx_nonce: tx.nonce } });
      }
      w.nonces.set(pub, tx.nonce);
      w.included.add(params.signed_tx_base64);
      return ok({ final_execution_status: 'INCLUDED' });
    }
    if (method === 'tx') {
      return w.included.size && [...w.included].some((b) => signTxHash(b) === params.tx_hash) ? ok({ final_execution_status: 'INCLUDED' }) : err({ name: 'HANDLER_ERROR', cause: { name: 'UNKNOWN_TRANSACTION' } });
    }
    throw new Error(`no fake for ${method}`);
  };
  return w;
}

// The hash a signed transaction was signed over: its bytes up to the signature.
function signTxHash(base64) {
  const bytes = fromBase64(base64);
  return base58Encode(sha256(bytes.slice(0, bytes.length - 65)));
}

function relayWith(world, extra = {}) {
  const ns = extra.UNDO_STATE ?? localStateNamespace();
  const env = {
    CONTRACT_ID: CONTRACT,
    RELAY_ACCOUNT: ACCOUNT,
    NEAR_RPC_URLS: RPC,
    ESPLORA_URL: ESPLORA,
    RELAY_GENERAL_KEY: secretText('general'),
    RELAY_OWNER_KEY: secretText('owner'),
    DISPENSER_SECRET: toHex(label('dispenser')),
    DISPENSER_NETWORK: 'regtest',
    IP_SALT: 'undo-test-only:salt',
    POW_BITS: 0,
    STATUS_CACHE_MS: 0,
    KEY_CACHE_MS: 0,
    BEAT_TOKEN: BEAT,
    UNDO_STATE: ns,
    ...extra,
  };
  const handler = makeRelay(env, { fetchFn: world.fetchFn, nowFn: () => world.now ?? NOW });
  const post = async (path, body, { ip = '198.51.100.7', origin = null, raw = null, beat = BEAT } = {}) => {
    const headers = { 'content-type': 'application/json', 'cf-connecting-ip': ip };
    if (origin) headers.origin = origin;
    if (beat) headers['x-undo-beat'] = beat;
    const res = await handler(new Request(`https://site.test${path}`, { method: 'POST', headers, body: raw ?? JSON.stringify(body) }));
    return { status: res.status, cache: res.headers.get('cache-control'), body: await res.json() };
  };
  return {
    env,
    ns,
    relay: (method, args, opts = {}) => post('/api/relay', opts.pow === undefined ? { method, args } : { method, args, pow: opts.pow }, opts),
    funds: (vault, opts) => post('/api/funds', { vault, pow: 0 }, opts),
    post,
    status: async () => {
      const res = await handler(new Request('https://site.test/api/relay'));
      return { status: res.status, body: await res.json() };
    },
    state: new StateClient(ns),
  };
}

const passkey = await (async () => {
  const soft = softCredentials({ secret: label('passkey'), origin: 'https://site.test', rpId: 'site.test' });
  const made = await createPasskey({ credentials: soft, rpId: 'site.test' });
  return { soft, made, hex: toHex(made.pubkey) };
})();

const vaultRow = (over = {}) => ({ passkey: passkey.hex, passkey_nonce: 3, k_e_intent: null, active: true, script_pubkey: `0020${toHex(label('spk'))}`, guard: ACCOUNT, address: 'vault-address', spend_epoch: 2, spend_nonce: 0, k_s: toHex(ed25519.getPublicKey(label('ks'))), ...over });
const requestRow = (over = {}) => ({ inputs: [{}], status: 'Pending', epoch: 2, unlock: NOW - 1000, expires_at: NOW + 3_600_000, ...over });

async function rotateBody({ nonce = 3, digestNonce = nonce, soft = passkey.soft } = {}) {
  const newKs = ed25519.getPublicKey(label('new-ks'));
  const digest = rotateDigest({ contract: CONTRACT, vaultHex: VAULT, newKs, nonce: digestNonce, expiresAt: NOW + 60_000 });
  const { args } = await getAssertion({ credentials: soft, digest, rpId: 'site.test' });
  return rotateArgs({ vaultHex: VAULT, newKs, nonce, expiresAt: NOW + 60_000, assertion: args });
}

// ---------------------------------------------------------------- state store

test('state: a ceiling and a rate limit are different answers, and a refusal counts nothing', async () => {
  const state = new StateClient(localStateNamespace());
  const ask = (over = {}) => state.call('charge', { key: 'general', method: 'propose_btc', ipHash: 'a', vault: VAULT, now: NOW, ceiling: 100_000, ...over });
  for (let i = 0; i < RELAY_METHODS.propose_btc.perIpHour; i += 1) assert.equal((await ask()).ok, true);
  const limited = await ask();
  assert.equal(limited.code, 'rate_limited');
  assert.equal(limited.retry_after_s, 3600);
  assert.equal(limited.bucket, undefined);
  assert.equal((await ask({ ipHash: 'b' })).ok, true, 'another address is not limited by the first');
  assert.equal((await ask({ ipHash: 'a', now: NOW + 3_600_000 })).ok, true, 'a new hour starts over');
  const over = await ask({ ipHash: 'c', ceiling: 1 });
  assert.equal(over.code, 'daily_ceiling');
  assert.equal(over.bucket, 'general');
  assert.equal(over.resets_at, Date.UTC(2026, 10, 2));
  const status = await state.call('status', { now: NOW + 3_600_000 });
  assert.equal(status.spent.general, 12 * RELAY_METHODS.propose_btc.costMicro);
  assert.equal((await ask({ ipHash: 'c', ceiling: 13 * RELAY_METHODS.propose_btc.costMicro, now: NOW + 3_600_000 })).ok, true);
  assert.equal((await ask({ ipHash: 'd', now: NOW + 86_400_000, ceiling: RELAY_METHODS.propose_btc.costMicro })).ok, true, 'a new UTC day starts the ceiling over');
});

test('state: a method on the wrong key is refused; owner methods take a limit per vault and none per address', async () => {
  const state = new StateClient(localStateNamespace());
  assert.equal((await state.call('charge', { key: 'owner', method: 'propose_btc', now: NOW, ceiling: 1e9 })).code, 'bad_request');
  assert.equal((await state.call('charge', { key: 'general', method: 'cancel', now: NOW, ceiling: 1e9 })).code, 'bad_request');
  assert.equal((await state.call('charge', { key: 'general', method: 'set_policy', now: NOW, ceiling: 1e9 })).code, 'bad_request');
  const cancel = (vault) => state.call('charge', { key: 'owner', method: 'cancel_all_and_rotate', vault, now: NOW, ceiling: 1e9 });
  for (let i = 0; i < 6; i += 1) assert.equal((await cancel(VAULT)).ok, true);
  const seventh = await cancel(VAULT);
  assert.equal(seventh.code, 'rate_limited');
  assert.equal(seventh.retry_after_s, 60);
  assert.equal((await cancel('other')).ok, true);
});

test('state: nonce rows are per key, seed and reset only move forward, concurrent leases never repeat', async () => {
  const state = new StateClient(localStateNamespace());
  const a = { id: 'a' };
  const b = { id: 'b' };
  assert.deepEqual(await state.lease(a), { need_chain: true });
  assert.equal((await state.seed(a, 500, NOW)).nonce, 501);
  assert.equal((await state.lease(a)).nonce, 502);
  assert.deepEqual(await state.lease(b), { need_chain: true }, 'another key has its own row');
  const many = await Promise.all(Array.from({ length: 20 }, () => state.lease(a)));
  assert.equal(new Set(many.map((m) => m.nonce)).size, 20);
  assert.equal((await state.reset(a, 900, NOW)).nonce, 901);
  assert.equal((await state.reset(a, 10, NOW)).nonce, 902, 'a stale answer cannot move it back');
});

test('state: a coin is leased to one funding, comes back after its lease, and a spent one stays spent', async () => {
  const state = new StateClient(localStateNamespace());
  const coin = (txid, value) => ({ txid: txid.repeat(64), vout: 0, value });
  await state.call('addCoins', { coins: [coin('a', 5000), coin('b', 50_000)], now: NOW });
  const first = await state.call('reserveCoin', { need: 3000, now: NOW });
  assert.equal(first.coins[0].value, 5000, 'smallest that covers it');
  const second = await state.call('reserveCoin', { need: 3000, now: NOW });
  assert.equal(second.coins[0].value, 50_000, 'not the one already leased');
  assert.equal((await state.call('reserveCoin', { need: 3000, now: NOW })).code, 'dispenser_empty');
  const later = await state.call('reserveCoin', { need: 3000, now: NOW + 60_000 });
  assert.equal(later.coins[0].value, 5000, 'a lease runs out');
  await state.call('commitCoin', { coins: later.coins, change: { txid: 'c'.repeat(64), vout: 1, value: 2500 } });
  await state.call('addCoins', { coins: [coin('a', 5000)], now: NOW + 60_000 });
  const free = await state.call('status', { now: NOW + 120_000 });
  assert.equal(free.coins.free_sats, 52_500, 'spent stays spent; change is free; the other lease ran out');
  await state.call('releaseCoin', { coins: second.coins, gone: true });
  assert.equal((await state.call('status', { now: NOW + 120_000 })).coins.free_sats, 2500);
  const split = await state.call('reserveCoin', { need: 2000, perInput: 100, now: NOW + 120_000 });
  assert.equal(split.coins.length, 1);
});

test('state: one funding per vault. Limit, ceiling and claim are one step, and a lost answer can be asked again', async () => {
  const state = new StateClient(localStateNamespace());
  const ask = (vault, over = {}) => state.call('funded', { vault, ipHash: 'a', sats: 2000, ceiling: 40_000, now: NOW, ...over });
  assert.deepEqual(await ask('v1'), { ok: true, already: false });
  const inFlight = await ask('v1');
  assert.equal(inFlight.code, 'rate_limited');
  assert.equal(inFlight.retry_after_s, 120);
  assert.deepEqual(await ask('v1', { now: NOW + 120_000 }), { ok: true, already: false }, 'a claim nobody finished runs out');
  assert.equal((await state.call('status', { now: NOW })).spent.funds, 2000, 'and is not charged twice');
  await state.call('fundedDone', { vault: 'v1', txid: 'aa', now: NOW });
  assert.deepEqual(await ask('v1'), { ok: true, already: true, txid: 'aa' });
  assert.equal((await ask('v2')).ok, true);
  assert.equal((await ask('v3')).code, 'rate_limited', 'two per hour per address');
  assert.equal((await ask('v3', { ipHash: 'b', ceiling: 4000 })).code, 'daily_ceiling');
  await state.call('fundedDrop', { vault: 'v2', sats: 2000, now: NOW });
  assert.equal((await ask('v3', { ipHash: 'b', ceiling: 4000 })).ok, true, 'a funding that moved nothing gives its sats back');
});

test('state: tables are the design\'s, old counts are pruned, and only a hash of an address is ever stored', async () => {
  const object = new UndoState({ storage: localStorage() }, {});
  const tables = object.sql.exec("SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name").toArray().map((r) => r.name);
  assert.deepEqual(tables, ['alert_state', 'daily_ceiling', 'dispenser_utxos', 'funded_vaults', 'heartbeat_log', 'ip_counter', 'nonce_lease', 'vault_counter']);
  const op = async (name, body) => (await object.fetch(new Request(`https://do/${name}`, { method: 'POST', body: JSON.stringify(body) }))).json();
  assert.equal((await object.fetch(new Request('https://do/nothing', { method: 'POST', body: '{}' }))).status, 404);
  const charge = (now) => op('charge', { key: 'general', method: 'heartbeat', ipHash: 'hash-only', vault: VAULT, now, ceiling: 1e6 });
  await charge(NOW);
  assert.equal(object.sql.exec('SELECT COUNT(*) AS n FROM ip_counter').toArray()[0].n, 1);
  await charge(NOW + 3 * 3_600_000);
  assert.equal(object.sql.exec('SELECT COUNT(*) AS n FROM ip_counter').toArray()[0].n, 1, 'the old hour is gone');
  assert.equal(object.sql.exec('SELECT ip_hash FROM ip_counter').toArray()[0].ip_hash, 'hash-only');
});

// ---------------------------------------------------------------- handler: refusals that cost nothing

test('relay: the body names a method from the list and nothing else. No state touched, no RPC asked', async () => {
  const world = fakeWorld();
  const r = relayWith(world);
  const heartbeat = { vault: VAULT };
  const cases = [
    [{ method: 'set_policy', args: heartbeat }, 'unknown_method'],
    [{ method: 'upgrade_propose', args: {} }, 'unknown_method'],
    [{ method: 'constructor', args: {} }, 'unknown_method'],
    [{ method: '__proto__', args: {} }, 'unknown_method'],
    [{ method: 'heartbeat', args: heartbeat, contract: 'other.near' }, 'bad_request'],
    [{ method: 'heartbeat', args: heartbeat, receiver_id: 'other.near' }, 'bad_request'],
    [{ method: 'heartbeat', args: heartbeat, gas: 300 }, 'bad_request'],
    [{ method: 'heartbeat', args: { ...heartbeat, receiver_id: 'other.near' } }, 'bad_request'],
    [{ method: 'heartbeat', args: { vault: 'nope' } }, 'bad_request'],
    [{ method: 'create_vault', args: {} }, 'bad_request'],
    [[], 'bad_request'],
    ['x', 'bad_request'],
  ];
  for (const [body, code] of cases) {
    const out = await r.post('/api/relay', body);
    assert.equal(out.body.code, code, JSON.stringify(body));
    assert.equal(out.status, 400);
    assert.equal(out.body.ok, false);
    for (const field of ['message', 'verbatim', 'retry_after_s', 'bucket', 'resets_at']) assert.ok(field in out.body);
  }
  assert.equal(world.sent.length, 0);
  assert.equal(world.reads, 0);
  assert.equal(r.ns.calls.length, 0);
});

test('relay: origin, body size and shape come before anything else, and no answer carries CORS', async () => {
  const world = fakeWorld();
  const r = relayWith(world);
  const hb = { method: 'heartbeat', args: { vault: VAULT } };
  const evil = await r.post('/api/relay', hb, { origin: 'https://evil.example' });
  assert.equal(evil.status, 403);
  assert.equal(evil.body.code, 'bad_origin');
  const evilFunds = await r.post('/api/funds', { vault: VAULT }, { origin: 'https://evil.example' });
  assert.equal(evilFunds.body.code, 'bad_origin');
  assert.equal((await r.post('/api/relay', hb, { origin: 'https://site.test' })).body.ok, true);
  assert.equal((await r.post('/api/relay', hb)).body.ok, true, 'no Origin, as from demo.sh, is allowed');
  const big = await r.post('/api/relay', null, { raw: `{"method":"heartbeat","pad":"${'x'.repeat(30 * 1024)}"}` });
  assert.equal(big.status, 400);
  assert.equal(big.body.message, 'the body is too large');
  assert.equal((await r.post('/api/relay', null, { raw: '{not json' })).body.code, 'bad_request');
  const res = await makeRelay(r.env, {})(new Request('https://site.test/api/relay', { method: 'OPTIONS' }));
  assert.equal(res.status, 405);
  assert.equal(res.headers.get('access-control-allow-origin'), null);
  const site = relayWith(fakeWorld(), { SITE_ORIGIN: 'https://undo.example' });
  assert.equal((await site.relay('heartbeat', { vault: VAULT }, { origin: 'https://site.test' })).body.code, 'bad_origin');
});

test('relay: a missing binding says so. No fallback values, and a cancel needs only its own key', async () => {
  const world = fakeWorld();
  const bare = relayWith(world, { CONTRACT_ID: undefined });
  assert.equal((await bare.status()).status, 503);
  assert.equal((await bare.status()).body.code, 'relay_not_configured');
  const client = new RelayClient({ relay: 'https://site.test/api/relay', funds: 'https://site.test/api/funds', fetchFn: (url, init) => makeRelay(bare.env)(new Request(url, init)) });
  const said = await client.status();
  assert.equal(said.reachable, false);
  assert.equal(said.why, 'relay_not_configured');

  const noGeneral = relayWith(world, { RELAY_GENERAL_KEY: undefined, DISPENSER_SECRET: undefined });
  const s = (await noGeneral.status()).body;
  assert.equal(s.owner.up, true);
  assert.deepEqual([s.general.up, s.general.why], [false, 'relay_not_configured']);
  assert.deepEqual([s.funds.up, s.funds.why], [false, 'relay_not_configured']);
  assert.equal((await noGeneral.relay('heartbeat', { vault: VAULT })).body.code, 'relay_not_configured');
  assert.equal((await noGeneral.funds(VAULT)).body.code, 'relay_not_configured');
  const noOwner = relayWith(world, { RELAY_OWNER_KEY: undefined });
  assert.deepEqual([(await noOwner.status()).body.owner.up, (await noOwner.status()).body.owner.why], [false, 'relay_not_configured']);
  const badKey = relayWith(world, { RELAY_GENERAL_KEY: 'ed25519:notakey0OIl' });
  const refused = await badKey.relay('heartbeat', { vault: VAULT });
  assert.equal(refused.body.code, 'relay_not_configured');
  assert.ok(!JSON.stringify(refused.body).includes('notakey'));
});

// ---------------------------------------------------------------- handler: what gets sent

test('relay: the transaction is the relay\'s own: exact gas, this contract, and the bytes tools/lib/near.mjs makes', async () => {
  const world = fakeWorld();
  const r = relayWith(world);
  const out = await r.relay('heartbeat', { vault: VAULT });
  assert.deepEqual(out.body, { ok: true, hash: out.body.hash, key: 'general', method: 'heartbeat' });
  assert.equal(out.cache, 'no-store');
  const tx = decodeTx(world.sent[0]);
  assert.equal(tx.receiverId, CONTRACT);
  assert.equal(tx.signerId, ACCOUNT);
  assert.equal(tx.pub, toHex(GENERAL.pub));
  assert.deepEqual(tx.actions.map((a) => [a.method, a.tgas]), [['heartbeat', 10]]);
  assert.equal(tx.nonce, 101, 'seeded from the chain');
  const same = signTransaction({ signerId: ACCOUNT, key: GENERAL, nonce: 101n, receiverId: CONTRACT, blockHash: label('block'), actions: [action.call('heartbeat', { vault: VAULT }, 10n * TGAS, 0n)] });
  assert.equal(world.sent[0], same.base64, 'WebCrypto and noble sign the same bytes');
  assert.equal(out.body.hash, same.hash);
  assert.equal((await r.relay('heartbeat', { vault: VAULT })).body.ok, true);
  assert.equal(decodeTx(world.sent[1]).nonce, 102, 'the next comes from the lease, with no chain read');
});

test('relay: execute reads its input count and takes the gas that count needs, and refuses a request that does not exist', async () => {
  const world = fakeWorld({ vaults: { [VAULT]: vaultRow() }, requests: { 7: requestRow({ inputs: [{}, {}, {}] }) } });
  const r = relayWith(world);
  assert.equal((await r.relay('execute', { vault: VAULT, request: 7 })).body.ok, true);
  assert.deepEqual(decodeTx(world.sent[0]).actions.map((a) => [a.method, a.tgas]), [['execute', 3 * (30 + 10 + 4) + 6]]);
  const none = await r.relay('execute', { vault: VAULT, request: 8 });
  assert.equal(none.body.code, 'bad_request');
  assert.equal(world.sent.length, 1);
  assert.equal((await r.state.call('status', { now: NOW })).spent.general, 3 * RELAY_METHODS.execute.costMicro, 'three inputs cost three, and the refused one nothing');
});

test('relay: create_vault checks guard and proof of work before any cost, and sends create and heartbeat in one batch', async () => {
  const world = fakeWorld();
  const r = relayWith(world, { POW_BITS: 8 });
  const soft = softCredentials({ secret: label('c'), origin: 'https://site.test', rpId: 'site.test' });
  const made = await createPasskey({ credentials: soft, rpId: 'site.test' });
  const { buildCreateArgs, newVaultKeys, rpIdHashOf } = await import('../lib/intents.mjs');
  const { checkPow, solvePow } = await import('../lib/pow.mjs');
  const keys = newVaultKeys({ seed: label('seed'), cold: label('cold') });
  const built = await buildCreateArgs({
    contract: CONTRACT, keys, passkeyPub: made.pubkey, rpIdHash: rpIdHashOf('site.test'), km: secp256k1.getPublicKey(label('km'), true), guard: ACCOUNT, policy: POLICY, csv: 6, expiresAt: NOW + 60_000,
    assert: async (digest) => (await getAssertion({ credentials: soft, digest, rpId: 'site.test' })).args,
  });
  const noPow = await r.relay('create_vault', built.args);
  assert.equal(noPow.body.code, 'pow_required');
  let wrong = 0;
  while (checkPow(built.vaultHex, wrong, 8)) wrong += 1;
  assert.equal((await r.relay('create_vault', built.args, { pow: wrong })).body.code, 'pow_bad');
  const pow = await solvePow(built.vaultHex, 8);
  assert.equal((await r.relay('create_vault', { ...built.args, guard: 'someone.else' }, { pow })).body.code, 'wrong_guard');
  assert.equal(world.sent.length, 0);
  assert.equal(r.ns.calls.length, 0, 'none of those touched the state store');
  const out = await r.relay('create_vault', built.args, { pow });
  assert.equal(out.body.ok, true);
  const tx = decodeTx(world.sent[0]);
  assert.deepEqual(tx.actions.map((a) => [a.method, a.tgas]), [['create_vault', 120], ['heartbeat', 10]]);
  assert.deepEqual(tx.actions[0].args, { args: built.args });
  assert.deepEqual(tx.actions[1].args, { vault: built.vaultHex });
  assert.equal(tx.actions[0].depositLow, milliNear(30) & 0xffffffffffffffffn);
});

test('relay: a stale nonce re-signs with the node\'s number, up to twice, and then says so and gives the charge back', async () => {
  const world = fakeWorld({ vaults: { [VAULT]: vaultRow() }, requests: { 1: requestRow() } });
  const r = relayWith(world);
  world.nonces.set(GENERAL.publicKey, 100);
  assert.equal((await r.relay('heartbeat', { vault: VAULT })).body.ok, true);
  world.nonces.set(GENERAL.publicKey, 5000);
  const out = await r.relay('heartbeat', { vault: VAULT });
  assert.equal(out.body.ok, true);
  assert.equal(out.body.retries, 1);
  assert.equal(decodeTx(world.sent.at(-1)).nonce, 5001);
  world.invalidNonceTimes = 3;
  const spentBefore = (await r.state.call('status', { now: NOW })).spent.general;
  const gone = await r.relay('execute', { vault: VAULT, request: 1 });
  assert.equal(gone.status, 503);
  assert.equal(gone.body.code, 'stale_nonce');
  assert.ok(gone.body.verbatim.includes('InvalidNonce'), 'the node\'s words');
  assert.equal((await r.state.call('status', { now: NOW })).spent.general, spentBefore);
  world.expiredTimes = 1;
  const again = await r.relay('heartbeat', { vault: 'cd'.repeat(32) });
  assert.equal(again.body.ok, true);
  assert.equal(again.body.retries, 1);
});

test('relay: a timeout never re-signs. Same bytes, and if nothing is known the answer says unknown', async () => {
  const world = fakeWorld();
  const r = relayWith(world);
  world.dropSends = 1;
  world.landedButDropped = true;
  const landed = await r.relay('heartbeat', { vault: VAULT });
  assert.equal(landed.body.ok, true);
  assert.equal(landed.body.state, undefined);
  assert.equal(world.sent.length, 1, 'a look at the hash answered it');

  const world2 = fakeWorld();
  const r2 = relayWith(world2);
  world2.dropSends = 2;
  const resent = await r2.relay('heartbeat', { vault: VAULT });
  assert.equal(resent.body.ok, true);
  assert.equal(new Set(world2.sent).size, 1, 'one set of bytes');
  assert.equal(world2.sent.length, 3);

  // Time runs out with nothing known: each look at the clock moves it on.
  const world3 = fakeWorld();
  world3.dropSends = 1e9;
  let clock = NOW;
  Object.defineProperty(world3, 'now', { get: () => (clock += 3000) });
  const unknown = await relayWith(world3).relay('heartbeat', { vault: VAULT });
  assert.equal(unknown.body.ok, true);
  assert.equal(unknown.body.state, 'unknown');
  assert.ok(unknown.body.hash);
  assert.equal(new Set(world3.sent).size, 1);
});

test('relay: a node\'s refusal comes back in its own words, and costs no ceiling', async () => {
  const world = fakeWorld();
  const r = relayWith(world);
  world.refuseWith = { InvalidAccessKeyError: { NotEnoughAllowance: { allowance: '1', cost: '2' } } };
  const out = await r.relay('heartbeat', { vault: VAULT });
  assert.equal(out.status, 422);
  assert.equal(out.body.code, 'tx_refused');
  assert.ok(out.body.verbatim.includes('NotEnoughAllowance'));
  assert.equal((await r.state.call('status', { now: NOW })).spent.general, 0);
  const down = relayWith(Object.assign(fakeWorld(), { rpcDown: true }));
  const none = await down.relay('heartbeat', { vault: VAULT });
  assert.equal(none.status, 503);
});

// ---------------------------------------------------------------- the griefing boundary

test('owner: junk spends nothing. A victim\'s per-vault limit and the owner ceiling cannot be used up by someone without the passkey', async () => {
  const world = fakeWorld({ vaults: { [VAULT]: vaultRow() } });
  const r = relayWith(world);
  const good = await rotateBody();
  const other = softCredentials({ secret: label('someone-else'), origin: 'https://site.test', rpId: 'site.test' });
  const forged = await rotateBody({ soft: other });
  const wrongDigest = { ...good, new_k_s: toHex(ed25519.getPublicKey(label('another'))) };
  const used = await rotateBody({ nonce: 2 });
  const elsewhere = { ...good, vault: 'ef'.repeat(32) };
  const answers = [
    [forged, 'webauthn: bad signature'],
    [wrongDigest, 'webauthn: wrong challenge'],
    [used, 'passkey nonce already used'],
    [elsewhere, 'webauthn: wrong challenge'],
  ];
  for (let i = 0; i < 10; i += 1) {
    for (const [args, words] of answers) {
      const out = await r.relay('cancel_all_and_rotate', args);
      assert.equal(out.status, 422);
      assert.equal(out.body.code, 'assertion_refused');
      assert.equal(out.body.message, words);
    }
  }
  assert.equal(world.sent.length, 0, 'the owner key signed nothing');
  assert.equal(r.ns.calls.length, 0, 'nothing was charged');
  const out = await r.relay('cancel_all_and_rotate', good);
  assert.equal(out.body.ok, true, 'and the real one goes straight through');
  assert.equal(out.body.key, 'owner');
  const tx = decodeTx(world.sent[0]);
  assert.equal(tx.pub, toHex(OWNER.pub));
  assert.deepEqual(tx.actions.map((a) => [a.method, a.tgas]), [['cancel_all_and_rotate', 30]]);
  const unknownVault = relayWith(fakeWorld());
  assert.equal((await unknownVault.relay('cancel_all_and_rotate', good)).body.message, 'no such vault');
});

test('owner: every check is one the contract makes, so a nonce ahead of a lagging node and a dead read both go through', async () => {
  const lag = fakeWorld({ vaults: { [VAULT]: vaultRow({ passkey_nonce: 1 }) } });
  assert.equal((await relayWith(lag).relay('cancel_all_and_rotate', await rotateBody({ nonce: 3 }))).body.ok, true);
  const dead = fakeWorld();
  dead.viewDown = true;
  assert.equal((await relayWith(dead).relay('cancel_all_and_rotate', await rotateBody())).body.ok, true);
});

test('owner: cancel with a passkey or the cold key, and neither for a request that is gone', async () => {
  const cold = label('cold-file');
  const intent = coldKeys(cold).intent;
  const world = fakeWorld({ vaults: { [VAULT]: vaultRow({ k_e_intent: toHex(intent.pub) }) }, requests: { 5: { inputs: [{}] } } });
  const r = relayWith(world);
  const digest = cancelDigest({ contract: CONTRACT, vaultHex: VAULT, request: 5, expiresAt: NOW + 60_000 });
  const { args } = await getAssertion({ credentials: passkey.soft, digest, rpId: 'site.test' });
  const body = cancelArgs({ vaultHex: VAULT, request: 5, expiresAt: NOW + 60_000, assertion: args });
  assert.equal((await r.relay('cancel', body)).body.ok, true);
  assert.equal((await r.relay('cancel', { ...body, request: 6 })).body.message, 'webauthn: wrong challenge');
  const signed = signColdIntent({ cold, contract: CONTRACT, vault: VAULT, method: 'cancel', fields: { request: 5 }, expiresAt: NOW + 60_000 });
  const coldBody = { vault: VAULT, request: 5, expires_at: NOW + 60_000, auth: { Cold: signed.signature } };
  assert.equal((await r.relay('cancel', coldBody)).body.ok, true);
  const forged = signColdIntent({ cold: label('not-the-cold-file'), contract: CONTRACT, vault: VAULT, method: 'cancel', fields: { request: 5 }, expiresAt: NOW + 60_000 });
  assert.equal((await r.relay('cancel', { ...coldBody, auth: { Cold: forged.signature } })).body.message, 'cold key: bad signature');
  const noRequest = signColdIntent({ cold, contract: CONTRACT, vault: VAULT, method: 'cancel', fields: { request: 9 }, expiresAt: NOW + 60_000 });
  assert.equal((await r.relay('cancel', { ...coldBody, request: 9, auth: { Cold: noRequest.signature } })).body.message, 'no such request');
});

test('status near the ceiling: no new vault fits, and it says whether one more proposal and execute still do', async () => {
  const { propose_btc: propose, execute, create_vault: create, heartbeat } = RELAY_METHODS;
  const fits = relayWith(fakeWorld({ vaults: { [VAULT]: vaultRow() } }), { CEILING_GENERAL_MICRO: propose.costMicro + execute.costMicro + heartbeat.costMicro });
  assert.ok(create.costMicro > propose.costMicro + execute.costMicro + heartbeat.costMicro);
  assert.deepEqual((await fits.status()).body.general, { up: false, why: 'daily_ceiling', resets_at: Date.UTC(2026, 10, 2), calls_fit: true });
  assert.equal((await fits.relay('heartbeat', { vault: VAULT })).body.ok, true);
  assert.equal((await fits.status()).body.general.calls_fit, true, 'exactly enough left');
  assert.equal((await fits.relay('heartbeat', { vault: VAULT })).body.ok, true);
  const s = (await fits.status()).body.general;
  assert.deepEqual([s.up, s.why, s.calls_fit], [false, 'daily_ceiling', undefined]);
});

test('owner: general at its ceiling, owner still up, and two different answers', async () => {
  const world = fakeWorld({ vaults: { [VAULT]: vaultRow() } });
  const r = relayWith(world, { CEILING_GENERAL_MICRO: 800 });
  assert.equal((await r.status()).body.general.up, false, 'a new vault no longer fits');
  assert.equal((await r.relay('heartbeat', { vault: VAULT })).body.ok, true);
  assert.equal((await r.relay('heartbeat', { vault: VAULT })).body.ok, true);
  const third = await r.relay('heartbeat', { vault: VAULT });
  assert.equal(third.status, 429);
  assert.equal(third.body.code, 'daily_ceiling');
  assert.equal(third.body.bucket, 'general');
  assert.equal(third.body.resets_at, Date.UTC(2026, 10, 2));
  const s = (await r.status()).body;
  assert.deepEqual([s.general.up, s.general.why, s.general.resets_at], [false, 'daily_ceiling', Date.UTC(2026, 10, 2)]);
  assert.deepEqual([s.owner.up, s.owner.why], [true, null]);
  const burst = await Promise.all([r.relay('cancel_all_and_rotate', await rotateBody()), ...Array.from({ length: 8 }, () => r.relay('heartbeat', { vault: VAULT }))]);
  assert.equal(burst[0].body.ok, true);
  assert.equal(burst[0].body.key, 'owner');
  assert.ok(burst.slice(1).every((o) => o.body.code === 'daily_ceiling'));
  const limited = relayWith(fakeWorld());
  for (let i = 0; i < 20; i += 1) await limited.relay('heartbeat', { vault: toHex(label(`v${i}`)) });
  const over = await limited.relay('heartbeat', { vault: VAULT });
  assert.equal(over.body.code, 'rate_limited');
  assert.ok(over.body.retry_after_s > 0);
  assert.equal(over.body.bucket, null);

  const atLimit = relayWith(fakeWorld({ vaults: { [VAULT]: vaultRow() } }), { CEILING_OWNER_MICRO: 0 });
  const refused = await atLimit.relay('cancel_all_and_rotate', await rotateBody());
  assert.equal(refused.body.code, 'daily_ceiling');
  assert.equal(refused.body.bucket, 'owner');
  assert.deepEqual([(await atLimit.status()).body.owner.up, (await atLimit.status()).body.owner.why], [false, 'daily_ceiling']);
});

test('owner: with the state store down a cancel still goes, on a chain nonce, and says it is degraded. Nothing else goes', async () => {
  const world = fakeWorld({ vaults: { [VAULT]: vaultRow() } });
  const ns = localStateNamespace();
  ns.down = true;
  const r = relayWith(world, { UNDO_STATE: ns });
  const s = (await r.status()).body;
  assert.deepEqual([s.owner.up, s.owner.degraded], [true, true]);
  assert.deepEqual([s.general.up, s.general.why], [false, 'state_store_down']);
  assert.deepEqual([s.funds.up, s.funds.why], [false, 'state_store_down']);
  const out = await r.relay('cancel_all_and_rotate', await rotateBody());
  assert.equal(out.body.ok, true);
  assert.equal(out.body.degraded, true);
  assert.equal(decodeTx(world.sent[0]).nonce, 101);
  const general = await r.relay('heartbeat', { vault: VAULT });
  assert.equal(general.status, 503);
  assert.equal(general.body.code, 'state_store_down');
  assert.equal((await r.funds(VAULT)).body.code, 'state_store_down');

  // It falls over halfway: charged, then the nonce lease dies.
  const half = localStateNamespace();
  const realGet = half.get;
  let calls = 0;
  half.get = (id) => {
    const stub = realGet(id);
    return { fetch: async (url, init) => {
      calls += 1;
      if (new URL(url).pathname === '/lease') throw new Error('gone');
      return stub.fetch(url, init);
    } };
  };
  const world2 = fakeWorld({ vaults: { [VAULT]: vaultRow() } });
  const out2 = await relayWith(world2, { UNDO_STATE: half }).relay('cancel_all_and_rotate', await rotateBody());
  assert.equal(out2.body.ok, true);
  assert.equal(out2.body.degraded, true);
  assert.ok(calls >= 2);
});

test('relay: an address counts per /64 on IPv6, and only ever as a salted hash', async () => {
  assert.equal(limitAddress('2001:db8:1:2:aaaa::1'), limitAddress('2001:db8:1:2:bbbb::9'));
  assert.notEqual(limitAddress('2001:db8:1:3::1'), limitAddress('2001:db8:1:2::1'));
  assert.equal(limitAddress('192.0.2.1'), '192.0.2.1');
  assert.equal(limitAddress(null), 'unknown');
});

test('p256Uncompressed gives the same point as noble, for both signs of y', () => {
  for (const name of ['a', 'b', 'c', 'd', 'e', 'f']) {
    const compressed = p256.getPublicKey(label(name), true);
    assert.equal(toHex(p256Uncompressed(compressed)), toHex(p256.getPublicKey(label(name), false)));
  }
  assert.equal(p256Uncompressed(new Uint8Array(33)), null);
});

// ---------------------------------------------------------------- funds

const dispenserText = () => toHex(label('dispenser'));
const dispenserSpk = () => p2wpkhSpk(secp256k1.getPublicKey(label('dispenser'), true));

test('funding copy: the same transaction as tools/lib/dispenser.mjs, on the same inputs', async () => {
  const mine = dispenserFromSecret(dispenserText(), 'regtest');
  const original = parseDispenser(JSON.stringify({ format: 'undo-dispenser-v1', network: 'regtest', secret: dispenserText(), address: mine.address }), 'regtest');
  assert.equal(JSON.stringify(mine), JSON.stringify({ ...mine }));
  assert.ok(!JSON.stringify(mine).includes(dispenserText()), 'the secret does not serialize');
  const payTo = fromHex(`0020${toHex(label('pay'))}`);
  const coin = (t, value, confirmed = true) => ({ txid: toHex(label(t)), vout: 0, value, status: { confirmed } });
  const sets = [
    [coin('a', 100_000)],
    [coin('a', 2000), coin('b', 50_000), coin('c', 5000)],
    [coin('a', 1500), coin('b', 1500), coin('c', 400)],
    [coin('a', 2400)],
    [coin('a', 100)],
    [coin('a', 100_000, false)],
    [],
  ];
  for (const utxos of sets) {
    for (const feeRate of [1, 2, 7]) {
      if (utxos.length === 0) continue;
      assert.deepEqual(buildFunding({ dispenser: mine, utxos, payTo, value: 2000, feeRate }), originalFunding({ dispenser: original, utxos, payTo, value: 2000, feeRate }));
    }
  }
  assert.equal(toHex(mine.spk), toHex(dispenserSpk()));
});

function fundsWorld(over = {}) {
  const world = fakeWorld({ vaults: { [VAULT]: vaultRow() } });
  world.utxos = [{ txid: toHex(label('coin')), vout: 0, value: 50_000, status: { confirmed: true } }];
  return Object.assign(world, over);
}

async function txidOfRaw(raw) {
  const { parseTx, txid } = await import('../../tools/lib/btc.mjs');
  return txid(parseTx(fromHex(raw)));
}

test('funds: the address comes from the contract, once per vault, and never on anything else', async () => {
  const { parseTx } = await import('../../tools/lib/btc.mjs');
  const world = fundsWorld();
  const raws = new Map();
  world.fetchFn = ((inner) => async (url, init = {}) => {
    if (String(url).endsWith('/tx')) raws.set(init.body, await txidOfRaw(init.body));
    return inner(url, init);
  })(world.fetchFn);
  world.lastBuiltTxid = (raw) => raws.get(raw);
  const r = relayWith(world);
  const out = await r.funds(VAULT);
  assert.equal(out.body.ok, true);
  assert.equal(out.body.value, 2000);
  assert.equal(out.body.vout, 0);
  assert.deepEqual(out.body.broadcast, { status: 200, body: out.body.txid });
  assert.equal(world.posts.length, 1);
  const tx = parseTx(fromHex(world.posts[0]));
  assert.equal(toHex(tx.outputs[0].spk), vaultRow().script_pubkey, 'pays the contract\'s own script');
  assert.equal(Number(tx.outputs[0].value), 2000);
  const again = await r.funds(VAULT);
  assert.deepEqual([again.body.ok, again.body.txid, again.body.already], [true, out.body.txid, true]);
  assert.equal(world.posts.length, 1, 'no second coin');
  for (const body of [{ vault: VAULT, to: 'tb1qsomeoneelse' }, { vault: 'nope' }, { to: 'x' }, []]) assert.equal((await r.post('/api/funds', body)).body.code, 'bad_request');
  const none = await r.funds('ab'.repeat(32));
  assert.deepEqual([none.body.code, none.body.message], ['bad_request', 'no such vault']);
  const inactive = relayWith(fakeWorld({ vaults: { [VAULT]: vaultRow({ active: false }) } }));
  assert.equal((await inactive.funds(VAULT)).body.message, 'that vault is not active');
});

function fundedRelay(extra = {}, worldOver = {}) {
  const raws = new Map();
  const vaults = {};
  for (let i = 0; i < 40; i += 1) vaults[toHex(label(`funds-${i}`))] = vaultRow({ script_pubkey: `0020${toHex(label(`spk-${i}`))}` });
  const world = fakeWorld({ vaults });
  world.utxos = [{ txid: toHex(label('coin')), vout: 0, value: 500_000, status: { confirmed: true } }];
  Object.assign(world, worldOver);
  const inner = world.fetchFn;
  world.fetchFn = async (url, init = {}) => {
    if (String(url).endsWith('/tx')) raws.set(init.body, await txidOfRaw(init.body));
    return inner(url, init);
  };
  world.lastBuiltTxid = (raw) => raws.get(raw);
  return { world, r: relayWith(world, extra), vault: (i) => toHex(label(`funds-${i}`)) };
}

test('funds: over the per-address limit and over the daily ceiling are different answers, and the page can read both', async () => {
  const { r, vault } = fundedRelay({ CEILING_FUNDS_SATS: 6000 });
  assert.equal((await r.funds(vault(0), { ip: '192.0.2.1' })).body.ok, true);
  assert.equal((await r.funds(vault(1), { ip: '192.0.2.1' })).body.ok, true);
  const limited = await r.funds(vault(2), { ip: '192.0.2.1' });
  assert.equal(limited.status, 429);
  assert.equal(limited.body.code, 'rate_limited');
  assert.ok(limited.body.retry_after_s > 0);
  assert.equal(limited.body.bucket, null);
  assert.equal((await r.funds(vault(2), { ip: '192.0.2.2' })).body.ok, true);
  assert.equal((await r.status()).body.funds.why, 'daily_ceiling');
  const ceiling = await r.funds(vault(3), { ip: '192.0.2.3' });
  assert.equal(ceiling.status, 429);
  assert.equal(ceiling.body.code, 'daily_ceiling');
  assert.equal(ceiling.body.bucket, 'funds');
  assert.equal(ceiling.body.resets_at, Date.UTC(2026, 10, 2));
  assert.equal(ceiling.body.retry_after_s, null);
});

test('funds: concurrent asks never spend one coin twice. Change is spendable at once, and spent inputs are retried once', async () => {
  const { world, r, vault } = fundedRelay();
  const answers = await Promise.all(Array.from({ length: 6 }, (_, i) => r.funds(vault(i), { ip: `192.0.2.${i + 10}` })));
  assert.ok(answers.filter((a) => a.body.ok).length >= 1);
  const { parseTx } = await import('../../tools/lib/btc.mjs');
  const inputs = world.posts.flatMap((raw) => parseTx(fromHex(raw)).inputs.map((i) => `${i.coin.txid}:${i.coin.vout}`));
  assert.equal(new Set(inputs).size, inputs.length, 'no input twice');
  for (const a of answers.filter((x) => !x.body.ok)) {
    assert.equal(a.body.code, 'rate_limited', 'the only coin is on lease: busy, which is not empty');
    assert.equal(a.body.retry_after_s, 5);
  }
  const later = await r.funds(vault(20), { ip: '192.0.2.99' });
  assert.equal(later.body.ok, true, 'the change is free now');

  const gone = fundedRelay();
  let first = true;
  gone.world.postRule = () => {
    if (!first) return null;
    first = false;
    gone.world.utxos = [{ txid: toHex(label('coin-2')), vout: 0, value: 90_000, status: { confirmed: true } }];
    return { status: 400, body: 'sendrawtransaction RPC error: {"code":-25,"message":"bad-txns-inputs-missingorspent"}' };
  };
  const retried = await gone.r.funds(gone.vault(0));
  assert.equal(retried.body.ok, true);
  assert.equal(gone.world.posts.length, 2);
});

test('funds: empty, down and refused are each their own answer, a refusal in the node\'s words, and what moved nothing can ask again', async () => {
  const empty = fundedRelay({}, { utxos: [] });
  const e = await empty.r.funds(empty.vault(0));
  assert.equal(e.status, 503);
  assert.equal(e.body.code, 'dispenser_empty');
  assert.equal((await empty.r.status()).body.funds.why, 'dispenser_empty');
  assert.equal((await empty.r.state.call('status', { now: NOW })).spent.funds, 0, 'gave its sats back');
  empty.world.now = NOW + 11 * 60_000;
  assert.equal((await empty.r.status()).body.funds.up, true, 'empty holds for a while, so a refill by hand is found');
  empty.world.utxos = [{ txid: toHex(label('refill')), vout: 0, value: 90_000, status: { confirmed: true } }];
  assert.equal((await empty.r.funds(empty.vault(0))).body.ok, true);

  const down = fundedRelay({}, { utxoStatus: 502 });
  const d = await down.r.funds(down.vault(0));
  assert.equal(d.body.code, 'esplora_down');
  assert.equal(d.body.verbatim, 'Bad Gateway');

  const refused = fundedRelay();
  const words = 'sendrawtransaction RPC error: {"code":-26,"message":"min relay fee not met, 100 < 121"}';
  refused.world.postRule = () => ({ status: 400, body: words });
  const rf = await refused.r.funds(refused.vault(0));
  assert.equal(rf.status, 422);
  assert.equal(rf.body.code, 'tx_refused');
  assert.equal(rf.body.verbatim, words);
  refused.world.postRule = null;
  assert.equal((await refused.r.funds(refused.vault(0))).body.ok, true);

  const lost = fundedRelay();
  lost.world.postRule = () => ({ status: 502, body: '<html>Bad Gateway</html>' });
  const l = await lost.r.funds(lost.vault(0));
  assert.equal(l.status, 503);
  assert.equal(l.body.code, 'esplora_down');
  assert.equal(l.body.retry_after_s, 120);
  lost.world.postRule = null;
  const hold = await lost.r.funds(lost.vault(0));
  assert.equal(hold.body.code, 'rate_limited', 'it may yet land, so the claim stands');
  lost.world.now = NOW + 3 * 60_000;
  assert.equal((await lost.r.funds(lost.vault(0))).body.ok, true, 'until it runs out');
});

test('funds: a bad dispenser key is not configured, and no answer repeats a key', async () => {
  const world = fundsWorld();
  const r = relayWith(world, { DISPENSER_SECRET: 'zz-not-hex' });
  const out = await r.funds(VAULT);
  assert.equal(out.body.code, 'relay_not_configured');
  assert.ok(!JSON.stringify(out.body).includes('zz-not-hex'));
});

// ---------------------------------------------------------------- cron

test('cron: one canary heartbeat on its own key, logged. Without a canary it does nothing', async () => {
  const world = fakeWorld();
  const ns = localStateNamespace();
  assert.equal(await canaryBeat({ UNDO_STATE: ns }), null);
  assert.deepEqual(ns.calls, []);
  await assert.rejects(() => canaryBeat({ UNDO_STATE: ns, CANARY_VAULT: VAULT }), /not configured: CONTRACT_ID, RELAY_ACCOUNT, RELAY_CRON_KEY, NEAR_RPC_URLS/);
  const env = { UNDO_STATE: ns, CANARY_VAULT: VAULT, CONTRACT_ID: CONTRACT, RELAY_ACCOUNT: ACCOUNT, RELAY_CRON_KEY: secretText('cron'), NEAR_RPC_URLS: RPC };
  const hash = await canaryBeat(env, { fetchFn: world.fetchFn, nowFn: () => NOW });
  assert.equal(world.sent.length, 1);
  const tx = decodeTx(world.sent[0]);
  assert.equal(tx.pub, toHex(keyFromSecret(label('cron')).pub));
  assert.deepEqual(tx.actions.map((a) => [a.method, a.tgas]), [['heartbeat', 10]]);
  const { beats } = await new StateClient(ns).call('heartbeats', { vault: VAULT });
  assert.deepEqual(beats, [{ at: NOW, hash }]);
});

// ---------------------------------------------------------------- configuration and deploy

const read = (path) => readFileSync(resolve(REPO, path), 'utf8');

test('config: no hostname, no account id, no source maps, and the design\'s bindings', () => {
  const cron = read('worker/undo-cron/wrangler.toml');
  assert.match(cron, /^workers_dev = false$/m);
  assert.match(cron, /^preview_urls = false$/m);
  assert.match(cron, /^upload_source_maps = false$/m);
  assert.match(cron, /^crons = \["\*\/5 \* \* \* \*"\]$/m);
  assert.match(cron, /new_sqlite_classes = \["UndoState"\]/);
  assert.doesNotMatch(cron, /^\s*routes?\s*=/m);
  const pages = read('site/wrangler.toml');
  assert.match(pages, /^pages_build_output_dir = "dist"$/m);
  assert.match(pages, /^script_name = "undo-cron"$/m);
  assert.match(pages, /^SITE_ORIGIN = "https:\/\/undo-btc\.pages\.dev"$/m);
  for (const text of [cron, pages]) {
    assert.doesNotMatch(text, /^\s*account_id/m);
    for (const secret of ['RELAY_GENERAL_KEY', 'RELAY_OWNER_KEY', 'RELAY_CRON_KEY', 'DISPENSER_SECRET', 'IP_SALT', 'CONTRACT_ID', 'RELAY_ACCOUNT']) assert.doesNotMatch(text, new RegExp(`^${secret}`, 'm'), `${secret} comes from the environment`);
  }
});

test('workerFetch: never the redirect value workerd throws on', async () => {
  const seen = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    seen.push(init.redirect);
    return new Response('x');
  };
  try {
    await workerFetch('http://x', { redirect: 'error' });
  } finally {
    globalThis.fetch = real;
  }
  assert.deepEqual(seen, ['manual']);
});

test('source: the relay logs nothing, holds no default endpoint, and imports nothing from Node', () => {
  const files = [
    ...readdirSync(resolve(SITE, 'functions/_relay')).map((f) => resolve(SITE, 'functions/_relay', f)),
    ...readdirSync(resolve(SITE, 'functions/api')).map((f) => resolve(SITE, 'functions/api', f)),
    ...readdirSync(resolve(REPO, 'worker/undo-cron/src')).map((f) => resolve(REPO, 'worker/undo-cron/src', f)),
  ];
  assert.ok(files.length >= 8);
  for (const file of files) {
    const text = readFileSync(file, 'utf8');
    assert.doesNotMatch(text, /console\./, file);
    assert.doesNotMatch(text, /from 'node:/, file);
    assert.doesNotMatch(text, /https?:\/\/(?!do\/)[a-z]/, file);
    assert.doesNotMatch(text, /from 'cloudflare:/, file);
  }
});

const fakeWrangler = (dir, whoami) => {
  const path = join(dir, 'wrangler');
  writeFileSync(path, `#!/bin/sh\nprintf '%s\\n' "$*" >> "${dir}/calls"\ncase "$1" in\n  whoami) printf '%s\\n' "${whoami}" ;;\n  secret) printf '%s\\n' '[{"name":"CONTRACT_ID"},{"name":"RELAY_ACCOUNT"},{"name":"RELAY_CRON_KEY"}]' ;;\n  pages) if [ "$2 $3" = "secret list" ]; then printf 'CONTRACT_ID\\nRELAY_ACCOUNT\\nRELAY_GENERAL_KEY\\nRELAY_OWNER_KEY\\nDISPENSER_SECRET\\nIP_SALT\\n'; fi ;;\nesac\n`);
  chmodSync(path, 0o755);
  return path;
};

for (const script of ['worker/undo-cron/deploy.sh', 'site/deploy.sh']) {
  test(`${script} stops unless whoami shows the public account, and stops before any deploy`, () => {
    const dir = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'undo-deploy-'));
    try {
      const run = (whoami, env = {}) => {
        const wrangler = fakeWrangler(dir, whoami);
        rmSync(join(dir, 'calls'), { force: true });
        const out = spawnSync('bash', [resolve(REPO, script), '--check-only'], {
          encoding: 'utf8',
          env: { PATH: process.env.PATH, WRANGLER: wrangler, CLOUDFLARE_ACCOUNT_ID: 'test-account-0001', ...env },
        });
        let calls = '';
        try {
          calls = readFileSync(join(dir, 'calls'), 'utf8');
        } catch {
          // Never called.
        }
        return { ...out, calls };
      };
      const wrong = run('logged in as someone-else test-account-0001');
      assert.notEqual(wrong.status, 0);
      assert.doesNotMatch(wrong.calls, /deploy/);
      assert.doesNotMatch(`${wrong.stdout}${wrong.stderr}`, /someone-else/, 'it does not repeat what whoami said');
      const otherId = run('tedinroc other-id-0002');
      assert.notEqual(otherId.status, 0);
      assert.doesNotMatch(otherId.calls, /deploy/);
      const noId = run('tedinroc test-account-0001', { CLOUDFLARE_ACCOUNT_ID: '' });
      assert.notEqual(noId.status, 0);
      assert.equal(noId.calls, '', 'it stops before asking');
      const right = run('tedinroc test-account-0001');
      assert.equal(right.status, 0, right.stderr);
      assert.doesNotMatch(right.calls, /deploy/, '--check-only sends nothing');
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
}

// ---------------------------------------------------------------- what the attack on the relay found

const spentGeneral = async (r) => (await r.state.call('status', { now: NOW })).spent.general;

test('attack 1: a well-signed call that cannot work spends nothing of the owner ceiling', async () => {
  const world = fakeWorld({ vaults: { [VAULT]: vaultRow() } });
  const r = relayWith(world);
  const newKs = ed25519.getPublicKey(label('new-ks'));
  const rotate = async ({ nonce = 3, expiresAt = NOW + 60_000 }) => {
    const digest = rotateDigest({ contract: CONTRACT, vaultHex: VAULT, newKs, nonce, expiresAt });
    const { args } = await getAssertion({ credentials: passkey.soft, digest, rpId: 'site.test' });
    return rotateArgs({ vaultHex: VAULT, newKs, nonce, expiresAt, assertion: args });
  };
  const expired = await r.relay('cancel_all_and_rotate', await rotate({ expiresAt: 1 }));
  assert.deepEqual([expired.status, expired.body.code, expired.body.message], [422, 'assertion_refused', 'that intent has expired']);
  const ahead = await r.relay('cancel_all_and_rotate', await rotate({ nonce: 1003 }));
  assert.deepEqual([ahead.status, ahead.body.message], [422, 'that passkey nonce is too far ahead']);
  assert.equal(world.sent.length, 0, 'the owner key signed neither');
  assert.equal(r.ns.calls.length, 0, 'and nothing was charged');
  assert.equal((await r.relay('cancel_all_and_rotate', await rotate({ nonce: 5 }))).body.ok, true, 'a node two behind is still a lagging node');
});

test('attack 1: a cancel already past cancelling is refused before the owner key signs', async () => {
  const world = fakeWorld({ vaults: { [VAULT]: vaultRow() }, requests: { 5: requestRow({ status: 'Signed' }) } });
  const r = relayWith(world);
  const digest = cancelDigest({ contract: CONTRACT, vaultHex: VAULT, request: 5, expiresAt: NOW + 60_000 });
  const { args } = await getAssertion({ credentials: passkey.soft, digest, rpId: 'site.test' });
  const out = await r.relay('cancel', cancelArgs({ vaultHex: VAULT, request: 5, expiresAt: NOW + 60_000, assertion: args }));
  assert.equal(out.body.message, 'that request is past cancelling');
  assert.equal(world.sent.length, 0);
});

test('attack 1: one vault gets twelve owner sends a day, whichever method, and someone else\'s cancel still lands', async () => {
  const other = 'ef'.repeat(32);
  const world = fakeWorld({ vaults: { [VAULT]: vaultRow(), [other]: vaultRow() } });
  const r = relayWith(world);
  let clock = NOW;
  Object.defineProperty(world, 'now', { get: () => clock });
  const newKs = ed25519.getPublicKey(label('new-ks'));
  const rotate = async (vaultHex) => {
    const expiresAt = clock + 60_000;
    const digest = rotateDigest({ contract: CONTRACT, vaultHex, newKs, nonce: 3, expiresAt });
    const { args } = await getAssertion({ credentials: passkey.soft, digest, rpId: 'site.test' });
    return rotateArgs({ vaultHex, newKs, nonce: 3, expiresAt, assertion: args });
  };
  for (let i = 0; i < RELAY_METHODS.cancel_all_and_rotate.perVaultDay; i += 1) {
    assert.equal((await r.relay('cancel_all_and_rotate', await rotate(VAULT))).body.ok, true, `send ${i}`);
    clock += 61_000;
  }
  const over = await r.relay('cancel_all_and_rotate', await rotate(VAULT));
  assert.deepEqual([over.status, over.body.code], [429, 'rate_limited']);
  assert.ok(over.body.retry_after_s > 60, 'until the day turns');
  assert.equal(over.body.bucket, null, 'a limit, not the ceiling');
  assert.equal((await r.relay('cancel_all_and_rotate', await rotate(other))).body.ok, true);
  clock += 86_400_000;
  assert.equal((await r.relay('cancel_all_and_rotate', await rotate(VAULT))).body.ok, true, 'the next day it may send again');
});

test('attack 4: the owner key\'s allowance covers every send that can be in flight at the default ceiling', () => {
  const needed = ownerAllowanceNeeded(CEILING_OWNER_DEFAULT_MICRO);
  assert.ok(needed > 2, 'the old 2 NEAR would not have done');
  assert.ok(OWNER_ALLOWANCE_NEAR >= needed, `${OWNER_ALLOWANCE_NEAR} NEAR allowance, ${needed} NEAR can be held at once`);
});

test('attack 5: junk a contract would refuse is refused first, in the contract\'s words when it gave any, and costs no ceiling', async () => {
  const ks = label('ks');
  const world = fakeWorld({ vaults: { [VAULT]: vaultRow(), [`${'cd'.repeat(32)}`]: vaultRow({ active: false }) }, requests: {} });
  const r = relayWith(world);
  const { intentDigest, argBytes, SPEND_TAG, signEd25519 } = await import('../../tools/lib/intent.mjs');
  const coin = { txid: 'ab'.repeat(32), vout: 0, value: 2000 };
  const propose = (over = {}) => {
    const fields = { vault: VAULT, inputs: [coin], to: `0014${'11'.repeat(20)}`, amount: 1500, change: null, half_sigs: ['ab'.repeat(65)], nonce: 0, expires_at: NOW + 60_000, memo: null, ...over };
    const digest = intentDigest({ tag: SPEND_TAG, contract: CONTRACT, vault: fromHex(fields.vault), method: 'propose_btc', args: argBytes.propose_btc({ inputs: fields.inputs, to: fromHex(fields.to), amount: fields.amount, change: fields.change, memo: fields.memo }), expiresAt: fields.expires_at, nonce: fields.nonce });
    return { ...fields, spend_sig: toHex(signEd25519(digest, ks)) };
  };
  const refusals = [
    [propose({ vault: 'ef'.repeat(32) }), 'no such vault'],
    [propose({ vault: 'cd'.repeat(32) }), 'that vault is not active yet'],
    [{ ...propose(), spend_sig: 'ab'.repeat(64) }, 'that proposal is not signed by this vault\'s spend key'],
    [propose({ expires_at: 1 }), 'that intent has expired'],
  ];
  for (const [args, words] of refusals) {
    const out = await r.relay('propose_btc', args);
    assert.deepEqual([out.status, out.body.code, out.body.message], [422, 'would_refuse', words]);
  }
  const usedNonce = relayWith(fakeWorld({ vaults: { [VAULT]: vaultRow({ spend_nonce: 4 }) } }));
  assert.equal((await usedNonce.relay('propose_btc', propose({ nonce: 3 }))).body.message, 'that spend nonce was already used');
  world.viewRefuses = { check_propose: 'wasm execution failed with error: Smart contract panicked: OutpointBusy' };
  const busy = await r.relay('propose_btc', propose());
  assert.deepEqual([busy.body.code, busy.body.verbatim], ['would_refuse', 'wasm execution failed with error: Smart contract panicked: OutpointBusy'], 'the contract\'s own words, untouched');
  world.viewRefuses = null;
  assert.equal(world.sent.length, 0, 'the general key signed none of them');
  assert.equal(await spentGeneral(r), 0, 'and every charge came back');
  assert.equal((await r.relay('propose_btc', propose())).body.ok, true, 'the real one goes');
  assert.equal(await spentGeneral(r), RELAY_METHODS.propose_btc.costMicro);
});

test('attack 5: activate on a vault that is missing or already active goes nowhere', async () => {
  const world = fakeWorld({ vaults: { [VAULT]: vaultRow(), [`${'cd'.repeat(32)}`]: vaultRow({ active: false }) } });
  const r = relayWith(world);
  assert.equal((await r.relay('activate', { vault: 'ef'.repeat(32) })).body.message, 'no such vault');
  assert.equal((await r.relay('activate', { vault: VAULT })).body.message, 'that vault is already active');
  assert.equal(world.sent.length, 0);
  assert.equal((await r.relay('activate', { vault: 'cd'.repeat(32) })).body.ok, true);
});

test('attack 5: execute goes only when it can run: not early, not cancelled, not signed, not expired', async () => {
  const world = fakeWorld({
    vaults: { [VAULT]: vaultRow() },
    requests: {
      1: requestRow({ unlock: NOW + 281_000 }),
      2: requestRow({ epoch: 1 }),
      3: requestRow({ status: 'Signed' }),
      4: requestRow({ expires_at: NOW - 1 }),
      5: requestRow({ unlock: NOW + 3000 }),
      6: requestRow({ status: 'Signing', unlock: NOW + 281_000, epoch: 1 }),
    },
  });
  const r = relayWith(world);
  const early = await r.relay('execute', { vault: VAULT, request: 1 });
  assert.deepEqual([early.status, early.body.code, early.body.message, early.body.retry_after_s], [422, 'would_refuse', 'that request has not unlocked', 281]);
  assert.equal((await r.relay('execute', { vault: VAULT, request: 2 })).body.message, 'that request was cancelled');
  assert.equal((await r.relay('execute', { vault: VAULT, request: 3 })).body.message, 'that request is already signed');
  assert.equal((await r.relay('execute', { vault: VAULT, request: 4 })).body.message, 'that request has expired');
  assert.equal(world.sent.length, 0);
  assert.equal(await spentGeneral(r), 0);
  assert.equal((await r.relay('execute', { vault: VAULT, request: 5 })).body.ok, true, 'a page at zero, a moment ahead of this node');
  assert.equal((await r.relay('execute', { vault: VAULT, request: 6 })).body.ok, true, 'a sign call that died is picked up again');
});

test('attack 5: a creation its spend key did not sign, or of a vault that exists, is refused and costs nothing', async () => {
  const world = fakeWorld();
  const r = relayWith(world, { POW_BITS: 0 });
  const soft = softCredentials({ secret: label('c5'), origin: 'https://site.test', rpId: 'site.test' });
  const made = await createPasskey({ credentials: soft, rpId: 'site.test' });
  const { buildCreateArgs, newVaultKeys, rpIdHashOf } = await import('../lib/intents.mjs');
  const keys = newVaultKeys({ seed: label('seed5'), cold: label('cold5') });
  const built = await buildCreateArgs({
    contract: CONTRACT, keys, passkeyPub: made.pubkey, rpIdHash: rpIdHashOf('site.test'), km: secp256k1.getPublicKey(label('km'), true), guard: ACCOUNT, policy: POLICY, csv: 6, expiresAt: NOW + 60_000,
    assert: async (digest) => (await getAssertion({ credentials: soft, digest, rpId: 'site.test' })).args,
  });
  const badPop = await r.relay('create_vault', { ...built.args, pop_s: 'ab'.repeat(64) }, { pow: 0 });
  assert.deepEqual([badPop.status, badPop.body.message], [422, 'that creation is not signed by its spend key']);
  assert.equal(r.ns.calls.length, 0, 'before the state store');
  const old = await r.relay('create_vault', { ...built.args, expires_at: 1 }, { pow: 0 });
  assert.equal(old.body.message, 'that intent has expired');
  const taken = fakeWorld({ vaults: { [built.vaultHex]: vaultRow() } });
  const again = relayWith(taken, { POW_BITS: 0 });
  const replay = await again.relay('create_vault', built.args, { pow: 0 });
  assert.equal(replay.body.message, 'that vault exists');
  assert.equal(taken.sent.length, 0);
  assert.equal(await spentGeneral(again), 0);
  assert.equal((await r.relay('create_vault', built.args, { pow: 0 })).body.ok, true, 'the real one goes');
});

test('attack 5: vaults stop at their share of the general ceiling, and calls on existing vaults keep the rest', async () => {
  const create = RELAY_METHODS.create_vault.costMicro;
  const ceiling = Math.ceil((create * 1.5) / CREATE_SHARE);
  const world = fakeWorld({ vaults: { [VAULT]: vaultRow() }, requests: { 1: requestRow() } });
  const r = relayWith(world, { CEILING_GENERAL_MICRO: ceiling });
  await r.state.call('charge', { key: 'general', method: 'create_vault', ipHash: 'x', vault: null, now: NOW, ceiling });
  const s = (await r.status()).body.general;
  assert.deepEqual([s.up, s.why, s.calls_fit], [false, 'daily_ceiling', true], 'no new vault fits, and calls do');
  assert.equal((await r.relay('execute', { vault: VAULT, request: 1 })).body.ok, true);
});

test('attack 6: status says when the owner key cannot pay, and a dead RPC claims nothing', async () => {
  const world = fakeWorld({ vaults: { [VAULT]: vaultRow() } });
  const r = relayWith(world);
  assert.deepEqual([(await r.status()).body.owner.up, (await r.status()).body.owner.why], [true, null]);
  world.accessKeys[OWNER.publicKey] = { permission: { FunctionCall: { allowance: `${10n ** 22n}`, receiver_id: CONTRACT, method_names: [] } } };
  assert.deepEqual([(await r.status()).body.owner.up, (await r.status()).body.owner.why], [false, 'owner_key_low']);
  world.accessKeys[OWNER.publicKey] = { permission: { FunctionCall: { allowance: `${10n ** 24n}`, receiver_id: CONTRACT, method_names: [] } } };
  assert.equal((await r.status()).body.owner.up, true);
  world.account = { amount: `${6n * 10n ** 22n}`, storage_usage: 2000 };
  assert.deepEqual([(await r.status()).body.owner.up, (await r.status()).body.owner.why], [false, 'owner_key_low'], '0.06 NEAR with 0.02 of it locked for storage');
  world.account = { amount: `${10n ** 25n}`, storage_usage: 182 };
  world.accessKeys[OWNER.publicKey] = { error: 'access key does not exist', permission: undefined };
  assert.deepEqual([(await r.status()).body.owner.up, (await r.status()).body.owner.why], [false, 'owner_key_missing']);
  delete world.accessKeys[OWNER.publicKey];
  const unlimited = { permission: { FunctionCall: { allowance: null, receiver_id: CONTRACT, method_names: [] } } };
  world.accessKeys[OWNER.publicKey] = unlimited;
  assert.equal((await r.status()).body.owner.up, true, 'a function-call key with no allowance limit');
  const dead = relayWith(Object.assign(fakeWorld(), { rpcDown: true }));
  assert.deepEqual([(await dead.status()).body.owner.up, (await dead.status()).body.owner.why], [true, null], 'it does not know, so it does not say');
});

test('attack 6: a tap refused for allowance turns the status off, until a read says otherwise', async () => {
  const world = fakeWorld({ vaults: { [VAULT]: vaultRow() } });
  const r = relayWith(world, { KEY_CACHE_MS: 30_000 });
  assert.equal((await r.status()).body.owner.up, true);
  world.refuseWith = { InvalidAccessKeyError: { NotEnoughAllowance: { allowance: '1', cost: '2' } } };
  const out = await r.relay('cancel_all_and_rotate', await rotateBody());
  assert.deepEqual([out.status, out.body.code], [422, 'tx_refused']);
  assert.ok(out.body.verbatim.includes('NotEnoughAllowance'));
  assert.deepEqual([(await r.status()).body.owner.up, (await r.status()).body.owner.why], [false, 'owner_key_low']);
  world.refuseWith = null;
  world.now = NOW + 31_000;
  assert.equal((await r.status()).body.owner.up, true, 'the next read clears it');
});

test('attack 7: heartbeat is off the public list. A stranger can\'t make a vault read guard online', async () => {
  const world = fakeWorld({ vaults: { [VAULT]: vaultRow() } });
  const r = relayWith(world);
  for (const beat of [null, 'wrong', `${BEAT}x`]) {
    const out = await r.relay('heartbeat', { vault: VAULT }, { beat });
    assert.deepEqual([out.status, out.body.code], [400, 'unknown_method'], String(beat));
  }
  assert.equal(world.sent.length, 0);
  assert.equal(r.ns.calls.length, 0);
  assert.equal((await r.relay('heartbeat', { vault: VAULT })).body.ok, true, 'the holder of the binding still can, before a take');
  const unset = relayWith(world, { BEAT_TOKEN: undefined });
  assert.equal((await unset.relay('heartbeat', { vault: VAULT }, { beat: 'undefined' })).body.code, 'unknown_method', 'no binding, no beat');
});

test('attack 9: with the state store down the owner key still has a limit per vault in this isolate', async () => {
  const world = fakeWorld({ vaults: { [VAULT]: vaultRow() } });
  const ns = localStateNamespace();
  ns.down = true;
  const r = relayWith(world, { UNDO_STATE: ns });
  const good = await rotateBody();
  const answers = [];
  for (let i = 0; i < 12; i += 1) answers.push((await r.relay('cancel_all_and_rotate', good)).body);
  assert.equal(answers.filter((a) => a.ok && a.degraded).length, RELAY_METHODS.cancel_all_and_rotate.perVaultMinute);
  assert.ok(answers.slice(RELAY_METHODS.cancel_all_and_rotate.perVaultMinute).every((a) => a.code === 'rate_limited'));
  world.now = NOW + 61_000;
  assert.equal((await r.relay('cancel_all_and_rotate', good)).body.ok, true, 'and it clears');
  const expired = await r.relay('cancel_all_and_rotate', { ...good, expires_at: 1 });
  assert.equal(expired.body.code, 'assertion_refused', 'the checks run with the store down too');
});

test('attack 10: funds only for a vault this relay guards, holding no coin, with its own proof of work', async () => {
  const { checkPow, fundsPowTarget, solvePow } = await import('../lib/pow.mjs');
  const foreignWorld = fakeWorld({ vaults: { [VAULT]: vaultRow({ guard: 'someone.else' }) } });
  foreignWorld.utxos = fundsWorld().utxos;
  const foreign = relayWith(foreignWorld);
  const wrong = await foreign.funds(VAULT);
  assert.deepEqual([wrong.status, wrong.body.code, wrong.body.message], [422, 'would_refuse', 'this relay only funds vaults it guards']);
  assert.equal((await foreign.state.call('status', { now: NOW })).spent.funds, 0);

  const holding = fundsWorld();
  holding.vaultCoins['vault-address'] = [{ txid: 'ab'.repeat(32), vout: 0, value: 2000 }];
  const r = relayWith(holding);
  const has = await r.funds(VAULT);
  assert.deepEqual([has.body.code, has.body.message], ['would_refuse', 'that vault already holds a coin']);
  assert.equal(holding.posts.length, 0);
  assert.equal((await r.state.call('status', { now: NOW })).spent.funds, 0, 'the ceiling got its sats back');

  const worked = relayWith(fundsWorld(), { POW_BITS: 10 });
  const none = await worked.post('/api/funds', { vault: VAULT });
  assert.equal(none.body.code, 'bad_request', 'the work is not optional');
  let bad = 0;
  while (checkPow(fundsPowTarget(VAULT), bad, 10)) bad += 1;
  assert.equal((await worked.post('/api/funds', { vault: VAULT, pow: bad })).body.code, 'pow_bad');
  const createWork = await solvePow(VAULT, 10);
  if (!checkPow(fundsPowTarget(VAULT), createWork, 10)) assert.equal((await worked.post('/api/funds', { vault: VAULT, pow: createWork })).body.code, 'pow_bad', 'the work that made the vault does not pay it');
});

test('attack 11: one /64 is one address however it is written', () => {
  const same = ['2a01:4f8::1:1', '2a01:4f8::2:1', '2a01:4f8:0:0::3', '2a01:04f8:0000:0000:0000:0000:0000:0009', '2A01:4F8::A'];
  assert.deepEqual([...new Set(same.map(limitAddress))], ['2a01:4f8:0:0']);
  assert.equal(limitAddress('2a01:4f8:c17:1234::1'), '2a01:4f8:c17:1234');
  assert.equal(limitAddress('2a01:4f8:c17:1234:aa:bb:cc:2'), '2a01:4f8:c17:1234');
  assert.notEqual(limitAddress('2a01:4f8:0:1::1'), limitAddress('2a01:4f8:0:2::1'));
  assert.equal(limitAddress('::1'), '0:0:0:0');
  assert.equal(limitAddress('::ffff:1.2.3.4'), '1.2.3.4', 'a v4 address in v6 clothes counts as that v4 address');
  assert.equal(limitAddress('::ffff:0102:0304'), '1.2.3.4');
  assert.equal(limitAddress('1.2.3.4'), '1.2.3.4');
  assert.equal(limitAddress('not an address'), 'not an address');
  assert.equal(limitAddress('1:2:3'), '1:2:3', 'too few to be an address: left alone');
  assert.equal(limitAddress(null), 'unknown');
});

test('attack 12: a chunked body is read only up to the cap', async () => {
  const world = fakeWorld();
  const r = relayWith(world);
  const handler = makeRelay(r.env, { fetchFn: world.fetchFn, nowFn: () => NOW });
  let pulled = 0;
  const body = new ReadableStream({
    pull(controller) {
      pulled += 1;
      if (pulled > 10_000) controller.close();
      else controller.enqueue(new Uint8Array(1024));
    },
  });
  const res = await handler(new Request('https://site.test/api/relay', { method: 'POST', headers: { 'content-type': 'application/json' }, body, duplex: 'half' }));
  const out = await res.json();
  assert.deepEqual([res.status, out.message], [400, 'the body is too large']);
  assert.ok(pulled < 40, `read ${pulled} KB of 10,000 KB before stopping`);
  const fits = new Request('https://site.test/api/relay', { method: 'POST', body: new ReadableStream({ start(c) { c.enqueue(utf8('{"method":"x",')); c.enqueue(utf8('"args":{}}')); c.close(); } }), duplex: 'half' });
  assert.equal((await (await handler(fits)).json()).code, 'unknown_method', 'a body in pieces still reads whole');
});

test('attack 13: a method is a string. An array or an object is not on the list, whatever it coerces to', async () => {
  const world = fakeWorld({ vaults: { [VAULT]: vaultRow() } });
  const r = relayWith(world);
  const digest = cancelDigest({ contract: CONTRACT, vaultHex: VAULT, request: 5, expiresAt: NOW + 60_000 });
  const { args } = await getAssertion({ credentials: passkey.soft, digest, rpId: 'site.test' });
  for (const method of [['cancel'], ['create_vault'], [['cancel_all_and_rotate']], { toString: 1 }, 5, null]) {
    const out = await r.post('/api/relay', { method, args: cancelArgs({ vaultHex: VAULT, request: 5, expiresAt: NOW + 60_000, assertion: args }) });
    assert.deepEqual([out.status, out.body.code], [400, 'unknown_method'], JSON.stringify(method));
  }
  assert.equal(world.sent.length, 0);
  assert.equal(r.ns.calls.length, 0);
});

test('attack 15: execute costs per input, and an execute past the ceiling gives back what it was charged', async () => {
  const world = fakeWorld({ vaults: { [VAULT]: vaultRow() }, requests: { 1: requestRow({ inputs: Array(16).fill({}) }) } });
  const cost = RELAY_METHODS.execute.costMicro;
  const r = relayWith(world);
  assert.equal((await r.relay('execute', { vault: VAULT, request: 1 })).body.ok, true);
  assert.equal(await spentGeneral(r), 16 * cost);
  const tight = relayWith(fakeWorld({ vaults: { [VAULT]: vaultRow() }, requests: { 1: requestRow({ inputs: Array(16).fill({}) }) } }), { CEILING_GENERAL_MICRO: 4 * cost });
  const over = await tight.relay('execute', { vault: VAULT, request: 1 });
  assert.deepEqual([over.body.code, over.body.bucket], ['daily_ceiling', 'general']);
  assert.equal(await spentGeneral(tight), 0);
});

test('state: a day limit per vault, across the key\'s methods, and it outlives the two-hour prune', async () => {
  const ns = localStateNamespace();
  const state = new StateClient(ns);
  const charge = (method, now) => state.call('charge', { key: 'owner', method, vault: VAULT, now, ceiling: 1e9 });
  let at = NOW;
  for (let i = 0; i < 12; i += 1) {
    assert.equal((await charge(i % 2 ? 'cancel' : 'cancel_all_and_rotate', at)).ok, true, `send ${i}`);
    at += 11 * 60_000;
  }
  const over = await charge('cancel', at);
  assert.deepEqual([over.ok, over.code], [false, 'rate_limited']);
  assert.ok(over.retry_after_s > 0 && over.retry_after_s <= 86_400);
});
