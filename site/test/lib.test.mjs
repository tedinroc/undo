// The library's own logic, offline. Network answers here are copied from real ones where a real one exists.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { sha256 } from '../../tools/lib/crypto.mjs';
import { toHex } from '../../tools/lib/bytes.mjs';
import { fromBase64, fromBase64Url, toBase64, toBase64Url } from '../lib/base64.mjs';
import { p2wshSpk, postTxOnce, scriptMatchesVault } from '../lib/bitcoin.mjs';
import { clock, digits, SkewTracker } from '../lib/clock.mjs';
import { btcAddressLabel, btcTxLabel, btcTxLink, checkConfig, ConfigError, loadConfig, nearTxLabel } from '../lib/config.mjs';
import { buildFragment, parseFragment, withoutSecret } from '../lib/fragment.mjs';
import { NearReader, RpcDown, StaleRead, ViewRefused } from '../lib/near-read.mjs';
import { checkPow, solvePow } from '../lib/pow.mjs';
import { RelayClient, RelayRefused } from '../lib/relay-client.mjs';
import { executeTgas, RELAY_ERRORS, RELAY_METHODS, relayBodyProblem } from '../lib/relay-table.mjs';
import { chooseOnScreen, coinCheck } from '../lib/pending.mjs';
import { advanceState, cancelButton, requestState, RETRY_AFTER_BLOCKS, RETRY_WINDOW_MS, retryClosesAt } from '../lib/request-state.mjs';
import { credentialsFor } from '../lib/passkey-source.mjs';
import { parseRequest, parseVault, ShapeError } from '../lib/views.mjs';

const hex32 = (label) => toHex(sha256(new TextEncoder().encode(`undo-test-only:web:${label}`)));

// ---------------------------------------------------------------- clock

test('clock: the contract\'s unlock against the block time, moved on by elapsed local time', () => {
  const c = clock(1_000_300_000, { blockMs: 1_000_000_000, localMs: 5_000 }, 5_000);
  assert.equal(c.remainingMs, 300_000);
  assert.equal(c.text, '5:00.0');
  const later = clock(1_000_300_000, { blockMs: 1_000_000_000, localMs: 5_000 }, 6_500);
  assert.equal(later.remainingMs, 298_500);
  assert.equal(later.text, '4:58.5');
});

test('clock: a laptop with a wrong clock reads the same, because only elapsed time is local', () => {
  const unlock = 1_000_060_000;
  const right = clock(unlock, { blockMs: 1_000_000_000, localMs: 1_000_000_000 }, 1_000_002_000);
  const wrong = clock(unlock, { blockMs: 1_000_000_000, localMs: 7_777 }, 9_777);
  assert.equal(wrong.remainingMs, right.remainingMs);
});

test('clock: no request, no clock', () => {
  assert.equal(clock(null, { blockMs: 1, localMs: 1 }, 2), null);
  assert.equal(clock(100, null, 2), null);
});

test('clock: stops at zero and says so, and the fuse burns from one to zero', () => {
  const sample = { blockMs: 1000, localMs: 0 };
  const zero = clock(1000, sample, 50, 0);
  assert.equal(zero.zero, true);
  assert.equal(zero.text, '0:00.0');
  assert.equal(zero.fuse, 0);
  assert.equal(clock(1600, sample, 0, 1000).fuse, 1);
  assert.equal(clock(1600, sample, 300, 1000).fuse, 0.5);
});

test('digits: reads 0:00.0 only at real zero, and keeps a fixed shape', () => {
  assert.equal(digits(1).text, '0:00.1');
  assert.equal(digits(0).text, '0:00.0');
  assert.equal(digits(59_950).text, '1:00.0');
  assert.equal(digits(60_001).text, '1:00.1');
  assert.equal(digits(599_999).text, '10:00.0');
  for (const ms of [1, 999, 9_001, 59_999, 299_999]) assert.match(digits(ms).text, /^\d:\d\d\.\d$/);
});

test('SkewTracker: keeps the reading closest to the chain, and forgets old ones', () => {
  const t = new SkewTracker({ windowMs: 10_000 });
  t.add({ blockMs: 1000, localMs: 5000 });
  // Slow response: the same block heard later reads further behind.
  assert.deepEqual(t.add({ blockMs: 1000, localMs: 7000 }), { blockMs: 1000, localMs: 5000 });
  assert.deepEqual(t.add({ blockMs: 3500, localMs: 7200 }), { blockMs: 3500, localMs: 7200 });
  // Window passes.
  assert.deepEqual(t.add({ blockMs: 12_000, localMs: 20_000 }), { blockMs: 12_000, localMs: 20_000 });
});

test('SkewTracker: one read ahead of the rest moves nothing, and a second that agrees moves it', () => {
  const t = new SkewTracker();
  t.add({ blockMs: 10_000, localMs: 10_000 });
  t.add({ blockMs: 15_000, localMs: 15_000 });
  const twoHoursOn = t.add({ blockMs: 20_000 + 7_200_000, localMs: 20_000 });
  assert.equal(twoHoursOn.blockMs - twoHoursOn.localMs, 0, 'a block time two hours ahead, once');
  const again = t.add({ blockMs: 25_000, localMs: 25_000 });
  assert.equal(again.blockMs - again.localMs, 0, 'and the next good read does not bring it back');

  const jump = new SkewTracker();
  jump.add({ blockMs: 10_000, localMs: 10_000 });
  jump.add({ blockMs: 15_000, localMs: 15_000 });
  const unconfirmed = jump.add({ blockMs: 280_000, localMs: 20_000 });
  assert.equal(unconfirmed.blockMs - unconfirmed.localMs, 0);
  assert.equal(jump.add({ blockMs: 285_000, localMs: 25_000 }).blockMs, 280_000, 'a real jump, seen twice');
  const first = new SkewTracker();
  assert.equal(first.sample(), null);
  assert.equal(first.add({ blockMs: 5, localMs: 1 }).blockMs, 5, 'one read is all there is at the start');
});

// ---------------------------------------------------------------- request state

const VAULT = { spend_epoch: 4, frozen_until: null };
const req = (over = {}) => ({ status: 'Pending', epoch: 4, unlock: 1000, expires_at: 5000, ...over });
const read = (request, chainNow = 500, vault = VAULT, lastKnown = null) => requestState({ request, vault, chainNow, lastKnown });

test('advanceState: expired does not stick, because it rests on a block time. Cancelled and signed do', () => {
  const expired = read(req(), 6000);
  assert.equal(expired.kind, 'expired');
  assert.equal(expired.terminal, false);
  assert.equal(advanceState(expired, read(req(), 500)).kind, 'waiting', 'a read with a sane clock brings the request back');
  assert.equal(advanceState(read(req({ epoch: 3 })), read(req(), 6000)).kind, 'cancelled');
});

test('chooseOnScreen: a small self-spend cannot hide a drain, or end the screen while the drain can still be cancelled', () => {
  const SELF = 'self';
  const item = (id, state, over = {}) => ({ id, state: { kind: state, cancellable: state === 'waiting' || state === 'unlocked' }, request: { to: 'thief', unlock: 1000, inputs: [{ value: 2000 }], ...over } });
  const decoy = { to: SELF, unlock: 100, inputs: [{ value: 1000 }] };
  const on = (...items) => chooseOnScreen(items, { selfSpk: SELF });
  const both = on(item(0, 'waiting'), item(1, 'waiting', decoy));
  assert.deepEqual([both.focus.id, both.moreWaiting, both.alreadySigned], [0, 1, 0]);
  const signedDecoy = on(item(0, 'waiting'), item(1, 'signed', decoy));
  assert.deepEqual([signedDecoy.focus.id, signedDecoy.focus.state.kind, signedDecoy.moreWaiting, signedDecoy.alreadySigned], [0, 'waiting', 0, 1], 'Cancel stays');
  const cancelled = on(item(0, 'cancelled'), item(1, 'signed', decoy));
  assert.deepEqual([cancelled.focus.id, cancelled.focus.state.kind, cancelled.alreadySigned], [0, 'cancelled', 1]);
  const realDrain = on(item(0, 'signed'), item(1, 'cancelled', decoy));
  assert.deepEqual([realDrain.focus.id, realDrain.focus.state.kind], [0, 'signed'], 'a spend that paid out is what the screen is about');
  assert.equal(on(item(0, 'cancelled'), item(1, 'signed')).focus.id, 1, 'among spends, the latest');
  assert.equal(on(item(5, 'waiting', { inputs: [{ value: 5000 }] }), item(7, 'waiting')).focus.id, 5, 'the larger');
  assert.equal(on().focus, null);
  assert.equal(on({ id: 0, state: null, request: null }).focus, null, 'a request not yet read is not on the screen');
  const valued = chooseOnScreen([item(5, 'waiting', { inputs: [{ value: 5_000_000 }] }), item(7, 'waiting')], { selfSpk: SELF, realValue: (r) => (r.inputs[0].value > 2000 ? 0 : 2000) });
  assert.equal(valued.focus.id, 7, 'a coin a node doesn\'t know counts for nothing, whatever it declares');
});

test('coinCheck: what a node says about each coin, and declared only until it has said', () => {
  const request = { inputs: [{ txid: 'a', vout: 0, value: 100 }, { txid: 'b', vout: 1, value: 200 }] };
  assert.deepEqual(coinCheck(request, new Map()), { real: 300, unknown: 0, differs: false, complete: false });
  assert.deepEqual(coinCheck(request, new Map([['a:0', { known: true, value: 100 }], ['b:1', { known: true, value: 200 }]])), { real: 300, unknown: 0, differs: false, complete: true });
  assert.deepEqual(coinCheck(request, new Map([['a:0', { known: false }], ['b:1', { known: true, value: 150 }]])), { real: 150, unknown: 1, differs: true, complete: true });
});

test('txOutcome: an answer from before the contract ran is not settled, and a settled failure is the chain\'s words', async () => {
  const answers = { INCLUDED: { final_execution_status: 'INCLUDED', status: { SuccessValue: '' }, receipts_outcome: [] }, EXECUTED_OPTIMISTIC: { final_execution_status: 'EXECUTED_OPTIMISTIC', status: { Failure: { ActionError: 'BadNonce' } }, receipts_outcome: [] } };
  const reader = new NearReader({ urls: ['http://x'], fetchFn: async (url, init) => {
    const { params } = JSON.parse(init.body);
    return new Response(JSON.stringify({ result: answers[params.wait_until] }));
  } });
  const early = await reader.txOutcome('h', 's');
  assert.deepEqual([early.known, early.settled, early.failure], [true, false, null]);
  const ran = await reader.txOutcome('h', 's', { wait: 'EXECUTED_OPTIMISTIC' });
  assert.deepEqual([ran.known, ran.settled], [true, true]);
  assert.match(ran.failure, /BadNonce/);
});

test('requestState: waiting, then unlocked at exactly the unlock, still cancellable until execute', () => {
  assert.equal(read(req(), 999).kind, 'waiting');
  assert.equal(read(req(), 999).clockRuns, true);
  const open = read(req(), 1000);
  assert.equal(open.kind, 'unlocked');
  assert.equal(open.cancellable, true);
  assert.equal(open.executable, true);
  assert.equal(open.clockRuns, false);
});

test('requestState: a Pending request of an old epoch is cancelled, though its status says Pending', () => {
  const s = read(req({ epoch: 3 }));
  assert.equal(s.kind, 'cancelled');
  assert.equal(s.reason, 'rotated');
  assert.equal(s.clockRuns, false);
  assert.equal(s.cancellable, false);
  assert.equal(read(req({ epoch: 3 }), 500, { spend_epoch: 4, frozen_until: 9000 }).reason, 'frozen');
});

test('requestState: a vault read behind the request is not a cancel. Epochs only rise', () => {
  const s = read(req({ epoch: 5 }));
  assert.equal(s.kind, 'unseen');
  assert.equal(s.terminal, false);
  assert.equal(s.clockRuns, false);
});

test('requestState: a signature of an old epoch is NOT cancelled. The coin got out', () => {
  for (const status of ['Signing', 'Signed']) {
    const s = read(req({ status, epoch: 3 }));
    assert.notEqual(s.kind, 'cancelled', `${status} after a rotation must not read as cancelled`);
    assert.equal(s.cancellable, false);
  }
});

test('requestState: expired, at one past expires_at. Alive at exactly expires_at, as is_dead has it', () => {
  assert.equal(read(req(), 5000).kind, 'unlocked');
  assert.equal(read(req(), 5001).kind, 'expired');
});

test('requestState: null is gone only for a request this page has read. A lagging node answers null too', () => {
  assert.equal(read(null).kind, 'unseen');
  assert.equal(read(null).clockRuns, false);
  assert.equal(read(null, 500, VAULT, req()).kind, 'cancelled');
  assert.equal(read(null, 500, VAULT, req()).reason, 'deleted');
  assert.equal(read(null, 500, VAULT, req({ epoch: 3 })).reason, 'rotated');
  assert.equal(read(null, 6000, VAULT, req()).kind, 'expired');
  assert.equal(read(null, 500, VAULT, req({ status: 'Signed' })).kind, 'signed');
  assert.equal(read(req(), 500, null).kind, 'no_vault');
});

test('advanceState: a terminal state holds against a lagging read, and only a signature overrides it', () => {
  const cancelled = read(req({ epoch: 3 }));
  assert.equal(advanceState(cancelled, read(req())).kind, 'cancelled');
  assert.equal(advanceState(cancelled, read(null)).kind, 'cancelled');
  assert.equal(advanceState(cancelled, read(req({ status: 'Signed' }))).kind, 'signed');
  assert.equal(advanceState(read(req()), read(req({ epoch: 3 }))).kind, 'cancelled');
  assert.equal(advanceState(null, read(req())).kind, 'waiting');
});

test('retryClosesAt: a spend that pays out stops asking a day after its first execute; a self-spend never does. The numbers are the core\'s', () => {
  const DAY = 24 * 60 * 60 * 1000;
  const signing = (over = {}) => ({ status: 'Signing', tier: 'Known', first_execute_at: 5_000, ...over });
  assert.equal(retryClosesAt(signing()), 5_000 + DAY);
  assert.equal(retryClosesAt(signing({ tier: 'New' })), 5_000 + DAY);
  assert.equal(retryClosesAt(signing({ tier: 'SelfSpend' })), null, 'a self-spend, and so a reclaim, keeps retrying');
  assert.equal(retryClosesAt(signing({ first_execute_at: null })), null);
  assert.equal(retryClosesAt(signing({ status: 'Pending' })), null);
  assert.equal(retryClosesAt(signing({ status: 'Signed' })), null);
  assert.equal(retryClosesAt(null), null);
  const core = (file) => readFileSync(new URL(`../../crates/undo-core/src/${file}`, import.meta.url), 'utf8');
  assert.match(core('policy.rs'), new RegExp(`pub const RETRY_AFTER_BLOCKS: u64 = ${RETRY_AFTER_BLOCKS};`));
  assert.match(core('policy.rs'), /pub const DAY: Ms = 24 \* HOUR;/);
  assert.equal(RETRY_WINDOW_MS, DAY);
  const vault = core('vault.rs');
  assert.match(vault, /if request\.tier != Tier::SelfSpend \{\n\s*let mut closed_at = request\.first_execute_at\.unwrap_or\(now\)\.saturating_add\(DAY\);/, 'the window the core keeps');
  assert.match(vault, /if !request\.in_flight\.is_empty\(\) && height < retry_at_height \{/, 'the in-flight rule the core keeps');
});

const RELAY_UP = { reachable: true, owner: { up: true } };
const GOOD = { state: read(req()), relay: RELAY_UP, passkey: { canAssert: true, rpMatches: true }, originAllowed: true };

test('cancelButton: shown only when it can work, and each refusal names why', () => {
  assert.deepEqual(cancelButton(GOOD), { show: true, why: null });
  const why = (over) => cancelButton({ ...GOOD, ...over });
  assert.equal(why({ state: read(req(), 1000) }).show, true, 'still works at zero, until execute');
  assert.equal(why({ state: read(req({ status: 'Signed' })) }).why, 'not_cancellable');
  assert.equal(why({ relay: { reachable: false, owner: { up: false } } }).why, 'relay_down');
  assert.equal(why({ relay: { reachable: true, owner: { up: false, why: 'daily_ceiling' } } }).why, 'daily_ceiling');
  assert.equal(why({ passkey: { canAssert: false, rpMatches: true } }).why, 'no_passkey_here');
  assert.equal(why({ passkey: { canAssert: true, rpMatches: false } }).why, 'wrong_site_for_passkey');
  assert.equal(why({ originAllowed: false }).why, 'origin_not_allowed');
  assert.equal(why({ frozen: true }).why, 'frozen');
});

// ---------------------------------------------------------------- fragment

test('fragment: round trip, and a malformed field is reported and not used', () => {
  const v = hex32('vault');
  const hash = buildFragment({ v, r: 7, c: 'abc-_', to: 'tb1qaaaaaaaaaaaaaaaaaaaa' });
  assert.deepEqual(parseFragment(hash), { v, r: 7, c: 'abc-_', to: 'tb1qaaaaaaaaaaaaaaaaaaaa', refused: [] });
  const bad = parseFragment('#v=XYZ&r=-1&other=1');
  assert.equal(bad.v, undefined);
  assert.deepEqual(bad.refused, ['v', 'r']);
  assert.throws(() => buildFragment({ v: 'nope' }));
  assert.throws(() => buildFragment({ query: '1' }));
});

test('fragment: each field is exactly its form. A request id reads back as itself, never rounded to another', () => {
  const v = hex32('vault');
  const cases = [
    [`#v=${v.slice(1)}`, 'v'],
    [`#v=${v}a`, 'v'],
    ['#r=01', 'r'],
    ['#r=99999999999999999', 'r'],
    // Sixteen digits, but past 2^53: Number() would read 9007199254740992, another request.
    ['#r=9007199254740993', 'r'],
    ['#r=9999999999999999', 'r'],
    ['#to=tb1q<aaaaaaaaaaaaaaaaaaaa', 'to'],
    ['#to=TB1QAAAAAAAAAAAAAAAAAAAA', 'to'],
    ['#to=tb1q%20aaaaaaaaaaaaaaaaaaa', 'to'],
  ];
  for (const [hash, field] of cases) {
    const out = parseFragment(hash);
    assert.deepEqual([out[field], out.refused], [undefined, [field]], hash);
  }
  assert.equal(parseFragment('#r=9007199254740991').r, Number.MAX_SAFE_INTEGER, 'the largest id a page can hold still reads');
  assert.equal(parseFragment('#r=0').r, 0);
  assert.throws(() => buildFragment({ r: 2 ** 53 }), /malformed/, 'and none is written');
});

test('fragment: a stolen seed can be taken back out of the address bar', () => {
  const v = hex32('vault');
  const hash = buildFragment({ v, k: hex32('stolen') });
  assert.ok(hash.includes('k='));
  assert.equal(withoutSecret(hash), buildFragment({ v }));
});

// ---------------------------------------------------------------- base64

test('base64: agrees with Node on every length, url form unpadded', () => {
  for (let n = 0; n < 70; n += 1) {
    const bytes = Uint8Array.from({ length: n }, (_, i) => (i * 37 + n) & 0xff);
    assert.equal(toBase64(bytes), Buffer.from(bytes).toString('base64'));
    assert.equal(toBase64Url(bytes), Buffer.from(bytes).toString('base64url'));
    assert.deepEqual(fromBase64(toBase64(bytes)), bytes);
    assert.deepEqual(fromBase64Url(toBase64Url(bytes)), bytes);
  }
});

// ---------------------------------------------------------------- config

const LOCAL = {
  mode: 'local', contract: 'film.test.near', rpc: ['http://127.0.0.1:3030'], esplora: 'http://127.0.0.1:3002', relay: '/api/relay', funds: '/api/funds',
  btcTxUrl: null, btcAddressUrl: null, nearTxUrl: null, rpId: 'localhost', softPasskey: true,
};
const LIVE = {
  ...LOCAL, mode: 'testnet', contract: 'x.testnet', rpc: ['https://rpc.example'], esplora: 'https://esplora.example/api',
  btcTxUrl: 'https://esplora.example/tx/{}', btcAddressUrl: 'https://esplora.example/address/{}', nearTxUrl: 'https://near.example/tx/{}', rpId: 'site.example', softPasskey: false,
};

test('config: local mode refuses any host off this machine, for every URL', () => {
  assert.ok(checkConfig(LOCAL));
  assert.throws(() => checkConfig({ ...LOCAL, rpc: ['http://127.0.0.1:1', 'https://rpc.example'] }), ConfigError);
  assert.throws(() => checkConfig({ ...LOCAL, esplora: 'https://esplora.example/api' }), ConfigError);
  assert.throws(() => checkConfig({ ...LOCAL, btcTxUrl: 'https://esplora.example/tx/{}' }), ConfigError);
});

test('config: a live page refuses local hosts, plain http and an unlabelled software passkey', () => {
  assert.ok(checkConfig(LIVE));
  assert.throws(() => checkConfig({ ...LIVE, rpc: ['http://rpc.example'] }), ConfigError);
  assert.throws(() => checkConfig({ ...LIVE, esplora: 'https://localhost:1/api' }), ConfigError);
  assert.throws(() => checkConfig({ ...LIVE, softPasskey: true }), ConfigError);
  assert.ok(checkConfig({ ...LIVE, softPasskey: true, softPasskeyLabel: 'Signed by a test key in this browser.' }));
});

test('config: there is no default. Anything missing stops the page', async () => {
  for (const field of ['mode', 'contract', 'rpc', 'esplora', 'relay', 'funds', 'rpId', 'softPasskey']) {
    const partial = { ...LOCAL };
    delete partial[field];
    assert.throws(() => checkConfig(partial), ConfigError, field);
  }
  await assert.rejects(loadConfig({ fetchFn: async () => { throw new TypeError('x'); } }), ConfigError);
  await assert.rejects(loadConfig({ fetchFn: async () => ({ ok: false, status: 404 }) }), ConfigError);
  assert.equal((await loadConfig({ fetchFn: async () => ({ ok: true, json: async () => LOCAL }) })).contract, LOCAL.contract);
});

test('config: every label names its chain, and a local run cannot read as a live one', () => {
  const live = checkConfig(LIVE);
  const local = checkConfig(LOCAL);
  assert.equal(live.labels.chip, 'signet test coins');
  assert.equal(nearTxLabel(live, 'H'), 'NEAR testnet tx H');
  assert.equal(btcTxLabel(live, 't'), 'Mutinynet txid t');
  assert.equal(btcAddressLabel(live, 'a'), 'Mutinynet address a');
  assert.equal(btcTxLink(live, 't'), 'https://esplora.example/tx/t');
  assert.equal(nearTxLabel(local, 'H'), 'local NEAR sandbox tx H');
  assert.equal(btcTxLabel(local, 't'), 'local regtest txid t');
  assert.equal(btcTxLink(local, 't'), null);
  assert.notEqual(local.labels.chip, 'signet test coins');
});

// ---------------------------------------------------------------- NEAR reads

function rpcFake(handlers) {
  const calls = [];
  const fetchFn = async (url, init) => {
    const body = JSON.parse(init.body);
    calls.push({ url, method: body.method });
    const answer = await handlers[url](body);
    if (answer instanceof Error) throw answer;
    return { status: answer.status ?? 200, text: async () => (typeof answer.raw === 'string' ? answer.raw : JSON.stringify(answer.raw)) };
  };
  return { fetchFn, calls };
}
const viewResult = (value, height = 100) => ({ raw: { jsonrpc: '2.0', id: 1, result: { result: [...new TextEncoder().encode(JSON.stringify(value))], logs: [], block_height: height, block_hash: 'x' } } });

test('NearReader: moves to the next URL on a dropped connection, a 429, a web page or a rate-limit error, and sticks with what works', async () => {
  for (const bad of [new TypeError('fetch failed'), { status: 429, raw: 'Too Many Requests' }, { status: 502, raw: '<html>Bad Gateway</html>' }, { raw: { jsonrpc: '2.0', id: 1, error: { code: -429, message: 'Rate limits exceeded' } } }]) {
    const { fetchFn, calls } = rpcFake({ a: () => bad, b: () => viewResult({ ok: 1 }) });
    const r = new NearReader({ urls: ['a', 'b'], fetchFn });
    assert.deepEqual(await r.view('c', 'status'), { ok: 1 });
    assert.deepEqual(calls.map((c) => c.url), ['a', 'b']);
    await r.view('c', 'status');
    assert.equal(calls.at(-1).url, 'b', 'the next read starts at the URL that worked');
  }
});

test('NearReader: RpcDown names every URL tried, and a timeout reaches fetch', async () => {
  const signals = [];
  const r = new NearReader({ urls: ['a', 'b'], timeoutMs: 123, fetchFn: async (_, init) => {
    signals.push(init.signal);
    throw new TypeError('down');
  } });
  await assert.rejects(r.view('c', 'status'), (err) => err instanceof RpcDown && err.tried.length === 2);
  assert.ok(signals.every((s) => s instanceof AbortSignal));
});

test('NearReader: a contract refusal keeps the node\'s words and is not retried elsewhere', async () => {
  const text = 'wasm execution failed with error: FunctionCallError(ExecutionError("Smart contract panicked: no such vault"))';
  const { fetchFn, calls } = rpcFake({ a: () => ({ raw: { jsonrpc: '2.0', id: 1, result: { error: text, logs: [], block_height: 5, block_hash: 'x' } } }), b: () => viewResult({}) });
  await assert.rejects(new NearReader({ urls: ['a', 'b'], fetchFn }).view('c', 'vault'), (err) => err instanceof ViewRefused && err.verbatim === text);
  assert.equal(calls.length, 1);
});

test('NearReader: reads do not go back in time. An old block tries the next node, then says it is stale', async () => {
  let height = 100;
  const { fetchFn, calls } = rpcFake({ a: () => viewResult('new', height), b: () => viewResult('lagging', 90) });
  const r = new NearReader({ urls: ['a', 'b'], fetchFn });
  assert.equal(await r.view('c', 'x'), 'new');
  height = 95; // Behind by more than the tolerance.
  await assert.rejects(r.view('c', 'x'), StaleRead);
  assert.equal(calls.length, 3);
  height = 98; // Within it. Two honest nodes are often a block or two apart.
  assert.equal(await r.view('c', 'x'), 'new');
});

test('NearReader: accessKeys asks for the account\'s key list at a final block, and anything that is not a list is an error, never an empty list', async () => {
  const asked = [];
  const answer = (body) => async (url, init) => {
    asked.push(JSON.parse(init.body));
    return new Response(JSON.stringify(body), { status: 200 });
  };
  const keys = [{ public_key: 'ed25519:4W7aoutQcmfkctj8PddfREwcySTQoyrM91F9Lh4M6RWq', access_key: { nonce: 7, permission: 'FullAccess' } }];
  const read = await new NearReader({ urls: ['a'], fetchFn: answer({ jsonrpc: '2.0', id: 1, result: { keys, block_height: 9, block_hash: 'x' } }) }).accessKeys('c.testnet');
  assert.deepEqual(read, keys);
  assert.deepEqual(asked[0].params, { request_type: 'view_access_key_list', account_id: 'c.testnet', finality: 'final' });
  assert.equal(asked[0].method, 'query');
  assert.deepEqual(await new NearReader({ urls: ['a'], fetchFn: answer({ jsonrpc: '2.0', id: 1, result: { keys: [], block_height: 9 } }) }).accessKeys('c.testnet'), []);
  // An account that does not exist, and an answer with no list: both throw, so a page cannot read them as "no key".
  const unknown = { jsonrpc: '2.0', id: 1, error: { name: 'HANDLER_ERROR', cause: { name: 'UNKNOWN_ACCOUNT', info: { requested_account_id: 'c.testnet' } }, code: -32000 } };
  await assert.rejects(new NearReader({ urls: ['a'], fetchFn: answer(unknown) }).accessKeys('c.testnet'), (err) => err instanceof ViewRefused && /UNKNOWN_ACCOUNT/.test(err.verbatim));
  await assert.rejects(new NearReader({ urls: ['a'], fetchFn: answer({ jsonrpc: '2.0', id: 1, result: { block_height: 9 } }) }).accessKeys('c.testnet'), ViewRefused);
  await assert.rejects(new NearReader({ urls: ['a', 'b'], fetchFn: async () => { throw new TypeError('fetch failed'); } }).accessKeys('c.testnet'), RpcDown);
});

test('NearReader: blockTime returns the block\'s own time and when it was heard', async () => {
  let t = 1000;
  const { fetchFn } = rpcFake({ a: () => {
    t += 40;
    return { raw: { jsonrpc: '2.0', id: 1, result: { header: { height: 77, timestamp_nanosec: '1730000000123456789' } } } };
  } });
  const b = await new NearReader({ urls: ['a'], fetchFn, nowFn: () => t }).blockTime();
  assert.deepEqual(b, { blockMs: 1730000000123, height: 77, localMs: 1040, rttMs: 40 });
});

// ---------------------------------------------------------------- Bitcoin POST

// Mutinynet's real answers. The first is what the node said on 11/1 to the spend key alone, in the S2 capture.
const REAL_SCRIPT_REFUSAL = "sendrawtransaction RPC error: {\"code\":-26,\"message\":\"mempool-script-verify-flag-failed (Script evaluated without error but finished with a false/empty top stack element), input 0 of 6aa2b419a2f28a475c539fa25445101650ac90f0960aa1ae0ec5bbdae0128eb2 (wtxid b8cf7847664583ca66c10a55a93e61231bd1eeacf1b45a4af20bd13427234f9f), spending 65801b967be8ada9e4299513908960952f18c7f0e5e3f96aaba04a46a5a66e24:0\"}";
const REAL_ALREADY = 'sendrawtransaction RPC error: {"code":-27,"message":"Transaction outputs already in utxo set"}';

const postFake = (status, body) => async () => ({ status, text: async () => body });

test('postTxOnce: keeps exactly what the node said, untrimmed, and sorts it', async () => {
  const padded = ` ${REAL_SCRIPT_REFUSAL}\n`;
  const r = await postTxOnce('http://x', 'aa', 'id', { fetchFn: postFake(400, padded) });
  assert.equal(r.body, padded, 'verbatim');
  assert.equal(r.kind, 'rejected');
  assert.equal(r.refusal, 'script');
  assert.equal((await postTxOnce('http://x', 'aa', 'id', { fetchFn: postFake(400, REAL_ALREADY) })).refusal, 'already');
});

test('postTxOnce: only a node\'s answer counts. A gateway error or a dropped line is not a refusal', async () => {
  assert.equal((await postTxOnce('http://x', 'aa', 'id', { fetchFn: postFake(503, 'Service Unavailable') })).kind, 'transient');
  assert.equal((await postTxOnce('http://x', 'aa', 'id', { fetchFn: postFake(400, '<html>nope</html>') })).kind, 'transient');
  const dropped = await postTxOnce('http://x', 'aa', 'id', { fetchFn: async () => { throw new TypeError('fetch failed'); } });
  assert.equal(dropped.kind, 'no_answer');
  assert.equal(dropped.body, null);
  assert.equal(dropped.error, 'the connection failed', 'a screen shows words, not the browser\'s error name');
  assert.equal(dropped.errorKind, 'TypeError', 'which is kept for logs');
  assert.equal((await postTxOnce('http://x', 'aa', 'id', { fetchFn: postFake(200, 'id') })).kind, 'accepted');
});

test('postTxOnce: sends once, as text', async () => {
  const calls = [];
  await postTxOnce('http://x', 'aabb', 'id', { fetchFn: async (url, init) => {
    calls.push({ url, body: init.body, type: init.headers['content-type'] });
    return { status: 503, text: async () => '' };
  } });
  assert.deepEqual(calls, [{ url: 'http://x/tx', body: 'aabb', type: 'text/plain' }]);
});

test('scriptMatchesVault: the thief tab goes on only when the contract\'s script pays the vault\'s own address', () => {
  const script = new TextEncoder().encode('undo-test-only:web:script-a');
  const vault = { script_pubkey: toHex(p2wshSpk(script)) };
  assert.equal(scriptMatchesVault(script, vault), true);
  assert.equal(scriptMatchesVault(new TextEncoder().encode('undo-test-only:web:script-b'), vault), false, 'another vault\'s script');
  assert.equal(scriptMatchesVault(script, { script_pubkey: `0014${'11'.repeat(20)}` }), false, 'a key hash, not this script');
});

// ---------------------------------------------------------------- views

test('parsers: a field a page reads, if missing or wrong, is an error here and not a blank on a screen', () => {
  assert.throws(() => parseRequest({ id: 1 }), ShapeError);
  assert.throws(() => parseVault({ id: 'zz' }), ShapeError);
  assert.throws(() => parseVault(null), ShapeError);
});

// ---------------------------------------------------------------- proof of work

test('pow: a solution checks, binds the vault, and bits are real bits', async () => {
  const v = hex32('pow');
  const nonce = await solvePow(v, 10);
  assert.ok(checkPow(v, nonce, 10));
  assert.ok(!checkPow(hex32('other'), nonce, 10) || !checkPow(hex32('other2'), nonce, 10));
  assert.equal(checkPow(v, -1, 0), false);
  assert.equal(checkPow(v, 1.5, 0), false);
  let tries = 0;
  for (let i = 0; i < 2000; i += 1) if (checkPow(v, i, 4)) tries += 1;
  assert.ok(tries > 60 && tries < 200, `about 1 in 16, got ${tries} of 2000`);
});

// ---------------------------------------------------------------- relay table

test('relay table: owner methods go on the owner key and nothing else does', () => {
  const owner = Object.entries(RELAY_METHODS).filter(([, m]) => m.key === 'owner').map(([n]) => n).sort();
  assert.deepEqual(owner, ['cancel', 'cancel_all_and_rotate']);
  for (const name of owner) assert.equal(RELAY_METHODS[name].perIpHour, undefined, 'a shared IP must not stop a cancel');
  assert.equal(RELAY_METHODS.create_vault.pow, true);
});

test('relay table: execute gas is at or above every measured least, inside the transaction limit', () => {
  const cfg = { signTgas: 30, callbackTgas: 10 };
  for (const [inputs, least] of [[1, 46], [3, 130], [8, 344], [16, 688]]) {
    assert.ok(executeTgas(inputs, cfg) >= least);
    assert.ok(executeTgas(inputs, cfg) <= 1000);
  }
});

test('relay table: refuses unknown methods, extra keys and bad hex before any gas is spent', () => {
  const vault = hex32('v');
  assert.equal(relayBodyProblem({ method: 'heartbeat', args: { vault } }), null);
  assert.equal(relayBodyProblem({ method: 'set_policy', args: { vault } }), 'unknown_method');
  assert.equal(relayBodyProblem({ method: 'upgrade_propose', args: {} }), 'unknown_method');
  assert.equal(relayBodyProblem({ method: '__proto__', args: {} }), 'unknown_method');
  assert.equal(relayBodyProblem({ method: 'heartbeat', args: { vault, extra: 1 } }), 'bad_request');
  assert.equal(relayBodyProblem({ method: 'heartbeat', args: { vault: 'XY' } }), 'bad_request');
  assert.equal(relayBodyProblem({ method: 'heartbeat', args: { vault }, gas: 300 }), 'bad_request');
  assert.equal(relayBodyProblem({ method: 'execute', args: { vault, request: 1, sign_tgas: 300 } }), 'bad_request');
  assert.equal(relayBodyProblem(null), 'bad_request');
  assert.equal(relayBodyProblem([]), 'bad_request');
});

// ---------------------------------------------------------------- relay client

const jsonFake = (status, value) => async () => ({ status, json: async () => value });

test('RelayClient.status: never throws. A dead relay, a web page or a refusal all read as a state', async () => {
  const make = (fetchFn) => new RelayClient({ relay: '/api/relay', funds: '/api/funds', fetchFn }).status();
  const down = await make(async () => { throw new TypeError('down'); });
  assert.equal(down.reachable, false);
  assert.equal(down.owner.up, false);
  assert.equal(down.why, 'the connection failed');
  assert.equal(down.errorKind, 'TypeError');
  assert.equal((await make(async () => ({ status: 502, json: async () => { throw new SyntaxError('html'); } }))).reachable, false);
  assert.equal((await make(jsonFake(503, { ok: false, code: 'relay_not_configured' }))).why, 'relay_not_configured');
  const up = await make(jsonFake(200, { ok: true, relay_account: 'r.testnet', pow_bits: 18, owner: { up: true }, general: { up: false, why: 'daily_ceiling' }, funds: { up: true } }));
  assert.equal(up.reachable, true);
  assert.equal(up.relayAccount, 'r.testnet');
  assert.equal(up.general.why, 'daily_ceiling');
});

test('RelayClient.call: a refusal keeps the code and the chain\'s own words', async () => {
  const verbatim = '{"ActionError":{"index":0,"kind":{"FunctionCallError":{"ExecutionError":"Smart contract panicked: webauthn: wrong challenge"}}}}';
  const client = new RelayClient({ relay: '/api/relay', funds: '/api/funds', fetchFn: jsonFake(422, { ok: false, code: 'tx_refused', message: 'the contract refused it', verbatim }) });
  await assert.rejects(client.call('cancel', {}), (err) => err instanceof RelayRefused && err.code === 'tx_refused' && err.verbatim === verbatim && err.httpStatus === 422);
  const ceiling = new RelayClient({ relay: '/r', funds: '/f', fetchFn: jsonFake(429, { ok: false, code: 'daily_ceiling', bucket: 'general', resets_at: 1730000000000 }) });
  await assert.rejects(ceiling.call('propose_btc', {}), (err) => err.code === 'daily_ceiling' && err.bucket === 'general' && err.resetsAt === 1730000000000);
  const dead = new RelayClient({ relay: '/r', funds: '/f', fetchFn: async () => { throw new TypeError('x'); } });
  await assert.rejects(dead.call('cancel', {}), (err) => err.code === 'relay_down' && err.message === 'no answer from the relay: the connection failed' && err.errorKind === 'TypeError');
  const slow = new RelayClient({ relay: '/r', funds: '/f', fetchFn: async () => { throw new DOMException('timed out', 'TimeoutError'); } });
  await assert.rejects(slow.call('cancel', {}), (err) => err.message === 'no answer from the relay: no answer in time' && err.errorKind === 'TimeoutError');
  assert.ok(Object.hasOwn(RELAY_ERRORS, 'tx_refused'));
});

test('RelayClient.fund: the page names a vault, never a payee', async () => {
  const sent = [];
  const client = new RelayClient({ relay: '/r', funds: '/f', fetchFn: async (path, init) => {
    sent.push([path, JSON.parse(init.body)]);
    return { status: 200, json: async () => ({ ok: true, txid: 'abc', vout: 0, value: 2000 }) };
  } });
  await client.fund('aa', { pow: 7 });
  assert.deepEqual(sent, [['/f', { vault: 'aa', pow: 7 }]]);
});

// ---------------------------------------------------------------- where a page's passkey comes from

test('credentialsFor: the browser\'s on a normal build, a labelled software key only if the config says so', async () => {
  const browser = { get: 1 };
  const config = checkConfig(LOCAL);
  const off = checkConfig({ ...LOCAL, softPasskey: false });
  assert.equal(await credentialsFor(off, { browser }), browser);
  await assert.rejects(credentialsFor(off, { browser: undefined }), /no passkeys/);
  const soft = await credentialsFor(config, { browser, soft: { secret: sha256(new TextEncoder().encode('undo-test-only:web:soft')), origin: 'http://localhost:1' }, softPath: '../lib/soft-authenticator.mjs' });
  assert.equal(soft.label, '[software authenticator]');
  await assert.rejects(credentialsFor(config, { browser }), /needs a key/);
});
