// Offline tests of the watcher: its parts against stand-ins, and the command line against a stand-in NEAR RPC and
// tools/test/mock-ntfy.mjs, both on 127.0.0.1. Nothing here reaches a live host. Run with:
//   node --test tools/test/watch.test.mjs
// UNDO_SITE_DIR may point at a site/ folder from another branch, for the checks that compare with the site's
// config and fragment rules. In a tree that has site/config and site/lib, they run without it.
// Under a sandbox that blocks the keychain, NODE_USE_SYSTEM_CA=1 makes Node 22 hang at exit after any fetch, so
// the children here run without it, and so should this file.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { addressToSpk, p2wpkhAddress, p2wpkhSpk, p2wshAddress, p2wshSpk } from '../lib/btc.mjs';
import { toHex, utf8 } from '../lib/bytes.mjs';
import { randomBytes, secp256k1, sha256 } from '../lib/crypto.mjs';
import {
  addressOf, ALERT_TITLE, amountSats, buildAlert, chainNowOf, checkWatchConfig, clockText, CONFIG_FORMAT, ConfigError, contractReads, liveness, makeTopic, ntfyPublisher, phoneLink,
  PushFailed, RpcDown, RpcPool, StateStore, TESTNET_RPC, topicTag, unlockText, vaultFrom, Watcher,
} from '../lib/watch.mjs';
import { startMockNtfy } from './mock-ntfy.mjs';

const TOOLS = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const REPO = resolve(TOOLS, '..');
const SITE = process.env.UNDO_SITE_DIR ? resolve(process.env.UNDO_SITE_DIR) : join(REPO, 'site');
const WATCH = join(TOOLS, 'watch.mjs');
const VAULT = toHex(sha256(utf8('undo-test-only:watch-vault')));
const OTHER_TO = `0014${toHex(sha256(utf8('undo-test-only:watch-thief'))).slice(0, 40)}`;
const VAULT_SPK = `0020${toHex(sha256(utf8('undo-test-only:watch-vault-spk')))}`;

let work;
before(() => { work = mkdtempSync(join(tmpdir(), 'undo-watch-')); });
after(() => rmSync(work, { recursive: true, force: true }));

const localRaw = (over = {}) => ({
  format: CONFIG_FORMAT, network: 'local', contract: 'undo.test.near', vault: VAULT, rpc: ['http://127.0.0.1:1'], page_origin: 'http://localhost:8788',
  ntfy_server: 'http://127.0.0.1:2', ntfy_topic: makeTopic(), priority: 5, poll_ms: 200, ...over,
});
const testnetRaw = (over = {}) => ({
  format: CONFIG_FORMAT, network: 'testnet', contract: 'undo-btc.testnet', vault: VAULT, rpc: [...TESTNET_RPC], page_origin: 'https://undo-btc.pages.dev',
  ntfy_server: 'https://ntfy.sh', ntfy_topic: makeTopic(), priority: 5, poll_ms: 2000, ...over,
});

const request = (id, over = {}) => ({
  id, kind: 'Normal', status: 'Pending', epoch: 0, inputs: [{ txid: 'aa'.repeat(32), vout: 0, value: 2000 }], to: OTHER_TO, amount: 1600, change: null,
  tier: 'New', fee: 400, proposed_at: 1_000_000, base_unlock: 1_300_000, unlock: 1_300_000, expires_at: 2_800_000, ...over,
});
const vaultView = (pending, over = {}) => ({ id: VAULT, pending, spend_epoch: 0, script_pubkey: VAULT_SPK, ...over });

// ---------------------------------------------------------------- topic and config

test('a topic is 22 characters of A-Z a-z 0-9, and 2,000 of them never repeat', () => {
  const seen = new Set();
  const chars = new Set();
  for (let i = 0; i < 2000; i += 1) {
    const t = makeTopic();
    assert.match(t, /^[A-Za-z0-9]{22}$/);
    seen.add(t);
    for (const c of t) chars.add(c);
  }
  assert.equal(seen.size, 2000);
  assert.equal(chars.size, 62, 'every character of the alphabet turns up');
});

test('a topic tag is one-way and short, and never contains the topic', () => {
  const t = makeTopic();
  assert.match(topicTag(t), /^[0-9a-f]{16}$/);
  assert.ok(!topicTag(t).includes(t));
  assert.notEqual(topicTag(t), topicTag(makeTopic()));
});

test('the config refuses mainnet, a local run that leaves this machine, a live one that does not, and short topics', () => {
  assert.equal(checkWatchConfig(localRaw()).labels.label, '[mock-signer]');
  assert.equal(checkWatchConfig(testnetRaw()).labels.label, '[live-testnet]');
  const refuses = (raw, words) => assert.throws(() => checkWatchConfig(raw), (err) => err instanceof ConfigError && err.message.includes(words), words);
  refuses(testnetRaw({ network: 'mainnet' }), 'no mainnet watcher');
  refuses(testnetRaw({ contract: 'undo-btc.near' }), 'ends in .testnet');
  refuses(testnetRaw({ rpc: ['http://127.0.0.1:3030'] }), 'public https');
  refuses(testnetRaw({ rpc: ['http://rpc.testnet.near.org'] }), 'public https');
  refuses(localRaw({ rpc: ['https://rpc.testnet.near.org'] }), 'leaves this machine');
  refuses(localRaw({ ntfy_server: 'https://ntfy.sh' }), 'leaves this machine');
  refuses(localRaw({ page_origin: 'https://undo-btc.pages.dev' }), 'leaves this machine');
  refuses(testnetRaw({ page_origin: 'https://undo-btc.pages.dev/p/' }), 'origin alone');
  refuses(testnetRaw({ page_origin: 'https://undo-btc.pages.dev?x=1' }), 'origin alone');
  refuses(testnetRaw({ page_origin: 'https://undo-btc.pages.dev/' }), 'origin alone');
  refuses(testnetRaw({ ntfy_server: 'https://user:pw@ntfy.sh' }), 'user or password');
  refuses(testnetRaw({ ntfy_topic: 'short' }), 'ntfy_topic');
  refuses(testnetRaw({ ntfy_topic: 'has space in it and is long' }), 'ntfy_topic');
  refuses(testnetRaw({ vault: VAULT.toUpperCase() }), 'vault');
  refuses(testnetRaw({ poll_ms: 500 }), 'poll_ms');
  refuses(testnetRaw({ priority: 6 }), 'priority');
  refuses(testnetRaw({ format: 'other' }), 'format');
  refuses(testnetRaw({ rpc: [] }), 'rpc');
});

test('the testnet fallback list is the web config\'s, in its order', { skip: existsSync(join(SITE, 'config/testnet.json')) ? false : 'no site/config/testnet.json in this tree: set UNDO_SITE_DIR' }, () => {
  const site = JSON.parse(readFileSync(join(SITE, 'config/testnet.json'), 'utf8'));
  assert.deepEqual([...TESTNET_RPC], site.rpc);
  assert.equal(`https://${site.rpId}`, 'https://undo-btc.pages.dev');
});

test('a vault comes from an id or a phone link\'s fragment, never from a query string', () => {
  assert.equal(vaultFrom(VAULT), VAULT);
  assert.equal(vaultFrom(` ${VAULT}\n`), VAULT);
  assert.equal(vaultFrom(`https://undo-btc.pages.dev/p/#v=${VAULT}&r=3`), VAULT);
  assert.equal(vaultFrom(`https://undo-btc.pages.dev/p/#c=abc&v=${VAULT}`), VAULT);
  assert.equal(vaultFrom(`https://undo-btc.pages.dev/p/?v=${VAULT}`), null);
  assert.equal(vaultFrom(VAULT.toUpperCase()), null);
  assert.equal(vaultFrom(VAULT.slice(1)), null);
  assert.equal(vaultFrom(undefined), null);
});

// ---------------------------------------------------------------- what an alert says

test('the phone link puts the vault and request in the fragment, which the phone page\'s rules accept', async () => {
  const link = phoneLink('https://undo-btc.pages.dev', VAULT, 12);
  assert.equal(link, `https://undo-btc.pages.dev/p/#v=${VAULT}&r=12`);
  assert.ok(!link.includes('?'));
  const fields = new URLSearchParams(new URL(link).hash.slice(1));
  // The forms site/lib/fragment.mjs takes: a vault id of 64 hex, and a request id with no leading zero that reads back
  // as a safe integer. Where site/ is in the tree, parseFragment below applies the rule itself.
  assert.match(fields.get('v'), /^[0-9a-f]{64}$/);
  assert.match(fields.get('r'), /^(0|[1-9][0-9]{0,15})$/);
  assert.ok(Number.isSafeInteger(Number(fields.get('r'))));
  const fragmentLib = join(SITE, 'lib/fragment.mjs');
  if (existsSync(fragmentLib)) {
    const { parseFragment } = await import(pathToFileURL(fragmentLib).href);
    const parsed = parseFragment(new URL(link).hash);
    assert.equal(parsed.v, VAULT);
    assert.equal(parsed.r, 12);
    assert.deepEqual(parsed.refused, []);
  }
});

test('addresses: each script type gives the address the tools build, and decodes back to the same script', () => {
  const pub = secp256k1.getPublicKey(sha256(utf8('undo-test-only:watch-addr')), true);
  for (const net of ['mutinynet', 'regtest']) {
    assert.equal(addressOf(net, toHex(p2wpkhSpk(pub))), p2wpkhAddress(net, pub));
    const script = utf8('undo-test-only:a script');
    assert.equal(addressOf(net, toHex(p2wshSpk(script))), p2wshAddress(net, script));
    const tr = `5120${'cd'.repeat(32)}`;
    const p2pkh = `76a914${'ab'.repeat(20)}88ac`;
    const p2sh = `a914${'ef'.repeat(20)}87`;
    for (const spk of [tr, p2pkh, p2sh]) assert.equal(toHex(addressToSpk(net, addressOf(net, spk))), spk, `${net} ${spk.slice(0, 6)}`);
  }
  assert.ok(addressOf('mutinynet', toHex(p2wpkhSpk(pub))).startsWith('tb1q'));
  assert.ok(addressOf('regtest', toHex(p2wpkhSpk(pub))).startsWith('bcrt1q'));
  assert.equal(addressOf('mutinynet', '6a0474657374'), null, 'OP_RETURN names no address');
  assert.equal(addressOf('mutinynet', 'zz'), null);
});

test('the clock reads M:SS rounded up, H:MM:SS past an hour, and says when it has unlocked', () => {
  assert.equal(clockText(300_000), '5:00');
  assert.equal(clockText(299_001), '5:00');
  assert.equal(clockText(299_000), '4:59');
  assert.equal(clockText(9_000), '0:09');
  assert.equal(clockText(3_600_000), '1:00:00');
  assert.equal(clockText(3_661_000), '1:01:01');
  assert.equal(unlockText(1_300_000, 1_000_000), 'unlocks in 5:00');
  assert.match(unlockText(1_300_000, 1_300_000), /^unlocked/);
  assert.match(unlockText(1_300_000, 1_400_000), /cancel first/);
});

test('an alert says the amount, the destination prefix, unlocks in M:SS and the link, and nothing else of the vault', () => {
  const config = checkWatchConfig(testnetRaw());
  const r = request(4);
  const alert = buildAlert({ config, vault: vaultView([4]), request: r, chainNowMs: 1_002_500 });
  const [first, second, third] = alert.message.split('\n');
  const prefix = addressOf('mutinynet', OTHER_TO).slice(0, 14);
  assert.equal(first, `2,000 sats to ${prefix}… unlocks in 4:58`);
  assert.equal(second, 'signet test coins. Not you? Tap to cancel.');
  assert.equal(third, `https://undo-btc.pages.dev/p/#v=${VAULT}&r=4`);
  assert.equal(alert.click, third);
  assert.equal(alert.title, ALERT_TITLE);
  assert.equal(alert.priority, 5);
  assert.ok(!JSON.stringify(alert).includes(config.ntfy_topic), 'the topic is in no alert');
  assert.ok(Buffer.byteLength(alert.message) < 4096, 'under ntfy\'s message limit');
  assert.ok(!alert.message.includes(OTHER_TO), 'only a prefix, the phone page has the whole address');
  const withChange = buildAlert({ config, vault: vaultView([5]), request: request(5, { amount: 50_000, change: 149_000, inputs: [{ txid: 'bb'.repeat(32), vout: 1, value: 200_000 }] }), chainNowMs: 1_000_000 });
  assert.match(withChange.message, /^50,000 sats to /);
  const self = buildAlert({ config, vault: vaultView([6]), request: request(6, { to: VAULT_SPK }), chainNowMs: 1_000_000 });
  assert.match(self.message, /^2,000 sats back to this vault unlocks in 5:00/);
  const repeat = buildAlert({ config, vault: vaultView([4]), request: r, chainNowMs: 1_000_000, repeat: true });
  assert.match(repeat.title, /may repeat/);
  const local = buildAlert({ config: checkWatchConfig(localRaw()), vault: vaultView([4]), request: r, chainNowMs: 1_000_000 });
  assert.match(local.message, /local test coins, mock signer/);
  assert.match(local.message, /to bcrt1q/);
});

test('amount is every coin when there is no change, as the phone page counts it', () => {
  assert.equal(amountSats(request(1, { inputs: [{ value: 1500 }, { value: 700 }], change: null })), 2200);
  assert.equal(amountSats(request(1, { amount: 900, change: 50 })), 900);
});

test('only a live Pending request gets an alert', () => {
  const v = vaultView([1], { spend_epoch: 2 });
  assert.equal(liveness(request(1, { epoch: 2 }), v, 1_000_000), null);
  assert.equal(liveness(request(1, { epoch: 2, status: 'Signing' }), v, 1_000_000), 'status Signing');
  assert.equal(liveness(request(1, { epoch: 1 }), v, 1_000_000), 'cancelled by a rotation');
  assert.equal(liveness(request(1, { epoch: 2 }), v, 2_800_001), 'expired');
  assert.equal(liveness(request(1, { epoch: 2 }), v, 2_800_000), null, 'alive at exactly expires_at, as the contract says');
});

test('the chain clock takes the later reading, so "unlocks in" errs short', () => {
  assert.equal(chainNowOf({ blockMs: 1000, heardAt: 1000 }, 1500), 1500);
  assert.equal(chainNowOf({ blockMs: 5000, heardAt: 1000 }, 1500), 5500, 'this machine\'s clock behind the chain\'s');
  assert.equal(chainNowOf({ blockMs: 500, heardAt: 1000 }, 1500), 1500, 'ahead');
});

// ---------------------------------------------------------------- the loop, with stand-ins

function fakeChain() {
  const chain = { vault: vaultView([]), requests: new Map(), now: 1_001_000, reads: 0 };
  chain.reads_ = {
    vault: async () => { chain.reads += 1; return { value: chain.vault ? { ...chain.vault, pending: [...chain.vault.pending] } : null, height: 10 }; },
    request: async (_v, id) => ({ value: chain.requests.get(id) ?? null, height: 10 }),
    clock: async () => ({ blockMs: chain.now, height: 10, heardAt: chain.now }),
  };
  chain.add = (id, over = {}) => {
    chain.requests.set(id, request(id, over));
    chain.vault.pending.push(id);
  };
  chain.drop = (id, { keep = false, status } = {}) => {
    chain.vault.pending = chain.vault.pending.filter((p) => p !== id);
    if (!keep) chain.requests.delete(id);
    else chain.requests.set(id, { ...chain.requests.get(id), status });
  };
  return chain;
}

function pushRecorder({ failures = [] } = {}) {
  const sent = [];
  const push = async (alert) => {
    const f = failures.shift();
    if (f) throw f;
    sent.push(alert);
    return { id: `m${sent.length}`, serverTime: null };
  };
  return { sent, push };
}

const makeWatcher = (chain, statePath, push, extra = {}) => new Watcher({
  config: checkWatchConfig(localRaw()), vault: VAULT, reads: chain.reads_, push, nowFn: () => chain.now,
  state: new StateStore(statePath, { contract: 'undo.test.near', vault: VAULT, network: 'local' }), sleep: async () => {}, ...extra,
});

test('one push per new Pending request, and none for a request already pushed', async () => {
  const chain = fakeChain();
  const p = pushRecorder();
  const w = makeWatcher(chain, join(work, 's1.json'), p.push);
  await w.pollOnce();
  assert.equal(p.sent.length, 0);
  chain.add(0);
  chain.add(1);
  await w.pollOnce();
  await w.pollOnce();
  assert.equal(p.sent.length, 2);
  assert.match(p.sent[0].click, /&r=0$/);
  assert.match(p.sent[1].click, /&r=1$/);
  chain.add(2);
  await w.pollOnce();
  assert.equal(p.sent.length, 3);
  assert.equal(w.state.get(2).outcome, 'pushed');
  assert.equal(w.state.get(2).latency_ms, chain.now - 1_000_000);
});

test('a restart reads the state file and sends nothing twice', async () => {
  const chain = fakeChain();
  const statePath = join(work, 's2.json');
  const first = pushRecorder();
  chain.add(0);
  await makeWatcher(chain, statePath, first.push).pollOnce();
  assert.equal(first.sent.length, 1);
  const second = pushRecorder();
  const again = makeWatcher(chain, statePath, second.push);
  await again.pollOnce();
  await again.pollOnce();
  assert.equal(second.sent.length, 0);
  chain.add(1);
  await again.pollOnce();
  assert.equal(second.sent.length, 1);
  assert.match(second.sent[0].click, /&r=1$/);
  assert.equal(statSync(statePath).mode & 0o777, 0o600);
});

test('a crash between marking and sending: the restart sends once more and says it may repeat', async () => {
  const chain = fakeChain();
  const statePath = join(work, 's3.json');
  chain.add(0);
  const s = new StateStore(statePath, { contract: 'undo.test.near', vault: VAULT, network: 'local' });
  s.set(0, { outcome: 'sending', seen_at: 1 });
  const p = pushRecorder();
  const w = makeWatcher(chain, statePath, p.push);
  await w.pollOnce();
  await w.pollOnce();
  assert.equal(p.sent.length, 1);
  assert.match(p.sent[0].title, /may repeat/);
  assert.equal(w.state.get(0).repeat, true);
});

test('a failed push is tried again, then on the next poll, and lands once', async () => {
  const chain = fakeChain();
  chain.add(0);
  const p = pushRecorder({ failures: [new PushFailed('503', { status: 503 }), new PushFailed('503', { status: 503 })] });
  const w = makeWatcher(chain, join(work, 's4.json'), p.push, { pushAttempts: 2 });
  const first = await w.pollOnce();
  assert.equal(first.events[0].kind, 'push_failed');
  assert.equal(w.state.get(0).outcome, 'sending');
  await w.pollOnce();
  await w.pollOnce();
  assert.equal(p.sent.length, 1);
  assert.match(p.sent[0].title, /^Undo for Bitcoin: a spend is waiting$/, 'a retry in the same run is not a repeat');
  const refused = pushRecorder({ failures: [new PushFailed('403', { status: 403, retry: false })] });
  const chain2 = fakeChain();
  chain2.add(0);
  let tries = 0;
  const counting = async (a) => { tries += 1; return refused.push(a); };
  const w2 = makeWatcher(chain2, join(work, 's4b.json'), counting, { pushAttempts: 4 });
  await w2.pollOnce();
  assert.equal(tries, 1, 'a refusal is not hammered');
  await w2.pollOnce();
  assert.equal(refused.sent.length, 1);
});

test('a request seen first as Signing, from an old epoch or expired gets no alert', async () => {
  const chain = fakeChain();
  chain.vault.spend_epoch = 1;
  chain.add(0, { status: 'Signing', epoch: 1 });
  chain.add(1, { epoch: 0 });
  chain.add(2, { epoch: 1, expires_at: 1_000_500 });
  const p = pushRecorder();
  const w = makeWatcher(chain, join(work, 's5.json'), p.push);
  const { events } = await w.pollOnce();
  assert.equal(p.sent.length, 0);
  assert.deepEqual(events.map((e) => e.why), ['status Signing', 'cancelled by a rotation', 'expired']);
});

test('when a pushed request leaves the queue the log says how: cancelled, or executed', async () => {
  const chain = fakeChain();
  chain.add(0);
  chain.add(1);
  const lines = [];
  const w = makeWatcher(chain, join(work, 's6.json'), pushRecorder().push, { log: (l) => lines.push(l) });
  await w.pollOnce();
  chain.now += 8000;
  chain.drop(0);
  chain.drop(1, { keep: true, status: 'Signing' });
  const { events } = await w.pollOnce();
  assert.deepEqual(events.map((e) => [e.kind, e.id, e.why]), [['gone', 0, 'cancelled or swept'], ['gone', 1, 'status Signing']]);
  assert.ok(lines.some((l) => /GONE r=0 \[mock-signer\] cancelled or swept 8\.0 s after the push/.test(l)), lines.join('\n'));
  await w.pollOnce();
  assert.equal(lines.filter((l) => l.startsWith('GONE')).length, 2, 'said once');
});

test('a dry run pushes nothing and keeps its own state', async () => {
  const chain = fakeChain();
  chain.add(0);
  let pushed = 0;
  const lines = [];
  const w = makeWatcher(chain, join(work, 's7.dry-run.json'), async () => { pushed += 1; }, { dryRun: true, log: (l) => lines.push(l) });
  await w.pollOnce();
  await w.pollOnce();
  assert.equal(pushed, 0);
  assert.equal(lines.filter((l) => l.startsWith('DRY RUN r=0')).length, 1);
  assert.match(lines[0], /unlocks in 4:59/, "299 s left at the fake chain's clock");
  assert.equal(w.state.get(0).outcome, 'dry-run');
});

test('a state file for another vault or contract is refused', () => {
  const path = join(work, 's8.json');
  new StateStore(path, { contract: 'undo.test.near', vault: VAULT, network: 'local' }).save();
  assert.throws(() => new StateStore(path, { contract: 'other.test.near', vault: VAULT, network: 'local' }), /another vault or contract/);
  assert.throws(() => new StateStore(path, { contract: 'undo.test.near', vault: 'ab'.repeat(32), network: 'local' }), /another vault or contract/);
});

// ---------------------------------------------------------------- RPC fallback and the ntfy request

const jsonResponse = (status, obj) => new Response(typeof obj === 'string' ? obj : JSON.stringify(obj), { status, headers: { 'content-type': 'application/json' } });

test('RPC: a rate limit, a dead host and a proxy page each move to the next URL; the one that answered goes first next time', async () => {
  const calls = [];
  const fetchFn = async (url) => {
    calls.push(new URL(url).host);
    if (url.includes('one')) return jsonResponse(429, 'Too Many Requests');
    if (url.includes('two')) throw Object.assign(new Error('refused'), { name: 'TypeError' });
    if (url.includes('three')) return new Response('<html>proxy</html>', { status: 200 });
    return jsonResponse(200, { jsonrpc: '2.0', id: 1, result: { chain_id: 'testnet' } });
  };
  const pool = new RpcPool(['https://one.example', 'https://two.example', 'https://three.example', 'https://four.example'], { fetchFn });
  assert.deepEqual(await pool.call('status', []), { result: { chain_id: 'testnet' } });
  assert.deepEqual(calls, ['one.example', 'two.example', 'three.example', 'four.example']);
  assert.equal(pool.lastHost, 'four.example');
  calls.length = 0;
  await pool.call('status', []);
  assert.deepEqual(calls, ['four.example']);
});

test('RPC: a JSON rate-limit error moves on, a contract\'s own refusal does not, and all down says which hosts', async () => {
  const fetchFn = async (url) => {
    if (url.includes('one')) return jsonResponse(200, { jsonrpc: '2.0', id: 1, error: { code: -429, message: 'rate limit exceeded' } });
    return jsonResponse(200, { jsonrpc: '2.0', id: 1, error: { name: 'HANDLER_ERROR', cause: { name: 'UNKNOWN_ACCOUNT', info: {} } } });
  };
  const seen = [];
  const pool = new RpcPool(['https://one.example', 'https://two.example', 'https://three.example'], { fetchFn: async (u, i) => { seen.push(new URL(u).host); return fetchFn(u, i); } });
  const out = await pool.call('query', {});
  assert.equal(out.error.cause.name, 'UNKNOWN_ACCOUNT');
  assert.deepEqual(seen, ['one.example', 'two.example'], 'the third is not asked: every node would refuse the same');
  const down = new RpcPool(['https://a.example', 'https://b.example'], { fetchFn: async () => jsonResponse(503, 'down') });
  await assert.rejects(down.call('block', {}), (err) => err instanceof RpcDown && err.tried.map((t) => t.host).join() === 'a.example,b.example');
});

test('reads: the vault and request views decode, and a missing vault reads as null', async () => {
  const fetchFn = async (_url, init) => {
    const body = JSON.parse(init.body);
    if (body.method === 'block') return jsonResponse(200, { jsonrpc: '2.0', id: 1, result: { header: { height: 7, timestamp_nanosec: '1700000000123456789' } } });
    const args = JSON.parse(Buffer.from(body.params.args_base64, 'base64').toString());
    const value = body.params.method_name === 'vault' ? (args.vault === VAULT ? vaultView([3]) : null) : request(args.request);
    return jsonResponse(200, { jsonrpc: '2.0', id: 1, result: { result: [...Buffer.from(JSON.stringify(value))], block_height: 7, logs: [] } });
  };
  const reads = contractReads(new RpcPool(['https://x.example'], { fetchFn }), 'undo.test.near', { nowFn: () => 42 });
  assert.deepEqual((await reads.vault(VAULT)).value.pending, [3]);
  assert.equal((await reads.vault('00'.repeat(32))).value, null);
  assert.equal((await reads.request(VAULT, 3)).value.id, 3);
  assert.deepEqual(await reads.clock(), { blockMs: 1_700_000_000_123, height: 7, heardAt: 42 });
});

test('ntfy: one JSON POST to the server root, the topic only in the body, and refusals say whether to retry', async () => {
  const ntfy = await startMockNtfy();
  try {
    const topic = makeTopic();
    const urls = [];
    const fetchFn = (url, init) => { urls.push(url); return fetch(url, init); };
    const push = ntfyPublisher({ server: ntfy.url, topic, fetchFn });
    const out = await push({ title: 'T', message: 'M', click: 'http://localhost:1/p/#v=1', priority: 5, actions: [] });
    assert.match(out.id, /^[A-Za-z0-9_-]+$/);
    assert.deepEqual(urls, [`${ntfy.url}/`]);
    assert.equal(ntfy.messages[0].topic, topic);
    assert.equal(ntfy.messages[0].form, 'json');
    assert.equal(ntfy.messages[0].priority, 5);
    ntfy.failNext(1, 503);
    await assert.rejects(push({ title: 'T', message: 'M' }), (err) => err instanceof PushFailed && err.retry === true && err.status === 503);
    ntfy.failNext(1, 403);
    await assert.rejects(push({ title: 'T', message: 'M' }), (err) => err instanceof PushFailed && err.retry === false);
    const dead = ntfyPublisher({ server: 'http://127.0.0.1:1', topic });
    await assert.rejects(dead({ title: 'T', message: 'M' }), (err) => err instanceof PushFailed && err.retry === true);
  } finally {
    await ntfy.stop();
  }
});

// ---------------------------------------------------------------- the command line, against stand-ins

/** A NEAR JSON-RPC stand-in: status, block, and the vault and request views, from a mutable chain. */
async function fakeRpc(chain, { chainId = 'sandbox-test' } = {}) {
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = JSON.parse(Buffer.concat(chunks).toString());
    const ok = (result) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id: body.id, result }));
    };
    const now = Date.now();
    if (body.method === 'status') return ok({ chain_id: chainId });
    if (body.method === 'block') return ok({ header: { height: 9, timestamp_nanosec: `${now}000000` } });
    const args = JSON.parse(Buffer.from(body.params.args_base64, 'base64').toString());
    const value = body.params.method_name === 'vault' ? { ...chain.vault, pending: [...chain.vault.pending] } : (chain.requests.get(args.request) ?? null);
    return ok({ result: [...Buffer.from(JSON.stringify(value))], block_height: 9, logs: [] });
  });
  await new Promise((r) => { server.listen(0, '127.0.0.1', r); });
  return { url: `http://127.0.0.1:${server.address().port}`, stop: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) };
}

const childEnv = () => {
  const env = { ...process.env };
  delete env.NODE_USE_SYSTEM_CA;
  return env;
};
const node = (args, opts = {}) => spawnSync(process.execPath, [WATCH, ...args], { encoding: 'utf8', timeout: 30_000, env: childEnv(), ...opts });

function initLocal(dir, { rpc, ntfy }) {
  const config = join(dir, 'config.json');
  const out = node(['init', '--network', 'local', '--contract', 'undo.test.near', '--vault', VAULT, '--rpc', rpc, '--page-origin', 'http://localhost:8788', '--ntfy-server', ntfy, '--config', config, '--poll-ms', '200']);
  return { config, out };
}

test('init: mode 600, a fresh 22-character topic printed once, and refusals for a git tree, an existing file and mainnet', () => {
  const dir = mkdtempSync(join(work, 'init-'));
  const { config, out } = initLocal(dir, { rpc: 'http://127.0.0.1:1', ntfy: 'http://127.0.0.1:2' });
  assert.equal(out.status, 0, out.stderr);
  assert.equal(statSync(config).mode & 0o777, 0o600);
  const raw = JSON.parse(readFileSync(config, 'utf8'));
  assert.match(raw.ntfy_topic, /^[A-Za-z0-9]{22}$/);
  assert.equal(out.stdout.split(raw.ntfy_topic).length - 1, 1, 'the topic is printed exactly once');
  assert.match(out.stdout, /Show Previews: Always/);
  const again = initLocal(dir, { rpc: 'http://127.0.0.1:1', ntfy: 'http://127.0.0.1:2' });
  assert.equal(again.out.status, 2);
  assert.match(again.out.stderr, /exists/);
  assert.equal(JSON.parse(readFileSync(config, 'utf8')).ntfy_topic, raw.ntfy_topic, 'the first topic is kept');
  const inRepo = join(REPO, 'watch-config-must-not-exist.json');
  const refused = node(['init', '--contract', 'undo-btc.testnet', '--config', inRepo]);
  assert.equal(refused.status, 2);
  assert.match(refused.stderr, /inside a git work tree/);
  assert.ok(!existsSync(inRepo));
  const mainnet = node(['init', '--network', 'mainnet', '--contract', 'undo-btc.near', '--config', join(dir, 'm.json')]);
  assert.equal(mainnet.status, 2);
  assert.ok(!existsSync(join(dir, 'm.json')));
  const live = node(['init', '--contract', 'undo-btc.testnet', '--config', join(dir, 'live.json')]);
  assert.equal(live.status, 0, live.stderr);
  const liveRaw = JSON.parse(readFileSync(join(dir, 'live.json'), 'utf8'));
  assert.deepEqual(liveRaw.rpc, [...TESTNET_RPC]);
  assert.equal(liveRaw.page_origin, 'https://undo-btc.pages.dev');
  assert.equal(liveRaw.ntfy_server, 'https://ntfy.sh');
  assert.notEqual(liveRaw.ntfy_topic, raw.ntfy_topic);
});

test('run refuses a config other users can read', () => {
  const dir = mkdtempSync(join(work, 'mode-'));
  const { config } = initLocal(dir, { rpc: 'http://127.0.0.1:1', ntfy: 'http://127.0.0.1:2' });
  chmodSync(config, 0o644);
  const out = node(['run', '--config', config, '--once']);
  assert.equal(out.status, 2);
  assert.match(out.stderr, /chmod 600/);
});

test('run stops when the RPC is on another chain than the config says', async () => {
  const chain = fakeChain();
  const rpc = await fakeRpc(chain, { chainId: 'testnet' });
  const ntfy = await startMockNtfy();
  try {
    const dir = mkdtempSync(join(work, 'chain-'));
    const { config } = initLocal(dir, { rpc: rpc.url, ntfy: ntfy.url });
    const out = await runAsync(['run', '--config', config, '--once']);
    assert.equal(out.status, 1);
    assert.match(out.stdout, /STOP \[mock-signer\] the RPC answers for chain testnet/);
    assert.equal(ntfy.messages.length, 0);
  } finally {
    await rpc.stop();
    await ntfy.stop();
  }
});

function runAsync(args, { input = null, timeoutMs = 30_000 } = {}) {
  return new Promise((resolveRun) => {
    const child = spawn(process.execPath, [WATCH, ...args], { stdio: ['pipe', 'pipe', 'pipe'], env: childEnv() });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (d) => { stdout += d; });
    child.stderr.on('data', (d) => { stderr += d; });
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    child.on('close', (status) => {
      clearTimeout(timer);
      resolveRun({ status, stdout, stderr });
    });
    if (input !== null) child.stdin.end(input);
    else child.stdin.end();
  });
}

function startRun(args) {
  const child = spawn(process.execPath, [WATCH, ...args], { stdio: ['ignore', 'pipe', 'pipe'], env: childEnv() });
  const out = { stdout: '', stderr: '' };
  child.stdout.on('data', (d) => { out.stdout += d; });
  child.stderr.on('data', (d) => { out.stderr += d; });
  const closed = new Promise((r) => child.on('close', (status, signal) => r({ status, signal })));
  return { child, out, closed };
}

const until = async (fn, timeoutMs, what) => {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    if (fn()) return;
    await new Promise((r) => { setTimeout(r, 50); });
  }
  throw new Error(`timed out waiting for ${what}`);
};

test('run, the command: one push per request, a clean stop on SIGTERM, nothing twice after a restart, and the topic never printed', async () => {
  const chain = fakeChain();
  chain.vault = vaultView([]);
  chain.add(0, { proposed_at: Date.now(), unlock: Date.now() + 300_000, expires_at: Date.now() + 1_800_000 });
  const rpc = await fakeRpc(chain);
  const ntfy = await startMockNtfy();
  try {
    const dir = mkdtempSync(join(work, 'run-'));
    const { config } = initLocal(dir, { rpc: rpc.url, ntfy: ntfy.url });
    const topic = JSON.parse(readFileSync(config, 'utf8')).ntfy_topic;
    const first = startRun(['run', '--config', config]);
    await ntfy.waitFor((m) => m.click?.endsWith('&r=0'), 10_000);
    await until(() => /PUSH r=0/.test(first.out.stdout), 5000, 'the PUSH line');
    first.child.kill('SIGTERM');
    const end = await first.closed;
    assert.equal(end.status, 0, first.out.stderr);
    assert.match(first.out.stdout, /READY \[mock-signer\]/);
    assert.match(first.out.stdout, /STOPPED/);
    assert.equal(ntfy.messages.length, 1);
    assert.equal(ntfy.messages[0].topic, topic);
    assert.match(ntfy.messages[0].message, /^2,000 sats to bcrt1q.{8}… unlocks in [45]:[0-9]{2}\n/);
    assert.equal(ntfy.messages[0].click, `http://localhost:8788/p/#v=${VAULT}&r=0`);

    const second = startRun(['run', '--config', config]);
    await until(() => /READY/.test(second.out.stdout), 10_000, 'READY');
    await new Promise((r) => { setTimeout(r, 1200); });
    assert.equal(ntfy.messages.length, 1, 'the restart sent nothing for request 0');
    chain.add(1, { proposed_at: Date.now(), unlock: Date.now() + 300_000, expires_at: Date.now() + 1_800_000 });
    await ntfy.waitFor((m) => m.click?.endsWith('&r=1'), 10_000);
    await new Promise((r) => { setTimeout(r, 800); });
    second.child.kill('SIGTERM');
    await second.closed;
    assert.equal(ntfy.messages.length, 2);
    for (const text of [first.out.stdout, first.out.stderr, second.out.stdout, second.out.stderr]) assert.ok(!text.includes(topic), 'no output holds the topic');
    const states = readdirSync(dir).filter((f) => f.startsWith('state-') && f.endsWith('.json'));
    assert.equal(states.length, 1);
    const state = JSON.parse(readFileSync(join(dir, states[0]), 'utf8'));
    assert.deepEqual(Object.keys(state.requests), ['0', '1']);
    assert.ok(!JSON.stringify(state).includes(topic), 'the state file holds no topic');
    const log = readFileSync(join(dir, states[0].replace(/\.json$/, '.log.jsonl')), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    assert.deepEqual(log.filter((e) => e.event === 'pushed').map((e) => e.request), [0, 1]);
    assert.ok(log.every((e) => e.latency_ms === undefined || e.latency_ms >= 0));
  } finally {
    await rpc.stop();
    await ntfy.stop();
  }
});

test('run --dry-run --once prints the alert, sends nothing and leaves the real state alone', async () => {
  const chain = fakeChain();
  chain.vault = vaultView([]);
  chain.add(0, { proposed_at: Date.now(), unlock: Date.now() + 300_000, expires_at: Date.now() + 1_800_000 });
  const rpc = await fakeRpc(chain);
  const ntfy = await startMockNtfy();
  try {
    const dir = mkdtempSync(join(work, 'dry-'));
    const { config } = initLocal(dir, { rpc: rpc.url, ntfy: ntfy.url });
    const out = await runAsync(['run', '--config', config, '--dry-run', '--once']);
    assert.equal(out.status, 0, out.stderr);
    assert.match(out.stdout, /DRY RUN r=0 \[mock-signer\] would push:/);
    assert.match(out.stdout, /unlocks in [45]:[0-9]{2}/);
    assert.match(out.stdout, /tap: http:\/\/localhost:8788\/p\/#v=/);
    assert.equal(ntfy.messages.length, 0);
    const files = readdirSync(dir);
    assert.ok(files.some((f) => f.endsWith('.dry-run.json')));
    assert.ok(!files.some((f) => /^state-[0-9a-f]{12}\.json$/.test(f)), 'no real state file');
    const again = await runAsync(['run', '--config', config, '--dry-run', '--once']);
    assert.ok(!/DRY RUN r=0/.test(again.stdout), 'said once per dry state');
  } finally {
    await rpc.stop();
    await ntfy.stop();
  }
});

test('phone-test: pushes test alerts, times the Enter presses, and passes only with 5/5, the words on the lock screen and no topic', async () => {
  const ntfy = await startMockNtfy();
  try {
    const dir = mkdtempSync(join(work, 'phone-'));
    const { config } = initLocal(dir, { rpc: 'http://127.0.0.1:1', ntfy: ntfy.url });
    const topic = JSON.parse(readFileSync(config, 'utf8')).ntfy_topic;
    const good = await runAsync(['phone-test', '--config', config, '--count', '5'], { input: `${'\n'.repeat(10)}y\nn\n` });
    assert.equal(good.status, 0, good.stdout + good.stderr);
    assert.match(good.stdout, /PHONE TEST PASS \[live-ntfy, timed by hand\] 5\/5 within 10 s/);
    assert.equal(ntfy.messages.length, 5);
    assert.deepEqual(ntfy.messages.map((m) => m.title), [1, 2, 3, 4, 5].map((i) => `Undo for Bitcoin: TEST ${i}/5`));
    assert.ok(ntfy.messages.every((m) => m.click === `http://localhost:8788/p/#v=${VAULT}`));
    const pass = readdirSync(dir).filter((f) => f.startsWith('phone-test-'));
    assert.equal(pass.length, 2, 'the run record and the pass record');
    for (const f of pass) assert.ok(!readFileSync(join(dir, f), 'utf8').includes(topic));
    assert.ok(!good.stdout.includes(topic));

    const missed = await runAsync(['phone-test', '--config', config, '--count', '2'], { input: '\nm\n\n\ny\nn\n' });
    assert.equal(missed.status, 1);
    assert.match(missed.stdout, /PHONE TEST FAIL .* 1\/2 within 10 s: missed /);
    const hidden = await runAsync(['phone-test', '--config', config, '--count', '1'], { input: '\n\nn\nn\n' });
    assert.equal(hidden.status, 1);
    assert.match(hidden.stdout, /lock-screen words no/);
    const shown = await runAsync(['phone-test', '--config', config, '--count', '1'], { input: '\n\ny\ny\n' });
    assert.equal(shown.status, 1);
    assert.match(shown.stdout, /topic shown yes/);
  } finally {
    await ntfy.stop();
  }
});
