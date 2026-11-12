// /try/'s steps in Node with fakes (T7): the coin's ask and its one retry rule, the chain deciding where the relay gave no
// answer (M8 for a vault, D2 for a coin, T7 for the thief's proposal), the thief half's checks and its one POST, and the
// owner half reading only the contract. No chain, no browser; every value here is made up.
import assert from 'node:assert/strict';
import { register } from 'node:module';
import { test } from 'node:test';

register('./page-hooks.mjs', import.meta.url);
const steps = await import('../pages/try/steps.mjs');
const { RelayRefused, fundsPowTarget, solvePow } = await import('../lib/index.mjs');
const { waitActive } = await import('../pages/p/vault-make.mjs');

const VAULT = 'ab'.repeat(32);
const refused = (code, extra = {}) => new RelayRefused({ code, ...extra });

/** A clock that moves only when a step sleeps, so a 60 s wait takes no time. */
function clock() {
  const c = { t: 1_700_000_000_000, slept: [] };
  c.now = () => c.t;
  c.sleep = async (ms) => {
    c.slept.push(ms);
    c.t += ms;
    if (c.slept.length > 10_000) throw new Error('the step never stopped waiting');
  };
  return c;
}

/** The relay's /api/funds, answering in turn as `answers` says: an error to throw, or an answer. */
function fundsRelay(answers) {
  const asked = [];
  return {
    asked,
    relay: {
      fund: async (vault, { pow }) => {
        asked.push({ vault, pow });
        const a = answers[Math.min(asked.length - 1, answers.length - 1)];
        if (a instanceof Error) throw a;
        return a;
      },
    },
  };
}

test('T7: the coin is asked for again only after a short rate_limited, at most three more times', async () => {
  const c = clock();
  const r = fundsRelay([refused('rate_limited', { retryAfterS: 5 })]);
  await assert.rejects(steps.askCoin({ relay: r.relay }, { vaultHex: VAULT, pow: Promise.resolve(7), sleep: c.sleep }), (err) => err.code === 'rate_limited');
  assert.equal(r.asked.length, 4, 'one ask and three retries');
  assert.deepEqual(c.slept, [5000, 5000, 5000]);

  const once = fundsRelay([refused('rate_limited', { retryAfterS: 5 }), { ok: true, txid: 'cc'.repeat(32), value: 2000 }]);
  const paid = await steps.askCoin({ relay: once.relay }, { vaultHex: VAULT, pow: Promise.resolve(7), sleep: clock().sleep });
  assert.equal(paid.txid, 'cc'.repeat(32));
  assert.equal(once.asked.length, 2);
});

test('T7: an hour\'s limit, an empty dispenser and no answer are said, not asked again', async () => {
  for (const err of [refused('rate_limited', { retryAfterS: 3000 }), refused('dispenser_empty'), refused('relay_down'), refused('rate_limited')]) {
    const r = fundsRelay([err]);
    const c = clock();
    await assert.rejects(steps.askCoin({ relay: r.relay }, { vaultHex: VAULT, pow: Promise.resolve(7), sleep: c.sleep }), (e) => e === err);
    assert.equal(r.asked.length, 1, `${err.code} ${err.retryAfterS}: asked once`);
    assert.deepEqual(c.slept, []);
  }
});

test('T7: a coin the relay already sent this vault is the same as paid', async () => {
  const r = fundsRelay([{ ok: true, txid: 'dd'.repeat(32), vout: 0, value: 2000, already: true }]);
  const paid = await steps.askCoin({ relay: r.relay }, { vaultHex: VAULT, pow: Promise.resolve(7) });
  assert.equal(paid.txid, 'dd'.repeat(32));
});

test('T7: the coin\'s proof of work is solved once, before the first ask, and reused by the retries', async () => {
  let solves = 0;
  const pow = (async () => {
    solves += 1;
    return solvePow(fundsPowTarget(VAULT), 4);
  })();
  const r = fundsRelay([refused('rate_limited', { retryAfterS: 5 }), refused('rate_limited', { retryAfterS: 5 }), { ok: true, txid: 'ee'.repeat(32) }]);
  await steps.askCoin({ relay: r.relay }, { vaultHex: VAULT, pow, sleep: clock().sleep });
  assert.equal(solves, 1);
  const nonce = await pow;
  assert.deepEqual(r.asked.map((a) => a.pow), [nonce, nonce, nonce]);
});

test('R10: the coin waits for the page to be on screen, before every ask', async () => {
  const order = [];
  const r = fundsRelay([refused('rate_limited', { retryAfterS: 5 }), { ok: true, txid: 'ff'.repeat(32) }]);
  const relay = { fund: async (...a) => { order.push('ask'); return r.relay.fund(...a); } };
  await steps.askCoin({ relay }, { vaultHex: VAULT, pow: Promise.resolve(1), sleep: clock().sleep, whenVisible: async () => { order.push('visible?'); } });
  assert.deepEqual(order, ['visible?', 'ask', 'visible?', 'ask']);
});

test('T7 M8: a creation with no answer, and the contract reads the vault active: the chain decides, it goes on', async () => {
  const c = clock();
  let reads = 0;
  const ctx = { views: { vault: async () => { reads += 1; return reads >= 5 ? { id: VAULT, active: true } : null; } }, relay: { call: async () => ({ ok: true }) } };
  const got = await steps.vaultAfterNoAnswer(ctx, { vaultHex: VAULT }, { waitActive, now: c.now, sleep: c.sleep });
  assert.deepEqual(got.vault, { id: VAULT, active: true });
  const none = await steps.vaultAfterNoAnswer({ views: { vault: async () => null }, relay: ctx.relay }, { vaultHex: VAULT }, { waitActive, now: c.now, sleep: c.sleep });
  assert.equal(none.vault, null, 'not active in the awake time: the page says "yet"');
});

test('T7 D2: a coin with no answer: Esplora decides, every 2 s for 60 s', async () => {
  const c = clock();
  let reads = 0;
  const listed = { esplora: { utxos: async () => { reads += 1; return reads >= 4 ? [{ txid: 'aa'.repeat(32), vout: 1, value: 2000, status: { confirmed: false } }] : []; } } };
  const got = await steps.waitForCoin(listed, { address: 'tb1qx', everyMs: 2000, forMs: 60_000, sleep: c.sleep, now: c.now });
  assert.deepEqual(got.coins, [{ txid: 'aa'.repeat(32), vout: 1, value: 2000 }], 'an unconfirmed coin counts, as the thief tab takes it');
  assert.deepEqual(c.slept, [2000, 2000, 2000]);

  const c2 = clock();
  const downs = [];
  const none = await steps.waitForCoin({ esplora: { utxos: async () => { throw new Error('no answer'); } } }, { address: 'tb1qx', everyMs: 2000, forMs: 60_000, sleep: c2.sleep, now: c2.now, onDown: (e) => downs.push(e) });
  assert.deepEqual(none.coins, []);
  assert.equal(c2.slept.reduce((a, b) => a + b, 0), 60_000, 'it stops at 60 s');
  assert.ok(downs.length >= 30, 'each failed read is said');
});

test('T7 T7: a proposal with no answer: the contract decides; a request that appears is found, none in 30 s is said', async () => {
  const c = clock();
  let reads = 0;
  const ctx = { views: { vault: async () => { reads += 1; return { pending: reads >= 6 ? [3, 4] : [3] }; } }, reader: { txOutcome: async () => assert.fail('no hash, no outcome read') } };
  assert.equal(await steps.findRequest(ctx, { vaultHex: VAULT, seenBefore: new Set([3]), hash: null, sleep: c.sleep, now: c.now }), 4);

  const c2 = clock();
  const never = { views: { vault: async () => ({ pending: [] }) }, reader: { txOutcome: async () => ({ settled: true, failure: null }) } };
  await assert.rejects(steps.findRequest(never, { vaultHex: VAULT, seenBefore: new Set(), hash: 'H', sleep: c2.sleep, now: c2.now }), (e) => e.code === 'no_request');
  assert.ok(c2.t - 1_700_000_000_000 >= 30_000);

  const failed = { views: { vault: async () => ({ pending: [] }) }, reader: { txOutcome: async () => ({ settled: true, failure: '{"ActionError":{"kind":{"FunctionCallError":{"ExecutionError":"Smart contract panicked: BadNonce"}}}}' }) } };
  const c3 = clock();
  await assert.rejects(steps.findRequest(failed, { vaultHex: VAULT, seenBefore: new Set(), hash: 'H', sleep: c3.sleep, now: c3.now }), (e) => e.code === 'contract_refused' && /BadNonce/.test(e.verbatim));
  assert.equal(c3.t - 1_700_000_000_000, 15_000, 'read at 15 s');
});

test('T8 R3: "no request appeared" only from a read that got the vault; while the reads fail or give no vault, it reads on', async () => {
  // Every read fails (or answers with no vault) for 90 s, then one gets the vault and its new request.
  for (const failing of [async () => { throw new Error('503'); }, async () => null]) {
    const c = clock();
    const ctx = {
      views: { vault: async () => (c.t - 1_700_000_000_000 < 90_000 ? failing() : { pending: [5] }) },
      reader: { txOutcome: async () => { throw new Error('503'); } },
    };
    assert.equal(await steps.findRequest(ctx, { vaultHex: VAULT, seenBefore: new Set(), hash: 'H', sleep: c.sleep, now: c.now }), 5);
    assert.ok(c.t - 1_700_000_000_000 >= 90_000, 'it read on past the 30 s');
  }
  // The reads fail past the 30 s, then one answers with the vault and no new request: now that is said.
  const c = clock();
  const ctx = { views: { vault: async () => { if (c.t - 1_700_000_000_000 < 40_000) throw new Error('503'); return { pending: [] }; } }, reader: { txOutcome: async () => null } };
  await assert.rejects(steps.findRequest(ctx, { vaultHex: VAULT, seenBefore: new Set(), hash: 'H', sleep: c.sleep, now: c.now }), (e) => e.code === 'no_request');
  assert.equal(c.t - 1_700_000_000_000, 40_000, 'at the first read that answered');
  // stop() still ends it while the reads fail.
  const c2 = clock();
  let stopped = false;
  const down = { views: { vault: async () => { if (c2.t - 1_700_000_000_000 >= 60_000) stopped = true; throw new Error('503'); } }, reader: { txOutcome: async () => null } };
  assert.equal(await steps.findRequest(down, { vaultHex: VAULT, seenBefore: new Set(), hash: 'H', sleep: c2.sleep, now: c2.now, stop: () => stopped }), null);
});

test('the thief half: a script that does not pay this vault stops it, and a failed read is told apart', async () => {
  const { p2wshSpk } = await import('../lib/index.mjs');
  const { toHex } = await import('../../tools/lib/bytes.mjs');
  const script = Uint8Array.of(0x51);
  const vault = { script_pubkey: toHex(p2wshSpk(script)) };
  const ok = await steps.theftPrep({ views: { script: async () => '51' }, esplora: { feeEstimates: async () => ({ 6: 3.2 }) } }, { vaultHex: VAULT, vault, network: 'signet' });
  assert.equal(ok.feeRate, 4);
  assert.equal(ok.to.length, 22);
  assert.match(ok.toAddress, /^tb1q/);
  const floor = await steps.theftPrep({ views: { script: async () => '51' }, esplora: { feeEstimates: async () => null } }, { vaultHex: VAULT, vault, network: 'signet' });
  assert.equal(floor.feeRate, 2);
  await assert.rejects(steps.theftPrep({ views: { script: async () => '52' }, esplora: { feeEstimates: async () => ({}) } }, { vaultHex: VAULT, vault, network: 'signet' }), (e) => e.code === 'script_mismatch');
  await assert.rejects(steps.theftPrep({ views: { script: async () => { throw new Error('rpc'); } }, esplora: {} }, { vaultHex: VAULT, vault, network: 'signet' }), (e) => e.code === 'near_down');
  await assert.rejects(steps.theftPrep({ views: { script: async () => '51' }, esplora: { feeEstimates: async () => { throw new Error('x'); } } }, { vaultHex: VAULT, vault, network: 'signet' }), (e) => e.code === 'btc_down');
});

test('R10: the key-alone send is not posted while the page is not on screen', async () => {
  let posted = 0;
  const saved = globalThis.fetch;
  globalThis.fetch = async () => { posted += 1; return new Response('x', { status: 400 }); };
  try {
    const ctx = { config: { esplora: 'https://esplora.example.test/api' }, esplora: { utxos: async () => [{ txid: 'aa'.repeat(32), vout: 0, value: 5000 }] } };
    const got = await steps.sendKeyAlone(ctx, { address: 'tb1qx', seed: new Uint8Array(32).fill(1), script: Uint8Array.of(0x51), to: Uint8Array.of(0, 20, ...new Uint8Array(20)), feeRate: 2, visible: () => false });
    assert.deepEqual(got, { hidden: true });
    assert.equal(posted, 0);
    // On screen when the coins are read, hidden by the time they are back: the look that counts is the one after the read.
    let read = false;
    const late = await steps.sendKeyAlone({ ...ctx, esplora: { utxos: async () => { read = true; return [{ txid: 'aa'.repeat(32), vout: 0, value: 5000 }]; } } }, { address: 'tb1qx', seed: new Uint8Array(32).fill(1), script: Uint8Array.of(0x51), to: Uint8Array.of(0, 20, ...new Uint8Array(20)), feeRate: 2, visible: () => !read });
    assert.deepEqual(late, { hidden: true });
    assert.equal(posted, 0, 'posted for a page that went off screen during the read');
    const none = await steps.sendKeyAlone({ ...ctx, esplora: { utxos: async () => [] } }, { address: 'tb1qx', seed: new Uint8Array(32).fill(1), script: Uint8Array.of(0x51), to: Uint8Array.of(0, 20, ...new Uint8Array(20)), feeRate: 2 });
    assert.deepEqual(none, { none: true });
  } finally {
    globalThis.fetch = saved;
  }
});

test('R4: the owner half reads only the contract; a null is believed after three; a second request is not its to handle', async () => {
  const NOW = Date.now();
  const vault = (pending, epoch = 2) => ({ pending, spend_epoch: epoch, frozen_until: null });
  const req = (id) => ({ id, status: 'Pending', epoch: 2, inputs: [{ txid: 'aa'.repeat(32), vout: 0, value: 2000 }], to: '0014', amount: 1700, fee: 300, unlock: NOW + 300_000, proposed_at: NOW, expires_at: NOW + 3_600_000 });
  let v = vault([1]);
  const rows = new Map([[1, req(1)]]);
  const ctx = { views: { vault: async () => v, request: async (_, id) => rows.get(id) ?? null }, skew: { sample: () => null } };
  const items = new Map();
  await steps.readOwner(ctx, { vaultHex: VAULT, items });
  let focus = steps.ownerFocus(items);
  assert.equal(focus.kind, 'request');
  assert.equal(focus.item.id, 1);
  assert.equal(focus.item.state.kind, 'waiting');
  // Gone from one node: still waiting until three reads in a row say so, then cancelled (the epoch did not move: deleted).
  v = vault([]);
  rows.delete(1);
  for (let i = 0; i < 2; i += 1) {
    await steps.readOwner(ctx, { vaultHex: VAULT, items });
    assert.equal(steps.ownerFocus(items).item.state.kind, 'waiting', `null read ${i + 1}`);
  }
  await steps.readOwner(ctx, { vaultHex: VAULT, items });
  focus = steps.ownerFocus(items);
  assert.equal(focus.kind, 'other');
  assert.equal(focus.why, 'cancelled');

  const two = new Map();
  v = vault([1, 2]);
  rows.set(1, req(1));
  rows.set(2, req(2));
  await steps.readOwner(ctx, { vaultHex: VAULT, items: two });
  assert.deepEqual(steps.ownerFocus(two), { kind: 'other', why: 'second' });
});

test('"The coin never moved." only on both answers: a node knows the coin, and its output is unspent', async () => {
  const inputs = [{ txid: 'aa'.repeat(32), vout: 0, value: 2000 }];
  assert.equal(await steps.coinStill({ esplora: { tx: async () => ({ txid: 'aa' }), outspend: async () => ({ spent: false }) } }, inputs), true);
  assert.equal(await steps.coinStill({ esplora: { tx: async () => null, outspend: async () => ({ spent: false }) } }, inputs), false);
  assert.equal(await steps.coinStill({ esplora: { tx: async () => ({}), outspend: async () => ({ spent: true }) } }, inputs), false);
  assert.equal(await steps.coinStill({ esplora: { tx: async () => ({}), outspend: async () => null } }, inputs), false);
});

test('"The coin never moved." needs the node to say spent: false, not an answer that leaves it out', async () => {
  const inputs = [{ txid: 'aa'.repeat(32), vout: 0, value: 2000 }];
  const known = async () => ({ txid: 'aa' });
  assert.equal(await steps.coinStill({ esplora: { tx: known, outspend: async () => ({}) } }, inputs), false, 'no spent field');
  assert.equal(await steps.coinStill({ esplora: { tx: known, outspend: async () => ({ spent: null }) } }, inputs), false, 'spent: null');
  assert.equal(await steps.coinStill({ esplora: { tx: known, outspend: async () => ({ spent: 'false' }) } }, inputs), false, 'spent as a string');
  // Two coins: both must be read unspent.
  const two = [...inputs, { txid: 'bb'.repeat(32), vout: 1, value: 1000 }];
  assert.equal(await steps.coinStill({ esplora: { tx: known, outspend: async (txid) => (txid.startsWith('bb') ? {} : { spent: false }) } }, two), false);
  assert.equal(await steps.coinStill({ esplora: { tx: known, outspend: async () => ({ spent: false }) } }, two), true);
});
