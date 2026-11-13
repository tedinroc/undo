// The wait for a vault the relay has sent, in Node with a made-up clock: time a phone spent asleep is not time the page
// spent reading, and a wait that gives up says the creation was sent.
import assert from 'node:assert/strict';
import { register } from 'node:module';
import { test } from 'node:test';

register('./page-hooks.mjs', import.meta.url);
const { ACTIVE_WAIT_MS, prepareVault, sendVault, STEP_COUNTS_MS, waitActive } = await import('../pages/p/vault-make.mjs');
const { RpcDown, StaleRead, ViewRefused } = await import('../lib/near-read.mjs');
const { SkewTracker } = await import('../lib/clock.mjs');
const { base58Encode } = await import('../../tools/lib/bytes.mjs');

const VAULT = 'cd'.repeat(32);
const HASH = 'H'.repeat(44);

/** A page's world for the wait: a clock that moves only when the page sleeps, and a contract read that costs `readMs`. */
function world({ activeAtRead = Infinity, readMs = 100, sleeps = [], failing = () => false, noVault = () => false } = {}) {
  const w = { t: 1_700_000_000_000, reads: 0, slept: 0, calls: [] };
  w.ctx = {
    views: {
      vault: async () => {
        w.reads += 1;
        w.t += readMs;
        if (failing(w.reads)) throw new Error('no node answered');
        if (noVault(w.reads)) return null;
        return { id: VAULT, active: w.reads >= activeAtRead };
      },
    },
    relay: { call: async (method, args, extra) => { w.calls.push({ method, args, extra, at: w.t, reads: w.reads }); return { ok: true, hash: HASH }; } },
  };
  w.opts = {
    now: () => w.t,
    // The nth pause takes what the scenario says, in place of the 600 ms it asked for: a phone put to sleep.
    sleep: async (ms) => {
      w.t += sleeps[w.slept] ?? ms;
      w.slept += 1;
      // A wait that never ends would hang this file: it ends here, as a failure of the test that asked.
      if (w.slept > 5000) throw new Error('the wait went on past 5000 pauses');
    },
  };
  return w;
}

test('a vault that reads active ends the wait, with the hash the relay gave', async () => {
  const w = world({ activeAtRead: 4 });
  const made = await waitActive(w.ctx, { vaultHex: VAULT }, HASH, w.opts);
  assert.deepEqual(made, { vault: { id: VAULT, active: true }, hash: HASH });
  assert.equal(w.reads, 4);
  assert.deepEqual(w.calls, [], 'no activate for a vault that came at once');
});

test('time asleep does not count: a phone that sleeps for ten minutes after Confirm still gets its vault', async () => {
  // The third pause is ten minutes long, far past the whole wait. The vault reads active a few reads later.
  const w = world({ activeAtRead: 9, sleeps: [600, 600, 600_000] });
  const made = await waitActive(w.ctx, { vaultHex: VAULT }, HASH, w.opts);
  assert.equal(made.vault.active, true);
  assert.equal(w.reads, 9);
  // Two sleeps, each longer than the whole wait: each still counts for one step only.
  const twice = world({ activeAtRead: 12, sleeps: [600, 3_600_000, 600, 600, 3_600_000] });
  assert.equal((await waitActive(twice.ctx, { vaultHex: VAULT }, HASH, twice.opts)).vault.active, true);
  assert.ok(2 * STEP_COUNTS_MS < ACTIVE_WAIT_MS, 'a step counts for a small part of the wait');
});

test('it gives up after 45 s of time awake, and the error says the creation was sent', async () => {
  const w = world();
  const err = await waitActive(w.ctx, { vaultHex: VAULT }, HASH, w.opts).then(() => null, (e) => e);
  assert.ok(err instanceof Error);
  assert.equal(err.message, 'the contract has not read this vault active yet');
  assert.equal(err.sentHash, HASH, 'the page still has the hash to show');
  // 100 ms for the first read, then 700 ms a step (a pause and a read): the 66th read is the first past 45 s.
  assert.equal(ACTIVE_WAIT_MS, 45_000);
  assert.equal(w.reads, 66);
  // Halfway through, one activate for a vault that exists and is not active yet, and only one.
  assert.deepEqual(w.calls.map((c) => c.method), ['activate']);
  assert.deepEqual(w.calls[0].args, { vault: VAULT });
  assert.equal(w.calls[0].reads, 34, 'after the first read past half the wait');
});

test('reads that fail, and a node that has not heard of the vault, are waited out and not thrown; no activate goes to a vault no node knows', async () => {
  const failing = world({ activeAtRead: 6, failing: (n) => n <= 3 });
  assert.equal((await waitActive(failing.ctx, { vaultHex: VAULT }, HASH, failing.opts)).vault.active, true);
  const unknown = world({ noVault: () => true });
  const err = await waitActive(unknown.ctx, { vaultHex: VAULT }, HASH, unknown.opts).then(() => null, (e) => e);
  assert.equal(err.sentHash, HASH);
  assert.deepEqual(unknown.calls, []);
  // A read that takes long, as one does when a node is down, cannot stretch the wait for ever: each counts as a step.
  const slow = world({ readMs: 20_000 });
  await assert.rejects(waitActive(slow.ctx, { vaultHex: VAULT }, HASH, slow.opts), /not read this vault active/);
  assert.equal(slow.reads, Math.floor(ACTIVE_WAIT_MS / STEP_COUNTS_MS) + 1);
});

test('sendVault says each step as it comes: working, the work done, then the hash the relay sent', async () => {
  const w = world({ activeAtRead: 1 });
  const steps = [];
  const made = await sendVault(w.ctx, { vaultHex: VAULT }, { k_s: '11'.repeat(32) }, { powBits: 4, onLine: (step, hash) => steps.push(hash ? `${step} ${hash}` : step) });
  assert.deepEqual(steps, ['working', 'work', `sent ${HASH}`]);
  assert.equal(made.hash, HASH);
  assert.equal(w.calls[0].method, 'create_vault');
  assert.ok(Number.isSafeInteger(w.calls[0].extra.pow), 'the proof of work goes with the creation');
});

// ---------------------------------------------------------------- the read between the two sheets

const SIGNER_KEY = `secp256k1:${base58Encode(new Uint8Array(64).fill(5))}`;
const PASSKEY = { pubkey: Uint8Array.of(2, ...new Uint8Array(32).fill(7)), credentialId: new Uint8Array(20).fill(7) };

/**
 * The first tap's world: a reader whose K_m and clock reads each answer by plan (n is the nth call): a value, a thrown
 * error, or 'hold' (a promise kept until the test lets it go). `patience` is readPatiently's made-up clock.
 */
function makeWorld({ km = () => SIGNER_KEY, clock = () => ({ blockMs: 1_700_000_000_000, height: 7, localMs: 1, rttMs: 1 }), sampled = true } = {}) {
  const w = { t: 0, kmReads: [], clockReads: [], relayCalls: 0, held: {} };
  const answer = (plan, n, kind) => {
    const a = plan(n);
    if (a === 'hold') return new Promise((resolve) => { w.held[kind] = resolve; });
    if (a instanceof Error) return Promise.reject(a);
    return Promise.resolve(a);
  };
  const skew = new SkewTracker();
  if (sampled) skew.add({ blockMs: 1_699_999_000_000, localMs: 0 });
  w.ctx = {
    config: { contract: 'c.testnet' },
    instance: { signer: 'v1.signer-prod.testnet', domain_id: 0 },
    skew,
    reader: {
      view: (account, method, args) => {
        w.kmReads.push({ at: w.t, account, method, args });
        return answer(km, w.kmReads.length, 'km');
      },
      blockTime: () => {
        w.clockReads.push({ at: w.t });
        return answer(clock, w.clockReads.length, 'clock');
      },
    },
    relay: { call: async () => { w.relayCalls += 1; return { hash: HASH }; } },
  };
  w.patience = { now: () => w.t, sleep: async (ms) => { w.t += ms; } };
  return w;
}

test('prepareVault asks for K_m and the chain\'s clock at once, not one after the other', async () => {
  const w = makeWorld({ km: () => 'hold', clock: () => 'hold' });
  const p = prepareVault(w.ctx, PASSKEY, { patience: w.patience });
  await new Promise((r) => { setImmediate(r); });
  assert.equal(w.kmReads.length, 1);
  assert.equal(w.clockReads.length, 1, 'the clock read went out before K_m answered');
  assert.equal(w.kmReads[0].method, 'derived_public_key');
  w.held.km(SIGNER_KEY);
  w.held.clock({ blockMs: 1_700_000_000_000, height: 7, localMs: 5, rttMs: 1 });
  const prepared = await p;
  assert.equal(prepared.km.length, 33);
  assert.equal(prepared.vaultHex.length, 64);
  assert.equal(w.ctx.skew.samples.length, 2, 'the new clock reading goes to the tracker');
});

test('prepareVault: a pass with no answer is read again, with the same keys, and nothing goes to the relay', async () => {
  for (const down of [new RpcDown('query', []), new StaleRead('every node behind block 9')]) {
    const w = makeWorld({ km: (n) => (n <= 2 ? down : SIGNER_KEY) });
    const keys = (await import('../lib/intents.mjs')).newVaultKeys();
    const prepared = await prepareVault(w.ctx, PASSKEY, { keys, patience: w.patience });
    assert.equal(prepared.keys, keys);
    assert.equal(w.kmReads.length, 3);
    assert.deepEqual(w.kmReads.map((r) => r.at), [0, 1000, 4000]);
    assert.equal(new Set(w.kmReads.map((r) => JSON.stringify(r.args))).size, 1, 'the same vault each time');
    assert.equal(w.relayCalls, 0);
  }
});

test('prepareVault: no node answering ends in RpcDown after the last pass, with nothing sent to the relay', async () => {
  const w = makeWorld({ km: () => new RpcDown('query', [{ url: 'https://a', error: 'TimeoutError' }]) });
  const err = await prepareVault(w.ctx, PASSKEY, { patience: w.patience }).then(() => null, (e) => e);
  assert.ok(err instanceof RpcDown);
  assert.deepEqual(w.kmReads.map((r) => r.at), [0, 1000, 4000, 10_000]);
  assert.equal(w.relayCalls, 0);
});

test('prepareVault: the contract\'s refusal of the K_m read is thrown at once, not read again', async () => {
  const w = makeWorld({ km: () => new ViewRefused('derived_public_key', 'Smart contract panicked: unknown domain') });
  await assert.rejects(prepareVault(w.ctx, PASSKEY, { patience: w.patience }), ViewRefused);
  assert.equal(w.kmReads.length, 1);
});

test('prepareVault: a clock read that fails or is late does not hold up K_m when the page already holds a reading; with none it does', async () => {
  const failing = makeWorld({ clock: () => new RpcDown('block', []) });
  assert.equal((await prepareVault(failing.ctx, PASSKEY, { patience: failing.patience })).km.length, 33);
  assert.equal(failing.ctx.skew.samples.length, 1, 'the boot reading stands alone');
  const late = makeWorld({ clock: () => 'hold' });
  const started = Date.now();
  assert.equal((await prepareVault(late.ctx, PASSKEY, { patience: late.patience })).km.length, 33);
  assert.ok(Date.now() - started < 4000, 'K_m in, the late clock read is waited for 2 s at most');
  const none = makeWorld({ clock: () => new RpcDown('block', []), sampled: false });
  await assert.rejects(prepareVault(none.ctx, PASSKEY, { patience: none.patience }), RpcDown);
});

test('prepareVault says K_m is in as soon as it is, before it waits on the clock read sent with it, and never when K_m fails', async () => {
  const tick = () => new Promise((r) => { setImmediate(r); });
  const w = makeWorld({ km: () => 'hold', clock: () => 'hold' });
  let said = 0;
  let done = false;
  const p = prepareVault(w.ctx, PASSKEY, { patience: w.patience, onKm: () => { said += 1; } }).then((v) => { done = true; return v; });
  await tick();
  assert.equal(said, 0, 'not before K_m');
  w.held.km(SIGNER_KEY);
  await tick();
  assert.equal(said, 1, 'K_m in, the clock read still out');
  assert.equal(done, false, 'prepareVault itself still waits on the clock read');
  w.held.clock({ blockMs: 1_700_000_000_000, height: 7, localMs: 5, rttMs: 1 });
  assert.equal((await p).km.length, 33);
  assert.equal(said, 1);
  const down = makeWorld({ km: () => new RpcDown('query', []) });
  let saidDown = 0;
  await assert.rejects(prepareVault(down.ctx, PASSKEY, { patience: down.patience, onKm: () => { saidDown += 1; } }), RpcDown);
  assert.equal(saidDown, 0);
});
