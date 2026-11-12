// The wait for a vault the relay has sent, in Node with a made-up clock: time a phone spent asleep is not time the page
// spent reading, and a wait that gives up says the creation was sent.
import assert from 'node:assert/strict';
import { register } from 'node:module';
import { test } from 'node:test';

register('./page-hooks.mjs', import.meta.url);
const { ACTIVE_WAIT_MS, sendVault, STEP_COUNTS_MS, waitActive } = await import('../pages/p/vault-make.mjs');

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
