// /try/ end to end in Node, with a made-up browser, relay, contract and Esplora (try-flow-page.mjs). No Chrome, no chain.
//   T2  the whole run takes the three taps and nothing else: every passkey call inside its tap, the coin, the key-alone
//       send and the proposal with no tap at all, no window.open; and the retry rows, each call still inside its tap.
//   T3  nothing is asked or sent while the page is hidden (R10): the coin, the count, the send.
//   T4  the owner half goes on only from the contract (R4).
//   T9  the run time on CANCELLED is wall time (v2).
//   T10 the spend key and the cold key never leave memory.
//   R3  what the contract shows is said only after a read of it that answered (M8, M9, T7, T8, C9 with the node away).
// Nothing here says anything about a real phone, Safari, or Apple's sheet.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const PAGE = join(HERE, 'try-flow-page.mjs');
const CANCEL_HERE = /export const CANCEL_HERE = true;/.test(readFileSync(join(HERE, '../pages/try/try.mjs'), 'utf8'));
const HANG_MS = 15_000;

function run(opts) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [PAGE, JSON.stringify(opts)], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), 150_000);
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) return reject(new Error(`the page run ended with ${code}: ${err.slice(-800)}`));
      try {
        const page = JSON.parse(out.trim().split('\n').pop());
        page.snap = (label) => page.snaps.find((s) => s.label === label) ?? assert.fail(`no snap ${label}: missed ${JSON.stringify(page.missed)}`);
        page.posts = (method) => page.sent.filter((p) => p.method === method || (method === 'fund' && p.url === '/api/funds') || (method === 'tx' && p.url.endsWith('/api/tx')));
        return resolve(page);
      } catch (e) {
        return reject(new Error(`no result from the page run: ${e.message}: ${out.slice(-300)} ${err.slice(-300)}`));
      }
    });
  });
}

// A few scenarios at a time: several wait out the page's own 12 s before it says no sheet came, and the read-down rows
// below wait out its 30 s and 45 s.
const queue = [];
let running = 0;
const LIMIT = 4;
function scenario(opts) {
  return new Promise((resolve, reject) => {
    queue.push(() => run(opts).then(resolve, reject).finally(() => {
      running -= 1;
      queue.shift()?.();
    }));
    if (running < LIMIT) {
      running += 1;
      queue.shift()();
    }
  });
}
const later = (opts) => {
  const p = scenario(opts);
  p.catch(() => {});
  return p;
};

const MADE = [{ tap: 'make' }, { until: { id: 'confirm' } }, { tap: 'confirm' }];
const END = CANCEL_HERE
  ? [{ until: { id: 'cancel' }, max: 40_000 }, { snap: 'request' }, { tap: 'cancel' }, { until: { step: 'recap' }, max: 40_000 }, { snap: 'end' }]
  : [{ until: { went: true }, max: 40_000 }, { snap: 'end' }];

// The NEAR node stops answering just before the Confirm tap, and stays down until a step brings it back.
const DOWN_AT_CONFIRM = [{ tap: 'make' }, { until: { id: 'confirm' } }, { set: { rpcDown: true } }, { tap: 'confirm' }];
const NODE_FEE = 'sendrawtransaction RPC error: {"code":-26,"message":"min relay fee not met, 110 < 141"}';
const UNSURE_COIN = 'can\'t tell whether a coin was sent';
const UNSURE_CALL = 'can\'t tell whether the call went out';
const RUNS = {
  happy: later({ steps: [{ snap: 'start' }, { tap: 'make' }, { until: { id: 'confirm' } }, { snap: 'confirm' }, { tap: 'confirm' }, ...END] }),
  m1: later({ create: ['dismiss', 'ok'], steps: [{ tap: 'make' }, { until: { fail: 'M1' } }, { snap: 'closed' }, ...MADE, ...END] }),
  m2: later({ create: ['fast', 'ok'], steps: [{ tap: 'make' }, { until: { fail: 'M2' } }, { snap: 'blocked' }, { tap: 'retry-passkey' }, { until: { id: 'confirm' } }, { tap: 'confirm' }, ...END] }),
  m3: later({ create: ['never', 'ok'], steps: [{ tap: 'make' }, { until: { fail: 'M3' }, max: HANG_MS }, { snap: 'hang' }, ...MADE, ...END] }),
  m5: later({ get: ['dismiss', 'ok'], steps: [...MADE, { until: { fail: 'M5' } }, { snap: 'closed' }, { tap: 'confirm' }, ...END] }),
  m6: later({ get: ['never', 'ok'], steps: [...MADE, { until: { fail: 'M6' }, max: HANG_MS }, { snap: 'hang' }, { tap: 'confirm' }, ...END] }),
  hiddenCoin: later({ steps: [...MADE, { hide: true }, { until: { step: 'fund' }, max: 20_000 }, { wait: 2500 }, { snap: 'hidden' }, { show: true }, { until: { post: '/api/funds' } }, ...END] }),
  hiddenCount: later({ steps: [...MADE, { until: { state: 'count' }, max: 20_000 }, { hide: true }, { wait: 4500 }, { snap: 'hidden' }, { show: true }, { wait: 50 }, { snap: 'shown' }, ...END] }),
  // The red bar's 3 s are 3 s on screen: shown for 50 ms at a time, eight times, it never ends early; then 3 s shown.
  hiddenRefusal: later({ steps: [...MADE, { until: { state: 'refused' }, max: 20_000 }, { hide: true }, { wait: 600 }, ...Array.from({ length: 8 }, () => [{ show: true }, { wait: 50 }, { hide: true }, { wait: 600 }]).flat(), { snap: 'hidden' }, { show: true }, { snap: 'shown' }, { until: { state: 'asking' }, max: 10_000 }, { snap: 'asking' }] }),
  quietHidden: later({ steps: [...MADE, { until: { state: 'count' }, max: 20_000 }, { hideQuiet: true }, { wait: 4500 }, { snap: 'hidden' }, { show: true }, { wait: 50 }, { snap: 'shown' }, ...END] }),
  // W3: hidden the moment the page draws "Asking the NEAR contract" (its read of the vault already out), for 5 s; then
  // shown, and on to the end. With every answer 20 ms late, and 600 ms late from the refusal on.
  askHidden: later({ steps: [...MADE, { until: { state: 'refused' }, max: 30_000 }, { set: { hideOn: { state: 'asking' } } }, { until: { state: 'asking' }, max: 10_000 }, { wait: 5000 }, { snap: 'hidden' }, { show: true }, ...END] }),
  askHiddenSlow: later({ steps: [...MADE, { until: { state: 'refused' }, max: 30_000 }, { set: { netMs: 600, hideOn: { state: 'asking' } } }, { until: { state: 'asking' }, max: 10_000 }, { wait: 5000 }, { snap: 'hidden' }, { show: true }, ...END] }),
  proposeLost: later({ post: { propose_btc: 'timeoutListed' }, steps: [...MADE, ...END] }),
  neverListed: later({ proposeNotListed: true, steps: [...MADE, { until: { fail: 'T8' }, max: 50_000 }, { wait: 1500 }, { snap: 'end' }] }),
  ...(CANCEL_HERE ? {
    warp: later({ clockWarp: 3, steps: [...MADE, ...END] }),
    c1: later({ get: ['ok', 'dismiss', 'ok'], steps: [...MADE, { until: { id: 'cancel' }, max: 40_000 }, { tap: 'cancel' }, { until: { fail: 'C1' }, max: 20_000 }, { wait: 300 }, { snap: 'closed' }, { tap: 'cancel' }, { until: { step: 'recap' }, max: 40_000 }, { snap: 'end' }] }),
    c3: later({ get: ['ok', 'never', 'ok'], steps: [...MADE, { until: { id: 'cancel' }, max: 40_000 }, { tap: 'cancel' }, { until: { fail: 'C3' }, max: HANG_MS }, { snap: 'hang' }, { tap: 'cancel' }, { until: { step: 'recap' }, max: 40_000 }, { snap: 'end' }] }),
    c5: later({ post: { cancel_all_and_rotate: [{ status: 429, body: { ok: false, code: 'rate_limited', message: 'too many', retry_after_s: 2 } }, 'ok'] }, steps: [...MADE, { until: { id: 'cancel' }, max: 40_000 }, { tap: 'cancel' }, { until: { fail: 'C5' }, max: 20_000 }, { snap: 'limited' }, { wait: 2500 }, { until: { id: 'cancel' }, max: 20_000 }, { tap: 'cancel' }, { until: { step: 'recap' }, max: 40_000 }, { snap: 'end' }] }),
    c7: later({ post: { cancel_all_and_rotate: 'failAfterSend' }, steps: [...MADE, { until: { id: 'cancel' }, max: 40_000 }, { tap: 'cancel' }, { until: { step: 'recap' }, max: 60_000 }, { snap: 'end' }] }),
  } : {}),
  // The coin takes 3 s to be listed, then the relay's general side is down when step 3 checks it (T1r), then back.
  t1rCount: later({ hideCoin: true, steps: [...MADE, { until: { step: 'fund' }, max: 20_000 }, { wait: 3000 }, { set: { generalDown: true, hideCoin: false } }, { until: { fail: 'T1r' }, max: 10_000 }, { snap: 't1r' }, { wait: 6500 }, { snap: 't1rLater' }, { set: { generalDown: false } }, { until: { state: 'count' }, max: 30_000 }, { snap: 'count' }] }),
  // T1 by the fee: at 20 sat/vB the fee takes the whole 2,000-sat coin, while Mutinynet lists it; then the fee drops.
  feeTakesAll: later({ fee: 20, steps: [...MADE, { until: { fail: 'T1' }, max: 30_000 }, { snap: 't1' }, { wait: 10_000 }, { snap: 't1Later' }, { set: { fee: 1 } }, { until: { state: 'count' }, max: 15_000 }, { snap: 'count' }] }),
  // The fee is high when step 2 reads it and low by the time the coin is listed: the rate is read again before T1 is said.
  feeDropped: later({ fee: 20, hideCoin: true, steps: [...MADE, { until: { step: 'fund' }, max: 20_000 }, { wait: 3000 }, { set: { fee: 1, hideCoin: false } }, { until: { state: 'count' }, max: 15_000 }, { snap: 'count' }] }),
  // Step 2's read of the fee fails (it fails again 5 s later), and Mutinynet lists the coin 1.5 s into that pause; the
  // fee read keeps failing until T1 is up, then answers.
  listedFeeDown: later({ feeDown: true, hideCoin: true, steps: [...MADE, { until: { step: 'fund' }, max: 20_000 }, { wait: 1500 }, { set: { hideCoin: false } }, { until: { id: 'balance' }, max: 10_000 }, { snap: 'listed' }, { until: { fail: 'T1' }, max: 15_000 }, { snap: 't1' }, { set: { feeDown: false } }, { until: { state: 'count' }, max: 15_000 }, { snap: 'count' }] }),
  // No answer from the relay for the coin (D2), and a short rate_limited on every ask (D5).
  fundNoAnswer: later({ fund: ['fail'], steps: [...MADE, { until: { text: UNSURE_COIN }, max: 20_000 }, { snap: 'unsure' }, { wait: 2500 }, { snap: 'later' }] }),
  fundLimited: later({ fund: [{ status: 429, body: { ok: false, code: 'rate_limited', message: 'another funding holds the coin', retry_after_s: 1 } }], steps: [...MADE, { until: { text: UNSURE_COIN }, max: 30_000 }, { snap: 'unsure' }] }),
  // A proposal with no answer and nothing on the contract (T7); then the NEAR node goes away under the T7 line, and comes back.
  t7Plain: later({ post: { propose_btc: 'timeout' }, steps: [...MADE, { until: { text: UNSURE_CALL }, max: 60_000 }, { snap: 'unsure' }, { wait: 25_000 }, { snap: 'before' }, { until: { fail: 'T7' }, max: 15_000 }, { snap: 't7' }, { set: { rpcDown: true } }, { wait: 4500 }, { snap: 't7Down' }, { set: { rpcDown: false } }, { wait: 2500 }, { snap: 't7Up' }] }),
  // A proposal the contract lists while no read of the page's can reach the NEAR node: T7 must not say there is none.
  t7ReadDown: later({ rpcDownOnPropose: true, post: { propose_btc: 'timeoutListed' }, steps: [...MADE, { until: { fail: 'T7' }, max: 80_000 }, { snap: 't7' }, { set: { rpcDown: false } }, { until: { id: 'cancel' }, max: 20_000 }, { snap: 'request' }] }),
  // T3, which must never happen: a node took the key-alone spend.
  t3Accepted: later({ nodeAnswer: 'accept', steps: [...MADE, { until: { fail: 'T3' }, max: 30_000 }, { snap: 't3' }, { wait: 4000 }, { snap: 'after' }] }),
  // T4: a node said no for a reason of its own (the fee), not the script's.
  t4Fee: later({ nodeAnswer: { status: 400, body: NODE_FEE }, steps: [...MADE, { until: { fail: 'T4' }, max: 30_000 }, { snap: 't4' }, { tap: 'try-again' }, { wait: 2000 }, { snap: 'again' }] }),
  // What the contract shows, from reads that answered (R3). M8: no answer for the creation and no read reaching the NEAR
  // node for the whole wait; then the node is back (no vault there) and Check again reads it.
  m8ReadDown: later({ post: { create_vault: 'fail' }, steps: [...DOWN_AT_CONFIRM, { until: { fail: 'M8' }, max: 75_000 }, { snap: 'm8' }, { set: { rpcDown: false } }, { tap: 'check-again' }, { wait: 1500 }, { snap: 'read' }] }),
  // M8 with the vault on the contract, inactive: the relay sent it and the page heard nothing. Check again reads it
  // inactive, then reads nothing, then reads it active.
  m8Inactive: later({ neverActive: true, post: { create_vault: 'failAfterSend' }, steps: [...MADE, { until: { fail: 'M8' }, max: 75_000 }, { snap: 'm8' }, { tap: 'check-again' }, { wait: 1500 }, { snap: 'checked' }, { set: { rpcDown: true } }, { tap: 'check-again' }, { wait: 1500 }, { snap: 'down' }, { set: { rpcDown: false, neverActive: false } }, { tap: 'check-again' }, { until: { step: 'fund' }, max: 10_000 }, { snap: 'active' }] }),
  // M8 with two reads that cross: a Check again read that the node answers late (the vault inactive), and a later one
  // that fails at once. Only the later read's answer draws the line.
  m8Crossing: later({ neverActive: true, post: { create_vault: 'failAfterSend' }, steps: [...MADE, { until: { fail: 'M8' }, max: 75_000 }, { set: { vaultSlowMs: 3000 } }, { tap: 'check-again' }, { wait: 300 }, { set: { rpcDown: true } }, { tap: 'check-again' }, { wait: 800 }, { snap: 'down' }, { wait: 3000 }, { snap: 'late' }] }),
  // M9: the relay sent the vault and the contract has it active, while no read reaches the node; then a read finds it
  // inactive (a node behind), then active.
  m9ReadDown: later({ steps: [...DOWN_AT_CONFIRM, { until: { fail: 'M9' }, max: 75_000 }, { snap: 'm9' }, { set: { rpcDown: false, neverActive: true } }, { tap: 'check-again' }, { wait: 1500 }, { snap: 'inactive' }, { set: { neverActive: false } }, { tap: 'check-again' }, { until: { step: 'fund' }, max: 10_000 }, { snap: 'active' }] }),
  // T8: the relay sent the proposal and the contract lists it, while no read reaches the node for longer than the 30 s.
  t8ReadDown: later({ rpcDownOnPropose: true, steps: [...MADE, { until: { post: 'propose_btc' }, max: 40_000 }, { wait: 36_000 }, { snap: 'down' }, { set: { rpcDown: false } }, CANCEL_HERE ? { until: { id: 'cancel' }, max: 20_000 } : { until: { went: true }, max: 20_000 }, { snap: 'request' }] }),
  // T7 with a node behind: a read with no vault in it, then the vault again.
  t7NoVault: later({ post: { propose_btc: 'timeout' }, steps: [...MADE, { until: { fail: 'T7' }, max: 80_000 }, { snap: 't7' }, { set: { vaultNull: true } }, { wait: 2500 }, { snap: 'noVault' }, { set: { vaultNull: false } }, { wait: 2500 }, { snap: 'back' }] }),
  // T7 with the request listed and its row not read yet (a node that has the vault's list and no row for the id).
  t7Unread: later({ requestNull: true, post: { propose_btc: 'timeoutListed' }, steps: [...MADE, { until: { fail: 'T7' }, max: 80_000 }, { snap: 't7' }, { set: { requestNull: false } }, CANCEL_HERE ? { until: { id: 'cancel' }, max: 20_000 } : { until: { went: true }, max: 20_000 }, { snap: 'request' }] }),
  ...(CANCEL_HERE ? {
    // C9: the relay sent the cancel and the contract applied it, while no read reaches the node; then one does.
    c9ReadDown: later({ steps: [...MADE, { until: { id: 'cancel' }, max: 40_000 }, { set: { rpcDown: true } }, { tap: 'cancel' }, { until: { fail: 'C9' }, max: 45_000 }, { wait: 300 }, { snap: 'c9' }, { set: { rpcDown: false } }, { until: { step: 'recap' }, max: 20_000 }, { snap: 'end' }] }),
  } : {}),
};
// Runs that make no keys (S0 only): not in RUNS, whose every run T10 reads for its keys.
const X_APP = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Twitter for iPhone/11.20';
const HOUR_MS = 60 * 60_000;
const BOOT = {
  ownerDown: later({ ownerDown: true, boot: { state: 'blocked' }, steps: [{ snap: 'blocked' }, { set: { ownerDown: false } }, { until: { state: 'ready' }, max: 12_000 }, { snap: 'ready' }] }),
  // A browser that reports no passkey manager or screen lock it can use: Safari, and the X app's own browser.
  noPlatform: later({ uvpaa: false, steps: [{ snap: 'ready' }] }),
  noPlatformApp: later({ ua: X_APP, uvpaa: false, steps: [{ snap: 'ready' }] }),
  // Two vaults made in the past hour, with the relay's coin side down at first (held back for 2.5 s: the hint is counted
  // again each second on S0), then back.
  madeHeld: later({ made: 2, fundsDown: true, boot: { state: 'blocked' }, steps: [{ snap: 'blocked' }, { wait: 2500 }, { snap: 'blockedLater' }, { set: { fundsDown: false } }, { until: { state: 'ready' }, max: 12_000 }, { snap: 'ready' }] }),
  // Four vaults made in the past hour: two pass the hour 8.5 s and 9 s after the run starts, one after 20 s; S0 stays up.
  madeAging: later({ madeAgo: [HOUR_MS - 9000, HOUR_MS - 8500, HOUR_MS - 20_000, 120_000], steps: [{ snap: 'four' }, { wait: 12_000 }, { snap: 'two' }, { wait: 10_000 }, { snap: 'one' }] }),
};

const T = { timeout: 400_000 };
const allInTap = (page) => page.calls.every((c) => c.inTap && c.signal);

test('T2: the whole run is three taps, each a passkey sheet in its tap, and nothing else is tapped', T, async () => {
  const page = await RUNS.happy;
  assert.deepEqual(page.missed, []);
  const start = page.snap('start');
  assert.equal(start.state, 'ready');
  assert.deepEqual(start.dockIds, ['make']);
  assert.match(start.dock, /^Make my test vault\s*Passkey prompt 1 of 3$/);
  assert.equal(page.opened, 0, 'no window.open');
  assert.ok(allInTap(page), JSON.stringify(page.calls));
  assert.deepEqual(page.calls.map((c) => c.call), CANCEL_HERE ? ['create', 'get', 'get'] : ['create', 'get']);
  const funds = page.posts('fund');
  assert.equal(funds.length, 1);
  assert.equal(funds[0].inTap, false, 'the coin is asked with no tap');
  const tx = page.posts('tx');
  assert.equal(tx.length, 1, 'one key-alone POST');
  assert.equal(tx[0].inTap, false);
  assert.equal(page.posts('propose_btc').length, 1);
  assert.equal(page.posts('propose_btc')[0].inTap, false);
  assert.equal(page.posts('create_vault').length, 1);
  if (CANCEL_HERE) {
    assert.equal(page.posts('cancel_all_and_rotate').length, 1);
    assert.equal(page.snap('end').step, 'recap');
    assert.deepEqual(page.went, []);
  } else {
    assert.equal(page.posts('cancel_all_and_rotate').length, 0);
    assert.equal(page.went.length, 1);
    const { how, url } = page.went[0];
    assert.equal(how, 'replace', 'the same tab, with no history entry for a page that held keys');
    const m = /^\/p\/#v=([0-9a-f]{64})&r=(\d+)&c=([A-Za-z0-9_-]+)$/.exec(url);
    assert.ok(m, url);
    assert.equal(m[2], '7', 'the request id the contract lists');
    assert.equal(m[1], page.historyLog.at(-1).match(/v=([0-9a-f]{64})/)[1], 'the vault this page made');
    assert.equal(page.snap('end').step, 'cancel');
    assert.equal(page.snap('end').state, 'handoff');
  }
});

test('T2: the step titles, the rail and the Next line follow the run', T, async () => {
  const page = await RUNS.happy;
  const seen = page.drawn.map((d) => d.text);
  const order = ['intro/boot', 'intro/ready', 'make/sheet1', 'make/km', 'make/confirm', 'make/sheet2', 'make/making', 'fund/funding', 'steal/count', 'steal/sending', 'steal/refused', 'steal/asking', CANCEL_HERE ? 'cancel/request' : 'cancel/handoff'];
  let at = 0;
  for (const want of order) {
    const i = seen.findIndex((t, j) => j >= at && t.startsWith(`${want}:`));
    assert.ok(i >= 0, `${want} never drawn after ${seen[at]?.slice(0, 40)}`);
    at = i;
  }
  for (const d of seen) assert.equal((d.match(/\|\| NEXT /g) ?? []).length, 1, d);
  assert.ok(seen.some((t) => /steal\/count: .*The thief sends in 3/.test(t)));
  assert.ok(seen.some((t) => /steal\/count: .*The thief sends in 1/.test(t)));
  assert.ok(seen.some((t) => /steal\/refused: .*REFUSED.*BY BITCOIN.*It needs a second signature\..*finished with a false\/empty top stack element/.test(t)));
  assert.ok(seen.some((t) => /steal\/asking: .*refused the key alone\..*NEAR testnet tx P{44}/.test(t)));
  // The spend key: its first 8 and last 4 hex characters, never more.
  const shown = seen.find((t) => t.startsWith('steal/count:')).match(/your spend key ([0-9a-f]+)…([0-9a-f]+)/);
  assert.ok(shown);
  assert.equal(shown[1].length, 8);
  assert.equal(shown[2].length, 4);
});

test('T2: a sheet closed, refused at once, or never shown: each try is inside its own tap', T, async () => {
  const m1 = await RUNS.m1;
  assert.equal(m1.snap('closed').step, 'intro');
  assert.match(m1.snap('closed').text, /No passkey came back, so nothing was made\./);
  assert.equal(m1.snap('closed').next, 'Next, tap Make my test vault to try again.');
  const m2 = await RUNS.m2;
  assert.match(m2.snap('blocked').text, /If you opened this inside an app, open it in Safari or Chrome\./);
  assert.deepEqual(m2.snap('blocked').dockIds, ['retry-passkey']);
  const m3 = await RUNS.m3;
  assert.match(m3.snap('hang').next, /^No passkey sheet yet\? Tap Make my test vault again\./);
  assert.deepEqual(m3.snap('hang').dockIds, ['make']);
  assert.ok(m3.calls[0].aborted, 'the stuck call is ended by the tap that asks again');
  const m5 = await RUNS.m5;
  assert.match(m5.snap('closed').text, /The passkey did not sign\. Tap Confirm to try again\./);
  assert.equal(m5.snap('closed').next, 'Next, tap Confirm with your passkey.');
  assert.equal(m5.calls.filter((c) => c.call === 'create').length, 1, 'the same passkey, not a second one');
  const m6 = await RUNS.m6;
  assert.match(m6.snap('hang').next, /^No passkey sheet yet\? Tap Confirm again\./);
  for (const page of [m1, m2, m3, m5, m6]) {
    assert.deepEqual(page.missed, []);
    assert.ok(allInTap(page), JSON.stringify(page.calls));
    assert.equal(page.posts('create_vault').length, 1);
    assert.ok(CANCEL_HERE ? page.snap('end').step === 'recap' : page.went.length === 1);
  }
});

test('T3: no coin is asked for while the page is hidden; it is asked when the page is back', T, async () => {
  const page = await RUNS.hiddenCoin;
  assert.deepEqual(page.missed, []);
  assert.equal(page.snap('hidden').step, 'fund');
  assert.ok(page.fundAsks.length >= 1);
  assert.ok(page.fundAsks.every((a) => !a.hidden), JSON.stringify(page.fundAsks));
  assert.ok(page.fundAsks[0].at >= page.snap('hidden').at, 'asked only after the page came back');
});

test('T3: the count stops while hidden and starts again at 3; no key-alone send goes out while hidden', T, async () => {
  for (const name of ['hiddenCount', 'quietHidden']) {
    const page = await RUNS[name];
    assert.deepEqual(page.missed, [], name);
    const hidden = page.snap('hidden');
    assert.equal(page.posts('tx').filter((p) => p.hidden).length, 0, `${name}: a send while hidden`);
    assert.ok(page.posts('tx').every((p) => p.at > hidden.at), `${name}: sent before the page came back`);
    assert.equal(page.snap('shown').count, '3', `${name}: the count starts again at 3`);
    assert.equal(page.posts('tx').length, 1);
  }
});

test('T4 R4: the request is the contract\'s: a proposal with no answer that the contract lists goes on', T, async () => {
  const page = await RUNS.proposeLost;
  assert.deepEqual(page.missed, []);
  if (CANCEL_HERE) assert.equal(page.snap('request').step, 'cancel');
  else assert.match(page.went[0].url, /&r=7&/);
  const end = page.snap(CANCEL_HERE ? 'request' : 'end');
  assert.ok(end.at < 20_000 + 10_000, 'before the relay\'s own 20 s');
});

test('T4 R4: a proposal the relay says it sent, and no request on the contract: no Cancel, no hand-off, the thief\'s words', T, async () => {
  const page = await RUNS.neverListed;
  assert.deepEqual(page.missed, []);
  const end = page.snap('end');
  assert.equal(end.fail, 'T8');
  assert.match(end.text, /Sent to the NEAR contract, and no request appeared\./);
  assert.equal(end.next, 'Next, tap Try again.');
  assert.deepEqual(page.went, []);
  assert.ok(!end.dockIds.includes('cancel'));
});

test('T9: the Done line\'s time is the wall clock\'s, as Date.now measured it (v2)', { ...T, skip: CANCEL_HERE ? false : 'v1: this page has no Done line' }, async () => {
  const page = await RUNS.warp;
  const end = page.snap('end');
  const ms = page.undoRun.endWall - page.undoRun.startWall;
  const s = Math.floor(ms / 1000);
  assert.match(end.next, new RegExp(`This run took ${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')} on this page`));
});

test('T10: the spend key and the cold key are never in the address, history, storage, the console, a request or more of the screen than 8 + 4', T, async () => {
  for (const name of Object.keys(RUNS)) {
    const page = await RUNS[name];
    const secrets = page.secrets;
    assert.ok(secrets.length >= 2, `${name}: the run made its keys`);
    const places = {
      history: page.historyLog.join('\n'),
      went: JSON.stringify(page.went),
      local: JSON.stringify(page.local),
      session: JSON.stringify(page.session),
      console: page.consoleLines.join('\n'),
      bodies: page.sent.map((p) => `${p.url} ${p.body ?? ''}`).join('\n'),
    };
    for (const secret of secrets) {
      for (const [where, text] of Object.entries(places)) assert.ok(!text.includes(secret), `${name}: a key in ${where}`);
      const dom = page.drawn.map((d) => d.text).join('\n');
      for (let i = 0; i + 9 <= secret.length; i += 1) assert.ok(!dom.includes(secret.slice(i, i + 9)), `${name}: more of a key on screen than its first 8 and last 4`);
    }
  }
});

test('T2 v2: the Cancel call is inside its tap after a closed sheet (C1), a sheet that never came (C3) and a relay limit (C5)', { ...T, skip: CANCEL_HERE ? false : 'v1: the phone page owns the cancel' }, async () => {
  for (const name of ['c1', 'c3', 'c5']) {
    const page = await RUNS[name];
    assert.deepEqual(page.missed, [], name);
    assert.ok(allInTap(page), `${name}: ${JSON.stringify(page.calls)}`);
    assert.equal(page.calls.filter((c) => c.call === 'get').length, 3, `${name}: Confirm, Cancel, Cancel again`);
    assert.equal(page.snap('end').step, 'recap', name);
  }
  const c1 = await RUNS.c1;
  assert.match(c1.snap('closed').text, /Not cancelled\. The passkey did not sign\./);
  const c3 = await RUNS.c3;
  assert.match(c3.snap('hang').next, /^No passkey sheet yet\? Tap Cancel again\./);
  assert.ok(c3.calls.find((c) => c.call === 'get' && c.how === 'never').aborted, 'the stuck call ended by the tap that asks again');
  const c5 = await RUNS.c5;
  assert.match(c5.snap('limited').text, /Not cancelled\./);
  assert.equal(c5.posts('cancel_all_and_rotate').length, 2);
});

test('T2 v2 C7: a cancel the relay sent with no answer back: the chain decides, and the recap says only what the contract reads', { ...T, skip: CANCEL_HERE ? false : 'v1: the phone page owns the cancel' }, async () => {
  const page = await RUNS.c7;
  assert.deepEqual(page.missed, []);
  const end = page.snap('end');
  assert.equal(end.step, 'recap');
  assert.match(end.page, /The contract reads this request cancelled\./);
  assert.doesNotMatch(end.page, /Your passkey cancelled it\./);
  assert.match(end.page, /What just happened/);
});

// ---------------------------------------------------------------- what the page says, held: the count, the coin's answers, S0, T7, T1r, T3

const frames = (page, prefix) => page.drawn.filter((d) => d.text.startsWith(prefix));
const firstAt = (page, test) => page.drawn.find((d) => test(d.text))?.at ?? null;

test('T2: the count shows 3, 2 and 1 only; the refusal holds 3 s; step 1 is done only when the contract reads the vault', T, async () => {
  const page = await RUNS.happy;
  assert.deepEqual(page.missed, []);
  const digits = new Set(frames(page, 'steal/count:').map((d) => d.text.match(/\|\| DOCK The thief sends in (\d+)/)?.[1] ?? 'none'));
  assert.deepEqual([...digits].sort(), ['1', '2', '3'], `the count drew ${[...digits]}`);
  const refused = firstAt(page, (t) => t.startsWith('steal/refused:'));
  const asking = page.drawn.find((d) => d.at > refused && d.text.startsWith('steal/asking:'))?.at;
  assert.ok(refused !== null && asking !== undefined);
  assert.ok(asking - refused >= 2900, `Bitcoin's refusal held ${asking - refused} ms, not 3 s`);
  // Confirm is up: the passkey is made and K_m read, but no vault is on the contract yet.
  assert.deepEqual(page.snap('confirm').rail, ['now', '', '', '']);
  assert.deepEqual(page.snap('start').rail, ['', '', '', '']);
});

test('T1r: "Checking before the theft" counts from when the checks stopped the theft, not from step 2', T, async () => {
  const page = await RUNS.t1rCount;
  assert.deepEqual(page.missed, []);
  const t1r = page.snap('t1r');
  assert.equal(t1r.fail, 'T1r');
  assert.match(t1r.dock, /^Checking before the theft · \d+ s$/);
  assert.ok(Number(t1r.count) <= 1, `the first T1r frame says ${t1r.count} s: the coin's wait counted in`);
  // The back-off asks again 5 s later: the count goes on, it does not start again.
  const later2 = page.snap('t1rLater');
  assert.equal(later2.fail, 'T1r');
  assert.ok(Number(later2.count) >= 5 && Number(later2.count) <= 8, `${later2.count} s, 6.5 s after the first frame`);
  // Back: the count of the theft, from 3.
  assert.equal(page.snap('count').count, '3');
  assert.equal(page.posts('tx').length, 0, 'no send before the relay could take the proposal');
});

test('the refusal\'s 3 s are time on screen: glimpses of the page while it is mostly hidden do not count toward them', T, async () => {
  const page = await RUNS.hiddenRefusal;
  assert.deepEqual(page.missed, []);
  const hidden = page.snap('hidden');
  assert.equal(hidden.state, 'refused', 'the thief asked NEAR while the page was hidden, or before 3 s on screen');
  assert.equal(page.posts('propose_btc').length, 0);
  const shown = page.snap('shown');
  const asking = page.snap('asking');
  // Nine glimpses of 50 ms at most: never close to 3 s on screen before the last show.
  assert.ok(asking.at - shown.at >= 2400, `the thief asked ${asking.at - shown.at} ms after the page came back`);
  assert.ok(page.posts('propose_btc').every((p) => p.at >= shown.at && !p.hidden));
});

test('W3 R10: hidden the moment the thief starts asking NEAR, nothing goes to the relay until the page is shown; the proposal is then built from reads made after', T, async () => {
  const rpcOf = (p) => {
    const body = JSON.parse(p.body);
    return body.method === 'query' ? body.params.method_name ?? body.params.request_type : body.method;
  };
  for (const name of ['askHidden', 'askHiddenSlow']) {
    const page = await RUNS[name];
    assert.deepEqual(page.missed, [], name);
    assert.equal(page.hides.length, 1, `${name}: not hidden as asking was drawn`);
    const hidden = page.snap('hidden');
    // Held while hidden: still asking, and nothing on the screen says the request was sent.
    assert.equal(`${hidden.step}/${hidden.state}/${hidden.fail}`, 'steal/asking/null', name);
    assert.match(hidden.text, /Asking the NEAR contract/, name);
    assert.doesNotMatch(hidden.text, /NEAR testnet tx/, `${name}: a tx line for a proposal not sent`);
    // No POST to the relay, the coin's dispenser or Bitcoin while hidden; the proposal once, after the page was shown.
    const sends = page.sent.filter((p) => p.url === '/api/relay' || p.url === '/api/funds' || p.url.endsWith('/api/tx'));
    assert.deepEqual(sends.filter((p) => p.hidden).map((p) => p.method), [], `${name}: sent while hidden`);
    const proposals = page.posts('propose_btc');
    assert.equal(proposals.length, 1, name);
    assert.ok(proposals[0].at >= hidden.at, `${name}: the proposal went out at ${proposals[0].at} ms, the page was shown at ${hidden.at} ms`);
    // Built from reads made once the page was back: the vault's read again, and the chain's clock too (the proposal's
    // expiry is 30 min from a block read after the 5 s off screen, not before them).
    const ownReads = page.sent.filter((p) => p.url.startsWith('https://rpc.example.test') && p.at >= hidden.at && p.at < proposals[0].at).map(rpcOf);
    assert.ok(ownReads.includes('vault') && ownReads.includes('block'), `${name}: read after the show ${JSON.stringify(ownReads)}`);
    const expires = JSON.parse(proposals[0].body).args.expires_at;
    const left = expires - (page.t0 + proposals[0].at);
    assert.ok(left > 30 * 60_000 - 2500, `${name}: the proposal expires ${left} ms after it was sent, from a clock read before the page was hidden`);
    // While hidden no reads in a loop: only the ones under way when the page went (the ask's vault and clock, and the
    // owner watch's last read, whose timer was set before the hide: its vault, and the clock when that is due). A loop
    // makes over a hundred in these 5 s at 20 ms a read.
    const hiddenReads = page.sent.filter((p) => p.hidden && p.url.startsWith('https://rpc.example.test')).map(rpcOf);
    assert.ok(hiddenReads.length <= 6, `${name}: ${hiddenReads.length} reads while hidden ${JSON.stringify(hiddenReads)}`);
    // And the run goes on as on any other: the request, then Cancel and the recap (v2) or the phone page (v1).
    assert.ok(allInTap(page), name);
    if (CANCEL_HERE) assert.equal(page.snap('end').step, 'recap', name);
    else assert.equal(page.went.length, 1, name);
  }
});

test('T1 by a fee read that failed at step 2: when Mutinynet lists the coin the fee is read again at once, and step 2\'s Next line goes as soon as that read answers', T, async () => {
  const page = await RUNS.listedFeeDown;
  assert.deepEqual(page.missed, []);
  const fundAt = firstAt(page, (t) => t.startsWith('fund/'));
  const listedAt = firstAt(page, (t) => /2,000 sats \|\| NEXT/.test(t));
  const stealAt = page.drawn.find((d) => d.at > listedAt && d.text.startsWith('steal/'))?.at;
  assert.ok(fundAt !== null && listedAt !== null && stealAt !== undefined, JSON.stringify({ fundAt, listedAt, stealAt }));
  const feeReads = (from, to) => page.fetches.filter((f) => f.at >= from && f.at < to && f.url.endsWith('/fee-estimates')).map((f) => f.at);
  // Before the listing: step 2's one try (a read and its one retry), then its 5 s pause; no reads in a loop.
  assert.ok(feeReads(fundAt, listedAt).length <= 2, `fee reads before the listing: ${feeReads(fundAt, listedAt)}`);
  // The listing ends the pause: the fee is read again at once, not when the 5 s are up.
  assert.ok(feeReads(listedAt - 50, listedAt + 400).length >= 1, `no fee read right after the listing at ${listedAt}: ${feeReads(listedAt - 50, stealAt)}`);
  // So step 2's "Step 3 starts by itself when Mutinynet lists the coin." stays beside the listed coin only while that
  // read and the check's own read again are under way (each a try and a retry 0.3 s and 0.6 s apart: about 2 s here),
  // not for the rest of a 5 s pause on top (at least 3.4 s more here).
  assert.ok(stealAt - listedAt < 4000, `step 2 stayed ${stealAt - listedAt} ms beside a listed coin`);
  assert.ok(page.drawn.every((d) => d.at < stealAt || !d.text.includes('Step 3 starts by itself')), 'said step 3 waits for a coin Mutinynet lists');
  const t1 = page.snap('t1');
  assert.equal(t1.fail, 'T1');
  assert.match(t1.text, /2,000 sats Can't read Mutinynet right now\./);
  assert.equal(t1.next, 'Nothing to tap. This page tries again every 5 s.');
  assert.ok(feeReads(listedAt, t1.at).length <= 4, `fee reads from the listing to T1: ${feeReads(listedAt, t1.at)}`);
  // The fee read answers: the next try goes on to the count, from 3, with nothing sent before it.
  assert.equal(page.snap('count').count, '3');
  assert.ok(feeReads(t1.at, page.snap('count').at).length <= 3, 'the fee read in a loop while T1 was up');
  assert.equal(page.posts('tx').length, 0);
});

test('M8: two reads that cross, a Check again the node answers late and a later one that fails: the later read draws the line', T, async () => {
  const page = await RUNS.m8Crossing;
  assert.deepEqual(page.missed, []);
  const down = page.snap('down');
  assert.equal(down.fail, 'M8');
  assert.match(down.text, /Can't read the NEAR contract right now\./);
  // The first read's answer (the vault inactive) comes back after the second read's: it is older, and draws nothing.
  const late = page.snap('late');
  assert.equal(late.fail, 'M8');
  assert.match(late.text, /Can't read the NEAR contract right now\./);
  assert.doesNotMatch(late.text, /does not read this vault active/);
});

test('T1 by the fee: a listed coin the fee would take whole waits at T1 and reads the fee again, not the address in a loop', T, async () => {
  const page = await RUNS.feeTakesAll;
  assert.deepEqual(page.missed, []);
  const t1 = page.snap('t1');
  assert.equal(t1.step, 'steal');
  assert.equal(t1.fail, 'T1');
  assert.match(t1.text, /2,000 sats The fee would take all of these sats right now, so the thief waits\./);
  assert.equal(t1.next, 'Nothing to tap. This page tries again every 5 s.');
  assert.match(t1.dock, /^Checking before the theft · \d+ s$/);
  const later2 = page.snap('t1Later');
  assert.equal(later2.fail, 'T1');
  assert.match(later2.text, /The fee would take all of these sats right now/);
  assert.ok(Number(later2.count) >= 9, `the check's count says ${later2.count} s 10 s later`);
  // In those 10 s: no storm of address reads, and the fee read again every 5 s.
  const within = (end) => (f) => f.at > t1.at && f.at <= later2.at && f.url.endsWith(end);
  const utxoReads = page.fetches.filter(within('/utxo')).length;
  const feeReads = page.fetches.filter(within('/fee-estimates')).length;
  assert.ok(utxoReads <= 3, `${utxoReads} address reads in 10 s`);
  assert.ok(feeReads >= 1 && feeReads <= 3, `${feeReads} fee reads in 10 s`);
  assert.ok(page.fetches.filter((f) => f.at > t1.at && f.at <= later2.at).length <= 20, 'a request storm while T1 is up');
  // The sentence is about a rate read for it: a fee read after the address read that listed the coin, before T1.
  const listedAt = Math.max(...page.fetches.filter((f) => f.at < t1.at && f.url.endsWith('/utxo')).map((f) => f.at));
  assert.ok(page.fetches.some((f) => f.at > listedAt && f.at < t1.at && f.url.endsWith('/fee-estimates')), 'T1 said of a fee rate read before the coin was listed');
  // Once the coin is listed, step 2's "Step 3 starts by itself when Mutinynet lists the coin." is never said again.
  const firstT1 = firstAt(page, (t) => t.startsWith('steal/stuck/T1:'));
  assert.ok(page.drawn.every((d) => d.at < firstT1 || !d.text.includes('Step 3 starts by itself')), 'said step 3 waits for a coin Mutinynet lists');
  assert.ok(page.drawn.every((d) => d.at < firstT1 || d.text.startsWith('steal/')), 'went back to step 2');
  // The fee drops: the next try goes on to the count, from 3, with nothing sent before it.
  assert.equal(page.snap('count').count, '3');
  assert.equal(page.posts('tx').length, 0);
});

test('T1 by the fee is said only of a rate read when the coin is listed: a fee that dropped since step 2 goes on to the count', T, async () => {
  const page = await RUNS.feeDropped;
  assert.deepEqual(page.missed, []);
  assert.equal(page.snap('count').count, '3');
  assert.ok(page.drawn.every((d) => !d.text.includes('The fee would take all')), 'said the fee takes the coin at a rate it no longer read');
  assert.ok(page.drawn.every((d) => !d.text.startsWith('steal/stuck')), 'stopped the theft');
});

test('D2: the relay did not answer the coin: "can\'t tell", never "No coins sent.", and Esplora decides', T, async () => {
  const page = await RUNS.fundNoAnswer;
  assert.deepEqual(page.missed, []);
  const unsure = page.snap('unsure');
  assert.match(unsure.text, /The relay did not answer, so this page can't tell whether a coin was sent\./);
  assert.ok(page.drawn.every((d) => !d.text.includes('No coins sent.')), 'said no coin was sent');
  const later2 = page.snap('later');
  assert.equal(later2.step, 'fund');
  assert.equal(later2.state, 'funding', 'still reading the address, not D1');
  assert.equal(page.fundAsks.length, 1, 'no answer is not asked again by itself');
});

test('D5: a short rate_limited is asked again after its wait, three times, and then the page can\'t tell', T, async () => {
  const page = await RUNS.fundLimited;
  assert.deepEqual(page.missed, []);
  assert.equal(page.fundAsks.length, 4, 'the first ask and three more');
  for (let i = 1; i < 4; i += 1) assert.ok(page.fundAsks[i].at - page.fundAsks[i - 1].at >= 900, 'each after the relay\'s 1 s');
  assert.match(page.snap('unsure').text, /Too many tries through the relay, so this page can't tell whether a coin was sent\./);
  assert.ok(page.drawn.every((d) => !d.text.includes('No coins sent.')), 'said no coin was sent while another ask\'s coin may be on its way');
});

test('S0: the relay\'s cancel side down blocks the run, in its words; when it is back, Make comes', T, async () => {
  const page = await BOOT.ownerDown;
  assert.deepEqual(page.missed, []);
  const blocked = page.snap('blocked');
  assert.equal(blocked.fail, 'blocked');
  assert.match(blocked.text, /The relay says it can't send a cancel right now, so step 4 would have no Cancel\./);
  assert.deepEqual(blocked.dockIds, ['watch']);
  assert.equal(blocked.next, 'Next, watch a recorded run, or come back later.');
  assert.deepEqual(page.snap('ready').dockIds, ['make']);
  assert.equal(page.calls.length, 0);
});

// Inside an app's own browser the line about the app says passkeys may not work there and how to leave; the hint about
// this browser's passkey manager would be a second answer to the same thing, under the button, on a screen with no room.
test('S0 in a browser that reports no passkey manager: in Safari the hint of what to check; inside an app, the line about the app only', T, async () => {
  const safari = await BOOT.noPlatform;
  const app = await BOOT.noPlatformApp;
  assert.deepEqual(safari.missed, []);
  assert.deepEqual(app.missed, []);
  const s = safari.snap('ready');
  const a = app.snap('ready');
  assert.match(s.aside, /This browser reports no passkey manager or screen lock it can use\. If no passkey sheet comes up, check that this iPhone has a passcode/);
  assert.doesNotMatch(s.text, /You opened this inside/);
  assert.match(a.text, /You opened this inside the X app, where passkeys may not work\. Open this page in Safari or Chrome itself: use the app's menu, or copy this page's address\./);
  assert.doesNotMatch(a.page, /passkey manager/);
  assert.equal(a.aside, '');
  for (const snap of [s, a]) assert.deepEqual(snap.dockIds, ['make']);
});

// The hint of vaults made in the past hour warns that a new vault may get no coin: while the run is held back there is no
// Make button and no new vault, so it is not drawn; when Make comes back, the hint comes with it.
test('S0 held back by the relay: no hint of vaults made in the past hour; when Make is back, the hint is too', T, async () => {
  const page = await BOOT.madeHeld;
  assert.deepEqual(page.missed, []);
  for (const label of ['blocked', 'blockedLater']) {
    const held = page.snap(label);
    assert.equal(held.fail, 'blocked', label);
    assert.deepEqual(held.dockIds, ['watch'], label);
    assert.doesNotMatch(held.page, /in the past hour/, label);
  }
  const ready = page.snap('ready');
  assert.deepEqual(ready.dockIds, ['make']);
  assert.match(ready.text, /This browser made 2 test vaults in the past hour\. One network address gets 2 test coin tries an hour, so a new one may get none\./);
  assert.equal(page.calls.length, 0);
});

// "This browser made N test vaults in the past hour" holds while S0 stays up: as vaults pass the hour, N is counted again,
// and with fewer than 2 left the hint goes. A tab left on S0 for an hour does not keep saying it.
test('S0 left up: the hint of vaults made in the past hour counts again as they pass the hour, and goes under 2', T, async () => {
  const page = await BOOT.madeAging;
  assert.deepEqual(page.missed, []);
  const four = page.snap('four');
  assert.equal(four.state, 'ready');
  assert.match(four.text, /This browser made 4 test vaults in the past hour\./);
  const two = page.snap('two');
  assert.equal(two.state, 'ready');
  assert.match(two.text, /This browser made 2 test vaults in the past hour\. One network address gets 2 test coin tries an hour, so a new one may get none\./);
  assert.doesNotMatch(two.page, /made 4 test vaults/);
  const one = page.snap('one');
  assert.equal(one.state, 'ready');
  assert.doesNotMatch(one.page, /in the past hour/);
  assert.deepEqual(one.dockIds, ['make']);
  assert.equal(page.calls.length, 0);
});

test('T7: the "no request" line comes only after 30 s of the contract\'s reads, and only while a read can say so', T, async () => {
  const page = await RUNS.t7Plain;
  assert.deepEqual(page.missed, []);
  assert.match(page.snap('unsure').text, /The relay did not answer, so this page can't tell whether the call went out\./);
  const before = page.snap('before');
  assert.equal(before.fail, null);
  assert.equal(before.state, 'asking');
  assert.doesNotMatch(before.page, /lists no request/);
  const t7 = page.snap('t7');
  assert.match(t7.text, /The contract lists no request for this vault yet\./);
  assert.equal(t7.next, 'Next, tap Try again. It asks the contract only.');
  const unsureAt = firstAt(page, (t) => t.includes(UNSURE_CALL));
  const t7At = firstAt(page, (t) => t.startsWith('steal/stuck/T7:'));
  assert.ok(t7At - unsureAt >= 29_500, `T7 came ${t7At - unsureAt} ms after the relay's silence`);
  // The NEAR node goes away under the line: the page no longer says the contract lists none.
  const down = page.snap('t7Down');
  assert.equal(down.fail, 'T7');
  assert.doesNotMatch(down.text, /lists no request/);
  assert.match(down.text, /Can't read the NEAR contract right now\./);
  const up = page.snap('t7Up');
  assert.match(up.text, /The contract lists no request for this vault yet\./);
  assert.doesNotMatch(up.text, /Can't read the NEAR contract right now\./);
});

test('T7 R4: a request the contract lists while no read reaches it is never said to be missing; when a read does, S4', T, async () => {
  const page = await RUNS.t7ReadDown;
  assert.deepEqual(page.missed, []);
  const t7 = page.snap('t7');
  assert.equal(t7.fail, 'T7');
  assert.match(t7.text, /Can't read the NEAR contract right now\./);
  assert.ok(page.drawn.every((d) => !d.text.includes('lists no request')), 'said the contract lists no request while it lists one');
  const request = page.snap('request');
  assert.equal(request.step, 'cancel');
  assert.ok(request.dockIds.includes('cancel'));
});

test('T3: a node took the key-alone spend: its words, no control, and nothing further runs on this page', T, async () => {
  const page = await RUNS.t3Accepted;
  assert.deepEqual(page.missed, []);
  const t3 = page.snap('t3');
  assert.match(t3.text, /A NODE ACCEPTED THIS/);
  assert.equal(t3.next, 'Nothing further runs on this page.');
  assert.deepEqual(t3.dockIds, []);
  // A read already out when T3 came may end; nothing starts after it.
  const late = page.fetches.filter((f) => f.at > t3.at + 1500);
  assert.deepEqual(late.map((f) => f.url), [], 'requests after T3');
  assert.equal(page.snap('after').fail, 'T3');
});

// ---------------------------------------------------------------- T4, and what the contract shows only from a read that answered (R3)

/** The frames up to `at` that say `words`: a sentence said while no read could stand behind it. */
const saidBy = (page, at, words) => page.drawn.filter((d) => d.at <= at && d.text.includes(words)).map((d) => `${d.at} ms: ${d.text.slice(0, 160)}`);
const READ_DOWN = /Can't read the NEAR contract right now\./;

test('T4: a node said no, and not about the script: its words and Try again, never Bitcoin\'s refusal of the key alone', T, async () => {
  const page = await RUNS.t4Fee;
  assert.deepEqual(page.missed, []);
  const t4 = page.snap('t4');
  assert.equal(t4.fail, 'T4');
  assert.match(t4.text, /A node said no, but not about the signature\./);
  assert.match(t4.text, /Its fee is too low for the node to pass it on\./);
  assert.equal(t4.next, 'Next, tap Try again.');
  assert.deepEqual(t4.dockIds, ['try-again']);
  for (const words of ['REFUSED', 'It needs a second signature.', 'refused the key alone']) assert.deepEqual(saidBy(page, Infinity, words), [], words);
  assert.equal(page.posts('propose_btc').length, 0, 'the thief asked the contract after a refusal that was not the script\'s');
  // Try again: the coins read again and one more POST, and the same words.
  assert.equal(page.posts('tx').length, 2);
  assert.equal(page.snap('again').fail, 'T4');
});

test('M8: every read of the wait failed: "Can\'t read the NEAR contract", never that the contract does not read the vault active; a read that answers gives that', T, async () => {
  const page = await RUNS.m8ReadDown;
  assert.deepEqual(page.missed, []);
  const m8 = page.snap('m8');
  assert.equal(m8.fail, 'M8');
  assert.match(m8.text, READ_DOWN);
  assert.deepEqual(saidBy(page, m8.at, 'does not read this vault active'), [], 'said with no read behind it');
  assert.deepEqual(m8.dockIds, ['check-again']);
  assert.equal(m8.next, 'Nothing to tap. This page reads the contract again every 15 s.');
  // The node is back and has no vault for this id: the contract does not read it active, and now a read says so.
  const read = page.snap('read');
  assert.equal(read.fail, 'M8');
  assert.match(read.text, /The relay did not answer, and the contract does not read this vault active yet\./);
  assert.doesNotMatch(read.text, READ_DOWN);
});

test('M8 with the vault read inactive: the row\'s sentence, never "Vault active"; the line follows each read; active goes on', T, async () => {
  const page = await RUNS.m8Inactive;
  assert.deepEqual(page.missed, []);
  const m8 = page.snap('m8');
  assert.equal(m8.fail, 'M8');
  assert.match(m8.text, /The relay did not answer, and the contract does not read this vault active yet\./);
  const checked = page.snap('checked');
  assert.equal(checked.fail, 'M8');
  assert.match(checked.text, /does not read this vault active yet/);
  // Check again with the node gone: the last sentence was a read's, and this read got nothing.
  const down = page.snap('down');
  assert.equal(down.fail, 'M8');
  assert.match(down.text, READ_DOWN);
  assert.doesNotMatch(down.text, /does not read this vault active/);
  assert.deepEqual(saidBy(page, down.at, 'Vault active'), [], 'said "Vault active" of a vault the contract reads inactive');
  assert.ok(page.fundAsks.every((a) => a.at > down.at), 'a coin asked for a vault the contract does not read active');
  assert.equal(page.snap('active').step, 'fund');
});

test('M9: the vault is active and no read reaches the node: the tx and "Can\'t read", never "does not read it active"; then each read\'s answer', T, async () => {
  const page = await RUNS.m9ReadDown;
  assert.deepEqual(page.missed, []);
  const m9 = page.snap('m9');
  assert.equal(m9.fail, 'M9');
  assert.match(m9.text, /NEAR testnet tx C{44}/);
  assert.match(m9.text, READ_DOWN);
  assert.deepEqual(saidBy(page, m9.at, 'does not read it active'), [], 'said of a vault the contract reads active, with no read behind it');
  const inactive = page.snap('inactive');
  assert.equal(inactive.fail, 'M9');
  assert.match(inactive.text, /The vault was sent, but the contract does not read it active yet\./);
  assert.doesNotMatch(inactive.text, READ_DOWN);
  assert.equal(page.snap('active').step, 'fund');
});

test('T8: the contract lists the request and no read reaches the node past the 30 s: never "no request appeared"; when a read does, the request', T, async () => {
  const page = await RUNS.t8ReadDown;
  assert.deepEqual(page.missed, []);
  const down = page.snap('down');
  assert.ok(down.at - page.posts('propose_btc')[0].at >= 35_000, 'not past the 30 s');
  assert.equal(down.step, 'steal');
  assert.equal(down.state, 'asking');
  assert.equal(down.fail, null);
  assert.deepEqual(saidBy(page, Infinity, 'no request appeared'), [], 'said with no read behind it');
  if (CANCEL_HERE) assert.ok(page.snap('request').dockIds.includes('cancel'));
  else assert.match(page.went[0].url, /&r=7&/);
});

test('T7: a read with no vault in it says nothing of requests, so the line goes; a listed id not read yet says nothing either', T, async () => {
  const page = await RUNS.t7NoVault;
  assert.deepEqual(page.missed, []);
  assert.match(page.snap('t7').text, /The contract lists no request for this vault yet\./);
  const noVault = page.snap('noVault');
  assert.equal(noVault.fail, 'T7');
  assert.doesNotMatch(noVault.text, /lists no request/);
  assert.doesNotMatch(noVault.text, READ_DOWN, 'the node answered');
  assert.match(page.snap('back').text, /The contract lists no request for this vault yet\./);
  const unread = await RUNS.t7Unread;
  assert.deepEqual(unread.missed, []);
  const t7 = unread.snap('t7');
  assert.equal(t7.fail, 'T7');
  assert.deepEqual(saidBy(unread, Infinity, 'lists no request'), [], 'said while the contract lists one');
  if (CANCEL_HERE) assert.ok(unread.snap('request').dockIds.includes('cancel'));
  else assert.match(unread.went[0].url, /&r=7&/);
});

test('C9: the cancel is applied and no read reaches the node: "Can\'t read" and the tx, never "doesn\'t show it yet"; CANCELLED when a read does (v2)', { ...T, skip: CANCEL_HERE ? false : 'v1: the phone page owns the cancel' }, async () => {
  const page = await RUNS.c9ReadDown;
  assert.deepEqual(page.missed, []);
  const c9 = page.snap('c9');
  assert.equal(c9.fail, 'C9');
  assert.match(c9.text, READ_DOWN);
  assert.match(c9.text, /NEAR testnet tx X{44}/);
  assert.equal(c9.next, 'Nothing to tap. This page keeps reading the contract.');
  assert.deepEqual(saidBy(page, c9.at, 'doesn\'t show it yet'), [], 'said of a cancel the contract applied, with no read behind it');
  assert.equal(page.snap('end').step, 'recap');
});
