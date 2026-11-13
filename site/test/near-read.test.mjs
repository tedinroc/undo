// A page's NEAR reads on a slow or flaky phone network, on a made-up clock: the hedged reader (PAGE_READS) and
// readPatiently. Hosts here answer after a set time, fail at once, or never answer; nothing goes to a real network.
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { NearReader, PAGE_READS, readPatiently, RpcDown, StaleRead, triedWords, ViewRefused } from '../lib/near-read.mjs';

const SITE = join(dirname(fileURLToPath(import.meta.url)), '..');

/** A clock that moves only when run() moves it, and the timers on it. */
class Clock {
  constructor() {
    this.t = 0;
    this.q = [];
    this.n = 0;
  }

  set = (fn, ms) => {
    this.n += 1;
    this.q.push({ at: this.t + ms, fn, id: this.n });
    return this.n;
  };

  clear = (id) => {
    this.q = this.q.filter((e) => e.id !== id);
  };

  now = () => this.t;

  pending() {
    return this.q.length;
  }

  async run(ms) {
    const end = this.t + ms;
    for (;;) {
      await new Promise((r) => { setImmediate(r); });
      this.q.sort((a, b) => a.at - b.at);
      const e = this.q[0];
      if (!e || e.at > end) break;
      this.q.shift();
      this.t = e.at;
      e.fn();
    }
    this.t = end;
    await new Promise((r) => { setImmediate(r); });
  }
}

const enc = (v) => [...new TextEncoder().encode(JSON.stringify(v))];
const view = (value, height = 100) => ({ jsonrpc: '2.0', id: 1, result: { result: enc(value), logs: [], block_height: height, block_hash: 'x' } });
const block = (height = 100) => ({ jsonrpc: '2.0', id: 1, result: { header: { height, timestamp_nanosec: '1730000000123456789' } } });
const contractRefusal = { jsonrpc: '2.0', id: 1, result: { error: 'wasm execution failed with error: FunctionCallError(ExecutionError("Smart contract panicked: no such vault"))', logs: [], block_height: 100, block_hash: 'x' } };
const tx = { jsonrpc: '2.0', id: 1, result: { final_execution_status: 'EXECUTED_OPTIMISTIC', status: { SuccessValue: '' }, receipts_outcome: [] } };

/**
 * Hosts on the clock. plan[url](n, body) gives each call: { ms, body } answers after ms, { ms, fail: true } fails then,
 * { never: true } never answers, and `ignoresAbort` keeps a call going after its signal fires, as a host that never lets go.
 */
function hosts(clock, plan) {
  const log = [];
  const counts = new Map();
  const fetchFn = (url, init) => {
    const n = (counts.get(url) ?? 0) + 1;
    counts.set(url, n);
    const body = JSON.parse(init.body);
    const step = plan[url](n, body);
    const entry = { url, n, method: body.method, at: clock.t, aborted: false, signal: init.signal };
    log.push(entry);
    return new Promise((resolve, reject) => {
      let id = null;
      init.signal.addEventListener('abort', () => {
        entry.aborted = true;
        if (step.ignoresAbort) return;
        clock.clear(id);
        reject(init.signal.reason);
      }, { once: true });
      if (step.never) return;
      id = clock.set(() => {
        if (step.fail) reject(new TypeError('Load failed'));
        else resolve({ status: step.status ?? 200, text: async () => (typeof step.body === 'string' ? step.body : JSON.stringify(step.body)) });
      }, step.ms);
    });
  };
  return { fetchFn, log };
}

const page = (clock, fetchFn, urls = ['a', 'b', 'c']) => new NearReader({ urls, ...PAGE_READS, fetchFn, nowFn: clock.now, timers: clock });
const every = (step) => ({ a: step, b: step, c: step });

test('PAGE_READS: 6 s for an in-turn read, the next host after 2.5 s, 15 s for one read in all', () => {
  assert.deepEqual({ ...PAGE_READS }, { timeoutMs: 6000, hedgeMs: 2500, budgetMs: 15_000 });
  assert.ok(Object.isFrozen(PAGE_READS));
});

test('hedged: a quick first host is one request, no hedge, and no timer left behind', async () => {
  const clock = new Clock();
  const { fetchFn, log } = hosts(clock, every(() => ({ ms: 300, body: view('ok') })));
  const p = page(clock, fetchFn).view('x', 'm');
  await clock.run(20_000);
  assert.equal(await p, 'ok');
  assert.deepEqual(log.map((e) => e.url), ['a']);
  assert.equal(clock.pending(), 0);
});

for (const ms of [6000, 9000, 14_000]) {
  test(`hedged: every host at ${ms / 1000} s answers inside the budget; the hosts still out are dropped once one answers`, async () => {
    const clock = new Clock();
    const { fetchFn, log } = hosts(clock, { a: () => ({ ms, body: view('a') }), b: () => ({ ms, body: view('b') }), c: () => ({ ms, body: view('c') }) });
    const p = page(clock, fetchFn).view('x', 'm');
    let done = null;
    p.then(() => { done = clock.t; });
    await clock.run(20_000);
    assert.equal(await p, 'a');
    assert.equal(done, ms, 'the answer is taken when it comes');
    assert.deepEqual(log.map((e) => [e.url, e.at]), [['a', 0], ['b', 2500], ['c', 5000]]);
    assert.ok(log.filter((e) => e.url !== 'a').every((e) => e.aborted));
    assert.equal(clock.pending(), 0);
  });
}

test('hedged: a first host that never answers costs 2.5 s, and the next read starts at the host that answered', async () => {
  const clock = new Clock();
  const { fetchFn, log } = hosts(clock, { a: () => ({ never: true }), b: () => ({ ms: 4500, body: view('b') }), c: () => ({ ms: 4500, body: view('c') }) });
  const r = page(clock, fetchFn);
  const p = r.view('x', 'm');
  let done = null;
  p.then(() => { done = clock.t; });
  await clock.run(20_000);
  assert.equal(await p, 'b');
  assert.equal(done, 7000);
  assert.equal(log.find((e) => e.url === 'a').aborted, true);
  const q = r.view('x', 'm');
  await clock.run(20_000);
  assert.equal(await q, 'b');
  const second = log.filter((e) => e.at >= 20_000);
  assert.equal(second[0].url, 'b', 'the second read starts at the host that answered');
  assert.equal(second.some((e) => e.url === 'a'), false, 'and does not wait on the host that never answered');
});

test('hedged: a host that fails at once hands over at once, not after the hedge', async () => {
  const clock = new Clock();
  const { fetchFn, log } = hosts(clock, { a: () => ({ ms: 80, fail: true }), b: () => ({ ms: 300, body: view('b') }), c: () => ({ ms: 300, body: view('c') }) });
  const p = page(clock, fetchFn).view('x', 'm');
  await clock.run(20_000);
  assert.equal(await p, 'b');
  assert.deepEqual(log.map((e) => [e.url, e.at]), [['a', 0], ['b', 80]]);
});

test('hedged: a 429, a proxy page or a node rate limit hands over at once too', async () => {
  for (const bad of [{ status: 429, body: 'Too Many Requests' }, { status: 502, body: '<html>Bad Gateway</html>' }, { body: { jsonrpc: '2.0', id: 1, error: { code: -429, message: 'Rate limits exceeded' } } }]) {
    const clock = new Clock();
    const { fetchFn, log } = hosts(clock, { a: () => ({ ms: 100, ...bad }), b: () => ({ ms: 300, body: view('b') }), c: () => ({ ms: 300, body: view('c') }) });
    const p = page(clock, fetchFn).view('x', 'm');
    await clock.run(20_000);
    assert.equal(await p, 'b');
    assert.deepEqual(log.map((e) => [e.url, e.at]), [['a', 0], ['b', 100]]);
  }
});

test('hedged: nothing answers: RpcDown at the budget, every host tried and ended, no timer left', async () => {
  const clock = new Clock();
  const { fetchFn, log } = hosts(clock, every(() => ({ never: true })));
  const p = page(clock, fetchFn).view('x', 'm').then(() => null, (e) => e);
  await clock.run(14_999);
  assert.equal(log.length, 3);
  assert.ok(log.every((e) => !e.aborted), 'still waiting just before the budget');
  await clock.run(10);
  const err = await p;
  assert.ok(err instanceof RpcDown);
  assert.deepEqual(err.tried.map((t) => [t.url, t.error]), [['a', 'TimeoutError'], ['b', 'TimeoutError'], ['c', 'TimeoutError']]);
  assert.ok(log.every((e) => e.aborted));
  assert.equal(clock.pending(), 0);
});

test('hedged: a host that never lets go of a call cannot hold the read past the budget', async () => {
  const clock = new Clock();
  const { fetchFn } = hosts(clock, every(() => ({ never: true, ignoresAbort: true })));
  const p = page(clock, fetchFn).view('x', 'm').then(() => null, (e) => e);
  await clock.run(15_000);
  assert.ok((await p) instanceof RpcDown);
  assert.equal(clock.pending(), 0);
});

test('hedged: every host failing at once is RpcDown at once, each host asked once', async () => {
  const clock = new Clock();
  const { fetchFn, log } = hosts(clock, every(() => ({ ms: 50, fail: true })));
  const p = page(clock, fetchFn).view('x', 'm').then(() => null, (e) => e);
  await clock.run(1000);
  const err = await p;
  assert.ok(err instanceof RpcDown);
  assert.deepEqual(log.map((e) => [e.url, e.at]), [['a', 0], ['b', 50], ['c', 100]]);
  assert.equal(clock.pending(), 0);
});

test('hedged: the contract\'s refusal is the answer at once, as in turn, and is not asked elsewhere', async () => {
  const clock = new Clock();
  const { fetchFn, log } = hosts(clock, { a: () => ({ ms: 300, body: contractRefusal }), b: () => ({ ms: 300, body: view('b') }), c: () => ({ ms: 300, body: view('c') }) });
  const p = page(clock, fetchFn).view('x', 'vault').then(() => null, (e) => e);
  await clock.run(20_000);
  assert.ok((await p) instanceof ViewRefused);
  assert.equal(log.length, 1);
});

test('hedged: reads do not go back in time: a quick host behind is passed over for a slower one at the head', async () => {
  const clock = new Clock();
  let heightA = 100;
  const { fetchFn } = hosts(clock, { a: () => ({ ms: 200, body: view('a', heightA) }), b: () => ({ ms: 3000, body: view('b', 100) }), c: () => ({ ms: 3000, body: view('c', 101) }) });
  const r = page(clock, fetchFn);
  let p = r.view('x', 'm');
  await clock.run(20_000);
  assert.equal(await p, 'a');
  heightA = 90;
  p = r.view('x', 'm');
  await clock.run(20_000);
  assert.equal(await p, 'b');
});

test('hedged: every host behind is StaleRead', async () => {
  const clock = new Clock();
  const { fetchFn } = hosts(clock, { a: (n) => ({ ms: 200, body: view('a', n === 1 ? 100 : 90) }), b: () => ({ ms: 300, body: view('b', 90) }), c: () => ({ ms: 400, body: view('c', 90) }) });
  const r = page(clock, fetchFn);
  let p = r.view('x', 'm');
  await clock.run(20_000);
  await p;
  p = r.view('x', 'm').then(() => null, (e) => e);
  await clock.run(20_000);
  assert.ok((await p) instanceof StaleRead);
});

test('hedged: an answer that comes after the one taken is never judged, so it cannot move the height', async () => {
  const clock = new Clock();
  const { fetchFn } = hosts(clock, { a: () => ({ ms: 3000, body: view('a', 100) }), b: () => ({ ms: 1000, ignoresAbort: true, body: view('b', 1_000_000) }), c: () => ({ ms: 100, body: view('c', 100) }) });
  const r = page(clock, fetchFn);
  const p = r.view('x', 'm');
  await clock.run(20_000);
  assert.equal(await p, 'a');
  assert.equal(r.maxHeight, 100);
});

test('hedged: blockTime is hedged as well, and its round trip is the one that answered', async () => {
  const clock = new Clock();
  const { fetchFn, log } = hosts(clock, { a: () => ({ never: true }), b: () => ({ ms: 1000, body: block(77) }), c: () => ({ ms: 1000, body: block(77) }) });
  const p = page(clock, fetchFn).blockTime();
  await clock.run(20_000);
  const b = await p;
  assert.equal(b.height, 77);
  assert.equal(b.rttMs, 3500);
  assert.deepEqual(log.map((e) => e.url), ['a', 'b']);
});

test('a page reader still reads a tx in turn: a call held by wait_until is never doubled', async () => {
  const clock = new Clock();
  const { fetchFn, log } = hosts(clock, { a: () => ({ ms: 4000, body: tx }), b: () => ({ ms: 100, body: tx }), c: () => ({ ms: 100, body: tx }) });
  const p = page(clock, fetchFn).txOutcome('h', 's', { wait: 'EXECUTED_OPTIMISTIC' });
  await clock.run(5000);
  assert.equal((await p).settled, true);
  assert.deepEqual(log.map((e) => e.url), ['a']);
  assert.equal(clock.pending(), 0);
});

test('no hedgeMs (the relay, the cron Worker, the tools): one request at a time, in order, each with its own timeout', async () => {
  let out = 0;
  let most = 0;
  const order = [];
  const signals = [];
  const fetchFn = async (url, init) => {
    out += 1;
    most = Math.max(most, out);
    order.push(url);
    signals.push(init.signal);
    await new Promise((r) => { setTimeout(r, 20); });
    out -= 1;
    if (url !== 'c') throw new TypeError('down');
    return { status: 200, text: async () => JSON.stringify(view('c')) };
  };
  assert.equal(await new NearReader({ urls: ['a', 'b', 'c'], timeoutMs: 6000, fetchFn }).view('x', 'm'), 'c');
  assert.equal(most, 1);
  assert.deepEqual(order, ['a', 'b', 'c']);
  assert.ok(signals.every((s) => s instanceof AbortSignal && !s.aborted));
});

test('readPatiently: a pass with no answer is asked again after 1 s, 3 s and 6 s', async () => {
  let t = 0;
  const starts = [];
  const opts = { now: () => t, sleep: async (ms) => { t += ms; } };
  const read = (okAt) => async () => {
    starts.push(t);
    if (starts.length < okAt) throw new RpcDown('query', []);
    return 'ok';
  };
  assert.equal(await readPatiently(read(4), opts), 'ok');
  assert.deepEqual(starts, [0, 1000, 4000, 10_000]);
  starts.length = 0;
  t = 0;
  await assert.rejects(readPatiently(read(9), opts), RpcDown);
  assert.deepEqual(starts, [0, 1000, 4000, 10_000], 'a network that refuses at once: four passes, then the failure, at about 10 s');
});

test('readPatiently: StaleRead is asked again; a refusal or any other error is thrown at once', async () => {
  let t = 0;
  const opts = { now: () => t, sleep: async (ms) => { t += ms; } };
  let calls = 0;
  assert.equal(await readPatiently(async () => { calls += 1; if (calls === 1) throw new StaleRead('behind'); return 'ok'; }, opts), 'ok');
  for (const err of [new ViewRefused('m', 'no'), new TypeError('a bug'), Object.assign(new Error('relay'), { code: 'relay_down' })]) {
    calls = 0;
    await assert.rejects(readPatiently(async () => { calls += 1; throw err; }, opts), (e) => e === err);
    assert.equal(calls, 1);
  }
});

test('readPatiently: never starts a pass past the deadline: a network that never answers fails after two 15 s passes', async () => {
  let t = 0;
  const starts = [];
  const opts = { now: () => t, sleep: async (ms) => { t += ms; } };
  await assert.rejects(readPatiently(async () => {
    starts.push(t);
    t += 15_000;
    throw new RpcDown('query', []);
  }, opts), RpcDown);
  assert.deepEqual(starts, [0, 16_000]);
  assert.equal(t, 31_000);
});

test('readPatiently over the hedged reader: hosts that refuse for 3 s and then answer give the answer', async () => {
  const clock = new Clock();
  const { fetchFn } = hosts(clock, every(() => (clock.t < 3000 ? { ms: 80, fail: true } : { ms: 500, body: view('back') })));
  const r = page(clock, fetchFn);
  const p = readPatiently(() => r.view('x', 'm'), { now: clock.now, sleep: (ms) => new Promise((res) => { clock.set(res, ms); }) });
  let done = null;
  p.then(() => { done = clock.t; });
  await clock.run(60_000);
  assert.equal(await p, 'back');
  assert.ok(done > 3000 && done < 6000, `answered at ${done} ms`);
});

test('triedWords: each host and what it did, for the console', () => {
  const err = new RpcDown('query', [{ url: 'https://test.rpc.fastnear.com', error: 'TimeoutError' }, { url: 'https://near-testnet.drpc.org', status: 429, text: 'Too Many Requests' }, { url: 'https://rpc.testnet.near.org', stale: true }]);
  assert.equal(triedWords(err), 'test.rpc.fastnear.com TimeoutError, near-testnet.drpc.org HTTP 429 Too Many Requests, rpc.testnet.near.org behind');
  assert.equal(triedWords(new Error('x')), '');
});

test('every page that reads NEAR builds its reader with PAGE_READS', () => {
  const pages = join(SITE, 'pages');
  const builds = [];
  for (const dir of readdirSync(pages, { withFileTypes: true }).filter((d) => d.isDirectory())) {
    for (const file of readdirSync(join(pages, dir.name)).filter((f) => f.endsWith('.mjs'))) {
      const text = readFileSync(join(pages, dir.name, file), 'utf8');
      for (const m of text.matchAll(/new NearReader\(([^)]*)\)/g)) builds.push({ file: `${dir.name}/${file}`, args: m[1] });
    }
  }
  assert.ok(builds.length >= 2, builds.map((b) => b.file).join(', '));
  for (const b of builds) assert.match(b.args, /\.\.\.PAGE_READS/, `${b.file}: new NearReader(${b.args})`);
});
