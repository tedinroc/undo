// Public NEAR RPC, read only: a fallback list, a timeout, and reads that do not go back in time. A page
// holds no key and sends no transaction from here. Errors keep the node's own words.
import { fromBase64, toBase64 } from './base64.mjs';

export class RpcDown extends Error {
  constructor(method, tried) {
    super(`no NEAR RPC answered ${method}`);
    this.tried = tried;
  }
}

/** The contract refused a view. `verbatim` is the node's text. */
export class ViewRefused extends Error {
  constructor(method, verbatim) {
    super(`view ${method} refused`);
    this.verbatim = verbatim;
  }
}

/** Every node answered from a block older than one this page already read. Skip the tick. */
export class StaleRead extends Error {}

const SETTLED = new Set(['EXECUTED_OPTIMISTIC', 'EXECUTED', 'FINAL']);

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export class NearReader {
  /**
   * `hedgeMs` and `budgetMs` (PAGE_READS), when set, make a view or block read ask the next host after hedgeMs with no
   * answer, without dropping the one still out, and give the whole read budgetMs. Unset (the relay, the cron Worker, the
   * tools), each host gets timeoutMs and the next is asked only after it, as before. `timers` is the clock, for a test.
   */
  constructor({ urls, timeoutMs = 4000, fetchFn = (...a) => globalThis.fetch(...a), nowFn = () => Date.now(), staleBlocks = 3, hedgeMs = null, budgetMs = null, timers = TIMERS }) {
    if (!Array.isArray(urls) || urls.length === 0) throw new Error('NearReader needs at least one URL');
    Object.assign(this, { urls, timeoutMs, fetchFn, nowFn, staleBlocks, hedgeMs, budgetMs, timers });
    this.first = 0;
    this.maxHeight = 0;
    this.id = 0;
  }

  /**
   * This reader with each hedged read given `budgetMs` in all, in place of its own. It is still this reader: the same
   * hosts, the host that answered last, and the newest block read, so what it takes is held to the same staleness rule.
   */
  withBudget(budgetMs) {
    return new Proxy(this, { get: (reader, key) => (key === 'budgetMs' ? budgetMs : Reflect.get(reader, key)) });
  }

  async once(url, method, params, signal = AbortSignal.timeout(this.timeoutMs)) {
    const res = await this.fetchFn(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: (this.id += 1), method, params }),
      redirect: 'error',
      signal,
    });
    const text = await res.text();
    let data = null;
    try {
      data = JSON.parse(text);
    } catch {
      // A proxy's page, or a rate limiter's. It said nothing about the chain.
    }
    return { status: res.status, text, data };
  }

  /**
   * Tries each URL once, starting from the last that worked. `accept` may refuse an answer so the next
   * URL gets a try. A node's own handler error, such as an unknown request, is returned as `error`
   * and not retried, because every node would say the same.
   */
  async rpc(method, params, accept = () => true) {
    const tried = [];
    let stale = false;
    const order = this.urls.map((_, i) => (this.first + i) % this.urls.length);
    for await (const { at, url, answer, error } of this.answers(order, method, params)) {
      if (error) {
        tried.push({ url, error: error.name });
        continue;
      }
      const { status, text, data } = answer;
      if (!data || status === 429 || status >= 500 || status === 403 || status === 410) {
        tried.push({ url, status, text: text.slice(0, 300) });
        continue;
      }
      if (data.error) {
        const cause = data.error.cause?.name;
        const limited = /rate limit/i.test(text) || data.error.code === -429;
        if (limited || cause === 'TIMEOUT_ERROR' || cause === 'NO_SYNCED_BLOCKS' || cause === 'UNKNOWN_BLOCK' || cause === 'INTERNAL_ERROR') {
          tried.push({ url, status, text: text.slice(0, 300) });
          continue;
        }
        this.first = at;
        return { error: data.error };
      }
      if (!accept(data.result)) {
        stale = true;
        tried.push({ url, stale: true });
        continue;
      }
      this.first = at;
      return { result: data.result };
    }
    if (stale) throw new StaleRead(`every node behind block ${this.maxHeight}`);
    throw new RpcDown(method, tried);
  }

  fresh(height) {
    if (typeof height !== 'number') return true;
    if (height + this.staleBlocks < this.maxHeight) return false;
    if (height > this.maxHeight) this.maxHeight = height;
    return true;
  }

  async view(account, method, args = {}, finality = 'optimistic') {
    const { result, error } = await this.rpc('query', {
      request_type: 'call_function',
      account_id: account,
      method_name: method,
      args_base64: toBase64(textEncoder.encode(JSON.stringify(args))),
      finality,
    }, (r) => this.fresh(r.block_height));
    if (error) throw new ViewRefused(method, error.data ?? error.cause?.info?.vm_error ?? JSON.stringify(error));
    if (result.error) throw new ViewRefused(method, result.error);
    return JSON.parse(textDecoder.decode(Uint8Array.from(result.result)));
  }

  /**
   * An account's access keys at a final block, as the node lists them: [{ public_key, access_key: { permission } }].
   * A full-access key on a contract's account can replace its code at once, so a page reads this before it says how
   * long an upgrade waits. Throws when no node gives a list.
   */
  async accessKeys(account) {
    const { result, error } = await this.rpc('query', { request_type: 'view_access_key_list', account_id: account, finality: 'final' });
    if (error) throw new ViewRefused('view_access_key_list', JSON.stringify(error));
    if (!Array.isArray(result?.keys)) throw new ViewRefused('view_access_key_list', 'the answer holds no key list');
    return result.keys;
  }

  /**
   * The time of the block at `height`, or null when no node answers with it: a height the chain skipped, one older
   * than a node keeps, or no node at all. Only a lower bound on a height is ever drawn from it.
   */
  async blockMsAt(height) {
    try {
      const { result, error } = await this.rpc('block', { block_id: height });
      if (error || result?.header?.height !== height) return null;
      return Number(BigInt(result.header.timestamp_nanosec) / 1_000_000n);
    } catch {
      return null;
    }
  }

  /** What the contract's clock read, and when this machine heard it. Feed it to SkewTracker. */
  async blockTime() {
    const sentAt = this.nowFn();
    const { result, error } = await this.rpc('block', { finality: 'optimistic' }, (r) => this.fresh(r.header?.height));
    if (error) throw new RpcDown('block', [{ error: JSON.stringify(error) }]);
    const localMs = this.nowFn();
    return {
      blockMs: Number(BigInt(result.header.timestamp_nanosec) / 1_000_000n),
      height: result.header.height,
      localMs,
      rttMs: localMs - sentAt,
    };
  }

  /**
   * A transaction's outcome, read by the page itself. `failure` is the chain's own JSON text. Reads the
   * state of a request, not this, to learn what happened: a transaction can report success with a dead
   * callback. This is only for showing why a call was refused.
   *
   * At the default `wait`, an answer can come before the contract has run, and then `failure` is null because nothing
   * has failed yet: `settled` says whether it has run. EXECUTED_OPTIMISTIC waits for that, up to the reader's timeout,
   * so use it only for a call with no long receipts behind it. An `execute` waits on the signer.
   */
  async txOutcome(hash, sender, { wait = 'INCLUDED' } = {}) {
    const { result, error } = await this.rpc('tx', { tx_hash: hash, sender_account_id: sender, wait_until: wait });
    if (error) return { known: false, settled: false, verbatim: JSON.stringify(error) };
    return { known: true, settled: SETTLED.has(result?.final_execution_status), failure: failureOf(result), value: returnValue(result) };
  }

  /**
   * The answers to one read, in the order they come: { at, url, sentAt, answer } or { at, url, sentAt, error }. In turn
   * (no hedgeMs, or a method not in HEDGED): each host once, the next only after the one before has answered or failed,
   * each within timeoutMs. Hedged: the first host now, the next after hedgeMs with no answer, or at once when an answer
   * is passed over, every one still out kept; all of it within budgetMs, after which whatever is still out ends as a
   * TimeoutError and nothing new starts. The host `avoidAt` names is never started by the hedge timer. Leaving the loop
   * ends whatever is still out, and an answer that comes after that is never seen.
   */
  async *answers(order, method, params, { avoidAt = -1 } = {}) {
    if (this.hedgeMs === null || !HEDGED.has(method)) {
      for (const at of order) {
        const url = this.urls[at];
        const sentAt = this.nowFn();
        let item;
        try {
          item = { at, url, sentAt, answer: await this.once(url, method, params) };
        } catch (error) {
          item = { at, url, sentAt, error };
        }
        yield item;
      }
      return;
    }
    const { set, clear } = this.timers;
    const queue = [];
    // Each host still out: at -> { url, sentAt, stop }.
    const out = new Map();
    let next = 0;
    let over = false;
    let wake = null;
    let hedge = null;
    const ping = () => {
      const w = wake;
      wake = null;
      w?.();
    };
    const settle = (at, outcome) => {
      const o = out.get(at);
      if (!o) return;
      out.delete(at);
      queue.push({ at, url: o.url, sentAt: o.sentAt, ...outcome });
      ping();
    };
    const budget = set(() => {
      over = true;
      clear(hedge);
      // Ended here, not when the fetch notices its signal: a host that never lets go of the call cannot hold the read.
      for (const [at, o] of [...out]) {
        const error = new DOMException('the read took longer than its budget', 'TimeoutError');
        o.stop.abort(error);
        settle(at, { error });
      }
      ping();
    }, this.budgetMs);
    const launch = () => {
      const at = order[next];
      next += 1;
      const url = this.urls[at];
      const stop = new AbortController();
      out.set(at, { url, sentAt: this.nowFn(), stop });
      this.once(url, method, params, stop.signal).then((answer) => settle(at, { answer }), (error) => settle(at, { error }));
      clear(hedge);
      hedge = null;
      if (next < order.length && order[next] !== avoidAt) {
        hedge = set(() => {
          hedge = null;
          if (!over && next < order.length) launch();
          ping();
        }, this.hedgeMs);
      }
    };
    try {
      let passedOver = false;
      for (;;) {
        if (queue.length === 0 && !over && next < order.length && (out.size === 0 || passedOver)) launch();
        passedOver = false;
        while (queue.length === 0 && out.size > 0) await new Promise((r) => { wake = r; });
        if (queue.length === 0) return;
        yield queue.shift();
        passedOver = true;
      }
    } finally {
      over = true;
      clear(hedge);
      clear(budget);
      for (const o of out.values()) o.stop.abort(new DOMException('another host answered', 'AbortError'));
      out.clear();
    }
  }
}

export function failureOf(result) {
  if (!result) return null;
  const top = result.status?.Failure;
  if (top) return JSON.stringify(top);
  for (const r of result.receipts_outcome ?? []) {
    if (r.outcome.status?.Failure) return JSON.stringify(r.outcome.status.Failure);
  }
  return null;
}

export function returnValue(result) {
  const value = result?.status?.SuccessValue;
  if (value === undefined || value === null || value === '') return null;
  return JSON.parse(textDecoder.decode(fromBase64(value)));
}

/**
 * A page's reader on a phone network: a view or block read asks the next host after 2.5 s with no answer and gets 15 s
 * in all, so hosts that each take 6 to 14 s still answer, and a host that never answers costs 2.5 s. A `tx` read goes
 * in turn, 6 s a host.
 */
export const PAGE_READS = Object.freeze({ timeoutMs: 6000, hedgeMs: 2500, budgetMs: 15_000 });

/** Methods whose read is hedged. A `tx` read can wait at the node on purpose (wait_until), so it goes in turn. */
const HEDGED = new Set(['query', 'block']);

const TIMERS = Object.freeze({ set: (fn, ms) => setTimeout(fn, ms), clear: (id) => clearTimeout(id) });

/**
 * A read a tap waits on, asked again when it ended with no answer from any node (RpcDown, StaleRead): after each pause
 * in `pausesMs` in turn, and never starting after `deadlineMs`. A node's or the contract's own answer, a refusal, is
 * thrown at once. With PAGE_READS (15 s a pass) a network that never answers throws after about 31 s, one that refuses
 * at once after about 10 s, and none takes longer than deadlineMs plus one pass.
 */
export async function readPatiently(read, { pausesMs = [1000, 3000, 6000], deadlineMs = 30_000, now = () => Date.now(), sleep = (ms) => new Promise((r) => { setTimeout(r, ms); }) } = {}) {
  const start = now();
  for (let i = 0; ; i += 1) {
    try {
      return await read();
    } catch (err) {
      if (!(err instanceof RpcDown || err instanceof StaleRead) || i >= pausesMs.length || now() - start + pausesMs[i] >= deadlineMs) throw err;
      await sleep(pausesMs[i]);
    }
  }
}

/** What each host did on a read no node answered, for the console: "host TimeoutError, host HTTP 429, ...". */
export function triedWords(err) {
  if (!Array.isArray(err?.tried) || err.tried.length === 0) return '';
  const host = (url) => {
    try {
      return new URL(url).host || url;
    } catch {
      return url;
    }
  };
  const what = (t) => t.error ?? (t.stale ? 'behind' : `HTTP ${t.status ?? '?'}${t.text ? ` ${t.text.slice(0, 80)}` : ''}`);
  return err.tried.map((t) => `${host(t.url ?? '?')} ${what(t)}`).join(', ');
}
