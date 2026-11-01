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

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export class NearReader {
  constructor({ urls, timeoutMs = 4000, fetchFn = (...a) => globalThis.fetch(...a), nowFn = () => Date.now(), staleBlocks = 3 }) {
    if (!Array.isArray(urls) || urls.length === 0) throw new Error('NearReader needs at least one URL');
    Object.assign(this, { urls, timeoutMs, fetchFn, nowFn, staleBlocks });
    this.first = 0;
    this.maxHeight = 0;
    this.id = 0;
  }

  async once(url, method, params) {
    const res = await this.fetchFn(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: (this.id += 1), method, params }),
      redirect: 'error',
      signal: AbortSignal.timeout(this.timeoutMs),
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
    for (let i = 0; i < this.urls.length; i += 1) {
      const at = (this.first + i) % this.urls.length;
      const url = this.urls[at];
      let answer;
      try {
        answer = await this.once(url, method, params);
      } catch (err) {
        tried.push({ url, error: err.name });
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
   */
  async txOutcome(hash, sender) {
    const { result, error } = await this.rpc('tx', { tx_hash: hash, sender_account_id: sender, wait_until: 'INCLUDED' });
    if (error) return { known: false, verbatim: JSON.stringify(error) };
    return { known: true, failure: failureOf(result), value: returnValue(result) };
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
