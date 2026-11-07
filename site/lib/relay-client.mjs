// The page's side of /api/relay and /api/funds, whose methods and codes are in relay-table.mjs. A refusal keeps
// the relay's code and, when it carries one, the chain's own words, so a screen never paraphrases a node.
import { noAnswerWords } from '../../tools/lib/esplora.mjs';

/**
 * The relay said no. `code` is one of RELAY_ERRORS. `verbatim` is the chain's or node's text, if any. `errorKind` is
 * the name of the error a fetch threw when no answer came, for logs: the message says it in words.
 */
export class RelayRefused extends Error {
  constructor({ code, message, verbatim = null, retryAfterS = null, httpStatus = null, bucket = null, resetsAt = null, errorKind = null }) {
    super(message ?? code);
    Object.assign(this, { code, verbatim, retryAfterS, httpStatus, bucket, resetsAt, errorKind });
  }
}

const DOWN = (why, errorKind = null) => ({
  reachable: false,
  why,
  errorKind,
  relayAccount: null,
  powBits: null,
  owner: { up: false, why: 'relay_down' },
  general: { up: false, why: 'relay_down' },
  funds: { up: false, why: 'relay_down' },
});

export class RelayClient {
  constructor({ relay, funds, fetchFn = (...a) => globalThis.fetch(...a), timeoutMs = 20_000 }) {
    Object.assign(this, { relay, funds, fetchFn, timeoutMs });
  }

  /** Never throws. A dead relay is a state a page draws, not an exception it can forget to catch. */
  async status() {
    let res;
    let data;
    try {
      res = await this.fetchFn(this.relay, { method: 'GET', cache: 'no-store', signal: AbortSignal.timeout(Math.min(this.timeoutMs, 8000)) });
      data = await res.json();
    } catch (err) {
      return DOWN(noAnswerWords(err), err.name);
    }
    if (!data || data.ok !== true) return DOWN(data?.code ?? `HTTP ${res.status}`);
    return {
      reachable: true,
      why: null,
      relayAccount: data.relay_account,
      powBits: data.pow_bits,
      owner: data.owner,
      general: data.general,
      funds: data.funds,
    };
  }

  async post(path, body) {
    let res;
    let data = null;
    try {
      res = await this.fetchFn(path, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(this.timeoutMs),
      });
      data = await res.json();
    } catch (err) {
      throw new RelayRefused({ code: 'relay_down', message: `no answer from the relay: ${noAnswerWords(err)}`, httpStatus: res?.status ?? null, errorKind: err.name });
    }
    if (data?.ok !== true) {
      throw new RelayRefused({
        code: data?.code ?? 'relay_down',
        message: data?.message,
        verbatim: data?.verbatim ?? null,
        retryAfterS: data?.retry_after_s ?? null,
        bucket: data?.bucket ?? null,
        resetsAt: data?.resets_at ?? null,
        httpStatus: res.status,
      });
    }
    return data;
  }

  /** Returns { ok, hash, key, method } once the transaction is included. Read the contract for what it did. */
  call(method, args, { pow } = {}) {
    return this.post(this.relay, pow === undefined ? { method, args } : { method, args, pow });
  }

  /** The vault's address comes from the contract, on the server, so nobody can name another payee. */
  fund(vault, { pow = 0 } = {}) {
    return this.post(this.funds, { vault, pow });
  }
}
