// A small Esplora client for gate G2. Node's own fetch, no dependency.
//
// The one rule that matters: only a node's answer about the transaction counts as a rejection. A 5xx,
// a 429, a dropped connection or a proxy's HTML page says nothing about the transaction, so it is
// retried and never reported as a refusal. Reporting one as a refusal would pass the CSV test wrongly.

export const ESPLORA_ALLOW = ['https://mutinynet.com/api'];
export const NEAR_RPC_ALLOW = ['https://test.rpc.fastnear.com', 'https://rpc.testnet.near.org'];
const LOCAL_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]']);

export class RelayError extends Error {}
export class EndpointRefused extends Error {}

/** Live: exact names from the allow lists. Rehearsal: this machine only. Throws before any request. */
export function checkEndpoints({ regtest, esplora, rpc }) {
  const isLocal = (url) => {
    try {
      const u = new URL(url);
      return u.protocol === 'http:' && LOCAL_HOSTS.has(u.hostname);
    } catch {
      return false;
    }
  };
  for (const url of rpc) {
    if (regtest ? !isLocal(url) : !NEAR_RPC_ALLOW.includes(url)) throw new EndpointRefused('that NEAR RPC is not on the allow list');
  }
  if (regtest ? !isLocal(esplora) : !ESPLORA_ALLOW.includes(esplora)) throw new EndpointRefused('that Esplora is not on the allow list');
}

/** What a node's refusal text means. Only `bip68` proves the CSV held. */
export function refusalKind(text) {
  if (/non-BIP68-final|sequence[- ]locks? (not|on)/i.test(text)) return 'bip68';
  if (/txn-already-in-mempool|txn-already-known|txn-same-nonwitness-data-in-mempool|already known|already in block ?chain|already-in-utxo|already in utxo/i.test(text)) return 'already';
  if (/missingorspent|missing-inputs|missing inputs|txn-mempool-conflict/i.test(text)) return 'inputs_gone';
  if (/script-verify|Non-canonical|Locktime requirement|Witness program/i.test(text)) return 'script';
  return 'other';
}

// A node too busy to look at the transaction has said nothing about it.
const NODE_BUSY = /Loading block index|Loading wallet|Verifying blocks|Rewinding blocks|Work queue depth|"code":\s*-28\b|"code":\s*-32603\b/i;

/** One POST's answer, sorted into accepted, rejected by a node, or no information at all. */
export function classifyBroadcast(status, body, txid) {
  const text = String(body ?? '').trim().slice(0, 400);
  if (status >= 200 && status < 300) {
    return text.toLowerCase() === txid ? { kind: 'accepted', status, text } : { kind: 'transient', status, text: 'a 2xx that does not name this transaction' };
  }
  // Esplora answers every node refusal with a 400. Any other status came from something on the way.
  if (status !== 400) return { kind: 'transient', status, text };
  if (/<html/i.test(text)) return { kind: 'transient', status, text: 'a web page, not a node' };
  if (NODE_BUSY.test(text)) return { kind: 'transient', status, text };
  return { kind: 'rejected', status, text, refusal: refusalKind(text) };
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export class Esplora {
  constructor(base, { timeoutMs = 30_000, backoffMs = 3000, attempts = 8 } = {}) {
    this.base = base;
    this.timeoutMs = timeoutMs;
    this.backoffMs = backoffMs;
    this.attempts = attempts;
    // How many answers carried no information, for the proof.
    this.transient = 0;
  }

  async request(path, init = {}) {
    try {
      return await fetch(`${this.base}${path}`, { redirect: 'error', signal: AbortSignal.timeout(this.timeoutMs), ...init });
    } catch (err) {
      throw new RelayError(`${init.method ?? 'GET'} ${path.split('/')[1]}: ${err.cause?.code ?? err.name}`);
    }
  }

  /** Text of a read, or null on a 404. Reads are safe to repeat. */
  async get(path) {
    let last;
    for (let i = 0; i < this.attempts; i += 1) {
      try {
        const res = await this.request(path);
        if (res.status === 404) return null;
        if (res.ok) return await res.text();
        last = new RelayError(`GET ${path.split('/')[1]}: HTTP ${res.status}`);
      } catch (err) {
        if (!(err instanceof RelayError)) throw err;
        last = err;
      }
      this.transient += 1;
      await sleep(this.backoffMs * (i + 1));
    }
    throw last;
  }

  async json(path) {
    const text = await this.get(path);
    if (text === null) return null;
    try {
      return JSON.parse(text);
    } catch {
      throw new RelayError(`GET ${path.split('/')[1]}: not JSON`);
    }
  }

  /** A read that must have an answer. A 404 or an empty body here is the relay's gap, not a fact. */
  async must(path, parse) {
    for (let i = 0; i < this.attempts; i += 1) {
      const text = await this.get(path);
      const value = text === null ? undefined : parse(text);
      if (value !== undefined) return value;
      this.transient += 1;
      await sleep(this.backoffMs * (i + 1));
    }
    throw new RelayError(`GET ${path.split('/')[1]}: no usable answer in ${this.attempts} tries`);
  }

  tip() {
    return this.must('/blocks/tip/height', (text) => {
      const trimmed = text.trim();
      const height = Number(trimmed);
      return trimmed !== '' && Number.isSafeInteger(height) && height >= 0 ? height : undefined;
    });
  }

  genesis() {
    return this.get('/block-height/0');
  }

  /** An address with no coins answers an empty list, so no list at all is never read as no coins. */
  utxos(address) {
    return this.must(`/address/${address}/utxo`, (text) => {
      try {
        const list = JSON.parse(text);
        return Array.isArray(list) ? list : undefined;
      } catch {
        return undefined;
      }
    });
  }

  tx(txid) {
    return this.json(`/tx/${txid}`);
  }

  /** The bytes, or null if the answer is missing or is not hex. */
  async txHex(txid) {
    const text = (await this.get(`/tx/${txid}/hex`))?.trim();
    return text && /^[0-9a-f]+$/i.test(text) ? text.toLowerCase() : null;
  }

  /** Real Esplora answers {"confirmed":false} for a transaction it has never heard of. Use tx() to ask. */
  txStatus(txid) {
    return this.json(`/tx/${txid}/status`);
  }

  outspend(txid, vout) {
    return this.json(`/tx/${txid}/outspend/${vout}`);
  }

  feeEstimates() {
    return this.json('/fee-estimates');
  }

  /**
   * Sends these bytes until a node answers. Returns accepted or rejected. After a transient answer it
   * looks for the transaction first, because a 5xx can arrive for a POST that landed. `guard` runs
   * before each try and may throw to stop. Throws RelayError if no node ever answered.
   */
  async broadcast(hex, txid, { guard } = {}) {
    let last = null;
    for (let i = 0; i < this.attempts; i += 1) {
      if (guard) await guard();
      let answer;
      try {
        const res = await this.request('/tx', { method: 'POST', headers: { 'content-type': 'text/plain' }, body: hex });
        answer = classifyBroadcast(res.status, await res.text(), txid);
      } catch (err) {
        if (!(err instanceof RelayError)) throw err;
        answer = { kind: 'transient', status: null, text: err.message };
      }
      if (answer.kind === 'accepted') return answer;
      if (answer.kind === 'rejected') {
        // Already there is success. A spent input can also mean that this very transaction was mined.
        if (answer.refusal === 'already' || answer.refusal === 'inputs_gone') {
          const seen = await this.tx(txid).catch(() => null);
          if (seen?.txid === txid) return { kind: 'accepted', status: answer.status, text: answer.text, already: true };
        }
        return answer;
      }
      last = answer;
      this.transient += 1;
      const seen = await this.tx(txid).catch(() => null);
      if (seen?.txid === txid) return { kind: 'accepted', status: answer.status, text: answer.text, landed_despite: true };
      await sleep(this.backoffMs * (i + 1));
    }
    throw new RelayError(`no node answered after ${this.attempts} tries. Last: HTTP ${last?.status ?? 'none'}`);
  }

  /** A CORS preflight from a script. It sends no transaction, and it is not a browser. */
  async preflight(origin) {
    const res = await this.request('/tx', {
      method: 'OPTIONS',
      headers: { origin, 'access-control-request-method': 'POST', 'access-control-request-headers': 'content-type' },
    });
    const h = (name) => res.headers.get(name);
    const allowOrigin = h('access-control-allow-origin');
    const allowMethods = h('access-control-allow-methods');
    return {
      origin,
      http_status: res.status,
      allow_origin: allowOrigin,
      allow_methods: allowMethods,
      allow_headers: h('access-control-allow-headers'),
      preflight_allows_post: (allowOrigin === '*' || allowOrigin === origin) && /(^|[ ,])POST([ ,]|$)/i.test(allowMethods ?? ''),
    };
  }
}
