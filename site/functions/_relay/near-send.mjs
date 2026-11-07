// Signs with WebCrypto, because noble's JavaScript does not fit a Worker's CPU limit, and sends one transaction
// until the chain has it. Same rule as Near.send in tools/lib/near.mjs: a timeout is settled by asking about
// that same hash and resending the same bytes, never by signing again, because the first send may have landed.
import { base58Decode, base58Encode, concat, fromHex } from '../../../tools/lib/bytes.mjs';
import { fromBase64Url } from '../../lib/base64.mjs';
import { signedTransaction } from '../../lib/near-tx.mjs';
import { Refusal, workerFetch } from './answer.mjs';

const PKCS8_ED25519 = fromHex('302e020100300506032b657004220420');
const ED25519 = { name: 'Ed25519' };
const MAX_RESIGNS = 2;

const keyCache = new Map();

/**
 * A relay key from its `ed25519:<base58>` text of 32 or 64 bytes. Holds no bytes of the secret outside a
 * non-extractable WebCrypto key after this returns. No error here repeats the text.
 */
export function relayKey(text, accountId) {
  const cacheKey = `${accountId}\n${text}`;
  if (!keyCache.has(cacheKey)) keyCache.set(cacheKey, importRelayKey(text, accountId));
  return keyCache.get(cacheKey);
}

async function importRelayKey(text, accountId) {
  if (typeof text !== 'string' || !text.startsWith('ed25519:')) throw new Error('relay key: not an ed25519 key');
  let raw;
  try {
    raw = base58Decode(text.slice('ed25519:'.length));
  } catch {
    throw new Error('relay key: not base58');
  }
  if (raw.length !== 32 && raw.length !== 64) throw new Error('relay key: wrong length');
  const pkcs8 = concat(PKCS8_ED25519, raw.slice(0, 32));
  const readable = await crypto.subtle.importKey('pkcs8', pkcs8, ED25519, true, ['sign']);
  const { x } = await crypto.subtle.exportKey('jwk', readable);
  const pub = fromBase64Url(x);
  const key = await crypto.subtle.importKey('pkcs8', pkcs8, ED25519, false, ['sign']);
  pkcs8.fill(0);
  raw.fill(0);
  const publicKey = `ed25519:${base58Encode(pub)}`;
  return {
    pub,
    publicKey,
    accountId,
    id: `${accountId}:${publicKey}`,
    sign: async (hash) => new Uint8Array(await crypto.subtle.sign(ED25519, key, hash)),
  };
}

function findField(value, name) {
  if (!value || typeof value !== 'object') return null;
  if (Object.hasOwn(value, name)) return value[name];
  for (const child of Object.values(value)) {
    const found = findField(child, name);
    if (found) return found;
  }
  return null;
}

const isInvalidTx = (error) => error?.cause?.name === 'INVALID_TRANSACTION' || Boolean(error?.data?.TxExecutionError);

export class NearSender {
  /**
   * `nonces` is a StateClient or null. Null reads every nonce from the chain, which is what a cancel falls back
   * to when the state store is down. `budgetMs` keeps the answer inside the page's own 20 s wait.
   */
  constructor({ urls, signerId, receiverId, fetchFn = workerFetch, nowFn = () => Date.now(), callTimeoutMs = 6000, budgetMs = 16_000, pauseMs = 400 }) {
    Object.assign(this, { urls, signerId, receiverId, fetchFn, nowFn, callTimeoutMs, budgetMs, pauseMs });
    this.id = 0;
  }

  /** One call to one URL. Returns { result }, { error } from the node, or { silent } when it said nothing usable. */
  async once(url, method, params) {
    let res;
    let text;
    try {
      res = await this.fetchFn(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: (this.id += 1), method, params }),
        // Signed transactions stay on the host that was asked for: workerFetch follows no redirect.
        signal: AbortSignal.timeout(this.callTimeoutMs),
      });
      text = await res.text();
    } catch (err) {
      return { silent: err.name };
    }
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      return { silent: `HTTP ${res.status}` };
    }
    if (data.error) {
      if (res.status === 429 || /rate limit/i.test(text) || ['TIMEOUT_ERROR', 'NO_SYNCED_BLOCKS', 'INTERNAL_ERROR'].includes(data.error.cause?.name)) return { silent: data.error.cause?.name ?? `HTTP ${res.status}`, error: data.error };
      return { error: data.error };
    }
    return { result: data.result };
  }

  /** For calls that are safe to repeat. Every URL once. */
  async ask(method, params) {
    let last = null;
    for (const url of this.urls) {
      const out = await this.once(url, method, params);
      if (out.result !== undefined) return out.result;
      if (out.error && !out.silent) return { nodeError: out.error };
      last = out.silent;
    }
    throw new Refusal('rpc_down', { message: `no NEAR RPC answered ${method}`, verbatim: last });
  }

  async chainNonce(key) {
    const out = await this.ask('query', { request_type: 'view_access_key', account_id: key.accountId, public_key: key.publicKey, finality: 'optimistic' });
    if (out.nodeError) throw new Refusal('relay_not_configured', { message: 'the relay key could not be read on its account', verbatim: JSON.stringify(out.nodeError) });
    return out.nonce;
  }

  async finalHash() {
    const out = await this.ask('block', { finality: 'final' });
    if (out.nodeError) throw new Refusal('rpc_down', { message: 'no final block', verbatim: JSON.stringify(out.nodeError) });
    return out.header.hash;
  }

  async firstNonce(key, nonces) {
    if (!nonces) return (await this.chainNonce(key)) + 1;
    const leased = await nonces.lease(key);
    if (!leased.need_chain) return leased.nonce;
    return (await nonces.seed(key, await this.chainNonce(key), this.nowFn())).nonce;
  }

  async nonceAfterStale(key, nonces, stale) {
    if (!nonces) return Math.max(await this.chainNonce(key), stale?.ak_nonce ?? 0) + 1;
    const ak = stale?.ak_nonce ?? (await this.chainNonce(key));
    return (await nonces.reset(key, ak, this.nowFn())).nonce;
  }

  async landed(hash) {
    for (const url of this.urls) {
      const out = await this.once(url, 'tx', { tx_hash: hash, sender_account_id: this.signerId, wait_until: 'INCLUDED' });
      if (out.result !== undefined) return true;
    }
    return false;
  }

  /** Until the chain has these bytes, the node refuses them, or time runs out. Never re-signs. */
  async deliver(signed, deadline) {
    for (let i = 0; this.nowFn() < deadline; i += 1) {
      const out = await this.once(this.urls[i % this.urls.length], 'send_tx', { signed_tx_base64: signed.base64, wait_until: 'INCLUDED' });
      if (out.result !== undefined) return { included: true };
      if (out.error && !out.silent && isInvalidTx(out.error)) {
        // On a resend this can mean the first send landed, so look before calling it a failure.
        if (i > 0 && (await this.landed(signed.hash))) return { included: true };
        return { invalid: out.error };
      }
      if (out.error && !out.silent) return { invalid: out.error };
      if (await this.landed(signed.hash)) return { included: true };
      await new Promise((r) => setTimeout(r, this.pauseMs));
    }
    return { unknown: true };
  }

  /**
   * Returns { hash, retries } once included, or { hash, retries, state: 'unknown' }. Throws a Refusal. `onSigned(hash)`
   * runs before each signed transaction goes out, and if it throws, nothing more is sent.
   */
  async send(key, actions, { nonces = null, onSigned = null } = {}) {
    const deadline = this.nowFn() + this.budgetMs;
    let retries = 0;
    let nonce = await this.firstNonce(key, nonces);
    for (;;) {
      if (!Number.isSafeInteger(nonce)) throw new Refusal('stale_nonce', { message: 'the nonce is out of range' });
      const signed = await signedTransaction({
        signerId: this.signerId,
        publicKey: key.pub,
        nonce: BigInt(nonce),
        receiverId: this.receiverId,
        blockHash: await this.finalHash(),
        actions,
      }, key.sign);
      if (onSigned) await onSigned(signed.hash);
      const out = await this.deliver(signed, deadline);
      if (out.included) return { hash: signed.hash, retries };
      if (out.unknown) return { hash: signed.hash, retries, state: 'unknown' };
      const stale = findField(out.invalid, 'InvalidNonce');
      const expired = JSON.stringify(out.invalid).includes('Expired');
      // Either way the transaction never ran, so signing again is safe.
      if (!stale && !expired) throw new Refusal('tx_refused', { message: 'the node refused the transaction', verbatim: JSON.stringify(out.invalid) });
      if (retries >= MAX_RESIGNS) throw new Refusal('stale_nonce', { message: 'nonce retries used up', verbatim: JSON.stringify(out.invalid) });
      retries += 1;
      nonce = stale ? await this.nonceAfterStale(key, nonces, stale) : await this.firstNonce(key, nonces);
    }
  }
}

