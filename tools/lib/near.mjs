// A small NEAR client: JSON-RPC, Borsh transactions and ed25519 signing, with no dependency but noble.
//
// Never blocks on a transaction that waits on the signer. `send` returns once the transaction is
// included, and callers read contract state, because transaction status reports success even when
// callbacks ran out of gas.
import { readFileSync, statSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { b } from './borsh.mjs';
import { base58Decode, base58Encode, concat, fromBase64, toBase64, u128le, utf8 } from './bytes.mjs';
import { ed25519, sha256 } from './crypto.mjs';

export const TGAS = 1_000_000_000_000n;
export const NEAR = 10n ** 24n;
export const milliNear = (n) => (BigInt(n) * NEAR) / 1000n;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------- keys

export function keyFromSecret(secret32) {
  const pub = ed25519.getPublicKey(secret32);
  return { secret: secret32, pub, publicKey: `ed25519:${base58Encode(pub)}` };
}

export function parseSecretKey(text) {
  if (typeof text !== 'string' || !text.startsWith('ed25519:')) throw new Error('only ed25519 keys are supported');
  const raw = base58Decode(text.slice('ed25519:'.length));
  if (raw.length !== 64 && raw.length !== 32) throw new Error('bad secret key length');
  return keyFromSecret(raw.slice(0, 32));
}

/** near-cli's legacy file, or a node's validator_key.json. The secret never leaves this process. */
export function loadKeyFile(path) {
  const data = JSON.parse(readFileSync(path, 'utf8'));
  const text = data.private_key ?? data.secret_key;
  if (!text) throw new Error('key file has no key');
  return { ...parseSecretKey(text), accountId: data.account_id };
}

export function credentialsPath(network, account) {
  const home = process.env.NEAR_CREDENTIALS_DIR ?? join(homedir(), '.near-credentials');
  return join(home, network, `${account}.json`);
}

export function loadCredentials(network, account) {
  const path = credentialsPath(network, account);
  const mode = statSync(path).mode & 0o077;
  const key = loadKeyFile(path);
  return { ...key, accountId: account, looseMode: mode !== 0 };
}

// ---------------------------------------------------------------- transactions

const borshPublicKey = (pub) => concat(Uint8Array.of(0), pub);

export const action = {
  createAccount: () => Uint8Array.of(0),
  deploy: (code) => concat(Uint8Array.of(1), b.bytes(code)),
  call: (method, args, gas, deposit = 0n) => concat(
    Uint8Array.of(2),
    b.str(method),
    b.bytes(args instanceof Uint8Array ? args : utf8(JSON.stringify(args))),
    b.u64(gas),
    u128le(deposit),
  ),
  transfer: (amount) => concat(Uint8Array.of(3), u128le(amount)),
  addFullKey: (pub) => concat(Uint8Array.of(5), borshPublicKey(pub), b.u64(0), Uint8Array.of(1)),
  addCallKey: (pub, receiver, methods, allowance) => concat(
    Uint8Array.of(5),
    borshPublicKey(pub),
    b.u64(0),
    Uint8Array.of(0),
    allowance === null ? Uint8Array.of(0) : concat(Uint8Array.of(1), u128le(allowance)),
    b.str(receiver),
    b.vec(methods, b.str),
  ),
  deleteKey: (pub) => concat(Uint8Array.of(6), borshPublicKey(pub)),
};

export function signTransaction({ signerId, key, nonce, receiverId, blockHash, actions }) {
  const tx = concat(
    b.str(signerId),
    borshPublicKey(key.pub),
    b.u64(nonce),
    b.str(receiverId),
    b.raw(blockHash),
    b.vec(actions, (a) => a),
  );
  const hash = sha256(tx);
  const signed = concat(tx, Uint8Array.of(0), ed25519.sign(hash, key.secret));
  return { hash: base58Encode(hash), base64: toBase64(signed) };
}

// ---------------------------------------------------------------- rpc

export class RpcError extends Error {
  constructor(message, data) {
    super(message);
    this.data = data;
  }
}

export class Near {
  constructor(urls, { timeoutMs = 60_000 } = {}) {
    this.urls = Array.isArray(urls) ? urls : [urls];
    this.timeoutMs = timeoutMs;
    this.nonces = new Map();
    this.id = 0;
  }

  async rpcOnce(url, method, params) {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: (this.id += 1), method, params }),
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    const text = await res.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch {
      throw new RpcError(`rpc ${method}: HTTP ${res.status} with no JSON`, null);
    }
    if (data.error) {
      const cause = data.error.cause?.name ?? data.error.name;
      throw new RpcError(`rpc ${method}: ${cause ?? 'error'}`, data.error);
    }
    return data.result;
  }

  /** Only for calls that are safe to repeat. Moves to the next URL on a network failure. */
  async rpc(method, params, { attempts = 4 } = {}) {
    let last;
    for (let i = 0; i < attempts; i += 1) {
      const url = this.urls[i % this.urls.length];
      try {
        return await this.rpcOnce(url, method, params);
      } catch (err) {
        last = err;
        if (err instanceof RpcError && err.data) {
          const cause = err.data.cause?.name;
          if (cause !== 'TIMEOUT_ERROR' && cause !== 'NO_SYNCED_BLOCKS') throw err;
        }
        await sleep(400 * (i + 1));
      }
    }
    throw last;
  }

  async status() {
    return this.rpc('status', []);
  }

  async block(finality = 'final') {
    return this.rpc('block', { finality });
  }

  /** Block time in ms, the clock the contract compares with. */
  async nowMs() {
    const block = await this.block('optimistic');
    return Math.floor(Number(BigInt(block.header.timestamp_nanosec) / 1_000_000n));
  }

  async view(account, method, args = {}, finality = 'optimistic') {
    const result = await this.rpc('query', {
      request_type: 'call_function',
      account_id: account,
      method_name: method,
      args_base64: toBase64(utf8(JSON.stringify(args))),
      finality,
    });
    if (result.error) throw new RpcError(`view ${method}: ${result.error}`, { view: result.error });
    return JSON.parse(Buffer.from(result.result).toString('utf8'));
  }

  async account(account) {
    try {
      return await this.rpc('query', { request_type: 'view_account', account_id: account, finality: 'final' });
    } catch (err) {
      if (/UNKNOWN_ACCOUNT/.test(err.message)) return null;
      throw err;
    }
  }

  async nextNonce(key) {
    // One key can sit on two accounts, and each keeps its own nonce.
    const id = `${key.accountId}:${key.publicKey}`;
    const known = this.nonces.get(id);
    if (known !== undefined) {
      this.nonces.set(id, known + 1n);
      return known + 1n;
    }
    const access = await this.rpc('query', { request_type: 'view_access_key', account_id: key.accountId, public_key: key.publicKey, finality: 'optimistic' });
    const nonce = BigInt(access.nonce) + 1n;
    this.nonces.set(id, nonce);
    return nonce;
  }

  /**
   * Signs and sends once. Returns the hash as soon as the transaction is known to the chain. A
   * timeout is resolved by asking about that same hash, never by signing again.
   */
  async send(key, receiverId, actions, { waitUntil = 'INCLUDED' } = {}) {
    const nonce = await this.nextNonce(key);
    const block = await this.block('final');
    const signed = signTransaction({
      signerId: key.accountId,
      key,
      nonce,
      receiverId,
      blockHash: base58Decode(block.header.hash),
      actions,
    });
    let result = null;
    for (let i = 0; i < 12 && result === null; i += 1) {
      try {
        result = await this.rpcOnce(this.urls[i % this.urls.length], 'send_tx', { signed_tx_base64: signed.base64, wait_until: waitUntil });
      } catch (err) {
        const cause = err.data?.cause?.name;
        const data = err.data?.data;
        if (cause === 'INVALID_TRANSACTION' || (typeof data === 'object' && data?.TxExecutionError)) {
          // On a resend this can mean the first send landed, so look before calling it a failure.
          const landed = i > 0 ? await this.txStatus(signed.hash, key.accountId, waitUntil).catch(() => null) : null;
          if (landed) {
            result = landed;
            break;
          }
          this.nonces.delete(`${key.accountId}:${key.publicKey}`);
          throw err;
        }
        // Timed out, or the network failed. The same signed bytes are safe to resend.
        await sleep(1000);
        const seen = await this.txStatus(signed.hash, key.accountId, waitUntil).catch(() => null);
        if (seen) result = seen;
      }
    }
    if (result === null) throw new Error(`transaction ${signed.hash} could not be confirmed`);
    return { hash: signed.hash, result };
  }

  async txStatus(hash, sender, waitUntil = 'NONE') {
    return this.rpcOnce(this.urls[0], 'tx', { tx_hash: hash, sender_account_id: sender, wait_until: waitUntil });
  }

  /** Sends and waits for the whole receipt tree. Not for anything that waits on the signer. */
  async sendAndWait(key, receiverId, actions) {
    return this.send(key, receiverId, actions, { waitUntil: 'EXECUTED_OPTIMISTIC' });
  }

  async sandboxFastForward(deltaHeight) {
    return this.rpc('sandbox_fast_forward', { delta_height: deltaHeight }, { attempts: 1 });
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
  return JSON.parse(Buffer.from(fromBase64(value)).toString('utf8'));
}

export const logsOf = (result) => (result?.receipts_outcome ?? []).flatMap((r) => r.outcome.logs);
