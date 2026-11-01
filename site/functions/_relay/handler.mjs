// /api/relay and /api/funds. The page names a method from a short table, and this builds the transaction itself,
// with its own gas, against the one contract in its environment: never a free-form relay. Two keys with two
// nonce rows and two ceilings, so no amount of general traffic can stop a cancel. Logs nothing of a body, an
// address or a vault. Reads its keys only from the environment, and has no default for any of them.
import { toHex } from '../../../tools/lib/bytes.mjs';
import { vaultIdOfCreateArgs } from '../../lib/intents.mjs';
import { callAction, milliNear } from '../../lib/near-tx.mjs';
import { NearReader } from '../../lib/near-read.mjs';
import { checkPow } from '../../lib/pow.mjs';
import { executeTgas, GENERAL, OWNER, RELAY_METHODS, relayBodyProblem } from '../../lib/relay-table.mjs';
import { hashIp, json, numberOr, readBody, Refusal, refused, workerFetch } from './answer.mjs';
import { fundsHandler, fundsStatus } from './funds.mjs';
import { NearSender, relayKey } from './near-send.mjs';
import { ownerRefusal } from './owner-check.mjs';
import { StateClient, StateDown } from './state-client.mjs';

const DEFAULT_CEILINGS = { general: 600_000, owner: 60_000 };
const DEFAULT_POW_BITS = 18;
const STATUS_CACHE_MS = 10_000;
const INSTANCE_CACHE_MS = 5 * 60_000;

const urlsOf = (text) => String(text ?? '').split(',').map((u) => u.trim()).filter(Boolean);

class Relay {
  constructor(env, { fetchFn = workerFetch, nowFn = () => Date.now() }) {
    Object.assign(this, { env, fetchFn, nowFn });
    this.contract = env.CONTRACT_ID;
    this.account = env.RELAY_ACCOUNT;
    this.urls = urlsOf(env.NEAR_RPC_URLS);
    this.powBits = numberOr(env.POW_BITS, DEFAULT_POW_BITS);
    this.ceilings = {
      general: numberOr(env.CEILING_GENERAL_MICRO, DEFAULT_CEILINGS.general),
      owner: numberOr(env.CEILING_OWNER_MICRO, DEFAULT_CEILINGS.owner),
    };
    this.state = env.UNDO_STATE ? new StateClient(env.UNDO_STATE, env.UNDO_STATE_NAME) : null;
    this.statusCacheMs = numberOr(env.STATUS_CACHE_MS, STATUS_CACHE_MS);
    this.statusCache = null;
    this.instanceCache = null;
  }

  get configured() {
    return Boolean(this.contract && this.account && this.urls.length);
  }

  keyText(bucket) {
    return bucket === OWNER ? this.env.RELAY_OWNER_KEY : this.env.RELAY_GENERAL_KEY;
  }

  /** Needs a key, and for the general key the state store and the salt too. A cancel needs only its key. */
  bucketConfigured(bucket) {
    if (!this.configured || !this.keyText(bucket)) return false;
    return bucket === OWNER || Boolean(this.state && this.env.IP_SALT);
  }

  reader() {
    return new NearReader({ urls: this.urls, timeoutMs: 6000, fetchFn: this.fetchFn, nowFn: this.nowFn });
  }

  sender() {
    return new NearSender({ urls: this.urls, signerId: this.account, receiverId: this.contract, fetchFn: this.fetchFn, nowFn: this.nowFn });
  }

  async instance(reader) {
    const now = this.nowFn();
    if (this.instanceCache && now - this.instanceCache.at < INSTANCE_CACHE_MS) return this.instanceCache.value;
    const value = await reader.view(this.contract, 'instance');
    this.instanceCache = { value, at: now };
    return value;
  }

  originProblem(request) {
    const origin = request.headers.get('origin');
    if (origin === null) return false;
    return origin !== (this.env.SITE_ORIGIN || new URL(request.url).origin);
  }

  // ------------------------------------------------------------ status

  async readStatus() {
    const now = this.nowFn();
    if (this.statusCacheMs && this.statusCache && now - this.statusCache.at < this.statusCacheMs) return this.statusCache.value;
    let value = null;
    if (this.state) {
      try {
        value = await this.state.call('status', { now });
      } catch (err) {
        if (!(err instanceof StateDown)) throw err;
      }
    }
    this.statusCache = { value, at: now };
    return value;
  }

  async status() {
    if (!this.configured) throw new Refusal('relay_not_configured', { message: 'the relay has no contract, account or RPC set' });
    const read = await this.readStatus();
    const owner = { up: true, why: null, degraded: false, resets_at: null };
    const general = { up: true, why: null, resets_at: null };
    if (!this.keyText(OWNER)) Object.assign(owner, { up: false, why: 'relay_not_configured' });
    if (!this.bucketConfigured(GENERAL)) Object.assign(general, { up: false, why: 'relay_not_configured' });
    if (read === null) {
      if (owner.up) owner.degraded = true;
      if (general.up) Object.assign(general, { up: false, why: 'state_store_down' });
    } else {
      if (owner.up && read.spent.owner + RELAY_METHODS.cancel_all_and_rotate.costMicro > this.ceilings.owner) Object.assign(owner, { up: false, why: 'daily_ceiling', resets_at: read.resets_at });
      // Up means a new vault still fits: making one is what a page offers on this. `charge` decides each call.
      if (general.up && read.spent.general + RELAY_METHODS.create_vault.costMicro > this.ceilings.general) Object.assign(general, { up: false, why: 'daily_ceiling', resets_at: read.resets_at });
    }
    return json(200, {
      ok: true,
      relay_account: this.account,
      contract: this.contract,
      pow_bits: this.powBits,
      owner,
      general,
      funds: fundsStatus(this, read),
    });
  }

  // ------------------------------------------------------------ relay

  /** The transaction's actions. Everything that can be refused without a charge is refused here. */
  async actionsFor(method, args, body, reader) {
    const spec = RELAY_METHODS[method];
    if (method === 'create_vault') {
      if (args.guard !== this.account) throw new Refusal('wrong_guard', { message: 'guard must be this relay\'s account' });
      const vault = toHex(vaultIdOfCreateArgs(this.contract, args));
      if (!checkPow(vault, body.pow, this.powBits)) throw new Refusal('pow_bad', { message: 'that proof of work does not solve this vault' });
      return [
        callAction('create_vault', { args }, spec.tgas, milliNear(spec.depositMilli)),
        callAction('heartbeat', { vault }, spec.heartbeatTgas),
      ];
    }
    if (method === 'execute') {
      let request;
      let instance;
      try {
        [request, instance] = await Promise.all([reader.view(this.contract, 'request', args), this.instance(reader)]);
      } catch (err) {
        if (err.verbatim !== undefined) throw new Refusal('bad_request', { message: 'the contract refused that read', verbatim: err.verbatim });
        throw new Refusal('rpc_down', { message: 'could not read the request' });
      }
      if (request === null) throw new Refusal('bad_request', { message: 'no such request' });
      const tgas = executeTgas(request.inputs.length, { signTgas: instance.sign_tgas, callbackTgas: instance.callback_tgas });
      return [callAction('execute', args, tgas)];
    }
    if (spec.key === OWNER) {
      const problem = await ownerRefusal({ method, args, contract: this.contract, read: (name, a) => reader.view(this.contract, name, a) });
      if (problem) throw new Refusal('assertion_refused', { message: problem });
    }
    return [callAction(method, args, spec.tgas)];
  }

  /** Returns { ok, degraded }. A cancel goes out even with the state store down; nothing else does. */
  async charge(method, args, request) {
    const spec = RELAY_METHODS[method];
    const owner = spec.key === OWNER;
    const body = { key: spec.key, method, vault: args.vault ?? null, now: this.nowFn(), ceiling: this.ceilings[spec.key] };
    if (!owner) body.ipHash = await hashIp(this.env.IP_SALT, request.headers.get('cf-connecting-ip'));
    let out;
    try {
      out = await this.state.call('charge', body);
    } catch (err) {
      if (owner) return { degraded: true };
      if (err instanceof StateDown) throw new Refusal('state_store_down', { message: 'the state store is not answering' });
      throw err;
    }
    if (!out.ok) {
      throw new Refusal(out.code, {
        message: out.code === 'daily_ceiling' ? `the ${out.bucket} key is at today's limit` : 'too many calls',
        retryAfterS: out.retry_after_s ?? null,
        bucket: out.bucket ?? null,
        resetsAt: out.resets_at ?? null,
      });
    }
    return { degraded: false };
  }

  async refund(method) {
    const spec = RELAY_METHODS[method];
    await this.state?.call('refund', { bucket: spec.key, cost: spec.costMicro, now: this.nowFn() }).catch(() => {});
  }

  async relay(request) {
    if (this.originProblem(request)) throw new Refusal('bad_origin', { message: 'that origin may not call this relay' });
    const body = await readBody(request);
    const problem = relayBodyProblem(body);
    if (problem) throw new Refusal(problem, { message: problem === 'unknown_method' ? 'that method is not on the list' : problem });
    const { method, args } = body;
    const spec = RELAY_METHODS[method];
    if (!this.bucketConfigured(spec.key)) throw new Refusal('relay_not_configured', { message: 'this key is not set' });
    let key;
    try {
      key = await relayKey(this.keyText(spec.key), this.account);
    } catch {
      throw new Refusal('relay_not_configured', { message: 'this key cannot be read' });
    }
    const reader = this.reader();
    const actions = await this.actionsFor(method, args, body, reader);
    const { degraded } = this.state ? await this.charge(method, args, request) : { degraded: true };
    const sender = this.sender();
    let sent;
    try {
      sent = await this.withNonces(sender, key, actions, spec.key === OWNER && !degraded, degraded);
    } catch (err) {
      if (err instanceof Refusal && err.code !== 'relay_not_configured' && !degraded) await this.refund(method);
      if (err instanceof StateDown) throw new Refusal('state_store_down', { message: 'the state store is not answering' });
      throw err;
    }
    const answer = { ok: true, hash: sent.out.hash, key: spec.key, method };
    if (sent.out.state) answer.state = sent.out.state;
    if (sent.out.retries) answer.retries = sent.out.retries;
    if (degraded || sent.degraded) answer.degraded = true;
    return json(200, answer);
  }

  /** A cancel that loses the state store halfway still goes out, on a nonce read from the chain. */
  async withNonces(sender, key, actions, fallBack, degraded) {
    if (degraded || !this.state) return { out: await sender.send(key, actions, { nonces: null }), degraded: true };
    try {
      return { out: await sender.send(key, actions, { nonces: this.state }), degraded: false };
    } catch (err) {
      if (!(fallBack && err instanceof StateDown)) throw err;
    }
    return { out: await sender.send(key, actions, { nonces: null }), degraded: true };
  }

  async route(request) {
    const { pathname } = new URL(request.url);
    if (pathname === '/api/funds') {
      if (request.method !== 'POST') throw new Refusal('bad_request', { message: 'POST only', status: 405 });
      return fundsHandler(this, request);
    }
    if (pathname !== '/api/relay') throw new Refusal('bad_request', { message: 'no such path', status: 404 });
    if (request.method === 'GET') return this.status();
    if (request.method !== 'POST') throw new Refusal('bad_request', { message: 'GET or POST only', status: 405 });
    return this.relay(request);
  }

  async handle(request) {
    try {
      return await this.route(request);
    } catch (err) {
      if (err instanceof Refusal) return refused(err);
      // A failure of this code, and nothing about it goes out: an error here could carry a body or a key.
      return refused(new Refusal('relay_error', { message: 'the relay failed' }));
    }
  }
}

const relays = new WeakMap();

/** The handler for one environment. `options` are for tests. */
export function makeRelay(env, options = {}) {
  let relay = relays.get(env);
  if (!relay) {
    relay = new Relay(env, options);
    relays.set(env, relay);
  }
  return (request) => relay.handle(request);
}

