// /api/relay and /api/funds. The page names a method from a short table, and this builds the transaction itself,
// with its own gas, against the one contract in its environment: never a free-form relay. Two keys with two
// nonce rows and two ceilings, so no amount of general traffic can stop a cancel. Logs nothing of a body, an
// address or a vault. Reads its keys only from the environment, and has no default for any of them.
import { fromHex, toHex } from '../../../tools/lib/bytes.mjs';
import { argBytes, createDigest, intentDigest, SPEND_TAG } from '../../../tools/lib/intent.mjs';
import { vaultIdOfCreateArgs } from '../../lib/intents.mjs';
import { callAction, milliNear } from '../../lib/near-tx.mjs';
import { NearReader } from '../../lib/near-read.mjs';
import { checkPow } from '../../lib/pow.mjs';
import { CEILING_OWNER_DEFAULT_MICRO, CREATE_SHARE, executeTgas, GENERAL, OWNER, RELAY_METHODS, relayBodyProblem } from '../../lib/relay-table.mjs';
import { ed25519Verifies, hashIp, json, numberOr, readBody, Refusal, refused, workerFetch } from './answer.mjs';
import { fundsHandler, fundsStatus } from './funds.mjs';
import { NearSender, relayKey } from './near-send.mjs';
import { ownerRefusal } from './owner-check.mjs';
import { StateClient, StateDown } from './state-client.mjs';

const DEFAULT_CEILINGS = { general: 600_000, owner: CEILING_OWNER_DEFAULT_MICRO };
const DEFAULT_POW_BITS = 18;
const STATUS_CACHE_MS = 10_000;
const INSTANCE_CACHE_MS = 5 * 60_000;
const KEY_CACHE_MS = 30_000;
// A status read must stay well inside the page's 8 s wait: a dead RPC here must not read as a dead relay.
const KEY_READ_MS = 1500;
// Under this a send can't be paid for: a 30 Tgas send holds about 0.031 NEAR until its refund lands.
const KEY_FLOOR_YOCTO = 50_000_000_000_000_000_000_000n;
const STORAGE_YOCTO_PER_BYTE = 10_000_000_000_000_000_000n;
const CANNOT_PAY = /NotEnoughAllowance|NotEnoughBalance|LackBalanceForState|AccessKeyNotFound|InvalidAccessKeyError/;
// The relay's clock against the chain's. The contract decides at the edge.
const EXPIRY_GRACE_MS = 60_000;
// A page's zero may land a moment before this node's block says so. The contract decides that too.
const UNLOCK_SLACK_MS = 5000;

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
    this.keyCacheMs = numberOr(env.KEY_CACHE_MS, KEY_CACHE_MS);
    this.keyCache = null;
    this.localMinute = null;
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

  sender(options = {}) {
    return new NearSender({ urls: this.urls, signerId: this.account, receiverId: this.contract, fetchFn: this.fetchFn, nowFn: this.nowFn, ...options });
  }

  /** What a vault may spend of the general ceiling. The rest is kept for calls on vaults that already exist. */
  createCeiling() {
    return Math.floor(this.ceilings.general * CREATE_SHARE);
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

  /** Null, or why the owner key cannot pay for a send. A read that fails claims nothing. */
  async readOwnerKey() {
    let key;
    try {
      key = await relayKey(this.keyText(OWNER), this.account);
    } catch {
      return 'relay_not_configured';
    }
    const sender = this.sender({ callTimeoutMs: KEY_READ_MS });
    const [access, account] = await Promise.all([
      sender.ask('query', { request_type: 'view_access_key', account_id: this.account, public_key: key.publicKey, finality: 'optimistic' }),
      sender.ask('query', { request_type: 'view_account', account_id: this.account, finality: 'optimistic' }),
    ]);
    if (access.nodeError || access.error || account.nodeError || account.error) return 'owner_key_missing';
    const allowance = access.permission?.FunctionCall?.allowance;
    if (allowance !== undefined && allowance !== null && BigInt(allowance) < KEY_FLOOR_YOCTO) return 'owner_key_low';
    if (account.amount !== undefined && BigInt(account.amount) - BigInt(account.storage_usage ?? 0) * STORAGE_YOCTO_PER_BYTE < KEY_FLOOR_YOCTO) return 'owner_key_low';
    return null;
  }

  async ownerKeyProblem() {
    const now = this.nowFn();
    if (this.keyCacheMs && this.keyCache && now - this.keyCache.at < this.keyCacheMs) return this.keyCache.why;
    let why = this.keyCache?.why ?? null;
    let timer;
    try {
      const out = await Promise.race([
        this.readOwnerKey(),
        new Promise((resolve) => { timer = setTimeout(() => resolve(undefined), KEY_READ_MS + 500); }),
      ]);
      if (out !== undefined) why = out;
    } catch {
      // Nothing was learned, so nothing changes.
    } finally {
      clearTimeout(timer);
    }
    this.keyCache = { why, at: now };
    return why;
  }

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
    else {
      const problem = await this.ownerKeyProblem();
      if (problem) Object.assign(owner, { up: false, why: problem });
    }
    if (!this.bucketConfigured(GENERAL)) Object.assign(general, { up: false, why: 'relay_not_configured' });
    if (read === null) {
      if (owner.up) owner.degraded = true;
      if (general.up) Object.assign(general, { up: false, why: 'state_store_down' });
    } else {
      if (owner.up && read.spent.owner + RELAY_METHODS.cancel_all_and_rotate.costMicro > this.ceilings.owner) Object.assign(owner, { up: false, why: 'daily_ceiling', resets_at: read.resets_at });
      // Up means a new vault still fits: making one is what a page offers on this. `charge` decides each call.
      if (general.up && read.spent.general + RELAY_METHODS.create_vault.costMicro > this.createCeiling()) {
        // A vault no longer fits, but one proposal and its execute may. A page mid-film must not say it can't send.
        const callsFit = read.spent.general + RELAY_METHODS.propose_btc.costMicro + RELAY_METHODS.execute.costMicro <= this.ceilings.general;
        Object.assign(general, { up: false, why: 'daily_ceiling', resets_at: read.resets_at }, callsFit ? { calls_fit: true } : null);
      }
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

  /**
   * Everything that can be refused without a read of the chain or a charge. A proof of work and a signature the
   * contract would refuse cost a visitor something to make, and nothing here costs the relay more than a read.
   */
  async refuseBeforeCharge(method, args, body, reader) {
    const spec = RELAY_METHODS[method];
    if (method === 'create_vault') {
      if (args.guard !== this.account) throw new Refusal('wrong_guard', { message: 'guard must be this relay\'s account' });
      const vault = toHex(vaultIdOfCreateArgs(this.contract, args));
      if (!checkPow(vault, body.pow, this.powBits)) throw new Refusal('pow_bad', { message: 'that proof of work does not solve this vault' });
      if (args.expires_at + EXPIRY_GRACE_MS < this.nowFn()) throw new Refusal('would_refuse', { message: 'that intent has expired' });
      const instance = await this.read(() => this.instance(reader));
      const digest = createDigest({ contract: this.contract, vault: fromHex(vault), km: fromHex(args.k_m), rpIdHash: fromHex(args.passkey.rp_id_hash), guard: args.guard, policy: instance.policy, expiresAt: args.expires_at });
      if (!(await ed25519Verifies(fromHex(args.k_s), fromHex(args.pop_s), digest))) throw new Refusal('would_refuse', { message: 'that creation is not signed by its spend key' });
    }
    if (spec.key === OWNER) {
      const problem = await ownerRefusal({ method, args, contract: this.contract, now: this.nowFn(), read: (name, a) => reader.view(this.contract, name, a) });
      if (problem) throw new Refusal('assertion_refused', { message: problem });
    }
  }

  /** A view, with a refusal in the contract's own words, or rpc_down. */
  async read(fn) {
    try {
      return await fn();
    } catch (err) {
      if (err instanceof Refusal) throw err;
      if (err.verbatim !== undefined) throw new Refusal('would_refuse', { message: 'the contract refused that read', verbatim: err.verbatim });
      throw new Refusal('rpc_down', { message: 'could not read the contract' });
    }
  }

  /** After the charge, so a flood from one address reaches the RPC only as often as its limit. Returns what to send. */
  async chainChecks(method, args, reader, charged) {
    const spec = RELAY_METHODS[method];
    const view = (name, a) => this.read(() => reader.view(this.contract, name, a));
    switch (method) {
      case 'create_vault': {
        const vault = toHex(vaultIdOfCreateArgs(this.contract, args));
        if ((await view('vault', { vault })) !== null) throw new Refusal('would_refuse', { message: 'that vault exists' });
        return [
          callAction('create_vault', { args }, spec.tgas, milliNear(spec.depositMilli)),
          callAction('heartbeat', { vault }, spec.heartbeatTgas),
        ];
      }
      case 'activate': {
        const row = await view('vault', { vault: args.vault });
        if (row === null) throw new Refusal('would_refuse', { message: 'no such vault' });
        if (row.active) throw new Refusal('would_refuse', { message: 'that vault is already active' });
        break;
      }
      case 'propose_btc': await this.proposeChecks(args, view); break;
      case 'execute': return this.executeChecks(args, view, reader, charged);
      default:
    }
    return [callAction(method, args, spec.tgas)];
  }

  async proposeChecks(args, view) {
    const row = await view('vault', { vault: args.vault });
    if (row === null) throw new Refusal('would_refuse', { message: 'no such vault' });
    if (!row.active) throw new Refusal('would_refuse', { message: 'that vault is not active yet' });
    if (args.nonce < row.spend_nonce) throw new Refusal('would_refuse', { message: 'that spend nonce was already used' });
    if (args.expires_at + EXPIRY_GRACE_MS < this.nowFn()) throw new Refusal('would_refuse', { message: 'that intent has expired' });
    const digest = intentDigest({
      tag: SPEND_TAG, contract: this.contract, vault: fromHex(args.vault), method: 'propose_btc',
      args: argBytes.propose_btc({ inputs: args.inputs, to: fromHex(args.to), amount: args.amount, change: args.change, memo: args.memo }),
      expiresAt: args.expires_at, nonce: args.nonce,
    });
    if (!(await ed25519Verifies(fromHex(row.k_s), fromHex(args.spend_sig), digest))) throw new Refusal('would_refuse', { message: 'that proposal is not signed by this vault\'s spend key' });
    await view('check_propose', { vault: args.vault, inputs: args.inputs, to: args.to, amount: args.amount, change: args.change });
  }

  /** Reads its input count, which sets the gas and what the call costs, and refuses what cannot run yet or again. */
  async executeChecks(args, view, reader, charged) {
    const [request, vault, instance, block] = await Promise.all([
      view('request', args),
      view('vault', { vault: args.vault }),
      this.read(() => this.instance(reader)),
      this.read(() => reader.blockTime()),
    ]);
    if (request === null) throw new Refusal('bad_request', { message: 'no such request' });
    if (vault === null) throw new Refusal('would_refuse', { message: 'no such vault' });
    if (request.status === 'Signed') throw new Refusal('would_refuse', { message: 'that request is already signed' });
    if (request.status === 'Pending') {
      if (request.epoch !== vault.spend_epoch) throw new Refusal('would_refuse', { message: 'that request was cancelled' });
      if (block.blockMs > request.expires_at) throw new Refusal('would_refuse', { message: 'that request has expired' });
      if (block.blockMs + UNLOCK_SLACK_MS < request.unlock) throw new Refusal('would_refuse', { message: 'that request has not unlocked', retryAfterS: Math.ceil((request.unlock - block.blockMs) / 1000) });
    }
    await this.chargeInputs(args, request.inputs.length, charged);
    const tgas = executeTgas(request.inputs.length, { signTgas: instance.sign_tgas, callbackTgas: instance.callback_tgas });
    return [callAction('execute', args, tgas)];
  }

  /** Sixteen inputs burn sixteen times the gas. The first was charged already. */
  async chargeInputs(args, inputs, charged) {
    if (inputs <= 1) return;
    const cost = RELAY_METHODS.execute.costMicro * (inputs - 1);
    let out;
    try {
      out = await this.state.call('addCost', { key: GENERAL, cost, now: this.nowFn(), ceiling: this.ceilings.general });
    } catch {
      throw new Refusal('state_store_down', { message: 'the state store is not answering' });
    }
    if (!out.ok) throw new Refusal(out.code, { message: `the ${GENERAL} key is at today's limit`, bucket: out.bucket ?? null, resetsAt: out.resets_at ?? null });
    charged.units = inputs;
  }

  chargeWithoutState(args, spec) {
    if (spec.key === OWNER) this.limitWithoutState(args.vault, spec);
    return { degraded: true };
  }

  /** Returns { ok, degraded }. A cancel goes out even with the state store down; nothing else does. */
  async charge(method, args, request) {
    const spec = RELAY_METHODS[method];
    const owner = spec.key === OWNER;
    const ceiling = method === 'create_vault' ? this.createCeiling() : this.ceilings[spec.key];
    const body = { key: spec.key, method, vault: args.vault ?? null, now: this.nowFn(), ceiling };
    if (!owner) body.ipHash = await hashIp(this.env.IP_SALT, request.headers.get('cf-connecting-ip'));
    let out;
    try {
      out = await this.state.call('charge', body);
    } catch (err) {
      if (owner) {
        this.limitWithoutState(args.vault, spec);
        return { degraded: true };
      }
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

  /** With the state store down only this isolate can count, and that is still better than no limit on the owner key. */
  limitWithoutState(vault, spec) {
    const minute = Math.floor(this.nowFn() / 60_000);
    if (this.localMinute !== minute) {
      this.localMinute = minute;
      this.localCounts = new Map();
    }
    const seen = (this.localCounts.get(vault) ?? 0) + 1;
    this.localCounts.set(vault, seen);
    if (seen > spec.perVaultMinute) throw new Refusal('rate_limited', { message: 'too many calls', retryAfterS: 60 });
  }

  async refund(method, units = 1) {
    const spec = RELAY_METHODS[method];
    await this.state?.call('refund', { bucket: spec.key, cost: spec.costMicro * units, now: this.nowFn() }).catch(() => {});
  }

  /** A heartbeat makes a vault read guard online, so it answers only to the one holding this binding. */
  operatorAsked(request) {
    const token = this.env.BEAT_TOKEN;
    const offered = request.headers.get('x-undo-beat');
    if (!token || !offered || token.length !== offered.length) return false;
    let difference = 0;
    for (let i = 0; i < token.length; i += 1) difference |= token.charCodeAt(i) ^ offered.charCodeAt(i);
    return difference === 0;
  }

  async relay(request) {
    if (this.originProblem(request)) throw new Refusal('bad_origin', { message: 'that origin may not call this relay' });
    const body = await readBody(request);
    const problem = relayBodyProblem(body);
    if (problem) throw new Refusal(problem, { message: problem === 'unknown_method' ? 'that method is not on the list' : problem });
    const { method, args } = body;
    const spec = RELAY_METHODS[method];
    if (spec.operatorOnly && !this.operatorAsked(request)) throw new Refusal('unknown_method', { message: 'that method is not on the list' });
    if (!this.bucketConfigured(spec.key)) throw new Refusal('relay_not_configured', { message: 'this key is not set' });
    let key;
    try {
      key = await relayKey(this.keyText(spec.key), this.account);
    } catch {
      throw new Refusal('relay_not_configured', { message: 'this key cannot be read' });
    }
    const reader = this.reader();
    await this.refuseBeforeCharge(method, args, body, reader);
    const { degraded } = this.state ? await this.charge(method, args, request) : this.chargeWithoutState(args, spec);
    const charged = { units: 1 };
    let actions;
    try {
      actions = spec.key === OWNER ? [callAction(method, args, spec.tgas)] : await this.chainChecks(method, args, reader, charged);
    } catch (err) {
      await this.refund(method, charged.units);
      throw err;
    }
    const sender = this.sender();
    let sent;
    try {
      sent = await this.withNonces(sender, key, actions, spec.key === OWNER && !degraded, degraded);
    } catch (err) {
      if (err instanceof Refusal && err.code !== 'relay_not_configured' && !degraded) await this.refund(method, charged.units);
      if (spec.key === OWNER && err instanceof Refusal && err.code === 'tx_refused' && CANNOT_PAY.test(err.verbatim ?? '')) this.keyCache = { why: 'owner_key_low', at: this.nowFn() };
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

