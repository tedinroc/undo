// The watcher's parts, kept apart from the command line so the tests drive the same code. It reads one vault over
// public NEAR RPC and pushes one phone alert per new Pending request. It holds no key, signs nothing and sends no
// transaction. The only thing it writes outside this machine is the alert, to the ntfy server in its config.
//
// What an alert says is what the contract already shows anyone: the amount, the destination and the unlock time.
import { closeSync, existsSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, statSync, writeSync } from 'node:fs';
import { homedir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { segwitAddress, sha256d } from './btc.mjs';
import { base58Encode, concat, fromHex, toHex, utf8 } from './bytes.mjs';
import { randomBytes, sha256 } from './crypto.mjs';

export const CONFIG_FORMAT = 'undo-watch-v1';
export const STATE_FORMAT = 'undo-watch-state-v1';

// The same fallback list as site/config/testnet.json, in the same order. tools/test/watch.test.mjs compares them
// whenever that file is in the tree.
export const TESTNET_RPC = Object.freeze(['https://test.rpc.fastnear.com', 'https://near-testnet.drpc.org', 'https://rpc.testnet.near.org']);
export const DEFAULT_PAGE_ORIGIN = 'https://undo-btc.pages.dev';
export const DEFAULT_NTFY = 'https://ntfy.sh';

// Every label a line prints comes from the network, so a local run cannot pass for a live one. The words match
// site/lib/config.mjs.
export const NETWORKS = Object.freeze({
  testnet: Object.freeze({ label: '[live-testnet]', chip: 'signet test coins', near: 'NEAR testnet', bitcoin: 'Mutinynet', btcNetwork: 'mutinynet', chainId: 'testnet', minPollMs: 1000 }),
  local: Object.freeze({ label: '[mock-signer]', chip: 'local test coins, mock signer', near: 'local NEAR sandbox', bitcoin: 'local regtest', btcNetwork: 'regtest', chainId: null, minPollMs: 100 }),
});

export class ConfigError extends Error {}

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);
const TOPIC = /^[A-Za-z0-9_-]{22,64}$/;
const VAULT = /^[0-9a-f]{64}$/;
const ACCOUNT = /^(?=.{2,64}$)(([a-z\d]+[-_])*[a-z\d]+\.)*([a-z\d]+[-_])*[a-z\d]+$/;
const TOPIC_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

/**
 * 22 characters from 62, about 131 bits. On ntfy.sh anyone who knows a topic can read it and post to it, so the
 * topic is the password. Rejection sampling keeps every character equally likely.
 */
export function makeTopic(random = randomBytes) {
  let out = '';
  while (out.length < 22) {
    for (const byte of random(32)) {
      if (byte < 248 && out.length < 22) out += TOPIC_ALPHABET[byte % 62];
    }
  }
  return out;
}

/** Short and one-way, so a phone-test record can name its topic without holding it. */
export const topicTag = (topic) => toHex(sha256(utf8(`undo-watch-topic:${topic}`))).slice(0, 16);

function parseUrl(text, field) {
  if (typeof text !== 'string') throw new ConfigError(`config: ${field} is missing`);
  let url;
  try {
    url = new URL(text);
  } catch {
    throw new ConfigError(`config: ${field} is not a URL`);
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') throw new ConfigError(`config: ${field} is not http or https`);
  if (url.username || url.password) throw new ConfigError(`config: ${field} must not carry a user or password`);
  return url;
}

function checkHost(text, field, network) {
  const url = parseUrl(text, field);
  const local = LOCAL_HOSTS.has(url.hostname);
  if (network === 'local' && !local) throw new ConfigError(`config: ${field} leaves this machine in local mode`);
  if (network !== 'local' && (local || url.protocol !== 'https:')) throw new ConfigError(`config: ${field} must be a public https host on ${network}`);
  return url;
}

function checkOrigin(text, field, network) {
  const url = checkHost(text, field, network);
  if ((url.pathname !== '/' && url.pathname !== '') || url.search || url.hash || text.endsWith('/')) {
    throw new ConfigError(`config: ${field} must be an origin alone, like https://example.com`);
  }
  return url.origin;
}

/** A vault id, or a phone-page link that names one in its fragment. */
export function vaultFrom(text) {
  if (typeof text !== 'string') return null;
  const trimmed = text.trim();
  if (VAULT.test(trimmed)) return trimmed;
  const at = trimmed.indexOf('#');
  if (at < 0) return null;
  const v = new URLSearchParams(trimmed.slice(at + 1)).get('v');
  return v && VAULT.test(v) ? v : null;
}

/** Returns a frozen copy, or throws naming the first field it refuses. */
export function checkWatchConfig(raw) {
  if (!raw || typeof raw !== 'object') throw new ConfigError('config: missing');
  if (raw.format !== CONFIG_FORMAT) throw new ConfigError(`config: format must be ${CONFIG_FORMAT}`);
  const { network } = raw;
  if (!Object.hasOwn(NETWORKS, network)) throw new ConfigError('config: network must be testnet or local. There is no mainnet watcher');
  const net = NETWORKS[network];
  if (typeof raw.contract !== 'string' || !ACCOUNT.test(raw.contract)) throw new ConfigError('config: contract is not a NEAR account id');
  if (network === 'testnet' && !raw.contract.endsWith('.testnet')) throw new ConfigError('config: a testnet contract ends in .testnet');
  if (raw.vault !== null && raw.vault !== undefined && !VAULT.test(raw.vault)) throw new ConfigError('config: vault must be 64 lowercase hex characters, or null');
  if (!Array.isArray(raw.rpc) || raw.rpc.length === 0) throw new ConfigError('config: rpc needs at least one URL');
  raw.rpc.forEach((u, i) => checkHost(u, `rpc[${i}]`, network));
  const pageOrigin = checkOrigin(raw.page_origin, 'page_origin', network);
  const ntfyServer = checkOrigin(raw.ntfy_server, 'ntfy_server', network);
  if (typeof raw.ntfy_topic !== 'string' || !TOPIC.test(raw.ntfy_topic)) throw new ConfigError('config: ntfy_topic must be 22 to 64 characters of A-Z a-z 0-9 _ -');
  const priority = raw.priority ?? 5;
  if (!Number.isInteger(priority) || priority < 1 || priority > 5) throw new ConfigError('config: priority must be 1 to 5');
  const pollMs = raw.poll_ms ?? 2000;
  if (!Number.isInteger(pollMs) || pollMs < net.minPollMs || pollMs > 60_000) throw new ConfigError(`config: poll_ms must be ${net.minPollMs} to 60000 on ${network}`);
  return Object.freeze({
    format: CONFIG_FORMAT,
    network,
    contract: raw.contract,
    vault: raw.vault ?? null,
    rpc: Object.freeze([...raw.rpc]),
    page_origin: pageOrigin,
    ntfy_server: ntfyServer,
    ntfy_topic: raw.ntfy_topic,
    priority,
    poll_ms: pollMs,
    labels: net,
  });
}

/**
 * A path as the watcher prints it: the default folder as ~/.undo-watch/NAME, anything else by its file name alone.
 * Output may be filmed or pasted, so it never carries a folder or a user name.
 */
export function shownPath(path) {
  const p = resolve(path);
  return dirname(p) === join(homedir(), '.undo-watch') ? `~/.undo-watch/${basename(p)}` : basename(p);
}

/** Where the config may live: never inside a git work tree, so a topic cannot be committed by accident. */
export function gitTreeAbove(path) {
  let dir = resolve(dirname(path));
  for (;;) {
    if (existsSync(join(dir, '.git'))) return dir;
    const up = dirname(dir);
    if (up === dir) return null;
    dir = up;
  }
}

/** Writes a file that holds the topic: mode 600, in a folder of mode 700, and never over an existing one unless asked. */
export function writePrivateFile(path, text, { force = false } = {}) {
  if (!force && existsSync(path)) throw new ConfigError(`config: ${shownPath(path)} exists. Pass --force to replace it`);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.tmp-${process.pid}`;
  const fd = openSync(tmp, 'wx', 0o600);
  try {
    writeSync(fd, text);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, path);
}

export function loadWatchConfig(path) {
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch (err) {
    throw new ConfigError(err.code === 'ENOENT' ? `config: no file ${shownPath(path)} there. Run: node tools/watch.mjs init` : `config: ${err.code}`);
  }
  let raw;
  try {
    raw = JSON.parse(text);
  } catch {
    throw new ConfigError('config: not JSON');
  }
  const mode = statSync(path).mode & 0o077;
  if (mode !== 0) throw new ConfigError(`config: ${shownPath(path)} can be read by other users. Run chmod 600 on it`);
  return checkWatchConfig(raw);
}

// ---------------------------------------------------------------- reading NEAR

export class RpcDown extends Error {
  constructor(method, tried) {
    super(`no NEAR RPC answered ${method}`);
    this.tried = tried;
  }
}

/** The contract refused a view, in the node's own words. Every node would say the same, so no retry. */
export class ViewRefused extends Error {
  constructor(method, verbatim) {
    super(`view ${method} refused: ${String(verbatim).slice(0, 300)}`);
    this.verbatim = verbatim;
  }
}

const RETRY_CAUSES = new Set(['TIMEOUT_ERROR', 'NO_SYNCED_BLOCKS', 'UNKNOWN_BLOCK', 'INTERNAL_ERROR']);

/** Public RPC, read only, with the fallback list: each URL once per call, starting from the last that answered. */
export class RpcPool {
  constructor(urls, { timeoutMs = 5000, fetchFn = (...a) => globalThis.fetch(...a) } = {}) {
    if (!Array.isArray(urls) || urls.length === 0) throw new Error('RpcPool needs at least one URL');
    Object.assign(this, { urls, timeoutMs, fetchFn });
    this.first = 0;
    this.id = 0;
    this.lastHost = null;
  }

  async call(method, params) {
    const tried = [];
    for (let i = 0; i < this.urls.length; i += 1) {
      const at = (this.first + i) % this.urls.length;
      const url = this.urls[at];
      let status;
      let text;
      try {
        const res = await this.fetchFn(url, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', id: (this.id += 1), method, params }),
          redirect: 'error',
          signal: AbortSignal.timeout(this.timeoutMs),
        });
        status = res.status;
        text = await res.text();
      } catch (err) {
        tried.push({ host: new URL(url).host, error: err.name });
        continue;
      }
      let data = null;
      try {
        data = JSON.parse(text);
      } catch {
        // A proxy's page or a rate limiter's. It said nothing about the chain.
      }
      if (!data || status === 429 || status >= 500 || status === 403 || status === 408 || status === 410) {
        tried.push({ host: new URL(url).host, status });
        continue;
      }
      if (data.error) {
        const cause = data.error.cause?.name;
        if (/rate limit/i.test(text) || data.error.code === -429 || RETRY_CAUSES.has(cause)) {
          tried.push({ host: new URL(url).host, status, cause: cause ?? 'rate limit' });
          continue;
        }
        this.first = at;
        this.lastHost = new URL(url).host;
        return { error: data.error };
      }
      this.first = at;
      this.lastHost = new URL(url).host;
      return { result: data.result };
    }
    throw new RpcDown(method, tried);
  }
}

/** The four reads the watcher makes. `clock` says what the chain's clock read and when this machine heard it. */
export function contractReads(pool, contract, { nowFn = () => Date.now() } = {}) {
  const view = async (method, args) => {
    const { result, error } = await pool.call('query', {
      request_type: 'call_function',
      account_id: contract,
      method_name: method,
      args_base64: Buffer.from(JSON.stringify(args)).toString('base64'),
      finality: 'optimistic',
    });
    if (error) throw new ViewRefused(method, error.data ?? error.cause?.info?.vm_error ?? JSON.stringify(error));
    if (result.error) throw new ViewRefused(method, result.error);
    return { value: JSON.parse(Buffer.from(result.result).toString('utf8')), height: result.block_height };
  };
  return {
    vault: async (vault) => view('vault', { vault }),
    request: async (vault, request) => view('request', { vault, request }),
    clock: async () => {
      const { result, error } = await pool.call('block', { finality: 'optimistic' });
      const heardAt = nowFn();
      if (error) throw new ViewRefused('block', JSON.stringify(error));
      return { blockMs: Number(BigInt(result.header.timestamp_nanosec) / 1_000_000n), height: result.header.height, heardAt };
    },
    chainId: async () => {
      const { result, error } = await pool.call('status', []);
      if (error) throw new ViewRefused('status', JSON.stringify(error));
      return result.chain_id;
    },
  };
}

/** The chain's own clock: the last block's time plus the time since it was heard. Liveness is decided on this alone. */
export const chainClockOf = (sample, now) => sample.blockMs + (now - sample.heardAt);

/** How far this machine's clock may sit from the chain's before it is taken to be wrong: a lagging node, not a bad clock. */
export const CLOCK_TOLERANCE_MS = 30_000;

/**
 * What an alert counts down from. Within CLOCK_TOLERANCE_MS, the later of this machine's clock and the chain's, which
 * gives the shorter "unlocks in", the safe side when a node lags a block. Past it, this machine's clock is wrong and
 * the chain's is used, so a fast clock neither reads "unlocked" early nor, through liveness, hides a live request.
 */
export const chainNowOf = (sample, now) => {
  const chain = chainClockOf(sample, now);
  return Math.abs(now - chain) <= CLOCK_TOLERANCE_MS ? Math.max(now, chain) : chain;
};

// ---------------------------------------------------------------- what an alert says

function base58Check(version, hash) {
  const body = concat(Uint8Array.of(version), hash);
  return base58Encode(concat(body, sha256d(body).slice(0, 4)));
}

const LEGACY = { mutinynet: { p2pkh: 0x6f, p2sh: 0xc4 }, regtest: { p2pkh: 0x6f, p2sh: 0xc4 } };

/** The address an output script pays, or null for a script no address names. */
export function addressOf(btcNetwork, spkHex) {
  let s;
  try {
    s = fromHex(spkHex);
  } catch {
    return null;
  }
  if (s.length === 22 && s[0] === 0x00 && s[1] === 0x14) return segwitAddress(btcNetwork, 0, s.slice(2));
  if (s.length === 34 && s[0] === 0x00 && s[1] === 0x20) return segwitAddress(btcNetwork, 0, s.slice(2));
  if (s.length === 34 && s[0] === 0x51 && s[1] === 0x20) return segwitAddress(btcNetwork, 1, s.slice(2));
  if (s.length === 25 && s[0] === 0x76 && s[1] === 0xa9 && s[2] === 0x14 && s[23] === 0x88 && s[24] === 0xac) return base58Check(LEGACY[btcNetwork].p2pkh, s.slice(3, 23));
  if (s.length === 23 && s[0] === 0xa9 && s[1] === 0x14 && s[22] === 0x87) return base58Check(LEGACY[btcNetwork].p2sh, s.slice(2, 22));
  return null;
}

export const PREFIX_CHARS = 14;

export function destinationText(btcNetwork, request, vault) {
  if (request.kind === 'Reclaim' || request.to === vault.script_pubkey) return 'back to this vault';
  const address = addressOf(btcNetwork, request.to);
  if (!address) return `script ${request.to.slice(0, PREFIX_CHARS)}…`;
  return `to ${address.slice(0, PREFIX_CHARS)}…`;
}

/** What leaves the vault, the way the phone page counts it: every coin when there is no change, else the amount. */
export function amountSats(request) {
  if (request.change === null || request.change === undefined) return request.inputs.reduce((sum, c) => sum + c.value, 0);
  return request.amount;
}

export const satsText = (n) => `${n.toLocaleString('en-US')} sats`;

/** `M:SS`, or `H:MM:SS` past an hour. Rounded up, so it never reads a second shorter than the contract's wait. */
export function clockText(ms) {
  const total = Math.max(0, Math.ceil(ms / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = String(total % 60).padStart(2, '0');
  return h > 0 ? `${h}:${String(m).padStart(2, '0')}:${s}` : `${m}:${s}`;
}

export function unlockText(unlockMs, chainNowMs) {
  const left = unlockMs - chainNowMs;
  return left > 0 ? `unlocks in ${clockText(left)}` : 'unlocked: anyone can execute it now, cancel first';
}

/** The phone page, with the vault and the request in the fragment, which a browser never sends to a server. */
export function phoneLink(pageOrigin, vault, request = null) {
  const fragment = request === null ? `#v=${vault}` : `#v=${vault}&r=${request}`;
  const link = `${pageOrigin}/p/${fragment}`;
  if (link.includes('?')) throw new Error('a phone link carries no query string');
  return link;
}

export const ALERT_TITLE = 'Undo for Bitcoin: a spend is waiting';

/** Title, body, tap target. `repeat` marks a resend after a restart that may have sent it once already. */
export function buildAlert({ config, vault, request, chainNowMs, repeat = false }) {
  const net = config.labels;
  const link = phoneLink(config.page_origin, vault.id, request.id);
  const first = `${satsText(amountSats(request))} ${destinationText(net.btcNetwork, request, vault)} ${unlockText(request.unlock, chainNowMs)}`;
  const message = `${first}\n${net.chip}. Not you? Tap to cancel.\n${link}`;
  return {
    title: repeat ? `${ALERT_TITLE} (may repeat)` : ALERT_TITLE,
    message,
    click: link,
    priority: config.priority,
    actions: [{ action: 'view', label: 'Open the phone page', url: link, clear: true }],
  };
}

export function testAlert({ config, index, count }) {
  const link = config.vault ? phoneLink(config.page_origin, config.vault) : `${config.page_origin}/p/`;
  return {
    title: `Undo for Bitcoin: TEST ${index}/${count}`,
    message: `TEST ${index}/${count}: 2,000 sats to tb1q… unlocks in 5:00\nNothing is waiting. This checks delivery only.\n${link}`,
    click: link,
    priority: config.priority,
    actions: [],
  };
}

/** Whether a request still needs its owner: Pending, this epoch, not expired. Everything else is said and skipped. */
export function liveness(request, vault, chainNowMs) {
  if (request.status !== 'Pending') return `status ${request.status}`;
  if (request.epoch !== vault.spend_epoch) return 'cancelled by a rotation';
  if (chainNowMs > request.expires_at) return 'expired';
  return null;
}

// ---------------------------------------------------------------- pushing

export class PushFailed extends Error {
  constructor(message, { status = null, retry = true } = {}) {
    super(message);
    this.status = status;
    this.retry = retry;
  }
}

/** One POST of ntfy's JSON form. The topic goes in the body, so it is in no URL and no log line. */
export function ntfyPublisher({ server, topic, fetchFn = (...a) => globalThis.fetch(...a), timeoutMs = 10_000 }) {
  return async (alert) => {
    let res;
    try {
      res = await fetchFn(`${server}/`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ topic, title: alert.title, message: alert.message, priority: alert.priority, click: alert.click, actions: alert.actions }),
        redirect: 'error',
        signal: AbortSignal.timeout(timeoutMs),
      });
    } catch (err) {
      throw new PushFailed(`ntfy did not answer: ${err.name}`);
    }
    const text = await res.text();
    if (!res.ok) {
      const retry = res.status === 429 || res.status >= 500 || res.status === 408;
      throw new PushFailed(`ntfy answered HTTP ${res.status}`, { status: res.status, retry });
    }
    let body = null;
    try {
      body = JSON.parse(text);
    } catch {
      // A 200 that is not ntfy's JSON still went somewhere. Say so and keep the time.
    }
    return { id: typeof body?.id === 'string' ? body.id : null, serverTime: typeof body?.time === 'number' ? body.time : null };
  };
}

// ---------------------------------------------------------------- state across restarts

export class StateStore {
  constructor(path, { contract, vault, network }) {
    Object.assign(this, { path, contract, vault, network });
    this.requests = {};
    if (existsSync(path)) {
      const raw = JSON.parse(readFileSync(path, 'utf8'));
      if (raw.format !== STATE_FORMAT) throw new Error(`state: ${shownPath(path)} is not a watcher state file`);
      if (raw.contract !== contract || raw.vault !== vault || raw.network !== network) throw new Error(`state: ${shownPath(path)} is for another vault or contract`);
      this.requests = raw.requests ?? {};
    }
  }

  get(id) {
    return this.requests[String(id)] ?? null;
  }

  set(id, entry) {
    this.requests[String(id)] = { ...(this.requests[String(id)] ?? {}), ...entry };
    this.save();
  }

  /** Atomic: a crash leaves the old file or the new one, never half of one. */
  save() {
    const text = `${JSON.stringify({ format: STATE_FORMAT, contract: this.contract, vault: this.vault, network: this.network, requests: this.requests }, null, 1)}\n`;
    mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
    const tmp = `${this.path}.tmp`;
    const fd = openSync(tmp, 'w', 0o600);
    try {
      writeSync(fd, text);
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    renameSync(tmp, this.path);
  }
}

/** One file per contract and vault, beside the config. A dry run keeps its own, so it never hides a real alert. */
export function statePathFor(configPath, { contract, vault, dryRun }) {
  const tag = toHex(sha256(utf8(`${contract}\n${vault}`))).slice(0, 12);
  return join(dirname(resolve(configPath)), `state-${tag}${dryRun ? '.dry-run' : ''}.json`);
}

// ---------------------------------------------------------------- the loop

/**
 * One vault. `reads` is contractReads or a stand-in, `push` is ntfyPublisher or a stand-in. `record` gets one
 * object per event, for the JSON log. Nothing here sleeps: the caller owns the timing.
 */
export class Watcher {
  constructor({ config, vault, reads, push, state, nowFn = () => Date.now(), log = () => {}, record = () => {}, dryRun = false, pushAttempts = 4, retryMs = 700, sleep = (ms) => new Promise((r) => { setTimeout(r, ms); }) }) {
    Object.assign(this, { config, vault, reads, push, state, nowFn, log, record, dryRun, pushAttempts, retryMs, sleep });
    this.polls = 0;
    this.lastSample = null;
    this.restarted = new Set(Object.entries(state.requests).filter(([, e]) => e.outcome === 'sending').map(([id]) => Number(id)));
  }

  label() {
    return this.config.labels.label;
  }

  async sample() {
    this.lastSample = await this.reads.clock();
    return this.lastSample;
  }

  /** One read of the vault, and whatever it calls for. Returns what happened, for tests and the status line. */
  async pollOnce() {
    const read = await this.reads.vault(this.vault);
    const seenAt = this.nowFn();
    this.polls += 1;
    const v = read.value;
    if (v === null) return { vault: null, events: [{ kind: 'no_vault' }] };
    const events = [];
    const pending = new Set(v.pending);
    // New ones first: an alert is the whole point, and a request that left the queue can wait a poll.
    for (const id of [...v.pending].sort((a, b) => a - b)) {
      const entry = this.state.get(id);
      if (entry && entry.outcome !== 'sending') continue;
      events.push(await this.consider(v, id, seenAt, read.height));
    }
    for (const [key, entry] of Object.entries(this.state.requests)) {
      const id = Number(key);
      if (entry.gone_at || pending.has(id)) continue;
      events.push(await this.gone(id, entry));
    }
    return { vault: v, events };
  }

  async gone(id, entry) {
    let why = 'gone';
    try {
      const { value } = await this.reads.request(this.vault, id);
      why = value === null ? 'cancelled or swept' : `status ${value.status}`;
    } catch {
      why = 'gone, not read';
    }
    const at = this.nowFn();
    this.state.set(id, { gone_at: at, gone_why: why });
    const after = entry.pushed_at ? ` ${((at - entry.pushed_at) / 1000).toFixed(1)} s after the push` : '';
    this.log(`GONE r=${id} ${this.label()} ${why}${after}`);
    this.record({ event: 'gone', request: id, why, at, after_push_ms: entry.pushed_at ? at - entry.pushed_at : null });
    return { kind: 'gone', id, why };
  }

  async consider(v, id, seenAt, height) {
    const [{ value: request }, sample] = await Promise.all([this.reads.request(this.vault, id), this.sample()]);
    if (request === null) {
      this.state.set(id, { outcome: 'skipped', why: 'gone before it was read', seen_at: seenAt, gone_at: seenAt });
      return { kind: 'skipped', id, why: 'gone before it was read' };
    }
    const now = this.nowFn();
    const chainNow = chainNowOf(sample, now);
    const skew = now - chainClockOf(sample, now);
    if (Math.abs(skew) > CLOCK_TOLERANCE_MS && !this.warnedSkew) {
      this.warnedSkew = true;
      this.log(`CLOCK ${this.label()} this machine's clock is ${Math.round(Math.abs(skew) / 1000)} s ${skew > 0 ? 'ahead of' : 'behind'} the chain's: alerts count down from the chain's clock`);
      this.record({ event: 'clock_skew', skew_ms: skew });
    }
    // On the chain's clock alone: this machine's clock running ahead must never mark a live request expired.
    const dead = liveness(request, v, chainClockOf(sample, now));
    if (dead) {
      this.state.set(id, { outcome: 'skipped', why: dead, seen_at: seenAt, proposed_at: request.proposed_at });
      this.log(`SKIP r=${id} ${this.label()} not alerted: ${dead}`);
      this.record({ event: 'skipped', request: id, why: dead, seen_at: seenAt });
      return { kind: 'skipped', id, why: dead };
    }
    const repeat = this.restarted.has(id);
    const alert = buildAlert({ config: this.config, vault: v, request, chainNowMs: chainNow, repeat });
    const base = { request: id, proposed_at: request.proposed_at, unlock: request.unlock, seen_at: seenAt, view_height: height, clock_skew_ms: sample.heardAt - sample.blockMs };
    if (this.dryRun) {
      this.log(`DRY RUN r=${id} ${this.label()} would push:\n  title: ${alert.title}\n  ${alert.message.split('\n').join('\n  ')}\n  tap: ${alert.click}`);
      this.state.set(id, { outcome: 'dry-run', seen_at: seenAt, proposed_at: request.proposed_at });
      this.record({ event: 'dry-run', ...base, alert });
      return { kind: 'dry-run', id, alert };
    }
    this.state.set(id, { outcome: 'sending', seen_at: seenAt, proposed_at: request.proposed_at });
    let sent = null;
    let lastError = null;
    for (let attempt = 1; attempt <= this.pushAttempts && !sent; attempt += 1) {
      try {
        sent = await this.push(alert);
      } catch (err) {
        lastError = err;
        this.log(`PUSH FAILED r=${id} attempt ${attempt}: ${err.message}`);
        if (err.retry === false) break;
        if (attempt < this.pushAttempts) await this.sleep(this.retryMs * attempt);
      }
    }
    if (!sent) {
      // Left as "sending", so the next poll tries again for as long as the request is waiting.
      this.record({ event: 'push_failed', ...base, error: lastError?.message ?? 'unknown' });
      return { kind: 'push_failed', id, error: lastError?.message };
    }
    const pushedAt = this.nowFn();
    const entry = {
      outcome: 'pushed', pushed_at: pushedAt, latency_ms: pushedAt - request.proposed_at, detect_ms: seenAt - request.proposed_at, push_ms: pushedAt - seenAt, ntfy_id: sent.id, repeat,
    };
    this.state.set(id, entry);
    this.restarted.delete(id);
    this.log(`PUSH r=${id} ${this.label()} ${satsText(amountSats(request))}: ${(entry.latency_ms / 1000).toFixed(2)} s from the propose's block time to ntfy's answer (seen after ${(entry.detect_ms / 1000).toFixed(2)} s, push took ${(entry.push_ms / 1000).toFixed(2)} s)${repeat ? ', marked may repeat' : ''}`);
    this.record({ event: 'pushed', ...base, ...entry });
    return { kind: 'pushed', id, alert, ...entry };
  }
}
