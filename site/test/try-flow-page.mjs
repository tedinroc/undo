// Runs /try/'s own module in Node, one scenario at a time (after phone-flow-page.mjs): a made-up DOM whose buttons can be
// tapped, a made-up network (relay, NEAR node with a small contract, Esplora with a node that refuses the key-alone spend),
// and a made-up navigator.credentials that answers, refuses, closes or never settles as the scenario says. It prints every
// step the page drew, every passkey call with whether it was made inside the tap's own handler, every request it sent with
// whether a tap was running then, and where it sent the tab. try-flow.test.mjs starts it in a child process per scenario.
// Every host and key here is made up, and nothing leaves this machine.
//
//   node try-flow-page.mjs '{"steps":[{"tap":"make"},{"until":{"id":"confirm"}},{"tap":"confirm"},{"until":{"replaced":true}}]}'
import { createHash, generateKeyPairSync, sign as nodeSign, webcrypto } from 'node:crypto';
import { register } from 'node:module';

register('./page-hooks.mjs', import.meta.url);

const opts = JSON.parse(process.argv[2] ?? '{}');
// `clockWarp`: Date.now runs that many times faster for the page; its timers and performance.now do not.
const wall = Date.now.bind(Date);
if (opts.clockWarp) {
  const zero = wall();
  Date.now = () => Math.round(zero + (wall() - zero) * opts.clockWarp);
}
const t0 = wall();
const sleep = (ms) => new Promise((r) => { setTimeout(r, ms); });
const sha = (b) => new Uint8Array(createHash('sha256').update(b).digest());
const hex = (u8) => Buffer.from(u8).toString('hex');
const ab = (u8) => u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
const b64u = (u8) => Buffer.from(u8).toString('base64url');
const nth = (list, i, fallback) => (Array.isArray(list) && list.length ? list[Math.min(i, list.length - 1)] : fallback);

// Every 32 random bytes the page makes: the spend seed and the cold key are among them (T10).
const secrets = [];
const realRandom = webcrypto.getRandomValues.bind(webcrypto);
Object.defineProperty(globalThis, 'crypto', {
  value: { subtle: webcrypto.subtle, getRandomValues: (a) => { const out = realRandom(a); if (a.length === 32) secrets.push(Buffer.from(out).toString('hex')); return out; }, randomUUID: () => webcrypto.randomUUID() },
  configurable: true,
});

// ---------------------------------------------------------------- a DOM with what the page touches

class Text {
  constructor(text) {
    this.text = String(text);
    this.parentNode = null;
  }

  get textContent() { return this.text; }
}

class El {
  constructor(tag) {
    Object.assign(this, { tag, attrs: {}, childNodes: [], parentNode: null, dataset: {}, className: '', hidden: false, style: {}, listeners: {}, clientWidth: 360 });
    const self = this;
    this.classList = {
      add: (...c) => { self.className = [...new Set([...self.className.split(/\s+/).filter(Boolean), ...c])].join(' '); },
      remove: (...c) => { self.className = self.className.split(/\s+/).filter((x) => x && !c.includes(x)).join(' '); },
      toggle: (c, on) => { if (on ?? !self.classList.contains(c)) self.classList.add(c); else self.classList.remove(c); },
      contains: (c) => self.className.split(/\s+/).includes(c),
    };
  }

  setAttribute(name, value) { this.attrs[name] = String(value); }

  getAttribute(name) { return this.attrs[name] ?? null; }

  get id() { return this.attrs.id ?? null; }

  get href() { return this.attrs.href ?? null; }

  get children() { return this.childNodes.filter((n) => n instanceof El); }

  get firstChild() { return this.childNodes[0] ?? null; }

  get parentElement() { return this.parentNode instanceof El ? this.parentNode : null; }

  get nextSibling() {
    const p = this.parentNode;
    if (!p) return null;
    return p.childNodes[p.childNodes.indexOf(this) + 1] ?? null;
  }

  get lastElementChild() { return this.children.at(-1) ?? null; }

  addEventListener(type, fn) { (this.listeners[type] ??= []).push(fn); }

  removeEventListener() {}

  dispatchEvent() { return true; }

  #adopt(n) {
    const node = typeof n === 'string' || typeof n === 'number' ? new Text(n) : n;
    if (node.parentNode) node.parentNode.childNodes = node.parentNode.childNodes.filter((x) => x !== node);
    node.parentNode = this;
    return node;
  }

  append(...kids) { for (const k of kids) this.childNodes.push(this.#adopt(k)); }

  replaceChildren(...kids) {
    for (const k of this.childNodes) k.parentNode = null;
    this.childNodes = [];
    this.append(...kids);
  }

  insertBefore(node, ref) {
    const n = this.#adopt(node);
    const at = ref ? this.childNodes.indexOf(ref) : -1;
    if (at < 0) this.childNodes.push(n);
    else this.childNodes.splice(at, 0, n);
    return n;
  }

  replaceWith(node) {
    const p = this.parentNode;
    if (!p) return;
    const at = p.childNodes.indexOf(this);
    const n = typeof node === 'string' ? new Text(node) : node;
    if (n.parentNode) n.parentNode.childNodes = n.parentNode.childNodes.filter((x) => x !== n);
    n.parentNode = p;
    p.childNodes[at] = n;
    this.parentNode = null;
  }

  remove() {
    if (!this.parentNode) return;
    this.parentNode.childNodes = this.parentNode.childNodes.filter((x) => x !== this);
    this.parentNode = null;
  }

  focus() {}

  /** A tap: the handlers run now, and a passkey call made before they return was made inside the tap. */
  click() {
    globalThis.inTap = (globalThis.inTap ?? 0) + 1;
    try {
      for (const fn of this.listeners.click ?? []) fn({ type: 'click', preventDefault() {}, currentTarget: this, target: this });
    } finally {
      globalThis.inTap -= 1;
    }
  }

  all(test, out = []) {
    for (const k of this.children) {
      if (test(k)) out.push(k);
      k.all(test, out);
    }
    return out;
  }

  #match(sel) {
    if (sel.startsWith('#')) return (n) => n.id === sel.slice(1);
    if (sel.startsWith('.')) return (n) => n.classList.contains(sel.slice(1));
    return (n) => n.tag === sel;
  }

  querySelector(sel) {
    const parts = sel.trim().split(/\s+/);
    let scope = [this];
    for (const part of parts) scope = scope.flatMap((s) => s.all(this.#match(part)));
    return scope[0] ?? null;
  }

  querySelectorAll(sel) { return this.all(this.#match(sel)); }

  getBoundingClientRect() { return { top: 0, bottom: 20, left: 0, right: 100, width: 100, height: 20 }; }

  get textContent() { return this.childNodes.map((k) => k.textContent).join(''); }

  set textContent(v) {
    for (const k of this.childNodes) k.parentNode = null;
    this.childNodes = [];
    if (v !== '' && v !== null && v !== undefined) this.append(String(v));
  }

  /** The text a person reads, block by block. */
  get innerText() {
    if (this.hidden) return '';
    const own = this.childNodes.map((k) => (k instanceof El ? k.innerText : k.text));
    return own.join(['p', 'div', 'li', 'h1', 'ol', 'main', 'header', 'button', 'a'].includes(this.tag) ? ' ' : '').replace(/\s+/g, ' ').trim();
  }

  find(id) {
    if (this.id === id) return this;
    for (const k of this.children) {
      const got = k.find(id);
      if (got) return got;
    }
    return null;
  }
}

const el = (tag, attrs = {}, ...kids) => {
  const n = new El(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') n.className = v;
    else if (k.startsWith('data-')) n.dataset[k.slice(5)] = v;
    else n.setAttribute(k, v);
  }
  n.append(...kids);
  return n;
};
// index.html, as the page finds it before its script runs.
const html = el('html', { 'data-step': 'intro', 'data-state': 'boot' });
// Every change of step or state is looked at once the page has drawn it, so a screen up for a moment is not missed.
html.dataset = new Proxy({ step: 'intro', state: 'boot' }, {
  set(target, key, value) {
    target[key] = value;
    queueMicrotask(() => globalThis.lookNow?.());
    globalThis.onDrawn?.(key, value);
    return true;
  },
});
const body = el('body', {},
  el('div', { id: 'frame' },
    el('header', { class: 'top' }, el('div', { id: 'chip', class: 'chip' }, 'signet test coins'), el('div', { class: 'wordmark' }, 'Undo for Bitcoin')),
    el('ol', { id: 'rail', class: 'rail' }, ...[1, 2, 3, 4].map((n) => el('li', { 'data-n': String(n) }, el('span', { class: 'dot' }), el('span', { class: 'nm' }, String(n))))),
    el('main', { id: 'screen' }, el('h1', { id: 'title', class: 'title' }, 'Rob yourself. Then undo it.'), el('div', { id: 'lines' }), el('div', { id: 'stage' }), el('div', { id: 'card', class: 'card' }), el('div', { id: 'more' })),
    el('p', { id: 'next', class: 'next' }, 'Nothing to tap yet.'),
    el('div', { id: 'dock', class: 'dock' }),
    el('div', { id: 'aside', class: 'aside' })));
html.append(body);
body.find('card').hidden = true;

const heard = { document: {}, window: {} };
const fire = (who, type, event = {}) => { for (const fn of heard[who][type] ?? []) fn({ type, ...event }); };
let hidden = false;
const doc = {
  documentElement: html, body, title: 'Undo · try it', createElement: (t) => new El(t), getElementById: (id) => body.find(id),
  addEventListener: (type, fn) => { (heard.document[type] ??= []).push(fn); }, removeEventListener() {},
  querySelector: (sel) => html.querySelector(sel),
  hasFocus: () => true,
};
Object.defineProperty(doc, 'hidden', { get: () => hidden });
Object.defineProperty(doc, 'visibilityState', { get: () => (hidden ? 'hidden' : 'visible') });
// `hideOn: { state }`: the page is hidden, and told so, right after it draws that state, once (as a person who leaves the
// moment that screen comes up): in the microtask after data-state is set, where a MutationObserver would see it.
const hides = [];
globalThis.onDrawn = (key, value) => {
  if (key !== 'state' || !live.hideOn || value !== live.hideOn.state) return;
  live.hideOn = null;
  queueMicrotask(() => {
    hidden = true;
    hides.push(wall() - t0);
    fire('document', 'visibilitychange');
  });
};
globalThis.document = doc;
globalThis.window = globalThis;
globalThis.addEventListener = (type, fn) => { (heard.window[type] ??= []).push(fn); };
globalThis.removeEventListener = () => {};
globalThis.innerHeight = 844;
globalThis.innerWidth = 390;
globalThis.isSecureContext = true;
globalThis.requestAnimationFrame = (cb) => setTimeout(() => cb(performance.now()), 16);
globalThis.cancelAnimationFrame = (id) => clearTimeout(id);
globalThis.getComputedStyle = () => ({ marginTop: '0', fontSize: '16' });
const opened = [];
globalThis.open = (...a) => { opened.push(a); return null; };

// Everything the page writes to the console, for T10.
const consoleLines = [];
for (const level of ['log', 'info', 'warn', 'error', 'debug']) {
  console[level] = (...a) => { consoleLines.push(a.map((x) => (typeof x === 'string' ? x : JSON.stringify(x))).join(' ')); };
}

const RP = 'undo.example.test';
const ORIGIN = `https://${RP}`;
const IPHONE = 'Mozilla/5.0 (iPhone; CPU iPhone OS 26_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Mobile/15E148 Safari/604.1';

// ---------------------------------------------------------------- passkeys

const keychain = [];
const calls = [];
const refusal = (message) => Object.assign(new Error(message), { name: 'NotAllowedError' });

function sheet(kind, how, signal, answer) {
  const call = { call: kind, at: wall() - t0, inTap: (globalThis.inTap ?? 0) > 0, signal: Boolean(signal), aborted: false, how };
  calls.push(call);
  const deaf = typeof how === 'object' && how?.deaf === true;
  return new Promise((resolve, reject) => {
    signal?.addEventListener('abort', () => {
      call.aborted = true;
      if (!deaf) reject(Object.assign(new Error('The operation was aborted.'), { name: 'AbortError' }));
    });
    if (how === 'never') return;
    if (how === 'fast') sleep(20).then(() => reject(refusal('The document is not focused.')));
    else if (how === 'dismiss' || how === 'quiet') {
      if (how === 'dismiss') sleep(20).then(() => fire('window', 'blur'));
      sleep(opts.dismissMs ?? 900).then(() => reject(refusal('This request has been cancelled by the user.')));
    } else sleep(typeof how === 'number' ? how : typeof how === 'object' ? how.ms : 150).then(() => { try { resolve(answer()); } catch (e) { reject(e); } });
  });
}

const credentials = {
  create(o) {
    const how = nth(opts.create, calls.filter((c) => c.call === 'create').length, 'ok');
    return sheet('create', how, o.signal, () => {
      const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const item = { id: new Uint8Array(20).fill(40 + keychain.length), privateKey, spki: new Uint8Array(publicKey.export({ type: 'spki', format: 'der' })) };
      keychain.push(item);
      const authData = new Uint8Array([...sha(Buffer.from(RP)), 0x5d, 0, 0, 0, 0]);
      return { rawId: ab(item.id), response: { getPublicKey: () => ab(item.spki), getAuthenticatorData: () => ab(authData), clientDataJSON: ab(new Uint8Array(2)), attestationObject: ab(new Uint8Array(2)) } };
    });
  },
  get(o) {
    const how = nth(opts.get, calls.filter((c) => c.call === 'get').length, 'ok');
    const allow = o.publicKey.allowCredentials.map((c) => b64u(new Uint8Array(c.id)));
    return sheet('get', how, o.signal, () => {
      const item = keychain.find((k) => allow.includes(b64u(k.id))) ?? (allow.length ? null : keychain.at(-1));
      if (!item) throw refusal('No credential here.');
      const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: b64u(new Uint8Array(o.publicKey.challenge)), origin: ORIGIN }));
      const authData = new Uint8Array([...sha(Buffer.from(RP)), 0x1d, 0, 0, 0, 0]);
      const der = new Uint8Array(nodeSign('sha256', Buffer.concat([authData, sha(client)]), { key: item.privateKey, dsaEncoding: 'der' }));
      return { rawId: ab(item.id), response: { authenticatorData: ab(authData), clientDataJSON: ab(new Uint8Array(client)), signature: ab(der) } };
    });
  },
};

const wake = { asked: 0 };
Object.defineProperty(globalThis, 'navigator', {
  value: {
    userAgent: opts.ua ?? IPHONE, maxTouchPoints: 5, credentials,
    wakeLock: { request: async () => { wake.asked += 1; return { addEventListener() {}, release: async () => {} }; } },
  },
  configurable: true,
});
// `uvpaa: false`: the browser reports no passkey manager or screen lock it can use (an app's own browser often does).
globalThis.PublicKeyCredential = { isUserVerifyingPlatformAuthenticatorAvailable: async () => opts.uvpaa ?? true };
const historyLog = [];
Object.defineProperty(globalThis, 'history', { value: { replaceState(a, b, url) { historyLog.push(String(url)); location.hash = String(url).includes('#') ? String(url).slice(String(url).indexOf('#')) : ''; } }, configurable: true });
const went = [];
Object.defineProperty(globalThis, 'location', {
  value: {
    pathname: '/try/', hash: opts.hash ?? '', origin: ORIGIN, hostname: RP, host: RP, protocol: 'https:',
    get href() { return `${ORIGIN}/try/${this.hash}`; },
    reload() { went.push({ how: 'reload' }); }, assign(url) { went.push({ how: 'assign', url: String(url) }); }, replace(url) { went.push({ how: 'replace', url: String(url) }); },
  },
  configurable: true,
});
const store = () => {
  const m = new Map();
  return { getItem: (k) => m.get(k) ?? null, setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), dump: () => Object.fromEntries(m) };
};
globalThis.sessionStorage = store();
globalThis.localStorage = store();
// `made`: that many vaults this browser made in the past hour, as an earlier visit left them (S0's hint).
if (opts.made) globalThis.localStorage.setItem('undo-try:made', JSON.stringify(Array.from({ length: opts.made }, (_, i) => wall() - (i + 1) * 60_000)));
// `madeAgo`: the Make times themselves, each that many ms before this run starts (one just short of an hour ages out).
if (opts.madeAgo) globalThis.localStorage.setItem('undo-try:made', JSON.stringify(opts.madeAgo.map((ago) => wall() - ago)));

// ---------------------------------------------------------------- the network: config, relay, a NEAR node, Esplora

const NOW = Date.now();
const POLICY = { t_known_ms: 60_000, t_new_ms: 300_000, t_new_unguarded_ms: 600_000, hold_ms: 300_000, t_stuck_ms: 900_000, fee_cap_tx: 5000, fee_budget_24h: 20000, outflow_cap_24h: 1_000_000 };
const { vaultIdOfCreateArgs, p2wshSpk } = await import('/site/lib/index.mjs');
const { base58Encode, fromHex, toHex } = await import('/tools/lib/bytes.mjs');
const live = { ...opts };
const config = { mode: 'testnet', contract: 'c.testnet', rpc: ['https://rpc.example.test'], esplora: 'https://esplora.example.test/api', relay: '/api/relay', funds: '/api/funds', btcTxUrl: null, btcAddressUrl: null, nearTxUrl: null, rpId: RP, softPasskey: false, h7: false };
const instance = { signer: 'signer.testnet', domain_id: 0, sign_tgas: 30, callback_tgas: 10, network: 'signet', origins: [ORIGIN], policy: POLICY, expiry_window_ms: 3_600_000, block_ms: 1000, csv_min: 6, csv_max: 52_560, restrict_create: false, guard_model: 'model' };
const SCRIPT = '63' + '51'.repeat(20) + '68';
const ADDRESS = 'tb1qexampleexampleexampleexampleexampleexa';
const COIN = { txid: 'cc'.repeat(32), vout: 0, value: 2000 };

// What the contract holds: vaults made through the relay, by id, and their requests.
const vaults = new Map();
const requests = new Map();
let nextRequest = 7;
const status = () => ({
  ok: true, relay_account: 'relay.testnet', contract: 'c.testnet', pow_bits: 4,
  owner: { up: !live.ownerDown, why: live.ownerDown ? 'rpc_down' : null, degraded: false, resets_at: null },
  general: { up: !live.generalDown, why: live.generalDown ? 'daily_ceiling' : null, resets_at: null },
  funds: { up: !live.fundsDown, why: live.fundsDown ? 'daily_ceiling' : null, resets_at: null, sats: 2000 },
});
const vaultRow = (id) => {
  const v = vaults.get(id);
  return {
    id, active: !live.neverActive, k_s: v.k_s, k_s_suspended: v.suspended, k_u: v.k_u, k_m: v.k_m, k_e_leaf: v.k_e_leaf, k_e_intent: v.k_e_intent,
    passkey: v.passkey, rp_id_hash: hex(sha(Buffer.from(RP))), backup_eligible: true, backup_state: true, guard: 'relay.testnet', guard_online: true, last_heartbeat: Date.now() - 1000,
    created_at: NOW, csv: 6, script_pubkey: toHex(p2wshSpk(fromHex(SCRIPT))), address: ADDRESS, policy: POLICY, spend_epoch: v.epoch, frozen_until: null,
    spend_nonce: v.spendNonce, passkey_nonce: v.passkeyNonce, cold_nonce: 0, pending: live.noList ? [] : [...requests.values()].filter((r) => r.vault === id && v.pendingIds.has(r.id)).map((r) => r.id), storage_credit: '1000000000000000000000',
  };
};
const requestRow = (r) => ({
  id: r.id, kind: 'Normal', status: 'Pending', epoch: r.epoch, inputs: r.inputs, to: r.to, amount: r.amount, change: null, tier: 'New', fee: r.inputs.reduce((s, c) => s + c.value, 0) - r.amount,
  proposed_at: r.at, base_unlock: r.at + 300_000, unlock: r.at + 300_000, expires_at: r.at + 3_600_000, first_execute_at: null, attempt: 0, in_flight: 0, sigs: [null],
  assessed: false, assess_hold: false, assess_reason: 'none', hold_used: false, hold_active: false,
});

const json = (value, s = 200) => new Response(JSON.stringify(value), { status: s, headers: { 'content-type': 'application/json' } });
const rpc = (result) => json({ jsonrpc: '2.0', id: 1, result });
const view = (value) => rpc({ result: [...Buffer.from(JSON.stringify(value))], block_height: 1000, logs: [] });
const sent = [];
// Every request the page makes, GET or POST: after T3 there must be none.
const fetches = [];
const relayGets = [];
const relayCalls = {};
const fundAsks = [];
let coinThere = false;
let coinSpent = false;

/** create_vault on the contract: the vault, by the id its arguments hash to. */
function createVault(a) {
  const id = toHex(vaultIdOfCreateArgs(config.contract, a));
  vaults.set(id, { k_s: a.k_s, k_u: a.k_u, k_m: a.k_m, k_e_leaf: a.k_e_leaf, k_e_intent: a.k_e_intent, passkey: a.passkey.pubkey, epoch: 2, spendNonce: 0, passkeyNonce: 0, suspended: false, pendingIds: new Set() });
}

/** Answers propose_btc on the contract: a request in the vault's epoch, with what the proposal named. */
function propose(args) {
  const v = vaults.get(args.vault);
  if (!v) return { ok: false, code: 'would_refuse', verbatim: 'Smart contract panicked: Inactive' };
  v.spendNonce += 1;
  if (live.proposeNotListed) return { ok: true, hash: 'P'.repeat(44) };
  const r = { id: nextRequest, vault: args.vault, epoch: v.epoch, inputs: args.inputs, to: args.to, amount: args.amount, at: Date.now() };
  nextRequest += 1;
  requests.set(r.id, r);
  v.pendingIds.add(r.id);
  return { ok: true, hash: 'P'.repeat(44) };
}

globalThis.fetch = async (url, init = {}) => {
  const u = String(url);
  const method = init.method ?? 'GET';
  const record = { at: wall() - t0, url: u, method, body: init.body ?? null, inTap: (globalThis.inTap ?? 0) > 0, hidden };
  if (method === 'POST') sent.push(record);
  fetches.push({ at: record.at, url: u });
  await sleep(live.netMs ?? 20);
  if (u === '/undo-config.json') return json(config);
  if (u === '/api/relay' && method === 'GET') {
    relayGets.push(record.at);
    return json(status());
  }
  if (u === '/api/funds') {
    const body = JSON.parse(init.body);
    fundAsks.push({ at: record.at, hidden });
    const how = nth(live.fund, fundAsks.length - 1, 'ok');
    if (how === 'fail') throw new TypeError('Load failed');
    if (typeof how === 'object') return json(how.body, how.status);
    coinThere = !live.coinNeverListed;
    return json({ ok: true, txid: COIN.txid, vout: 0, value: COIN.value, vault: body.vault });
  }
  if (u === '/api/relay') {
    const body = JSON.parse(init.body);
    record.method = body.method;
    // `rpcDownOnPropose`: the NEAR node stops answering as the proposal reaches the relay, so no read of the page's
    // can see a request the contract may list.
    if (body.method === 'propose_btc' && live.rpcDownOnPropose) live.rpcDown = true;
    // A rule per call: a list answers the nth call with its nth entry, the last repeating; 'ok' lets the call through.
    const asked = (relayCalls[body.method] = (relayCalls[body.method] ?? 0) + 1);
    const given = live.post?.[body.method];
    const rule = Array.isArray(given) ? nth(given, asked - 1, 'ok') : given;
    if (rule === 'fail') throw new TypeError('Load failed');
    if (rule === 'timeout' || rule === 'timeoutListed') {
      if (rule === 'timeoutListed') propose(body.args);
      return new Promise((_, reject) => { init.signal?.addEventListener('abort', () => reject(init.signal.reason)); });
    }
    if (rule && typeof rule === 'object') return json(rule.body, rule.status);
    if (rule === 'failAfterSend' && body.method === 'create_vault') {
      // The relay sent the creation, and the page hears nothing back (M8): the contract has the vault.
      createVault(body.args);
      throw new TypeError('Load failed');
    }
    if (rule === 'failAfterSend' && body.method === 'cancel_all_and_rotate') {
      // The relay sent it, and the page hears nothing back: the chain decides.
      const v = vaults.get(body.args.vault);
      if (v) {
        v.epoch += 1;
        v.passkeyNonce += 1;
        v.k_s = body.args.new_k_s;
        v.suspended = true;
        v.pendingIds.clear();
      }
      throw new TypeError('Load failed');
    }
    if (body.method === 'create_vault') {
      createVault(body.args);
      return json({ ok: true, hash: 'C'.repeat(44), method: 'create_vault' });
    }
    if (body.method === 'propose_btc') {
      const answer = propose(body.args);
      return answer.ok ? json(answer) : json(answer, 422);
    }
    if (body.method === 'cancel_all_and_rotate') {
      const v = vaults.get(body.args.vault);
      if (v && !live.cancelNotApplied) {
        v.epoch += 1;
        v.passkeyNonce += 1;
        v.k_s = body.args.new_k_s;
        v.suspended = true;
        v.pendingIds.clear();
      }
      if (live.cancelAnswer === 'fail') throw new TypeError('Load failed');
      return json({ ok: true, hash: 'X'.repeat(44), method: body.method, key: 'owner' });
    }
    return json({ ok: true, hash: 'H'.repeat(44), method: body.method });
  }
  if (u.startsWith('https://rpc.example.test')) {
    const { method: m, params } = JSON.parse(init.body);
    if (live.rpcDown) return new Response('down', { status: 503 });
    // `blockMs`: the chain's clock (a block read) answers that much later, while every other read answers as usual.
    if (m === 'block' && live.blockMs) await sleep(live.blockMs);
    if (m === 'block') return rpc({ header: { hash: '1'.repeat(32), height: 1000, timestamp_nanosec: `${Date.now()}000000` } });
    if (m === 'tx') return rpc({ final_execution_status: 'EXECUTED_OPTIMISTIC', status: { SuccessValue: '' }, receipts_outcome: [] });
    if (m === 'query' && params.request_type === 'view_access_key_list') return rpc({ keys: [], block_height: 1000, block_hash: '1'.repeat(32) });
    if (m === 'query' && params.request_type === 'call_function') {
      const args = JSON.parse(Buffer.from(params.args_base64, 'base64').toString());
      const name = params.method_name;
      if (name === 'instance') return view(instance);
      if (name === 'derived_public_key') return view(`secp256k1:${base58Encode(new Uint8Array(64).fill(5))}`);
      // `vaultNull`: a node behind, which answers with no vault. `requestNull`: one that lists the id and has no row for it.
      if (name === 'vault') {
        const answer = view(vaults.has(args.vault) && !live.vaultNull ? vaultRow(args.vault) : null);
        // `vaultSlowMs`: the next read of the vault is answered that much later, with what the contract held when it
        // was asked (once), so a later read can answer before it.
        if (live.vaultSlowMs) {
          const ms = live.vaultSlowMs;
          live.vaultSlowMs = 0;
          await sleep(ms);
        }
        return answer;
      }
      if (name === 'script') return view(SCRIPT);
      if (name === 'check_propose') return view({ tier: 'New', delay_ms: 300_000, fee: 300, unguarded: false });
      if (name === 'request') {
        const r = requests.get(args.request);
        const v = vaults.get(args.vault);
        if (!r || !v || r.vault !== args.vault || live.requestNull) return view(null);
        // A cancelled request stays in the row with its old epoch: the vault's has moved on.
        return view(requestRow(r));
      }
    }
    return rpc(null);
  }
  if (u.startsWith('https://esplora.example.test')) {
    const path = u.slice('https://esplora.example.test/api'.length);
    if (path === '/tx' && method === 'POST') {
      const answer = live.nodeAnswer ?? 'script';
      if (answer === 'accept') {
        // A node that took it answers with the transaction's own txid (Esplora's 200), which the page reads as accepted.
        coinSpent = true;
        const { parseTx, txid } = await import('/tools/lib/btc.mjs');
        return new Response(txid(parseTx(fromHex(String(init.body)))), { status: 200 });
      }
      if (answer === 'none') throw new TypeError('Load failed');
      // `{ status, body }`: a node that says no in its own words (T4).
      if (typeof answer === 'object') return new Response(answer.body, { status: answer.status });
      return new Response('sendrawtransaction RPC error: {"code":-26,"message":"mandatory-script-verify-flag-failed (Script evaluated without error but finished with a false/empty top stack element)"}', { status: 400 });
    }
    // `hideCoin`: the coin is sent, and the node does not list it until the scenario says so.
    if (path.endsWith('/utxo')) return json(coinThere && !coinSpent && !live.hideCoin ? [{ ...COIN, status: { confirmed: false } }] : []);
    // `fee`: the node's fee estimate in sat/vB, which the scenario can raise and drop (T1 with a fee that takes the coin).
    // `feeDown`: the fee read alone fails (a busy node), while the address reads answer.
    if (path === '/fee-estimates' && live.feeDown) return new Response('busy', { status: 503 });
    // `feeHang`: the fee read gets no answer at all, until the page's own timeout ends it (a node that hangs).
    if (path === '/fee-estimates' && live.feeHang) return new Promise((_, reject) => { init.signal?.addEventListener('abort', () => reject(init.signal.reason)); });
    if (path === '/fee-estimates') return json({ 1: live.fee ?? 1.0, 6: live.fee ?? 1.0 });
    if (path === `/tx/${COIN.txid}`) return json({ txid: COIN.txid, vout: [{ value: COIN.value }] });
    if (path.startsWith(`/tx/${COIN.txid}/outspend/`)) return json({ spent: coinSpent });
    return new Response('not found', { status: 404 });
  }
  return new Response('not here', { status: 404 });
};

// ---------------------------------------------------------------- the steps

const state = () => ({ step: html.dataset.step, state: html.dataset.state, fail: html.dataset.fail ?? null });
const drawn = [];
let lastDrawn = '';
const look = () => {
  const s = state();
  const text = `${s.step}/${s.state}${s.fail ? `/${s.fail}` : ''}: ${body.find('screen').innerText} || NEXT ${body.find('next').textContent} || DOCK ${body.find('dock').innerText} || ASIDE ${body.find('aside').innerText}`;
  if (text !== lastDrawn) {
    drawn.push({ at: wall() - t0, text });
    lastDrawn = text;
  }
};
const watcher = setInterval(look, 25);
globalThis.lookNow = look;
const snaps = [];
const missed = [];
function snap(label) {
  look();
  snaps.push({
    label, at: wall() - t0, ...state(), title: doc.title, next: body.find('next').textContent, nextTag: body.find('next').dataset.tag ?? null,
    dock: body.find('dock').innerText, dockIds: body.find('dock').all((n) => Boolean(n.id)).map((n) => n.id), text: body.find('screen').innerText, aside: body.find('aside').innerText,
    rail: body.find('rail').children.map((li) => li.className), hash: location.hash, page: html.innerText, count: body.find('dock').querySelector('.n')?.textContent ?? null,
  });
}
const holds = (c) => {
  const s = state();
  if (c.step && s.step !== c.step) return false;
  if (c.state && s.state !== c.state) return false;
  if (c.fail && s.fail !== c.fail) return false;
  if (c.id && !body.find(c.id)) return false;
  if (c.noId && body.find(c.noId)) return false;
  if (c.text && !html.innerText.includes(c.text)) return false;
  if (c.next && !body.find('next').textContent.includes(c.next)) return false;
  if (c.post && !sent.some((p) => p.method === c.post || p.url.endsWith(c.post))) return false;
  if (c.went && went.length === 0) return false;
  if (c.count !== undefined && body.find('dock').querySelector('.n')?.textContent !== String(c.count)) return false;
  return true;
};
async function until(cond, max = 15_000) {
  const end = wall() + max;
  while (wall() < end) {
    if (holds(cond)) return true;
    await sleep(20);
  }
  missed.push(cond);
  return false;
}

// `confirmEarly`: the mutant check of T2. The page would draw Confirm before K_m is read: tapped here at once.
await import('../pages/try/try.mjs');
await until(opts.boot ?? { state: opts.hash ? 'reloaded' : 'ready' }, 8000);
for (const step of opts.steps ?? []) {
  if (step.set) Object.assign(live, step.set);
  if (step.tap) {
    const node = body.find(step.tap);
    if (node) node.click();
    else missed.push({ tap: step.tap });
  }
  // `hide`: the page is hidden and told so. `hideQuiet`: hidden with no event, as a timer that fires on a page the
  // browser has not yet told it is hidden.
  if (step.hide || step.hideQuiet) {
    hidden = true;
    if (step.hide) fire('document', 'visibilitychange');
  }
  if (step.show) {
    hidden = false;
    fire('document', 'visibilitychange');
  }
  if (step.until) await until(step.until, step.max);
  if (step.wait) await sleep(step.wait);
  if (step.snap) snap(step.snap);
}
look();
clearInterval(watcher);
process.stdout.write(`${JSON.stringify({
  t0, snaps, calls, sent, fetches, relayGets: relayGets.length, fundAsks, missed, went, opened: opened.length, historyLog, drawn, hides,
  local: globalThis.localStorage.dump(), session: globalThis.sessionStorage.dump(), consoleLines, secrets, undoRun: globalThis.undoRun, timings: globalThis.undoTimings,
  dom: html.innerText, wake,
})}\n`, () => process.exit(0));
