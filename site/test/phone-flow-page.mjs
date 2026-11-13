// Runs the phone page's own module in Node, one scenario at a time: a made-up DOM whose buttons can be tapped, a made-up
// network, and a made-up navigator.credentials that answers, refuses, closes or never settles as the scenario says.
// It prints what the page drew at each step, every passkey call with whether it was made inside the tap's own handler,
// and every request to the relay. phone-flow.test.mjs starts it in child processes, because the page polls for as long
// as it lives. After phone-boot-page.mjs. Every host and key here is made up, and nothing leaves this machine.
//
//   node phone-flow-page.mjs '{"steps":[{"tap":"make"},{"until":{"id":"confirm"}},{"snap":"passkey made"}]}'
import { createHash, generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { register } from 'node:module';

register('./page-hooks.mjs', import.meta.url);

const opts = JSON.parse(process.argv[2] ?? '{}');
// `clockWarp`: this machine's clock runs that many times faster for the page, and its timers do not, which is what a
// page sees when it is put to sleep between two of its own steps.
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
/** The nth answer of a list whose last entry repeats: ['fast', 'ok'] refuses the first call and answers the rest. */
const nth = (list, i, fallback) => (Array.isArray(list) && list.length ? list[Math.min(i, list.length - 1)] : fallback);

// ---------------------------------------------------------------- a DOM with just what the page touches

class Node {
  constructor(tag) {
    Object.assign(this, { tag, attrs: {}, kids: [], className: '', dataset: {}, value: '', hidden: false, style: {}, clientWidth: 0, listeners: {} });
    this.classList = { add() {}, remove() {}, toggle() {}, contains: () => false };
  }

  setAttribute(name, value) { this.attrs[name] = value; }

  get id() { return this.attrs.id ?? null; }

  addEventListener(type, fn) { (this.listeners[type] ??= []).push(fn); }

  removeEventListener() {}

  append(...kids) { for (const k of kids) this.kids.push(typeof k === 'string' ? { text: k } : k); }

  replaceChildren(...kids) { this.kids = []; this.append(...kids); }

  replaceWith() {}

  remove() {}

  focus() {}

  /** A tap: the handlers run now, and a passkey call made before they return was made inside the tap. */
  click() {
    globalThis.inTap = true;
    try {
      for (const fn of this.listeners.click ?? []) fn({ type: 'click' });
    } finally {
      globalThis.inTap = false;
    }
  }

  all(test, out = []) {
    for (const k of this.kids) {
      if (!(k instanceof Node)) continue;
      if (test(k)) out.push(k);
      k.all(test, out);
    }
    return out;
  }

  querySelector(sel) { return sel === '.slot' ? this.all((n) => /\bslot\b/.test(n.className))[0] ?? null : null; }

  querySelectorAll(sel) { return sel === 'button' ? this.all((n) => n.tag === 'button') : []; }

  getBoundingClientRect() { return { top: 0, bottom: 0, left: 0, right: 0, width: 0, height: 0 }; }

  get textContent() { return this.kids.map((k) => (k instanceof Node ? k.textContent : k.text)).join(' | '); }

  set textContent(v) { this.kids = [{ text: String(v) }]; }

  get lastElementChild() { return [...this.kids].reverse().find((k) => k instanceof Node) ?? null; }

  find(id) {
    if (this.id === id) return this;
    for (const k of this.kids) {
      const got = k instanceof Node ? k.find(id) : null;
      if (got) return got;
    }
    return null;
  }
}

const body = new Node('body');
for (const id of ['chip', 'screen']) {
  const node = new Node(id === 'screen' ? 'main' : 'span');
  node.setAttribute('id', id);
  body.append(node);
}
// Every screen the page drew, in order: a line that is on screen for less than a poll is still in here.
const drawn = [];
const screenNode = body.find('screen');
const replace = screenNode.replaceChildren.bind(screenNode);
screenNode.replaceChildren = (...kids) => {
  replace(...kids);
  drawn.push(`${document.documentElement.dataset.state ?? ''}: ${screenNode.textContent.slice(0, 500)}`);
};
const store = (seed = {}) => {
  const m = new Map(Object.entries(seed));
  return { getItem: (k) => m.get(k) ?? null, setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k), keys: () => [...m.keys()] };
};
const heard = { document: {}, window: {} };
const fire = (who, type, event = {}) => { for (const fn of heard[who][type] ?? []) fn({ type, ...event }); };
globalThis.document = {
  documentElement: new Node('html'), body, hidden: false, createElement: (t) => new Node(t), getElementById: (id) => body.find(id),
  addEventListener: (type, fn) => { (heard.document[type] ??= []).push(fn); }, removeEventListener() {}, querySelector: () => null,
};
globalThis.window = globalThis;
globalThis.addEventListener = (type, fn) => { (heard.window[type] ??= []).push(fn); };
globalThis.removeEventListener = () => {};
globalThis.innerHeight = 844;
globalThis.innerWidth = 390;
globalThis.isSecureContext = opts.secure ?? true;
// A page that keeps drawing, with no blur and no visibilitychange: what a sheet that leaves no trace looks like to it.
globalThis.requestAnimationFrame = (cb) => setTimeout(() => cb(performance.now()), 16);
globalThis.cancelAnimationFrame = (id) => clearTimeout(id);
globalThis.scrollTo = () => {};
globalThis.getComputedStyle = () => ({ marginTop: '0', fontSize: '16' });

const RP = 'undo.example.test';
const ORIGIN = `https://${RP}`;
const IPHONE = 'Mozilla/5.0 (iPhone; CPU iPhone OS 26_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Mobile/15E148 Safari/604.1';
const VAULT = 'ab'.repeat(32);

// ---------------------------------------------------------------- passkeys: a keychain, and a browser that may not answer

const keychain = [];
const newPasskey = () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const item = { id: new Uint8Array(20).fill(7 + keychain.length), privateKey, spki: new Uint8Array(publicKey.export({ type: 'spki', format: 'der' })) };
  keychain.push(item);
  return item;
};
// The passkey of the vault a link names: it is on this phone unless the scenario says the phone holds none.
const linked = newPasskey();
const calls = [];
const refusal = (message) => Object.assign(new Error(message), { name: 'NotAllowedError' });

/**
 * One passkey call, answered as the scenario says for this call: 'ok', a number of ms before it answers, 'fast' (refused
 * at once, as WebKit refuses a document without focus), 'dismiss' (the sheet closed by a person: the page lost focus
 * while it was up, the trace watchSheet looks for), 'quiet' (refused as late, with no trace of a sheet: one that left
 * none, or none came), 'never' (never settles on its own), or { ms, deaf } (answers after ms even if the page aborted it
 * meanwhile). An aborted call settles with AbortError unless it is deaf.
 */
function sheet(kind, how, signal, answer) {
  const call = { call: kind, at: wall() - t0, inTap: globalThis.inTap === true, signal: Boolean(signal), aborted: false, how };
  calls.push(call);
  const deaf = typeof how === 'object' && how.deaf === true;
  return { call, promise: new Promise((resolve, reject) => {
    signal?.addEventListener('abort', () => {
      call.aborted = true;
      if (!deaf) reject(Object.assign(new Error('The operation was aborted.'), { name: 'AbortError' }));
    });
    if (how === 'never') return;
    if (how === 'fast') sleep(20).then(() => reject(refusal('The document is not focused.')));
    else if (how === 'dismiss' || how === 'quiet') {
      if (how === 'dismiss') sleep(20).then(() => fire('window', 'blur'));
      sleep(opts.dismissMs ?? 900).then(() => reject(refusal('This request has been cancelled by the user.')));
    }
    else sleep(typeof how === 'number' ? how : typeof how === 'object' ? how.ms : 150).then(() => resolve(answer()));
  }) };
}

const credentials = {
  create(o) {
    const how = nth(opts.create, calls.filter((c) => c.call === 'create').length, 'ok');
    const { call, promise } = sheet('create', how, o.signal, () => {
      const item = newPasskey();
      const authData = new Uint8Array([...sha(Buffer.from(RP)), 0x5d, 0, 0, 0, 0]);
      // `noPublicKey`: the browser saved the passkey and has no getPublicKey to read it with.
      return { rawId: ab(item.id), response: { getPublicKey: opts.noPublicKey ? undefined : () => ab(item.spki), getAuthenticatorData: () => ab(authData), clientDataJSON: ab(new Uint8Array(2)), attestationObject: ab(new Uint8Array(2)) } };
    });
    Object.assign(call, { name: o.publicKey.user.name, selection: o.publicKey.authenticatorSelection });
    return promise;
  },
  get(o) {
    const how = nth(opts.get, calls.filter((c) => c.call === 'get').length, 'ok');
    const allow = o.publicKey.allowCredentials.map((c) => b64u(new Uint8Array(c.id)));
    const { call, promise } = sheet('get', how, o.signal, () => {
      const item = keychain.find((k) => allow.includes(b64u(k.id))) ?? (allow.length ? null : keychain[keychain.length - 1]);
      if (!item) throw refusal('No credential here.');
      const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: b64u(new Uint8Array(o.publicKey.challenge)), origin: ORIGIN }));
      const authData = new Uint8Array([...sha(Buffer.from(RP)), 0x1d, 0, 0, 0, 0]);
      const der = new Uint8Array(nodeSign('sha256', Buffer.concat([authData, sha(client)]), { key: item.privateKey, dsaEncoding: 'der' }));
      return { rawId: ab(item.id), response: { authenticatorData: ab(authData), clientDataJSON: ab(new Uint8Array(client)), signature: ab(der) } };
    });
    Object.assign(call, { allow: allow.length });
    return promise;
  },
};

const wake = { asked: 0, released: 0 };
const assigned = [];
let platformAsked = 0;
Object.defineProperty(globalThis, 'navigator', {
  value: {
    userAgent: opts.ua ?? IPHONE, maxTouchPoints: 5, credentials: opts.noWebauthn ? undefined : credentials, clipboard: { writeText: async () => {} },
    wakeLock: { request: async () => { wake.asked += 1; return { addEventListener() {}, release: async () => { wake.released += 1; } }; } },
  },
  configurable: true,
});
// `platform`: what isUserVerifyingPlatformAuthenticatorAvailable() answers, call by call; the last answer repeats.
globalThis.PublicKeyCredential = opts.noWebauthn ? undefined : { isUserVerifyingPlatformAuthenticatorAvailable: async () => { platformAsked += 1; return nth(opts.platform, platformAsked - 1, true); } };
Object.defineProperty(globalThis, 'history', { value: { replaceState(a, b, url) { location.hash = String(url).includes('#') ? String(url).slice(String(url).indexOf('#')) : ''; } }, configurable: true });
Object.defineProperty(globalThis, 'location', {
  value: { pathname: '/p/', hash: opts.hash ?? '', origin: ORIGIN, hostname: RP, host: RP, protocol: 'https:', reload() {}, assign(url) { assigned.push(String(url)); } },
  configurable: true,
});
globalThis.sessionStorage = store();
// `stored`: this browser made the linked vault, or has used its passkey, so the credential id is in localStorage.
globalThis.localStorage = store(opts.stored ? { [`undo.passkey.${VAULT}`]: b64u(linked.id) } : {});

// ---------------------------------------------------------------- the network: one config, a relay, a NEAR node, Esplora

const NOW = Date.now();
const POLICY = { t_known_ms: 60_000, t_new_ms: 300_000, t_new_unguarded_ms: 600_000, hold_ms: 300_000, t_stuck_ms: 900_000, fee_cap_tx: 1000, fee_budget_24h: 2000, outflow_cap_24h: 1_000_000 };
const { p256FromSpki } = await import('/site/lib/webauthn.mjs');
const { base58Encode } = await import('/tools/lib/bytes.mjs');
const live = { ...opts };
const kmReads = [];
// Vaults this page made through the relay, by id. The relay's create_vault names no id, so the id is learned from the
// first read of a vault nobody knows that comes after a creation was taken.
const made = new Map();
let takenPasskey = null;
let rotatedTo = null;
// `rotated`: another device's cancel moved the vault on, as a K_s the scenario names.
const rotation = () => rotatedTo ?? live.rotated ?? null;
const limit = (down) => (down ? { up: false, why: down.why ?? 'daily_ceiling', resets_at: down.resetsInMs ? NOW + down.resetsInMs : null } : { up: true, why: null, resets_at: null });
const relayStatus = () => ({
  // `ownerDown`: the relay answers, and says its cancel side is down, with no reason (true) or with this one (a string).
  ok: true, relay_account: 'relay.testnet', contract: 'c.testnet', pow_bits: opts.powBits ?? 8,
  owner: { up: !live.ownerDown, why: typeof live.ownerDown === 'string' ? live.ownerDown : null, degraded: false, resets_at: null },
  general: limit(live.generalDown), funds: { ...limit(live.fundsDown), sats: 2000 },
});
// `second`: a second request, made after the first one ended, in the vault's epoch of that moment.
const vaultRow = (id, passkeyHex, pending) => ({
  id, active: true, k_s: rotation() ?? '11'.repeat(32), k_s_suspended: false, k_u: '02'.padEnd(66, '1'), k_m: '02'.padEnd(66, '2'), k_e_leaf: '33'.repeat(32), k_e_intent: '44'.repeat(32),
  passkey: passkeyHex, rp_id_hash: hex(sha(Buffer.from(RP))), backup_eligible: true, backup_state: true, guard: 'relay.testnet', guard_online: true, last_heartbeat: NOW - 1000,
  created_at: NOW - 600_000, csv: 6, script_pubkey: `0020${'77'.repeat(32)}`, address: 'tb1qexample', policy: POLICY, spend_epoch: rotation() ? 3 : 2, frozen_until: null, spend_nonce: 1,
  passkey_nonce: rotation() ? 1 : 0, cold_nonce: 0, pending: [...(pending && !rotation() && !live.first ? [1] : []), ...(live.second ? [2] : [])], storage_credit: '1000000000000000000000',
});
// `first`: how the first request ended, if not by a cancel: 'signed' by the contract, or 'expired' with nobody signing.
const request = (id = 1) => ({
  id, kind: 'Normal', status: id === 1 && live.first === 'signed' ? 'Signed' : 'Pending', epoch: id === 2 && rotation() ? 3 : 2, inputs: [{ txid: '88'.repeat(32), vout: 0, value: 2000 }],
  to: `0014${'99'.repeat(20)}`, amount: 1700, change: null, tier: 'New', fee: 300, proposed_at: NOW - 60_000, base_unlock: NOW + 240_000, unlock: NOW + 240_000,
  expires_at: id === 1 && live.first === 'expired' ? NOW - 1000 : NOW + 3_600_000, first_execute_at: null, attempt: 0,
  in_flight: 0, sigs: id === 1 && live.first === 'signed' ? ['aa'.repeat(64)] : [null], assessed: false, assess_hold: false, assess_reason: 'none', hold_used: false, hold_active: false,
});
const config = { mode: 'testnet', contract: 'c.testnet', rpc: ['https://rpc.example.test'], esplora: 'https://esplora.example.test/api', relay: '/api/relay', funds: '/api/funds', btcTxUrl: null, btcAddressUrl: null, nearTxUrl: null, rpId: RP, softPasskey: false, h7: false };
const instance = { signer: 'signer.testnet', domain_id: 0, sign_tgas: 30, callback_tgas: 10, network: 'signet', origins: [ORIGIN], policy: POLICY, expiry_window_ms: 3_600_000, block_ms: 1000, csv_min: 6, csv_max: 52_560, restrict_create: false, guard_model: 'model' };

const json = (value, status = 200) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });
const rpc = (result) => json({ jsonrpc: '2.0', id: 1, result });
const view = (value) => rpc({ result: [...Buffer.from(JSON.stringify(value))], block_height: 1000, logs: [] });
const posts = [];
const relayGets = [];

function vaultAnswer(id) {
  if (id === VAULT) return vaultRow(VAULT, hex(p256FromSpki(linked.spki)), live.pending);
  if (!made.has(id) && takenPasskey) {
    made.set(id, { passkey: takenPasskey });
    takenPasskey = null;
  }
  const row = made.get(id);
  if (!row) return null;
  return { ...vaultRow(id, row.passkey, live.pendingAfterCreate), active: !live.neverActive };
}
const pendingFor = (id) => (id === VAULT ? live.pending : made.has(id) && live.pendingAfterCreate);

globalThis.fetch = async (url, init = {}) => {
  const u = String(url);
  await sleep(live.netMs ?? 30);
  if (u === '/undo-config.json') return json(config);
  if (u === '/api/relay' && (init.method ?? 'GET') === 'GET') {
    relayGets.push(wall() - t0);
    // 'fail': no answer. 'page': a proxy's error page, not JSON. 'refused': the relay's own no, in its JSON.
    const how = nth(live.relayGet, relayGets.length - 1, 'ok');
    if (how === 'fail') throw new TypeError('Load failed');
    if (how === 'page') return new Response('<html><body>502 Bad Gateway</body></html>', { status: 502, headers: { 'content-type': 'text/html' } });
    if (how === 'refused') return json({ ok: false, code: 'relay_not_configured', message: 'the relay has no contract, account or RPC set' }, 503);
    return json(relayStatus());
  }
  if (u === '/api/relay' || u === '/api/funds') {
    const sent = JSON.parse(init.body);
    const method = u === '/api/funds' ? 'fund' : sent.method;
    posts.push(method);
    const refused = live.post?.[method];
    // 'fail': no answer at all, as when the connection drops after the request left.
    if (refused === 'fail') throw new TypeError('Load failed');
    // 'timeout': nothing comes back until the page's own time for an answer runs out. Whether the relay sent it after
    // all is the scenario's to say (`rotated`).
    if (refused === 'timeout') return new Promise((_, reject) => { init.signal?.addEventListener('abort', () => reject(init.signal.reason)); });
    if (refused) return json(refused.body, refused.status);
    if (method === 'create_vault') takenPasskey = sent.args.passkey.pubkey;
    if (method === 'cancel_all_and_rotate') rotatedTo = sent.args.new_k_s;
    if (method === 'fund') return json({ ok: true, txid: 'cc'.repeat(32) });
    return json({ ok: true, hash: 'H'.repeat(44), method });
  }
  if (u.startsWith('https://rpc.example.test')) {
    const { method, params } = JSON.parse(init.body);
    if (method === 'block') return rpc({ header: { hash: '1'.repeat(32), height: 1000, timestamp_nanosec: `${Date.now()}000000` } });
    if (method === 'tx') return rpc({ final_execution_status: 'EXECUTED_OPTIMISTIC', status: { SuccessValue: '' }, receipts_outcome: [] });
    if (method === 'query' && params.request_type === 'view_access_key_list') return rpc({ keys: [], block_height: 1000, block_hash: '1'.repeat(32) });
    if (method === 'query' && params.request_type === 'call_function') {
      const args = JSON.parse(Buffer.from(params.args_base64, 'base64').toString());
      if (params.method_name === 'instance') return view(instance);
      if (params.method_name === 'vault') return view(vaultAnswer(args.vault));
      // A cancelled request keeps its row, with the epoch it was made in: the vault's has moved on.
      if (params.method_name === 'request') {
        if (args.request === 2) return view(live.second ? request(2) : null);
        return view(args.request === 1 && (pendingFor(args.vault) || rotation()) ? request() : null);
      }
      if (params.method_name === 'derived_public_key') {
        kmReads.push(wall() - t0);
        // `kmDown`: no node answers the signer's view, as on a phone network that dropped after the first sheet.
        if (live.kmDown) throw new TypeError('Load failed');
        return view(`secp256k1:${base58Encode(new Uint8Array(64).fill(5))}`);
      }
    }
    return rpc(null);
  }
  // `coin`: the vault's address holds a coin, as after a funding that landed.
  if (u.startsWith('https://esplora.example.test')) return json(live.coin && u.endsWith('/utxo') ? [{ txid: 'cc'.repeat(32), vout: 0, value: 2000, status: { confirmed: false } }] : []);
  return new Response('not here', { status: 404 });
};
// ---------------------------------------------------------------- the steps

const screen = () => body.find('screen');
const state = () => document.documentElement.dataset.state ?? null;
const snaps = [];
const missed = [];
function snap(label) {
  const node = screen();
  const ids = node.all((n) => Boolean(n.id)).map((n) => n.id);
  const texts = Object.fromEntries(ids.map((id) => [id, body.find(id).textContent]));
  const order = node.kids.filter((k) => k instanceof Node).map((k) => k.id ?? k.tag);
  snaps.push({ label, at: wall() - t0, state: state(), text: node.textContent, buttons: node.querySelectorAll('button').map((b) => b.id), ids, texts, order, hash: location.hash, wake: { ...wake }, relayGets: relayGets.length });
}
const holds = (cond) => (cond.drawn ? state() !== null : cond.state ? state() === cond.state : cond.id ? Boolean(body.find(cond.id)) : cond.noId ? !body.find(cond.noId) : cond.text ? screen().textContent.includes(cond.text) : cond.post ? posts.includes(cond.post) : cond.relayGets ? relayGets.length >= cond.relayGets : false);
async function until(cond, max = 8000) {
  const end = wall() + max;
  while (wall() < end) {
    if (holds(cond)) return true;
    await sleep(20);
  }
  missed.push(cond);
  return false;
}

await import('../pages/p/phone.mjs');
await until(opts.boot ?? { drawn: true }, 6000);
if (opts.bootMs) await sleep(opts.bootMs);
for (const step of opts.steps ?? []) {
  if (step.set) Object.assign(live, step.set);
  if (step.tap) {
    const node = body.find(step.tap);
    if (node) node.click();
    else missed.push({ tap: step.tap });
  }
  if (step.hide) {
    document.hidden = true;
    fire('document', 'visibilitychange');
  }
  if (step.show) {
    document.hidden = false;
    fire('document', 'visibilitychange');
  }
  if (step.fire) fire('window', step.fire, { persisted: true });
  // A finger on the page somewhere that is not a button.
  if (step.touch) fire('document', 'pointerdown');
  if (step.until) await until(step.until, step.max);
  if (step.wait) await sleep(step.wait);
  if (step.snap) snap(step.snap);
}
process.stdout.write(`${JSON.stringify({ snaps, calls, posts, relayGets, kmReads, missed, assigned, platformAsked, drawn: drawn.filter((d, i) => d !== drawn[i - 1]).slice(-400), stored: globalThis.localStorage.keys(), session: globalThis.sessionStorage.keys() })}\n`);
process.exit(0);
