// Runs the phone page's own module in Node, with a made-up DOM and a fetch that answers each request after a delay,
// then prints what the page fetched and when, and the screen it drew. phone-boot.test.mjs starts it in a child
// process, because the page polls for as long as it lives. Every host and key here is made up.
//
//   node phone-boot-page.mjs '{"hash":"#v=...","delays":{"relay":300},"waitMs":2000}'
import { register } from 'node:module';

register('./page-hooks.mjs', import.meta.url);

const opts = JSON.parse(process.argv[2] ?? '{}');
const DELAY = opts.delayMs ?? 300;
const t0 = Date.now();
const fetched = [];
const sleep = (ms) => new Promise((r) => { setTimeout(r, ms); });

// ---------------------------------------------------------------- a DOM with just what the page touches

class Node {
  constructor(tag) {
    Object.assign(this, { tag, attrs: {}, kids: [], className: '', dataset: {}, value: '', hidden: false, style: {}, clientWidth: 0 });
    this.classList = { add() {}, remove() {}, toggle() {}, contains: () => false };
  }

  setAttribute(name, value) { this.attrs[name] = value; }

  get id() { return this.attrs.id ?? null; }

  addEventListener() {}

  removeEventListener() {}

  append(...kids) { for (const k of kids) this.kids.push(typeof k === 'string' ? { text: k } : k); }

  replaceChildren(...kids) { this.kids = []; this.append(...kids); }

  replaceWith() {}

  remove() {}

  focus() {}

  click() {}

  querySelector() { return null; }

  getBoundingClientRect() { return { top: 0, bottom: 0, left: 0, right: 0, width: 0, height: 0 }; }

  get textContent() { return this.kids.map((k) => (k instanceof Node ? k.textContent : k.text)).join('\n'); }

  set textContent(v) { this.kids = [{ text: String(v) }]; }

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
const store = () => {
  const m = new Map();
  return { getItem: (k) => m.get(k) ?? null, setItem: (k, v) => m.set(k, String(v)), removeItem: (k) => m.delete(k) };
};
globalThis.document = {
  documentElement: new Node('html'), body, hidden: false, createElement: (t) => new Node(t), getElementById: (id) => body.find(id),
  addEventListener() {}, removeEventListener() {}, querySelector: () => null,
};
globalThis.window = globalThis;
globalThis.addEventListener = () => {};
globalThis.removeEventListener = () => {};
globalThis.innerHeight = 844;
globalThis.innerWidth = 390;
globalThis.isSecureContext = true;
globalThis.sessionStorage = store();
globalThis.localStorage = store();
globalThis.requestAnimationFrame = () => 0;
globalThis.cancelAnimationFrame = () => {};
globalThis.scrollTo = () => {};
Object.defineProperty(globalThis, 'navigator', { value: { userAgent: 'node', maxTouchPoints: 0 }, configurable: true });
Object.defineProperty(globalThis, 'history', { value: { replaceState() {} }, configurable: true });
Object.defineProperty(globalThis, 'location', { value: { pathname: '/p/', hash: opts.hash ?? '', origin: 'https://undo.example.test', hostname: 'undo.example.test', host: 'undo.example.test', protocol: 'https:', reload() {} }, configurable: true });

// ---------------------------------------------------------------- the network: one config, a relay, a NEAR node

const NOW = Date.now();
const POLICY = { t_known_ms: 60_000, t_new_ms: 300_000, t_new_unguarded_ms: 600_000, hold_ms: 300_000, t_stuck_ms: 900_000, fee_cap_tx: 1000, fee_budget_24h: 2000, outflow_cap_24h: 1_000_000 };
const VAULT = 'ab'.repeat(32);
const answers = {
  config: { mode: 'testnet', contract: 'c.testnet', rpc: ['https://rpc.example.test'], esplora: 'https://esplora.example.test/api', relay: '/api/relay', funds: '/api/funds', btcTxUrl: null, btcAddressUrl: null, nearTxUrl: null, rpId: 'undo.example.test', softPasskey: false, h7: true },
  relay: { ok: true, relay_account: 'relay.testnet', contract: 'c.testnet', pow_bits: 8, owner: { up: true, why: null, degraded: false }, general: { up: true, why: null }, funds: { up: false, why: 'esplora_down', sats: 2000 } },
  instance: { signer: 'signer.testnet', domain_id: 0, sign_tgas: 30, callback_tgas: 10, network: 'signet', origins: ['https://undo.example.test'], policy: POLICY, expiry_window_ms: 3_600_000, block_ms: 1000, csv_min: 6, csv_max: 52_560, restrict_create: false, guard_model: 'model' },
  vault: {
    id: VAULT, active: true, k_s: '11'.repeat(32), k_s_suspended: false, k_u: '02'.padEnd(66, '1'), k_m: '02'.padEnd(66, '2'), k_e_leaf: '33'.repeat(32), k_e_intent: '44'.repeat(32),
    passkey: '04'.padEnd(130, '5'), rp_id_hash: '66'.repeat(32), backup_eligible: true, backup_state: true, guard: 'relay.testnet', guard_online: true, last_heartbeat: NOW - 1000,
    created_at: NOW - 600_000, csv: 6, script_pubkey: `0020${'77'.repeat(32)}`, address: 'tb1qexample', policy: POLICY, spend_epoch: 2, frozen_until: null, spend_nonce: 1,
    passkey_nonce: 0, cold_nonce: 0, pending: [1], storage_credit: '1000000000000000000000',
  },
  request: {
    id: 1, kind: 'Normal', status: 'Pending', epoch: 2, inputs: [{ txid: '88'.repeat(32), vout: 0, value: 2000 }], to: `0014${'99'.repeat(20)}`, amount: 1700, change: null,
    tier: 'New', fee: 300, proposed_at: NOW - 60_000, base_unlock: NOW + 240_000, unlock: NOW + 240_000, expires_at: NOW + 3_600_000, first_execute_at: null, attempt: 0,
    in_flight: 0, sigs: [null], assessed: false, assess_hold: false, assess_reason: 'none', hold_used: false, hold_active: false,
  },
};

function kindOf(url, init) {
  const u = String(url);
  if (u === '/undo-config.json') return { kind: 'config' };
  if (u === '/api/relay' && (init.method ?? 'GET') === 'GET') return { kind: 'relay' };
  if (u.startsWith('https://rpc.example.test')) {
    const { method, params } = JSON.parse(init.body);
    if (method === 'block') return { kind: 'block' };
    if (method === 'query' && params.request_type === 'call_function') return { kind: params.method_name, args: JSON.parse(Buffer.from(params.args_base64, 'base64').toString()) };
    return { kind: `rpc:${method}` };
  }
  if (u.startsWith('https://esplora.example.test')) return { kind: 'esplora' };
  return { kind: `other:${u}` };
}

const json = (value) => new Response(JSON.stringify(value), { status: 200, headers: { 'content-type': 'application/json' } });
const rpc = (result) => json({ jsonrpc: '2.0', id: 1, result });
const view = (value) => rpc({ result: [...Buffer.from(JSON.stringify(value))], block_height: 1000, logs: [] });

globalThis.fetch = async (url, init = {}) => {
  const { kind, args } = kindOf(url, init);
  const start = Date.now() - t0;
  await sleep(opts.delays?.[kind] ?? DELAY);
  fetched.push({ kind, start, end: Date.now() - t0 });
  switch (kind) {
    case 'config': return json(answers.config);
    case 'relay': return json(answers.relay);
    case 'block': return rpc({ header: { hash: '11111111111111111111111111111111', height: 1000, timestamp_nanosec: `${Date.now()}000000` } });
    case 'instance': return view(answers.instance);
    case 'vault': return view(args.vault === VAULT ? answers.vault : null);
    case 'request': return view(args.request === 1 ? answers.request : null);
    case 'esplora': return json([]);
    default: return new Response('not here', { status: 404 });
  }
};

await import('../pages/p/phone.mjs');
await sleep(opts.waitMs ?? DELAY * 8);
process.stdout.write(`${JSON.stringify({ fetched, state: document.documentElement.dataset.state ?? null, text: body.find('screen').textContent })}\n`);
process.exit(0);
