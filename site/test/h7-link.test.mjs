// The phone page's test mode and operator check, in Node with a made-up DOM, because a browser cannot run here. What
// a link may say, and what the report says. The modules are the ones the site ships.
import assert from 'node:assert/strict';
import { register } from 'node:module';
import { test } from 'node:test';
import { createECDH } from 'node:crypto';
import { toHex, utf8 } from '../../tools/lib/bytes.mjs';
import { p256, sha256 } from '../../tools/lib/crypto.mjs';

register('./page-hooks.mjs', import.meta.url);

class Node {
  constructor(tag) {
    Object.assign(this, { tag, attrs: {}, kids: [], className: '', dataset: {}, value: '', listeners: {} });
  }

  setAttribute(name, value) { this.attrs[name] = value; }

  get id() { return this.attrs.id ?? null; }

  addEventListener(type, fn) { (this.listeners[type] ??= []).push(fn); }

  append(...kids) { for (const k of kids) this.kids.push(typeof k === 'string' ? { text: k } : k); }

  replaceChildren(...kids) { this.kids = []; this.append(...kids); }

  replaceWith() {}

  remove() {}

  focus() {}

  select() {}

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

const screenNode = new Node('main');
screenNode.setAttribute('id', 'screen');
const store = new Map();
const hashes = [];
globalThis.document = {
  documentElement: new Node('html'), createElement: (t) => new Node(t), getElementById: (id) => screenNode.find(id), body: new Node('body'),
  hidden: false, addEventListener() {}, removeEventListener() {},
};
globalThis.addEventListener = () => {};
globalThis.removeEventListener = () => {};
globalThis.window = globalThis;
globalThis.sessionStorage = { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) };
globalThis.localStorage = { getItem: () => null, setItem: () => {} };
Object.defineProperty(globalThis, 'history', { value: { replaceState: (_s, _t, url) => hashes.push(url) }, configurable: true });
Object.defineProperty(globalThis, 'location', { value: { pathname: '/p/', hash: '', origin: 'https://undo-btc.pages.dev' }, configurable: true });
globalThis.requestAnimationFrame = () => 0;
globalThis.cancelAnimationFrame = () => {};
globalThis.scrollTo = () => {};

const { parsePhoneFragment, recallCredential, recallH7, rememberH7 } = await import('../pages/p/phone-fragment.mjs');
const { reportText, sFormSentence } = await import('../pages/p/h7-report.mjs');
const { runH7 } = await import('../pages/p/h7.mjs');
const { checkConfig } = await import('../lib/config.mjs');
const { softCredentials } = await import('../lib/soft-authenticator.mjs');
const { refusalOf } = await import('../lib/webauthn.mjs');

const config = checkConfig({ mode: 'testnet', contract: 'tmp-h7.example', rpc: ['https://rpc.example'], esplora: 'https://esplora.example', relay: '/api/relay', funds: '/api/funds', btcTxUrl: null, btcAddressUrl: null, nearTxUrl: null, rpId: 'undo-btc.pages.dev', softPasskey: false, h7: true });
const VAULT = 'ab'.repeat(32);
const settle = async () => { for (let i = 0; i < 30; i += 1) await new Promise((r) => { setImmediate(r); }); };
const planted = (() => { const e = createECDH('prime256v1'); e.generateKeys(); return e.getPublicKey('hex', 'compressed'); })();
const LOG = Array.from({ length: 8 }, () => 'c.l.900.2100.2600.n.30.8gZ1dzfAhVn1jZ1dzfAhVn1jZ1dzfAhVn1jZ').join('~');

function ctxWith({ suspended = false } = {}) {
  const calls = { create: 0, get: 0, relay: 0 };
  return {
    calls,
    ctx: {
      config,
      sense: { ua: 'node', inApp: null, api: true, secure: true, platform: true },
      views: { vault: async (v) => ({ id: v, k_s_suspended: suspended, pending: [], spend_nonce: 0, passkey_nonce: 0 }), request: async () => null, both: async () => ({}), script: async () => '' },
      reader: { blockTime: async () => ({ blockMs: Date.now() }), txOutcome: async () => ({ known: false }) },
      skew: { add() {}, sample() { return 0; } },
      relay: { call: async () => { calls.relay += 1; return { hash: 'x' }; }, status: async () => ({}) },
      credentials: { create: async () => { calls.create += 1; throw new Error('no'); }, get: async () => { calls.get += 1; throw new Error('no'); } },
      awake: { start() {}, stop() {}, state: 'on' },
    },
  };
}

test('AUDIT-5: a link cannot name the operator passkey, the tries or the flags: the parser drops them', () => {
  const f = parsePhoneFragment(`#h7=1&v=${VAULT}&pk=be1.bs1.l&aw=on&log=${LOG}&op=${planted}&opc=attackerCred_1&q=blank.one`);
  for (const name of ['op', 'opc', 'log', 'pk', 'aw', 'q']) assert.equal(f[name], undefined, name);
  assert.equal(f.v, VAULT, 'where to look still comes from the link');
  assert.equal(f.h7, '1');
});

test('AUDIT-5: a crafted link does not reach the report, and asks no passkey and no relay', async () => {
  store.clear();
  for (const suspended of [false, true]) {
    const { ctx, calls } = ctxWith({ suspended });
    location.hash = `#h7=1&v=${VAULT}&pk=be1.bs1.l&aw=on&log=${LOG}&op=${planted}&opc=attackerCred_1&q=blank.one`;
    runH7(ctx, parsePhoneFragment(location.hash), { general: { up: true }, owner: { up: true } });
    await settle();
    const state = document.documentElement.dataset.state;
    assert.notEqual(state, 'h7_report', `suspended=${suspended}: the link alone must not draw the report`);
    assert.equal(state, suspended ? 'h7_operator' : 'h7_stopped');
    assert.ok(!screenNode.textContent.includes(planted), 'the planted key is shown nowhere');
    assert.ok(!screenNode.textContent.includes('contract took it'), 'no try is claimed');
    assert.deepEqual(calls, { create: 0, get: 0, relay: 0 });
    assert.equal(recallH7().op, undefined, 'and nothing from the link was kept');
  }
});

test('AUDIT-5: what this tab made reaches the report, which says so, and a written-over record keeps only well-formed fields', async () => {
  store.clear();
  const made = toHex(p256.getPublicKey(sha256(utf8('undo-test-only:h7-op')), true));
  rememberH7({ v: VAULT, op: made, opc: 'ownCred_1', log: LOG, pk: 'be1.bs0.l', aw: 'on', q: 'blank.one', junk: 'x' });
  assert.deepEqual(Object.keys(recallH7()).sort(), ['aw', 'log', 'op', 'opc', 'pk', 'q', 'v']);
  const { ctx } = ctxWith();
  runH7(ctx, parsePhoneFragment(`#h7=1&v=${VAULT}`), { general: { up: true }, owner: { up: true } });
  await settle();
  assert.equal(document.documentElement.dataset.state, 'h7_report');
  const text = screenNode.find('report').textContent;
  assert.match(text, /Everything below was made or seen in this browser tab\. A link cannot add to it\./);
  assert.match(text, new RegExp(`"pubkey":"${made}"`));
  assert.match(text, /Passkey "test vault": made\. Can sync: yes\. Synced now: no\./);
  store.set('undo-h7', JSON.stringify({ v: VAULT, op: 'not-a-key', log: '<script>' }));
  assert.deepEqual(recallH7(), { v: VAULT });
});

test('a finished run in this tab stays out of the next: a link naming no vault, or another, starts with no tries and no operator passkey', async () => {
  const made = toHex(p256.getPublicKey(sha256(utf8('undo-test-only:h7-op')), true));
  for (const [link, state] of [['#h7=1', 'h7_check'], [`#h7=1&v=${'cd'.repeat(32)}`, 'h7_stopped']]) {
    store.clear();
    rememberH7({ v: VAULT, op: made, opc: 'ownCred_1', log: LOG, pk: 'be1.bs0.l', aw: 'on', q: 'blank.one' });
    const { ctx } = ctxWith();
    runH7(ctx, parsePhoneFragment(link), { general: { up: true }, owner: { up: true } });
    await settle();
    assert.equal(document.documentElement.dataset.state, state, link);
    assert.deepEqual(window.undoH7.tries, [], `${link}: no tries from the earlier run`);
    assert.equal(window.undoH7.kept.op, undefined, `${link}: no operator passkey from the earlier run`);
  }
  // What Start again keeps, the tries with no vault yet, still counts.
  store.clear();
  rememberH7({ log: LOG });
  runH7(ctxWith().ctx, parsePhoneFragment('#h7=1'), { general: { up: true }, owner: { up: true } });
  await settle();
  assert.equal(window.undoH7.tries.length, 8);
});

test('AUDIT-5: the operator check signs only the deploy\'s own digest, which the deploy can check against the key', async () => {
  const { runOperatorCheck } = await import('../pages/p/operator-check.mjs');
  const { operatorProofDigest } = await import('../../tools/lib/operator-proof.mjs');
  const secret = sha256(utf8('undo-test-only:operator-check'));
  const credentials = softCredentials({ secret, origin: 'https://undo-btc.pages.dev', rpId: 'undo-btc.pages.dev' });
  const nonce = 'cd'.repeat(32);
  const instance = 'v1.s.example';
  const { ctx } = ctxWith();
  ctx.credentials = credentials;
  Object.defineProperty(globalThis, 'navigator', { value: { clipboard: { writeText: async () => {} } }, configurable: true });
  runOperatorCheck(ctx, { nonce, instance });
  assert.equal(document.documentElement.dataset.state, 'op_check');
  assert.match(screenNode.textContent, /signs one check for v1\.s\.example, and nothing else/);
  screenNode.find('op-sign').listeners.click[0]();
  await settle();
  assert.equal(document.documentElement.dataset.state, 'op_signed');
  const proof = JSON.parse(screenNode.find('op-proof').textContent);
  assert.deepEqual([proof.format, proof.instance, proof.nonce], ['undo-operator-proof-v1', instance, nonce]);
  const args = { authenticator_data: proof.authenticator_data, client_data_json: proof.client_data_json, signature: proof.signature };
  const check = (pub) => refusalOf({ assertion: args, digest: operatorProofDigest({ instance, nonce }), pubkey: pub, rpIdHash: sha256(utf8('undo-btc.pages.dev')), origins: ['https://undo-btc.pages.dev'] });
  assert.equal(check(p256.getPublicKey(secret, true)), null, 'the key that signed passes');
  assert.equal(check(p256.getPublicKey(sha256(utf8('another key')), true)), 'webauthn: bad signature', 'any other key does not');
  assert.equal(refusalOf({ assertion: args, digest: operatorProofDigest({ instance, nonce: 'ef'.repeat(32) }), pubkey: p256.getPublicKey(secret, true), rpIdHash: sha256(utf8('undo-btc.pages.dev')), origins: ['https://undo-btc.pages.dev'] }), 'webauthn: wrong challenge', 'nor another nonce');
  const link = parsePhoneFragment(`#opproof=${nonce}&opfor=${instance}`);
  assert.deepEqual([link.opproof, link.opfor], [nonce, instance]);
  assert.equal(parsePhoneFragment('#opproof=zz&opfor=a').opproof, undefined);
  for (const short of [nonce.slice(1), `${nonce}a`]) {
    const out = parsePhoneFragment(`#opproof=${short}&opfor=${instance}`);
    assert.deepEqual([out.opproof, out.refused], [undefined, ['opproof']], `a nonce of ${short.length} characters is not the deploy's`);
  }
});

test('a stored credential id is used only in its own form: junk under the key cannot break Cancel', () => {
  const kept = new Map();
  const win = { localStorage: { getItem: (k) => kept.get(k) ?? null, setItem: (k, v) => kept.set(k, v) } };
  assert.equal(recallCredential(VAULT, win), null);
  kept.set(`undo.passkey.${VAULT}`, 'ownCred_1-x');
  assert.equal(recallCredential(VAULT, win), 'ownCred_1-x');
  for (const junk of ['bad id!', '<script>', '', 'a'.repeat(513)]) {
    kept.set(`undo.passkey.${VAULT}`, junk);
    assert.equal(recallCredential(VAULT, win), null, JSON.stringify(junk.slice(0, 20)));
  }
  assert.equal(recallCredential(VAULT, { get localStorage() { throw new Error('blocked'); } }), null, 'and storage that throws is no id');
});

test('the report says which call each try was and its S form, and claims no high-S result before eight tries', () => {
  const tryOf = (m, s) => ({ m, s, sheetMs: 900, includedMs: 2100, readMs: 2600, hidden: false, blurred: false, pagehide: false, stallMs: 30, hash: null });
  const base = { sense: { ua: 'node', inApp: null, api: true, secure: true, platform: true }, config, passkeyFlags: { be: true, bs: false }, operator: null, answers: {}, vault: VAULT };
  // What a line says, not its wording: the call it names, its S-form tokens, and its try count.
  const lines = (over) => reportText({ ...base, ...over }).split('\n');
  const line = (all, start) => all.find((l) => l.startsWith(start)) ?? '';
  const sForms = (text) => text.match(/\b(high|low)-S\b/g) ?? [];
  const callOf = (text) => /^Try \d+: ([a-z_]+)\b/.exec(text)?.[1] ?? null;
  const mixed = lines({ proofS: 'l', tries: [tryOf('c', 'l'), tryOf('r', 'h')] });
  assert.deepEqual(sForms(line(mixed, 'Creation tap')), ['low-S'], mixed.join('\n'));
  assert.deepEqual(sForms(line(lines({ proofS: 'h', tries: [] }), 'Creation tap')), ['high-S']);
  assert.deepEqual([callOf(line(mixed, 'Try 1:')), sForms(line(mixed, 'Try 1:'))], ['cancel', ['low-S']], mixed.join('\n'));
  assert.deepEqual([callOf(line(mixed, 'Try 2:')), sForms(line(mixed, 'Try 2:'))], ['cancel_all_and_rotate', ['high-S']], mixed.join('\n'));
  const found = sFormSentence([tryOf('c', 'l'), tryOf('r', 'h')]);
  assert.match(found, /\bhigh-S\b.*\btry 2 of 2\b/, 'a high-S try is named, with its place among the tries');
  assert.ok(mixed.includes(found), `the report carries that sentence as its own line\n${mixed.join('\n')}`);
  for (let n = 1; n < 8; n += 1) {
    const sofar = sFormSentence(Array(n).fill(tryOf('c', 'l')));
    assert.match(sofar, new RegExp(`\\b${n} of 8\\b`), `${n} tries`);
    assert.doesNotMatch(sofar, /^No high-S/, `no claim of none after ${n} tries`);
  }
  const eightTries = Array(8).fill(tryOf('c', 'l'));
  const eight = sFormSentence(eightTries);
  assert.match(eight, /^No high-S\b.*\b8 tries\b/, 'after eight tries, the claim of none');
  assert.doesNotMatch(eight, /\bof 8\b/);
  const eightReport = lines({ proofS: 'l', tries: eightTries });
  assert.ok(eightReport.includes(eight), `and the report carries it\n${eightReport.join('\n')}`);
});
