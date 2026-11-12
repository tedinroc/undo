// T11: /try/ on the local stage, start to end: the real contract wasm, a local NEAR node, regtest bitcoind behind an
// Esplora stand-in, the mock signer, the in-Node relay, and Chrome with its virtual authenticator for navigator.credentials
// (softPasskey off). Three real clicks. Then the chain is read: the vault made, the request proposed and gone from
// pending, the cancel's rotation, the coin unspent, and K2: the key-alone send of a coin that is still UNCONFIRMED (no
// miner runs here) was refused by the node for its script. [mock-signer]
//
// v1 (CANCEL_HERE false): /try/ hands the tab to /p/#v&r&c, and /p/'s Cancel is clicked there.
// v2 (CANCEL_HERE true): Cancel is clicked on /try/; once plainly, and once with the cancel POST answered with nothing
// while the relay sent it (relay_down): the chain decides.
import assert from 'node:assert/strict';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { classifyBroadcast } from '../../tools/lib/esplora.mjs';
import { NearReader } from '../lib/near-read.mjs';
import { requestState } from '../lib/request-state.mjs';
import { contractViews } from '../lib/views.mjs';
import { chromeAvailable, startChrome } from './chrome.mjs';
import { stageAvailable, startStage } from './stage.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const CANCEL_HERE = /export const CANCEL_HERE = true;/.test(readFileSync(join(HERE, '../pages/try/try.mjs'), 'utf8'));
const skip = !stageAvailable() ? 'set NEAR_SANDBOX_BIN_PATH and UNDO_WASM_DIR to run this against the real wasm' : !chromeAvailable() ? 'no Chrome' : false;
const SHOTS = process.env.UNDO_TRY_SHOTS ?? null;
const sleep = (ms) => new Promise((r) => { setTimeout(r, ms); });

// Every click listener runs with a depth above zero; every navigator.credentials call records the depth it was made at.
const SPY = `(() => {
  const depth = { n: 0, target: null };
  const add = EventTarget.prototype.addEventListener;
  const wrapped = new WeakMap();
  EventTarget.prototype.addEventListener = function (type, fn, opts) {
    if (type !== 'click' || typeof fn !== 'function') return add.call(this, type, fn, opts);
    let w = wrapped.get(fn);
    if (!w) {
      w = function (event) {
        depth.n += 1;
        const before = depth.target;
        depth.target = (event && event.currentTarget && event.currentTarget.id) || '?';
        try { return fn.call(this, event); } finally { depth.n -= 1; depth.target = before; }
      };
      wrapped.set(fn, w);
    }
    return add.call(this, type, w, opts);
  };
  const log = (entry) => {
    const all = JSON.parse(sessionStorage.getItem('__spy') || '[]');
    all.push(entry);
    sessionStorage.setItem('__spy', JSON.stringify(all));
  };
  const c = navigator.credentials;
  for (const op of ['create', 'get']) {
    const real = c[op].bind(c);
    c[op] = (options) => {
      log({ op, inClick: depth.n > 0, button: depth.target, page: location.pathname, signal: Boolean(options && options.signal) });
      return real(options);
    };
  }
  const realFetch = window.fetch.bind(window);
  window.fetch = async (url, init = {}) => {
    const res = await realFetch(url, init);
    const u = String(url);
    if ((init.method || 'GET') === 'POST' && (u.endsWith('/tx') || u.includes('/api/'))) {
      const method = u.endsWith('/tx') ? 'tx' : u.endsWith('/api/funds') ? 'fund' : (() => { try { return JSON.parse(init.body).method; } catch { return '?'; } })();
      const body = method === 'tx' ? await res.clone().text() : null;
      log({ post: method, status: res.status, inClick: depth.n > 0, page: location.pathname, body });
    }
    return res;
  };
})();`;

let stage;
let browser;
let cdp;
let views;
let reader;
const consoleLines = [];

before(async () => {
  if (skip) return;
  // No miner: the test coin stays unconfirmed, which is the coin the page steals on Mutinynet too (K2).
  stage = await startStage({ miner: false, softPasskey: false, relayEnv: { STATUS_CACHE_MS: 0, CEILING_GENERAL_MICRO: 10_000_000 } });
  reader = new NearReader({ urls: stage.config.rpc, timeoutMs: 15_000 });
  views = contractViews(reader, stage.contract);
  browser = await startChrome({ width: 390, height: 844, scale: 2 });
  ({ cdp } = browser);
  await cdp.send('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 2, mobile: true });
  await cdp.send('WebAuthn.enable');
  await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
  await cdp.send('Page.addScriptToEvaluateOnNewDocument', { source: SPY });
  cdp.ws.addEventListener('message', (event) => {
    const data = JSON.parse(event.data);
    if (data.method === 'Runtime.consoleAPICalled') consoleLines.push(data.params.args.map((a) => a.value ?? a.description ?? '').join(' '));
    // A page that still holds a vault's keys asks before it is left (beforeunload): a run that stopped half way must not
    // hold up the next one's navigation, so the question is answered yes.
    if (data.method === 'Page.javascriptDialogOpening') cdp.send('Page.handleJavaScriptDialog', { accept: true }).catch(() => {});
  });
}, { timeout: 240_000 });

after(async () => {
  await browser?.stop();
  await stage?.stop();
});

const state = () => cdp.page('return { path: location.pathname, step: document.documentElement.dataset.step ?? null, state: document.documentElement.dataset.state ?? null, fail: document.documentElement.dataset.fail ?? null };');

async function waitFor(what, fn, timeoutMs = 30_000) {
  const end = Date.now() + timeoutMs;
  let last;
  while (Date.now() < end) {
    last = await fn().catch(() => null);
    if (last) return last;
    await sleep(150);
  }
  const text = await cdp.page('return document.body.innerText;').catch(() => '?');
  throw new Error(`never saw ${what}. ${JSON.stringify(await state().catch(() => null))} Screen: ${text}`);
}

async function clickOn(selector) {
  const box = await cdp.page(`const e = document.querySelector(${JSON.stringify(selector)}); if (!e) return null; const r = e.getBoundingClientRect(); return { x: r.x + r.width / 2, y: r.y + r.height / 2, top: r.top, bottom: r.bottom };`);
  assert.ok(box, `no ${selector}`);
  assert.ok(box.top >= 0 && box.bottom <= 844, `${selector} is not whole on the 844 px screen: ${JSON.stringify(box)}`);
  await cdp.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: box.x, y: box.y });
  await cdp.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: box.x, y: box.y, button: 'left', clickCount: 1 });
  await cdp.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: box.x, y: box.y, button: 'left', clickCount: 1 });
}

async function shot(name) {
  if (!SHOTS) return;
  mkdirSync(SHOTS, { recursive: true });
  const { data } = await cdp.send('Page.captureScreenshot', { format: 'png' });
  writeFileSync(join(SHOTS, `${name}.png`), Buffer.from(data, 'base64'));
}

const spyLog = () => cdp.page('return JSON.parse(sessionStorage.getItem("__spy") || "[]");');

/** One run from the first screen to CANCELLED. `lostCancel`: the cancel POST reaches the relay, and the page hears nothing back. */
async function runOnce({ lostCancel = false } = {}) {
  await cdp.send('Page.navigate', { url: 'about:blank' });
  await sleep(100);
  await cdp.page('sessionStorage.clear(); return true;').catch(() => {});
  await cdp.send('Page.navigate', { url: `${stage.origin}/try/` });
  await waitFor('the first screen', async () => (await state()).state === 'ready', 40_000);
  await shot(`${lostCancel ? 'b' : 'a'}-00-ready`);
  await clickOn('#make');
  await waitFor('Confirm', () => cdp.page('return Boolean(document.getElementById("confirm"));'), 40_000);
  await shot(`${lostCancel ? 'b' : 'a'}-01-confirm`);
  await clickOn('#confirm');
  await waitFor('the theft refused by the node', async () => ['refused', 'asking', 'handoff', 'request'].includes((await state()).state) || (await state()).path === '/p/', 120_000);
  await shot(`${lostCancel ? 'b' : 'a'}-02-refused`);
  let vaultHex;
  let requestId;
  if (!CANCEL_HERE) {
    await waitFor('the phone page with the request', async () => {
      const s = await state();
      return s.path === '/p/' && s.state === 'request';
    }, 90_000);
    const hash = new URLSearchParams((await cdp.page('return location.hash;')).slice(1));
    vaultHex = hash.get('v');
    requestId = Number(hash.get('r'));
    assert.ok(hash.get('c'), 'the credential the page made goes with the hand-off');
    assert.equal(hash.get('k'), null);
    await shot('a-03-phone-request');
    await clickOn('#cancel');
    await waitFor('CANCELLED on the phone page', async () => (await state()).state === 'cancelled', 60_000);
    await shot('a-04-cancelled');
  } else {
    await waitFor('the request and Cancel on this page', () => cdp.page('return Boolean(document.getElementById("cancel"));'), 90_000);
    // Cancel rises into the dock in 220 ms; it is measured and clicked where it rests.
    await sleep(600);
    await shot(`${lostCancel ? 'b' : 'a'}-03-request`);
    const hash = new URLSearchParams((await cdp.page('return location.hash;')).slice(1));
    vaultHex = hash.get('v');
    if (lostCancel) {
      // The page's own cancel POST is forwarded to the relay from here, and the page gets no answer: relay_down.
      await cdp.send('Fetch.enable', { patterns: [{ urlPattern: '*/api/relay', requestStage: 'Request' }] });
      const onPaused = async (event) => {
        const data = JSON.parse(event.data);
        if (data.method !== 'Fetch.requestPaused') return;
        const { requestId: id, request } = data.params;
        if (request.method === 'POST' && /cancel_all_and_rotate/.test(request.postData ?? '')) {
          await stage.api('/api/relay', JSON.parse(request.postData));
          await cdp.send('Fetch.failRequest', { requestId: id, errorReason: 'ConnectionReset' });
        } else await cdp.send('Fetch.continueRequest', { requestId: id });
      };
      cdp.ws.addEventListener('message', onPaused);
      await clickOn('#cancel');
      await waitFor('CANCELLED read from the contract', async () => ['cancelled', 'recap'].includes((await state()).step), 90_000);
      cdp.ws.removeEventListener('message', onPaused);
      await cdp.send('Fetch.disable');
    } else {
      await clickOn('#cancel');
      await waitFor('CANCELLED', async () => ['cancelled', 'recap'].includes((await state()).step), 60_000);
    }
    await shot(`${lostCancel ? 'b' : 'a'}-04-cancelled`);
    await waitFor('the recap', async () => (await state()).step === 'recap', 15_000);
    await shot(`${lostCancel ? 'b' : 'a'}-05-recap`);
    const items = await views.vault(vaultHex);
    requestId = null;
    for (let id = 0; id < 64 && requestId === null; id += 1) if (await views.request(vaultHex, id)) requestId = id;
    assert.ok(items);
  }
  return { vaultHex, requestId, spy: await spyLog(), screen: await cdp.page('return document.body.innerText;') };
}

async function chainSays({ vaultHex, requestId }) {
  const vault = await views.vault(vaultHex);
  assert.ok(vault?.active, 'the vault the page made is active on the contract');
  assert.ok(vault.k_s_suspended, 'the cancel rotated the spend key out: cancel_all_and_rotate ran');
  // A rotation moves the vault's epoch at once; the row may stay listed until a later change sweeps it, and a Pending
  // request of an old epoch is cancelled (request-state.mjs). So: gone from pending, or listed and of an old epoch.
  const request = await views.request(vaultHex, requestId);
  const block = await reader.blockTime();
  if (vault.pending.includes(requestId)) assert.notEqual(request.epoch, vault.spend_epoch, 'still pending in the vault\'s own epoch');
  if (request) assert.equal(requestState({ request, vault, chainNow: block.blockMs }).kind, 'cancelled', 'the request reads cancelled');
  for (const coin of request?.inputs ?? []) {
    const out = await (await fetch(`${stage.config.esplora}/tx/${coin.txid}/outspend/${coin.vout}`)).json();
    assert.equal(out.spent, false, 'the coin is unspent');
  }
  return { vault, request };
}

test('T11: the whole run on the local stage, three clicks, each passkey call in its click; the chain says what the page said [mock-signer]', { skip, timeout: 420_000 }, async (t) => {
  const run = await runOnce();
  const { request } = await chainSays(run);
  assert.ok(request, 'the proposal made a request on the contract');
  const creds = run.spy.filter((e) => e.op);
  t.diagnostic(`credentials: ${JSON.stringify(creds)}`);
  assert.deepEqual(creds.map((e) => e.op), ['create', 'get', 'get']);
  assert.ok(creds.every((e) => e.inClick && e.signal), JSON.stringify(creds));
  assert.deepEqual(creds.map((e) => e.page), CANCEL_HERE ? ['/try/', '/try/', '/try/'] : ['/try/', '/try/', '/p/']);
  const posts = run.spy.filter((e) => e.post);
  t.diagnostic(`posts: ${JSON.stringify(posts.map((p) => [p.post, p.status, p.inClick]))}`);
  for (const method of ['create_vault', 'fund', 'tx', 'propose_btc', 'cancel_all_and_rotate']) {
    const these = posts.filter((p) => p.post === method);
    assert.equal(these.length, 1, `${method}: ${these.length}`);
  }
  for (const method of ['fund', 'tx', 'propose_btc']) assert.equal(posts.find((p) => p.post === method).inClick, false, `${method} with no click`);
  for (const method of ['create_vault', 'fund', 'propose_btc', 'cancel_all_and_rotate']) assert.equal(posts.find((p) => p.post === method).status, 200, method);
  // K2: the coin was unconfirmed (no miner), and the node refused the key-alone spend for its script.
  const tx = posts.find((p) => p.post === 'tx');
  t.diagnostic(`node: ${tx.status} ${tx.body}`);
  const answer = classifyBroadcast(tx.status, tx.body, '');
  assert.equal(answer.kind, 'rejected');
  assert.equal(answer.refusal, 'script', tx.body);
  const coin = request.inputs[0];
  const status = await (await fetch(`${stage.config.esplora}/tx/${coin.txid}/status`)).json();
  assert.equal(status.confirmed, false, 'the coin the page stole was unconfirmed');
  assert.match(run.screen, /CANCELLED/);
  for (const line of consoleLines) assert.doesNotMatch(line, /Uncaught|TypeError|ReferenceError/, line);
});

test('T11: with the cancel POST answered by nothing while the relay sent it, the chain decides: CANCELLED (v2) [mock-signer]', { skip: skip || (CANCEL_HERE ? false : 'v1: /p/ owns the cancel'), timeout: 420_000 }, async () => {
  const run = await runOnce({ lostCancel: true });
  await chainSays(run);
  assert.match(run.screen, /The contract reads this request cancelled\./);
});

// S0 on a short phone (UX-SPEC 4: one column, no page scroll on the main path; worst cases 375x548 and 320x568): #screen
// needs no scrolling, and every line of text in the column, the footer under the links included, lies whole inside it
// (each line box, not each element: a paragraph cut at the fold has its upper lines whole). In Safari, inside an app's
// own browser (its line about the app comes first), and with the hint of vaults this browser made in the past hour. A
// screen that fits as drawn keeps its sizes; a resize fits again; the classes go when the page leaves S0.
const IOS_SAFARI = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1';
const X_APP = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Twitter for iPhone/11.20';
const FIT_STEPS = /\b(tight|tighter|tightest|dense|densest)\b/;
const S0_MEASURE = `
  const scr = document.getElementById('screen');
  const frame = document.getElementById('frame');
  const box = scr.getBoundingClientRect();
  const clip = { t: Math.max(0, box.top + scr.clientTop), b: Math.min(innerHeight, box.top + scr.clientTop + scr.clientHeight), l: Math.max(0, box.left), r: Math.min(innerWidth, box.right) };
  const shown = (el) => { for (let p = el; p; p = p.parentElement) { const cs = getComputedStyle(p); if (cs.display === 'none' || cs.visibility === 'hidden') return false; } return true; };
  const cut = [];
  let lines = 0;
  const walker = document.createTreeWalker(scr, NodeFilter.SHOW_TEXT);
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    if (!n.textContent.trim() || !n.parentElement || n.parentElement.closest('noscript') || !shown(n.parentElement)) continue;
    const range = document.createRange();
    range.selectNodeContents(n);
    for (const r of range.getClientRects()) {
      if (r.width < 0.5 || r.height < 0.5) continue;
      lines += 1;
      if (r.top < clip.t - 0.5 || r.bottom > clip.b + 0.5 || r.left < clip.l - 0.5 || r.right > clip.r + 0.5) cut.push((n.parentElement.id || n.parentElement.className || n.parentElement.tagName) + ' ' + Math.round(r.bottom - clip.b));
    }
  }
  const px = (id) => { const el = document.getElementById(id); return el ? parseFloat(getComputedStyle(el).fontSize) : null; };
  const next = document.getElementById('next').getBoundingClientRect();
  const go = document.querySelector('#dock .go, #dock .slot').getBoundingClientRect();
  return { state: document.documentElement.dataset.step + '/' + document.documentElement.dataset.state, over: scr.scrollHeight - scr.clientHeight, cut, lines,
    cls: frame.className, foot: Boolean(document.getElementById('foot')), inApp: Boolean(document.getElementById('in-app')), hint: Boolean(document.getElementById('made-hint')),
    title: px('title'), footPx: px('foot'), nextWhole: next.top >= clip.b - 0.5 && next.bottom <= innerHeight, goWhole: go.top >= 0 && go.bottom <= innerHeight + 0.5 };`;

test('S0 on a short phone, in Safari and inside an app: no scrolling, every line whole, the footer included', { skip, timeout: 240_000 }, async (t) => {
  const plainUa = await cdp.page('return navigator.userAgent;');
  const size = (width, height) => cdp.send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 2, mobile: true });
  // The runs above left their Make times in this browser: each S0 here is drawn after they are set as the case says.
  const open = async (made = 0) => {
    await cdp.send('Page.navigate', { url: 'about:blank' });
    await sleep(100);
    await cdp.send('Page.navigate', { url: `${stage.origin}/try/` });
    await waitFor('S0', async () => (await state()).state === 'ready', 40_000);
    await cdp.page(`localStorage.setItem('undo-try:made', JSON.stringify(Array.from({ length: ${made} }, (_, i) => Date.now() - (i + 1) * 60000))); return true;`);
    await cdp.send('Page.reload');
    await sleep(200);
    await waitFor('S0 again', async () => (await state()).state === 'ready', 40_000);
    await sleep(300);
  };
  const measure = () => cdp.page(S0_MEASURE);
  const whole = (m, label) => {
    t.diagnostic(`${label}: over ${m.over}, ${m.lines} lines, classes "${m.cls}", title ${m.title}px, foot ${m.footPx}px`);
    assert.equal(m.state, 'intro/ready', label);
    assert.ok(m.foot, `${label}: the footer is drawn`);
    assert.ok(m.over <= 0, `${label}: #screen is ${m.over} px taller than its box`);
    assert.deepEqual(m.cut, [], `${label}: lines not whole in #screen`);
    assert.ok(m.nextWhole && m.goWhole, `${label}: the Next line and the button whole under #screen`);
    assert.ok(m.footPx >= 11, `${label}: the footer at ${m.footPx}px`);
  };
  try {
    for (const [ua, name] of [[IOS_SAFARI, 'Safari'], [X_APP, 'the X app']]) {
      await cdp.send('Emulation.setUserAgentOverride', { userAgent: ua });
      for (const [width, height] of [[390, 844], [390, 664], [375, 548], [320, 568]]) {
        await size(width, height);
        await open();
        const m = await measure();
        whole(m, `${name} ${width}x${height}`);
        assert.equal(m.inApp, ua === X_APP, `the line about the app at ${width}x${height}`);
        assert.equal(m.hint, false, `no made-in-the-past-hour hint at ${width}x${height}`);
        // A screen that fits as drawn keeps its sizes.
        if (ua === IOS_SAFARI && height === 844) assert.doesNotMatch(m.cls, FIT_STEPS, 'Safari 390x844 fits as drawn');
        if (ua === IOS_SAFARI && height === 844) assert.equal(m.title, 32);
      }
    }
    // The hint of vaults made in the past hour adds a paragraph: still whole, inside the app, on the narrowest phone.
    await cdp.send('Emulation.setUserAgentOverride', { userAgent: X_APP });
    await size(320, 568);
    await open(2);
    const hinted = await measure();
    assert.ok(hinted.hint && hinted.inApp, 'the hint and the line about the app are both up');
    whole(hinted, 'the X app 320x568 with the made-in-the-past-hour hint');
    // A resize fits again: up to a tall screen, the sizes come back; down again, the fit comes back.
    await cdp.send('Emulation.setUserAgentOverride', { userAgent: IOS_SAFARI });
    await size(375, 548);
    await open();
    const small = await measure();
    whole(small, 'Safari 375x548 before the resizes');
    assert.match(small.cls, FIT_STEPS, 'Safari 375x548 needs a step');
    await size(390, 844);
    await sleep(300);
    const tall = await measure();
    whole(tall, 'Safari 375x548 -> 390x844');
    assert.doesNotMatch(tall.cls, FIT_STEPS, 'back on a tall screen, S0 is drawn as it was');
    await size(320, 568);
    await sleep(300);
    whole(await measure(), 'Safari 390x844 -> 320x568');
    // Leaving S0 (the Make tap: the first sheet; no vault is made before the second) takes the classes off.
    await clickOn('#make');
    await waitFor('step 1', async () => (await state()).step === 'make', 20_000);
    assert.doesNotMatch(await cdp.page('return document.getElementById("frame").className;'), FIT_STEPS, 'step 1 is drawn at its own sizes');
  } finally {
    await cdp.send('Page.navigate', { url: 'about:blank' }).catch(() => {});
    await sleep(200);
    await cdp.send('Emulation.setUserAgentOverride', { userAgent: plainUa });
    await size(390, 844);
  }
});

// The page as the live site draws it: its chip ("signet test coins", from the testnet labels) is short enough that
// "Undo for Bitcoin" fits beside it at some sizes, as the WebKit runs serve it. Only the labels change; the stage is local.
const CONFIG_SOURCE = readFileSync(join(HERE, '../lib/config.mjs'), 'utf8');
const LIVE_LABELS = CONFIG_SOURCE.replace(/local: \{ chip: [^}]*\}/, 'local: { chip: \'signet test coins\', near: \'NEAR testnet\', bitcoin: \'Mutinynet\' }');
async function withLiveLabels(fn) {
  assert.notEqual(LIVE_LABELS, CONFIG_SOURCE, 'site/lib/config.mjs has no local labels line to swap');
  const onPaused = (event) => {
    const data = JSON.parse(event.data);
    if (data.method !== 'Fetch.requestPaused') return;
    const { requestId, request } = data.params;
    if (/\/site\/lib\/config\.mjs(\?|$)/.test(request.url)) {
      cdp.send('Fetch.fulfillRequest', { requestId, responseCode: 200, responseHeaders: [{ name: 'content-type', value: 'text/javascript' }, { name: 'cache-control', value: 'no-store' }], body: Buffer.from(LIVE_LABELS).toString('base64') }).catch(() => {});
    } else cdp.send('Fetch.continueRequest', { requestId }).catch(() => {});
  };
  cdp.ws.addEventListener('message', onPaused);
  await cdp.send('Fetch.enable', { patterns: [{ urlPattern: '*/site/lib/config.mjs*', requestStage: 'Request' }] });
  try {
    return await fn();
  } finally {
    await cdp.send('Fetch.disable').catch(() => {});
    cdp.ws.removeEventListener('message', onPaused);
  }
}

// Set in localStorage before a reload, read at the document's start: the browser reports no passkey manager or screen
// lock it can use (isUserVerifyingPlatformAuthenticatorAvailable false, as an app's own browser often does), with no
// userAgentData, as Safari on an iPhone has none (Chrome's would say a desktop under the iPhone user agent); and the
// relay's coin side down (its status, as the page reads it, says so); and the passkey sheet closed with no passkey 1.5 s
// after it is asked for (NotAllowedError, as a closed sheet answers: M1), in place of the virtual authenticator's answer.
const TEST_FLAGS = `(() => {
  let flags = {};
  try { flags = { uvpaa: localStorage.getItem('__test_uvpaa'), fundsDown: localStorage.getItem('__test_funds_down'), dismiss: localStorage.getItem('__test_dismiss') }; } catch { return; }
  if (flags.uvpaa === 'false') {
    try { Object.defineProperty(Navigator.prototype, 'userAgentData', { get: () => undefined, configurable: true }); } catch {}
    if (window.PublicKeyCredential) window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = () => Promise.resolve(false);
  }
  if (flags.fundsDown === 'true') {
    const real = window.fetch.bind(window);
    window.fetch = async (url, init = {}) => {
      const res = await real(url, init);
      if ((init.method || 'GET') !== 'GET' || !String(url).endsWith('/api/relay')) return res;
      const data = await res.clone().json().catch(() => null);
      if (!data || !data.funds) return res;
      return new Response(JSON.stringify({ ...data, funds: { ...data.funds, up: false, why: 'daily_ceiling', resets_at: null } }), { status: res.status, headers: { 'content-type': 'application/json' } });
    };
  }
  if (flags.dismiss === 'true') {
    navigator.credentials.create = () => new Promise((_, reject) => { setTimeout(() => reject(new DOMException('This request has been cancelled by the user.', 'NotAllowedError')), 1500); });
  }
})();`;
const FLAG_KEYS = ['__test_uvpaa', '__test_funds_down', '__test_dismiss'];

/** S0 drawn fresh, with `made` Make times in the past hour and the flags above, after a reload. */
async function openS0({ made = 0, flags = {} } = {}) {
  await cdp.send('Page.navigate', { url: 'about:blank' });
  await sleep(100);
  await cdp.send('Page.navigate', { url: `${stage.origin}/try/` });
  const drawn = async () => ['ready', 'blocked'].includes((await state()).state);
  await waitFor('S0', drawn, 40_000);
  await cdp.page(`localStorage.setItem('undo-try:made', JSON.stringify(Array.from({ length: ${made} }, (_, i) => Date.now() - (i + 1) * 60000)));
    for (const k of ${JSON.stringify(FLAG_KEYS)}) localStorage.removeItem(k);
    for (const [k, v] of Object.entries(${JSON.stringify(flags)})) localStorage.setItem(k, v);
    return true;`);
  await cdp.send('Page.reload');
  await sleep(200);
  await waitFor('S0 again', drawn, 40_000);
  await sleep(300);
}

// What S0_MEASURE measures, and the hint under the button (#aside, outside #screen): each of its line boxes on screen.
const S0_ASIDE = `
  const m = (() => { ${S0_MEASURE} })();
  const aside = document.getElementById('aside');
  const dock = document.getElementById('dock').getBoundingClientRect();
  const asideCut = [];
  const walker = document.createTreeWalker(aside, NodeFilter.SHOW_TEXT);
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    if (!n.textContent.trim()) continue;
    const range = document.createRange();
    range.selectNodeContents(n);
    for (const r of range.getClientRects()) {
      if (r.width < 0.5 || r.height < 0.5) continue;
      if (r.top < dock.bottom - 0.5 || r.bottom > innerHeight + 0.5 || r.left < -0.5 || r.right > innerWidth + 0.5) asideCut.push(Math.round(r.bottom - innerHeight));
    }
  }
  return { ...m, asideCut, platformHint: Boolean(document.getElementById('platform-hint')), why: Boolean(document.getElementById('why')), dockIds: [...document.querySelectorAll('#dock [id]')].map((e) => e.id) };`;

test('S0 in a browser that reports no passkey manager, and S0 held back with vaults made in the past hour: every line whole at 375x548 and 320x568, the hint under the button included', { skip, timeout: 240_000 }, async (t) => {
  const plainUa = await cdp.page('return navigator.userAgent;');
  const size = (width, height) => cdp.send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 2, mobile: true });
  const { identifier } = await cdp.send('Page.addScriptToEvaluateOnNewDocument', { source: TEST_FLAGS });
  const measure = () => cdp.page(S0_ASIDE);
  const whole = (m, label, expect = 'intro/ready') => {
    t.diagnostic(`${label}: over ${m.over}, ${m.lines} lines, classes "${m.cls}", foot ${m.footPx}px, hint ${m.platformHint}, made ${m.hint}`);
    assert.equal(m.state, expect, label);
    assert.ok(m.foot, `${label}: the footer is drawn`);
    assert.ok(m.over <= 0, `${label}: #screen is ${m.over} px taller than its box`);
    assert.deepEqual(m.cut, [], `${label}: lines not whole in #screen`);
    assert.ok(m.nextWhole && m.goWhole, `${label}: the Next line and the button whole under #screen`);
    assert.deepEqual(m.asideCut, [], `${label}: lines under the button not whole on screen`);
    assert.ok(m.footPx >= 11, `${label}: the footer at ${m.footPx}px`);
  };
  try {
    await withLiveLabels(async () => {
      for (const [ua, name] of [[IOS_SAFARI, 'Safari'], [X_APP, 'the X app']]) {
        await cdp.send('Emulation.setUserAgentOverride', { userAgent: ua });
        for (const [width, height] of [[375, 548], [320, 568]]) {
          await size(width, height);
          await openS0({ flags: { __test_uvpaa: 'false' } });
          const m = await measure();
          whole(m, `${name} ${width}x${height}, no passkey manager`);
          // In Safari the hint says what to check; inside an app the line about the app says passkeys may not work
          // there and how to leave, and the hint (a second answer to the same thing) is not drawn.
          assert.equal(m.platformHint, ua === IOS_SAFARI, `the hint about this browser's passkey manager at ${name} ${width}x${height}`);
          assert.equal(m.inApp, ua === X_APP, `the line about the app at ${name} ${width}x${height}`);
        }
      }
      // Safari with the hint and the hint of vaults made in the past hour, on the narrowest phone.
      await cdp.send('Emulation.setUserAgentOverride', { userAgent: IOS_SAFARI });
      await size(320, 568);
      await openS0({ made: 2, flags: { __test_uvpaa: 'false' } });
      const both = await measure();
      assert.ok(both.platformHint && both.hint, 'the hint under the button and the made-in-the-past-hour hint are both up');
      whole(both, 'Safari 320x568, no passkey manager, 2 vaults made in the past hour');
      // Held back by the relay's coin side inside an app, 2 vaults made in the past hour: no Make button, so no new
      // vault for the made hint to warn of; the line about the app and the reason are up, and every line whole.
      await cdp.send('Emulation.setUserAgentOverride', { userAgent: X_APP });
      await openS0({ made: 2, flags: { __test_funds_down: 'true' } });
      const held = await measure();
      whole(held, 'the X app 320x568, held back by the coin side, 2 vaults made in the past hour', 'intro/blocked');
      assert.ok(held.why && held.inApp, 'the reason and the line about the app are up');
      assert.equal(held.hint, false, 'no made-in-the-past-hour hint with no Make button');
      assert.deepEqual(held.dockIds, ['watch']);
    });
  } finally {
    await cdp.page(`for (const k of ${JSON.stringify(FLAG_KEYS)}) localStorage.removeItem(k); localStorage.removeItem('undo-try:made'); return true;`).catch(() => {});
    await cdp.send('Page.removeScriptToEvaluateOnNewDocument', { identifier }).catch(() => {});
    await cdp.send('Page.navigate', { url: 'about:blank' }).catch(() => {});
    await sleep(200);
    await cdp.send('Emulation.setUserAgentOverride', { userAgent: plainUa });
    await size(390, 844);
  }
});

// fitIntro's deepest step draws the chip and the wordmark smaller, so "Undo for Bitcoin" fits beside the chip on S0
// where it does not at the size step 1 draws it. A resize on S0 (a rotation, or an app's browser that changes its
// viewport) must not leave the wordmark measured under S0's old steps: on S0 and on every step after, it is whole.
const WORDMARK = `const m = document.querySelector('.top .wordmark');
  const box = m.getBoundingClientRect();
  const rest = [...m.querySelector('.rest').getClientRects()];
  return { right: box.right, restRight: rest.length ? Math.max(...rest.map((r) => r.right)) : null, row: m.parentElement.getBoundingClientRect().right, w: innerWidth,
    short: m.classList.contains('short'), px: parseFloat(getComputedStyle(m).fontSize), cls: document.getElementById('frame').className, step: document.documentElement.dataset.step };`;

test('S0 then a resize at 320 px wide inside an app: the wordmark is whole on S0 and on step 1', { skip, timeout: 240_000 }, async (t) => {
  const plainUa = await cdp.page('return navigator.userAgent;');
  const size = (width, height) => cdp.send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 2, mobile: true });
  const fits = (w, label) => {
    t.diagnostic(`${label}: ${w.step}, wordmark ${w.px}px${w.short ? ' short' : ''}, right ${w.right.toFixed(1)} of ${w.w} (row ${w.row.toFixed(1)}), rest ${w.restRight === null ? '-' : w.restRight.toFixed(1)}, classes "${w.cls}"`);
    assert.ok(w.right <= w.row + 0.5 && w.right <= w.w + 0.5, `${label}: the wordmark ends at ${w.right} of ${w.w}`);
    assert.ok(w.restRight === null || w.restRight <= w.w + 0.5, `${label}: "for Bitcoin" ends at ${w.restRight} of ${w.w}`);
  };
  try {
    await withLiveLabels(async () => {
      await cdp.send('Emulation.setUserAgentOverride', { userAgent: X_APP });
      await size(320, 568);
      await openS0();
      fits(await cdp.page(WORDMARK), 'S0 at 320x568');
      await size(568, 320);
      await sleep(400);
      fits(await cdp.page(WORDMARK), 'S0 at 568x320');
      await size(320, 568);
      await sleep(400);
      const back = await cdp.page(WORDMARK);
      assert.match(back.cls, /\btightest\b/, 'S0 at 320x568 in the app takes the deepest step (the one that draws the wordmark smaller)');
      fits(back, 'S0 back at 320x568');
      // Step 1 as the Make tap draws it, measured when the tap's own drawing is done (a microtask after it), whatever
      // the passkey sheet then answers: a sheet refused at once puts S0 back within a moment.
      await cdp.page(`window.__step1 = null;
        new MutationObserver((list, observer) => {
          if (document.documentElement.dataset.step !== 'make') return;
          observer.disconnect();
          window.__step1 = (() => { ${WORDMARK} })();
        }).observe(document.documentElement, { attributes: true, attributeFilter: ['data-step'] });
        return true;`);
      await clickOn('#make');
      const step1 = await waitFor('step 1', () => cdp.page('return window.__step1;'), 20_000);
      assert.equal(step1.step, 'make');
      assert.doesNotMatch(step1.cls, FIT_STEPS, 'step 1 is drawn at its own sizes');
      fits(step1, 'step 1 after the resizes');
      // And while step 1 stays up.
      await sleep(600);
      const later = await cdp.page(WORDMARK);
      t.diagnostic(`600 ms later: ${JSON.stringify(await state())}`);
      if (later.step === 'make') fits(later, 'step 1, 600 ms on');
    });
  } finally {
    await cdp.send('Page.navigate', { url: 'about:blank' }).catch(() => {});
    await sleep(200);
    await cdp.send('Emulation.setUserAgentOverride', { userAgent: plainUa });
    await size(390, 844);
  }
});

// Safari on an iPhone that names iOS 18 or later (every current iPhone) draws the long hint under the button: the
// AutoFill path in Settings, two lines more than the short one an older user agent gets. With the hint of vaults made
// in the past hour and M1's line (a closed sheet) too, WebKit at 320x568 still had #screen over after .dense, the
// footer's last lines under the fold; .densest draws the type a size smaller again. Chrome draws this screen shorter
// than WebKit does, so the same overflow shows here on a shorter screen: at 320x544 .dense alone leaves #screen over in
// this Chrome. Both sizes: every line whole, no font under 11 px.
const S0_FONTS = `
  const m = (() => { ${S0_ASIDE} })();
  let minPx = Infinity;
  const walker = document.createTreeWalker(document.getElementById('frame'), NodeFilter.SHOW_TEXT);
  for (let n = walker.nextNode(); n; n = walker.nextNode()) {
    if (!n.textContent.trim() || !n.parentElement || n.parentElement.closest('noscript')) continue;
    minPx = Math.min(minPx, parseFloat(getComputedStyle(n.parentElement).fontSize));
  }
  return { ...m, minPx, notice: Boolean(document.getElementById('notice')), asidePx: parseFloat(getComputedStyle(document.getElementById('aside')).fontSize) };`;

test('S0 in Safari on iOS 18 with every line it can have (no passkey manager, vaults made in the past hour, a closed sheet): whole at 320x568, and on a shorter screen at the last step', { skip, timeout: 240_000 }, async (t) => {
  const plainUa = await cdp.page('return navigator.userAgent;');
  const size = (width, height) => cdp.send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 2, mobile: true });
  const { identifier } = await cdp.send('Page.addScriptToEvaluateOnNewDocument', { source: TEST_FLAGS });
  try {
    await withLiveLabels(async () => {
      await cdp.send('Emulation.setUserAgentOverride', { userAgent: IOS_SAFARI });
      for (const [width, height] of [[320, 568], [320, 544]]) {
        const label = `Safari 18 ${width}x${height}, no passkey manager, 3 vaults made in the past hour, M1`;
        await size(width, height);
        await openS0({ made: 3, flags: { __test_uvpaa: 'false', __test_dismiss: 'true' } });
        await clickOn('#make');
        await waitFor('M1', async () => { const s = await state(); return s.step === 'intro' && s.fail === 'M1'; }, 20_000);
        await sleep(600);
        const m = await cdp.page(S0_FONTS);
        t.diagnostic(`${label}: over ${m.over}, ${m.lines} lines, classes "${m.cls}", title ${m.title}px, foot ${m.footPx}px, under the button ${m.asidePx}px, smallest ${m.minPx}px`);
        assert.equal(m.state, 'intro/ready', label);
        assert.ok(m.platformHint && m.hint && m.notice, `${label}: the hint under the button, the made hint and M1's line are all up`);
        assert.ok(m.foot, `${label}: the footer is drawn`);
        assert.ok(m.over <= 0, `${label}: #screen is ${m.over} px taller than its box`);
        assert.deepEqual(m.cut, [], `${label}: lines not whole in #screen`);
        assert.ok(m.nextWhole && m.goWhole, `${label}: the Next line and the button whole under #screen`);
        assert.deepEqual(m.asideCut, [], `${label}: lines under the button not whole on screen`);
        assert.ok(m.minPx >= 11, `${label}: a line at ${m.minPx}px`);
        if (height === 544) {
          assert.match(m.cls, /\bdensest\b/, `${label}: the last step`);
          assert.equal(m.title, 18, `${label}: the title at .densest`);
        }
      }
    });
  } finally {
    await cdp.page(`for (const k of ${JSON.stringify(FLAG_KEYS)}) localStorage.removeItem(k); localStorage.removeItem('undo-try:made'); return true;`).catch(() => {});
    await cdp.send('Page.removeScriptToEvaluateOnNewDocument', { identifier }).catch(() => {});
    await cdp.send('Page.navigate', { url: 'about:blank' }).catch(() => {});
    await sleep(200);
    await cdp.send('Emulation.setUserAgentOverride', { userAgent: plainUa });
    await size(390, 844);
  }
});
