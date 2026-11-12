// The phone page in one headless Chrome with a virtual authenticator, against the real wasm, the local relay and
// regtest. Labelled [mock-signer] [virtual authenticator]: nothing here says anything about a real phone or Face ID.
// Set PHONE_SHOTS to a folder to keep 390x844 screenshots.
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { fromHex, toHex } from '../../tools/lib/bytes.mjs';
import { sha256 } from '../../tools/lib/crypto.mjs';
import { addressToSpk } from '../../tools/lib/btc.mjs';
import { signColdIntent } from '../../tools/lib/cold-intent.mjs';
import { buildFunding, loadDispenser } from '../../tools/lib/dispenser.mjs';
import { action, failureOf, returnValue, TGAS } from '../../tools/lib/near.mjs';
import { sendEverything } from '../lib/bitcoin.mjs';
import { base64ToBytes } from './phone-helpers.mjs';
import { buildCreateArgs, buildPropose, newVaultKeys, rpIdHashOf, vaultIdOf } from '../lib/intents.mjs';
import { NearReader } from '../lib/near-read.mjs';
import { fundsPowTarget, solvePow } from '../lib/pow.mjs';
import { executeTgas, OWN_ACCOUNT_PATH } from '../lib/relay-table.mjs';
import { contractViews, derivedKey } from '../lib/views.mjs';
import { chromeAvailable, startChrome } from './chrome.mjs';
import { stageAvailable, startStage } from './stage.mjs';

const skip = chromeAvailable() && stageAvailable() ? false : 'needs Chrome, NEAR_SANDBOX_BIN_PATH and UNDO_WASM_DIR';
const label = (text) => sha256(new TextEncoder().encode(`undo-test-only:phone:${text}`));
const SHOTS = process.env.PHONE_SHOTS ?? null;
const sleep = (ms) => new Promise((r) => { setTimeout(r, ms); });

let stage;
let browser;
let cdp;
let reader;
let views;
let instance;
let counter = 0;
const pausedHandlers = new Set();
let bootScripts = [];
let authenticatorId;
// What the page wrote to the console: the raw words it keeps off the screen go there.
const consoleLines = [];

// Chrome's virtual authenticator holds three resident keys and then refuses, so each scenario starts it empty.
const emptyAuthenticator = () => cdp.send('WebAuthn.clearCredentials', { authenticatorId });

before(async () => {
  if (skip) return;
  // Every vault here is made through the relay, so its general ceiling must hold a whole file's worth of them.
  stage = await startStage({ miner: false, softPasskey: false, relayEnv: { STATUS_CACHE_MS: 0, CEILING_GENERAL_MICRO: 10_000_000 } });
  reader = new NearReader({ urls: stage.config.rpc, timeoutMs: 15_000 });
  views = contractViews(reader, stage.contract);
  instance = await views.instance();
  browser = await startChrome({ width: 390, height: 844, scale: 2 });
  ({ cdp } = browser);
  await cdp.send('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 2, mobile: true });
  await cdp.send('WebAuthn.enable');
  ({ authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } }));
  cdp.ws.addEventListener('message', (event) => {
    const data = JSON.parse(event.data);
    if (data.method === 'Fetch.requestPaused') for (const handler of pausedHandlers) handler(data.params);
    if (data.method === 'Runtime.consoleAPICalled') consoleLines.push(data.params.args.map((a) => a.value ?? a.description ?? '').join(' '));
  });
  await cdp.send('Runtime.enable');
}, { timeout: 180_000 });

after(async () => {
  await browser?.stop();
  await stage?.stop();
});

// ---------------------------------------------------------------- driving Chrome

const stateOf = () => cdp.page('return document.documentElement.dataset.state;');

async function waitFor(what, fn, timeoutMs = 25_000) {
  const end = Date.now() + timeoutMs;
  let last;
  while (Date.now() < end) {
    last = await fn();
    if (last) return last;
    await sleep(120);
  }
  const text = await cdp.page('return document.body.innerText;').catch(() => '?');
  throw new Error(`never saw ${what}. State ${await stateOf().catch(() => '?')}. Screen: ${text}`);
}

const waitState = (id, timeoutMs) => waitFor(`state ${id}`, async () => (await stateOf()) === id, timeoutMs);

const textOf = (selector) => cdp.page(`return document.querySelector(${JSON.stringify(selector)})?.innerText ?? null;`);
const exists = (selector) => cdp.page(`return Boolean(document.querySelector(${JSON.stringify(selector)}));`);

async function clickOn(selector) {
  const box = await cdp.page(`const r = document.querySelector(${JSON.stringify(selector)})?.getBoundingClientRect(); return r ? { x: r.x + r.width / 2, y: r.y + r.height / 2, w: r.width, h: r.height } : null;`);
  assert.ok(box, `no ${selector} on the screen`);
  assert.ok(box.y >= 0 && box.y <= 844, `${selector} is off the 844 px screen at ${box.y}`);
  await cdp.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: box.x, y: box.y });
  await cdp.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: box.x, y: box.y, button: 'left', clickCount: 1 });
  await cdp.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: box.x, y: box.y, button: 'left', clickCount: 1 });
  return box;
}

async function shot(name) {
  if (!SHOTS) return;
  mkdirSync(SHOTS, { recursive: true });
  const { data } = await cdp.send('Page.captureScreenshot', { format: 'png' });
  writeFileSync(join(SHOTS, `${name}.png`), Buffer.from(data, 'base64'));
}

/** A fresh document, so a fragment-only change cannot leave the last page running. */
async function go(path, fields = {}, { raw = null } = {}) {
  await cdp.send('Page.navigate', { url: 'about:blank' });
  await sleep(50);
  await cdp.send('Page.navigate', { url: raw ?? stage.pageUrl(path, fields) });
  await waitFor('the page to start', () => cdp.page('return document.readyState === "complete" && document.documentElement.dataset.state !== undefined;').catch(() => false));
}

async function reload() {
  await cdp.send('Page.reload');
  await sleep(150);
  await waitFor('a reload', () => cdp.page('return document.readyState === "complete" && document.documentElement.dataset.state !== "boot";').catch(() => false));
}

/** Runs in every new document until `undo` is called: what a blocked or odd browser looks like. */
async function inject(source) {
  const { identifier } = await cdp.send('Page.addScriptToEvaluateOnNewDocument', { source });
  bootScripts.push(identifier);
  return identifier;
}

async function clearInjected() {
  for (const identifier of bootScripts) await cdp.send('Page.removeScriptToEvaluateOnNewDocument', { identifier });
  bootScripts = [];
}

/** While `body` runs, requests matching `pattern` go to `answer`. Returning null lets one through. */
async function intercept(pattern, answer, body) {
  const handler = async (params) => {
    const out = await answer(params.request);
    if (out === null) await cdp.send('Fetch.continueRequest', { requestId: params.requestId });
    else if (out === 'fail') await cdp.send('Fetch.failRequest', { requestId: params.requestId, errorReason: 'ConnectionFailed' });
    else {
      await cdp.send('Fetch.fulfillRequest', {
        requestId: params.requestId,
        responseCode: out.status,
        responseHeaders: [{ name: 'content-type', value: 'application/json' }, { name: 'access-control-allow-origin', value: '*' }],
        body: Buffer.from(JSON.stringify(out.body)).toString('base64'),
      });
    }
  };
  pausedHandlers.add(handler);
  await cdp.send('Fetch.enable', { patterns: [{ urlPattern: pattern }] });
  try {
    return await body();
  } finally {
    pausedHandlers.delete(handler);
    await cdp.send('Fetch.disable');
  }
}

// ---------------------------------------------------------------- the chain's side, as the thief tab would do it

/**
 * A vault whose passkey lives in Chrome's virtual authenticator, and whose keys Node holds, so Node can be the thief.
 * Made through the relay's own create_vault, as the page makes one: the relay sends cancels and test coins only for
 * vaults it made. Each comes from its own address, because the relay takes 3 creates an hour from one address, and
 * the page's own creates in this file come from 127.0.0.1.
 */
async function makeVault(name, { keepKeys = false } = {}) {
  if (!keepKeys) await emptyAuthenticator();
  await go('/p/', {});
  await waitFor('a page', async () => (await stateOf()) !== 'boot');
  const passkey = await cdp.page(`const lib = await import('/site/lib/index.mjs');
    const p = await lib.createPasskey({ credentials: navigator.credentials, rpId: 'localhost' });
    globalThis.made = p;
    return { pub: lib.toBase64(p.pubkey), cred: lib.toBase64Url(p.credentialId), flags: p.flags };`);
  const passkeyPub = base64ToBytes(passkey.pub);
  const keys = newVaultKeys({ seed: label(`${name}-seed-${counter += 1}`), cold: label(`${name}-cold-${counter}`) });
  const vaultHex = toHex(vaultIdOf({ contract: stage.contract, keys, passkeyPub, csv: 6 }));
  const km = await derivedKey(reader, { signer: instance.signer, domainId: instance.domain_id, contract: stage.contract, vaultHex });
  const chainNow = (await reader.blockTime()).blockMs;
  const built = await buildCreateArgs({
    contract: stage.contract, keys, passkeyPub, rpIdHash: rpIdHashOf(stage.rpId), km, guard: stage.relay.accountId, policy: instance.policy, csv: 6, expiresAt: chainNow + 30 * 60_000,
    assert: async (digest) => cdp.page(`const lib = await import('/site/lib/index.mjs');
      const a = await lib.getAssertion({ credentials: navigator.credentials, digest: lib.fromBase64('${Buffer.from(digest).toString('base64')}'), rpId: 'localhost', credentialId: lib.fromBase64Url('${passkey.cred}') });
      return a.args;`),
  });
  const powBits = (await (await fetch(`${stage.origin}/api/relay`)).json()).pow_bits;
  const pow = await solvePow(vaultHex, powBits);
  const ip = `10.${(counter >> 16) & 255}.${(counter >> 8) & 255}.${counter & 255}`;
  const sent = await stage.api('/api/relay', { method: 'create_vault', args: built.args, pow }, { ip });
  assert.equal(sent.status, 200, `the relay made the vault: ${JSON.stringify(sent.body)}`);
  await waitFor('the vault on the chain', async () => (await views.vault(vaultHex)) !== null);
  return { vaultHex, keys, cred: passkey.cred, passkeyPub };
}

async function thiefProposes(v, coin = { txid: toHex(label(`coin-${counter += 1}`)), vout: 0, value: 2000 }) {
  const vault = await views.vault(v.vaultHex);
  const script = fromHex(await views.script(v.vaultHex));
  const to = fromHex(`0014${toHex(label('thief')).slice(0, 40)}`);
  const spend = sendEverything({ coins: [coin], to, script, feeRate: 2 });
  const chainNow = (await reader.blockTime()).blockMs;
  const args = buildPropose({ contract: stage.contract, vault, script, seed: v.keys.seed, inputs: spend.inputs, to, amount: spend.amount, nonce: vault.spend_nonce, expiresAt: chainNow + 30 * 60_000 });
  const sent = await stage.near.sendAndWait(stage.payer, stage.contract, [action.call('propose_btc', args, 40n * TGAS, 0n)]);
  assert.equal(failureOf(sent.result), null);
  return { id: returnValue(sent.result), spend, coin };
}

/** A real coin from the relay's dispenser, as the phone page asks for one. The vault must be one the relay made. */
async function fundFromRelay(v) {
  const powBits = (await (await fetch(`${stage.origin}/api/relay`)).json()).pow_bits;
  const pow = await solvePow(fundsPowTarget(v.vaultHex), powBits);
  return (await fetch(`${stage.origin}/api/funds`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ vault: v.vaultHex, pow }) })).json();
}

/** A real coin straight from the dispenser, with no relay, so this file stays inside the relay's two fundings an hour per address. */
async function fundDirect(v) {
  const vault = await views.vault(v.vaultHex);
  const dispenser = loadDispenser(stage.rig.info.dispenser, 'regtest');
  await stage.rig.mine(1); // This file runs no miner, and a coin spent earlier left its change unconfirmed.
  const utxos = await (await fetch(`${stage.config.esplora}/address/${dispenser.address}/utxo`)).json();
  const made = buildFunding({ dispenser, utxos, payTo: addressToSpk('regtest', vault.address), value: 2000, feeRate: 2 });
  await stage.rig.rpc('sendrawtransaction', [made.raw]);
  await stage.rig.mine(1);
  return { txid: made.txid, vout: made.vout, value: made.value };
}

const realRpc = async (req) => (await fetch(req.url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: req.postData })).json();
const viewBody = (json) => Array.from(new TextEncoder().encode(JSON.stringify(json)));
const viewJson = (result) => JSON.parse(new TextDecoder().decode(Uint8Array.from(result.result.result)));
const hashOnScreen = () => cdp.page('return document.querySelector("#near-tx .hash")?.innerText ?? null;');

/** Answers the view named `method` from `patch(realJson)`, everything else from the node. */
const patchView = (method, patch) => async (req) => {
  const body = JSON.parse(req.postData ?? '{}');
  if (body.params?.method_name !== method) return null;
  const real = await realRpc(req);
  const next = patch(viewJson(real));
  if (next === undefined) return null;
  real.result.result = viewBody(next);
  return { status: 200, body: real };
};

async function fastForwardTo(target) {
  for (let i = 0; i < 200; i += 1) {
    const now = (await reader.blockTime()).blockMs;
    if (now >= target) return;
    await stage.near.sandboxFastForward(Math.min(Math.ceil((target - now) / 500) + 5, 5000));
    await sleep(300);
  }
  throw new Error('the clock never reached the target');
}

const clockMs = (text) => {
  const m = /^(\d+):(\d\d)\.(\d)$/.exec(text);
  return (Number(m[1]) * 60 + Number(m[2])) * 1000 + Number(m[3]) * 100;
};

const noHorizontalScroll = () => cdp.page('return document.documentElement.scrollWidth <= window.innerWidth;');

/**
 * What a person reads that they should not: an error's own name, the chain's or a node's JSON, a code with underscores,
 * or one sentence said twice. Empty when the screen is plain words.
 */
const rawOnScreen = async () => {
  const text = await cdp.page('return document.body.innerText;');
  const problems = [];
  const raw = /TypeError|NotAllowedError|HostError|GuestPanic|panic_msg|ActionError|FunctionCallError|ExecutionError|RPC error|sendrawtransaction|webauthn:|\{"|<html|\b[a-z]+_[a-z_]+\b/.exec(text);
  if (raw) problems.push(`"${raw[0]}" on screen in: ${text.replace(/\s+/g, ' ').slice(0, 240)}`);
  const sentences = text.split(/(?<=[.!?])\s+|\n+/).map((t) => t.trim()).filter((t) => t.length > 12);
  const twice = sentences.find((t, i) => sentences.indexOf(t) !== i);
  if (twice) problems.push(`said twice: ${twice}`);
  return problems;
};
const noScrollAtAll = () => cdp.page('return document.documentElement.scrollHeight <= window.innerHeight;');

// ---------------------------------------------------------------- the two phone sizes the README and the film need

const PHONE_SIZES = [[390, 844], [375, 667]];

async function setPhoneSize(width, height) {
  await cdp.send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 2, mobile: true });
  // The screen, not the window: a page wider than the phone widens the window with it.
  await waitFor(`the phone at ${width}x${height}`, () => cdp.page(`return screen.width === ${width} && screen.height === ${height};`));
  // The resize event, the page's refit on the next frame, and a frame after that.
  await cdp.page('return new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(() => requestAnimationFrame(r))));');
}

/**
 * `check` at 390x844 and at 375x667, each with a screenshot taken first, and the page left at 390x844. Both sizes are
 * looked at before any failure is reported, so a run on a broken page still leaves both screenshots.
 */
async function atPhoneSizes(name, check) {
  const failed = [];
  try {
    for (const [width, height] of PHONE_SIZES) {
      await setPhoneSize(width, height);
      await shot(`${name}-${width}x${height}`);
      try {
        assert.deepEqual(await rawOnScreen(), [], `plain words at ${width}x${height}`);
        await check({ size: `${width}x${height}`, width, height });
      } catch (err) {
        failed.push(err);
      }
    }
  } finally {
    await setPhoneSize(390, 844);
  }
  if (failed.length) throw failed[0];
}

/** No sideways scroll on a phone this wide: nothing wider than the screen, and the window not widened to fit it. */
const fitsAcross = (width) => cdp.page(`return document.documentElement.scrollWidth <= ${width} && innerWidth <= ${width};`);

/** All of the element on the phone's screen with the page at its top: what a person sees without scrolling. */
async function assertWhole(selector, { size, width, height }) {
  const r = await cdp.page(`scrollTo(0, 0); const b = document.querySelector(${JSON.stringify(selector)})?.getBoundingClientRect();
    return b ? { top: Math.round(b.top), bottom: Math.round(b.bottom), left: Math.round(b.left), right: Math.round(b.right) } : null;`);
  assert.ok(r, `no ${selector} at ${size}`);
  assert.ok(r.top >= 0 && r.left >= 0 && r.bottom <= height && r.right <= width, `${selector} is not whole on the ${size} screen: ${JSON.stringify(r)}`);
}

/** How many lines `phrase` takes inside `selector`. A command or flag set on one line reads as one. */
const linesOf = (selector, phrase) => cdp.page(`const root = document.querySelector(${JSON.stringify(selector)});
  if (!root) return null;
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const nodes = []; let text = '';
  while (walker.nextNode()) { nodes.push([walker.currentNode, text.length]); text += walker.currentNode.data; }
  const at = text.indexOf(${JSON.stringify(phrase)});
  if (at < 0) return null;
  const locate = (i) => { for (let k = nodes.length - 1; k >= 0; k -= 1) if (nodes[k][1] <= i) return [nodes[k][0], i - nodes[k][1]]; return null; };
  const range = document.createRange();
  range.setStart(...locate(at));
  range.setEnd(...locate(at + ${JSON.stringify(phrase)}.length));
  return new Set([...range.getClientRects()].filter((b) => b.width > 0).map((b) => Math.round(b.bottom))).size;`);

const digitsMode = () => cdp.page('return document.documentElement.dataset.digits ?? null;');
const cancelledLayout = () => cdp.page(`const top = (id) => { const e = document.getElementById(id); return e ? Math.round(e.getBoundingClientRect().top) : null; };
  return { digits: top('digits'), stamp: top('stamp'), key: top('key-line') };`);

// ---------------------------------------------------------------- the film's path

test('pending: destination, amount, the contract\'s clock, a big red Cancel. Tap stamps it, the contract agrees, a reload stays stamped. [mock-signer] [virtual authenticator]', { skip, timeout: 120_000 }, async (t) => {
  const v = await makeVault('hero');
  // A real coin, from the relay's dispenser on regtest, so `The coin never moved` has something to check.
  const paid = await fundFromRelay(v);
  t.diagnostic(`funds: ${JSON.stringify({ ok: paid.ok, value: paid.value, code: paid.code })}`);
  const coin = paid.ok ? { txid: paid.txid, vout: paid.vout, value: paid.value } : undefined;
  const { id } = await thiefProposes(v, coin);
  const r = await views.request(v.vaultHex, id);

  await go('/phone/', { v: v.vaultHex, c: v.cred });
  await waitState('request');
  assert.equal(await textOf('#amount'), '2,000 sats', 'the sum of inputs, not request.amount');
  assert.match(await textOf('#to'), /^bcrt1q/);
  assert.equal(await textOf('#chip'), 'local test coins, mock signer', 'a local run cannot read as live');
  assert.equal(await textOf('#cancel'), 'Cancel');

  const first = await cdp.page('return document.getElementById("digits").dataset.clock;');
  const now = (await reader.blockTime()).blockMs;
  const expected = r.unlock - now;
  assert.ok(Math.abs(clockMs(first) - expected) < 4000, `clock reads ${first}, the contract's unlock is ${expected} ms away`);
  await sleep(1300);
  const second = await cdp.page('return document.getElementById("digits").dataset.clock;');
  assert.ok(clockMs(second) < clockMs(first), `the clock falls: ${first} then ${second}`);

  const layout = await cdp.page(`const b = document.getElementById('cancel').getBoundingClientRect(); const d = document.getElementById('digits').getBoundingClientRect();
    const cs = getComputedStyle(document.getElementById('cancel')); const ds = getComputedStyle(document.getElementById('digits'));
    return { btnW: b.width, btnH: b.height, btnBottom: b.bottom, digitsW: d.width, digitsLeft: d.left, digitsRight: d.right, bg: cs.backgroundColor, color: ds.color, tnum: ds.fontVariantNumeric };`);
  assert.equal(layout.bg, 'rgb(255, 59, 48)');
  assert.equal(layout.color, 'rgb(255, 59, 48)');
  assert.match(layout.tnum, /tabular-nums/);
  assert.ok(layout.btnH >= 116 && layout.btnW >= 350, `button ${layout.btnW}x${layout.btnH}`);
  assert.ok(layout.btnBottom <= 844, 'Cancel is on the screen');
  assert.ok(layout.digitsLeft >= 0 && layout.digitsRight <= 390 && layout.digitsW > 260, `digits ${layout.digitsLeft} to ${layout.digitsRight}`);
  assert.ok(await noHorizontalScroll());
  assert.ok(await noScrollAtAll(), 'no scroll while a clock runs');
  await shot('01-request');

  // Fixed slots: a tick must not move the digits.
  const a = await cdp.page('return document.querySelector("#digits .col").getBoundingClientRect().x;');
  await sleep(1100);
  assert.equal(await cdp.page('return document.querySelector("#digits .col").getBoundingClientRect().x;'), a);

  const running = await cdp.page('return document.getElementById("digits").dataset.clock;');
  const digitsTop = () => cdp.page('return Math.round(document.getElementById("digits").getBoundingClientRect().top);');
  const topBefore = await digitsTop();
  await clickOn('#cancel');
  await waitState('cancelled');
  assert.ok(Math.abs((await digitsTop()) - topBefore) <= 1, `the digits stay where they were when the stamp lands: ${topBefore} then ${await digitsTop()}`);
  assert.equal(await digitsMode(), 'held', 'and hold that frame');
  assert.ok(await noScrollAtAll(), 'and the stamp fits under them');
  await shot('02a-cancelled-stamp');
  // Then they settle where a reload draws them: one layout for the cancelled screen, however it was reached.
  await waitFor('the digits to settle', async () => (await digitsMode()) === 'still', 5000);
  const settled = await cancelledLayout();
  assert.ok(settled.digits < topBefore, `they moved up to the top of the screen: ${topBefore} then ${settled.digits}`);
  const keyLineTop = await cdp.page('return document.getElementById("key-line").getBoundingClientRect().top;');
  await waitFor('the hash, once the chain says the cancel ran', hashOnScreen);
  assert.equal(await cdp.page('return document.getElementById("key-line").getBoundingClientRect().top;'), keyLineTop, 'its slot was kept, so the line under it does not jump');
  const timings = await cdp.page('return window.undoTimings;');
  assert.ok(timings.tap && timings.assertion && timings.sent && timings.included && timings.readCancelled, JSON.stringify(timings));
  assert.ok(['high', 'low'].includes(timings.sForm));
  t.diagnostic(`tap to read cancelled ${Math.round(timings.readCancelled - timings.tap)} ms, S form ${timings.sForm}`);

  const shown = await cdp.page(`const d = document.getElementById('digits'); return { clock: d.dataset.clock, color: getComputedStyle(d).color, stamp: document.getElementById('stamp').innerText, key: document.getElementById('key-line').innerText, hash: document.querySelector('.hash').innerText, line: document.querySelector('.hashline').innerText };`);
  assert.equal(shown.stamp, 'CANCELLED');
  assert.equal(shown.color, 'rgb(255, 255, 255)');
  assert.ok(clockMs(shown.clock) < clockMs(running), 'it stopped at the reading on screen, after the tap');
  assert.equal(shown.key, 'That key can\'t ask again.');
  assert.equal(shown.line, 'local NEAR sandbox tx');
  assert.match(shown.hash, /^[1-9A-HJ-NP-Za-km-z]{32,64}$/);
  assert.equal(await exists('#cancel'), false);

  // The contract is the judge, and the hash is the transaction that did it.
  const after = await views.vault(v.vaultHex);
  assert.equal(after.k_s_suspended, true);
  const req = await views.request(v.vaultHex, id);
  assert.equal(req.status, 'Pending');
  assert.notEqual(req.epoch, after.spend_epoch);
  const outcome = await reader.txOutcome(shown.hash, stage.relay.accountId);
  assert.equal(outcome.known, true);
  assert.equal(outcome.failure, null);

  if (coin) {
    await waitFor('the coin line', () => exists('#coin-line'), 30_000);
    assert.equal(await textOf('#coin-line'), 'The coin never moved.');
  }
  await shot('02-cancelled');
  await atPhoneSizes('02-cancelled', async (at) => {
    assert.ok(await fitsAcross(at.width), at.size);
    assert.ok(await noScrollAtAll(), `all of it on one ${at.size} screen`);
  });

  // The digits stay where they stopped.
  await sleep(1500);
  assert.equal(await cdp.page('return document.getElementById("digits").dataset.clock;'), shown.clock);

  assert.deepEqual(await cancelledLayout(), settled, 'and they stay there when the coin line lands');
  assert.ok(await noScrollAtAll(), 'all of it on one screen');

  // Sticky: chain plus what this tab saw.
  await reload();
  await waitState('cancelled');
  const again = await cdp.page(`return { clock: document.getElementById('digits')?.dataset.clock ?? null, hash: document.querySelector('.hash')?.innerText ?? null, stamp: document.getElementById('stamp').innerText, slam: document.getElementById('stamp').classList.contains('slam') };`);
  assert.deepEqual(again, { clock: shown.clock, hash: shown.hash, stamp: 'CANCELLED', slam: false }, 'and it does not stamp again');
  assert.equal(await digitsMode(), 'still');
  assert.deepEqual(await cancelledLayout(), settled, 'the same layout as live, after a reload');
  await shot('03-cancelled-after-reload');
  await atPhoneSizes('03-cancelled-after-reload', async (at) => {
    assert.ok(await fitsAcross(at.width), at.size);
    assert.ok(await noScrollAtAll(), `all of it on one ${at.size} screen`);
  });

  // Another device with only the vault id: still cancelled, read from the chain, with no number it did not see.
  await cdp.page('sessionStorage.clear();');
  await go('/p/', { v: v.vaultHex });
  await waitState('cancelled');
  assert.equal(await exists('#digits'), false);
  assert.equal(await exists('.hash'), coin ? true : false, 'a hash only shows where this page holds one');
  assert.equal(await cdp.page('return document.body.innerText.includes("tx ");'), false);
});

/** Anything on the phone's screen that reaches past its sides: the header, and every box of the screen below it. */
const pastTheSides = () => cdp.page(`return [...document.querySelectorAll('.top, .top *, #screen, #screen *')].filter((e) => e.checkVisibility())
  .map((e) => ({ e, r: e.getBoundingClientRect() })).filter(({ r }) => r.width > 0 && (r.right > innerWidth + 0.5 || r.left < -0.5))
  .map(({ e, r }) => (e.id || e.className || e.tagName) + ' ' + Math.round(r.left) + '..' + Math.round(r.right)).slice(0, 6);`);

test('the stamp never widens the page: not as it slams, not while its frame holds, and a turn during the hold settles at the new size [virtual authenticator]', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('stamp-width');
  await thiefProposes(v);
  await go('/p/', { v: v.vaultHex, c: v.cred });
  await waitState('request');
  const problems = [];
  await clickOn('#cancel');
  await waitState('cancelled');
  // The held frame is the one the film keeps: the page's width every 100 ms through it, with no resize.
  const samples = [];
  for (let i = 0; i < 6; i += 1) {
    samples.push(await cdp.page('return { inner: innerWidth, sw: document.documentElement.scrollWidth, digits: document.documentElement.dataset.digits ?? null };'));
    if (i === 3) await shot('02b-stamp-hold');
    await sleep(100);
  }
  if (!samples.some((m) => m.digits === 'held')) problems.push(`never sampled the held frame: ${JSON.stringify(samples)}`);
  const wide = samples.filter((m) => m.inner !== 390 || m.sw > 390);
  if (wide.length) problems.push(`wider than 390 during the hold: ${JSON.stringify(wide)}`);
  // A turn, or the browser's bar, while the frame still holds: the digits settle at once, and nothing is cut.
  await setPhoneSize(375, 667);
  await waitFor('the digits to settle after the turn', async () => (await digitsMode()) === 'still', 3000).catch(() => problems.push(`the digits still read ${'held'} after the turn`));
  await shot('02c-stamp-turned-375x667');
  if (!(await fitsAcross(375))) problems.push(`wider than 375 after the turn: ${await cdp.page('return document.documentElement.scrollWidth;')}`);
  for (const past of await pastTheSides()) problems.push(`past the side at 375x667: ${past}`);
  await setPhoneSize(390, 844);
  await sleep(600);
  await shot('02d-stamp-turned-back-390x844');
  if (!(await fitsAcross(390))) problems.push(`wider than 390 back at 390x844: ${await cdp.page('return document.documentElement.scrollWidth;')}`);
  for (const past of await pastTheSides()) problems.push(`past the side back at 390x844: ${past}`);
  assert.deepEqual(problems, []);
  // And the stamp is still the film's: a white bar from edge to edge, the word whole on it.
  const bar = await cdp.page(`const r = document.getElementById('stamp').getBoundingClientRect(); const t = document.createRange(); t.selectNodeContents(document.getElementById('stamp')); const w = t.getBoundingClientRect();
    return { left: Math.round(r.left), right: Math.round(r.right), bg: getComputedStyle(document.getElementById('stamp')).backgroundColor, wordLeft: Math.round(w.left), wordRight: Math.round(w.right) };`);
  assert.deepEqual({ left: bar.left, right: bar.right, bg: bar.bg }, { left: 0, right: 390, bg: 'rgb(255, 255, 255)' });
  assert.ok(bar.wordLeft >= 0 && bar.wordRight <= 390, `CANCELLED whole on the bar: ${JSON.stringify(bar)}`);
});

test('a request with an old epoch reads cancelled even when another device did the rotating, and the clock stops', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('other-device');
  const { id } = await thiefProposes(v);
  await go('/p/', { v: v.vaultHex, c: v.cred });
  await waitState('request');
  const before = await cdp.page('return document.getElementById("digits").dataset.clock;');
  // Same passkey, from outside this page's own code path: a second tab would look just like this.
  const vault = await views.vault(v.vaultHex);
  const out = await cdp.page(`const lib = await import('/site/lib/index.mjs');
    const newKs = lib.spendKeys(crypto.getRandomValues(new Uint8Array(32))).ks.pub;
    const expiresAt = ${(await reader.blockTime()).blockMs + 600_000};
    const digest = lib.rotateDigest({ contract: ${JSON.stringify(stage.contract)}, vaultHex: ${JSON.stringify(v.vaultHex)}, newKs, nonce: ${vault.passkey_nonce}, expiresAt });
    const a = await lib.getAssertion({ credentials: navigator.credentials, digest, rpId: 'localhost', credentialId: lib.fromBase64Url(${JSON.stringify(v.cred)}) });
    return lib.rotateArgs({ vaultHex: ${JSON.stringify(v.vaultHex)}, newKs, nonce: ${vault.passkey_nonce}, expiresAt, assertion: a.args });`);
  const sent = await stage.near.sendAndWait(stage.payer, stage.contract, [action.call('cancel_all_and_rotate', out, 30n * TGAS, 0n)]);
  assert.equal(failureOf(sent.result), null);
  await waitState('cancelled');
  const r = await views.request(v.vaultHex, id);
  assert.equal(r.status, 'Pending', 'status alone would say it is still going');
  const frozen = await cdp.page('return document.getElementById("digits").dataset.clock;');
  assert.ok(clockMs(frozen) <= clockMs(before));
  await sleep(1300);
  assert.equal(await cdp.page('return document.getElementById("digits").dataset.clock;'), frozen);
  assert.equal(await exists('.hash'), false, 'no view names the cancelling transaction, so this page shows none');
});

test('at zero Cancel still works; once the contract has signed there is no stamp, and no button', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('late');
  const { id } = await thiefProposes(v);
  const r0 = await views.request(v.vaultHex, id);
  await fastForwardTo(r0.unlock);
  await go('/p/', { v: v.vaultHex, c: v.cred });
  await waitState('request');
  await waitFor('zero on the clock', async () => (await cdp.page('return document.getElementById("digits").dataset.clock;')) === '0:00.0');
  const asked = await cdp.page('const e = document.getElementById("to"); const cs = getComputedStyle(e); return { text: e.innerText, font: `${cs.fontFamily} ${cs.fontWeight}`, className: e.className };');
  assert.ok(await exists('#at-zero'));
  assert.ok(await exists('#cancel'), 'the contract still takes a cancel at zero');
  await shot('04-at-zero');

  const gas = executeTgas(r0.inputs.length, { signTgas: instance.sign_tgas, callbackTgas: instance.callback_tgas });
  await stage.near.send(stage.payer, stage.contract, [action.call('execute', { vault: v.vaultHex, request: id }, BigInt(gas) * TGAS, 0n)]);
  await waitState('too_late', 30_000);
  await waitFor('the signature', async () => (await textOf('#too-late')) === 'Too late. The contract signed.', 30_000);
  assert.equal(await exists('#stamp'), false);
  assert.equal(await exists('#cancel'), false);
  // It spends a made-up coin, so no node will ever hold it, and the page must not print a txid as if one did.
  await waitFor('the page to say so', () => exists('#too-late-unsent'), 30_000);
  assert.equal(await textOf('#too-late-unsent'), 'This page can\'t find that transaction on local regtest yet. Anyone can send it.');
  assert.equal((await cdp.page('return document.body.innerText;')).includes('local regtest txid'), false);
  // One address, set one way: the too-late screen prints it as the request screen did, under its own "to".
  const late = await cdp.page('const e = document.getElementById("too-late-to"); const cs = getComputedStyle(e); const l = e.previousElementSibling; return { text: e.innerText, font: `${cs.fontFamily} ${cs.fontWeight}`, className: e.className, label: l?.innerText ?? null };');
  assert.deepEqual(late, { ...asked, label: 'to' }, 'the request screen\'s mono .addr, with the label on its own line');
  await shot('05-too-late');
  await atPhoneSizes('05-too-late', async (at) => {
    assert.ok(await fitsAcross(at.width), `the address wraps at ${at.size}, and nothing runs off the side`);
    await assertWhole('#too-late-to', at);
  });
  await reload();
  await waitState('too_late');
  await waitFor('the same after a reload', () => exists('#too-late-unsent'));
});

test('a tap that lands after the signature: the contract takes the tap and the page still says too late', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('late-tap');
  const { id } = await thiefProposes(v);
  const r0 = await views.request(v.vaultHex, id);
  await fastForwardTo(r0.unlock);
  await go('/p/', { v: v.vaultHex, c: v.cred });
  await waitState('request');
  // Slow the sheet so the signature lands during it.
  await cdp.page(`const real = navigator.credentials.get.bind(navigator.credentials);
    navigator.credentials.get = async (o) => { await new Promise((r) => setTimeout(r, 2500)); return real(o); };`);
  await clickOn('#cancel');
  await waitState('tapped', 3000);
  const gas = executeTgas(r0.inputs.length, { signTgas: instance.sign_tgas, callbackTgas: instance.callback_tgas });
  await stage.near.send(stage.payer, stage.contract, [action.call('execute', { vault: v.vaultHex, request: id }, BigInt(gas) * TGAS, 0n)]);
  await waitState('too_late', 30_000);
  assert.equal(await exists('#stamp'), false);
});

test('expired: says so, with no button and no stamp', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('expired');
  const { id } = await thiefProposes(v);
  const r0 = await views.request(v.vaultHex, id);
  await fastForwardTo(r0.expires_at + 2000);
  await go('/p/', { v: v.vaultHex, c: v.cred, r: id });
  await waitState('expired');
  assert.equal(await textOf('#expired'), 'This request expired.');
  assert.equal(await exists('#cancel'), false);
  assert.equal(await exists('#stamp'), false);
  await shot('06-expired');
});

// ---------------------------------------------------------------- the relay

test('relay down: no button, a plain sentence, the clock still the contract\'s, and it comes back on its own', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('down');
  await thiefProposes(v);
  await intercept('*/api/relay*', async () => 'fail', async () => {
    await go('/p/', { v: v.vaultHex, c: v.cred });
    await waitState('no_button');
    // No answer says nothing about the relay itself, so the page does not call it down; it reads again every 5 s.
    assert.equal(await textOf('#why'), 'Can\'t reach the relay, so this page can\'t send a cancel. Trying again.');
    assert.equal(await exists('#cancel'), false);
    assert.match(await textOf('#tool'), /recovery file/);
    const a = await cdp.page('return document.getElementById("digits").dataset.clock;');
    await sleep(1200);
    assert.ok(clockMs(await cdp.page('return document.getElementById("digits").dataset.clock;')) < clockMs(a), 'the clock keeps falling');
    assert.ok(await noScrollAtAll(), 'and nothing has pushed it off the screen');
    await shot('07-relay-down');
    await atPhoneSizes('07-relay-down', async (at) => {
      await assertWhole('#sign-own', at);
      assert.ok(await fitsAcross(at.width), at.size);
      for (const piece of ['tools/cancel.mjs', 'tools/freeze.mjs --method cancel']) assert.equal(await linesOf('#tool', piece), 1, `${piece} on one line at ${at.size}`);
    });
  });
  await waitState('request', 12_000);
  assert.ok(await exists('#cancel'), 'the status poll brought the button back');
});

test('at its ceiling: the status says so; and a ceiling met on the send itself takes the button away, keeping the request', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('ceiling');
  await thiefProposes(v);
  const live = await (await fetch(`${stage.origin}/api/relay`)).json();
  const resetsAt = Date.UTC(2030, 0, 2);
  const capped = { ...live, owner: { up: false, why: 'daily_ceiling', resets_at: resetsAt } };
  await intercept('*/api/relay*', async () => ({ status: 200, body: capped }), async () => {
    await go('/p/', { v: v.vaultHex, c: v.cred });
    await waitState('no_button');
    assert.equal(await textOf('#why'), 'The relay hit today\'s limit.');
    assert.match(await cdp.page('return document.body.innerText;'), /resets at 00:00 UTC/);
    assert.equal(await exists('#cancel'), false);
    await shot('08-ceiling');
  });

  await waitState('request', 12_000);
  await intercept('*/api/relay*', async (req) => {
    if (req.method !== 'POST') return { status: 200, body: live };
    return { status: 429, body: { ok: false, code: 'daily_ceiling', message: 'the owner bucket is at its ceiling', bucket: 'owner', resets_at: resetsAt } };
  }, async () => {
    await clickOn('#cancel');
    await waitFor('the ceiling', async () => (await textOf('#why')) === 'The relay hit today\'s limit.');
    assert.equal(await exists('#stamp'), false);
    const r = await views.vault(v.vaultHex);
    assert.equal(r.k_s_suspended, false, 'nothing was cancelled, and the page does not say it was');
  });
});

test('a node a little behind answers null for a request already on screen: no stamp, because a stamp cannot be taken back', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('lag');
  const { id } = await thiefProposes(v);
  await go('/p/', { v: v.vaultHex, c: v.cred });
  await waitState('request');
  const height = (await reader.blockTime()).height;
  let lies = 0;
  const seenState = [];
  await intercept(`${stage.config.rpc[0]}*`, async (req) => {
    const body = JSON.parse(req.postData ?? '{}');
    if (body.params?.method_name === 'request' && lies < 2) {
      lies += 1;
      return { status: 200, body: { jsonrpc: '2.0', id: body.id, result: { block_height: height, logs: [], result: Array.from(new TextEncoder().encode('null')) } } };
    }
    return null;
  }, async () => {
    while (lies < 2) {
      seenState.push(await stateOf());
      await sleep(100);
    }
    await sleep(1500);
    seenState.push(await stateOf());
  });
  assert.ok(seenState.every((s) => s === 'request'), seenState.join());
  assert.equal(await exists('#stamp'), false);
  assert.equal((await views.request(v.vaultHex, id)).status, 'Pending');
});

test('a plain cancel from elsewhere: the row is gone, and after three reads the page believes it, with no key line', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('plain');
  const { id } = await thiefProposes(v);
  await go('/p/', { v: v.vaultHex, c: v.cred });
  await waitState('request');
  const out = await cdp.page(`const lib = await import('/site/lib/index.mjs');
    const expiresAt = ${(await reader.blockTime()).blockMs + 600_000};
    const digest = lib.cancelDigest({ contract: ${JSON.stringify(stage.contract)}, vaultHex: ${JSON.stringify(v.vaultHex)}, request: ${id}, expiresAt });
    const a = await lib.getAssertion({ credentials: navigator.credentials, digest, rpId: 'localhost', credentialId: lib.fromBase64Url(${JSON.stringify(v.cred)}) });
    return lib.cancelArgs({ vaultHex: ${JSON.stringify(v.vaultHex)}, request: ${id}, expiresAt, assertion: a.args });`);
  const sent = await stage.near.sendAndWait(stage.payer, stage.contract, [action.call('cancel', out, 30n * TGAS, 0n)]);
  assert.equal(failureOf(sent.result), null);
  await waitState('cancelled', 8000);
  assert.equal(await exists('#key-line'), false, 'a plain cancel leaves the key able to ask again, so the page must not say otherwise');
  assert.equal((await views.vault(v.vaultHex)).k_s_suspended, false);
});

test('the relay refuses, or the contract refuses: one plain sentence on the screen, the raw words in the console, and the button comes back', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('refuse');
  await thiefProposes(v);
  const live = await (await fetch(`${stage.origin}/api/relay`)).json();
  const words = '{"ActionError":{"index":0,"kind":{"FunctionCallError":{"ExecutionError":"Smart contract panicked: words from a test"}}}}';
  await go('/p/', { v: v.vaultHex, c: v.cred });
  await waitState('request');
  await intercept('*/api/relay*', async (req) => (req.method !== 'POST' ? { status: 200, body: live } : { status: 422, body: { ok: false, code: 'tx_refused', message: 'refused', verbatim: words } }), async () => {
    const logged = consoleLines.length;
    await clickOn('#cancel');
    await waitFor('the refusal', () => exists('#notice'));
    // A contract panic the relay passes on is the contract's sentence. tx_refused can follow a send that landed unseen, so
    // the page does not say Not cancelled.
    assert.equal(await textOf('#notice'), 'The NEAR contract refused it.', 'one sentence, once');
    assert.equal(await exists('#verbatim'), false, 'and not the chain\'s JSON under it');
    assert.ok(consoleLines.slice(logged).some((line) => line.includes(words)), `the raw words are in the console: ${consoleLines.slice(logged).join(' | ')}`);
    await waitState('request');
    await shot('09-refused-plain');
    await waitFor('the signed cancel to save', () => exists('#save-cancel'));
    await atPhoneSizes('09-refused-plain', async (at) => {
      await assertWhole('#cancel', at);
      assert.ok(await fitsAcross(at.width), at.size);
      const gap = await cdp.page('return document.getElementById("cancel").getBoundingClientRect().top - document.getElementById("save-cancel").getBoundingClientRect().bottom;');
      assert.ok(gap >= 8, `a gap between Save and Cancel at ${at.size}: ${gap} px`);
      for (const piece of ['node tools/cancel.mjs', `--file undo-cancel-${v.vaultHex.slice(0, 8)}.json`, '--account YOUR-ACCOUNT']) {
        assert.equal(await linesOf('#own-path', piece), 1, `${piece} on one line at ${at.size}`);
      }
    });
  });
  // The button works after that: a real tap, a real stamp.
  await clickOn('#cancel');
  await waitState('cancelled');
});

test('a vault this relay did not make: Not cancelled by its sentence, no code, the signed cancel to save, whole on a phone screen', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('not-ours');
  // A made-up coin, so the unknown-coin flag shows too: the longest this screen gets.
  await thiefProposes(v);
  const live = await (await fetch(`${stage.origin}/api/relay`)).json();
  const message = `this relay sends cancels only for vaults it made. ${OWN_ACCOUNT_PATH}`;
  await go('/p/', { v: v.vaultHex, c: v.cred });
  await waitState('request');
  await intercept('*/api/relay*', async (req) => (req.method !== 'POST' ? { status: 200, body: live } : { status: 422, body: { ok: false, code: 'not_this_relays', message } }), async () => {
    await clickOn('#cancel');
    await waitState('no_button');
    await waitFor('the signed cancel to save', () => exists('#save-cancel'));
    await shot('06-not-this-relays');
    assert.equal(await cdp.page('return document.getElementById("why").dataset.why;'), 'not_this_relays');
    assert.ok(await exists('#coin-check'));
    const text = await cdp.page('return document.body.innerText;');
    const count = (phrase) => text.toLowerCase().split(phrase.toLowerCase()).length - 1;
    assert.equal(count('sends cancels only for vaults it made'), 1, `the sentence once: ${text}`);
    assert.equal(count('This relay is a convenience'), 0, 'and the relay\'s other sentences are not set over the page\'s own');
    assert.equal(await textOf('#notice'), 'Not cancelled.', 'the notice says only that, and the headline says why');
    assert.equal(await exists('#verbatim'), false, 'and no code under it');
    await atPhoneSizes('06-not-this-relays', async (at) => {
      await assertWhole('#save-cancel', at);
      assert.ok(await fitsAcross(at.width), at.size);
      // The notice leads into the headline: right above it, not across a screen of nothing.
      const gap = await cdp.page('return Math.round(document.getElementById("why").getBoundingClientRect().top - document.getElementById("notice").getBoundingClientRect().bottom);');
      assert.ok(gap >= 0 && gap <= 40, `the notice sits by the headline at ${at.size}: ${gap} px apart`);
      for (const piece of ['node tools/cancel.mjs', `--file undo-cancel-${v.vaultHex.slice(0, 8)}.json`, '--account YOUR-ACCOUNT']) {
        assert.equal(await linesOf('#own-path', piece), 1, `${piece} on one line at ${at.size}`);
      }
    });
  });
});

test('the header: Undo for Bitcoin beside the chip where it fits, as on the landing page, and Undo where a local run\'s chip leaves no room', { skip, timeout: 60_000 }, async () => {
  await go('/p/', {});
  await waitFor('a page', async () => (await stateOf()) !== 'boot');
  const header = () => cdp.page(`const c = document.getElementById('chip').getBoundingClientRect(); const m = document.querySelector('.top .wordmark'); const r = m.getBoundingClientRect();
    return { text: m.innerText, chipRight: Math.round(c.right), markLeft: Math.round(r.left), markRight: Math.round(r.right) };`);
  const seen = {};
  // The footnote names the address prefix of the contract's network. This page's is regtest; the deployed chip's is
  // Mutinynet. So a shot with the deployed chip gets the deployed footnote too, and each is asserted.
  const PREFIX = { regtest: 'bcrt1', mutinynet: 'tb1', signet: 'tb1' };
  const NETWORK = { 'signet test coins': 'mutinynet', 'local test coins, mock signer': instance.network };
  const foot = () => cdp.page('const f = document.getElementById("foot"); return f ? { network: f.dataset.network, prefix: /starts with (\\S+?)\\./.exec(f.textContent)?.[1] ?? null } : null;');
  assert.deepEqual(await foot(), { network: instance.network, prefix: PREFIX[instance.network] }, 'the page draws the footnote for its own contract\'s network');
  await atPhoneSizes('20-header', async (at) => {
    for (const chip of ['signet test coins', 'local test coins, mock signer']) {
      const network = NETWORK[chip];
      await cdp.page(`document.getElementById('chip').textContent = ${JSON.stringify(chip)};
        const f = document.getElementById('foot'); f.textContent = f.textContent.replace(/starts with \\S+?\\./, 'starts with ${PREFIX[network]}.'); f.dataset.network = '${network}';
        dispatchEvent(new Event('resize'));`);
      assert.deepEqual(await foot(), { network, prefix: PREFIX[network] }, `${at.size}: the footnote under the ${chip} chip names that chip's network`);
      const h = await header();
      seen[`${at.size} ${chip}`] = h.text;
      if (chip === 'signet test coins') await shot(`20-header-signet-${at.size}`);
      assert.ok(h.chipRight + 8 <= h.markLeft && h.markRight <= at.width - 16, `${at.size}, ${chip}: ${JSON.stringify(h)}`);
      assert.ok(await fitsAcross(at.width), `${at.size}, ${chip}`);
    }
  });
  for (const size of ['390x844', '375x667']) {
    assert.equal(seen[`${size} signet test coins`], 'Undo for Bitcoin', `the deployed chip leaves room at ${size}`);
    assert.equal(seen[`${size} local test coins, mock signer`], 'Undo', `a local run's chip does not at ${size}`);
  }
});

// ---------------------------------------------------------------- a wrong link

test('wrong vault: an id nobody made, a malformed id, and a phone whose passkey is another vault\'s', { skip, timeout: 120_000 }, async () => {
  await go('/p/', { v: toHex(label('nobody')) });
  await waitState('wrong_vault');
  assert.match(await cdp.page('return document.body.innerText;'), /This page can't find a vault with this id/);
  assert.equal(await exists('#cancel'), false);
  await shot('10-wrong-vault');

  await go('/p/', {}, { raw: `${stage.origin}/p/#v=nothex` });
  await waitState('wrong_vault');
  assert.match(await cdp.page('return document.body.innerText;'), /can't be read/);

  const a = await makeVault('mine');
  const b = await makeVault('theirs', { keepKeys: true });
  await thiefProposes(a);
  await go('/p/', { v: a.vaultHex, c: b.cred });
  await waitState('request');
  await clickOn('#cancel');
  await waitFor('the refusal', () => exists('#notice'));
  assert.equal(await textOf('#notice'), 'Not cancelled. That passkey\'s signature does not check out for this vault.');
  assert.equal(await exists('#verbatim'), false, 'no library words');
  assert.equal(await stateOf(), 'request');
  assert.equal((await views.vault(a.vaultHex)).k_s_suspended, false);
});

test('this page\'s origin not on the contract\'s list, and a vault made for another site: no button, and says why', { skip, timeout: 60_000 }, async () => {
  const v = await makeVault('origin');
  await thiefProposes(v);
  // The same request, with the contract's answer changed only in what this page's check reads.
  const views0 = await views.instance();
  const height = (await reader.blockTime()).height;
  const encoded = (value) => Array.from(new TextEncoder().encode(JSON.stringify(value)));
  await intercept(`${stage.config.rpc[0]}*`, async (req) => {
    const body = JSON.parse(req.postData ?? '{}');
    if (body.params?.method_name !== 'instance') return null;
    return { status: 200, body: { jsonrpc: '2.0', id: body.id, result: { block_height: height, logs: [], result: encoded({ ...views0, origins: ['https://elsewhere.example'] }) } } };
  }, async () => {
    await go('/p/', { v: v.vaultHex, c: v.cred });
    await waitState('no_button');
    assert.equal(await textOf('#why'), 'This page isn\'t allowed to cancel for this vault.');
    assert.equal(await cdp.page('return document.getElementById("why").dataset.why;'), 'origin_not_allowed');
  });
});

// ---------------------------------------------------------------- what the browser will not do

test('both S forms: a high-S and a low-S real assertion each cancel, and the page logs which. [virtual authenticator]', { skip, timeout: 240_000 }, async (t) => {
  const seen = { high: 0, low: 0 };
  for (let i = 0; i < 14 && (seen.high === 0 || seen.low === 0); i += 1) {
    const v = await makeVault(`s-${i}`);
    await thiefProposes(v);
    await go('/p/', { v: v.vaultHex, c: v.cred });
    await waitState('request');
    await clickOn('#cancel');
    await waitState('cancelled');
    const form = await cdp.page('return window.undoTimings.sForm;');
    assert.equal(await cdp.page('return document.documentElement.dataset.sForm;'), form);
    seen[form] += 1;
    assert.equal((await views.vault(v.vaultHex)).k_s_suspended, true);
  }
  t.diagnostic(`S forms over the loop: ${JSON.stringify(seen)}`);
  assert.ok(seen.high > 0 && seen.low > 0, `only saw ${JSON.stringify(seen)}`);
});

test('WebAuthn blocked: the sheet never appears, the page says so, and hides the red button', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('blocked');
  await thiefProposes(v);
  await inject(`navigator.credentials.get = () => Promise.reject(new DOMException('The operation is not allowed in this context.', 'NotAllowedError'));`);
  try {
    await go('/p/', { v: v.vaultHex, c: v.cred });
    await waitState('request');
    assert.ok(await exists('#cancel'), 'nothing says it is blocked until a tap shows it');
    await clickOn('#cancel');
    // The link's id may be all that is wrong, so one try with any passkey comes first.
    await waitFor('the first refusal', () => exists('#notice'));
    assert.equal(await textOf('#notice'), 'Not cancelled. The passkey did not sign.');
    assert.equal(await cdp.page('return location.hash.includes("c=");'), false, 'and the link\'s id is dropped');
    await waitState('request');
    await clickOn('#cancel');
    await waitState('no_button');
    assert.match(await textOf('#why'), /No passkey came back\..*may not hold this vault's passkey.*may be blocking passkeys/);
    assert.equal(await exists('#cancel'), false);
    assert.equal(await exists('#retry-passkey'), true);
    assert.ok(await noHorizontalScroll());
    await shot('11-webauthn-blocked');
    await atPhoneSizes('11-webauthn-blocked', async (at) => {
      await assertWhole('#retry-passkey', at);
      assert.ok(await fitsAcross(at.width), at.size);
      assert.equal(await linesOf('#tool', 'tools/freeze.mjs --method cancel'), 1, `the command on one line at ${at.size}`);
    });
  } finally {
    await clearInjected();
  }
});

test('no WebAuthn at all says so, with no button. A phone whose browser reports no platform authenticator keeps Make and Cancel, with a hint, and its Cancel works [virtual authenticator]', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('absent');
  await thiefProposes(v);
  await inject(`delete window.PublicKeyCredential; Object.defineProperty(window, 'PublicKeyCredential', { value: undefined });`);
  try {
    await go('/p/', { v: v.vaultHex, c: v.cred });
    await waitState('no_button');
    assert.match(await textOf('#why'), /no passkeys/);
    assert.equal(await exists('#cancel'), false);
    await shot('12-no-webauthn');
    await atPhoneSizes('12-no-webauthn', async (at) => {
      assert.ok(await fitsAcross(at.width), at.size);
      assert.equal(await linesOf('#tool', 'tools/freeze.mjs --method cancel'), 1, `the command on one line at ${at.size}`);
    });
    await go('/p/', {});
    await waitState('no_vault');
    assert.match(await textOf('#why'), /no passkeys/);
    assert.equal(await exists('#make'), false, 'no Make a test vault if it cannot work');
  } finally {
    await clearInjected();
  }

  await inject(`PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => false;
    Object.defineProperty(navigator, 'userAgentData', { value: { mobile: true } });`);
  try {
    // From iOS 26.2 an iPhone answers false with Face ID on and no passkey manager set up, and on Android false means
    // no screen lock. The page cannot tell which, and only a tap finds out, so nothing is taken away.
    await go('/p/', {});
    await waitState('no_vault');
    assert.ok(await exists('#make'), 'Make a test vault stays');
    assert.equal(await exists('#why'), false);
    // This Chrome's user agent names no iOS and no Android, so the hint names every step and no menu path.
    assert.equal(await textOf('#platform-hint'), 'This browser reports no passkey manager or screen lock it can use. If no passkey sheet comes up, turn one on (iPhone or iPad: set a passcode, and turn on AutoFill for passwords and passkeys in Settings; Android: set a screen lock), then come back to this page.');
    await shot('13-no-platform-no-vault');
    await atPhoneSizes('13-no-platform-no-vault', async (at) => {
      await assertWhole('#make', at);
      assert.ok(await fitsAcross(at.width), at.size);
    });
    await go('/p/', { v: v.vaultHex, c: v.cred });
    await waitState('request');
    assert.match(await textOf('#platform-hint'), /^This browser reports no passkey manager or screen lock it can use\./);
    assert.equal(await exists('#why'), false);
    await shot('13-no-platform');
    await atPhoneSizes('13-no-platform', async (at) => {
      await assertWhole('#cancel', at);
      assert.ok(await fitsAcross(at.width), at.size);
    });
    // The page asks again when it comes back: a passkey manager turned on in Settings takes the hint away, no reload.
    await cdp.page('PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => true; document.dispatchEvent(new Event("visibilitychange")); return true;');
    await waitFor('the hint to go', async () => !(await exists('#platform-hint')));
    assert.ok(await exists('#cancel'));
    await cdp.page('PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => false; document.dispatchEvent(new Event("visibilitychange")); return true;');
    await waitFor('the hint again', () => exists('#platform-hint'));
    // And the tap is what finds out: this authenticator answers, so the request is cancelled.
    await clickOn('#cancel');
    await waitState('cancelled');
  } finally {
    await clearInjected();
  }
});

test('opened inside the X app: the page warns, and a sheet that hangs gets a sentence after 12 s, not silence', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('x-app');
  await thiefProposes(v);
  const plainUa = await cdp.page('return navigator.userAgent;');
  await cdp.send('Emulation.setUserAgentOverride', { userAgent: 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Twitter for iPhone/11.0' });
  await inject(`navigator.credentials.get = () => new Promise(() => {});`);
  try {
    await go('/p/', { v: v.vaultHex, c: v.cred });
    await waitState('request');
    assert.match(await textOf('#in-app'), /inside the X app/);
    await shot('14-x-app');
    await clickOn('#cancel');
    await waitState('tapped', 2000);
    const a = await cdp.page('return document.getElementById("digits").dataset.clock;');
    await sleep(800);
    assert.ok(clockMs(await cdp.page('return document.getElementById("digits").dataset.clock;')) < clockMs(a), 'the clock keeps falling while the sheet is up');
    assert.equal(await exists('#cancel'), false, 'nothing to tap while a sheet may be on its way');
    await waitFor('the hang sentence', () => exists('#hang'), 15_000);
    assert.equal(await textOf('#hang'), 'No passkey sheet yet? This app\'s browser may be blocking passkeys. Open this page in Safari or Chrome, or tap Cancel to try once more.');
    // The button is back in the slot's place, whole on the screen, so the person is not left with a sentence and no way on.
    assert.equal(await exists('#waiting'), false);
    assert.equal(await cdp.page('return document.getElementById("cancel")?.dataset.again ?? null;'), '1');
    assert.equal(await stateOf(), 'tapped');
    await shot('15-sheet-hang');
    await atPhoneSizes('15-sheet-hang', async (at) => {
      await assertWhole('#cancel', at);
      assert.ok(await fitsAcross(at.width), at.size);
    });
  } finally {
    await clearInjected();
    await cdp.send('Emulation.setUserAgentOverride', { userAgent: plainUa });
  }
});

test('the sheet dismissed: Not cancelled, and the button is right there. A sheet that hid the page says so afterwards', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('dismiss');
  await thiefProposes(v);
  await go('/p/', { v: v.vaultHex, c: v.cred });
  await waitState('request');
  await cdp.page(`const real = navigator.credentials.get.bind(navigator.credentials); globalThis.realGet = real;
    let first = true;
    navigator.credentials.get = async (o) => {
      // A sheet a person closes: the page lost focus while it was up. Something else can take focus too, so with a trace
      // or none the page says only that the passkey did not sign (phone-flow.test.mjs closedCrowded, quietCrowded).
      if (first) { first = false; window.dispatchEvent(new Event('blur')); await new Promise((r) => setTimeout(r, 900)); throw new DOMException('dismissed', 'NotAllowedError'); }
      // A sheet that stalls drawing for over a second, as a blanking sheet would.
      const end = performance.now() + 1200; while (performance.now() < end) {}
      return real(o);
    };`);
  await clickOn('#cancel');
  await waitState('tapped', 2000);
  await waitState('request', 5000);
  assert.equal(await textOf('#notice'), 'Not cancelled. The passkey did not sign.');
  assert.ok(await exists('#cancel'));
  await shot('16-dismissed');
  await clickOn('#cancel');
  await waitState('cancelled');
  const sheet = await cdp.page('return window.undoTimings.sheet;');
  assert.ok(sheet.stallMs >= 1000 && sheet.seen, JSON.stringify(sheet));
});

test('a passkey call that never settles: after the page has said no sheet came, Cancel is back, and that tap aborts the real pending request and makes a new one in the same handler, which cancels [virtual authenticator]', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('stuck');
  await thiefProposes(v);
  await go('/p/', { v: v.vaultHex, c: v.cred });
  await waitState('request');
  // Chrome's own request, left pending: the authenticator is there and nobody touches it. What each call was given and
  // how it ended is recorded around the real call, which is otherwise untouched.
  await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: false });
  await cdp.page(`const real = navigator.credentials.get.bind(navigator.credentials);
    globalThis.gets = [];
    navigator.credentials.get = (o) => {
      const call = { signal: o.signal instanceof AbortSignal, active: navigator.userActivation.isActive, allow: o.publicKey.allowCredentials.length, ended: null };
      gets.push(call);
      const out = real(o);
      out.then(() => { call.ended = 'answered'; }, (err) => { call.ended = err.name; });
      return out;
    };
    return true;`);
  try {
    await clickOn('#cancel');
    await waitState('tapped', 2000);
    await sleep(1500);
    assert.equal(await exists('#cancel'), false, 'no button while the page has no reason to think the sheet is not coming');
    assert.equal(await exists('#hang'), false);
    await waitFor('the hang sentence', () => exists('#hang'), 15_000);
    assert.equal(await textOf('#hang'), 'No passkey sheet yet? Tap Cancel again. If none comes, reload this page and try once more.');
    assert.equal(await stateOf(), 'tapped');
    assert.deepEqual(await cdp.page('return gets.map((g) => g.ended);'), [null], 'the first request is still out: no timer ended it');
    await shot('16b-stuck-call');
    await atPhoneSizes('16b-stuck-call', async (at) => {
      await assertWhole('#cancel', at);
      assert.ok(await fitsAcross(at.width), at.size);
    });
    // Now the authenticator answers, and the same button asks again.
    await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: true });
    await sleep(300);
    assert.equal(await stateOf(), 'tapped', 'the request that was out stays out');
    await clickOn('#cancel');
    await waitState('cancelled');
    const gets = await cdp.page('return gets;');
    assert.equal(gets.length, 2);
    assert.deepEqual(gets.map((g) => [g.signal, g.active, g.allow]), [[true, true, 1], [true, true, 1]], 'both asks carried a signal, inside a tap, for this vault\'s passkey');
    assert.deepEqual(gets.map((g) => g.ended), ['AbortError', 'answered'], 'Chrome ended the first when the page aborted it, and took the second, made in the same tap');
    const vault = await views.vault(v.vaultHex);
    assert.equal(vault.passkey_nonce, 1, 'one cancel reached the contract');
  } finally {
    await cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId, enabled: true });
  }
});

test('after a reload the idle screen says why it has no thief link, that Cancel still works here, and offers a new vault; a phone that only opened a link is not told a reload lost anything', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('reloaded');
  // A page that made this vault and was then loaded again: its credential id is in localStorage, its spend key nowhere.
  await go('/p/', {});
  await cdp.page(`localStorage.setItem('undo.passkey.${v.vaultHex}', '${v.cred}'); return true;`);
  try {
    await go('/p/', { v: v.vaultHex, c: v.cred });
    await waitState('idle');
    await waitFor('the balance', () => exists('#balance'));
    assert.equal(await textOf('#no-seed'), 'This page does not hold this vault\'s spend key (a reload forgets it), so it can\'t make a thief link. Cancel still works here. To try a theft, make a new test vault.');
    assert.equal(await exists('#thief-link'), false);
    assert.equal(await exists('#recovery'), false);
    assert.equal(await exists('#fund'), false, 'no test coin for a vault whose spend key is gone');
    await shot('21c-idle-after-reload');
    await atPhoneSizes('21c-idle-after-reload', async (at) => {
      await assertWhole('#new-vault', at);
      assert.ok(await fitsAcross(at.width), at.size);
    });
    // The way out of the dead end is one tap: the page with no vault, and its Make a test vault.
    await clickOn('#new-vault');
    await waitState('no_vault');
    assert.equal(await cdp.page('return location.pathname + location.hash;'), '/p/');
    assert.ok(await exists('#make'));
    // And Cancel does still work on the reloaded page: a request brings the clock and the button, and the tap cancels.
    await go('/p/', { v: v.vaultHex, c: v.cred });
    await waitState('idle');
    await thiefProposes(v);
    await waitState('request', 15_000);
    await clickOn('#cancel');
    await waitState('cancelled');
  } finally {
    await cdp.page(`localStorage.removeItem('undo.passkey.${v.vaultHex}'); return true;`);
  }
  const other = await makeVault('visitor');
  await go('/p/', { v: other.vaultHex, c: other.cred });
  await waitState('idle');
  await waitFor('the balance', () => exists('#balance'));
  assert.equal(await exists('#no-seed'), false);
  assert.ok(await exists('#fund'));
  // Pull to refresh is stopped where a page can say so.
  assert.deepEqual(await cdp.page('return [getComputedStyle(document.documentElement).overscrollBehaviorY, getComputedStyle(document.body).overscrollBehaviorY];'), ['contain', 'contain']);
});

test('the relay out of reach when the page loads: the page says it is trying again, and Make a test vault appears on its own when a read answers', { skip, timeout: 60_000 }, async () => {
  let asked = 0;
  await intercept('*/api/relay*', async (req) => {
    if (req.method !== 'GET') return null;
    asked += 1;
    return asked === 1 ? 'fail' : null;
  }, async () => {
    await go('/p/', {});
    await waitState('no_vault');
    assert.equal(await textOf('#why'), 'Can\'t reach the relay. Trying again.');
    assert.equal(await exists('#make'), false);
    await shot('20b-relay-out-of-reach');
    await waitFor('Make a test vault', () => exists('#make'), 9000);
    assert.equal(await exists('#why'), false);
    assert.equal(asked, 2, 'one more read, 5 s later');
    await sleep(2500);
    assert.equal(asked, 2, 'and none after it answered');
  });
});

test('a laptop window: the same phone column in the middle, not stretched; the stamp sized for the column', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('desktop');
  await thiefProposes(v);
  await cdp.send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 720, deviceScaleFactor: 1, mobile: false });
  try {
    await go('/p/', { v: v.vaultHex, c: v.cred });
    await waitState('request');
    const column = await cdp.page('const r = document.body.getBoundingClientRect(); return { left: r.left, width: r.width, inner: innerWidth, scroll: document.documentElement.scrollWidth };');
    assert.equal(column.width, 480);
    assert.equal(column.left, (column.inner - 480) / 2, 'in the middle of the window');
    assert.ok(column.scroll <= column.inner, 'no sideways scroll');
    const button = await cdp.page('const r = document.getElementById("cancel").getBoundingClientRect(); return { width: r.width, top: r.top, bottom: r.bottom };');
    assert.equal(button.width, 480 - 32, 'Cancel is the column\'s width, not the window\'s');
    assert.ok(button.bottom <= 720, 'and whole in the window');
    const digits = await cdp.page('const r = document.getElementById("digits").getBoundingClientRect(); return { width: r.width, left: r.left, right: r.right };');
    assert.ok(digits.width <= 480 - 32 && digits.left >= column.left && digits.right <= column.left + 480, `the clock is inside the column: ${JSON.stringify(digits)}`);
    await shot('40-desktop-request');
    await clickOn('#cancel');
    await waitState('cancelled');
    await sleep(400); // The stamp lands from a larger scale, in 0.16 s.
    const stamp = await cdp.page('const e = document.getElementById("stamp"); const r = e.getBoundingClientRect(); return { font: getComputedStyle(e).fontSize, width: r.width, left: r.left, height: r.height };');
    assert.equal(stamp.font, '72px', '15% of the 480px column, as on a phone');
    assert.equal(stamp.width, 480);
    assert.ok(stamp.height < 110, `the stamp is ${stamp.height}px tall`);
    assert.ok(await cdp.page('return document.documentElement.scrollWidth <= innerWidth;'));
    await shot('41-desktop-cancelled');
    // A phone is untouched by the rule: the stamp is still 15% of its own width.
    await cdp.send('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 2, mobile: true });
    await reload();
    await waitState('cancelled');
    assert.equal(await cdp.page('return getComputedStyle(document.getElementById("stamp")).fontSize;'), '58.5px');
    assert.equal(await cdp.page('return document.body.getBoundingClientRect().width;'), 390);
  } finally {
    await cdp.send('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 2, mobile: true });
  }
});

test('localStorage that throws, and none at all: the page still works from the fragment; with neither, a discoverable passkey', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('storage');
  await thiefProposes(v);
  await inject(`Object.defineProperty(window, 'localStorage', { get() { throw new DOMException('denied', 'SecurityError'); } });`);
  try {
    await go('/p/', { v: v.vaultHex, c: v.cred });
    await waitState('request');
  } finally {
    await clearInjected();
  }

  // No credential id anywhere: the sheet offers what this device holds, and the id is kept once used.
  await go('/p/', { v: v.vaultHex });
  await waitState('request');
  await clickOn('#cancel');
  await waitFor('a stamp or a refusal', async () => ['cancelled'].includes(await stateOf()) || exists('#notice'));
});

test('the credential id goes to localStorage and nothing else does', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('store-only');
  await thiefProposes(v);
  await go('/p/', { v: v.vaultHex, c: v.cred });
  await waitState('request');
  assert.equal(await cdp.page(`return localStorage.getItem('undo.passkey.${v.vaultHex}');`), null, 'a link\'s id is only a guess until it has made an assertion');
  await clickOn('#cancel');
  await waitState('cancelled');
  const store = await cdp.page('return JSON.stringify(Object.entries(localStorage));');
  const entries = JSON.parse(store);
  assert.ok(entries.length >= 1);
  for (const [key, value] of entries) {
    assert.match(key, /^undo\.passkey\.[0-9a-f]{64}$/);
    assert.match(value, /^[A-Za-z0-9_-]+$/);
  }
  assert.ok(entries.some(([key, value]) => key === `undo.passkey.${v.vaultHex}` && value === v.cred));
  await go('/p/', { v: v.vaultHex });
  await waitState('cancelled');
  await waitFor('the fragment to regain it', async () => (await cdp.page('return location.hash;')).includes(`c=${v.cred}`));
});

test('RPC down: three misses say so, digits freeze and dim, the Cancel stays, and reading comes back', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('rpc');
  await thiefProposes(v);
  await go('/p/', { v: v.vaultHex, c: v.cred });
  await waitState('request');
  await intercept(`${stage.config.rpc[0]}*`, async () => 'fail', async () => {
    await waitFor('the sentence', () => exists('#read-down'), 20_000);
    assert.equal(await textOf('#read-down'), 'Can\'t read the NEAR contract right now.');
    const a = await cdp.page('return document.getElementById("digits").dataset.clock;');
    await sleep(1200);
    assert.equal(await cdp.page('return document.getElementById("digits").dataset.clock;'), a, 'frozen, never free-running past what was read');
    assert.equal(await cdp.page('return document.getElementById("digits").classList.contains("dimmed");'), true);
    assert.ok(await exists('#cancel'), 'a cancel must not depend on reading');
    await shot('17-rpc-down');
  });
  await waitFor('reading to come back', async () => !(await exists('#read-down')), 15_000);
  assert.equal(await cdp.page('return document.getElementById("digits").classList.contains("dimmed");'), false);
});

test('a page with no config says so, and draws no controls', { skip, timeout: 30_000 }, async () => {
  await intercept('*/undo-config.json', async () => ({ status: 404, body: {} }), async () => {
    await go('/p/', {});
    await waitState('no_config');
    assert.equal(await exists('button'), false);
    assert.match(await textOf('#chip'), /test coins/, 'the chip is drawn before any script');
  });
});

test('nothing waiting: the vault\'s address and a plain sentence, no clock. A short screen still fits. A request appearing brings the clock', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('idle');
  await go('/p/', { v: v.vaultHex, c: v.cred });
  await waitState('idle');
  assert.equal(await exists('#digits'), false, 'a clock moves only for a real request');
  assert.equal(await textOf('#nothing'), 'Nothing is waiting.');
  await waitFor('the balance', () => exists('#balance'));
  // One headline. No coins is a line under the address, with the period the sentence under it has.
  assert.equal(await textOf('#balance'), 'No coins yet.');
  const sizes = await cdp.page('const px = (id) => parseFloat(getComputedStyle(document.getElementById(id)).fontSize); return { balance: px("balance"), nothing: px("nothing") };');
  assert.ok(sizes.balance <= sizes.nothing / 2, `the balance is a line, not a second headline: ${JSON.stringify(sizes)}`);
  await shot('18-idle');
  // A test coin asked for on the idle screen, whose answer lands only after a request came up: that answer's words
  // belong to the idle screen, and stay off the theft alert.
  let release;
  const held = new Promise((r) => { release = r; });
  const { id } = await intercept('*/api/funds*', async () => {
    await held;
    return { status: 503, body: { ok: false, code: 'dispenser_empty' } };
  }, async () => {
    await clickOn('#fund');
    await waitFor('the ask', async () => (await textOf('#notice')) === 'Asking for a test coin.');
    const proposed = await thiefProposes(v);
    await waitState('request', 10_000);
    const logged = consoleLines.length;
    release();
    await waitFor('the answer to land', async () => consoleLines.slice(logged).some((line) => line.startsWith('undo: test coins:')), 15_000);
    // Past the next read too, which draws the request screen again.
    for (let i = 0; i < 8; i += 1) {
      assert.equal(await stateOf(), 'request', 'an answer for the idle screen does not draw it over the theft alert');
      assert.equal(await exists('#notice'), false, `the idle screen's words on the theft alert: ${await textOf('#notice')}`);
      await sleep(200);
    }
    return proposed;
  });
  assert.equal(await cdp.page('return location.hash;').then((h) => new URLSearchParams(h.slice(1)).get('r')), String(id));

  // Safari's bars on screen: a 390 wide phone, then an iPhone SE. The button is still above the fold.
  try {
    for (const [width, height] of [[390, 664], [375, 553]]) {
      await cdp.send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 2, mobile: true });
      await sleep(300);
      assert.ok(await noHorizontalScroll(), `${width}x${height} scrolls sideways`);
      assert.ok(await noScrollAtAll(), `${width}x${height} scrolls while the clock runs`);
      const box = await cdp.page('const r = document.getElementById("cancel").getBoundingClientRect(); const d = document.getElementById("digits").getBoundingClientRect(); return { b: r.bottom, h: r.height, dr: d.right, dl: d.left };');
      assert.ok(box.b <= height && box.h >= 100 && box.dl >= 0 && box.dr <= width, JSON.stringify(box));
      await shot(`19-request-${width}x${height}`);
    }
  } finally {
    await cdp.send('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 2, mobile: true });
  }
});

// ---------------------------------------------------------------- the footer of the screen with no vault

test('no vault: the footer reads the contract account\'s keys from public RPC. With its deploy key on it, that key could change the code at once; with none, an upgrade waits 1 hour; with no answer, it says it could not read', { skip, timeout: 120_000 }, async () => {
  const SHORT = 'The operator can upgrade this test contract after 1 hour.';
  const KEY_ON = 'The operator can upgrade this test contract after a 1 hour public wait. Today its deploy key is still on it, and that key could change the code at once.';
  const NOT_READ = 'The operator can upgrade this test contract after a 1 hour public wait. This page could not read whether its deploy key is still on it, and such a key could change the code at once.';
  const footAt = async () => {
    await go('/p/', {});
    await waitState('no_vault');
    return textOf('#foot');
  };
  const only = (foot, sentence) => [SHORT, KEY_ON, NOT_READ].filter((x) => foot.includes(x)).join('|') === sentence;
  // The stage's contract account holds the key that deployed it, as the live test instance does today: read here from
  // the same node the page reads.
  const onChain = await reader.accessKeys(stage.contract);
  assert.deepEqual(onChain.map((k) => k.access_key.permission), ['FullAccess']);
  const real = await footAt();
  assert.ok(only(real, KEY_ON), real);
  assert.ok(real.includes('This page makes your spend key and your cold key and holds them while it is open, so a changed page could take both.'));
  assert.ok(real.endsWith('The signing network alone can refuse, not take.'));
  await shot('19-no-vault-deploy-key-on');
  // The longest of the three still leaves Make a test vault and the whole footer on both phone screens.
  await atPhoneSizes('19-no-vault-deploy-key-on', async (at) => {
    await assertWhole('#make', at);
    await assertWhole('#foot', at);
    assert.ok(await fitsAcross(at.width), at.size);
  });
  // The same page with the node's answer changed on the way in, for that one read only: no key on the account, a
  // function-call key alone, and then no answer at all.
  const answering = (answer) => async (request) => (request.postData?.includes('view_access_key_list') ? answer : null);
  const list = (keys) => ({ status: 200, body: { jsonrpc: '2.0', id: 1, result: { keys, block_height: 1, block_hash: '11111111111111111111111111111111' } } });
  const call = { public_key: 'ed25519:Anva5xK7ZRtcJS2PPT7Dj3Fv23s3SkZLk8v6kZzGZXjq', access_key: { nonce: 1, permission: { FunctionCall: { allowance: null, receiver_id: stage.contract, method_names: ['execute'] } } } };
  for (const keys of [[], [call]]) {
    const foot = await intercept(`${stage.config.rpc[0]}*`, answering(list(keys)), footAt);
    assert.ok(only(foot, SHORT), foot);
  }
  await shot('19-no-vault-no-deploy-key');
  const dark = await intercept(`${stage.config.rpc[0]}*`, answering('fail'), footAt);
  assert.ok(only(dark, NOT_READ), dark);
  assert.equal(await exists('#make'), true, 'and the page still makes a vault');
});

// ---------------------------------------------------------------- making a vault, and the test mode

test('Make a test vault: two taps, each line when its step ends, then the page reads the vault it made', { skip, timeout: 120_000 }, async () => {
  await emptyAuthenticator();
  await go('/phone/', {});
  await waitState('no_vault');
  // One line before each sheet: what the device is about to ask, and why.
  assert.equal(await textOf('#before-sheet'), 'Next, this device asks to save a passkey named "test vault" for localhost: this vault\'s cancel key. You can delete it afterwards.');
  await atPhoneSizes('20-no-vault', async (at) => {
    await assertWhole('#make', at);
    await assertWhole('#before-sheet', at);
    assert.ok(await fitsAcross(at.width), at.size);
  });
  await shot('20-no-vault');
  await clickOn('#make');
  await waitFor('the second tap', () => exists('#confirm'), 20_000);
  assert.equal(await stateOf(), 'creating');
  assert.equal(await textOf('#before-sheet'), 'One more sheet: your passkey signs this vault\'s creation, and the contract checks it.');
  await shot('20a-confirm');
  await clickOn('#confirm');
  await waitState('idle', 40_000);
  const hash = await cdp.page('return location.hash;');
  const f = new URLSearchParams(hash.slice(1));
  assert.match(f.get('v'), /^[0-9a-f]{64}$/);
  assert.ok(f.get('c'));
  assert.equal(f.get('k'), null, 'the spend key stays out of the address bar');
  const vault = await views.vault(f.get('v'));
  assert.equal(vault.active, true);
  assert.equal(vault.guard_online, true, 'the relay beat at creation');
  assert.ok(await exists('#recovery'));
  assert.ok(await exists('#thief-link'));
  // The page's Cancel leaves only the cold key able to move the coins, so the button for its file says when to save it:
  // inside the button, which stays the height of the one above it, whole on the screen.
  assert.equal(await textOf('#recovery'), 'Recovery file\nSave it before your first Cancel');
  const [linkBox, fileBox] = await cdp.page('return ["#thief-link", "#recovery"].map((s) => { const r = document.querySelector(s).getBoundingClientRect(); return { top: r.top, bottom: r.bottom, height: r.height, width: r.width }; });');
  assert.ok(Math.abs(fileBox.height - linkBox.height) < 0.25, `two lines in the room of one: ${fileBox.height} and ${linkBox.height}`);
  assert.equal(fileBox.top - linkBox.bottom, 10, 'the gap between two buttons, as before');
  assert.ok(fileBox.bottom <= 844, 'whole on the screen');
  const why = await cdp.page('const e = document.getElementById("recovery-why"); const r = e.getBoundingClientRect(); const b = document.getElementById("recovery").getBoundingClientRect(); return { inside: r.top >= b.top && r.bottom <= b.bottom && r.left >= b.left && r.right <= b.right, lines: Math.round(r.height / parseFloat(getComputedStyle(e).lineHeight)) };');
  assert.deepEqual(why, { inside: true, lines: 1 });
  // Under the buttons, and still on the screen: the link is gone with a reload.
  assert.equal(await textOf('#copy-now'), 'Copy it now. A reload forgets the spend key.');
  const copyNow = await cdp.page('const r = document.getElementById("copy-now").getBoundingClientRect(); return { top: r.top, bottom: r.bottom };');
  assert.ok(copyNow.top >= fileBox.bottom && copyNow.bottom <= 844, `under Recovery file and on the screen: ${JSON.stringify(copyNow)}`);
  await shot('21-idle-own-vault');
  await atPhoneSizes('21-idle-own-vault', async (at) => {
    await assertWhole('#thief-link', at);
    await assertWhole('#recovery', at);
    await assertWhole('#copy-now', at);
    assert.ok(await fitsAcross(at.width), at.size);
  });

  // Copy the thief link, as the film does, and stay on the page: its notice is the idle screen's. When the thief's
  // request comes up, the theft alert starts with no notice, so "Copied." is not over its clock.
  await cdp.page('navigator.clipboard.writeText = async (text) => { globalThis.copied = text; }; return true;');
  await clickOn('#thief-link');
  await waitFor('the copy notice', async () => (await textOf('#notice')) === 'Copied. This link holds this vault\'s spend key.');
  const seedHex = /[#&]k=([0-9a-f]{64})/.exec(await cdp.page('return globalThis.copied ?? "";'))?.[1];
  assert.ok(seedHex, 'the copied link holds the spend key');
  await thiefProposes({ vaultHex: f.get('v'), keys: { seed: fromHex(seedHex) } });
  await waitState('request', 15_000);
  assert.equal(await exists('#notice'), false, `a notice from the idle screen on the theft alert: ${await textOf('#notice')}`);
  assert.equal(await exists('#verbatim'), false, 'and no link with the spend key on it');
  await shot('21b-request-after-copy');
});

// What a test run made and saw is kept in the tab's sessionStorage, never in the link (c2a445e).
const h7Kept = () => cdp.page('return JSON.parse(sessionStorage.getItem("undo-h7") ?? "{}");');
const h7Tries = async () => ((await h7Kept()).log ?? '').split('~').filter(Boolean);

async function h7ToReport(t) {
  await emptyAuthenticator();
  await inject(`const realCreate = navigator.credentials.create.bind(navigator.credentials); const realGet = navigator.credentials.get.bind(navigator.credentials);
    globalThis.seenCreate = []; globalThis.seenGet = [];
    navigator.credentials.create = (o) => { seenCreate.push({ name: o.publicKey.user.name, display: o.publicKey.user.displayName, uv: o.publicKey.authenticatorSelection.userVerification, resident: o.publicKey.authenticatorSelection.residentKey, alg: o.publicKey.pubKeyCredParams[0].alg }); return realCreate(o); };
    navigator.credentials.get = (o) => { seenGet.push({ uv: o.publicKey.userVerification, allowed: o.publicKey.allowCredentials.length }); return realGet(o); };`);
  await go('/phone', { }, { raw: `${stage.origin}/phone#h7=1` });
  await waitState('h7_check');
  await shot('30-h7-check');
  await clickOn('#make');
  await waitState('h7_confirm', 15_000);
  await clickOn('#confirm');
  let tapped = 0;
  for (let i = 0; i < 9; i += 1) {
    await waitFor('a try or the operator step', async () => ['h7_try', 'h7_rotate', 'h7_operator'].includes(await stateOf()), 40_000);
    const state = await stateOf();
    if (state === 'h7_operator') break;
    if (tapped === 0) await shot('31-h7-try');
    if (state === 'h7_rotate') await shot('32-h7-rotate');
    await clickOn('#cancel');
    tapped += 1;
    await waitFor('the tap to finish', async () => !['h7_wait', 'h7_sending'].includes(await stateOf()) && (await h7Tries()).length >= tapped, 30_000);
  }
  await waitState('h7_operator');
  await shot('33-h7-operator');
  t.diagnostic(`tapped ${tapped} times`);
  await clickOn('#make-operator');
  await waitState('h7_report', 15_000);
  await clearInjected();
  return tapped;
}

test('test mode: passkey, tries to a high-S or 8, the film\'s own call last, an operator passkey, plain words. A reload changes nothing. [virtual authenticator]', { skip, timeout: 300_000 }, async (t) => {
  const tapped = await h7ToReport(t);
  const report = await textOf('#report');
  t.diagnostic(`report:\n${report}`);
  assert.ok(tapped >= 1 && tapped <= 8);
  assert.match(report, /Passkey "test vault": made/);
  assert.match(report, /Try 1: cancel/);
  assert.match(report, new RegExp(`Try ${tapped}: cancel_all_and_rotate`));
  assert.match(report, /That is the wait to allow for when filming/);
  assert.match(report, /Passkey "operator": made/);
  assert.match(report, /operator_passkey for the contract's new: \{"pubkey":"0[23][0-9a-f]{64}","rp_id_hash":"[0-9a-f]{64}"\}/);
  assert.match(report, /(A high-S signature appeared on try \d of \d|No high-S signature in 8 tries)/);
  assert.match(report, /While the passkey was asked/);
  assert.match(report, /local NEAR sandbox tx/);
  await shot('34-h7-report');

  // What the OS sheet is told, and that the sheet asks for this one key.
  const asked = await cdp.page('return { create: globalThis.seenCreate, get: globalThis.seenGet };');
  assert.deepEqual(asked.create.map((c) => c.name), ['test vault', 'operator']);
  assert.ok(asked.create.every((c) => c.display === c.name && c.uv === 'required' && c.resident === 'required' && c.alg === -7), JSON.stringify(asked.create));
  assert.ok(asked.get.every((g) => g.uv === 'required' && g.allowed === 1), JSON.stringify(asked.get));
  assert.equal(asked.get.length, tapped + 1, 'one assertion per tap, plus the one that made the vault');

  // Nothing secret in what gets copied.
  const seed = new URLSearchParams((await cdp.page('return location.hash;')).slice(1)).get('k');
  assert.match(seed, /^[0-9a-f]{64}$/);
  assert.equal(report.includes(seed), false, 'the report never holds the throwaway key');

  await clickOn('#copy-report');
  await waitFor('the copy to land or the text to be offered', () => cdp.page('return document.documentElement.dataset.copied === "yes" || Boolean(document.getElementById("report-area"));'));

  // Every try is on chain: the contract took them, and the vault's key ended rotated.
  const f = new URLSearchParams((await cdp.page('return location.hash;')).slice(1));
  const vault = await views.vault(f.get('v'));
  assert.equal(vault.k_s_suspended, true);
  assert.equal(f.get('op'), null, 'the link names no operator passkey');
  assert.equal(f.get('log'), null, 'and no tries');
  const operatorPub = (await h7Kept()).op;
  assert.match(operatorPub, /^0[23][0-9a-f]{64}$/);
  assert.notEqual(operatorPub, vault.passkey, 'two different keys');
  const entries = await h7Tries();
  assert.equal(entries.length, tapped);
  for (const entry of entries) {
    const hash = entry.split('.').pop();
    const outcome = await reader.txOutcome(hash, stage.relay.accountId);
    assert.equal(outcome.failure, null);
  }
  assert.equal(entries[entries.length - 1][0], 'r');
  assert.ok(entries.slice(0, -1).every((e) => e.startsWith('c.')));
  const earlierHigh = entries.slice(0, -1).filter((e) => e.startsWith('c.h')).length;
  assert.ok(earlierHigh <= 1, 'it stops asking once a high-S has appeared');

  // The two answers only a person can give go into the report, and survive a reload with the rest.
  await cdp.page('document.querySelector("[data-answer=\\"recording:blank\\"]").click();');
  await cdp.page('document.querySelector("[data-answer=\\"gestures:one\\"]").click();');
  const answered = await textOf('#report');
  assert.match(answered, /went blank: blank/);
  assert.match(answered, /one Cancel: one/);
  await reload();
  await waitState('h7_report');
  assert.equal(await textOf('#report'), answered);
  assert.equal(await cdp.page('return (await navigator.credentials.get ? "yes" : "no");'), 'yes');
});

test('test mode: a reload in the middle carries on from the chain and the fragment; a blocked browser says so at once', { skip, timeout: 240_000 }, async () => {
  await emptyAuthenticator();
  await go('/phone/', {}, { raw: `${stage.origin}/phone/#h7=1` });
  await waitState('h7_check');
  await clickOn('#make');
  await waitState('h7_confirm', 15_000);
  await clickOn('#confirm');
  await waitFor('the first try', async () => ['h7_try', 'h7_rotate'].includes(await stateOf()), 40_000);
  const before = await cdp.page('return document.getElementById("digits")?.dataset.clock ?? null;');
  await reload();
  await waitFor('the try to come back', async () => ['h7_try', 'h7_rotate'].includes(await stateOf()), 20_000);
  assert.ok(await exists('#cancel'));
  const f = new URLSearchParams((await cdp.page('return location.hash;')).slice(1));
  const vault = await views.vault(f.get('v'));
  assert.equal(vault.pending.length, 1, 'the same request, not a second one');
  assert.ok(before === null || clockMs(await cdp.page('return document.getElementById("digits").dataset.clock;')) <= clockMs(before));

  await inject(`navigator.credentials.create = () => Promise.reject(new DOMException('The operation is not allowed in this context.', 'NotAllowedError'));`);
  try {
    await go('/phone/', {}, { raw: `${stage.origin}/phone/#h7=1` });
    await waitState('h7_check');
    await clickOn('#make');
    await waitState('h7_stopped');
    assert.match(await textOf('#why'), /No passkey came back/);
    assert.ok(await exists('#retry'));
    await shot('35-h7-blocked');
  } finally {
    await clearInjected();
  }
});

test('the fragment and report functions, in the page that ships them', { skip, timeout: 30_000 }, async () => {
  await go('/p/', {});
  const out = await cdp.page(`const f = await import('/p/phone-fragment.mjs'); const r = await import('/p/h7-report.mjs');
    const parsed = f.parsePhoneFragment('#v=${'a'.repeat(64)}&tx=8gZ1dzfAhVn1jZ1dzfAhVn1jZ1dzfAhVn1jZ&f=0:07.9&h7=1&log=c.h.1.2.3.b.4.abc~r.l.5.6.7.n.8.x&junk=1&q=blank.one');
    const bad = f.parsePhoneFragment('#tx=<script>&f=9&op=zz&log=<&opproof=zz');
    const tries = r.decodeTries('c.h.1.2.3.b.4.abc~r.l.5.6.7.n.8.x');
    const again = tries.map(r.encodeTry).join('~');
    return { parsed, bad, tries, again, built: f.buildPhoneFragment({ v: 'b', tx: 'x', f: '0:01.0', r: 3 }), s0: r.sFormSentence([]), s8: r.sFormSentence(Array(8).fill({ s: 'l' })), s3: r.sFormSentence([{ s: 'l' }, { s: 'l' }, { s: 'h' }]) };`);
  assert.equal(out.parsed.f, undefined, 'a link says nothing about what happened');
  assert.equal(out.parsed.tx, undefined);
  assert.equal(out.parsed.junk, undefined);
  assert.equal(out.parsed.log, undefined, 'nor what the test mode did: that is kept in sessionStorage');
  assert.deepEqual(out.bad.refused.sort(), ['opproof']);
  assert.equal(out.again, 'c.h.1.2.3.b.4.abc~r.l.5.6.7.n.8.x');
  assert.equal(out.tries[0].blurred, true);
  assert.equal(out.tries[1].hash, null);
  assert.equal(out.built, '#v=b&r=3');
  assert.match(out.s0, /0 of 8/);
  assert.match(out.s8, /No high-S signature in 8 tries/);
  assert.match(out.s3, /try 3 of 3/);
});

// ---------------------------------------------------------------- what the attack on the pages found

test('attack 1: a decoy self-spend cannot hide a drain. The page stays on the drain, says what else waits, and keeps Cancel when the decoy is signed', { skip, timeout: 180_000 }, async () => {
  const v = await makeVault('decoy');
  const drain = await thiefProposes(v);
  await go('/p/', { v: v.vaultHex, c: v.cred });
  await waitState('request');
  const drainTo = await textOf('#to');
  const vault = await views.vault(v.vaultHex);
  const coin = { txid: toHex(label(`decoy-coin-${counter += 1}`)), vout: 0, value: 1000 };
  const script = fromHex(await views.script(v.vaultHex));
  const spend = sendEverything({ coins: [coin], to: fromHex(vault.script_pubkey), script, feeRate: 2 });
  const args = buildPropose({ contract: stage.contract, vault, script, seed: v.keys.seed, inputs: spend.inputs, to: fromHex(vault.script_pubkey), amount: spend.amount, nonce: vault.spend_nonce, expiresAt: (await reader.blockTime()).blockMs + 30 * 60_000 });
  const sent = await stage.near.sendAndWait(stage.payer, stage.contract, [action.call('propose_btc', args, 40n * TGAS, 0n)]);
  assert.equal(failureOf(sent.result), null);
  const decoyId = returnValue(sent.result);

  await waitFor('the second request to be read', () => exists('#more'));
  assert.equal(await textOf('#more'), '1 more request waiting. Cancel stops them all.');
  assert.equal(await textOf('#to'), drainTo, 'still the drain, not the newest');
  const decoy = await views.request(v.vaultHex, decoyId);
  await fastForwardTo(decoy.unlock);
  const gas = executeTgas(1, { signTgas: instance.sign_tgas, callbackTgas: instance.callback_tgas });
  await stage.near.sendAndWait(stage.payer, stage.contract, [action.call('execute', { vault: v.vaultHex, request: decoyId }, BigInt(gas) * TGAS, 0n)]);
  await waitFor('the page to read the decoy signed', () => exists('#also-signed'), 30_000);
  assert.equal(await stateOf(), 'request', 'not too late: the drain is still cancellable');
  assert.ok(await exists('#cancel'));
  assert.equal(await textOf('#to'), drainTo);
  await reload();
  await waitState('request');
  assert.equal(await textOf('#to'), drainTo, 'a reload stays on the drain');

  await clickOn('#cancel');
  await waitState('cancelled');
  const after = await views.vault(v.vaultHex);
  const r = await views.request(v.vaultHex, drain.id);
  assert.notEqual(r.epoch, after.spend_epoch, 'the contract agrees the drain is dead');
  assert.equal(await textOf('#also-signed'), '1 other request has already been signed.');
});

test('attack 2 and relay 3: a link cannot stamp, cannot name a hash, and cannot hide a live request', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('forged');
  const fake = '4'.repeat(44);
  await go('/p/', {}, { raw: `${stage.origin}/p/#v=${v.vaultHex}&c=${v.cred}&r=777&tx=${fake}&f=0:07.9` });
  await waitState('idle');
  assert.equal(await exists('#stamp'), false, 'no request, no stamp');
  assert.equal((await cdp.page('return document.body.innerText;')).includes(fake), false);
  assert.ok(await exists('#nothing'));

  await thiefProposes(v);
  await go('/p/', {}, { raw: `${stage.origin}/p/#v=${v.vaultHex}&c=${v.cred}&r=99999&tx=${fake}&f=0:01.3` });
  await waitState('request');
  assert.ok(await exists('#cancel'), 'a request number past the newest hides nothing');
  assert.equal((await cdp.page('return document.body.innerText;')).includes(fake), false);
  assert.equal(await cdp.page('return location.hash.includes("tx=") || location.hash.includes("f=");'), false, 'the page does not write them back either');
  await sleep(1500);
  assert.equal(await stateOf(), 'request');
  assert.notEqual(await cdp.page('return document.getElementById("digits").dataset.clock;'), '0:01.3');
});

test('attack 4: one block read with a clock far ahead moves nothing on the phone, and expired does not stick', { skip, timeout: 120_000 }, async () => {
  for (const aheadMs of [7_200_000, 360_000]) {
    const v = await makeVault(`future-${aheadMs}`);
    await thiefProposes(v);
    await go('/p/', { v: v.vaultHex, c: v.cred });
    await waitState('request');
    let lies = 0;
    const states = [];
    await intercept(`${stage.config.rpc[0]}*`, async (req) => {
      const body = JSON.parse(req.postData ?? '{}');
      if (body.method !== 'block' || lies >= 1) return null;
      lies += 1;
      const real = await realRpc(req);
      real.result.header.timestamp_nanosec = String(BigInt(real.result.header.timestamp_nanosec) + BigInt(aheadMs) * 1_000_000n);
      return { status: 200, body: real };
    }, async () => {
      await waitFor('the lie to be read', async () => lies >= 1, 15_000);
      for (let i = 0; i < 10; i += 1) {
        states.push(await stateOf());
        await sleep(200);
      }
    });
    assert.ok(states.every((s) => s === 'request'), states.join());
    assert.ok(await exists('#cancel'));
    assert.ok(clockMs(await cdp.page('return document.getElementById("digits").dataset.clock;')) > 200_000, 'the digits did not jump');
  }
});

test('attack 5: a contract refusal says so at once, as a sentence for the contract\'s reason, not 30 s later in the relay\'s', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('refusal');
  await thiefProposes(v);
  await go('/p/', { v: v.vaultHex, c: v.cred });
  await waitState('request');
  await intercept(`${stage.config.rpc[0]}*`, patchView('vault', (r) => (r ? { ...r, passkey_nonce: r.passkey_nonce + 1 } : undefined)), async () => {
    await sleep(1600);
    const tapped = Date.now();
    await clickOn('#cancel');
    await waitFor('a notice', () => exists('#notice'), 20_000);
    const ms = Date.now() - tapped;
    assert.equal(await textOf('#notice'), 'Not cancelled. The vault changed after this was signed.', 'the contract\'s reason, in a sentence');
    assert.equal(await exists('#verbatim'), false);
    assert.ok(consoleLines.some((line) => /BadNonce/.test(line)), 'and its own word in the console');
    assert.ok(ms < 10_000, `${ms} ms`);
    assert.equal(await exists('#stamp'), false);
  });
  assert.equal((await views.vault(v.vaultHex)).k_s_suspended, false);
});

test('attack 6: a spend with change says what leaves and what comes back, from the contract\'s own numbers', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('change');
  const coin = { txid: toHex(label(`change-coin-${counter += 1}`)), vout: 0, value: 10_000 };
  const vault = await views.vault(v.vaultHex);
  const script = fromHex(await views.script(v.vaultHex));
  const to = fromHex(`0014${toHex(label('thief')).slice(0, 40)}`);
  const args = buildPropose({ contract: stage.contract, vault, script, seed: v.keys.seed, inputs: [coin], to, amount: 1000, change: 8700, nonce: vault.spend_nonce, expiresAt: (await reader.blockTime()).blockMs + 30 * 60_000 });
  const sent = await stage.near.sendAndWait(stage.payer, stage.contract, [action.call('propose_btc', args, 40n * TGAS, 0n)]);
  assert.equal(failureOf(sent.result), null);
  await go('/p/', { v: v.vaultHex, c: v.cred });
  await waitState('request');
  assert.equal(await textOf('#amount'), '1,000 sats');
  assert.equal(await textOf('#change'), '8,700 sats comes back to this vault. 300 sats goes to the Bitcoin fee.');
  assert.equal((await cdp.page('return document.body.innerText;')).includes('9,000'), false);
});

test('attack 7: a coin no node knows is flagged, and a value a node disputes is too. A real coin says nothing', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('declared');
  await thiefProposes(v, { txid: toHex(label(`lie-${counter += 1}`)), vout: 0, value: 5_000_000 });
  await go('/p/', { v: v.vaultHex, c: v.cred });
  await waitState('request');
  await waitFor('the coin check', () => exists('#coin-check'), 15_000);
  assert.equal(await textOf('#coin-check'), 'This page can\'t find this coin on local regtest. This amount is only what the request claims.');
  assert.ok(await exists('#cancel'), 'it can still be cancelled');
  await cdp.send('Emulation.setDeviceMetricsOverride', { width: 320, height: 568, deviceScaleFactor: 2, mobile: true });
  try {
    await sleep(300);
    const fit = await cdp.page('const r = document.getElementById("cancel").getBoundingClientRect(); return { bottom: r.bottom, h: innerHeight, scroll: document.documentElement.scrollHeight };');
    assert.ok(fit.bottom <= fit.h && fit.scroll <= fit.h, `the flag does not push Cancel off a short phone: ${JSON.stringify(fit)}`);
  } finally {
    await cdp.send('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 2, mobile: true });
  }

  const real = await makeVault('declared-real');
  const paid = await fundDirect(real);
  await thiefProposes(real, { txid: paid.txid, vout: paid.vout, value: 9000 });
  await go('/p/', { v: real.vaultHex, c: real.cred });
  await waitState('request');
  await waitFor('the coin check', () => exists('#coin-check'), 15_000);
  assert.equal(await textOf('#coin-check'), 'local regtest says this coin holds 2,000 sats, not what the request claims.');

  const honest = await makeVault('declared-honest');
  const paidAgain = await fundDirect(honest);
  await thiefProposes(honest, { txid: paidAgain.txid, vout: paidAgain.vout, value: paidAgain.value });
  await go('/p/', { v: honest.vaultHex, c: honest.cred });
  await waitState('request');
  await sleep(1500);
  assert.equal(await exists('#coin-check'), false);
});

test('attack 8: a lifted freeze stamped the request, and stopped no key. The page does not say it did', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('thaw');
  await thiefProposes(v);
  const cold = async (method, fields) => {
    const vault = await views.vault(v.vaultHex);
    const expiresAt = (await reader.blockTime()).blockMs + 600_000;
    const signed = signColdIntent({ cold: v.keys.cold, contract: stage.contract, vault: v.vaultHex, method, fields, expiresAt, nonce: vault.cold_nonce });
    const sent = await stage.near.sendAndWait(stage.payer, stage.contract, [action.call(method, { vault: v.vaultHex, ...fields, expires_at: expiresAt, nonce: vault.cold_nonce, signature: signed.signature }, 60n * TGAS, 0n)]);
    assert.equal(failureOf(sent.result), null);
  };
  await go('/p/', { v: v.vaultHex, c: v.cred });
  await waitState('request');
  await intercept(`${stage.config.rpc[0]}*`, async () => 'fail', async () => {
    await cold('freeze', { until: (await reader.blockTime()).blockMs + 120_000 });
    await cold('unfreeze', {});
  });
  await waitState('cancelled', 20_000);
  assert.equal(await textOf('#stamp'), 'CANCELLED');
  assert.equal(await exists('#key-line'), false);
  assert.equal((await views.vault(v.vaultHex)).k_s_suspended, false);
});

test('attack 9: a junk id in a link is not remembered, breaks nothing, and a phone with no id is told who the button is for', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('poison');
  await thiefProposes(v);
  await go('/p/', {}, { raw: `${stage.origin}/p/#v=${v.vaultHex}&c=AAAAAAAA` });
  await waitState('request');
  assert.equal(await cdp.page(`return localStorage.getItem('undo.passkey.${v.vaultHex}');`), null);
  assert.equal(await exists('#that-phone'), false, 'a link named an id, so the page has one to try');
  await go('/p/', { v: v.vaultHex });
  await waitState('request');
  assert.equal(await textOf('#that-phone'), 'Cancel here works only with this vault\'s passkey.');
  await clickOn('#cancel');
  await waitState('cancelled');
  assert.equal((await views.vault(v.vaultHex)).k_s_suspended, true, 'the owner\'s own clean link still works');
  assert.equal(await exists('#that-phone'), false);

  const w = await makeVault('poison-tap');
  await thiefProposes(w);
  await go('/p/', {}, { raw: `${stage.origin}/p/#v=${w.vaultHex}&c=AAAAAAAA` });
  await waitState('request');
  await clickOn('#cancel');
  await waitFor('the junk id to fail', () => exists('#notice'));
  assert.equal(await textOf('#notice'), 'Not cancelled. The passkey did not sign.');
  assert.equal(await stateOf(), 'request', 'the page does not blame the browser yet');
  await clickOn('#cancel');
  await waitState('cancelled');
  assert.equal((await views.vault(w.vaultHex)).k_s_suspended, true, 'the next tap offers any passkey here, and that one works');
  assert.ok(await cdp.page(`return localStorage.getItem('undo.passkey.${w.vaultHex}') !== 'AAAAAAAA';`));

  // A phone holding no passkey for this vault: a plain sentence that names both causes, and the button goes.
  await emptyAuthenticator();
  const x = await makeVault('stranger');
  await thiefProposes(x);
  await emptyAuthenticator();
  await go('/p/', { v: x.vaultHex });
  await waitState('request');
  await clickOn('#cancel');
  await waitState('no_button');
  assert.match(await textOf('#why'), /may not hold this vault's passkey/);
});

test('attack 11: the relay\'s answer held back: the stamp lands first, and the hash lands in its slot when the chain has it', { skip, timeout: 120_000 }, async () => {
  const v = await makeVault('nohash');
  await thiefProposes(v);
  await go('/p/', { v: v.vaultHex, c: v.cred });
  await waitState('request');
  const held = async (params) => {
    if (params.request.method === 'POST') await sleep(4000);
    await cdp.send('Fetch.continueResponse', { requestId: params.requestId }).catch(() => {});
  };
  pausedHandlers.add(held);
  await cdp.send('Fetch.enable', { patterns: [{ urlPattern: '*/api/relay*', requestStage: 'Response' }] });
  try {
    await clickOn('#cancel');
    await waitState('cancelled', 15_000);
    assert.equal(await hashOnScreen(), null, 'nothing is shown before the chain says so');
    assert.ok(await exists('#near-tx'), 'but its place is kept');
    await waitFor('the digits to settle', async () => (await digitsMode()) === 'still', 5000);
    assert.equal(await hashOnScreen(), null, 'the hash is still held back');
    const keyLine = await cdp.page('return document.getElementById("key-line").getBoundingClientRect().top;');
    await waitFor('the hash', hashOnScreen, 15_000);
    assert.equal(await cdp.page('return document.getElementById("key-line").getBoundingClientRect().top;'), keyLine);
  } finally {
    pausedHandlers.delete(held);
    await cdp.send('Fetch.disable');
  }
  const outcome = await reader.txOutcome(await hashOnScreen(), stage.relay.accountId);
  assert.equal(outcome.failure, null);
});

test('attack 12: Signing is not signed. The page says the contract asked', { skip, timeout: 60_000 }, async () => {
  const v = await makeVault('signing');
  await thiefProposes(v);
  await go('/p/', { v: v.vaultHex, c: v.cred });
  await waitState('request');
  await intercept(`${stage.config.rpc[0]}*`, patchView('request', (r) => (r ? { ...r, status: 'Signing', in_flight: 1, first_execute_at: r.proposed_at } : undefined)), async () => {
    await waitState('too_late', 10_000);
    assert.equal(await textOf('#too-late'), 'Too late. The contract asked for the signature.');
    assert.match(await cdp.page('return document.body.innerText;'), /Waiting for the signature/);
  });
});

test('attack 14: a relay that dies takes the button with it within seconds', { skip, timeout: 60_000 }, async () => {
  const v = await makeVault('relaydies');
  await thiefProposes(v);
  await go('/p/', { v: v.vaultHex, c: v.cred });
  await waitState('request');
  await sleep(1200);
  const died = Date.now();
  await intercept('*/api/relay*', async () => 'fail', async () => {
    await waitFor('the button to go', async () => !(await exists('#cancel')), 15_000);
    assert.ok(Date.now() - died < 7000, `${Date.now() - died} ms`);
    assert.equal(await textOf('#why'), 'Can\'t reach the relay, so this page can\'t send a cancel. Trying again.');
  });
});

test('attack 15: a node stuck well behind this clock gets a warning. Cancel stays', { skip, timeout: 60_000 }, async () => {
  const v = await makeVault('stuck');
  await thiefProposes(v);
  await intercept(`${stage.config.rpc[0]}*`, async (req) => {
    const body = JSON.parse(req.postData ?? '{}');
    if (body.method !== 'block') return null;
    const real = await realRpc(req);
    // Against this machine's clock, because earlier tests have fast-forwarded the chain's ahead of it.
    real.result.header.timestamp_nanosec = String(BigInt(Date.now() - 600_000) * 1_000_000n);
    return { status: 200, body: real };
  }, async () => {
    await go('/p/', { v: v.vaultHex, c: v.cred });
    await waitState('request');
    await waitFor('the warning', () => exists('#stale-node'));
    assert.match(await textOf('#stale-node'), /looks stuck/);
    assert.ok(await exists('#cancel'));
  });
});

test('attack 19: test mode only where the config has it', { skip, timeout: 60_000 }, async () => {
  const config = await (await fetch(`${stage.origin}/undo-config.json`)).json();
  await intercept('*/undo-config.json*', async () => ({ status: 200, body: { ...config, h7: false } }), async () => {
    await go('/p/', {}, { raw: `${stage.origin}/p/#h7=1` });
    await waitState('no_vault');
    assert.equal((await cdp.page('return document.body.innerText;')).includes('Test mode'), false);
  });
});

test('relay attack 6: an owner key that can\'t pay takes the button away, in plain words, without a tap', { skip, timeout: 60_000 }, async () => {
  const v = await makeVault('owner-low');
  await thiefProposes(v);
  const live = await (await fetch(`${stage.origin}/api/relay`)).json();
  await intercept('*/api/relay*', async (req) => (req.method === 'GET' ? { status: 200, body: { ...live, owner: { up: false, why: 'owner_key_low', degraded: false, resets_at: null } } } : null), async () => {
    await go('/p/', { v: v.vaultHex, c: v.cred });
    await waitState('no_button');
    assert.equal(await exists('#cancel'), false);
    assert.equal(await textOf('#why'), 'The relay\'s key can\'t pay for a cancel right now, so this page can\'t send one.');
  });
});

test('no CSP violation on any screen a phone reaches', { skip, timeout: 60_000 }, async () => {
  const seen = [];
  const listener = (event) => {
    const data = JSON.parse(event.data);
    if (data.method === 'Runtime.exceptionThrown') seen.push(data.params.exceptionDetails.text);
    if (data.method === 'Runtime.consoleAPICalled' && data.params.type === 'error') seen.push(JSON.stringify(data.params.args.map((a) => a.value)));
    if (data.method === 'Log.entryAdded' && /Content Security Policy|Refused/.test(data.params.entry.text)) seen.push(data.params.entry.text);
  };
  cdp.ws.addEventListener('message', listener);
  await cdp.send('Log.enable');
  const v = await makeVault('csp');
  await thiefProposes(v);
  await go('/phone/', { v: v.vaultHex, c: v.cred });
  await waitState('request');
  await clickOn('#cancel');
  await waitState('cancelled');
  await sleep(500);
  cdp.ws.removeEventListener('message', listener);
  await cdp.send('Log.disable');
  assert.deepEqual(seen, []);
});
