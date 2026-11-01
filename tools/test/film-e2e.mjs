#!/usr/bin/env node
// The film's sequence for real on a local chain, from the top, in one headless Chrome with two windows: the thief tab,
// and the phone page at 390 px with a CDP virtual authenticator. /api/* is the Pages Functions bundle and undo-cron in
// real workerd, the contract is the real wasm on a local NEAR node, signatures come from the mock signer, Bitcoin is
// bitcoind on regtest with standard relay policy. Nothing here can reach a live host.
//
//   Run 1  create through the relay, fund, Send, refused word for word, propose, one clock on both pages,
//          phone cancels, both freeze, CANCELLED on both, coin unspent, the thief's key cannot propose again.
//   Run 2  no cancel: execute at zero, signed, the spend mined.
//   Run 3  the general key at its ceiling and being refused in a burst: the cancel still goes out on the owner key.
//
// The test instance's wait is fixed at 5:00: the TestCoin preset has the same floor and ceiling for it, so no vault can
// read shorter. The script moves the contract's clock with the sandbox's fast-forward to under a minute left, and the
// pages must follow the block time. The last stretch runs in real seconds. --real-wait makes run 2 count the whole 5:00.
//
//   node tools/test/film-e2e.mjs [--real-wait] [--shots DIR] [--report FILE] [--only 1,2,3]
//
// Needs NEAR_SANDBOX_BIN_PATH, UNDO_WASM_DIR, UNDO_BITCOIN_BIN, UNDO_WRANGLER_MODULES, and UNDO_LIBLZMA_DIR where the
// sandbox binary links an outside liblzma. Prints one PASS or FAIL line per check, exits 0 only if none failed.
// Labelled [mock-signer] [virtual authenticator]: it says nothing about MPC, a real phone, public RPC or Mutinynet.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { addressToSpk, segwitAddress } from '../lib/btc.mjs';
import { base58Encode, fromHex, toHex, utf8 } from '../lib/bytes.mjs';
import { sha256 } from '../lib/crypto.mjs';
import { action, failureOf, keyFromSecret, NEAR } from '../lib/near.mjs';
import { sendEverything } from '../../site/lib/bitcoin.mjs';
import { buildPropose } from '../../site/lib/intents.mjs';
import { NearReader } from '../../site/lib/near-read.mjs';
import { RELAY_METHODS } from '../../site/lib/relay-table.mjs';
import { contractViews } from '../../site/lib/views.mjs';
import { chromeAvailable, startChrome } from '../../site/test/chrome.mjs';
import { stageAvailable, startStage } from '../../site/test/stage.mjs';
import { bundleBoth, loadMiniflare, startWorkerd, workerdAvailable } from '../../site/test/workerd.mjs';

const argv = process.argv.slice(2);
const flag = (name) => (argv.includes(name) ? argv[argv.indexOf(name) + 1] : null);
const REAL_WAIT = argv.includes('--real-wait');
const SHOTS = flag('--shots');
const REPORT = flag('--report');
const ONLY = (flag('--only') ?? '1,2,3').split(',').map(Number);
const BEAT = 'undo-test-only:film-e2e-beat';
const FIVE_MINUTES = 300_000;
// As on the deployed relay: real proof of work and real ceilings on the main worker.
const POW_BITS = '18';
const OWNER_METHODS = ['cancel', 'cancel_all_and_rotate'];
const VIEWPORT_THIEF = { width: 1080, height: 1350 };
const VIEWPORT_PHONE = { width: 390, height: 844 };

const label = (text) => sha256(utf8(`undo-test-only:film-e2e:${text}`));
const textOfKey = (secret) => `ed25519:${base58Encode(secret)}`;
const sleep = (ms) => new Promise((r) => { setTimeout(r, ms); });
const THIEF_TO = segwitAddress('mutinynet', 0, label('thief-destination').slice(0, 20));
const THIEF_SPK = toHex(addressToSpk('mutinynet', THIEF_TO));

// ---------------------------------------------------------------- results

const results = [];
const measured = {};
let currentRun = 'setup';

function check(name, ok, detail = '') {
  const passed = Boolean(ok);
  results.push({ run: currentRun, name, ok: passed, detail: String(detail) });
  console.log(`${passed ? 'PASS' : 'FAIL'} [${currentRun}] ${name}${detail !== '' ? `: ${detail}` : ''}`);
  return passed;
}

/** A check the next step cannot do without. */
function must(name, ok, detail = '') {
  if (!check(name, ok, detail)) throw new Error(`stopped at: ${name}`);
}

const note = (key, value) => {
  measured[currentRun] ??= {};
  measured[currentRun][key] = value;
  console.log(`  note [${currentRun}] ${key}: ${typeof value === 'string' ? value : JSON.stringify(value)}`);
};

// ---------------------------------------------------------------- a page

const clockMs = (text) => {
  const m = /^(\d+):(\d\d)\.(\d)$/.exec(text ?? '');
  return m ? (Number(m[1]) * 60 + Number(m[2])) * 1000 + Number(m[3]) * 100 : null;
};

class Tab {
  constructor(name, cdp, { stateJs, clockJs }) {
    Object.assign(this, { name, cdp, stateJs, clockJs, requests: [], exceptions: [], csp: [], states: [] });
    cdp.ws.addEventListener('message', (event) => {
      const { method, params } = JSON.parse(event.data);
      if (method === 'Network.requestWillBeSent') this.requests.push({ url: params.request.url, body: params.request.postData ?? '' });
      if (method === 'Runtime.exceptionThrown') this.exceptions.push(params.exceptionDetails.exception?.description ?? params.exceptionDetails.text);
      if (method === 'Log.entryAdded' && /Content Security Policy/i.test(params.entry.text)) this.csp.push(params.entry.text);
    });
  }

  async start() {
    await this.cdp.send('Network.enable');
    await this.cdp.send('Log.enable');
    await this.cdp.send('Emulation.setFocusEmulationEnabled', { enabled: true });
  }

  js(expr) {
    return this.cdp.page(`return (${expr});`);
  }

  state() {
    return this.js(this.stateJs).catch(() => null);
  }

  /** What is on the screen now, and when this page read it, so two pages can be compared at one instant. */
  async reading() {
    const out = await this.js(`({ text: ${this.clockJs}, at: Date.now() })`);
    return { ...out, ms: clockMs(out.text) };
  }

  async waitFor(what, fn, ms = 30_000) {
    const start = Date.now();
    let last;
    while (Date.now() - start < ms) {
      last = await fn().catch(() => null);
      if (last) return last;
      await sleep(60);
    }
    const screen = await this.js('document.body.innerText').catch(() => '?');
    throw new Error(`${this.name}: never saw ${what} in ${ms} ms. State ${await this.state()}, last ${JSON.stringify(last)}. Screen: ${screen}`);
  }

  async waitState(name, ms) {
    const before = Date.now();
    await this.waitFor(`state ${name}`, async () => (await this.state()) === name, ms);
    return Date.now() - before;
  }

  async go(url) {
    await this.cdp.send('Page.navigate', { url: 'about:blank' });
    await sleep(60);
    await this.cdp.send('Page.navigate', { url });
    await this.waitFor('the page to load', async () => (await this.js('document.readyState')) === 'complete', 20_000);
  }

  async click(selector) {
    const box = await this.js(`(() => { const r = document.querySelector(${JSON.stringify(selector)})?.getBoundingClientRect(); return r ? { x: r.left + r.width / 2, y: r.top + r.height / 2 } : null; })()`);
    if (!box) throw new Error(`${this.name}: nothing to click at ${selector}`);
    await this.cdp.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: box.x, y: box.y });
    await this.cdp.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: box.x, y: box.y, button: 'left', clickCount: 1 });
    await this.cdp.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: box.x, y: box.y, button: 'left', clickCount: 1 });
    return box;
  }

  text(selector) {
    return this.js(`document.querySelector(${JSON.stringify(selector)})?.textContent ?? null`);
  }

  visible(selector) {
    return this.js(`Boolean(document.querySelector(${JSON.stringify(selector)})?.checkVisibility({ visibilityProperty: true }))`);
  }

  async shot(name) {
    if (!SHOTS) return;
    mkdirSync(SHOTS, { recursive: true });
    const { data } = await this.cdp.send('Page.captureScreenshot', { format: 'png' });
    writeFileSync(join(SHOTS, `${currentRun}-${name}-${this.name}.png`), Buffer.from(data, 'base64'));
  }
}

// ---------------------------------------------------------------- the whole rig

const missing = [];
if (!stageAvailable()) missing.push('NEAR_SANDBOX_BIN_PATH and UNDO_WASM_DIR');
if (!workerdAvailable()) missing.push('UNDO_WRANGLER_MODULES');
if (!chromeAvailable()) missing.push('Chrome');
if (missing.length) {
  console.error(`film-e2e: needs ${missing.join(', ')}. Nothing ran.`);
  process.exit(2);
}

let stage;
let mf;
let bundles;
let chrome;
let thief;
let phone;
let reader;
let views;
let instance;
let ownerKey;
let authenticatorId;
let apiWorker = 'main';
let stopping = null;
const stolenSeeds = [];

async function stopAll() {
  stopping ??= (async () => {
    await chrome?.stop().catch(() => {});
    await mf?.dispose().catch(() => {});
    bundles?.remove();
    await stage?.stop().catch(() => {});
  })();
  return stopping;
}

for (const signal of ['SIGINT', 'SIGTERM']) {
  process.on(signal, () => stopAll().finally(() => process.exit(130)));
}

/** /api/* on the page's own origin goes to the Pages Functions in workerd, as on Cloudflare. */
async function toWorkerd(req, res, url) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const headers = { 'cf-connecting-ip': req.socket.remoteAddress ?? '127.0.0.1' };
  for (const name of ['content-type', 'origin', 'x-undo-beat']) if (req.headers[name]) headers[name] = req.headers[name];
  const worker = await mf.getWorker(apiWorker);
  const answer = await worker.fetch(`${stage.origin}${url.pathname}${url.search}`, { method: req.method, headers, body: chunks.length ? Buffer.concat(chunks) : undefined });
  res.writeHead(answer.status, Object.fromEntries(answer.headers));
  res.end(Buffer.from(await answer.arrayBuffer()));
}

async function startEverything() {
  const begun = Date.now();
  stage = await startStage({ miner: true, softPasskey: false });
  reader = new NearReader({ urls: stage.config.rpc, timeoutMs: 15_000 });
  views = contractViews(reader, stage.contract);
  instance = await views.instance();
  check('the test instance reads T_new = 5:00', instance.policy.t_new_ms === FIVE_MINUTES, instance.policy.t_new_ms);

  // As live: a full-access general key, because create_vault attaches a deposit, and a function-call owner key.
  ownerKey = keyFromSecret(label('owner-key'));
  const cronKey = keyFromSecret(label('cron-key'));
  const added = await stage.near.sendAndWait(stage.relay, stage.relay.accountId, [
    action.addCallKey(ownerKey.pub, stage.contract, OWNER_METHODS, 2n * NEAR),
    action.addCallKey(cronKey.pub, stage.contract, ['heartbeat'], NEAR / 2n),
  ]);
  must('owner and cron keys added as function-call keys', failureOf(added.result) === null, failureOf(added.result) ?? '');

  bundles = bundleBoth();
  const dispenser = JSON.parse(readFileSync(stage.rig.info.dispenser, 'utf8')).secret;
  const common = {
    SITE_ORIGIN: stage.origin,
    CONTRACT_ID: stage.contract,
    NEAR_RPC_URLS: stage.config.rpc.join(','),
    ESPLORA_URL: stage.config.esplora,
    RELAY_ACCOUNT: stage.relay.accountId,
    RELAY_GENERAL_KEY: textOfKey(stage.relay.secret),
    RELAY_OWNER_KEY: textOfKey(ownerKey.secret),
    DISPENSER_SECRET: dispenser,
    DISPENSER_NETWORK: 'regtest',
    IP_SALT: 'undo-test-only:film-e2e',
    POW_BITS,
    BEAT_TOKEN: BEAT,
  };
  const propose = RELAY_METHODS.propose_btc.costMicro;
  const execute = RELAY_METHODS.execute.costMicro;
  const { Miniflare } = loadMiniflare();
  mf = startWorkerd({ Miniflare }, {
    bundles,
    cronEnv: { CONTRACT_ID: stage.contract, NEAR_RPC_URLS: stage.config.rpc.join(','), RELAY_ACCOUNT: stage.relay.accountId, RELAY_CRON_KEY: textOfKey(cronKey.secret) },
    pages: {
      // No state name: the deployed default. Default ceilings.
      main: { bindings: common },
      // Run 3 makes and funds its vault here, so its address has fresh limits.
      film3: { bindings: { ...common, UNDO_STATE_NAME: 'film3' } },
      // No new vault fits. One proposal and one execute do.
      low: { bindings: { ...common, UNDO_STATE_NAME: 'low', CEILING_GENERAL_MICRO: String(propose + execute) } },
    },
  });
  await mf.ready;
  stage.useApi(toWorkerd);

  chrome = await startChrome({ ...VIEWPORT_THIEF, scale: 1, extraFlags: ['--disable-background-timer-throttling', '--disable-renderer-backgrounding', '--disable-backgrounding-occluded-windows'] });
  const phoneCdp = await chrome.newWindow({ ...VIEWPORT_PHONE, scale: 2, mobile: true });
  await phoneCdp.send('WebAuthn.enable');
  ({ authenticatorId } = await phoneCdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } }));
  await (await chrome.browser()).send('Browser.grantPermissions', { origin: stage.origin, permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite'] });
  thief = new Tab('thief', chrome.cdp, { stateJs: 'document.getElementById("root")?.dataset.state', clockJs: 'document.getElementById("clock")?.dataset.clock' });
  phone = new Tab('phone', phoneCdp, { stateJs: 'document.documentElement.dataset.state', clockJs: 'document.getElementById("digits")?.dataset.clock' });
  await thief.start();
  await phone.start();
  note('stage, workerd and Chrome up, ms', Date.now() - begun);
}

// ---------------------------------------------------------------- chain helpers

async function settled(hash) {
  for (let i = 0; i < 80; i += 1) {
    try {
      const out = await stage.near.txStatus(hash, stage.relay.accountId, 'EXECUTED_OPTIMISTIC');
      if (out?.receipts_outcome) return out;
    } catch {
      // Not there yet.
    }
    await sleep(250);
  }
  throw new Error(`transaction ${hash} never settled`);
}

const keyNonce = async (publicKey) => (await stage.near.rpc('query', { request_type: 'view_access_key', account_id: stage.relay.accountId, public_key: publicKey, finality: 'optimistic' })).nonce;

let msPerBlock = null;
/** Moves the contract's clock to within `leftMs` of `target`, never past it. Local sandbox only. */
async function fastForwardToLeft(target, leftMs) {
  for (let i = 0; i < 60; i += 1) {
    const now = (await reader.blockTime()).blockMs;
    const gap = target - leftMs - now;
    if (gap <= 1500) return target - now;
    if (msPerBlock === null) {
      await stage.near.sandboxFastForward(20);
      await sleep(300);
      msPerBlock = Math.max(50, ((await reader.blockTime()).blockMs - now) / 20);
      continue;
    }
    await stage.near.sandboxFastForward(Math.max(1, Math.floor((gap * 0.85) / msPerBlock)));
    await sleep(200);
  }
  throw new Error('the clock never got there');
}

/**
 * A jump in the contract's clock reaches each page at its next block read, up to 5 s later, and the sandbox goes on
 * advancing for a moment after it answers. Only this script makes jumps: a live chain's clock has none.
 */
async function letTheJumpLand() {
  await thief.waitFor('the chain to stop jumping', async () => {
    const a = await reader.blockTime();
    await sleep(1000);
    const b = await reader.blockTime();
    return b.blockMs - a.blockMs < 2500;
  }, 20_000);
  await sleep(6000);
}

/** Both digit readings at one instant, many times. The film's two screens must show one contract's clock. */
async function agreement(what, { samples = 12, gapMs = 350 } = {}) {
  const gaps = [];
  let first = null;
  let last = null;
  for (let i = 0; i < samples; i += 1) {
    const [a, b] = await Promise.all([thief.reading(), phone.reading()]);
    if (a.ms === null || b.ms === null) throw new Error(`no digits to compare: thief ${a.text}, phone ${b.text}`);
    // Thief's reading carried to the instant the phone was read.
    gaps.push(Math.abs(a.ms - (b.at - a.at) - b.ms));
    first ??= { a, b };
    last = { a, b };
    await sleep(gapMs);
  }
  const worst = Math.max(...gaps);
  note(`clocks ${what}`, { worstGapMs: Math.round(worst), samples, thief: last.a.text, phone: last.b.text });
  check(`clocks agree within 1 s ${what}`, worst <= 1000, `worst ${Math.round(worst)} ms over ${samples} readings`);
  check(`both clocks are running ${what}`, last.a.ms < first.a.ms && last.b.ms < first.b.ms, `thief ${first.a.text} to ${last.a.text}, phone ${first.b.text} to ${last.b.text}`);
  return worst;
}

async function againstChain(request, what) {
  const [r, block] = await Promise.all([thief.reading(), reader.blockTime()]);
  const truth = request.unlock - block.blockMs;
  // A block read is late by its age, so the page may read a little under this and only a little over.
  const off = r.ms - truth;
  note(`thief clock against the contract ${what}, ms off`, Math.round(off));
  check(`the clock is the contract's unlock against block time ${what}`, Math.abs(off) < 3000, `screen ${r.text}, unlock minus block time ${(truth / 1000).toFixed(1)} s`);
}

async function chips(when) {
  for (const tab of [thief, phone]) {
    const text = await tab.text('#chip');
    const seen = await tab.visible('#chip');
    check(`chip on the ${tab.name} ${when}`, seen && text === 'local test coins, mock signer', text);
  }
}

// ---------------------------------------------------------------- the steps of the film

/** The phone makes a passkey and a vault through the relay, gets a coin, and hands over the thief link. */
async function makeVaultFromPhone({ reopen }) {
  await phone.cdp.send('WebAuthn.clearCredentials', { authenticatorId });
  await phone.go(`${stage.origin}/p/`);
  await phone.waitState('no_vault');
  const made = Date.now();
  await phone.waitFor('the Make button', () => phone.visible('#make'));
  await phone.click('#make');
  await phone.waitFor('the second tap', () => phone.visible('#confirm'), 30_000);
  await phone.click('#confirm');
  await phone.waitState('idle', 90_000);
  note('create: two taps to a vault the contract reads active, ms', Date.now() - made);
  const hash = await phone.js('location.hash');
  const fields = new URLSearchParams(hash.slice(1));
  const vaultHex = fields.get('v');
  const cred = fields.get('c');
  must('the phone holds a vault id and a credential id', /^[0-9a-f]{64}$/.test(vaultHex ?? '') && cred, hash.slice(0, 20));
  const vault = await views.vault(vaultHex);
  must('the contract reads the vault active', vault?.active === true);
  check('the relay is the guard, and its heartbeat landed with the creation', vault.guard_online === true && vault.guard === stage.relay.accountId, vault.guard);
  const delay = await views.delayNow(vaultHex);
  check('a new destination on this vault reads 5:00 on the contract', delay === FIVE_MINUTES, delay);
  await phone.shot('idle');

  const funded = Date.now();
  await phone.waitFor('the Get test coins button', () => phone.visible('#fund'), 30_000);
  await phone.click('#fund');
  const utxos = await phone.waitFor('the coin on the node', async () => {
    const list = await (await fetch(`${stage.config.esplora}/address/${vault.address}/utxo`)).json();
    return list.length ? list : null;
  }, 60_000);
  note('fund: tap to the coin on the node, ms', Date.now() - funded);
  must('one coin of 2,000 sats landed at the vault', utxos.length === 1 && utxos[0].value === 2000, JSON.stringify(utxos[0]));
  const coin = utxos[0];
  await phone.waitFor('the coin confirmed', async () => (await stage.rig.rpc('gettxout', [coin.txid, coin.vout, false])) !== null, 30_000);
  check('the phone names the funding transaction by chain', (await phone.js('document.body.innerText')).includes('local regtest txid') || (await phone.js('document.body.innerText')).includes(coin.txid.slice(0, 12)));

  await phone.waitFor('the thief link button', () => phone.visible('#thief-link'), 20_000);
  await phone.click('#thief-link');
  const link = await phone.waitFor('the thief link', async () => {
    const shown = await phone.text('#verbatim');
    if (shown?.includes('/t/#')) return shown;
    const notice = await phone.text('#notice');
    if (notice?.startsWith('Copied')) return phone.js('navigator.clipboard.readText()');
    return null;
  }, 10_000);
  must('the link names this vault and holds its spend key', link.includes(`v=${vaultHex}`) && /k=[0-9a-f]{64}/.test(link));
  const seedHex = /k=([0-9a-f]{64})/.exec(link)[1];
  stolenSeeds.push(seedHex);

  if (reopen) {
    // As the film: the phone page opened from the vault's link, holding nothing but its id and the credential id.
    await phone.go(`${stage.origin}/phone/#v=${vaultHex}&c=${cred}`);
    await phone.waitState('idle');
  }

  await thief.go(link);
  await thief.waitState('armed', 15_000);
  check('the key leaves the address bar at once', !(await thief.js('location.hash')).includes('k='));
  await thief.js('document.getElementById("to").focus()');
  await thief.cdp.send('Input.insertText', { text: THIEF_TO });
  await thief.waitFor('Send enabled', async () => !(await thief.js('document.getElementById("send").disabled')), 15_000);
  check('the amount reads the coins before fee', (await thief.text('#amount-text')) === 'everything  2,000 sats', await thief.text('#amount-text'));
  await thief.shot('armed');
  return { vaultHex, vault, coin, seedHex, cred };
}

/** Send: the key alone at the node, its words on the screen, then the proposal and the digits. */
async function pressSend(v) {
  const postsBefore = stage.rig.posts.length;
  const pressedAt = Date.now();
  await thief.click('#send');
  await thief.waitState('refused', 20_000);
  note('press Send to refused, ms', Date.now() - pressedAt);
  must('one POST for one press', stage.rig.posts.length === postsBefore + 1, stage.rig.posts.length - postsBefore);
  const post = stage.rig.posts.at(-1);
  check('a real node answered with a 400 about the script', post.node === 400 && /script-verify|Script/.test(post.text), post.text);
  check('the screen shows the node\'s words byte for byte', (await thief.text('#node-text')) === post.text);
  check('the bar says REFUSED BY BITCOIN', (await thief.js('document.getElementById("bar").textContent.replace(/\\s+/g, " ")')) === 'REFUSED BY BITCOIN');
  check('the coin is still there after the refusal', (await stage.rig.rpc('gettxout', [v.coin.txid, v.coin.vout, true])) !== null);
  await sleep(300);
  await thief.shot('refused');

  const askedAt = Date.now();
  await thief.waitState('waiting', 60_000);
  note('refused to digits, ms', Date.now() - askedAt);
  check('the row reads the contract\'s wait', (await thief.text('#term-2')) === 'unlocks in 5:00', await thief.text('#term-2'));
  await thief.waitFor('the fling', async () => (await thief.js('document.getElementById("root").dataset.fling')) === 'done', 5000);
  const fragment = new URLSearchParams((await thief.js('location.hash')).slice(1));
  const requestId = Number(fragment.get('r'));
  const request = await views.request(v.vaultHex, requestId);
  must('the contract holds the request, with a 5:00 wait', request?.unlock - request?.proposed_at === FIVE_MINUTES, request?.unlock - request?.proposed_at);
  check('the near row names its chain', /^local NEAR sandbox tx \S+$/.test(await thief.text('#near-row')), await thief.text('#near-row'));
  check('the key left the fields once it was used', (await thief.js('document.getElementById("key").value')) === '');
  await thief.shot('waiting');

  await phone.waitState('request', 20_000);
  check('the phone reads the amount from the contract', (await phone.text('#amount')) === '2,000 sats', await phone.text('#amount'));
  const shownTo = await phone.text('#to');
  check('the phone reads the destination from the contract', toHex(addressToSpk('regtest', shownTo)) === THIEF_SPK, shownTo);
  check('the Cancel button is on the 844 px screen', await phone.js('(() => { const r = document.getElementById("cancel").getBoundingClientRect(); return r.bottom <= 844 && r.top >= 0; })()'));
  await phone.shot('request');
  return { requestId, request };
}

/** A proposal with the stolen key, sent from outside any page, against what the contract now says. */
async function proposeWithStolenKey(v) {
  const vault = await views.vault(v.vaultHex);
  const script = fromHex(await views.script(v.vaultHex));
  const to = addressToSpk('mutinynet', THIEF_TO);
  const spend = sendEverything({ coins: [{ txid: v.coin.txid, vout: v.coin.vout, value: v.coin.value }], to, script, feeRate: 2 });
  const chainNow = (await reader.blockTime()).blockMs;
  const args = buildPropose({ contract: stage.contract, vault, script, seed: fromHex(v.seedHex), inputs: spend.inputs, to, amount: spend.amount, nonce: vault.spend_nonce, expiresAt: chainNow + 30 * 60_000 });
  const res = await fetch(`${stage.origin}/api/relay`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ method: 'propose_btc', args }) });
  const body = await res.json();
  if (!body.ok) return { relay: body };
  const result = await settled(body.hash);
  return { hash: body.hash, failure: failureOf(result), pending: (await views.vault(v.vaultHex)).pending };
}

async function tapCancel(v, { lastRequest }) {
  const tapAt = Date.now();
  const [thiefAtTap, phoneAtTap] = await Promise.all([thief.reading(), phone.reading()]);
  await phone.click('#cancel');
  await phone.waitState('cancelled', 30_000);
  const stampedAt = Date.now();
  await thief.waitState('frozen', 30_000);
  const frozenAt = Date.now();
  note('tap to the phone reading cancelled, ms', stampedAt - tapAt);
  note('tap to the thief tab frozen, ms', frozenAt - tapAt);
  const timings = await phone.js('window.undoTimings');
  note('phone timings, ms from tap', {
    assertion: Math.round(timings.assertion - timings.tap),
    relayAnswered: Math.round(timings.included - timings.tap),
    readCancelled: Math.round(timings.readCancelled - timings.tap),
    sForm: timings.sForm,
  });

  const frozenThief = await thief.reading();
  const frozenPhone = await phone.reading();
  note('digits', { thiefAtTap: thiefAtTap.text, phoneAtTap: phoneAtTap.text, thiefFrozen: frozenThief.text, phoneFrozen: frozenPhone.text });
  check('the thief tab froze above zero', frozenThief.ms > 0, frozenThief.text);
  check('the phone froze above zero', frozenPhone.ms > 0, frozenPhone.text);
  check('the clock kept falling after the tap', frozenThief.ms <= thiefAtTap.ms, `${thiefAtTap.text} to ${frozenThief.text}`);

  check('CANCELLED on the phone', (await phone.text('#stamp')) === 'CANCELLED' && await phone.visible('#stamp'));
  check('CANCELLED on the thief tab', (await thief.text('.stamp-text')) === 'CANCELLED' && await thief.visible('.stamp-text'));
  check('That key can\'t ask again, on the phone', (await phone.text('#key-line')) === 'That key can\'t ask again.');
  check('That key can\'t ask again, on the thief tab', await thief.visible('#stamp-line') && (await thief.text('#stamp-line')) === 'That key can\'t ask again.');
  const hash = await phone.waitFor('the hash, once the chain says the cancel ran', () => phone.js('document.querySelector("#near-tx .hash")?.innerText ?? null'), 15_000);
  note('tap to the hash on the phone, ms', Date.now() - tapAt);
  const shown = await phone.js('document.body.innerText');
  check('the phone shows the hash and names its chain', Boolean(hash) && shown.includes('local NEAR sandbox tx') && shown.includes(hash), hash);
  check('no hash in the link: nothing a screen claims can be written into a link', !(await phone.js('location.hash')).includes('tx='));
  await thief.shot('frozen');
  await phone.shot('cancelled');

  await sleep(2500);
  const laterThief = await thief.reading();
  const laterPhone = await phone.reading();
  check('the digits stay where they stopped', laterThief.text === frozenThief.text && laterPhone.text === frozenPhone.text, `${laterThief.text}, ${laterPhone.text}`);
  await thief.shot('frozen-settled');
  check('neither page shows a Cancel or a Send after the stamp', !(await phone.visible('#cancel')) && !(await thief.visible('#send')));

  const result = await settled(hash);
  check('the contract ran the cancel', failureOf(result) === null, failureOf(result) ?? '');
  check('it was cancel_all_and_rotate on the owner key', result.transaction.actions[0].FunctionCall?.method_name === 'cancel_all_and_rotate' && result.transaction.public_key === ownerKey.publicKey, result.transaction.public_key);

  const { vault, request } = await views.both(v.vaultHex, lastRequest);
  check('the vault\'s epoch moved past the request\'s, and the spend key is suspended', request === null || (vault.spend_epoch > request.epoch), `epoch ${vault.spend_epoch}`);
  check('the contract reads the key suspended', vault.k_s_suspended === true);
  await phone.waitFor('the coin line', () => phone.visible('#coin-line'), 25_000);
  check('The coin never moved, only once a node says so', (await phone.text('#coin-line')) === 'The coin never moved.');
  check('bitcoind agrees: the coin is unspent', (await stage.rig.rpc('gettxout', [v.coin.txid, v.coin.vout, true])) !== null);
  await phone.shot('cancelled-coin');
  return { hash, result };
}

// ---------------------------------------------------------------- the three runs

async function runCancel() {
  currentRun = 'run1';
  apiWorker = 'main';
  const status = await (await fetch(`${stage.origin}/api/relay`)).json();
  check('workerd answers the page\'s origin with the state store up', status.ok === true && status.general.up && status.owner.up && status.funds.up, JSON.stringify({ general: status.general.up, owner: status.owner.up, funds: status.funds.up }));
  const v = await makeVaultFromPhone({ reopen: true });
  const { requestId, request } = await pressSend(v);
  await chips('while the clock runs');
  await agreement('at the start of the wait', { samples: 8 });
  await againstChain(request, 'at the start of the wait');

  const left = await fastForwardToLeft(request.unlock, 40_000);
  note('after the fast-forward, ms left on the contract', left);
  await letTheJumpLand();
  await agreement('in the last half minute');
  await againstChain(request, 'in the last half minute');
  check('the fuse has burned past 85% of its track, as it should under 45 s', await thief.js('document.getElementById("fuse-burn").getBoundingClientRect().width < document.getElementById("fuse").getBoundingClientRect().width * 0.85'));
  await thief.shot('last-seconds');
  await phone.shot('last-seconds');

  await tapCancel(v, { lastRequest: requestId });
  await chips('after the stamp');

  // The stolen key, on a page and without one.
  await thief.go(`${stage.origin}/t/#v=${v.vaultHex}&k=${v.seedHex}`);
  await thief.waitState('armed', 15_000);
  await thief.js('document.getElementById("to").focus()');
  await thief.cdp.send('Input.insertText', { text: THIEF_TO });
  await thief.waitFor('the page to read the key', async () => (await thief.text('#key-why')) !== '', 10_000);
  check('the thief tab, opened again with that key, says so and stays shut', (await thief.text('#key-why')) === 'That key can\'t ask again.' && await thief.js('document.getElementById("send").disabled'), await thief.text('#key-why'));
  await thief.shot('key-refused');
  const pendingBefore = (await views.vault(v.vaultHex)).pending;
  const stolen = await proposeWithStolenKey(v);
  note('the contract\'s words to the stolen key', stolen.failure ?? stolen.relay);
  check('the contract refuses a proposal from that key, sent without any page', Boolean(stolen.failure) || stolen.relay?.ok === false, stolen.failure ?? JSON.stringify(stolen.relay));
  check('no new request appeared', JSON.stringify(stolen.pending ?? pendingBefore) === JSON.stringify(pendingBefore), JSON.stringify(stolen.pending ?? pendingBefore));

  // A rotation's new key waits out T_known, and the old one must stay out after that too.
  const installAt = (await reader.blockTime()).blockMs + instance.policy.t_known_ms + 5000;
  await fastForwardToLeft(installAt, 0);
  await letTheJumpLand();
  const later = await proposeWithStolenKey(v);
  note('the contract\'s words to the stolen key after T_known', later.failure ?? later.relay);
  check('and still refuses it after T_known', Boolean(later.failure) || later.relay?.ok === false, later.failure ?? JSON.stringify(later.relay));
  check('no new request after that either', JSON.stringify(later.pending ?? pendingBefore) === JSON.stringify(pendingBefore), JSON.stringify(later.pending ?? pendingBefore));
  check('the coin is still unspent after all of it', (await stage.rig.rpc('gettxout', [v.coin.txid, v.coin.vout, true])) !== null);
}

async function runExecute() {
  currentRun = 'run2';
  apiWorker = 'main';
  const v = await makeVaultFromPhone({ reopen: false });
  const { request, requestId } = await pressSend(v);
  await agreement('at the start of the wait', { samples: 6 });
  if (REAL_WAIT) {
    note('the whole 5:00 counts in real time', true);
  } else {
    const left = await fastForwardToLeft(request.unlock, 40_000);
    note('after the fast-forward, ms left on the contract', left);
    await letTheJumpLand();
    await agreement('in the last half minute', { samples: 8 });
    await againstChain(request, 'in the last half minute');
  }
  // Nobody touches anything from here. The tab fires by itself at zero.
  const seen = [];
  const watchStart = Date.now();
  let lastClock = null;
  const deadline = watchStart + (REAL_WAIT ? 400_000 : 90_000);
  for (;;) {
    const s = await thief.state();
    if (s && seen.at(-1) !== s) seen.push(s);
    if (s === 'waiting') lastClock = (await thief.reading()).text;
    if (s === 'signed') break;
    if (Date.now() > deadline) throw new Error(`never signed: saw ${seen.join(' ')}, screen ${await thief.js('document.body.innerText')}`);
    await sleep(50);
  }
  note('thief states from here', seen.join(' > '));
  note('last reading while waiting', lastClock);
  const timings = await thief.js('window.undoTimings');
  note('zero to the contract signed, ms', Math.round((await thief.js('performance.now()')) - timings.firing));
  check('the tab called execute by itself at zero', timings.executed > 0 && seen.includes('firing'), seen.join(' > '));
  check('it says the contract signed', (await thief.text('#signed-line')) === 'The contract signed.', await thief.text('#signed-line'));
  check('the digits read zero', (await thief.reading()).text === '0:00.0', (await thief.reading()).text);

  await thief.waitFor('the txid row', async () => (await thief.js('document.getElementById("root").dataset.broadcast')) === 'done', 40_000);
  const row = await thief.text('#txid-row');
  const txid = /^local regtest txid ([0-9a-f]{64})$/.exec(row)?.[1];
  must('the txid row names its chain and appears only once a node has it', Boolean(txid), row);
  const final = await views.finalTx(v.vaultHex, requestId);
  check('the node holds the contract\'s own finished transaction', Boolean(final) && stage.rig.posts.some((p) => p.txid === txid && p.node === 200), txid);
  await thief.shot('signed');

  const mined = await thief.waitFor('the spend mined', async () => {
    const tx = await stage.rig.rpc('getrawtransaction', [txid, 1]);
    return tx.confirmations >= 1 ? tx : null;
  }, 40_000);
  check('the spend is mined', mined.confirmations >= 1, `${mined.confirmations} confirmation(s)`);
  check('it pays the thief\'s address', mined.vout.some((o) => o.scriptPubKey.hex === THIEF_SPK), THIEF_TO);
  check('its input is the vault\'s coin', mined.vin.some((i) => i.txid === v.coin.txid && i.vout === v.coin.vout));
  check('the coin is gone', (await stage.rig.rpc('gettxout', [v.coin.txid, v.coin.vout, true])) === null);
  const left = await (await fetch(`${stage.config.esplora}/address/${v.vault.address}/utxo`)).json();
  check('the vault holds nothing', left.length === 0, left.length);

  await phone.waitState('too_late', 20_000);
  check('the phone says too late, and shows no Cancel', (await phone.text('#too-late')) === 'Too late. The contract signed.' && !(await phone.visible('#cancel')));
  await phone.waitFor('the txid on the phone', async () => (await phone.js('document.body.innerText')).includes(txid), 15_000);
  check('the phone shows the same txid, named by chain', (await phone.js('document.body.innerText')).includes('local regtest txid'));
  await chips('after the signature');
  await phone.shot('too-late');
}

async function runCeiling() {
  currentRun = 'run3';
  apiWorker = 'film3';
  const v = await makeVaultFromPhone({ reopen: true });
  apiWorker = 'low';
  await sleep(10_500); // The relay's status cache.
  const near = await (await fetch(`${stage.origin}/api/relay`)).json();
  check('near the ceiling: no new vault fits, one more film does', near.general.up === false && near.general.calls_fit === true, JSON.stringify(near.general));
  check('and the thief tab does not claim it can\'t send', (await thief.text('#armed-note')) === '', await thief.text('#armed-note'));
  const { requestId } = await pressSend(v);
  check('the armed line stays on while this film still fits', (await thief.js('document.getElementById("root").dataset.auto')) === 'armed', await thief.text('#auto'));

  // An early execute is refused before the key signs, and charges nothing.
  const general = (method, args) => fetch(`${stage.origin}/api/relay`, { method: 'POST', headers: { 'content-type': 'application/json', 'x-undo-beat': BEAT }, body: JSON.stringify({ method, args }) }).then(async (r) => ({ status: r.status, body: await r.json() }));
  const generalAtStart = await keyNonce(stage.relay.publicKey);
  const early = [];
  for (let i = 0; i < 6; i += 1) early.push(await general('execute', { vault: v.vaultHex, request: requestId }));
  check('an execute before the unlock is refused by the relay, with nothing sent', early.every((o) => o.body.code === 'would_refuse') && (await keyNonce(stage.relay.publicKey)) === generalAtStart, early.map((o) => o.body.code).join(' '));

  // What is left goes as a day's traffic would have used it, and then the general key is refused.
  const ns = await mf.getDurableObjectNamespace('UNDO_STATE', 'undo-cron');
  const filled = await (await ns.get(ns.idFromName('low')).fetch('https://do/addCost', { method: 'POST', body: JSON.stringify({ key: 'general', cost: RELAY_METHODS.execute.costMicro, now: Date.now(), ceiling: 1e12 }) })).json();
  must('the rest of the general ceiling is spent', filled.ok === true, JSON.stringify(filled));
  const burst = await Promise.all(Array.from({ length: 6 }, () => general('execute', { vault: v.vaultHex, request: requestId })));
  const codes = burst.map((o) => o.body.code ?? 'sent');
  note('the burst at the ceiling', codes.join(' '));
  check('the general key is at its ceiling', codes.includes('daily_ceiling') && !codes.includes('sent'), codes.join(' '));
  await sleep(10_500); // The relay's status cache.
  const status = await (await fetch(`${stage.origin}/api/relay`)).json();
  check('status: general at its ceiling, owner up', status.general.up === false && status.general.why === 'daily_ceiling' && status.owner.up === true, JSON.stringify({ general: status.general, owner: status.owner }));

  await thief.waitFor('the thief tab to say it', async () => /today's limit/.test(await thief.text('#note')), 40_000);
  check('the thief tab says it plainly', /today's limit/.test(await thief.text('#note')), await thief.text('#note'));
  check('and does not call itself armed', (await thief.js('document.getElementById("root").dataset.auto')) === 'off', await thief.text('#auto'));
  await thief.shot('ceiling');
  await phone.waitFor('the phone to read the same status', async () => (await phone.state()) === 'request', 10_000);
  check('the Cancel button stays, because the owner key can still send', await phone.visible('#cancel'));
  await phone.shot('ceiling');

  const generalBefore = await keyNonce(stage.relay.publicKey);
  const ownerBefore = await keyNonce(ownerKey.publicKey);
  // General traffic keeps hammering while the thumb lands.
  let hammering = true;
  const refused = [];
  const hammer = (async () => {
    while (hammering) {
      const out = await Promise.all([general('heartbeat', { vault: v.vaultHex }), general('execute', { vault: v.vaultHex, request: requestId })]);
      refused.push(...out.map((o) => o.body.code ?? 'sent'));
      await sleep(150);
    }
  })();
  let tapped;
  try {
    tapped = await tapCancel(v, { lastRequest: requestId });
  } finally {
    hammering = false;
    await hammer;
  }
  note('refused while the cancel went out', { calls: refused.length, codes: [...new Set(refused)] });
  check('every general call was refused meanwhile', refused.length > 0 && refused.every((c) => c === 'daily_ceiling' || c === 'rate_limited'), [...new Set(refused)].join(' '));
  check('the general key\'s nonce did not move', (await keyNonce(stage.relay.publicKey)) === generalBefore);
  check('the owner key\'s nonce did', (await keyNonce(ownerKey.publicKey)) > ownerBefore);
  check('the cancel went out on the owner key', tapped.result.transaction.public_key === ownerKey.publicKey);
  check('the coin is unspent', (await stage.rig.rpc('gettxout', [v.coin.txid, v.coin.vout, true])) !== null);
}

// ---------------------------------------------------------------- run it

function finalChecks() {
  currentRun = 'all';
  const allowed = new Set([stage.origin, new URL(stage.config.rpc[0]).origin, new URL(stage.config.esplora).origin]);
  for (const tab of [thief, phone]) {
    check(`${tab.name}: no uncaught exception`, tab.exceptions.length === 0, tab.exceptions.slice(0, 3).join(' | '));
    check(`${tab.name}: no CSP violation`, tab.csp.length === 0, tab.csp.slice(0, 3).join(' | '));
    const hosts = new Set(tab.requests.map((r) => r.url).filter((u) => u.startsWith('http')).map((u) => new URL(u).origin));
    const off = [...hosts].filter((h) => !allowed.has(h));
    check(`${tab.name}: reached only this origin, the RPC and the node`, off.length === 0, off.join(' '));
    const leaks = tab.requests.filter((r) => stolenSeeds.some((seed) => r.url.includes(seed) || r.body.includes(seed)));
    check(`${tab.name}: no request of ${tab.requests.length} carried a spend key`, leaks.length === 0, leaks.map((r) => r.url).slice(0, 3).join(' '));
  }
}

let failed = null;
const started = Date.now();
try {
  await startEverything();
  const runs = { 1: runCancel, 2: runExecute, 3: runCeiling };
  for (const n of ONLY) {
    try {
      await runs[n]();
    } catch (err) {
      failed ??= err;
      check(`run ${n} finished`, false, err.message);
      await thief.shot('failure').catch(() => {});
      await phone.shot('failure').catch(() => {});
    }
  }
  finalChecks();
} catch (err) {
  failed ??= err;
  check('the film ran', false, err.stack);
} finally {
  await stopAll();
}

const passed = results.filter((r) => r.ok).length;
const failures = results.filter((r) => !r.ok);
console.log(`\nfilm-e2e [mock-signer] [virtual authenticator]: ${passed} passed, ${failures.length} failed, ${Math.round((Date.now() - started) / 1000)} s`);
for (const f of failures) console.log(`FAILED [${f.run}] ${f.name}: ${f.detail}`);
if (REPORT) writeFileSync(REPORT, `${JSON.stringify({ passed, failed: failures.length, realWait: REAL_WAIT, seconds: Math.round((Date.now() - started) / 1000), measured, results }, null, 1)}\n`);
process.exit(failures.length ? 1 : 0);
