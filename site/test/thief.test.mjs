// The thief tab, in one headless Chrome against the local stage: real wasm, real regtest node with standard relay
// policy, mock signer. Time is the contract's own, moved with sandboxFastForward, so the page must follow the block
// time. It says nothing about the live signer, public RPC, a real phone or a camera. Labelled [mock-signer].
//
// Until the real relay ships, /api/* here is a small stand-in below that sends the same calls with the relay's key, and
// can die or hold a call back on demand. A real-relay pass runs too once functions/_relay/handler.mjs answers.
//
// THIEF_SHOTS=DIR saves a PNG of each state at the film's size. UNDO_DRIFT_LOG=FILE saves the digit probe.
import assert from 'node:assert/strict';
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { after, before, describe, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { segwitAddress, addressToSpk } from '../../tools/lib/btc.mjs';
import { toHex } from '../../tools/lib/bytes.mjs';
import { ed25519, sha256 } from '../../tools/lib/crypto.mjs';
import { buildFunding, loadDispenser } from '../../tools/lib/dispenser.mjs';
import { action, TGAS } from '../../tools/lib/near.mjs';
import { build } from '../build.mjs';
import { buildCreateArgs, cancelArgs, cancelDigest, newVaultKeys, rotateArgs, rotateDigest, rpIdHashOf, vaultIdOf } from '../lib/intents.mjs';
import { NearReader } from '../lib/near-read.mjs';
import { executeTgas, RELAY_METHODS } from '../lib/relay-table.mjs';
import { softCredentials } from '../lib/soft-authenticator.mjs';
import { contractViews, derivedKey } from '../lib/views.mjs';
import { createPasskey, getAssertion } from '../lib/webauthn.mjs';
import { destinationProblem, fuseFraction, isNotYetUnlocked, liveRequestIn, parseSeed, relaySentence, satsText, sumOfInputs, tickPulse } from '../pages/t/logic.mjs';
import { chromeAvailable, startChrome } from './chrome.mjs';
import { stageAvailable, startStage, staticServer } from './stage.mjs';

const SITE = join(dirname(fileURLToPath(import.meta.url)), '..');
const skip = stageAvailable() && chromeAvailable() ? false : 'set NEAR_SANDBOX_BIN_PATH, UNDO_WASM_DIR and UNDO_BITCOIN_BIN, with Chrome installed';
const label = (text) => sha256(new TextEncoder().encode(`undo-test-only:thief:${text}`));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const SHOTS = process.env.THIEF_SHOTS ?? null;
const THIEF_TO = segwitAddress('mutinynet', 0, label('thief-destination').slice(0, 20));

// ---------------------------------------------------------------- no browser needed

describe('rules with no page around them', () => {
  test('only a tb1 address gets through, and the error says why', () => {
    assert.equal(destinationProblem(THIEF_TO), null);
    assert.equal(destinationProblem(''), 'empty');
    const mainnet = segwitAddress('mainnet', 0, label('x').slice(0, 20));
    assert.ok(mainnet.startsWith('bc1'));
    assert.equal(destinationProblem(mainnet), 'not_test_address');
    assert.equal(destinationProblem(segwitAddress('regtest', 0, label('x').slice(0, 20))), 'not_test_address');
    assert.equal(destinationProblem('1BoatSLRHtKNngkdXEeobR76b53LETtpyT'), 'not_test_address');
    assert.equal(destinationProblem(THIEF_TO.toUpperCase()), 'not_test_address');
    assert.equal(destinationProblem(`${THIEF_TO.slice(0, -1)}${THIEF_TO.endsWith('q') ? 'p' : 'q'}`), 'bad_address');
    assert.equal(toHex(addressToSpk('mutinynet', THIEF_TO)).slice(0, 4), '0014');
  });

  test('a key is 64 hex characters, however it was pasted, and nothing else', () => {
    const hex = 'ab'.repeat(32);
    assert.equal(toHex(parseSeed(` ${hex.slice(0, 30)}\n${hex.slice(30)} `)), hex);
    assert.equal(toHex(parseSeed(hex.toUpperCase())), hex);
    assert.equal(parseSeed('ab'.repeat(31)), null);
    assert.equal(parseSeed('zz'.repeat(32)), null);
    assert.equal(parseSeed(''), null);
  });

  test('the fuse is full at the proposal, empty exactly at zero, and burns fast in the last 45 s', () => {
    const T = 300_000;
    assert.equal(fuseFraction(T, T), 1);
    assert.equal(fuseFraction(0, T), 0);
    assert.equal(fuseFraction(-5, T), 0);
    for (let r = T; r > 1000; r -= 1000) assert.ok(fuseFraction(r - 1000, T) < fuseFraction(r, T), `moves at ${r}`);
    const inTheShot = fuseFraction(13_640, T) - fuseFraction(6_640, T);
    assert.ok(inTheShot > 0.1, `the 7 s shot burns ${inTheShot} of the track`);
    assert.ok(fuseFraction(600_000, 300_000) === 1, 'a hold that jumps past the total cannot overfill');
  });

  test('a beat falls within each second', () => {
    assert.ok(tickPulse(10_990) > 0.9);
    assert.ok(tickPulse(10_100) < 0.001);
    assert.equal(tickPulse(10_000), 0);
  });

  test('only being early is worth resending', () => {
    assert.equal(isNotYetUnlocked('{"ActionError":{"kind":{"FunctionCallError":{"ExecutionError":"Smart contract panicked: NotUnlocked { unlock: 123 }"}}}}'), true);
    assert.equal(isNotYetUnlocked('Smart contract panicked: RequestNotFound'), false);
    assert.equal(isNotYetUnlocked(null), false);
  });

  test('the relay sentences are plain, and absent while the relay works', () => {
    assert.equal(relaySentence({ reachable: true, general: { up: true, why: null } }), null);
    assert.match(relaySentence({ reachable: false, general: { up: false, why: 'relay_down' } }), /relay is down/);
    assert.match(relaySentence({ reachable: true, general: { up: false, why: 'daily_ceiling' } }), /today's limit/);
    assert.match(relaySentence({ reachable: true, general: { up: false, why: 'state_store_down' } }), /state_store_down/);
  });

  test('amount is the coins, before fee', () => {
    assert.equal(sumOfInputs([{ value: 1500 }, { value: 500 }]), 2000);
    assert.equal(satsText(2000), '2,000 sats');
  });

  test('liveRequestIn takes the newest live request and skips dead ones', async () => {
    const kinds = { 1: 'waiting', 2: 'cancelled', 3: 'expired' };
    assert.equal(await liveRequestIn([1, 2, 3], async (id) => ({ kind: kinds[id] })), 1);
    assert.equal(await liveRequestIn([2, 3], async (id) => ({ kind: kinds[id] })), null);
    assert.equal(await liveRequestIn([], async () => null), null);
  });

  test('the page ships with no inline script or style, at both paths, and needs no source map', () => {
    const page = readFileSync(join(SITE, 'pages/t/index.html'), 'utf8');
    assert.equal(readFileSync(join(SITE, 'pages/thief/index.html'), 'utf8'), page, '/thief and /t/ are the same page');
    assert.doesNotMatch(page, /<script(?![^>]*\bsrc=)/);
    assert.doesNotMatch(page, /<style|\bstyle=/);
    assert.match(page, /class="chip">signet test coins</, 'the chip is there before any script runs');
    const out = join(process.env.TMPDIR ?? '/tmp', `undo-thief-build-${process.pid}`);
    const built = build({ out, configObject: { mode: 'testnet', contract: 'c.testnet', rpc: ['https://rpc.example.test'], esplora: 'https://esplora.example.test/api', relay: '/api/relay', funds: '/api/funds', btcTxUrl: null, btcAddressUrl: null, nearTxUrl: null, rpId: 'example.test', softPasskey: false } });
    const walk = (dir) => readdirSync(dir).flatMap((n) => (statSync(join(dir, n)).isDirectory() ? walk(join(dir, n)) : [join(dir, n)]));
    const files = walk(built.out);
    assert.ok(files.some((f) => f.endsWith('/t/thief.mjs')));
    assert.ok(files.some((f) => f.endsWith('/thief/index.html')));
    assert.ok(files.some((f) => f.endsWith('/_shell.css')));
    assert.equal(files.filter((f) => f.endsWith('.map')).length, 0);
  });
});

// ---------------------------------------------------------------- the stand-in relay

function standInRelay(stage) {
  const r = {
    dead: false,
    general: { up: true, why: null, resets_at: null },
    owner: { up: true, why: null, degraded: false },
    calls: [],
    bodies: [],
    holdExecute: null,
    refuseAll: null,
  };
  r.onApi = async (req, res, url) => {
    if (r.dead) {
      req.socket.destroy();
      return;
    }
    const send = (status, value) => {
      res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
      res.end(JSON.stringify(value));
    };
    if (url.pathname !== '/api/relay') return send(404, { ok: false, code: 'bad_request' });
    if (req.method === 'GET') {
      return send(200, { ok: true, relay_account: stage.relay.accountId, contract: stage.contract, pow_bits: 8, owner: r.owner, general: r.general, funds: { up: false, why: 'esplora_down', sats: 2000 } });
    }
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const text = Buffer.concat(chunks).toString('utf8');
    r.bodies.push(text);
    const { method, args } = JSON.parse(text);
    r.calls.push(method);
    if (r.refuseAll) return send(r.refuseAll.status, r.refuseAll.body);
    if (!r.general.up) return send(429, { ok: false, code: r.general.why, message: 'over the ceiling', verbatim: null, retry_after_s: null, bucket: 'general', resets_at: null });
    if (method === 'execute' && r.holdExecute) await r.holdExecute;
    const spec = RELAY_METHODS[method];
    let tgas = spec.tgas;
    if (method === 'execute') {
      const request = await r.views.request(args.vault, args.request);
      tgas = request ? executeTgas(request.inputs.length, { signTgas: r.instance.sign_tgas, callbackTgas: r.instance.callback_tgas }) : 50;
    }
    const sent = await stage.near.send(stage.relay, stage.contract, [action.call(method, args, BigInt(tgas) * TGAS, 0n)]);
    return send(200, { ok: true, hash: sent.hash, key: 'general', method });
  };
  return r;
}

// ---------------------------------------------------------------- the whole page

describe('the thief tab in Chrome [mock-signer]', { skip, timeout: 1_500_000 }, () => {
  let stage;
  let relay;
  let server;
  let origin;
  let reader;
  let views;
  let instance;
  let chrome;
  let cdp;
  const netLog = [];
  let makes = 0;
  let msPerBlock = null;
  const drift = [];

  const shot = async (name) => {
    if (!SHOTS) return;
    mkdirSync(SHOTS, { recursive: true });
    const { data } = await cdp.send('Page.captureScreenshot', { format: 'png' });
    writeFileSync(join(SHOTS, `${name}.png`), Buffer.from(data, 'base64'));
  };

  const js = (expr) => cdp.page(`return (${expr});`);
  const stateNow = () => js('document.getElementById("root")?.dataset.state');
  const textOf = (id) => js(`document.getElementById(${JSON.stringify(id)}).textContent`);
  const clockText = () => js('document.getElementById("clock").dataset.clock');

  async function waitFor(what, fn, ms = 30_000) {
    const start = Date.now();
    let last;
    while (Date.now() - start < ms) {
      last = await fn();
      if (last) return last;
      await sleep(40);
    }
    const state = await stateNow().catch(() => 'no page');
    throw new Error(`timed out waiting for ${what} (state ${state}, last ${JSON.stringify(last)})`);
  }
  const waitState = (name, ms) => waitFor(`state ${name}`, async () => (await stateNow()) === name, ms);

  async function click(id) {
    const box = await js(`(() => { const r = document.getElementById(${JSON.stringify(id)}).getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; })()`);
    await cdp.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: box.x, y: box.y });
    await cdp.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: box.x, y: box.y, button: 'left', clickCount: 1 });
    await cdp.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: box.x, y: box.y, button: 'left', clickCount: 1 });
  }

  async function paste(id, text) {
    await js(`document.getElementById(${JSON.stringify(id)}).focus()`);
    await cdp.send('Input.insertText', { text });
  }

  const fitsFrame = () => js(`(() => { const e = document.scrollingElement; return { w: e.scrollWidth, h: e.scrollHeight, iw: innerWidth, ih: innerHeight }; })()`);
  const chipBox = () => js(`(() => { const r = document.getElementById('chip').getBoundingClientRect(); return { x: r.x, y: r.y, text: document.getElementById('chip').textContent, visible: document.getElementById('chip').checkVisibility() }; })()`);

  async function assertFrame(where) {
    const f = await fitsFrame();
    assert.ok(f.w <= f.iw && f.h <= f.ih, `${where}: ${f.w}x${f.h} in ${f.iw}x${f.ih}`);
    const c = await chipBox();
    assert.equal(c.visible, true, `${where}: chip`);
    assert.equal(c.x, 64, `${where}: chip x`);
    assert.equal(c.y, 150, `${where}: chip y`);
  }

  async function makeVault({ coin = 2000 } = {}) {
    makes += 1;
    const name = `v${makes}`;
    const soft = softCredentials({ secret: label(`${name}-passkey`), origin: stage.origin, rpId: stage.rpId });
    const made = await createPasskey({ credentials: soft, rpId: stage.rpId });
    const keys = newVaultKeys({ seed: label(`${name}-seed`), cold: label(`${name}-cold`) });
    const vaultHex = toHex(vaultIdOf({ contract: stage.contract, keys, passkeyPub: made.pubkey, csv: 6 }));
    const km = await derivedKey(reader, { signer: instance.signer, domainId: instance.domain_id, contract: stage.contract, vaultHex });
    const chainNow = (await reader.blockTime()).blockMs;
    const built = await buildCreateArgs({
      contract: stage.contract, keys, passkeyPub: made.pubkey, rpIdHash: rpIdHashOf(stage.rpId), km, guard: stage.relay.accountId, policy: instance.policy, csv: 6, expiresAt: chainNow + 30 * 60_000,
      assert: async (digest) => (await getAssertion({ credentials: soft, digest, rpId: stage.rpId, credentialId: made.credentialId })).args,
    });
    const spec = RELAY_METHODS.create_vault;
    await stage.near.sendAndWait(stage.relay, stage.contract, [
      action.call('create_vault', { args: built.args }, BigInt(spec.tgas) * TGAS, stage.milliNear(spec.depositMilli)),
      action.call('heartbeat', { vault: vaultHex }, BigInt(spec.heartbeatTgas) * TGAS, 0n),
    ]);
    const vault = await views.vault(vaultHex);
    assert.equal(vault.active, true);
    const out = { vaultHex, soft, made, keys, vault, seedHex: toHex(keys.seed), coin: null };
    if (coin) out.coin = await fund(vault.address, coin);
    return out;
  }

  async function fund(address, value) {
    const dispenser = loadDispenser(stage.rig.info.dispenser, 'regtest');
    const utxos = await (await fetch(`${stage.config.esplora}/address/${dispenser.address}/utxo`)).json();
    const made = buildFunding({ dispenser, utxos, payTo: addressToSpk('regtest', address), value, feeRate: 2 });
    await stage.rig.rpc('sendrawtransaction', [made.raw]);
    await stage.rig.mine(1);
    return made;
  }

  const open = async (path, fields, extra = '') => {
    await js('void 0').catch(() => {});
    await cdp.send('Page.navigate', { url: 'about:blank' });
    await sleep(50);
    const parts = Object.entries(fields).map(([k, v]) => `${k}=${v}`).join('&');
    await cdp.send('Page.navigate', { url: `${origin}${path}#${parts}${extra}` });
    await waitFor('page load', async () => (await js('document.readyState').catch(() => null)) === 'complete');
  };
  const openThief = (v, extra = {}) => open('/t/', { v: v.vaultHex, ...extra });

  async function rotate(v) {
    const vault = await views.vault(v.vaultHex);
    const newKs = ed25519.getPublicKey(label(`${v.vaultHex}-new-ks-${vault.passkey_nonce}`));
    const expiresAt = (await reader.blockTime()).blockMs + 10 * 60_000;
    const digest = rotateDigest({ contract: stage.contract, vaultHex: v.vaultHex, newKs, nonce: vault.passkey_nonce, expiresAt });
    const { args: assertion } = await getAssertion({ credentials: v.soft, digest, rpId: stage.rpId, credentialId: v.made.credentialId });
    return stage.near.sendAndWait(stage.payer, stage.contract, [action.call('cancel_all_and_rotate', rotateArgs({ vaultHex: v.vaultHex, newKs, nonce: vault.passkey_nonce, expiresAt, assertion }), 30n * TGAS, 0n)]);
  }

  async function plainCancel(v, request) {
    const expiresAt = (await reader.blockTime()).blockMs + 10 * 60_000;
    const digest = cancelDigest({ contract: stage.contract, vaultHex: v.vaultHex, request, expiresAt });
    const { args: assertion } = await getAssertion({ credentials: v.soft, digest, rpId: stage.rpId, credentialId: v.made.credentialId });
    return stage.near.sendAndWait(stage.payer, stage.contract, [action.call('cancel', cancelArgs({ vaultHex: v.vaultHex, request, expiresAt, assertion }), 30n * TGAS, 0n)]);
  }

  /** Moves the contract's clock to within `leftMs` of `target`, never past it. */
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

  /** Runs in the page: every text box and digit slot, every frame. The film's rule, read in real time and not by seeking. */
  const DRIFT_PROBE = `(() => {
    const P = window.__drift = { frames: 0, moves: 0, sub: [], long: [], runs: new Map(), prev: new Map(), ids: new WeakMap(), next: 0, seen: new Set(), on: true, digitChanges: 0, digitSlotMoves: 0, digitFirst: null, digitLast: null, start: performance.now() };
    const frame = (now) => {
      if (!P.on) return;
      P.frames += 1;
      const live = new Set();
      for (const e of document.querySelectorAll('#root *')) {
        const own = [...e.childNodes].filter((n) => n.nodeType === 3).map((n) => n.textContent).join('').trim();
        if (!own && !e.classList.contains('sl')) continue;
        if (!e.checkVisibility({ visibilityProperty: true })) continue;
        if (!P.ids.has(e)) P.ids.set(e, P.next++);
        const id = P.ids.get(e);
        const r = e.getBoundingClientRect();
        const b = { x: +r.x.toFixed(3), y: +r.y.toFixed(3), w: +r.width.toFixed(3), h: +r.height.toFixed(3), own };
        live.add(id); P.seen.add(id);
        const p = P.prev.get(id);
        if (p) {
          const dx = Math.abs(b.x - p.x), dy = Math.abs(b.y - p.y);
          const sameText = b.own === p.own;
          const dw = sameText ? Math.abs(b.w - p.w) : 0, dh = sameText ? Math.abs(b.h - p.h) : 0;
          const d = Math.max(dx, dy, dw, dh);
          if (e.classList.contains('sl') && !sameText) P.digitChanges += 1;
          if (d > 0.001) {
            P.moves += 1;
            if (e.classList.contains('sl')) { P.digitSlotMoves += 1; P.digitFirst ??= now; P.digitLast = now; }
            if (d < 0.8) P.sub.push({ t: Math.round(now - P.start), text: own.slice(0, 40), moved: d, state: document.getElementById('root').dataset.state });
            const run = P.runs.get(id) ?? { from: now };
            P.runs.set(id, run);
            if (now - run.from > 300 && !P.long.some((l) => l.id === id)) P.long.push({ id, t: Math.round(now - P.start), text: own.slice(0, 40), state: document.getElementById('root').dataset.state });
          } else P.runs.delete(id);
        }
        P.prev.set(id, b);
      }
      for (const id of [...P.prev.keys()]) if (!live.has(id)) { P.prev.delete(id); P.runs.delete(id); }
      requestAnimationFrame(frame);
    };
    requestAnimationFrame(frame);
    return true;
  })()`;

  const readDrift = () => js(`(() => { const P = window.__drift; P.on = false; return { frames: P.frames, textBoxes: P.seen.size, moves: P.moves, digitChanges: P.digitChanges, digitSlotMoves: P.digitSlotMoves, digitMoveSpanMs: P.digitLast === null ? 0 : Math.round(P.digitLast - P.digitFirst), sub: P.sub, long: P.long }; })()`);

  before(async () => {
    stage = await startStage({ miner: true, softPasskey: false });
    reader = new NearReader({ urls: stage.config.rpc, timeoutMs: 15_000 });
    views = contractViews(reader, stage.contract);
    instance = await views.instance();
    relay = standInRelay(stage);
    relay.views = views;
    relay.instance = instance;
    const port = Number(new URL(stage.origin).port) + 1;
    server = await staticServer({ dir: stage.dir, port, onApi: (req, res, url) => relay.onApi(req, res, url).catch((err) => {
      res.writeHead(500);
      res.end(err.message);
    }) });
    origin = `http://localhost:${port}`;
    chrome = await startChrome({ width: 1080, height: 1350, scale: 2 });
    cdp = chrome.cdp;
    await cdp.send('Network.enable');
    cdp.ws.addEventListener('message', (event) => {
      const data = JSON.parse(event.data);
      if (data.method === 'Network.requestWillBeSent') netLog.push({ url: data.params.request.url, body: data.params.request.postData ?? '' });
    });
  }, { timeout: 180_000 });

  after(async () => {
    await chrome?.stop();
    server?.close();
    server?.closeAllConnections?.();
    await stage?.stop();
    if (drift.length && process.env.UNDO_DRIFT_LOG) writeFileSync(process.env.UNDO_DRIFT_LOG, `${JSON.stringify(drift, null, 1)}\n`);
  });

  const toArmed = async (v, extra = {}) => {
    await openThief(v, { to: THIEF_TO, k: v.seedHex, ...extra });
    await waitState('armed');
    await waitFor('Send enabled', async () => !(await js('document.getElementById("send").disabled')));
  };

  /** From armed to digits on the frame, returning the request id. */
  const pressToWaiting = async () => {
    await click('send');
    await waitState('refused');
    await waitState('waiting', 60_000);
    return Number(new URLSearchParams((await js('location.hash')).slice(1)).get('r'));
  };

  test('armed: the key leaves the address bar at once, and a wrong key or a real address stops the button', { timeout: 60_000 }, async () => {
    const v = await makeVault();
    const other = await makeVault({ coin: 0 });
    await open('/t/', { v: v.vaultHex, k: v.seedHex, to: THIEF_TO, }, '&cursor=1');
    await waitState('armed');
    assert.ok(!(await js('location.hash')).includes(v.seedHex), 'the key is out of the address bar');
    assert.ok(!(await js('location.hash')).includes('k='));
    await waitFor('Send enabled', async () => !(await js('document.getElementById("send").disabled')));
    assert.equal(await js('document.getElementById("key").value'), v.seedHex);
    assert.equal(await textOf('amount'), 'everything  2,000 sats', 'the coins, before fee');
    assert.equal(await js('document.getElementById("root").dataset.delayMs'), '300000');
    await js('document.getElementById("send").scrollIntoView()');
    const box = await js(`(() => { const r = document.getElementById('send').getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; })()`);
    await cdp.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: box.x, y: box.y });
    await assertFrame('armed');
    await shot('01-armed');

    // Wrong key.
    await js('(() => { const e = document.getElementById("key"); e.value = ""; e.focus(); })()');
    await paste('key', other.seedHex);
    await waitFor('wrong key words', async () => (await textOf('key-why')) === 'That key is not this vault\'s');
    assert.equal(await js('document.getElementById("send").disabled'), true);
    await shot('02-wrong-key');
    await js('(() => { const e = document.getElementById("key"); e.value = ""; e.focus(); })()');
    await paste('key', 'not a key');
    await waitFor('not-a-key words', async () => /64 hex/.test(await textOf('key-why')));
    assert.equal(await js('document.getElementById("send").disabled'), true);
    await js('(() => { const e = document.getElementById("key"); e.value = ""; e.focus(); })()');
    await paste('key', v.seedHex);

    // A real address, and an address from another network.
    await js('(() => { const e = document.getElementById("to"); e.value = ""; e.focus(); })()');
    await paste('to', segwitAddress('mainnet', 0, label('real').slice(0, 20)));
    await waitFor('tb1 words', async () => /start with tb1/.test(await textOf('to-why')));
    assert.equal(await js('document.getElementById("send").disabled'), true);
    await shot('03-real-address-refused');
    await js('(() => { const e = document.getElementById("to"); e.value = ""; e.focus(); })()');
    await paste('to', THIEF_TO);
    await waitFor('Send enabled again', async () => !(await js('document.getElementById("send").disabled')));
  });

  test('no coin: says so, names the address, no button; then the coin lands and the button is there', { timeout: 60_000 }, async () => {
    const v = await makeVault({ coin: 0 });
    await openThief(v, { to: THIEF_TO, k: v.seedHex });
    await waitState('short');
    assert.equal(await textOf('plain-text'), 'No coin in this vault yet');
    assert.match(await textOf('plain-address'), /address bcrt1/, 'a local run labels itself by its own chain');
    await assertFrame('short');
    await shot('04-short');
    await fund(v.vault.address, 3000);
    await waitState('armed', 15_000);
    assert.equal(await textOf('amount'), 'everything  3,000 sats');
  });

  test('no vault in the link, and an unknown vault: a plain sentence and no controls', { timeout: 30_000 }, async () => {
    await open('/t/', {});
    await waitState('no_vault');
    assert.match(await textOf('plain-text'), /no vault/i);
    assert.equal(await js('[...document.querySelectorAll("button, input, textarea")].filter((e) => e.checkVisibility()).length'), 0);
    await assertFrame('no_vault');
    await shot('05-no-vault');
    await open('/t/', { v: 'ab'.repeat(32) });
    await waitState('no_vault');
    assert.match(await textOf('plain-text'), /not on this contract/);
    assert.equal(await js('[...document.querySelectorAll("button, input, textarea")].filter((e) => e.checkVisibility()).length'), 0);
  });

  test('the whole film, ending in CANCELLED: real refusal, proposal, fling, running digits, a stamp once, digits frozen', { timeout: 240_000 }, async () => {
    const v = await makeVault();
    await toArmed(v, {});
    netLog.length = 0;
    relay.bodies.length = 0;
    const postsBefore = stage.rig.posts.length;
    await js(DRIFT_PROBE);
    await click('send');
    await waitFor('the POST', async () => stage.rig.posts.length > postsBefore);
    await waitState('refused');
    await sleep(120);
    await shot('06-refused-slam');
    await sleep(900);
    await assertFrame('refused');
    await shot('07-refused');

    const post = stage.rig.posts.at(-1);
    assert.equal(stage.rig.posts.length, postsBefore + 1, 'one POST for one press');
    assert.equal(post.node, 400, 'a real node answered');
    assert.match(post.text, /mempool-script-verify-flag-failed|script-verify/);
    assert.equal(await textOf('node-text'), post.text, 'the node\'s words, byte for byte');
    assert.equal(await textOf('node-label'), 'local regtest node:');
    assert.equal(await js('document.getElementById("bar").textContent.replace(/\\s+/g, " ")'), 'REFUSED BY BITCOIN');
    assert.equal(await textOf('needs'), 'It needs a second signature.');
    const nodeBox = await js(`(() => { const r = document.getElementById('node').getBoundingClientRect(); return { bottom: r.bottom, font: getComputedStyle(document.getElementById('node')).fontSize }; })()`);
    assert.ok(nodeBox.bottom <= 1350, `the answer fits whole, ending at ${nodeBox.bottom}`);
    assert.equal(nodeBox.font, '36px', `a ${post.text.length}-character answer stays at the animatic's 36 mono`);

    await waitState('asking', 5_000);
    await shot('08-asking');
    await waitState('waiting', 60_000);
    const row = await textOf('term-2');
    assert.equal(row, 'unlocks in 5:00', 'the contract\'s wait, on the row the digits leave');
    await shot('09-row');
    await waitFor('the fling', async () => (await js('document.getElementById("root").dataset.fling')) === 'done', 5_000);
    const timing = await js('window.undoTimings');
    assert.ok(timing.landed - timing.fling < 300, `landed in ${timing.landed - timing.fling} ms`);
    await sleep(300);
    await assertFrame('waiting');
    await shot('10-waiting-5m');

    const r = await js('Number(new URLSearchParams(location.hash.slice(1)).get("r"))');
    const req = await views.request(v.vaultHex, r);
    assert.equal(req.unlock - req.proposed_at, 300_000);
    assert.equal(await textOf('dest-row'), `to ${THIEF_TO}  2,000 sats`);
    assert.match(await textOf('near-row'), /^local NEAR sandbox tx \S+$/);
    assert.equal(await js('document.getElementById("root").dataset.auto'), 'armed');
    assert.equal(await textOf('auto'), 'auto-execute armed');

    const size = await js(`(() => { const c = document.getElementById('clock'); const r = c.getBoundingClientRect(); const a = document.getElementById('d-m').getBoundingClientRect(), b = document.getElementById('d-t').getBoundingClientRect(); return { frac: (b.right - a.left) / innerWidth, slot: a.width, font: getComputedStyle(c).fontSize, tnum: getComputedStyle(c).fontVariantNumeric, top: r.top, left: a.left, right: b.right }; })()`);
    assert.ok(size.slot > 150, `a digit slot is ${size.slot} px wide`);
    assert.ok(size.frac >= 1 / 3, `digits take ${size.frac} of the width`);
    assert.ok(size.left >= 0 && size.right <= 1080, `digits stay on the frame, ${size.left} to ${size.right}`);
    assert.equal(size.font, '400px');
    assert.equal(size.tnum, 'tabular-nums');
    assert.equal(size.top, 596, 'digits on the film\'s line');

    // Running tenths, in fixed slots, against the contract's own number.
    const seen = new Set();
    for (let i = 0; i < 30; i += 1) {
      seen.add((await clockText()).slice(-1));
      await sleep(70);
    }
    assert.ok(seen.size >= 5, `tenths ran: ${[...seen]}`);
    const reading = await clockText();
    const block = await reader.blockTime();
    const truth = (req.unlock - block.blockMs) / 1000;
    const [mm, rest] = reading.split(':');
    const shown = Number(mm) * 60 + Number(rest);
    assert.ok(Math.abs(shown - truth) < 3, `reads ${reading}, chain says ${truth}`);

    // The contract's clock jumps; the page follows the block time and only that. Then the shot's real seconds.
    await fastForwardToLeft(req.unlock, 40_000);
    await waitFor('the page to follow the chain', async () => {
      const t = await clockText();
      return Number(t.split(':')[0]) === 0;
    }, 15_000);
    await shot('11-waiting-under-1m');
    const fuseMid = await js('document.getElementById("fuse-burn").getBoundingClientRect().width');
    await sleep(2000);
    const fuseLater = await js('document.getElementById("fuse-burn").getBoundingClientRect().width');
    assert.ok(fuseLater < fuseMid - 15, `the fuse burns: ${fuseMid} to ${fuseLater} in 2 s`);

    const postsDuring = stage.rig.posts.length;
    await js(`(() => { window.__stamps = 0; document.getElementById('stamp').addEventListener('animationstart', () => { window.__stamps += 1; }); })()`);
    const out = await rotate(v);
    assert.ok(out.hash);
    await waitState('frozen', 8_000);
    await sleep(40);
    await shot('12-stamp');
    const frozenAt = await clockText();
    await sleep(600);
    await assertFrame('frozen');
    await shot('13-frozen');
    assert.equal(await textOf('stamp').then((t) => t.trim()), 'CANCELLED');
    assert.equal(await js('getComputedStyle(document.getElementById("clock")).color'), 'rgb(255, 255, 255)');
    assert.equal(await js('document.getElementById("stamp-line").classList.contains("on")'), true);
    assert.equal(await textOf('stamp-line'), 'That key can\'t ask again.');
    assert.equal(await js('document.getElementById("near-row").checkVisibility()'), false, 'the proposal\'s hash is not shown under a cancel');
    assert.equal(await js('document.getElementById("fuse").checkVisibility()'), false);

    for (let i = 0; i < 12; i += 1) {
      assert.equal(await clockText(), frozenAt, 'the frozen reading does not move');
      await sleep(500);
    }
    assert.equal(await js('window.__stamps'), 1, 'it stamps once');
    assert.equal(relay.calls.filter((m) => m === 'execute').length, 0, 'it never called execute');
    assert.equal(stage.rig.posts.length, postsDuring, 'nothing else went to Bitcoin');
    assert.equal((await (await fetch(`${stage.config.esplora}/tx/${v.coin.txid}/outspend/${v.coin.vout}`)).json()).spent, false, 'the coin stayed');

    const probe = await readDrift();
    drift.push({ case: 'cancelled', ...probe });
    assert.ok(probe.digitChanges > 100, `the digits really changed: ${probe.digitChanges}`);
    assert.ok(probe.digitMoveSpanMs < 300, `digit slots moved only in the fling, over ${probe.digitMoveSpanMs} ms`);
    assert.deepEqual(probe.sub, [], 'no text moved by a fraction of a pixel');
    assert.deepEqual(probe.long, [], 'no text kept moving for over 0.3 s');

    // The key left only as signatures.
    for (const entry of netLog) {
      assert.ok(!entry.url.includes(v.seedHex), `key in a URL: ${entry.url}`);
      assert.ok(!entry.body.includes(v.seedHex), `key in a body to ${entry.url}`);
    }
    assert.ok(netLog.length > 10, `watched ${netLog.length} requests`);
    for (const body of relay.bodies) assert.ok(!body.includes(v.seedHex));
    assert.ok(!(await js('location.hash')).includes(v.seedHex));
    assert.equal(await js('document.getElementById("key").value'), '', 'dropped once proposed');

    // A reload of the finished page: stamp, no invented digits.
    await js('location.reload()');
    await waitState('frozen', 10_000);
    assert.equal(await js('document.getElementById("root").dataset.noReading'), '1');
    assert.equal(await js('getComputedStyle(document.getElementById("clock")).visibility'), 'hidden', 'no reading was on this screen, so none is drawn');
    await shot('14-frozen-after-reload');
  });

  test('the other ending: at zero it calls execute by itself, the contract signs, and a real node takes it', { timeout: 180_000 }, async () => {
    const v = await makeVault();
    await toArmed(v, {});
    const r = await pressToWaiting();
    const req = await views.request(v.vaultHex, r);
    await fastForwardToLeft(req.unlock, 9_000);
    await waitFor('under ten seconds', async () => {
      const t = await clockText();
      return t.startsWith('0:0') || t.startsWith('0:1');
    }, 20_000);
    await js(DRIFT_PROBE);
    const callsBefore = relay.calls.length;
    await waitState('firing', 40_000);
    assert.equal(await clockText(), '0:00.0');
    await assertFrame('firing');
    await waitFor('execute', async () => relay.calls.slice(callsBefore).includes('execute'), 10_000);
    await shot('15-firing');
    await waitFor('signing or signed', async () => ['signing', 'signed'].includes(await stateNow()), 30_000);
    if ((await stateNow()) === 'signing') await shot('16-signing');
    await waitState('signed', 60_000);
    await waitFor('the txid', async () => (await js('document.getElementById("root").dataset.broadcast')) === 'done', 30_000);
    await assertFrame('signed');
    await shot('17-signed');
    const row = await textOf('txid-row');
    assert.match(row, /^local regtest txid [0-9a-f]{64}$/);
    const txid = row.split(' ').at(-1);
    assert.equal(await textOf('signed-line'), 'The contract signed.');
    assert.equal(await js('document.getElementById("stamp").checkVisibility()'), false, 'no stamp');
    const tx = await (await fetch(`${stage.config.esplora}/tx/${txid}`)).json();
    assert.equal(tx.txid, txid, 'the node has it');
    assert.equal((await (await fetch(`${stage.config.esplora}/tx/${v.coin.txid}/outspend/${v.coin.vout}`)).json()).spent, true, 'the coin left');

    // A tap after this changes nothing on screen: never a stamp on a coin that left.
    await rotate(v);
    await sleep(6000);
    assert.equal(await stateNow(), 'signed');
    assert.equal(await js('document.getElementById("stamp").checkVisibility()'), false);
    const probe = await readDrift();
    drift.push({ case: 'executed', ...probe });
    assert.equal(probe.digitSlotMoves, 0, 'no fling in this stretch, so no digit slot moved at all');
    assert.deepEqual(probe.sub, []);
    assert.deepEqual(probe.long, []);
  });

  test('the race: execute is on its way when the cancel lands, and the contract decides for the cancel', { timeout: 180_000 }, async () => {
    const v = await makeVault();
    await toArmed(v, {});
    const r = await pressToWaiting();
    const req = await views.request(v.vaultHex, r);
    let release;
    relay.holdExecute = new Promise((res) => {
      release = res;
    });
    await fastForwardToLeft(req.unlock, 6_000);
    const callsBefore = relay.calls.filter((m) => m === 'execute').length;
    await waitState('firing', 40_000);
    await waitFor('execute sent', async () => relay.calls.filter((m) => m === 'execute').length > callsBefore, 10_000);
    const out = await rotate(v);
    assert.ok(out.hash);
    relay.holdExecute = null;
    release();
    await waitState('frozen', 15_000);
    assert.equal(await clockText(), '0:00.0', 'cancelled at zero is what happened');
    await assertFrame('frozen at zero');
    await shot('18-race-frozen-at-zero');
    await sleep(6000);
    assert.equal(await stateNow(), 'frozen', 'and it stays there');
    const after = await views.request(v.vaultHex, r);
    assert.equal(after.status, 'Pending', 'execute changed nothing');
    assert.equal((await (await fetch(`${stage.config.esplora}/tx/${v.coin.txid}/outspend/${v.coin.vout}`)).json()).spent, false);
  });

  test('a plain cancel: stamped, but the key can still ask, so the page does not say it can\'t', { timeout: 120_000 }, async () => {
    const v = await makeVault();
    await toArmed(v, {});
    const r = await pressToWaiting();
    await plainCancel(v, r);
    await waitState('frozen', 10_000);
    assert.equal(await js('document.getElementById("stamp-line").classList.contains("on")'), false);
    assert.equal((await js('document.getElementById("clock").dataset.clock')).length > 0, true);
  });

  test('a dead Mutinynet: no red bar, the node\'s words or the error, and a retry that gets the real refusal', { timeout: 120_000 }, async () => {
    const v = await makeVault();
    await toArmed(v, {});
    const words = '<html><body>Bad Gateway: not a node</body></html>';
    stage.rig.setRule(async (x) => (x.method === 'POST' ? { status: 502, body: words } : null));
    await click('send');
    await waitState('no_answer', 15_000);
    assert.equal(await textOf('plain-text'), 'The node did not answer:');
    assert.equal(await textOf('plain-verbatim'), words);
    assert.equal(await js('document.getElementById("bar").checkVisibility()'), false, 'a 502 is not a refusal');
    assert.equal(await js('document.body.textContent.includes("REFUSED") && document.getElementById("refused").checkVisibility()'), false);
    await assertFrame('no_answer');
    await shot('19-node-502');

    // A connection dropped halfway says so, with no invented words.
    stage.rig.setRule(null);
    stage.rig.setFault('relay-flaky');
    // relay-flaky answers 503, 429, drop, 502 on successive sends of the same bytes.
    for (const expectWords of ['Service Unavailable', 'Too Many Requests', 'TypeError', 'Bad Gateway']) {
      await click('plain-retry');
      await waitFor(`no_answer: ${expectWords}`, async () => (await stateNow()) === 'no_answer' && (await textOf('plain-verbatim')).includes(expectWords), 20_000).catch(async (err) => {
        throw new Error(`${err.message}; screen says ${await textOf('plain-verbatim')}`);
      });
      await sleep(100);
    }
    await click('plain-retry');
    await waitState('refused', 20_000);
    stage.rig.setFault(null);
    assert.match(await textOf('node-text'), /script-verify/);
    assert.equal(await js('document.getElementById("refused").checkVisibility()'), true);
    await waitState('waiting', 60_000);
  });

  test('a node that refuses for another reason gets no red bar', { timeout: 60_000 }, async () => {
    const v = await makeVault();
    await toArmed(v, {});
    const words = 'sendrawtransaction RPC error: {"code":-26,"message":"min relay fee not met, 100 < 121"}';
    stage.rig.setRule(async (x) => (x.method === 'POST' ? { status: 400, body: words } : null));
    await click('send');
    await waitState('other_refusal', 15_000);
    assert.equal(await textOf('plain-verbatim'), `local regtest node: ${words}`);
    assert.equal(await js('document.getElementById("refused").checkVisibility()'), false);
    await shot('20-other-refusal');
    stage.rig.setRule(null);
  });

  test('a dead Mutinynet before the press: says so, no button, and recovers by itself', { timeout: 90_000 }, async () => {
    const v = await makeVault();
    stage.rig.setRule(async (x) => (x.method === 'GET' && x.path.includes('/utxo') ? { status: 503, body: 'Service Unavailable' } : null));
    await openThief(v, { to: THIEF_TO, k: v.seedHex });
    await waitFor('the words', async () => /Can't read local regtest right now/.test(await textOf('armed-note')), 30_000);
    assert.equal(await stateNow(), 'armed');
    assert.equal(await js('document.getElementById("send").disabled'), true);
    await assertFrame('armed, node down');
    await shot('21-esplora-down');
    stage.rig.setRule(null);
    await waitFor('Send enabled', async () => !(await js('document.getElementById("send").disabled')), 20_000);
    assert.equal(await textOf('armed-note'), '');
  });

  test('Mutinynet dies at the end: signed, not sent, says so, and sends when it comes back', { timeout: 180_000 }, async () => {
    const v = await makeVault();
    await toArmed(v, {});
    const r = await pressToWaiting();
    const req = await views.request(v.vaultHex, r);
    stage.rig.setRule(async (x) => (x.method === 'POST' ? { status: 503, body: 'Service Unavailable' } : null));
    await fastForwardToLeft(req.unlock, 5_000);
    await waitState('signed', 90_000);
    await waitFor('the words', async () => (await js('document.getElementById("root").dataset.broadcast')) === 'no_answer', 15_000);
    assert.match(await textOf('note'), /Signed, not sent yet\. The node did not answer: Service Unavailable/);
    assert.equal(await textOf('txid-row'), '', 'no txid before a node has it');
    await shot('22-signed-not-sent');
    stage.rig.setRule(null);
    await waitFor('the txid', async () => (await js('document.getElementById("root").dataset.broadcast')) === 'done', 20_000);
    assert.match(await textOf('txid-row'), /^local regtest txid /);
  });

  test('a dead relay: says so before and after the press, shows no armed claim, and retries when it is back', { timeout: 180_000 }, async () => {
    const v = await makeVault();
    relay.dead = true;
    await openThief(v, { to: THIEF_TO, k: v.seedHex });
    await waitState('armed');
    await waitFor('the sentence', async () => /relay is down/.test(await textOf('armed-note')));
    await assertFrame('armed, relay down');
    await shot('23-relay-down-armed');
    await click('send');
    await waitState('refused', 15_000);
    await waitState('asking', 5_000);
    await waitFor('the asking words', async () => (await js('document.getElementById("root").dataset.why')) === 'relay_down', 30_000);
    assert.match(await textOf('term-1'), /relay is down/);
    assert.match(await textOf('ask-why'), /relay_down/);
    assert.equal(await js('document.getElementById("clock-block").checkVisibility()'), false, 'no clock without a request');
    await assertFrame('asking, relay down');
    await shot('24-relay-down-asking');
    relay.dead = false;
    await click('ask-retry');
    await waitState('waiting', 60_000);

    // It dies again during the count. The clock is the contract's and keeps falling; the page stops claiming it will fire.
    const r = Number(new URLSearchParams((await js('location.hash')).slice(1)).get('r'));
    const req = await views.request(v.vaultHex, r);
    relay.dead = true;
    await js('location.reload()');
    await waitState('waiting', 10_000);
    await waitFor('the waiting words', async () => (await js('document.getElementById("root").dataset.auto')) === 'off', 10_000);
    assert.match(await textOf('auto'), /relay down/);
    assert.match(await textOf('note'), /relay is down/);
    await shot('25-relay-down-waiting');
    await fastForwardToLeft(req.unlock, 4_000);
    await waitState('firing', 30_000);
    await waitFor('the firing words', async () => /relay is down/.test(await textOf('note')), 15_000);
    assert.equal(await clockText(), '0:00.0');
    await assertFrame('firing, relay down');
    await shot('26-relay-down-firing');
    relay.dead = false;
    await waitState('signed', 90_000);
  });

  test('the relay at its ceiling: says that, not down', { timeout: 60_000 }, async () => {
    const v = await makeVault();
    relay.general = { up: false, why: 'daily_ceiling', resets_at: 1 };
    await openThief(v, { to: THIEF_TO, k: v.seedHex });
    await waitFor('the sentence', async () => /today's limit/.test(await textOf('armed-note')));
    await click('send');
    await waitState('asking', 15_000);
    await waitFor('the asking words', async () => (await js('document.getElementById("root").dataset.why')) === 'daily_ceiling', 15_000);
    assert.match(await textOf('term-1'), /today's limit/);
    relay.general = { up: true, why: null, resets_at: null };
  });

  test('a reload mid-count: same contract reading, no replayed fling, auto-execute still armed, no key needed', { timeout: 180_000 }, async () => {
    const v = await makeVault();
    await toArmed(v, {});
    const r = await pressToWaiting();
    const req = await views.request(v.vaultHex, r);
    await fastForwardToLeft(req.unlock, 25_000);
    await sleep(5500);
    const before = await clockText();
    await js('location.reload()');
    await waitState('waiting', 10_000);
    assert.equal(await js('document.getElementById("root").dataset.fling'), 'done', 'no second fling');
    const afterReload = await clockText();
    const secs = (t) => Number(t.split(':')[0]) * 60 + Number(t.split(':')[1]);
    assert.ok(secs(afterReload) <= secs(before) && secs(before) - secs(afterReload) < 6, `${before} then ${afterReload}`);
    assert.equal(await js('document.getElementById("key").value'), '');
    assert.equal(await textOf('dest-row'), `to ${THIEF_TO}  2,000 sats`);
    assert.match(await textOf('near-row'), /^local NEAR sandbox tx /, 'the hash came through the reload');
    await assertFrame('reloaded');
    await shot('27-after-reload');
    await waitState('firing', 40_000);
    await waitState('signed', 90_000);

    // And a link that names no request finds nothing to resume once the request has gone out.
    await openThief(v, { to: THIEF_TO });
    await waitState('short', 15_000);
  });

  test('a reload, then the cancel lands while the page is away: a `cancel` deletes the row, and the sighting makes that a cancel', { timeout: 120_000 }, async () => {
    const v = await makeVault();
    await toArmed(v, {});
    const r = await pressToWaiting();
    await sleep(1500);
    await cdp.send('Page.navigate', { url: 'about:blank' });
    await plainCancel(v, r);
    assert.equal(await views.request(v.vaultHex, r), null);
    await open('/t/', { v: v.vaultHex, r });
    await waitState('frozen', 10_000);
    assert.equal(await js('document.getElementById("root").dataset.noReading'), '1');
    // With no sighting at all, the page does not claim a cancel.
    await js('sessionStorage.clear()');
    await open('/t/', { v: v.vaultHex, r });
    await waitState('no_request', 15_000);
    assert.equal(await textOf('plain-text'), 'That request is not on this contract.');
    await shot('28-no-request');
  });

  test('NEAR RPC unreachable: after three bad reads the clock stops and dims and says so, then picks up from the chain', { timeout: 120_000 }, async () => {
    const v = await makeVault();
    await toArmed(v, {});
    await pressToWaiting();
    await sleep(500);
    await cdp.send('Network.setBlockedURLs', { urls: [`${stage.config.rpc[0]}*`] });
    await waitFor('the dim', async () => (await js('document.getElementById("root").dataset.dim')) === '1', 25_000);
    assert.equal(await textOf('note'), 'Can\'t read the NEAR contract right now');
    const stopped = await clockText();
    await sleep(1500);
    assert.equal(await clockText(), stopped, 'stopped, not free-running');
    assert.equal(await js('getComputedStyle(document.getElementById("clock")).opacity'), '0.35');
    await assertFrame('rpc down');
    await shot('29-rpc-down');
    await cdp.send('Network.setBlockedURLs', { urls: [] });
    await waitFor('the recovery', async () => (await js('document.getElementById("root").dataset.dim')) === undefined, 15_000);
    await waitFor('digits moving', async () => (await clockText()) !== stopped, 5_000);
    assert.equal(await textOf('note'), '');
  });

  test('a hold: the unlock jumps on the contract, the digits go with it, and the real reason shows', { skip: 'needs a real guard signature; the screen is read from assess_reason and hold_active, and no test makes one yet', timeout: 10_000 }, async () => {});

  test('the laptop on the tripod: digits take over a third of a landscape screen, every state fits, and the chip stays', { timeout: 180_000 }, async () => {
    await cdp.send('Emulation.setDeviceMetricsOverride', { width: 1512, height: 982, deviceScaleFactor: 2, mobile: false });
    try {
      const fits = async (where) => {
        const f = await fitsFrame();
        assert.ok(f.w <= f.iw && f.h <= f.ih, `${where}: ${f.w}x${f.h} in ${f.iw}x${f.ih}`);
        assert.equal((await chipBox()).visible, true);
      };
      const v = await makeVault();
      await toArmed(v, {});
      await fits('armed');
      await shot('30-landscape-armed');
      await click('send');
      await waitState('refused', 15_000);
      await sleep(1000);
      await fits('refused');
      await shot('31-landscape-refused');
      await waitState('waiting', 60_000);
      await waitFor('the fling', async () => (await js('document.getElementById("root").dataset.fling')) === 'done', 5_000);
      await sleep(300);
      await fits('waiting');
      const frac = await js('(document.getElementById("d-t").getBoundingClientRect().right - document.getElementById("d-m").getBoundingClientRect().left) / innerWidth');
      assert.ok(frac >= 1 / 3, `digits take ${frac} of the width`);
      const r = await js('Number(new URLSearchParams(location.hash.slice(1)).get("r"))');
      const req = await views.request(v.vaultHex, r);
      await fastForwardToLeft(req.unlock, 20_000);
      await waitFor('under a minute', async () => (await clockText()).startsWith('0:'), 15_000);
      await shot('32-landscape-waiting');
      await rotate(v);
      await waitState('frozen', 10_000);
      await sleep(400);
      await fits('frozen');
      await shot('33-landscape-frozen');
    } finally {
      await cdp.send('Emulation.setDeviceMetricsOverride', { width: 1080, height: 1350, deviceScaleFactor: 2, mobile: false });
    }
  });

  test('a phone-width screen does not scroll sideways', { timeout: 60_000 }, async () => {
    await cdp.send('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 2, mobile: true });
    try {
      const v = await makeVault();
      await toArmed(v, {});
      const f = await fitsFrame();
      assert.ok(f.w <= f.iw, `${f.w} in ${f.iw}`);
      await shot('34-phone-width-armed');
    } finally {
      await cdp.send('Emulation.setDeviceMetricsOverride', { width: 1080, height: 1350, deviceScaleFactor: 2, mobile: false });
    }
  });

  test('through the relay owner\'s real handler, if it is there', { timeout: 180_000, skip: existsSync(join(SITE, 'functions/_relay/handler.mjs')) ? false : 'functions/_relay/handler.mjs is not there yet' }, async () => {
    const status = await (await fetch(`${stage.origin}/api/relay`)).json();
    if (!status.ok || !status.general?.up) return;
    const v = await makeVault();
    const old = origin;
    origin = stage.origin;
    try {
      await toArmed(v, {});
      const r = await pressToWaiting();
      const req = await views.request(v.vaultHex, r);
      await fastForwardToLeft(req.unlock, 5_000);
      await waitState('signed', 90_000);
      await waitFor('the txid', async () => (await js('document.getElementById("root").dataset.broadcast')) === 'done', 30_000);
    } finally {
      origin = old;
    }
  });
});

