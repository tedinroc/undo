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
import { after, before, beforeEach, describe, test } from 'node:test';
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
import { spkToAddress } from '../lib/bitcoin.mjs';
import { createPasskey, getAssertion } from '../lib/webauthn.mjs';
import { destinationProblem, destinationSpk, fuseFraction, isNotYetUnlocked, liveRequestIn, parseSeed, relaySentence, resendWhileSigning, satsText, sumOfInputs, tickPulse } from '../pages/t/logic.mjs';
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
  test('only the vault\'s own network\'s address gets through, in the form both pages print, and the error says why in one sentence', () => {
    const REGTEST_TO = segwitAddress('regtest', 0, label('thief-destination').slice(0, 20));
    assert.equal(destinationProblem(THIEF_TO, 'mutinynet'), null);
    assert.equal(destinationProblem(THIEF_TO, 'signet'), null);
    assert.equal(destinationProblem(REGTEST_TO, 'regtest'), null, 'a local run takes its own bcrt1 address');
    assert.equal(destinationProblem('', 'mutinynet'), 'empty');
    assert.equal(destinationProblem(THIEF_TO, undefined), 'no_network', 'nothing goes before the contract names its network');
    assert.equal(destinationProblem(THIEF_TO, 'mainnet'), 'no_network');
    const mainnet = segwitAddress('mainnet', 0, label('x').slice(0, 20));
    assert.ok(mainnet.startsWith('bc1'));
    for (const network of ['mutinynet', 'regtest']) {
      assert.equal(destinationProblem(mainnet, network), 'not_test_address');
      assert.equal(destinationProblem('1BoatSLRHtKNngkdXEeobR76b53LETtpyT', network), 'not_test_address');
    }
    // One destination, one string: each network takes its own form and names the other.
    assert.equal(destinationProblem(REGTEST_TO, 'mutinynet'), 'other_network');
    assert.equal(destinationProblem(THIEF_TO, 'regtest'), 'other_network');
    assert.equal(destinationProblem(THIEF_TO.toUpperCase(), 'mutinynet'), 'not_test_address');
    assert.equal(destinationProblem('mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn', 'mutinynet'), 'not_test_address', 'base58 is this network\'s, and not the form the pages print');
    assert.equal(destinationProblem(`bitcoin:${THIEF_TO}`, 'mutinynet'), 'uri');
    assert.equal(destinationProblem(`${THIEF_TO.slice(0, -1)}${THIEF_TO.endsWith('q') ? 'p' : 'q'}`, 'mutinynet'), 'bad_address');
    assert.equal(destinationProblem('hello', 'mutinynet'), 'bad_address');
    assert.equal(toHex(addressToSpk('mutinynet', THIEF_TO)).slice(0, 4), '0014');
    assert.equal(toHex(destinationSpk(REGTEST_TO, 'regtest')), toHex(destinationSpk(THIEF_TO, 'mutinynet')), 'the same script either way');
    assert.throws(() => destinationSpk(THIEF_TO, 'regtest'));
    // The whole field is the address: a valid one with anything in front of it is not one.
    for (const [network, to] of [['mutinynet', THIEF_TO], ['regtest', REGTEST_TO]]) {
      const other = segwitAddress(network, 0, label('y').slice(0, 20));
      for (const junk of [`${other}${to}`, `${to.slice(0, to.indexOf('1') + 1)}qqqqqqqqq${to}`, `${to.slice(0, to.indexOf('1') + 1)}${to}`]) {
        assert.equal(destinationProblem(junk, network), 'bad_address', junk);
        assert.throws(() => destinationSpk(junk, network));
      }
    }
  });

  test('a key is 64 hex characters, however it was pasted, and nothing else', () => {
    const hex = 'ab'.repeat(32);
    assert.equal(toHex(parseSeed(` ${hex.slice(0, 30)}\n${hex.slice(30)} `)), hex);
    assert.equal(toHex(parseSeed(hex.toUpperCase())), hex);
    assert.equal(parseSeed('ab'.repeat(31)), null);
    assert.equal(parseSeed('ab'.repeat(33)), null, 'not 64 characters out of a longer paste');
    assert.equal(parseSeed(`key:${hex}`), null, 'nor out of junk around them');
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
    assert.equal(relaySentence({ reachable: true, general: { up: false, why: 'daily_ceiling', calls_fit: true } }), null, 'a vault no longer fits, but this tab can still send');
    assert.equal(relaySentence({ reachable: true, general: { up: false, why: 'state_store_down' } }), 'The relay can\'t reach its records right now, so this tab can\'t ask the NEAR contract or call execute.', 'the reason in words, not its code');
    assert.equal(relaySentence({ reachable: true, general: { up: false, why: 'something_new' } }), 'The relay said no, so this tab can\'t ask the NEAR contract or call execute.');
    assert.match(relaySentence({ reachable: true, general: { up: false, why: 'relay_reserve' } }), /keeping what it has left for cancels/);
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
    const many = { 1: 'waiting', 2: 'unlocked', 3: 'cancelled', 4: 'signing', 5: 'expired' };
    assert.equal(await liveRequestIn([1, 2, 3, 4, 5], async (id) => ({ kind: many[id] })), 4, 'newest first, and one still asking for signatures is live');
    assert.equal(await liveRequestIn([3, 2, 1], async (id) => ({ kind: many[id] })), 2, 'whatever order the link\'s list is in');
  });

  test('while signing, execute goes again every interval, and stops once the request can no longer ask for signatures', async () => {
    const DAY = 24 * 60 * 60 * 1000;
    const signing = (over = {}) => ({ status: 'Signing', tier: 'New', first_execute_at: 1_000_000, in_flight: 0, ...over });
    const run = async (reads) => {
      let at = 0;
      const sent = [];
      const slept = [];
      const why = await resendWhileSigning({
        read: () => reads[Math.min(at, reads.length - 1)],
        send: async () => {
          sent.push(at);
          if (sent.length === 2) throw new Error('a refused send does not stop the loop');
        },
        sleep: async (ms) => {
          slept.push(ms);
          at += 1;
          // Every run here ends within a few waits. One that does not would otherwise spin until memory runs out.
          if (slept.length > 20) throw new Error('resendWhileSigning did not stop');
        },
        everyMs: 30_000,
      });
      return { why, sent: sent.length, slept };
    };
    // Open window: it sends after each wait, until the request leaves Signing.
    const open = { signing: true, request: signing(), chainNow: 1_000_000 + DAY - 1 };
    const out = await run([open, open, open, open, { signing: false, request: signing(), chainNow: 1_000_000 + DAY - 1 }]);
    assert.deepEqual([out.why, out.sent, out.slept[0]], ['left_signing', 3, 30_000]);
    // A day after the first execute of a spend that pays out, the contract asks the signer for nothing more: no send.
    const closed = { signing: true, request: signing(), chainNow: 1_000_000 + DAY };
    assert.deepEqual(await run([closed]), { why: 'retry_closed', sent: 0, slept: [] });
    // It closes while the tab waits: the send after that wait does not go.
    assert.deepEqual((await run([open, open, closed])).sent, 1);
    // A self-spend, a reclaim among them, keeps retrying, and so does a request with no first execute on record.
    const selfSpend = { ...closed, request: signing({ tier: 'SelfSpend' }) };
    assert.equal((await run([selfSpend, selfSpend, { signing: false }])).sent, 1);
    const noFirst = { ...closed, request: signing({ first_execute_at: null }) };
    assert.equal((await run([noFirst, noFirst, { signing: false }])).sent, 1);
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
  // The thief's address in the local contract's own network form, bcrt1, as the phone prints the same request.
  let LOCAL_TO;
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

  /**
   * What a viewer reads that they should not: an error's own name, a node's or the chain's JSON, a code with underscores,
   * or one sentence said twice. The red bar's box is left out, because the node's own bytes are what that frame shows.
   */
  const rawOnScreen = async () => {
    const text = await js(`(() => {
      const box = document.getElementById('node');
      return document.body.innerText.replace(box && box.checkVisibility() ? box.innerText : '', '');
    })()`);
    const problems = [];
    const raw = /TypeError|HostError|GuestPanic|panic_msg|ActionError|FunctionCallError|ExecutionError|RPC error|sendrawtransaction|\{"|<html|\b[a-z]+_[a-z_]+\b|\bHTTP [1-5]\d\d\b/.exec(text);
    if (raw) problems.push(`"${raw[0]}" on screen in: ${text.replace(/\s+/g, ' ').slice(0, 240)}`);
    const sentences = text.split(/(?<=[.!?])\s+|\n+/).map((t) => t.trim()).filter((t) => t.length > 12);
    const twice = sentences.find((t, i) => sentences.indexOf(t) !== i);
    if (twice) problems.push(`said twice: ${twice}`);
    // The same news in other words: the relay being down, said in two places at once.
    if ((text.match(/relay is down|relay down/gi) ?? []).length > 1) problems.push(`the relay is down, said ${(text.match(/relay is down|relay down/gi) ?? []).length} times`);
    return problems;
  };

  async function assertFrame(where) {
    const f = await fitsFrame();
    assert.ok(f.w <= f.iw && f.h <= f.ih, `${where}: ${f.w}x${f.h} in ${f.iw}x${f.ih}`);
    const c = await chipBox();
    assert.equal(c.visible, true, `${where}: chip`);
    assert.equal(c.x, 64, `${where}: chip x`);
    assert.equal(c.y, 150, `${where}: chip y`);
    // A browser's error name is not words: a dropped connection reads as a bug. Nor is a contract's panic or a node's JSON.
    assert.deepEqual(await rawOnScreen(), [], `${where}: plain words only`);
  }

  /** Nothing drawn over any part of an element's own box: each probe point, on its own text, finds that element on top. */
  const uncovered = (id) => js(`(() => {
    const e = document.getElementById(${JSON.stringify(id)});
    if (!e || !e.checkVisibility()) return { id: ${JSON.stringify(id)}, visible: false };
    const r = e.getBoundingClientRect();
    const covered = [];
    for (const fx of [0.02, 0.25, 0.5, 0.75, 0.98]) for (const fy of [0.25, 0.75]) {
      const x = r.left + r.width * fx, y = r.top + r.height * fy;
      if (x < 0 || y < 0 || x >= innerWidth || y >= innerHeight) { covered.push('off screen'); continue; }
      const top = document.elementFromPoint(x, y);
      if (top !== e && !e.contains(top)) covered.push((top?.id || top?.className || top?.tagName) + '@' + Math.round(x) + ',' + Math.round(y));
    }
    return { id: ${JSON.stringify(id)}, visible: true, box: [r.left, r.top, r.right, r.bottom].map(Math.round), covered };
  })()`);

  /**
   * The same screen at 1440x900 and 1512x982, the two laptops a judge may use, and at both phone sizes: a screenshot
   * of each, no sideways scroll and plain words on all, and whatever `check` asks of the screen at that size.
   */
  async function atOtherSizes(name, check = null) {
    const failed = [];
    try {
      for (const [width, height, mobile] of [[1440, 900, false], [1512, 982, false], [390, 844, true], [375, 667, true]]) {
        await cdp.send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 2, mobile });
        await sleep(300);
        await shot(`${name}-${width}x${height}`);
        const f = await fitsFrame();
        if (!(f.w <= width && f.iw <= width)) failed.push(`${name} at ${width}x${height}: ${f.w} wide`);
        for (const problem of await rawOnScreen()) failed.push(`${name} at ${width}x${height}: ${problem}`);
        for (const problem of (await check?.({ width, height, landscape: width > height })) ?? []) failed.push(`${name} at ${width}x${height}: ${problem}`);
      }
    } finally {
      await cdp.send('Emulation.setDeviceMetricsOverride', { width: 1080, height: 1350, deviceScaleFactor: 2, mobile: false });
    }
    assert.deepEqual(failed, []);
  }

  /** "unlocks in" whole on the screen and clear of the chip: nothing drawn over it. */
  const labelClear = async () => {
    const seen = await uncovered('wait-label');
    return seen.visible && seen.covered.length === 0 ? [] : [`"unlocks in" is under something: ${JSON.stringify(seen)}`];
  };

  /**
   * The ink gap from the bottom of the digits to the top of the "0:00" under them, in the page's own unit (one film pixel
   * at 1080 wide, the chip's height over 58 as the page reckons it): each line's baseline from a zero-size box set on it,
   * and the glyphs' own extent from the canvas, in the font each is drawn in.
   */
  const inkGap = () => js(`(() => {
    const baseline = (host) => { const s = document.createElement('span'); s.style.display = 'inline-block'; s.style.width = '0'; s.style.height = '0'; host.append(s); const y = s.getBoundingClientRect().bottom; s.remove(); return y; };
    const metrics = (el) => { const c = document.createElement('canvas').getContext('2d'); const cs = getComputedStyle(el); c.font = cs.fontWeight + ' ' + cs.fontSize + ' ' + cs.fontFamily; return c.measureText(el.textContent); };
    const digits = ['d-mt', 'd-m', 'd-s1', 'd-s2', 'd-t'].map((id) => document.getElementById(id)).filter((e) => e.textContent);
    const below = Math.max(...digits.map((e) => metrics(e).actualBoundingBoxDescent));
    const label = document.getElementById('zero-label');
    const u = document.getElementById('chip').getBoundingClientRect().height / 58;
    return Math.round(((baseline(label) - metrics(label).actualBoundingBoxAscent) - (baseline(document.getElementById('d-t')) + below)) / u);
  })()`);

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
    LOCAL_TO = segwitAddress(instance.network, 0, label('thief-destination').slice(0, 20));
    relay = standInRelay(stage);
    relay.views = views;
    relay.instance = instance;
    server = await staticServer({ dir: stage.dir, port: 0, onApi: (req, res, url) => relay.onApi(req, res, url).catch((err) => {
      res.writeHead(500);
      res.end(err.message);
    }) });
    origin = `http://localhost:${server.address().port}`;
    chrome = await startChrome({ width: 1080, height: 1350, scale: 2 });
    cdp = chrome.cdp;
    await cdp.send('Network.enable');
    cdp.ws.addEventListener('message', (event) => {
      const data = JSON.parse(event.data);
      if (data.method === 'Network.requestWillBeSent') netLog.push({ url: data.params.request.url, body: data.params.request.postData ?? '' });
    });
  }, { timeout: 180_000 });

  // One test's fault never reaches the next.
  beforeEach(async () => {
    if (!stage) return;
    stage.rig.setRule(null);
    stage.rig.setFault(null);
    relay.dead = false;
    relay.general = { up: true, why: null, resets_at: null };
    relay.holdExecute = null;
    await cdp.send('Network.setBlockedURLs', { urls: [] });
  });

  after(async () => {
    await chrome?.stop();
    server?.close();
    server?.closeAllConnections?.();
    await stage?.stop();
    if (drift.length && process.env.UNDO_DRIFT_LOG) writeFileSync(process.env.UNDO_DRIFT_LOG, `${JSON.stringify(drift, null, 1)}\n`);
  });

  const toArmed = async (v, extra = {}) => {
    await openThief(v, { to: LOCAL_TO, k: v.seedHex, ...extra });
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
    await open('/t/', { v: v.vaultHex, k: v.seedHex, to: LOCAL_TO, }, '&cursor=1');
    await waitState('armed');
    assert.ok(!(await js('location.hash')).includes(v.seedHex), 'the key is out of the address bar');
    assert.ok(!(await js('location.hash')).includes('k='));
    await waitFor('Send enabled', async () => !(await js('document.getElementById("send").disabled')));
    assert.equal(await js('document.getElementById("key").value'), v.seedHex);
    assert.equal(await textOf('amount-text'), 'everything  2,000 sats', 'the coins, before fee');
    assert.equal(await js('document.getElementById("root").dataset.delayMs'), '300000');
    await js('document.getElementById("send").scrollIntoView()');
    const box = await js(`(() => { const r = document.getElementById('send').getBoundingClientRect(); return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; })()`);
    await cdp.send('Input.dispatchMouseEvent', { type: 'mouseMoved', x: box.x, y: box.y });
    await assertFrame('armed');
    const clear = await js(`document.getElementById('send').getBoundingClientRect().bottom`);
    assert.ok(clear <= 915, `the film's caption lands at y=920, and the button ends at ${clear}`);
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
    await waitFor('bcrt1 words', async () => (await textOf('to-why')) === 'This demo only sends to test addresses that start with bcrt1.');
    assert.equal(await js('document.getElementById("send").disabled'), true);
    await shot('03-real-address-refused');
    // The same thief's address in Mutinynet's form is another network's here, and the tab says which, in one sentence.
    const refusals = [
      [segwitAddress('mutinynet', 0, label('thief-destination').slice(0, 20)), 'That is a signet or testnet address; this vault is on local regtest.', '03b-other-network-refused'],
      [`bitcoin:${LOCAL_TO}`, 'That is a bitcoin: link. Paste only the address in it.', '03c-uri-refused'],
      ['1BoatSLRHtKNngkdXEeobR76b53LETtpyT', 'This demo only sends to test addresses that start with bcrt1.', null],
      ['not an address at all', 'That address does not check out.', null],
    ];
    for (const [text, words, name] of refusals) {
      await js('(() => { const e = document.getElementById("to"); e.value = ""; e.focus(); })()');
      await paste('to', text);
      await waitFor(`the words for ${text}`, async () => (await textOf('to-why')) === words, 5000).catch(async (err) => {
        throw new Error(`${err.message}: the tab says "${await textOf('to-why')}"`);
      });
      assert.equal(await js('document.getElementById("send").disabled'), true, text);
      assert.doesNotMatch(await js('document.body.innerText'), /base58|not_|[a-z]+_[a-z]+/, `no library word or code on screen for ${text}`);
      if (name) await shot(name);
    }
    await js('(() => { const e = document.getElementById("to"); e.value = ""; e.focus(); })()');
    await paste('to', LOCAL_TO);
    await waitFor('Send enabled again', async () => !(await js('document.getElementById("send").disabled')));
  });

  test('no coin: says so, names the address, no button; then the coin lands and the button is there', { timeout: 60_000 }, async () => {
    const v = await makeVault({ coin: 0 });
    await openThief(v, { to: LOCAL_TO, k: v.seedHex });
    await waitState('short');
    assert.equal(await textOf('plain-text'), 'No coin in this vault yet');
    assert.match(await textOf('plain-address'), /address bcrt1/, 'a local run labels itself by its own chain');
    await assertFrame('short');
    await shot('04-short');
    await fund(v.vault.address, 3000);
    await waitState('armed', 15_000);
    assert.equal(await textOf('amount-text'), 'everything  3,000 sats');
  });

  test('no vault in the link, and an unknown vault: a plain sentence and no controls', { timeout: 30_000 }, async () => {
    await open('/t/', {});
    await waitState('no_vault');
    assert.match(await textOf('plain-text'), /no vault/i);
    assert.equal(await js('[...document.querySelectorAll("button, input, textarea")].filter((e) => e.checkVisibility()).length'), 0);
    await assertFrame('no_vault');
    await shot('05-no-vault');
    await open('/t/', { k: 'ab'.repeat(32) });
    await waitState('no_vault');
    assert.equal(await js('location.hash'), '', 'a key in a link with no vault comes out of the address bar too');
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
    assert.equal(await textOf('dest-row'), `to ${LOCAL_TO}  2,000 sats`);
    assert.equal(spkToAddress(instance.network, req.to), LOCAL_TO, 'the string the phone prints for this request');
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

    // The stolen key again, as the film reopens it: said once under the key, in the tab's own words, with room under it.
    await openThief(v, { to: LOCAL_TO, k: v.seedHex });
    await waitState('armed');
    await waitFor('the key\'s words', async () => (await textOf('key-why')) === 'That key can\'t ask again.', 10_000);
    await waitFor('the contract\'s view of the key', async () => (await js('document.getElementById("root").dataset.viewRefused ?? ""')) === 'SpendKeySuspended', 15_000);
    await js('document.activeElement?.blur()');
    assert.equal(await textOf('armed-note'), '', 'the contract says what the key line says, so it is not said again');
    assert.equal(await js('document.getElementById("send").disabled'), true);
    const gap = await js('Math.round(document.querySelector(\'label[for="to"]\').getBoundingClientRect().top - document.getElementById("key-why").getBoundingClientRect().bottom)');
    assert.ok(gap >= 10, `room between the red line and send to: ${gap} px`);
    await assertFrame('key refused');
    await shot('15-key-refused');
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
    await waitFor('the digits at zero', async () => (await clockText()) === '0:00.0', 5_000);
    // With the relay up, the label under the zero says what happens now.
    if ((await stateNow()) === 'firing') assert.equal(await textOf('auto'), 'The contract signs');
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
    await js('(() => { globalThis.infoLines = []; const info = console.info.bind(console); console.info = (...a) => { infoLines.push(a.join(" ")); info(...a); }; return true; })()');
    await click('send');
    await waitState('no_answer', 15_000);
    assert.equal(await textOf('plain-text'), 'The node did not answer.');
    // What answered, in a sentence with no status code: a proxy's page is not shown, and its status and words are in the console.
    assert.equal(await textOf('plain-verbatim'), 'Something on the way to the node got no good answer from it.');
    assert.doesNotMatch(await js('document.body.innerText'), /HTTP|\b502\b|Bad Gateway/, 'no status code on the screen');
    assert.ok((await js('globalThis.infoLines')).some((line) => line.includes('(HTTP 502)') && line.includes('Bad Gateway: not a node')), 'the status and the proxy\'s words are in the console');
    assert.equal(await js('document.getElementById("bar").checkVisibility()'), false, 'a 502 is not a refusal');
    assert.equal(await js('document.body.textContent.includes("REFUSED") && document.getElementById("refused").checkVisibility()'), false);
    await assertFrame('no_answer');
    await shot('19-node-502');

    // A proxy's words and a limiter's words are shown too, and neither reads as a refusal.
    stage.rig.setRule(null);
    stage.rig.setFault('relay-flaky');
    // relay-flaky answers 503, 429, a drop, then 502 on successive sends of the same bytes. Chrome retries a dropped
    // connection by itself, so the page never sees that drop, and sees the 502.
    for (const expectWords of ['Something on the way to the node said it isn\'t available right now.', 'Something on the way to the node said too many tries.', 'Something on the way to the node got no good answer from it.']) {
      await click('plain-retry');
      await waitFor(`no_answer: ${expectWords}`, async () => (await stateNow()) === 'no_answer' && (await textOf('plain-verbatim')) === expectWords, 20_000).catch(async (err) => {
        throw new Error(`${err.message}; screen says ${await textOf('plain-verbatim')}`);
      });
      assert.equal(await js('document.getElementById("bar").checkVisibility()'), false);
      await sleep(100);
    }
    stage.rig.setFault(null);

    // No connection at all: the browser gives the page only an error name, and that is what it shows.
    await cdp.send('Network.setBlockedURLs', { urls: [`${stage.config.esplora}/tx`] });
    await click('plain-retry');
    await waitFor('no_answer with no connection', async () => (await stateNow()) === 'no_answer' && ['TypeError', 'the connection failed', 'The connection failed.'].includes(await textOf('plain-verbatim')), 20_000);
    await shot('19b-node-no-connection');
    await atOtherSizes('19b-node-no-connection');
    assert.equal(await textOf('plain-verbatim'), 'The connection failed.', 'in words, not the browser\'s error name');
    await cdp.send('Network.setBlockedURLs', { urls: [] });

    await click('plain-retry');
    await waitState('refused', 20_000);
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
    assert.equal(await textOf('plain-text'), 'A node said no, but not about the signature.');
    assert.equal(await textOf('plain-verbatim'), 'Its fee is too low for the node to pass it on.', 'what the refusal means, not its JSON');
    await assertFrame('other refusal');
    assert.equal(await js('document.getElementById("refused").checkVisibility()'), false);
    await shot('20-other-refusal');
    stage.rig.setRule(null);
  });

  test('a dead Mutinynet before the press: says so, no button, and recovers by itself', { timeout: 90_000 }, async () => {
    const v = await makeVault();
    stage.rig.setRule(async (x) => (x.method === 'GET' && x.path.includes('/utxo') ? { status: 503, body: 'Service Unavailable' } : null));
    await openThief(v, { to: LOCAL_TO, k: v.seedHex });
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
    assert.equal(await textOf('note'), 'Signed, not sent yet. Something on the way to the node said it isn\'t available right now.');
    assert.equal(await textOf('txid-row'), '', 'no txid before a node has it');
    await shot('22-signed-not-sent');
    stage.rig.setRule(null);
    await waitFor('the txid', async () => (await js('document.getElementById("root").dataset.broadcast')) === 'done', 20_000);
    assert.match(await textOf('txid-row'), /^local regtest txid /);
  });

  test('a dead relay: says so before and after the press, shows no armed claim, and retries when it is back', { timeout: 180_000 }, async () => {
    const v = await makeVault();
    relay.dead = true;
    await openThief(v, { to: LOCAL_TO, k: v.seedHex });
    await waitState('armed');
    await waitFor('the sentence', async () => /relay is down/.test(await textOf('armed-note')));
    await assertFrame('armed, relay down');
    await shot('23-relay-down-armed');
    await click('send');
    await waitState('refused', 15_000);
    await waitState('asking', 5_000);
    await waitFor('the asking words', async () => (await js('document.getElementById("root").dataset.why')) === 'relay_down', 30_000);
    assert.equal(await textOf('term-1'), 'The relay is down, so this tab can\'t ask the NEAR contract or call execute.');
    assert.equal(await textOf('ask-why'), '', 'the row says it, so nothing says it again, and no code');
    assert.equal(await js('document.getElementById("ask-retry").checkVisibility()'), true);
    assert.equal(await js('document.getElementById("clock-block").checkVisibility()'), false, 'no clock without a request');
    await shot('24-relay-down-asking');
    // Try again sits above the row at every size, and covers none of its sentence.
    await atOtherSizes('24-relay-down-asking', async () => {
      const row = await uncovered('term-1');
      const retry = await js(`(() => { const a = document.getElementById('ask-retry').getBoundingClientRect(), b = document.getElementById('term').getBoundingClientRect(); return { retry: [a.left, a.top, a.right, a.bottom].map(Math.round), term: [b.left, b.top, b.right, b.bottom].map(Math.round), apart: a.bottom <= b.top || a.top >= b.bottom || a.right <= b.left || a.left >= b.right }; })()`);
      return [...(row.covered.length ? [`the relay sentence is covered: ${JSON.stringify(row)}`] : []), ...(retry.apart ? [] : [`Try again is on the row: ${JSON.stringify(retry)}`])];
    });
    await assertFrame('asking, relay down');
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
    assert.equal(await textOf('auto'), 'auto-execute off', 'what is off, under the digits');
    assert.equal(await textOf('note'), 'The relay is down, so this tab can\'t ask the NEAR contract or call execute.', 'and why, once');
    await assertFrame('waiting, relay down');
    await shot('25-relay-down-waiting');
    await fastForwardToLeft(req.unlock, 4_000);
    await waitState('firing', 30_000);
    await waitFor('the firing words', async () => /relay is down/.test(await textOf('note')), 15_000);
    assert.equal(await textOf('note'), 'The relay is down, so this tab can\'t ask the NEAR contract or call execute.', 'one sentence, and no code');
    // The read that accepts a fast-forward can be the one that reaches zero, and the digits draw on the next frame.
    await waitFor('the digits at zero', async () => (await clockText()) === '0:00.0', 5_000);
    // The label under the zero follows the waiting state's rule: it does not say the contract signs over a sentence that says it can't.
    assert.equal(await textOf('auto'), 'auto-execute off', 'what is off, under the zero');
    assert.equal(await js('document.getElementById("root").dataset.auto'), 'off');
    await shot('26-relay-down-firing');
    await atOtherSizes('26-relay-down-firing', async ({ landscape }) => (landscape ? labelClear() : []));
    await assertFrame('firing, relay down');
    relay.dead = false;
    await waitState('signed', 90_000);
  });

  test('the relay at its ceiling: says that, not down', { timeout: 60_000 }, async () => {
    const v = await makeVault();
    relay.general = { up: false, why: 'daily_ceiling', resets_at: 1 };
    await openThief(v, { to: LOCAL_TO, k: v.seedHex });
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
    await fastForwardToLeft(req.unlock, 30_000);
    // A page reads block time every 5 s, and a jump counts only when a second read agrees.
    await sleep(11_000);
    const before = await clockText();
    await js('location.reload()');
    await waitState('waiting', 10_000);
    assert.equal(await js('document.getElementById("root").dataset.fling'), 'done', 'no second fling');
    const afterReload = await clockText();
    const secs = (t) => Number(t.split(':')[0]) * 60 + Number(t.split(':')[1]);
    assert.ok(secs(afterReload) <= secs(before) && secs(before) - secs(afterReload) < 6, `${before} then ${afterReload}`);
    assert.equal(await js('document.getElementById("key").value'), '');
    assert.equal(await textOf('dest-row'), `to ${LOCAL_TO}  2,000 sats`);
    assert.match(await textOf('near-row'), /^local NEAR sandbox tx /, 'the hash came through the reload');
    await assertFrame('reloaded');
    await shot('27-after-reload');
    await waitState('firing', 40_000);
    await waitState('signed', 90_000);

    // And a link that names no request finds nothing to resume once the request has gone out.
    await openThief(v, { to: LOCAL_TO });
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

  test('a hold, on screen only: this feeds the page a contract answer no model made, because no test can make a real one yet', { timeout: 120_000 }, async () => {
    const v = await makeVault();
    const { identifier } = await cdp.send('Page.addScriptToEvaluateOnNewDocument', { source: `(() => {
      const real = window.fetch;
      window.fetch = async (url, init) => {
        const res = await real(url, init);
        const body = String(init?.body ?? '');
        if (!window.__holdMs || !body.includes('"method_name":"request"')) return res;
        const data = await res.json();
        const value = data.result?.result ? JSON.parse(String.fromCharCode(...data.result.result)) : null;
        if (value) {
          value.unlock += window.__holdMs;
          value.hold_active = true;
          value.assess_reason = 'test-only reason, no model was asked';
          data.result.result = [...new TextEncoder().encode(JSON.stringify(value))];
        }
        return new Response(JSON.stringify(data), { status: res.status, headers: res.headers });
      };
    })()` });
    try {
      await toArmed(v, {});
      await pressToWaiting();
      await sleep(600);
      const secs = (t) => Number(t.split(':')[0]) * 60 + Number(t.split(':')[1]);
      const before = secs(await clockText());
      await js('window.__holdMs = 300000');
      await waitFor('the hold row', async () => js('document.getElementById("hold-row").classList.contains("on")'), 6_000);
      assert.equal(await textOf('hold-plus'), '+5:00');
      assert.equal(await textOf('hold-reason'), 'test-only reason, no model was asked');
      // The row changes on the read and the digits on the next frame.
      await waitFor('the digits to go up with the unlock', async () => secs(await clockText()) > before + 280, 2_000);
      await assertFrame('hold');
      await shot('29b-hold');
      const threeDigits = await inkGap();
      await atOtherSizes('29b-hold', async ({ landscape }) => (landscape ? labelClear() : []));
      await js('window.__holdMs = 600000');
      await waitFor('two minute digits', async () => (await js('document.getElementById("root").dataset.wide')) === '1', 6_000);
      await sleep(300);
      const box = await js(`(() => { const a = document.getElementById('d-mt').getBoundingClientRect(), b = document.getElementById('d-t').getBoundingClientRect(); return { left: a.left, right: b.right, slot: a.width }; })()`);
      assert.ok(box.slot > 100 && box.left >= 0 && box.right <= 1080, JSON.stringify(box));
      await assertFrame('ten minutes');
      await shot('29c-ten-minutes');
      // Four digits are smaller, and the 0:00 under them must still clear them, on every screen the film or a judge uses.
      const gaps = {};
      const labelProblems = [];
      try {
        for (const [width, height, scale, mobile] of [[1080, 1350, 2, false], [1440, 900, 2, false], [1512, 982, 2, false], [390, 844, 2, true], [375, 667, 2, true]]) {
          await cdp.send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: scale, mobile });
          await sleep(300);
          gaps[`${width}x${height}`] = await inkGap();
          await shot(`29c-ten-minutes-${width}x${height}`);
          for (const problem of await labelClear()) labelProblems.push(`four digits at ${width}x${height}: ${problem}`);
        }
      } finally {
        await cdp.send('Emulation.setDeviceMetricsOverride', { width: 1080, height: 1350, deviceScaleFactor: 2, mobile: false });
      }
      for (const [size, gap] of Object.entries(gaps)) assert.ok(gap >= 8, `the 0:00 clears the four digits by 8 film pixels at ${size}: ${JSON.stringify(gaps)}, three digits ${threeDigits}`);
      assert.deepEqual(labelProblems, [], 'and "unlocks in" stays clear of the chip');
    } finally {
      await cdp.send('Page.removeScriptToEvaluateOnNewDocument', { identifier });
    }
  });

  test('a vault whose beat has gone quiet: the thief can\'t beat for the guard, so the wait is the contract\'s longer one, and the page says so', { timeout: 120_000 }, async () => {
    const v = await makeVault();
    const start = (await reader.blockTime()).blockMs;
    await fastForwardToLeft(start + 21 * 60_000 + 15_000, 10_000);
    assert.equal((await views.vault(v.vaultHex)).guard_online, false);
    assert.equal(await views.delayNow(v.vaultHex), 600_000, 'unbeaten, it reads longer');
    await toArmed(v, {});
    assert.equal(await js('document.getElementById("root").dataset.delayMs'), '600000', 'and the page reports that before the press');
    assert.match(await textOf('armed-note'), /guard has gone quiet.*10:00/);
    relay.calls.length = 0;
    const r = await pressToWaiting();
    assert.deepEqual(relay.calls.slice(0, 1), ['propose_btc'], 'no heartbeat');
    assert.equal(relay.calls.includes('heartbeat'), false);
    const req = await views.request(v.vaultHex, r);
    assert.equal(req.unlock - req.proposed_at, 600_000);
  });

  /** Runs in every new document until `undo`. `window.__patch(method, data)` may rewrite an RPC answer. */
  async function patchRpc(source) {
    const { identifier } = await cdp.send('Page.addScriptToEvaluateOnNewDocument', { source: `(() => {
      const real = window.fetch;
      const patch = ${source};
      window.fetch = async (url, init) => {
        const res = await real(url, init);
        const body = String(init?.body ?? '');
        if (!body.includes('"jsonrpc"')) return res;
        const data = await res.clone().json();
        const next = patch(JSON.parse(body), data);
        return next ? new Response(JSON.stringify(next), { status: res.status, headers: res.headers }) : res;
      };
    })()` });
    return () => cdp.send('Page.removeScriptToEvaluateOnNewDocument', { identifier });
  }

  test('attack 3: null reads from a node a block behind stamp nothing. The contract still reads Pending, and so does the screen', { timeout: 120_000 }, async () => {
    const v = await makeVault();
    await toArmed(v, {});
    const r = await pressToWaiting();
    for (const count of [1, 2]) {
      const undo = await patchRpc(`((left) => (sent, data) => {
        if (left === 0 || sent.params?.method_name !== 'request') return null;
        left -= 1;
        window.__nulls = (window.__nulls ?? 0) + 1;
        return { ...data, result: { ...data.result, result: [...new TextEncoder().encode('null')] } };
      })(${count})`);
      await openThief(v, { r });
      await waitState('waiting', 15_000);
      await waitFor('the null reads', async () => (await js('window.__nulls ?? 0')) >= count, 15_000);
      await sleep(600);
      await undo();
      assert.equal(await stateNow(), 'waiting', `${count} null reads`);
      assert.equal(await js('getComputedStyle(document.getElementById("stamp")).display'), 'none');
    }
    const after = await views.request(v.vaultHex, r);
    assert.equal(after.status, 'Pending');
  });

  test('attack 4: one block read with a clock far ahead: no expired, no firing, and no execute sent', { timeout: 180_000 }, async () => {
    for (const aheadMs of [7_200_000, 360_000]) {
      const v = await makeVault();
      await toArmed(v, {});
      const r = await pressToWaiting();
      relay.calls.length = 0;
      const undo = await patchRpc(`((left) => (sent, data) => {
        if (left === 0 || sent.method !== 'block') return null;
        left -= 1;
        if (window.__reads === undefined) { window.__reads = 0; return null; }
        window.__reads += 1;
        return { ...data, result: { ...data.result, header: { ...data.result.header, timestamp_nanosec: String(BigInt(data.result.header.timestamp_nanosec) + ${aheadMs}000000n) } } };
      })(2)`);
      await openThief(v, { r });
      await waitState('waiting', 15_000);
      await waitFor('the bad read', async () => (await js('window.__reads ?? 0')) >= 1, 15_000);
      const seen = [];
      for (let i = 0; i < 10; i += 1) {
        seen.push(await stateNow());
        await sleep(200);
      }
      await undo();
      assert.ok(seen.every((state) => state === 'waiting'), seen.join());
      assert.equal(relay.calls.includes('execute'), false, 'nothing fired');
      assert.ok(!(await clockText()).startsWith('0:0'), `the digits did not jump: ${await clockText()}`);
    }
  });

  test('attack 10: on a short laptop window the stamp fits, and nothing scrolls or moves when it lands', { timeout: 180_000 }, async () => {
    for (const [width, height] of [[1512, 830], [1280, 720], [1440, 900]]) {
      await cdp.send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: false });
      try {
        const v = await makeVault();
        await toArmed(v, {});
        const r = await pressToWaiting();
        await waitFor('the fling', async () => (await js('document.getElementById("root").dataset.fling')) === 'done', 5000);
        await sleep(300);
        const box = () => js('(() => { const c = document.getElementById("clock").getBoundingClientRect(); return { left: Math.round(c.left), top: Math.round(c.top), scroll: document.scrollingElement.scrollHeight <= innerHeight && document.scrollingElement.scrollWidth <= innerWidth }; })()');
        const before = await box();
        await rotate(v);
        await waitState('frozen', 15_000);
        await sleep(300);
        const after = await box();
        assert.deepEqual(after, before, `${width}x${height}: the digits hold still`);
        assert.equal(after.scroll, true, `${width}x${height}: no scrollbar`);
        const line = await js('document.getElementById("stamp-line").getBoundingClientRect().bottom');
        assert.ok(line <= height, `${width}x${height}: the key line ends at ${line}`);
        assert.ok(r >= 0);
      } finally {
        await cdp.send('Emulation.setDeviceMetricsOverride', { width: 1080, height: 1350, deviceScaleFactor: 2, mobile: false });
      }
    }
  });

  test('attack 14: when the contract answers, the page does not say it was not asked', { timeout: 120_000 }, async () => {
    const words = 'Smart contract panicked: OutpointBusy';
    for (const [refusal, sentence, why] of [
      [{ code: 'would_refuse', message: 'the contract refused that read', verbatim: words }, 'The NEAR contract refused this.', 'That coin is already in another request.'],
      [{ code: 'would_refuse', message: 'that proposal is not signed by this vault\'s spend key', verbatim: null }, 'The NEAR contract was not asked.', 'The relay checked it first and did not send it.'],
      [{ code: 'rate_limited', message: 'too many calls', verbatim: null }, 'The NEAR contract was not asked.', 'Too many tries through the relay. Wait a few seconds and try again.'],
    ]) {
      const v = await makeVault();
      await toArmed(v, {});
      relay.refuseAll = { status: 422, body: { ok: false, retry_after_s: null, bucket: null, resets_at: null, ...refusal } };
      try {
        await click('send');
        await waitFor('the sentence', async () => (await textOf('term-1')) === sentence, 20_000);
        // The second line says why in a sentence, the contract's reason when it gave one, and never a code or its raw words.
        assert.equal(await textOf('ask-why'), why);
        assert.deepEqual(await rawOnScreen(), [], 'plain words only');
      } finally {
        relay.refuseAll = null;
      }
    }
  });

  test('attack 17: the node\'s refusal stays on the wait screen in one line, its bytes on the red bar\'s frame only, and it is off the stamp', { timeout: 120_000 }, async () => {
    const v = await makeVault();
    await toArmed(v, {});
    await click('send');
    await waitState('refused', 15_000);
    const said = await textOf('node-text');
    assert.match(said, /script-verify/, 'the refused frame keeps the node\'s own bytes');
    await waitState('waiting', 60_000);
    await waitFor('the fling', async () => (await js('document.getElementById("root").dataset.fling')) === 'done', 5000);
    assert.equal(await textOf('node-row'), 'local regtest refused the key alone.');
    const cut = await js('(() => { const e = document.getElementById("node-row"); return e.scrollHeight > e.clientHeight + 1; })()');
    assert.equal(cut, false, 'a sentence that fits, never cut mid-word');
    assert.equal(await js('document.getElementById("node-row").checkVisibility()'), true);
    await assertFrame('waiting, with the node row');
    await rotate(v);
    await waitState('frozen', 15_000);
    assert.equal(await js('document.getElementById("node-row").checkVisibility()'), false);
    await assertFrame('frozen');
  });

  test('attack 18: the key leaves the address bar even when the page has no config', { timeout: 60_000 }, async () => {
    const seed = 'ab'.repeat(32);
    await cdp.send('Network.setBlockedURLs', { urls: ['*/undo-config.json*'] });
    try {
      await cdp.send('Page.navigate', { url: 'about:blank' });
      await sleep(50);
      await cdp.send('Page.navigate', { url: `${origin}/t/#v=${'cd'.repeat(32)}&k=${seed}` });
      await waitFor('the sentence', async () => /no config/.test(await js('document.getElementById("plain-text")?.textContent ?? ""').catch(() => '')), 15_000);
      assert.equal((await js('location.href')).includes(seed), false);
    } finally {
      await cdp.send('Network.setBlockedURLs', { urls: [] });
    }
  });

  test('/thief is the same page', { timeout: 30_000 }, async () => {
    const v = await makeVault();
    await open('/thief/', { v: v.vaultHex, to: LOCAL_TO, k: v.seedHex });
    await waitState('armed');
    assert.equal(await js('location.hash').then((h) => h.includes('k=')), false);
  });

  test('a testnet build says signet test coins, reads nothing it cannot, and draws no controls', { timeout: 60_000 }, async () => {
    const out = join(process.env.TMPDIR ?? '/tmp', `undo-thief-live-${process.pid}`);
    build({ out, configObject: { mode: 'testnet', contract: 'c.testnet', rpc: ['https://rpc.invalid'], esplora: 'https://esplora.invalid/api', relay: '/api/relay', funds: '/api/funds', btcTxUrl: null, btcAddressUrl: null, nearTxUrl: null, rpId: 'example.test', softPasskey: false } });
    const live = await staticServer({ dir: out, port: 0, onApi: (req, res) => {
      res.writeHead(503, { 'content-type': 'application/json' });
      res.end('{"ok":false,"code":"relay_not_configured"}');
    } });
    try {
      await cdp.send('Network.setBlockedURLs', { urls: ['https://rpc.invalid*', 'https://esplora.invalid*'] });
      await cdp.send('Page.navigate', { url: `http://localhost:${live.address().port}/t/#v=${'ab'.repeat(32)}` });
      await waitFor('the sentence', async () => /Can't read the NEAR contract/.test(await js('document.getElementById("plain-text")?.textContent ?? ""').catch(() => '')), 20_000);
      assert.equal((await chipBox()).text, 'signet test coins');
      assert.equal(await js('[...document.querySelectorAll("button, input, textarea")].filter((e) => e.checkVisibility()).length'), 0);
      await shot('35-testnet-chip');
      // The chip is in the HTML itself, so it is there with no script at all.
      assert.match(await (await fetch(`http://localhost:${live.address().port}/t/`)).text(), /<div id="chip" class="chip">signet test coins<\/div>/);
    } finally {
      live.close();
      live.closeAllConnections?.();
    }
  });

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
      assert.deepEqual(await labelClear(), [], 'three digits at 1512x982');
      await fastForwardToLeft(req.unlock, 20_000);
      await waitFor('under a minute', async () => (await clockText()).startsWith('0:'), 15_000);
      await shot('32-landscape-waiting');
      assert.deepEqual(await labelClear(), [], 'under a minute at 1512x982');
      await rotate(v);
      await waitState('frozen', 10_000);
      await sleep(400);
      await fits('frozen');
      await shot('33-landscape-frozen');
    } finally {
      await cdp.send('Emulation.setDeviceMetricsOverride', { width: 1080, height: 1350, deviceScaleFactor: 2, mobile: false });
    }
  });

  test('the wordmark: Undo for Bitcoin beside the chip where it fits, as on the landing page, and Undo where it does not; never over the chip', { timeout: 60_000 }, async () => {
    const v = await makeVault();
    await toArmed(v, {});
    const header = () => js(`(() => { const c = document.getElementById('chip').getBoundingClientRect(); const m = document.querySelector('#root > .wordmark'); const r = m.getBoundingClientRect();
      return { text: m.innerText, chipRight: Math.round(c.right), markLeft: Math.round(r.left), markRight: Math.round(r.right), w: innerWidth, sw: document.scrollingElement.scrollWidth }; })()`);
    const seen = {};
    try {
      for (const [width, height, scale, mobile] of [[375, 667, 2, true], [390, 844, 2, true], [1080, 1350, 2, false], [1440, 900, 2, false]]) {
        await cdp.send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: scale, mobile });
        await sleep(300);
        for (const chip of ['local test coins, mock signer', 'signet test coins']) {
          await js(`(() => { document.getElementById('chip').textContent = ${JSON.stringify(chip)}; dispatchEvent(new Event('resize')); })()`);
          await sleep(100);
          const h = await header();
          seen[`${width}x${height} ${chip}`] = h.text;
          assert.ok(h.chipRight < h.markLeft && h.markRight <= h.w && h.sw <= width, `${width}x${height}, ${chip}: ${JSON.stringify(h)}`);
          if (chip === 'local test coins, mock signer') await shot(`36-wordmark-${width}x${height}`);
        }
      }
    } finally {
      await js(`document.getElementById('chip').textContent = 'local test coins, mock signer'`);
      await cdp.send('Emulation.setDeviceMetricsOverride', { width: 1080, height: 1350, deviceScaleFactor: 2, mobile: false });
    }
    // The deployed chip leaves room at every size down to 375 px; this run's longer chip only on a landscape screen.
    for (const size of ['375x667', '390x844', '1080x1350', '1440x900']) assert.equal(seen[`${size} signet test coins`], 'Undo for Bitcoin', size);
    assert.equal(seen['1440x900 local test coins, mock signer'], 'Undo for Bitcoin');
    for (const size of ['375x667', '390x844', '1080x1350']) assert.equal(seen[`${size} local test coins, mock signer`], 'Undo', size);
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
    assert.equal(status.general?.up, true, JSON.stringify(status));
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
      assert.equal((await (await fetch(`${stage.config.esplora}/tx/${v.coin.txid}/outspend/${v.coin.vout}`)).json()).spent, true);
    } finally {
      origin = old;
    }
  });
});

