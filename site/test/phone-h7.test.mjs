// The test mode's long way round: no high-S in 8 tries. S is forced low in the page, because a tap's S form cannot be
// chosen, and everything else is real: the relay, the wasm, the storage credit over 8 proposals. Its own stage, because
// the relay's per-IP limit is what this run would otherwise share with phone.test.mjs. [mock-signer] [virtual authenticator]
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { NearReader } from '../lib/near-read.mjs';
import { contractViews } from '../lib/views.mjs';
import { chromeAvailable, startChrome } from './chrome.mjs';
import { stageAvailable, startStage } from './stage.mjs';

const skip = chromeAvailable() && stageAvailable() ? false : 'needs Chrome, NEAR_SANDBOX_BIN_PATH and UNDO_WASM_DIR';
const sleep = (ms) => new Promise((r) => { setTimeout(r, ms); });
const FORCE_LOW_S = `
  const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
  const hexOf = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
  const realGet = navigator.credentials.get.bind(navigator.credentials);
  navigator.credentials.get = async (o) => {
    const c = await realGet(o);
    const der = new Uint8Array(c.response.signature);
    const rLen = der[3];
    const r = der.slice(4, 4 + rLen);
    let s = BigInt('0x' + hexOf(der.slice(6 + rLen)));
    if (s > N >> 1n) s = N - s;
    let sHex = s.toString(16);
    if (sHex.length % 2) sHex = '0' + sHex;
    let sBytes = Uint8Array.from(sHex.match(/../g).map((x) => parseInt(x, 16)));
    if (sBytes[0] & 0x80) sBytes = Uint8Array.from([0, ...sBytes]);
    const body = [2, r.length, ...r, 2, sBytes.length, ...sBytes];
    const signature = Uint8Array.from([0x30, body.length, ...body]).buffer;
    return { rawId: c.rawId, response: { authenticatorData: c.response.authenticatorData, clientDataJSON: c.response.clientDataJSON, signature } };
  };`;

let stage;
let browser;
let cdp;
let views;
let authenticatorId;

before(async () => {
  if (skip) return;
  stage = await startStage({ miner: false, softPasskey: false, relayEnv: { STATUS_CACHE_MS: 0 } });
  views = contractViews(new NearReader({ urls: stage.config.rpc, timeoutMs: 15_000 }), stage.contract);
  browser = await startChrome({ width: 390, height: 844, scale: 2 });
  ({ cdp } = browser);
  await cdp.send('WebAuthn.enable');
  ({ authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } }));
}, { timeout: 180_000 });

after(async () => {
  await browser?.stop();
  await stage?.stop();
});

const stateOf = () => cdp.page('return document.documentElement.dataset.state;');

async function waitFor(what, fn, timeoutMs = 30_000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    if (await fn()) return;
    await sleep(120);
  }
  throw new Error(`never saw ${what}. State ${await stateOf()}. Screen: ${await cdp.page('return document.body.innerText;')}`);
}

async function clickOn(selector) {
  const box = await cdp.page(`const r = document.querySelector(${JSON.stringify(selector)})?.getBoundingClientRect(); return r ? { x: r.x + r.width / 2, y: r.y + r.height / 2 } : null;`);
  assert.ok(box, `no ${selector}`);
  await cdp.send('Input.dispatchMouseEvent', { type: 'mousePressed', x: box.x, y: box.y, button: 'left', clickCount: 1 });
  await cdp.send('Input.dispatchMouseEvent', { type: 'mouseReleased', x: box.x, y: box.y, button: 'left', clickCount: 1 });
}

// What the run did is kept in the tab's sessionStorage, never in the link.
const logCount = () => cdp.page('return (JSON.parse(sessionStorage.getItem("undo-h7") ?? "{}").log ?? "").split("~").filter(Boolean).length;');

test('no high-S in 8 tries: 7 cancels and the film\'s call, the report says the fixture has to cover it, and a reload midway loses nothing', { skip, timeout: 360_000 }, async (t) => {
  await cdp.send('WebAuthn.clearCredentials', { authenticatorId });
  await cdp.send('Page.addScriptToEvaluateOnNewDocument', { source: FORCE_LOW_S });
  await cdp.open(`${stage.origin}/phone/#h7=1`);
  await waitFor('the check', async () => (await stateOf()) === 'h7_check');
  await clickOn('#make');
  await waitFor('the confirm', async () => (await stateOf()) === 'h7_confirm');
  await clickOn('#confirm');

  let limited = 0;
  for (let tap = 1; tap <= 8; tap += 1) {
    await waitFor(`try ${tap}`, async () => ['h7_try', 'h7_rotate'].includes(await stateOf()) && (await logCount()) === tap - 1);
    assert.equal(await stateOf(), tap === 8 ? 'h7_rotate' : 'h7_try', `try ${tap}`);
    assert.match(await cdp.page('return document.getElementById("try-count").innerText;'), new RegExp(`^Try ${tap} of 8`));
    if (tap === 4) {
      // Reload with a request on the contract: it carries on with that request and the same log.
      await cdp.send('Page.reload');
      await sleep(300);
      await waitFor('the same try after a reload', async () => ['h7_try', 'h7_rotate'].includes(await stateOf()) && (await logCount()) === 3);
    }
    await clickOn('#cancel');
    await waitFor(`try ${tap} to land`, async () => {
      if ((await logCount()) === tap) return true;
      // This run taps faster than a person, so it meets the relay's 6 a minute per vault, which a quick thumb could too.
      if ((await stateOf()) === 'h7_stopped') {
        const wait = /Wait (\d+) s/.exec(await cdp.page('return document.getElementById("why").innerText;'));
        assert.ok(wait, 'the stop says how long');
        limited += 1;
        await sleep((Number(wait[1]) + 1) * 1000);
        await clickOn('#retry');
        await waitFor('the same try again', async () => ['h7_try', 'h7_rotate'].includes(await stateOf()));
        await clickOn('#cancel');
      }
      return false;
    }, 120_000);
  }
  t.diagnostic(`stopped by the relay's per-vault limit ${limited} times, each time carried on with Try again`);
  await waitFor('the operator step', async () => (await stateOf()) === 'h7_operator');
  await clickOn('#make-operator');
  await waitFor('the report', async () => (await stateOf()) === 'h7_report');

  const report = await cdp.page('return document.getElementById("report").innerText;');
  assert.match(report, /No high-S signature in 8 tries\. Fixtures cover high-S, and CLAIMS\.md must say so\./);
  assert.equal(report.match(/^Try \d: cancel,/gm).length, 7);
  assert.equal(report.match(/^Try 8: cancel_all_and_rotate/gm).length, 1);
  assert.match(report, /operator_passkey/);

  const f = new URLSearchParams((await cdp.page('return location.hash;')).slice(1));
  const vault = await views.vault(f.get('v'));
  assert.equal(vault.k_s_suspended, true);
  t.diagnostic(`storage credit after 8 proposals on a 30 mN vault: ${vault.storage_credit} yocto`);
  assert.equal(vault.pending.length, 1, 'only the rotated request is left in the list');
});

test('a relay limit in the middle of the run stops it with its reason, and Try again carries on', { skip, timeout: 120_000 }, async () => {
  await cdp.send('WebAuthn.clearCredentials', { authenticatorId });
  await cdp.send('Page.navigate', { url: 'about:blank' });
  await sleep(100);
  const handler = (event) => {
    const data = JSON.parse(event.data);
    if (data.method !== 'Fetch.requestPaused') return;
    const { requestId } = data.params;
    const body = Buffer.from(JSON.stringify({ ok: false, code: 'rate_limited', message: 'too many', retry_after_s: 42 })).toString('base64');
    cdp.send('Fetch.fulfillRequest', { requestId, responseCode: 429, responseHeaders: [{ name: 'content-type', value: 'application/json' }], body });
  };
  cdp.ws.addEventListener('message', handler);
  await cdp.open(`${stage.origin}/phone/#h7=1`);
  await waitFor('the check', async () => (await stateOf()) === 'h7_check');
  await clickOn('#make');
  await waitFor('the confirm', async () => (await stateOf()) === 'h7_confirm');
  await cdp.send('Fetch.enable', { patterns: [{ urlPattern: '*/api/relay', requestStage: 'Request' }] });
  try {
    await clickOn('#confirm');
    await waitFor('the stop', async () => (await stateOf()) === 'h7_stopped');
    assert.match(await cdp.page('return document.getElementById("why").innerText;'), /Wait 42 s/);
  } finally {
    cdp.ws.removeEventListener('message', handler);
    await cdp.send('Fetch.disable');
  }
  await clickOn('#retry');
  await waitFor('the run to go on', async () => ['h7_try', 'h7_rotate'].includes(await stateOf()));
});
