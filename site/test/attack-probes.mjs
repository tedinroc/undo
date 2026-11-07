#!/usr/bin/env node
// Hostile probes of the phone page and the thief tab, on the local stage only: real wasm, relay, regtest, one Chrome
// with a virtual authenticator. Each probe prints what the screen says next to what the contract says. A probe that
// prints FINDING has reproduced something; these are not tests of correct behaviour, and nothing here is in `npm test`.
//
//   node site/test/attack-probes.mjs [--shots DIR] [--only name,name]
//
// Needs the same variables as site/test/stage.mjs. Labelled [mock-signer] [virtual authenticator].
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fromHex, toHex } from '../../tools/lib/bytes.mjs';
import { sha256 } from '../../tools/lib/crypto.mjs';
import { addressToSpk } from '../../tools/lib/btc.mjs';
import { signColdIntent } from '../../tools/lib/cold-intent.mjs';
import { buildFunding, loadDispenser } from '../../tools/lib/dispenser.mjs';
import { action, failureOf, returnValue, TGAS } from '../../tools/lib/near.mjs';
import { sendEverything } from '../lib/bitcoin.mjs';
import { buildCreateArgs, buildPropose, newVaultKeys, rpIdHashOf, vaultIdOf } from '../lib/intents.mjs';
import { NearReader } from '../lib/near-read.mjs';
import { CREATE_DEPOSIT_MILLI, executeTgas, RELAY_METHODS } from '../lib/relay-table.mjs';
import { contractViews, derivedKey } from '../lib/views.mjs';
import { startChrome } from './chrome.mjs';
import { base64ToBytes } from './phone-helpers.mjs';
import { startStage } from './stage.mjs';

const argv = process.argv.slice(2);
const flag = (name) => (argv.includes(name) ? argv[argv.indexOf(name) + 1] : null);
const SHOTS = flag('--shots');
const ONLY = flag('--only')?.split(',') ?? null;
const sleep = (ms) => new Promise((r) => { setTimeout(r, ms); });
const label = (text) => sha256(new TextEncoder().encode(`undo-test-only:attack:${text}`));
const out = [];
const say = (kind, probe, text, data) => {
  const line = `${kind} [${probe}] ${text}${data === undefined ? '' : ` ${JSON.stringify(data)}`}`;
  out.push(line);
  console.log(line);
};

let stage;
let browser;
let cdp;
let reader;
let views;
let instance;
let authenticatorId;
let counter = 0;
const paused = new Set();
const network = [];

async function setViewport(width, height, mobile = true, scale = 2) {
  await cdp.send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: scale, mobile });
}

const page = (body) => cdp.page(body);
const stateOf = () => page('return document.documentElement.dataset.state;');
const thiefState = () => page('return document.getElementById("root")?.dataset.state;');
const screenText = () => page('return document.body.innerText;').catch(() => '?');

async function waitFor(what, fn, ms = 25_000) {
  const end = Date.now() + ms;
  let last;
  while (Date.now() < end) {
    last = await fn().catch(() => null);
    if (last) return last;
    await sleep(120);
  }
  throw new Error(`never saw ${what}. State ${await stateOf().catch(() => '?')}. Screen: ${await screenText()}`);
}
const waitState = (id, ms) => waitFor(`state ${id}`, async () => (await stateOf()) === id, ms);
const waitThief = (id, ms) => waitFor(`thief state ${id}`, async () => (await thiefState()) === id, ms);
const exists = (selector) => page(`return Boolean(document.querySelector(${JSON.stringify(selector)}));`);
const textOf = (selector) => page(`return document.querySelector(${JSON.stringify(selector)})?.innerText ?? null;`);

async function clickOn(selector) {
  const box = await page(`const r = document.querySelector(${JSON.stringify(selector)})?.getBoundingClientRect(); return r ? { x: r.x + r.width / 2, y: r.y + r.height / 2 } : null;`);
  if (!box) throw new Error(`nothing at ${selector}`);
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

async function go(url) {
  await cdp.send('Page.navigate', { url: 'about:blank' });
  await sleep(60);
  await cdp.send('Page.navigate', { url });
  await waitFor('the page to start', () => page('return document.readyState === "complete";'));
}

/** While `body` runs, requests matching `pattern` go to `answer`. null lets one through, 'fail' fails it. */
async function intercept(patterns, answer, body) {
  const handler = async (params) => {
    if (params.responseStatusCode !== undefined) {
      const held = await answer(params.request, params);
      if (typeof held === 'number') await sleep(held);
      await cdp.send('Fetch.continueResponse', { requestId: params.requestId }).catch(() => {});
      return;
    }
    const res = await answer(params.request, params);
    if (res === null) await cdp.send('Fetch.continueRequest', { requestId: params.requestId }).catch(() => {});
    else if (res === 'fail') await cdp.send('Fetch.failRequest', { requestId: params.requestId, errorReason: 'ConnectionFailed' }).catch(() => {});
    else {
      await cdp.send('Fetch.fulfillRequest', {
        requestId: params.requestId,
        responseCode: res.status,
        responseHeaders: [{ name: 'content-type', value: res.type ?? 'application/json' }, { name: 'access-control-allow-origin', value: '*' }],
        body: Buffer.from(typeof res.body === 'string' ? res.body : JSON.stringify(res.body)).toString('base64'),
      }).catch(() => {});
    }
  };
  paused.add(handler);
  await cdp.send('Fetch.enable', { patterns });
  try {
    return await body();
  } finally {
    paused.delete(handler);
    await cdp.send('Fetch.disable');
  }
}

const rpcPattern = () => [{ urlPattern: `${stage.config.rpc[0]}*` }];
const realRpc = async (req) => (await fetch(req.url, { method: 'POST', headers: { 'content-type': 'application/json' }, body: req.postData })).json();
const viewBody = (json) => Array.from(new TextEncoder().encode(JSON.stringify(json)));
const viewJson = (result) => JSON.parse(new TextDecoder().decode(Uint8Array.from(result.result.result)));

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

async function makeVault(name) {
  await cdp.send('WebAuthn.clearCredentials', { authenticatorId });
  await go(`${stage.origin}/p/`);
  await waitFor('a page', async () => (await stateOf()) !== 'boot');
  const passkey = await page(`const lib = await import('/site/lib/index.mjs');
    const p = await lib.createPasskey({ credentials: navigator.credentials, rpId: 'localhost' });
    return { pub: lib.toBase64(p.pubkey), cred: lib.toBase64Url(p.credentialId) };`);
  const passkeyPub = base64ToBytes(passkey.pub);
  counter += 1;
  const keys = newVaultKeys({ seed: label(`${name}-seed-${counter}`), cold: label(`${name}-cold-${counter}`) });
  const vaultHex = toHex(vaultIdOf({ contract: stage.contract, keys, passkeyPub, csv: 6 }));
  const km = await derivedKey(reader, { signer: instance.signer, domainId: instance.domain_id, contract: stage.contract, vaultHex });
  const chainNow = (await reader.blockTime()).blockMs;
  const built = await buildCreateArgs({
    contract: stage.contract, keys, passkeyPub, rpIdHash: rpIdHashOf(stage.rpId), km, guard: stage.payer.accountId, policy: instance.policy, csv: 6, expiresAt: chainNow + 30 * 60_000,
    assert: async (digest) => page(`const lib = await import('/site/lib/index.mjs');
      const a = await lib.getAssertion({ credentials: navigator.credentials, digest: lib.fromBase64('${Buffer.from(digest).toString('base64')}'), rpId: 'localhost', credentialId: lib.fromBase64Url('${passkey.cred}') });
      return a.args;`),
  });
  const spec = RELAY_METHODS.create_vault;
  const sent = await stage.near.sendAndWait(stage.payer, stage.contract, [
    action.call('create_vault', { args: built.args }, BigInt(spec.tgas) * TGAS, stage.milliNear(CREATE_DEPOSIT_MILLI)),
    action.call('heartbeat', { vault: vaultHex }, BigInt(spec.heartbeatTgas) * TGAS, 0n),
  ]);
  if (failureOf(sent.result)) throw new Error(failureOf(sent.result));
  return { vaultHex, keys, cred: passkey.cred };
}

/** The relay only funds vaults it made, and these were made straight on the contract, so a coin comes straight from the dispenser. */
async function fundDirect(v) {
  const vault = await views.vault(v.vaultHex);
  const dispenser = loadDispenser(stage.rig.info.dispenser, 'regtest');
  const utxos = await (await fetch(`${stage.config.esplora}/address/${dispenser.address}/utxo`)).json();
  const made = buildFunding({ dispenser, utxos, payTo: addressToSpk('regtest', vault.address), value: 2000, feeRate: 2 });
  await stage.rig.rpc('sendrawtransaction', [made.raw]);
  await stage.rig.mine(1);
}

const fakeCoin = (value = 2000) => ({ txid: toHex(label(`coin-${counter += 1}`)), vout: 0, value });
const THIEF_SPK = () => fromHex(`0014${toHex(label('thief')).slice(0, 40)}`);

async function propose(v, { coin = fakeCoin(), to = THIEF_SPK(), amount = null, change = null, memo = null } = {}) {
  const vault = await views.vault(v.vaultHex);
  const script = fromHex(await views.script(v.vaultHex));
  const spend = sendEverything({ coins: [coin], to, script, feeRate: 2 });
  const chainNow = (await reader.blockTime()).blockMs;
  const args = buildPropose({ contract: stage.contract, vault, script, seed: v.keys.seed, inputs: spend.inputs, to, amount: amount ?? spend.amount, change, memo, nonce: vault.spend_nonce, expiresAt: chainNow + 30 * 60_000 });
  const sent = await stage.near.sendAndWait(stage.payer, stage.contract, [action.call('propose_btc', args, 40n * TGAS, 0n)]);
  return { failure: failureOf(sent.result), id: returnValue(sent.result), spend, coin };
}

async function mustPropose(v, opts) {
  const made = await propose(v, opts);
  if (made.failure) throw new Error(`propose refused: ${made.failure}`);
  return made;
}

async function execute(v, id, inputs = 1) {
  const gas = executeTgas(inputs, { signTgas: instance.sign_tgas, callbackTgas: instance.callback_tgas });
  return stage.near.sendAndWait(stage.payer, stage.contract, [action.call('execute', { vault: v.vaultHex, request: id }, BigInt(gas) * TGAS, 0n)]);
}

async function fastForwardTo(target) {
  for (let i = 0; i < 200; i += 1) {
    const now = (await reader.blockTime()).blockMs;
    if (now >= target) return;
    await stage.near.sandboxFastForward(Math.min(Math.ceil((target - now) / 500) + 5, 5000));
    await sleep(300);
  }
  throw new Error('the clock never reached the target');
}

const phoneUrl = (v, extra = '') => `${stage.origin}/p/#v=${v.vaultHex}&c=${v.cred}${extra}`;
const clockText = () => page('return document.getElementById("digits")?.dataset.clock ?? null;');
const thiefClock = () => page('return document.getElementById("clock")?.dataset.clock ?? null;');
const clockMs = (text) => {
  const m = /^(\d+):(\d\d)\.(\d)$/.exec(text ?? '');
  return m ? (Number(m[1]) * 60 + Number(m[2])) * 1000 + Number(m[3]) * 100 : null;
};

// ---------------------------------------------------------------- probes

const probes = {
  /** A real drain, then a decoy to the vault itself on a coin that does not exist. */
  async decoy() {
    const v = await makeVault('decoy');
    const drain = await mustPropose(v);
    await go(phoneUrl(v));
    await waitState('request');
    const r = await views.request(v.vaultHex, drain.id);
    say('info', 'decoy', 'drain on screen', { to: await textOf('#to'), clock: await clockText(), id: drain.id });

    const vault = await views.vault(v.vaultHex);
    const decoy = await mustPropose(v, { to: fromHex(vault.script_pubkey), coin: fakeCoin(1000) });
    await sleep(2500);
    const dr = await views.request(v.vaultHex, decoy.id);
    const shown = { to: await textOf('#to'), amount: await textOf('#amount'), clock: await clockText(), cancel: await exists('#cancel') };
    await shot('decoy-1-phone-shows-decoy');
    const drainOnScreen = (await screenText()).includes('1,702') || (await screenText()).includes('2,000');
    say(drainOnScreen ? 'info' : 'FINDING', 'decoy', 'phone shows only the decoy; the drain is nowhere on the screen', { shown, drainUnlockIn: r.unlock - (await reader.blockTime()).blockMs, decoyWaitMs: dr.unlock - dr.proposed_at });

    await fastForwardTo(dr.unlock);
    const exec = await execute(v, decoy.id);
    say('info', 'decoy', 'execute on the decoy', { failure: failureOf(exec.result) });
    await sleep(3000);
    const now = (await reader.blockTime()).blockMs;
    const live = await views.request(v.vaultHex, drain.id);
    const after = await views.vault(v.vaultHex);
    await shot('decoy-2-phone-too-late');
    const words = await screenText();
    say(await exists('#cancel') ? 'info' : 'FINDING', 'decoy', 'after the decoy is signed, with the drain still pending and cancellable: does the phone keep Cancel?', {
      screen: words.replace(/\s+/g, ' ').slice(0, 200), cancelOnScreen: await exists('#cancel'),
      drain: { status: live.status, epochCurrent: live.epoch === after.spend_epoch, msLeft: live.unlock - now },
    });
    await cdp.send('Page.reload');
    await sleep(2500);
    say('info', 'decoy', 'after a reload of the same link', { state: await stateOf(), cancel: await exists('#cancel'), hash: await page('return location.hash.replace(/c=[^&]*/, "c=…");') });
    await fastForwardTo(live.unlock);
    const late = await execute(v, drain.id);
    const signed = await views.request(v.vaultHex, drain.id);
    say('info', 'decoy', 'nobody tapped, so the drain goes through', { failure: failureOf(late.result), status: signed.status });
  },

  /** A typed or sent link with a request number past the newest. */
  async highR() {
    const v = await makeVault('high-r');
    await mustPropose(v);
    await go(phoneUrl(v, '&r=99999'));
    await waitFor('a screen', async () => ['idle', 'request'].includes(await stateOf()));
    await sleep(1500);
    await shot('highr-nothing-waiting');
    const vault = await views.vault(v.vaultHex);
    say((await exists('#nothing')) && vault.pending.length ? 'FINDING' : 'info', 'highR', 'link with r past the newest says nothing is waiting while a request is', { nothing: await textOf('#nothing'), pending: vault.pending });
  },

  /** A link alone makes CANCELLED: no request, no cancel, a made-up hash. */
  async forgedStamp() {
    const v = await makeVault('forged');
    const fake = '4'.repeat(44);
    await go(`${phoneUrl(v, `&r=777&tx=${fake}&f=0:07.9`)}`);
    await waitFor('a screen', async () => ['idle', 'cancelled'].includes(await stateOf()));
    await sleep(1500);
    await shot('forged-cancelled');
    const vault = await views.vault(v.vaultHex);
    say(await exists('#stamp') ? 'FINDING' : 'info', 'forgedStamp', 'link stamps CANCELLED with a hash and a key line on a vault where nothing happened', {
      stamp: await textOf('#stamp'), digits: await clockText(), hash: await page('return document.querySelector(".hash")?.innerText;'), keyLine: await textOf('#key-line'),
      contract: { spend_epoch: vault.spend_epoch, k_s_suspended: vault.k_s_suspended, pending: vault.pending },
    });
  },

  /** The cold key freezes then unfreezes. The epoch moved; nobody rotated. */
  async freezeThaw() {
    const v = await makeVault('thaw');
    const { id } = await mustPropose(v);
    const cold = async (method, fields) => {
      const vault = await views.vault(v.vaultHex);
      const expiresAt = (await reader.blockTime()).blockMs + 600_000;
      const signed = signColdIntent({ cold: v.keys.cold, contract: stage.contract, vault: v.vaultHex, method, fields, expiresAt, nonce: vault.cold_nonce });
      const sent = await stage.near.sendAndWait(stage.payer, stage.contract, [action.call(method, { vault: v.vaultHex, ...fields, expires_at: expiresAt, nonce: vault.cold_nonce, signature: signed.signature }, 60n * TGAS, 0n)]);
      if (failureOf(sent.result)) throw new Error(`${method}: ${failureOf(sent.result)}`);
    };
    // The phone has the request on screen, then misses a few seconds of reads, as a locked screen or a tunnel would.
    await go(phoneUrl(v));
    await waitState('request');
    await intercept(rpcPattern(), async () => 'fail', async () => {
      await cold('freeze', { until: (await reader.blockTime()).blockMs + 120_000 });
      await cold('unfreeze', {});
    });
    await waitState('cancelled', 20_000);
    await shot('freezethaw-phone');
    const vault = await views.vault(v.vaultHex);
    const screenKeyLine = await textOf('#key-line');
    const again = await propose(v);
    say(screenKeyLine && !again.failure ? 'FINDING' : 'info', 'freezeThaw', 'phone says the key cannot ask again, and the same key then proposes', {
      keyLine: screenKeyLine, k_s_suspended: vault.k_s_suspended, frozen_until: vault.frozen_until, oldRequest: id, proposedAgain: again.failure === null ? `request ${again.id}` : again.failure,
    });
    await go(`${stage.origin}/t/#v=${v.vaultHex}&r=${id}`);
    await waitThief('frozen', 15_000);
    say('info', 'freezeThaw', 'thief tab on the same request', { stampLine: await page('return getComputedStyle(document.getElementById("stamp-line")).display;') });
  },

  /** One block read with a clock far ahead, as a node with a bad clock or a lying node could answer. */
  async futureBlock() {
    for (const [name, aheadMs] of [['2h', 7_200_000], ['6min', 360_000]]) {
      const v = await makeVault(`future-${name}`);
      const { id } = await mustPropose(v);
      await go(phoneUrl(v));
      await waitState('request');
      const before = await clockText();
      let lies = 0;
      await intercept(rpcPattern(), async (req) => {
        const body = JSON.parse(req.postData ?? '{}');
        if (body.method !== 'block' || lies >= 1) return null;
        lies += 1;
        const real = await realRpc(req);
        real.result.header.timestamp_nanosec = String(BigInt(real.result.header.timestamp_nanosec) + BigInt(aheadMs) * 1_000_000n);
        return { status: 200, body: real };
      }, async () => {
        await waitFor('the lie to be read', async () => lies >= 1, 15_000);
        await sleep(1800);
      });
      const [state, text, cancel, clk] = [await stateOf(), await screenText(), await exists('#cancel'), await clockText()];
      await shot(`futureblock-${name}-after-one-read`);
      await sleep(36_000);
      const later = { state: await stateOf(), cancel: await exists('#cancel'), clock: await clockText(), text: (await screenText()).replace(/\s+/g, ' ').slice(0, 140) };
      await shot(`futureblock-${name}-36s-later`);
      const r = await views.request(v.vaultHex, id);
      const now = (await reader.blockTime()).blockMs;
      say(state !== 'request' || clockMs(clk) < 100 ? 'FINDING' : 'info', 'futureBlock', `one block read ${name} ahead`, {
        before, afterOneRead: { state, cancel, clock: clk, text: text.replace(/\s+/g, ' ').slice(0, 140) }, thirtySixSecondsLater: later, chain: { status: r.status, msLeft: r.unlock - now },
      });
    }
  },

  async thiefNull() {
    const v = await makeVault('thief-null');
    const { id } = await mustPropose(v);
    await setViewport(1080, 1350, false, 1);
    await go(`${stage.origin}/t/#v=${v.vaultHex}&r=${id}`);
    await waitThief('waiting');
    const height = (await reader.blockTime()).height;
    let lies = 0;
    await intercept(rpcPattern(), async (req) => {
      const body = JSON.parse(req.postData ?? '{}');
      if (body.params?.method_name === 'request' && lies < 1) {
        lies += 1;
        return { status: 200, body: { jsonrpc: '2.0', id: body.id, result: { block_height: height, logs: [], result: viewBody(null) } } };
      }
      return null;
    }, async () => {
      await waitFor('the null read', async () => lies >= 1, 10_000);
      await sleep(600);
    });
    await sleep(3000);
    const state = await thiefState();
    await shot('thiefnull-stamp');
    const r = await views.request(v.vaultHex, id);
    const vault = await views.vault(v.vaultHex);
    say(state === 'frozen' ? 'FINDING' : 'info', 'thiefNull', 'one null read from a lagging node after a sighting', {
      state, stampShown: await page('return getComputedStyle(document.querySelector("#stamp")).display;'),
      chain: { status: r.status, epochCurrent: r.epoch === vault.spend_epoch, k_s_suspended: vault.k_s_suspended },
    });
    await setViewport(390, 844);
  },

  /** A spend with change: what the phone says of the fee. */
  async changeFee() {
    const v = await makeVault('change');
    const coin = fakeCoin(10_000);
    const { id } = await mustPropose(v, { coin, amount: 1000, change: 8700 });
    await go(phoneUrl(v));
    await waitState('request');
    await shot('changefee-phone');
    const r = await views.request(v.vaultHex, id);
    const fee = await page('return document.querySelector(".fee")?.innerText ?? null;');
    say(/9,000/.test(fee ?? '') ? 'FINDING' : 'info', 'changeFee', 'spend of 1,000 with 8,700 change and a 300 fee', {
      amountOnScreen: await textOf('#amount'), feeOnScreen: fee, chain: { amount: r.amount, change: r.change, fee: r.fee },
    });
  },

  /** A declared value the contract cannot check, on a coin that does not exist. */
  async declaredLie() {
    const v = await makeVault('declared');
    const { id } = await mustPropose(v, { coin: fakeCoin(5_000_000) });
    await go(phoneUrl(v));
    await waitState('request');
    await sleep(2000);
    await shot('declared-phone');
    const r = await views.request(v.vaultHex, id);
    const esplora = await fetch(`${stage.config.esplora}/tx/${r.inputs[0].txid}`).then((x) => x.status);
    const text = (await screenText()).replace(/\s+/g, ' ');
    const flagged = /doesn't know|only what the request claims/.test(text);
    say(flagged ? 'info' : 'FINDING', 'declaredLie', 'a made-up coin of 5,000,000 sats: is it flagged?', { amountOnScreen: await textOf('#amount'), esploraStatusForThatCoin: esplora, flagged });
  },

  /** A link with a junk credential id, then the owner's own link with no `c`. */
  async credentialPoison() {
    const v = await makeVault('poison');
    await mustPropose(v);
    await go(`${stage.origin}/p/#v=${v.vaultHex}&c=AAAAAAAA`);
    await waitState('request');
    const stored = await page(`return localStorage.getItem('undo.passkey.${v.vaultHex}');`);
    await go(`${stage.origin}/p/#v=${v.vaultHex}`);
    await waitState('request');
    await clickOn('#cancel');
    await sleep(2500);
    await shot('poison-after-tap');
    const vault = await views.vault(v.vaultHex);
    say(vault.k_s_suspended ? 'info' : 'FINDING', 'credentialPoison', 'one junk link replaces the remembered credential, and the tap on a clean link then fails', {
      stored, state: await stateOf(), screen: (await screenText()).replace(/\s+/g, ' ').slice(-200), why: await page('return document.getElementById("why")?.dataset.why ?? null;'), k_s_suspended: vault.k_s_suspended,
    });
  },

  /** The read beats the relay's answer: is the hash ever drawn? */
  async stampNoHash() {
    const v = await makeVault('nohash');
    await mustPropose(v);
    await go(phoneUrl(v));
    await waitState('request');
    await intercept([{ urlPattern: '*/api/relay*', requestStage: 'Response' }], async (req) => (req.method === 'POST' ? 4000 : 0), async () => {
      await clickOn('#cancel');
      await waitState('cancelled', 15_000);
      const atStamp = await exists('.hash');
      await sleep(7000);
      await shot('nohash-phone');
      const fragment = await page('return location.hash.includes("tx=");');
      say(!(await exists('.hash')) && fragment ? 'FINDING' : 'info', 'stampNoHash', 'relay answer held 4 s: the stamp lands, the hash is in the fragment and never reaches the screen', { hashAtStamp: atStamp, hashAfter7s: await exists('.hash'), hashInFragment: fragment });
    });
  },

  /** Status Signing: the signature has not come back. */
  async signingWords() {
    const v = await makeVault('signing');
    await mustPropose(v);
    await go(phoneUrl(v));
    await waitState('request');
    await intercept(rpcPattern(), patchView('request', (r) => (r ? { ...r, status: 'Signing', in_flight: 1, first_execute_at: r.proposed_at } : undefined)), async () => {
      await waitState('too_late', 10_000);
      await sleep(300);
      await shot('signing-phone');
      const screen = (await screenText()).replace(/\s+/g, ' ');
      say(/The contract signed/.test(screen) ? 'FINDING' : 'info', 'signingWords', 'status Signing, signature not back', { screen });
    });
  },

  /** Injection through everything read from the chain or the node, and through the fragment. */
  async xss() {
    const pay = '<img src=x onerror="window.__x=1"><script>window.__x=2</script>';
    const v = await makeVault('xss');
    await mustPropose(v, { memo: 'plain ascii memo' });
    await go(phoneUrl(v));
    await waitState('request');
    const results = {};
    await intercept(rpcPattern(), patchView('request', (r) => (r ? { ...r, hold_active: true, assess_reason: pay } : undefined)), async () => {
      await waitFor('the reason', async () => (await textOf('#hold'))?.includes('img src'), 10_000);
      results.phoneReason = await page('return { imgs: document.images.length, x: window.__x ?? null, text: document.getElementById("hold").innerText };');
    });
    await intercept(rpcPattern(), patchView('vault', (r) => (r ? { ...r, address: `"><img src=x onerror="window.__x=3">${pay}` } : undefined)), async () => {
      await go(`${stage.origin}/p/#v=${v.vaultHex}&r=88888`);
      await waitFor('a screen', async () => ['idle', 'request'].includes(await stateOf()));
      await sleep(400);
      results.phoneAddress = await page('return { imgs: document.images.length, x: window.__x ?? null };');
    });
    await go(`${stage.origin}/p/#v=${encodeURIComponent(pay)}&r=${encodeURIComponent(pay)}&tx=${encodeURIComponent(pay)}&c=${encodeURIComponent(pay)}&f=${encodeURIComponent(pay)}`);
    await sleep(800);
    results.phoneFragment = await page('return { imgs: document.images.length, x: window.__x ?? null, state: document.documentElement.dataset.state, text: document.getElementById("screen").innerText.slice(0, 80) };');
    await go(`${stage.origin}/t/#v=${v.vaultHex}&r=0&to=${encodeURIComponent(pay)}&k=${encodeURIComponent(pay)}`);
    await sleep(1200);
    results.thiefFragment = await page('return { imgs: document.images.length, x: window.__x ?? null, hash: location.hash.slice(0, 20), key: document.getElementById("key").value, to: document.getElementById("to").value };');
    const leaked = Object.values(results).some((r) => r.imgs > 0 || r.x !== null);
    say(leaked ? 'FINDING' : 'info', 'xss', 'injected strings stayed text', results);
  },

  /** Every outbound request a phone and a thief tab make: does a fragment, a key or a referrer leave? */
  async leaks() {
    const v = await makeVault('leak');
    const { id } = await mustPropose(v);
    network.length = 0;
    await go(phoneUrl(v, `&tx=${'4'.repeat(44)}`));
    await waitState('request');
    await sleep(2500);
    await clickOn('#cancel');
    await waitState('cancelled');
    await sleep(800);
    const seedHex = toHex(v.keys.seed);
    await setViewport(1080, 1350, false, 1);
    await go(`${stage.origin}/t/#v=${v.vaultHex}&k=${seedHex}&r=${id}`);
    await sleep(2500);
    const bad = network.filter((n) => [v.cred, seedHex, 'tx=', 'k='].some((s) => n.url.includes(s) || n.body.includes(s)));
    const referers = network.filter((n) => n.referer && !n.url.startsWith(stage.origin));
    const hosts = [...new Set(network.map((n) => new URL(n.url).host))];
    say(bad.length || referers.length ? 'FINDING' : 'info', 'leaks', `${network.length} requests`, { hosts, carryingFragmentOrKey: bad.length, crossOriginWithReferer: referers.length, sample: bad.slice(0, 2).map((b) => b.url.slice(0, 80)) });
    const store = await page('return { session: Object.keys(sessionStorage).map((k) => [k, sessionStorage[k].includes(' + JSON.stringify(seedHex) + ')]), local: Object.keys(localStorage) };');
    say('info', 'leaks', 'storage on the thief origin', store);
    await setViewport(390, 844);
  },

  async nodeWords() {
    const v = await makeVault('words');
    await fundDirect(v);
    await setViewport(1080, 1350, false, 1);
    const long = `mempool-script-verify-flag-failed (Script evaluated without error but finished with a false/empty top stack element), ${'detail <b>x</b> '.repeat(450)}END`;
    await intercept([{ urlPattern: `${stage.config.esplora}/tx` }], async (req) => (req.method === 'POST' ? { status: 400, type: 'text/plain', body: long } : null), async () => {
      await go(`${stage.origin}/t/#v=${v.vaultHex}&k=${toHex(v.keys.seed)}&to=${'tb1q'}`);
      await waitFor('the armed tab', async () => (await thiefState()) === 'armed', 20_000);
      await page('const to = document.getElementById("to"); to.focus();');
      await cdp.send('Input.insertText', { text: (await import('../../tools/lib/btc.mjs')).segwitAddress('mutinynet', 0, label('t').slice(0, 20)) });
      await waitFor('Send on', () => page('return !document.getElementById("send").disabled;'), 15_000);
      await clickOn('#send');
      await waitThief('refused', 15_000);
      const shownAt = Date.now();
      await sleep(1100);
      await shot('nodewords-long');
      const m = await page(`const n = document.getElementById('node'); const r = n.getBoundingClientRect(); const box = document.getElementById('node-text'); return { exact: box.textContent, nodeBottom: r.bottom, viewport: innerHeight, cls: n.className, clip: getComputedStyle(document.getElementById('refused')).overflow };`);
      say(m.exact === long ? 'info' : 'FINDING', 'nodeWords', 'the text in the DOM is byte for byte', { same: m.exact === long });
      say(m.nodeBottom > m.viewport && m.clip === 'hidden' ? 'FINDING' : 'info', 'nodeWords', 'a long answer on screen', { nodeBottom: Math.round(m.nodeBottom), viewport: m.viewport, cls: m.cls, overflowOfPanel: m.clip });
      await waitFor('the refused panel to go', async () => (await thiefState()) !== 'refused', 10_000);
      say('info', 'nodeWords', 'ms from the refused state to the words being gone', { ms: Date.now() - shownAt, anywhereLater: (await screenText()).includes('finished with a false') });
    });
    await setViewport(390, 844);
  },

  /** How long a dead relay leaves a live-looking Cancel on the screen. */
  async relayDies() {
    const v = await makeVault('relaydies');
    await mustPropose(v);
    await go(phoneUrl(v));
    await waitState('request');
    await sleep(1200);
    const t0 = Date.now();
    await intercept([{ urlPattern: '*/api/relay*' }], async () => 'fail', async () => {
      await waitFor('the button to go', async () => !(await exists('#cancel')), 45_000);
      const ms = Date.now() - t0;
      say(ms > 6000 ? 'FINDING' : 'info', 'relayDies', 'relay dead, page still showing Cancel for', { ms, thenSays: await textOf('#why') });
    });
  },

  /** A contract refusal after inclusion: how soon, and in whose words? */
  async contractRefusal() {
    const v = await makeVault('refusal');
    await mustPropose(v);
    await go(phoneUrl(v));
    await waitState('request');
    await intercept(rpcPattern(), patchView('vault', (r) => (r ? { ...r, passkey_nonce: r.passkey_nonce + 1 } : undefined)), async () => {
      await sleep(1600);
      const t0 = Date.now();
      await clickOn('#cancel');
      const seen = await waitFor('a notice', async () => (await exists('#notice')) ? { notice: await textOf('#notice'), verbatim: await textOf('#verbatim') } : null, 45_000);
      const ms = Date.now() - t0;
      await shot('contractrefusal-phone');
      const hash = (seen.verbatim ?? '').split(' ').at(-1);
      const chain = await stage.near.txStatus(hash, stage.relay.accountId, 'FINAL').catch((err) => ({ error: err.message }));
      say(ms > 6000 || !seen.verbatim?.includes('Smart contract') ? 'FINDING' : 'info', 'contractRefusal', 'the contract refused a stale nonce', { msToNotice: ms, ...seen, chainSaid: failureOf(chain) ?? chain.error ?? null });
    });
  },

  /** A node stuck on one block: does the clock keep falling, and does anything say so? */
  async stuckNode() {
    const v = await makeVault('stuck');
    await mustPropose(v);
    await go(phoneUrl(v));
    await waitState('request');
    await sleep(1500);
    let frozenBlock = null;
    const readings = [];
    await intercept(rpcPattern(), async (req) => {
      const body = JSON.parse(req.postData ?? '{}');
      if (body.method !== 'block') return null;
      const real = await realRpc(req);
      frozenBlock ??= real.result.header;
      real.result.header = { ...real.result.header, timestamp_nanosec: frozenBlock.timestamp_nanosec, height: frozenBlock.height };
      return { status: 200, body: real };
    }, async () => {
      for (let i = 0; i < 30; i += 1) {
        await sleep(2000);
        readings.push(await clockText());
      }
    });
    const ms = readings.map(clockMs);
    const backwards = ms.filter((x, i) => i > 0 && x > ms[i - 1]).length;
    const fell = ms[0] - ms.at(-1);
    say(backwards > 0 || (fell < 50_000 && !(await exists('#read-down'))) ? 'FINDING' : 'info', 'stuckNode', 'block time stuck for 60 s while views still answer', { first: readings[0], last: readings.at(-1), fellMs: fell, timesItWentUp: backwards, sample: readings.filter((_, i) => i % 5 === 0), warned: await exists('#read-down') });
  },

  /** A node stuck before the cancel answers everything, from the first read of a fresh load. */
  async staleReload() {
    const v = await makeVault('stale');
    await mustPropose(v);
    const saved = new Map();
    await intercept(rpcPattern(), async (req) => {
      if (req.method !== 'POST') return null;
      const body = JSON.parse(req.postData ?? '{}');
      const key = body.method === 'block' ? 'block' : body.params?.method_name;
      const real = await realRpc(req);
      if (!saved.has(key)) saved.set(key, real);
      return { status: 200, body: real };
    }, async () => {
      await go(phoneUrl(v));
      await waitState('request');
      await sleep(1500);
    });
    await clickOn('#cancel');
    await waitState('cancelled');
    const hash = await page('return location.hash;');
    const vault = await views.vault(v.vaultHex);
    await intercept(rpcPattern(), async (req) => {
      if (req.method !== 'POST') return null;
      const body = JSON.parse(req.postData ?? '{}');
      const key = body.method === 'block' ? 'block' : body.params?.method_name;
      return saved.has(key) ? { status: 200, body: { ...saved.get(key), id: body.id } } : null;
    }, async () => {
      await go(`${stage.origin}/p/${hash}`);
      await sleep(3000);
      await shot('stale-reload');
      say(await exists('#cancel') ? 'FINDING' : 'info', 'staleReload', 'cancelled on chain; fresh load, every read from one node stuck before the cancel', { state: await stateOf(), cancelShown: await exists('#cancel'), clock: await clockText(), warned: await exists('#read-down'), chain: { k_s_suspended: vault.k_s_suspended } });
      await sleep(20_000);
      say('info', 'staleReload', '20 s on', { state: await stateOf(), cancelShown: await exists('#cancel'), clock: await clockText(), warned: await exists('#read-down') });
    });
  },

  /** The same bad block read, on the thief tab. */
  async futureThief() {
    for (const [name, aheadMs] of [['2h', 7_200_000], ['6min', 360_000]]) {
      const v = await makeVault(`fthief-${name}`);
      const { id } = await mustPropose(v);
      await setViewport(1080, 1350, false, 1);
      await go(`${stage.origin}/t/#v=${v.vaultHex}&r=${id}`);
      await waitThief('waiting');
      let lies = 0;
      let executes = 0;
      await intercept([...rpcPattern(), { urlPattern: '*/api/relay*' }], async (req) => {
        if (req.url.includes('/api/relay')) {
          if (req.method === 'POST' && req.postData.includes('"execute"')) executes += 1;
          return null;
        }
        const body = JSON.parse(req.postData ?? '{}');
        if (body.method !== 'block' || lies >= 1) return null;
        lies += 1;
        const real = await realRpc(req);
        real.result.header.timestamp_nanosec = String(BigInt(real.result.header.timestamp_nanosec) + BigInt(aheadMs) * 1_000_000n);
        return { status: 200, body: real };
      }, async () => {
        await waitFor('the lie to be read', async () => lies >= 1, 15_000);
        await sleep(4000);
        const seen = { state: await thiefState(), clock: await thiefClock(), auto: await textOf('#auto'), plain: await textOf('#plain-text'), note: await textOf('#note'), executes };
        await shot(`futurethief-${name}`);
        const r = await views.request(v.vaultHex, id);
        const now = (await reader.blockTime()).blockMs;
        say(state === 'waiting' ? 'info' : 'FINDING', 'futureThief', `one block read ${name} ahead`, { ...seen, chain: { status: r.status, msLeft: r.unlock - now } });
      });
      await setViewport(390, 844);
    }
  },

  /** A live-but-unseen spoof: one read of a vault with a higher epoch stamps at once. */
  async oneEpochRead() {
    const v = await makeVault('epoch');
    const { id } = await mustPropose(v);
    await go(phoneUrl(v));
    await waitState('request');
    let lies = 0;
    await intercept(rpcPattern(), patchView('vault', (r) => {
      if (!r || lies >= 1) return undefined;
      lies += 1;
      return { ...r, spend_epoch: r.spend_epoch + 1 };
    }), async () => {
      await waitFor('the read', async () => lies >= 1, 10_000);
      await sleep(600);
    });
    await sleep(2500);
    const r = await views.request(v.vaultHex, id);
    const vault = await views.vault(v.vaultHex);
    say((await stateOf()) === 'cancelled' ? 'FINDING' : 'info', 'oneEpochRead', 'one optimistic read with a moved epoch', { state: await stateOf(), stamp: await textOf('#stamp'), keyLine: await textOf('#key-line'), cancel: await exists('#cancel'), chain: { status: r.status, epochCurrent: r.epoch === vault.spend_epoch, k_s_suspended: vault.k_s_suspended } });
    const finalities = [];
    await intercept(rpcPattern(), async (req) => {
      const body = JSON.parse(req.postData ?? '{}');
      finalities.push(body.params?.finality ?? body.params?.wait_until);
      return null;
    }, async () => { await go(phoneUrl(v)); await sleep(1500); });
    say('info', 'oneEpochRead', 'finality the page reads at', { finalities: [...new Set(finalities)] });
  },

  /** The forged link with a real drain running: does it hide the drain? */
  async forgedOverLive() {
    const v = await makeVault('forged-live');
    const { id } = await mustPropose(v);
    await go(phoneUrl(v, `&r=777&tx=${'4'.repeat(44)}&f=0:07.9`));
    await waitFor('a screen', async () => ['request', 'cancelled'].includes(await stateOf()));
    await sleep(1500);
    await shot('forged-over-live-drain');
    const r = await views.request(v.vaultHex, id);
    const vault = await views.vault(v.vaultHex);
    const now = (await reader.blockTime()).blockMs;
    say(await exists('#stamp') ? 'FINDING' : 'info', 'forgedOverLive', 'is CANCELLED on screen while a real drain is pending?', { state: await stateOf(), stamp: await textOf('#stamp'), cancel: await exists('#cancel'), drain: { status: r.status, epochCurrent: r.epoch === vault.spend_epoch, msLeft: r.unlock - now } });
  },

  /** A phone holding no passkey for this vault, on a clean link. */
  async strangerPhone() {
    const v = await makeVault('stranger');
    await mustPropose(v);
    await cdp.send('WebAuthn.clearCredentials', { authenticatorId });
    await page(`localStorage.clear();`);
    await go(`${stage.origin}/p/#v=${v.vaultHex}`);
    await waitState('request');
    const before = await exists('#cancel');
    await shot('stranger-before-tap');
    await clickOn('#cancel');
    await sleep(2000);
    await shot('stranger-after-tap');
    say(before ? 'FINDING' : 'info', 'strangerPhone', 'Cancel on a phone that holds no passkey for this vault', { cancelShownBeforeTap: before, afterTap: await stateOf(), says: (await textOf('#why')) ?? (await textOf('#notice')), why: await page('return document.getElementById("why")?.dataset.why ?? null;') });
  },

  /** Is a contract failure visible at `wait_until: INCLUDED`, the moment the relay answers? */
  async includedSays() {
    const v = await makeVault('included');
    const vault = await views.vault(v.vaultHex);
    const script = fromHex(await views.script(v.vaultHex));
    const spend = sendEverything({ coins: [fakeCoin()], to: THIEF_SPK(), script, feeRate: 2 });
    const chainNow = (await reader.blockTime()).blockMs;
    const args = buildPropose({ contract: stage.contract, vault, script, seed: v.keys.seed, inputs: spend.inputs, to: THIEF_SPK(), amount: spend.amount, nonce: vault.spend_nonce + 5, expiresAt: chainNow + 600_000 });
    const sent = await stage.near.send(stage.payer, stage.contract, [action.call('propose_btc', args, 40n * TGAS, 0n)], { waitUntil: 'INCLUDED' });
    const hash = sent.hash ?? sent.transaction?.hash ?? sent.transaction_outcome?.id ?? null;
    const first = await reader.txOutcome(hash, stage.payer.accountId);
    await sleep(3000);
    const later = await reader.txOutcome(hash, stage.payer.accountId);
    say(first.known && !first.failure && later.failure ? 'FINDING' : 'info', 'includedSays', 'the same reader call the phone uses, right after sending and 3 s later', { hash: Boolean(hash), first: { known: first.known, failure: first.failure }, later: { known: later.known, failure: later.failure } });
  },

  /** Thief tab on a laptop: the frozen frame with a real reading on it. */
  async frozenLandscape() {
    for (const [w, h] of [[1440, 900], [1280, 720], [1080, 1350], [1512, 945], [1512, 830]]) {
      const v = await makeVault(`frozen-${w}`);
      const { id } = await mustPropose(v);
      await setViewport(w, h, false, w > 1080 ? 2 : 1);
      await go(`${stage.origin}/t/#v=${v.vaultHex}&r=${id}`);
      await waitThief('waiting');
      await sleep(900);
      const rect = () => page('const r = document.getElementById("clock").getBoundingClientRect(); const c = document.getElementById("chip").getBoundingClientRect(); return { x: r.x, y: r.y, w: r.width, h: r.height, chipY: c.y };');
      const before = await rect();
      const vault = await views.vault(v.vaultHex);
      const expiresAt = (await reader.blockTime()).blockMs + 600_000;
      const call = await page(`const lib = await import('/site/lib/index.mjs');
        const newKs = lib.spendKeys(crypto.getRandomValues(new Uint8Array(32))).ks.pub;
        const digest = lib.rotateDigest({ contract: ${JSON.stringify(stage.contract)}, vaultHex: ${JSON.stringify(v.vaultHex)}, newKs, nonce: ${vault.passkey_nonce}, expiresAt: ${expiresAt} });
        const a = await lib.getAssertion({ credentials: navigator.credentials, digest, rpId: 'localhost', credentialId: lib.fromBase64Url(${JSON.stringify(v.cred)}) });
        return lib.rotateArgs({ vaultHex: ${JSON.stringify(v.vaultHex)}, newKs, nonce: ${vault.passkey_nonce}, expiresAt: ${expiresAt}, assertion: a.args });`);
      const sent = await stage.near.sendAndWait(stage.payer, stage.contract, [action.call('cancel_all_and_rotate', call, 30n * TGAS, 0n)]);
      if (failureOf(sent.result)) throw new Error(failureOf(sent.result));
      await waitThief('frozen');
      await sleep(700);
      const after = await rect();
      const m = await page('const b = (s) => { const r = document.querySelector(s).getBoundingClientRect(); return { top: Math.round(r.top), bottom: Math.round(r.bottom) }; }; return { stamp: b("#stamp"), line: b("#stamp-line"), clock: document.getElementById("clock").dataset.clock, h: innerHeight, scrollH: document.documentElement.scrollHeight };');
      await shot(`frozen-${w}x${h}`);
      const moved = JSON.stringify(before) !== JSON.stringify(after);
      say(moved || m.line.bottom > m.h || m.scrollH > m.h ? 'FINDING' : 'info', 'frozenLandscape', `${w}x${h}: digits and stamp`, { moved, before, after, ...m });
    }
    await setViewport(390, 844);
  },

  /** Does the phone hold a key-free test mode open to visitors? */
  async h7Open() {
    await go(`${stage.origin}/p/#h7=1`);
    await sleep(1200);
    await shot('h7-open');
    say('info', 'h7Open', 'test mode from a bare link', { state: await stateOf(), screen: (await screenText()).replace(/\s+/g, ' ').slice(0, 220) });
  },

  async keyStaysOnNoConfig() {
    const seed = 'ab'.repeat(32);
    await intercept([{ urlPattern: '*/undo-config.json*' }], async () => 'fail', async () => {
      await go(`${stage.origin}/t/#v=${'a'.repeat(64)}&k=${seed}`);
      await sleep(800);
      await shot('noconfig-thief');
      say((await page('return location.hash;')).includes(seed) ? 'FINDING' : 'info', 'keyStaysOnNoConfig', 'config fails to load', { keyStillInAddressBar: (await page('return location.hash;')).includes(seed), screen: (await screenText()).replace(/\s+/g, ' ').slice(0, 120) });
    });
  },

  /** Worst case content at each phone size, on the screen that must fit. */
  async layout() {
    const v = await makeVault('layout');
    const p2tr = fromHex(`5120${toHex(label('taproot'))}`);
    await mustPropose(v, { to: p2tr, coin: fakeCoin(1_234_567), amount: 1_234_000 });
    const worst = (reqPatch, vaultPatch) => async (req) => {
      const body = JSON.parse(req.postData ?? '{}');
      const name = body.params?.method_name;
      if (name !== 'request' && name !== 'vault') return null;
      const real = await realRpc(req);
      const json = viewJson(real);
      if (!json) return null;
      real.result.result = viewBody(name === 'request' ? { ...json, ...reqPatch } : { ...json, ...vaultPatch });
      return { status: 200, body: real };
    };
    const sizes = [[390, 844], [390, 664], [375, 553], [360, 640], [320, 568]];
    for (const [plain, patchedOn] of [['plain', false], ['hold+sync', true]]) {
      for (const [w, h] of sizes) {
        await setViewport(w, h);
        const run = async () => {
          await go(phoneUrl(v));
          await waitState('request');
          if (patchedOn) await waitFor('the hold line', () => exists('#hold'), 5000);
          await sleep(300);
          await page('document.getElementById("chip").textContent = "signet test coins";');
          await sleep(50);
          const m = await page(`const b = document.getElementById('cancel').getBoundingClientRect(); const d = document.getElementById('digits').getBoundingClientRect(); const a = document.getElementById('amount').getBoundingClientRect();
            return { cancelTop: Math.round(b.top), cancelBottom: Math.round(b.bottom), cancelH: Math.round(b.height), digitsW: Math.round(d.width), digitsH: Math.round(d.height), digitsLeft: Math.round(d.left), digitsRight: Math.round(d.right), amountBottom: Math.round(a.bottom), digitsTop: Math.round(d.top), scrollH: document.documentElement.scrollHeight, scrollW: document.documentElement.scrollWidth };`);
          const fits = m.cancelBottom <= h;
          const third = m.digitsW >= w / 3;
          const overlap = m.digitsTop < m.amountBottom - 4;
          say(!fits || !third || overlap || m.scrollW > w ? 'FINDING' : 'info', 'layout', `${w}x${h} ${plain}`, { ...m, fits, third, overlap });
          await shot(`layout-${w}x${h}-${plain.replace('+', '-')}`);
        };
        if (patchedOn) await intercept(rpcPattern(), worst({ hold_active: true, assess_reason: 'new_destination' }, { backup_eligible: true, backup_state: true }), run);
        else await run();
      }
    }
    await setViewport(390, 844);
  },

  /** Text that moves after landing, on both pages, frame by frame for 3 s. */
  async drift() {
    const v = await makeVault('drift');
    const { id } = await mustPropose(v);
    const sample = async (name, selectors) => {
      const moves = await page(`const sel = ${JSON.stringify(selectors)}; const seen = {}; const els = sel.flatMap((s) => [...document.querySelectorAll(s)]);
        const rect = (e) => { const r = e.getBoundingClientRect(); return [r.x, r.y, r.width, r.height].map((n) => Math.round(n * 100) / 100).join(','); };
        const first = els.map(rect); const out = new Set(); const end = performance.now() + 3000;
        await new Promise((done) => { const f = () => { els.forEach((e, i) => { if (rect(e) !== first[i]) out.add((e.id || e.className || e.tagName) + ':' + first[i] + '->' + rect(e)); }); if (performance.now() < end) requestAnimationFrame(f); else done(); }; requestAnimationFrame(f); });
        return [...out].slice(0, 8);`);
      say(moves.length ? 'FINDING' : 'info', 'drift', `${name}: boxes that moved in 3 s`, { moves });
    };
    await go(phoneUrl(v));
    await waitState('request');
    await sleep(500);
    await sample('phone request', ['#digits', '#digits .sl', '#digits .col', '#to', '#amount', '#cancel', '.fuse', '#chip', '.wordmark']);
    await setViewport(1080, 1350, false, 1);
    await go(`${stage.origin}/t/#v=${v.vaultHex}&r=${id}`);
    await waitThief('waiting');
    await sleep(800);
    await sample('thief waiting 1080x1350', ['#clock', '#clock .sl', '#auto', '#zero-label', '#fuse', '#dest-row', '#near-row', '#chip', '.wordmark', '#wait-label']);
    const w = await page('const r = document.getElementById("clock").getBoundingClientRect(); return { width: r.width, frac: r.width / innerWidth };');
    say(w.frac >= 1 / 3 ? 'info' : 'FINDING', 'drift', 'thief digits at 1080x1350', w);
    await setViewport(1440, 900, false, 2);
    await go(`${stage.origin}/t/#v=${v.vaultHex}&r=${id}`);
    await waitThief('waiting');
    await sleep(800);
    await shot('thief-1440x900-waiting');
    await sample('thief waiting 1440x900', ['#clock', '#clock .sl', '#auto', '#zero-label', '#fuse', '#dest-row', '#near-row', '#chip', '.wordmark']);
    const land = await page(`const r = (s) => { const b = document.querySelector(s)?.getBoundingClientRect(); return b ? { top: Math.round(b.top), bottom: Math.round(b.bottom), left: Math.round(b.left), right: Math.round(b.right) } : null; }; return { clock: r('#clock'), under: r('#under-clock'), fuse: r('#fuse'), rows: r('#rows'), chip: r('#chip'), label: r('#wait-label'), h: innerHeight, w: innerWidth, frac: document.getElementById('clock').getBoundingClientRect().width / innerWidth };`);
    say('info', 'drift', 'thief boxes at 1440x900', land);
    await setViewport(1280, 720, false, 2);
    await sleep(600);
    await shot('thief-1280x720-waiting');
    const land2 = await page(`const r = (s) => { const b = document.querySelector(s)?.getBoundingClientRect(); return b ? { top: Math.round(b.top), bottom: Math.round(b.bottom) } : null; }; return { clock: r('#clock'), fuse: r('#fuse'), rows: r('#rows'), h: innerHeight, scrollH: document.documentElement.scrollHeight, frac: document.getElementById('clock').getBoundingClientRect().width / innerWidth };`);
    say(land2.scrollH > land2.h ? 'FINDING' : 'info', 'drift', 'thief boxes at 1280x720', land2);

    // Cancelled: both pages, nothing moves after the stamp. Each read in its own document.
    await setViewport(390, 844);
    await go(phoneUrl(v));
    await waitState('request');
    await clickOn('#cancel');
    await waitState('cancelled');
    await sleep(400);
    await sample('phone cancelled', ['#digits', '#stamp', '#key-line', '.hash']);
    await shot('drift-phone-cancelled');
    await setViewport(1440, 900, false, 2);
    await go(`${stage.origin}/t/#v=${v.vaultHex}&r=${id}`);
    await waitThief('frozen');
    await sleep(600);
    await shot('thief-1440x900-frozen-no-reading');
    await setViewport(390, 844);
  },
};

// ---------------------------------------------------------------- run

async function main() {
  stage = await startStage({ miner: true, softPasskey: false, relayEnv: { STATUS_CACHE_MS: 0 } });
  reader = new NearReader({ urls: stage.config.rpc, timeoutMs: 15_000 });
  views = contractViews(reader, stage.contract);
  instance = await views.instance();
  browser = await startChrome({ width: 390, height: 844, scale: 2 });
  ({ cdp } = browser);
  await cdp.send('Emulation.setDeviceMetricsOverride', { width: 390, height: 844, deviceScaleFactor: 2, mobile: true });
  await cdp.send('Emulation.setFocusEmulationEnabled', { enabled: true });
  await cdp.send('WebAuthn.enable');
  ({ authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } }));
  await cdp.send('Network.enable');
  cdp.ws.addEventListener('message', (event) => {
    const data = JSON.parse(event.data);
    if (data.method === 'Fetch.requestPaused') for (const handler of paused) handler(data.params).catch((err) => say('error', 'intercept', err.message));
    if (data.method === 'Network.requestWillBeSent') network.push({ url: data.params.request.url, body: data.params.request.postData ?? '', referer: data.params.request.headers.Referer ?? null });
  });
  for (const [name, fn] of Object.entries(probes)) {
    if (ONLY && !ONLY.includes(name)) continue;
    const begun = Date.now();
    try {
      await fn();
      say('done', name, `${Math.round((Date.now() - begun) / 1000)} s`);
    } catch (err) {
      say('error', name, err.message.slice(0, 600));
      await setViewport(390, 844).catch(() => {});
    }
  }
}

let stopping = null;
const stopAll = () => {
  stopping ??= (async () => {
    await browser?.stop().catch(() => {});
    await stage?.stop().catch(() => {});
  })();
  return stopping;
};
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => stopAll().finally(() => process.exit(130)));
main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
}).finally(async () => {
  await stopAll();
  process.exit(process.exitCode ?? 0);
});
