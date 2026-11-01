// The thief tab. Everything it says about the coin it read from the contract or a Bitcoin node, and the only link to the
// phone is the contract: this page never hears from it. The stolen key stays in this tab and leaves only as signatures.
import {
  advanceState, bitcoinReader, btcAddressLabel, btcAddressLink, btcTxLabel, btcTxLink, buildFragment, buildPropose, clock, contractViews, digits, keyAloneSpend,
  loadConfig, NearReader, nearTxLabel, nearTxLink, parseFragment, postTxOnce, RelayClient, RpcDown, requestState, scriptMatchesVault, seedMatchesVault, sendEverything,
  SkewTracker, spkToAddress, StaleRead, ViewRefused,
} from '/site/lib/index.mjs';
import { parseTx, txid as txidOf } from '/tools/lib/btc.mjs';
import { fromHex, toHex } from '/tools/lib/bytes.mjs';
import { destinationProblem, destinationSpk, fuseFraction, isNotYetUnlocked, liveRequestIn, nodeTextClass, parseSeed, relaySentence, satsText, sumOfInputs, tickPulse } from './logic.mjs';

const $ = (id) => document.getElementById(id);
const root = $('root');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const POLL_MS = 1000;
const BLOCK_TIME_MS = 5000;
const STATUS_MS = 30_000;
const ARMED_MS = 5000;
const REFUSED_HOLD_MS = 2400;
const FLING_ROW_MS = 400;
const FLING_MS = 240;
const EXECUTE_RETRY_MS = 2000;
const EXECUTE_RESEND_MS = 20_000;
const SIGNING_RESEND_MS = 30_000;
const BAD_READS_TO_SAY = 3;
const MAX_INPUTS = 16;
const KEY_PHRASE = 'finished with a false/empty top stack element';

const S = {
  config: null, reader: null, views: null, btc: null, relay: null, instance: null,
  relayStatus: null,
  vaultHex: null, vault: null, requestId: null, request: null, lastKnown: null, read: null,
  tracker: new SkewTracker(), lastBlockRead: 0, badReads: 0, badReadsShown: false, unseenReads: 0,
  seed: null, script: null, coins: [], spend: null, seedOk: false, toOk: false, viewProblem: null, nearDown: null, btcDown: null, feeRate: null,
  nearTx: null, cursor: false, live: false, flung: false, onScreen: null, terminalSince: null, finalTxid: null, broadcasting: false,
  state: 'boot', timings: {},
};
window.undoTimings = S.timings;

// ---------------------------------------------------------------- drawing states

function setState(name, panel) {
  S.state = name;
  root.dataset.state = name;
  if (panel) root.dataset.panel = panel;
}

function setHash(el, label, link) {
  el.textContent = '';
  if (link) {
    const a = document.createElement('a');
    a.href = link;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    a.textContent = label;
    el.append(a);
  } else {
    el.textContent = label;
  }
}

function plain(state, sentence, { verbatim = '', address = null, retry = null } = {}) {
  setState(state, 'plain');
  $('plain-text').textContent = sentence;
  $('plain-verbatim').textContent = verbatim;
  if (address) setHash($('plain-address'), btcAddressLabel(S.config, address), btcAddressLink(S.config, address));
  else $('plain-address').textContent = '';
  const button = $('plain-retry');
  button.classList.toggle('on', Boolean(retry));
  button.onclick = retry;
}

const errorWords = (err) => err?.verbatim ?? err?.message ?? String(err);

// ---------------------------------------------------------------- the clock

/** Reads the real advance of the digit and colon from the glyphs, so a slot fits the font this machine really has. */
function measureClock() {
  const c = $('clock');
  const size = parseFloat(getComputedStyle(c).fontSize);
  const probe = (text) => {
    const span = document.createElement('span');
    span.textContent = text;
    span.style.position = 'absolute';
    span.style.visibility = 'hidden';
    span.style.whiteSpace = 'pre';
    c.append(span);
    const width = span.getBoundingClientRect().width;
    span.remove();
    return width / size;
  };
  c.style.setProperty('--adv', String(probe('0')));
  c.style.setProperty('--colon', String(probe(':')));
}

const slot = (el, text) => {
  if (el.textContent !== text) el.textContent = text;
};

function showDigits(d) {
  const tensOfMinutes = Math.floor(d.minutes / 10);
  if (tensOfMinutes > 0 && root.dataset.wide !== '1') {
    root.dataset.wide = '1';
    measureClock();
  }
  slot($('d-mt'), tensOfMinutes > 0 ? String(tensOfMinutes) : '');
  slot($('d-m'), String(d.minutes % 10));
  slot($('d-s1'), String(Math.floor(d.seconds / 10)));
  slot($('d-s2'), String(d.seconds % 10));
  slot($('d-t'), String(d.tenths));
  if ($('clock').dataset.clock !== d.text) $('clock').dataset.clock = d.text;
  S.onScreen = d.text;
}

function drawFuse(fraction) {
  $('fuse-burn').style.transform = `scaleX(${fraction})`;
  $('fuse-tip').style.left = `${(1 - fraction) * 100}%`;
}

let lastGlow = null;
function drawPulse(level, base) {
  const q = Math.round(level * 8) / 8;
  if (q === lastGlow) return;
  lastGlow = q;
  $('glow').style.opacity = String(base + 0.12 * q);
  $('clock').style.textShadow = q > 0 ? `0 0 ${(26 + 40 * q) * unit()}px rgba(255,59,48,${0.25 + 0.55 * q})` : 'none';
}

let unitPx = null;
const unit = () => {
  if (unitPx === null) unitPx = $('chip').getBoundingClientRect().height / 58;
  return unitPx;
};
window.addEventListener('resize', () => {
  unitPx = null;
});

/** One frame. Digits come only from the contract's unlock and the block time, and stop when reads stop. */
function draw() {
  requestAnimationFrame(draw);
  if (!S.live || !S.request) return;
  const r = S.request;
  const c = clock(r.unlock, S.tracker.sample(), Date.now(), r.proposed_at);
  if (!c) return;
  showDigits(c);
  drawFuse(fuseFraction(c.remainingMs, r.unlock - r.proposed_at));
  if (root.dataset.fling === 'done') drawPulse(c.zero ? 0 : tickPulse(c.remainingMs) * 0.5, 0.30);
}

// ---------------------------------------------------------------- what the page says about the relay

async function refreshRelay() {
  S.relayStatus = await S.relay.status();
  const sentence = relaySentence(S.relayStatus);
  if (S.state === 'armed' || S.state === 'short') $('armed-note').textContent = sentence ?? '';
  drawAuto();
}

function drawAuto() {
  if (S.state === 'waiting') {
    const sentence = relaySentence(S.relayStatus);
    root.dataset.auto = sentence ? 'off' : 'armed';
    $('auto').textContent = sentence ? 'relay down: execute can\'t fire' : 'auto-execute armed';
    if (!S.badReadsShown) $('note').textContent = sentence ?? '';
  }
}

// ---------------------------------------------------------------- armed

function fragmentFields() {
  const fields = { v: S.vaultHex };
  const to = $('to').value.trim();
  if (to && !destinationProblem(to)) fields.to = to;
  if (S.requestId !== null) fields.r = S.requestId;
  return fields;
}

function rewriteFragment() {
  const text = buildFragment(fragmentFields()) + (S.cursor ? '&cursor=1' : '');
  history.replaceState(null, '', text);
}

function checkKey() {
  const seed = parseSeed($('key').value);
  S.seed = seed;
  S.seedOk = false;
  let why = '';
  if ($('key').value.trim() !== '') {
    if (!seed) why = 'That is not a key: it should be 64 hex characters.';
    else if (S.vault) {
      const match = seedMatchesVault(seed, S.vault);
      if (match.ku && !match.ks) why = 'That key can\'t ask again.';
      else if (!match.ks || !match.ku) why = 'That key is not this vault\'s';
      else S.seedOk = true;
    }
  }
  if (S.seedOk && S.vault.k_s_suspended) {
    S.seedOk = false;
    why = 'That key can\'t ask again.';
  }
  $('key-why').textContent = why;
}

function checkTo() {
  const value = $('to').value.trim();
  const problem = destinationProblem(value);
  S.toOk = problem === null;
  $('to').classList.toggle('long', value.length > 44);
  $('to-why').textContent = {
    not_test_address: 'This demo only sends to test addresses that start with tb1.',
    bad_address: 'That address does not check out.',
  }[problem] ?? '';
}

function drawSend() {
  $('send').disabled = !(S.seedOk && S.toOk && S.spend && !S.spend.short && !S.nearDown && !S.btcDown && !S.viewProblem);
}

function buildSpend() {
  S.spend = null;
  if (!S.script || !S.coins.length) return;
  const to = S.toOk ? destinationSpk($('to').value) : new Uint8Array(22);
  S.spend = sendEverything({ coins: S.coins.slice(0, MAX_INPUTS), to, script: S.script, feeRate: S.feeRate ?? 2 });
}

/** The contract's own opinion of this spend, before anything is signed. Its refusal is shown word for word. */
async function checkPropose() {
  S.viewProblem = null;
  if (!S.toOk || !S.spend || S.spend.short) return;
  try {
    const check = await S.views.checkPropose(S.vaultHex, { inputs: S.spend.inputs, to: toHex(destinationSpk($('to').value)), amount: S.spend.amount });
    root.dataset.tier = check.tier;
  } catch (err) {
    if (err instanceof ViewRefused) S.viewProblem = err.verbatim;
    else throw err;
  }
}

function drawArmed() {
  const total = S.spend ? S.spend.total : sumOfInputs(S.coins);
  $('amount').textContent = S.coins.length ? `everything  ${satsText(total)}` : 'everything';
  $('fee').textContent = S.spend && !S.spend.short ? `fee ${S.spend.fee} sats comes out of it` : '';
  const notes = [];
  if (S.nearDown) notes.push(S.nearDown);
  if (S.btcDown) notes.push(S.btcDown);
  if (S.viewProblem) notes.push(`NEAR contract: ${S.viewProblem}`);
  const relay = relaySentence(S.relayStatus);
  if (relay) notes.push(relay);
  $('armed-note').textContent = notes.join(' ');
  drawSend();
}

function onFieldInput() {
  checkKey();
  checkTo();
  buildSpend();
  if (S.state === 'armed') {
    drawArmed();
    checkPropose().then(drawArmed).catch(() => {});
  }
}

/** Reads the coins and the contract's numbers, and draws armed or short. Keeps what is in the fields. */
async function refreshArmed() {
  if (S.state !== 'armed' && S.state !== 'short') return undefined;
  try {
    S.vault = await S.views.vault(S.vaultHex);
    if (!S.vault?.active) return plain('no_vault', 'That vault is not on this contract, or not active yet.');
    root.dataset.guardOnline = String(S.vault.guard_online);
    root.dataset.delayMs = String(await S.views.delayNow(S.vaultHex));
    if (!S.script) {
      const script = fromHex(await S.views.script(S.vaultHex));
      if (!scriptMatchesVault(script, S.vault)) return plain('no_vault', 'The contract\'s script does not pay this vault\'s address, so this page stops.');
      S.script = script;
    }
    S.nearDown = null;
  } catch (err) {
    if (!(err instanceof RpcDown || err instanceof StaleRead)) throw err;
    S.nearDown = 'Can\'t read the NEAR contract right now.';
  }
  if (S.vault) {
    try {
      S.coins = coinsOf(await S.btc.utxos(S.vault.address));
      const estimates = await S.btc.feeEstimates().catch(() => null);
      S.feeRate = Math.max(2, Math.ceil(estimates?.['6'] ?? 2));
      S.btcDown = null;
    } catch (err) {
      S.btcDown = `Can't read ${S.config.labels.bitcoin} right now: ${err.message}`;
    }
  }
  checkKey();
  checkTo();
  buildSpend();
  if (!S.nearDown && !S.btcDown && (S.coins.length === 0 || S.spend?.short)) {
    return plain('short', 'No coin in this vault yet', { address: S.vault.address });
  }
  await checkPropose().catch(() => {});
  if (S.state !== 'armed' && S.state !== 'short') return undefined;
  setState('armed', 'armed');
  drawArmed();
  return undefined;
}

const coinsOf = (utxos) => utxos.map((c) => ({ txid: c.txid, vout: c.vout, value: c.value })).sort((a, b) => b.value - a.value).slice(0, MAX_INPUTS);

let armedBusy = false;
async function startArmed() {
  setState('armed', 'armed');
  root.dataset.auto = 'armed';
  await refreshArmed();
  setInterval(async () => {
    if (armedBusy || (S.state !== 'armed' && S.state !== 'short')) return;
    armedBusy = true;
    await refreshArmed().catch(() => {});
    armedBusy = false;
  }, ARMED_MS);
}

// ---------------------------------------------------------------- pressing Send: first, Bitcoin with the key alone

async function pressSend() {
  const send = $('send');
  if (send.disabled) return undefined;
  S.timings.pressed = performance.now();
  setState('direct', 'armed');
  const label = send.textContent;
  send.disabled = true;
  send.textContent = 'Sending everything straight to Bitcoin';
  const answer = await sendKeyAlone().finally(() => {
    send.textContent = label;
  });
  S.timings.answered = performance.now();
  if (answer.none) return plain('short', 'No coin in this vault yet', { address: S.vault.address });
  if (answer.kind === 'accepted') {
    // The kill line for the whole product. Nothing else on this screen, and nothing further happens.
    return plain('accepted', 'A NODE ACCEPTED THIS', { verbatim: btcTxLabel(S.config, answer.body) });
  }
  if (answer.kind === 'rejected' && answer.refusal === 'script') return showRefused(answer.body);
  if (answer.kind === 'rejected') {
    return plain('other_refusal', 'A node said no, but not about the signature:', { verbatim: `${S.config.labels.bitcoin} node: ${answer.body}`, retry: retryFromTop });
  }
  return plain('no_answer', 'The node did not answer:', { verbatim: answer.body ?? answer.error ?? 'no words', retry: retryFromTop });
}

/** One real POST with the key alone, of the coins a node reports now. Never sent twice for one press. */
async function sendKeyAlone() {
  let coins;
  try {
    coins = coinsOf(await S.btc.utxos(S.vault.address));
  } catch (err) {
    return { kind: 'no_answer', body: null, error: err.message };
  }
  const to = destinationSpk($('to').value);
  const spend = sendEverything({ coins, to, script: S.script, feeRate: S.feeRate ?? 2 });
  if (coins.length === 0 || spend.short) return { none: true };
  S.spend = spend;
  S.coins = coins;
  const { raw, txid } = keyAloneSpend({ seed: S.seed, script: S.script, coins, to, amount: spend.amount });
  return postTxOnce(S.config.esplora, raw, txid);
}

function retryFromTop() {
  setState('armed', 'armed');
  refreshArmed().then(() => {
    if (S.state === 'armed' && !$('send').disabled) pressSend();
  });
}

/** Red bar, the one sentence, and the node's own bytes. The string comes from the POST, and only its colour is ours. */
function showRefused(body) {
  setState('refused', 'refused');
  $('node-label').textContent = `${S.config.labels.bitcoin} node:`;
  const box = $('node-text');
  box.textContent = '';
  const at = body.indexOf(KEY_PHRASE);
  if (at >= 0) {
    const key = document.createElement('span');
    key.className = 'key-phrase';
    key.textContent = KEY_PHRASE;
    box.append(body.slice(0, at), key, body.slice(at + KEY_PHRASE.length));
  } else {
    box.textContent = body;
  }
  $('node').className = `node mono ${nodeTextClass(body)}`;
  $('refused').classList.add('go');
  setTimeout(() => {
    ask().catch(showAskFailure);
  }, REFUSED_HOLD_MS);
}

// ---------------------------------------------------------------- asking the NEAR contract

function showAskFailure(err) {
  const words = [err.code, err.verbatim ?? err.message].filter(Boolean).join(': ');
  $('ask-why').textContent = words;
  const sentence = err.code === 'relay_down' ? relaySentence({ reachable: false })
    : err.code === 'daily_ceiling' ? relaySentence({ reachable: true, general: { up: false, why: 'daily_ceiling' } })
      : null;
  $('term-1').textContent = sentence ?? 'The NEAR contract was not asked.';
  root.dataset.why = err.code ?? 'error';
  $('ask-retry').classList.add('on');
  $('ask-retry').onclick = () => {
    $('ask-retry').classList.remove('on');
    $('ask-why').textContent = '';
    delete root.dataset.why;
    ask().catch(showAskFailure);
  };
}

/** Beats if the contract reads the guard offline, because a vault with no beat reads a longer wait. Then proposes. */
async function ask() {
  setState('asking', 'wait');
  $('term-1').textContent = 'Asking the NEAR contract';
  $('glow').style.opacity = '0';
  const vault = await S.views.vault(S.vaultHex);
  S.vault = vault;
  if (!vault.guard_online) {
    await S.relay.call('heartbeat', { vault: S.vaultHex });
    for (let i = 0; i < 20; i += 1) {
      await sleep(500);
      if ((await S.views.vault(S.vaultHex)).guard_online) break;
    }
    S.vault = await S.views.vault(S.vaultHex);
  }
  // A request may already be there from a press whose answer got lost.
  const seenBefore = new Set(S.vault.pending);
  const block = await S.reader.blockTime();
  S.tracker.add(block);
  const to = destinationSpk($('to').value);
  const args = buildPropose({
    contract: S.config.contract, vault: S.vault, script: S.script, seed: S.seed, inputs: S.spend.inputs, to, amount: S.spend.amount,
    nonce: S.vault.spend_nonce, expiresAt: block.blockMs + 30 * 60_000,
  });
  const sent = await S.relay.call('propose_btc', args);
  S.nearTx = sent.hash;
  S.timings.proposed = performance.now();
  const id = await findRequest(seenBefore, sent.hash);
  S.seed = null;
  $('key').value = '';
  S.requestId = id;
  S.flung = false;
  rewriteFragment();
  remember();
  startPolling();
}

async function findRequest(before, hash) {
  for (let i = 0; i < 60; i += 1) {
    const vault = await S.views.vault(S.vaultHex).catch(() => null);
    const fresh = vault?.pending.filter((id) => !before.has(id)) ?? [];
    if (fresh.length) return Math.max(...fresh);
    if (i === 15 || i === 45) {
      const outcome = await S.reader.txOutcome(hash, S.relayStatus?.relayAccount ?? '').catch(() => null);
      if (outcome?.failure) {
        const err = new Error(outcome.failure);
        err.code = 'contract_refused';
        err.verbatim = outcome.failure;
        throw err;
      }
    }
    await sleep(500);
  }
  const err = new Error('the transaction was sent and no new request appeared on the contract');
  err.code = 'no_request';
  throw err;
}

// ---------------------------------------------------------------- reading the request

const memoryKey = () => `undo-thief:${S.vaultHex}:${S.requestId}`;

function remember() {
  try {
    sessionStorage.setItem(memoryKey(), JSON.stringify({ lastKnown: S.lastKnown, nearTx: S.nearTx }));
  } catch {
    // A private window. A reload just reads less.
  }
}

function recall() {
  try {
    const saved = JSON.parse(sessionStorage.getItem(memoryKey()) ?? 'null');
    if (saved) {
      S.lastKnown = saved.lastKnown ?? null;
      S.nearTx = saved.nearTx ?? null;
    }
  } catch {
    // Nothing saved.
  }
}

let polling = false;
function startPolling() {
  if (polling) return;
  polling = true;
  const loop = async () => {
    const started = Date.now();
    await poll();
    const wait = S.read?.terminal ? terminalPollMs() : POLL_MS;
    if (wait !== null) setTimeout(loop, Math.max(0, wait - (Date.now() - started)));
  };
  loop();
}

function terminalPollMs() {
  // Keeps reading a while, because the contract reporting a signature overrides a stamp from a lagging node.
  if (S.state === 'signed' && !S.finalTxid) return 2000;
  if (S.terminalSince && Date.now() - S.terminalSince > 120_000) return null;
  return 5000;
}

async function poll() {
  try {
    if (Date.now() - S.lastBlockRead >= BLOCK_TIME_MS || !S.tracker.sample()) {
      S.tracker.add(await S.reader.blockTime());
      S.lastBlockRead = Date.now();
    }
    const { vault, request } = await S.views.both(S.vaultHex, S.requestId);
    readsWorked();
    onRead(vault, request);
  } catch (err) {
    if (err instanceof RpcDown || err instanceof StaleRead) return readFailed();
    if (err instanceof ViewRefused) {
      $('note').textContent = `NEAR contract: ${err.verbatim}`;
      return undefined;
    }
    $('note').textContent = errorWords(err);
  }
  return undefined;
}

function readsWorked() {
  S.badReads = 0;
  if (S.badReadsShown) {
    S.badReadsShown = false;
    delete root.dataset.dim;
    $('note').textContent = '';
    S.live = S.read?.clockRuns || S.state === 'firing';
    drawAuto();
  }
}

function readFailed() {
  S.badReads += 1;
  if (S.badReads >= BAD_READS_TO_SAY && !S.badReadsShown) {
    S.badReadsShown = true;
    S.live = false;
    root.dataset.dim = '1';
    $('note').textContent = 'Can\'t read the NEAR contract right now';
  }
}

function onRead(vault, request) {
  if (!vault) return;
  S.vault = vault;
  if (request) {
    S.request = request;
    S.lastKnown = request;
    remember();
  }
  const sample = S.tracker.sample();
  const chainNow = sample.blockMs + (Date.now() - sample.localMs);
  const next = requestState({ request, vault, chainNow, lastKnown: S.lastKnown });
  if (next.kind === 'no_vault') return;
  if (next.kind === 'unseen') {
    // No sighting and nothing on the contract. It might be a lagging node, so give it some reads before saying so.
    S.unseenReads += 1;
    if (S.unseenReads >= 5 && !S.lastKnown && !S.request) plain('no_request', 'That request is not on this contract.');
    return;
  }
  S.unseenReads = 0;
  S.read = advanceState(S.read, next);
  if (S.read.terminal && !S.terminalSince) S.terminalSince = Date.now();
  switch (S.read.kind) {
    case 'waiting': return enterWaiting();
    case 'unlocked': return enterFiring();
    case 'signing': return enterSigning();
    case 'signed': return enterSigned();
    case 'cancelled': return enterFrozen();
    case 'expired': return enterExpired();
    default: return undefined;
  }
}

function drawRows() {
  const r = S.request;
  if (r) {
    const address = spkToAddress('mutinynet', r.to);
    $('dest-row').textContent = `to ${address ?? r.to}  ${satsText(sumOfInputs(r.inputs))}`;
  }
  if (S.nearTx) setHash($('near-row'), nearTxLabel(S.config, S.nearTx), nearTxLink(S.config, S.nearTx));
}

function drawHold() {
  const r = S.request;
  const on = Boolean(r && r.hold_active);
  $('hold-row').classList.toggle('on', on);
  if (on) {
    $('hold-plus').textContent = `+${digits(r.unlock - r.base_unlock).short}`;
    $('hold-reason').textContent = r.assess_reason;
  }
}

function enterWaiting() {
  drawRows();
  drawHold();
  if (S.state === 'waiting') return;
  const first = !S.flung && S.state === 'asking';
  setState('waiting', 'wait');
  S.live = true;
  drawAuto();
  if (first) fling();
  else {
    root.dataset.fling = 'done';
    $('glow').style.opacity = '0.30';
  }
  S.flung = true;
}

/** `unlocks in 5:00` on the row, then the running digits land full frame in under 0.3 s. */
function fling() {
  const r = S.request;
  root.dataset.fling = 'row';
  $('term-1').textContent = 'proposed to the NEAR contract';
  $('term-wait').textContent = digits(r.unlock - r.proposed_at).short;
  setTimeout(() => {
    const c = $('clock');
    const to = c.getBoundingClientRect();
    const from = $('term-wait').getBoundingClientRect();
    const scale = from.height / to.height;
    const dx = from.left - to.left;
    const dy = from.top - to.top;
    const frames = [];
    for (let i = 0; i <= 8; i += 1) {
      const u = i / 8;
      const p = 1 - (1 - u) * (1 - u);
      frames.push({
        transform: `translate(${Math.round(dx * (1 - p))}px, ${Math.round(dy * (1 - p))}px) scale(${scale + (1 - scale) * p})`,
        filter: `blur(${(8 * (1 - p)).toFixed(2)}px)`,
      });
    }
    frames[8].filter = 'none';
    root.dataset.fling = 'go';
    S.timings.fling = performance.now();
    const motion = c.animate(frames, { duration: FLING_MS, easing: 'linear' });
    $('glow').animate([{ opacity: 0 }, { opacity: 0.30 }], { duration: FLING_MS });
    $('glow').style.opacity = '0.30';
    motion.onfinish = () => {
      root.dataset.fling = 'done';
      S.timings.landed = performance.now();
    };
  }, FLING_ROW_MS);
}

// ---------------------------------------------------------------- at zero

let firingLoop = false;
function enterFiring() {
  drawRows();
  if (S.state !== 'firing') {
    setState('firing', 'wait');
    root.dataset.fling = 'done';
    S.live = true;
    S.timings.firing = performance.now();
    $('auto').textContent = 'The contract signs';
    $('note').textContent = '';
    root.dataset.auto = 'firing';
  }
  if (!firingLoop) {
    firingLoop = true;
    fire().finally(() => {
      firingLoop = false;
    });
  }
}

/**
 * What makes "at zero, the contract signs for them" literally true. Sends until the contract moves. A refusal for being
 * a moment early is sent again in 2 s. Any other refusal stays on screen in the chain's words, and is not sent again.
 */
async function fire() {
  while (S.state === 'firing') {
    let waitMs = EXECUTE_RESEND_MS;
    try {
      const sent = await S.relay.call('execute', { vault: S.vaultHex, request: S.requestId });
      S.nearTx = sent.hash;
      S.timings.executed ??= performance.now();
      if (S.state !== 'firing') return;
      drawRows();
      await sleep(EXECUTE_RETRY_MS + 500);
      if (S.state !== 'firing') return;
      const outcome = await S.reader.txOutcome(sent.hash, S.relayStatus?.relayAccount ?? '').catch(() => null);
      if (S.state !== 'firing') return;
      if (isNotYetUnlocked(outcome?.failure)) {
        waitMs = 0;
      } else if (outcome?.failure) {
        $('note').textContent = `NEAR contract: ${outcome.failure}`;
        waitMs = null;
      }
    } catch (err) {
      $('note').textContent = [relaySentence(err.code === 'relay_down' ? { reachable: false } : err.code === 'daily_ceiling' ? { reachable: true, general: { up: false, why: 'daily_ceiling' } } : null), err.code, err.verbatim ?? err.message].filter(Boolean).join(' ');
      waitMs = err.retryAfterS ? err.retryAfterS * 1000 : EXECUTE_RETRY_MS;
      S.relayStatus = await S.relay.status();
    }
    if (waitMs === null) return;
    await sleep(waitMs);
  }
}

let signingLoop = false;
function enterSigning() {
  drawRows();
  if (S.state === 'signing') return;
  setState('signing', 'wait');
  root.dataset.fling = 'done';
  S.live = false;
  showDigits(digits(0));
  drawFuse(0);
  unstamp();
  $('auto').textContent = 'Waiting for the signature';
  $('note').textContent = '';
  if (!signingLoop) {
    signingLoop = true;
    resendWhileSigning();
  }
}

/** A sign call can die on the signer. `execute` picks up what is missing, and refuses while one is in flight. */
async function resendWhileSigning() {
  while (S.state === 'signing') {
    await sleep(SIGNING_RESEND_MS);
    if (S.state !== 'signing') return;
    await S.relay.call('execute', { vault: S.vaultHex, request: S.requestId }).catch(() => {});
  }
}

function unstamp() {
  $('stamp-line').classList.remove('on');
  delete root.dataset.noReading;
}

async function enterSigned() {
  drawRows();
  if (S.state !== 'signed') {
    setState('signed', 'wait');
    root.dataset.fling = 'done';
    S.live = false;
    if (S.onScreen === null) showDigits(digits(0));
    drawFuse(0);
    unstamp();
    $('wait-label').textContent = '';
    $('signed-line').classList.add('on');
    $('signed-line').textContent = 'The contract signed.';
    $('note').textContent = '';
    $('glow').style.opacity = '0.13';
    $('clock').style.textShadow = 'none';
  }
  if (S.broadcasting || S.finalTxid) return;
  S.broadcasting = true;
  try {
    await broadcastFinal();
  } finally {
    S.broadcasting = false;
  }
}

/** Anyone may send the contract's finished transaction. The txid shows only once a node has it. */
async function broadcastFinal() {
  const hex = await S.views.finalTx(S.vaultHex, S.requestId).catch(() => null);
  if (!hex) return;
  const txid = txidOf(parseTx(fromHex(hex)));
  const answer = await postTxOnce(S.config.esplora, hex, txid);
  let known = answer.kind === 'accepted';
  if (answer.kind === 'rejected' && (answer.refusal === 'already' || answer.refusal === 'inputs_gone')) {
    known = (await S.btc.tx(txid).catch(() => null))?.txid === txid;
  }
  if (known) {
    S.finalTxid = txid;
    setHash($('txid-row'), btcTxLabel(S.config, txid), btcTxLink(S.config, txid));
    $('note').textContent = '';
    root.dataset.broadcast = 'done';
  } else if (answer.kind === 'rejected') {
    $('note').textContent = `${S.config.labels.bitcoin} node: ${answer.body}`;
    root.dataset.broadcast = 'refused';
  } else {
    $('note').textContent = `Signed, not sent yet. The node did not answer: ${answer.body ?? answer.error ?? 'no words'}`;
    root.dataset.broadcast = 'no_answer';
  }
}

// ---------------------------------------------------------------- the two other endings

function enterFrozen() {
  if (S.state === 'frozen') return;
  // Whatever the digits read at this poll stays. It is this screen's reading, never the chain's number, and the
  // page says nothing about it. A page that never drew digits for this request shows none.
  S.live = false;
  S.timings.frozen = performance.now();
  const hadReading = S.onScreen !== null;
  setState('frozen', 'wait');
  root.dataset.fling = 'done';
  if (!hadReading) root.dataset.noReading = '1';
  $('hold-row').classList.remove('on');
  $('glow').style.opacity = '0.04';
  $('clock').style.textShadow = 'none';
  $('note').textContent = '';
  // Only a rotation stops that key. A plain cancel or a freeze stops this one request and leaves the key able to ask.
  $('stamp-line').classList.toggle('on', S.vault?.k_s_suspended === true);
  drawRows();
}

function enterExpired() {
  if (S.state === 'expired') return;
  S.live = false;
  plain('expired', 'This request expired');
}

// ---------------------------------------------------------------- boot

async function boot() {
  try {
    S.config = await loadConfig();
  } catch (err) {
    return plain('no_config', 'This page has no config, so it reads nothing.', { verbatim: err.message });
  }
  $('chip').textContent = S.config.labels.chip;

  // The key, if the link had one, comes out of the address bar before anything else happens.
  S.cursor = /(?:^#|&)cursor=1(?:&|$)/.test(location.hash);
  if (S.cursor) root.dataset.cursor = '1';
  const fields = parseFragment(location.hash);
  if (fields.k) $('key').value = fields.k;
  S.vaultHex = fields.v ?? null;
  if (fields.to) $('to').value = fields.to;
  S.requestId = fields.r ?? null;
  if (S.vaultHex) rewriteFragment();
  else history.replaceState(null, '', location.pathname);

  S.reader = new NearReader({ urls: [...S.config.rpc] });
  S.views = contractViews(S.reader, S.config.contract);
  S.btc = bitcoinReader(S.config.esplora);
  S.relay = new RelayClient({ relay: S.config.relay, funds: S.config.funds });

  await document.fonts?.ready;
  measureClock();
  requestAnimationFrame(draw);

  if (!S.vaultHex) return plain('no_vault', 'This tab needs a vault link. There is no vault in this one.');
  refreshRelay();
  setInterval(() => refreshRelay().catch(() => {}), STATUS_MS);
  return loadVault();
}

async function loadVault() {
  try {
    S.instance = await S.views.instance();
    if (S.instance.network === 'mainnet') return plain('no_config', 'This page is a demo for test coins only, and this contract is not on a test network.');
    S.vault = await S.views.vault(S.vaultHex);
    if (!S.vault || !S.vault.active) return plain('no_vault', 'That vault is not on this contract, or not active yet.');
    S.tracker.add(await S.reader.blockTime());
    S.lastBlockRead = Date.now();
    if (S.requestId === null) {
      const chainNow = () => {
        const sample = S.tracker.sample();
        return sample.blockMs + (Date.now() - sample.localMs);
      };
      S.requestId = await liveRequestIn(S.vault.pending, async (id) => {
        const request = await S.views.request(S.vaultHex, id);
        return requestState({ request, vault: S.vault, chainNow: chainNow() });
      });
      if (S.requestId !== null) rewriteFragment();
    }
  } catch (err) {
    plain('no_config', 'Can\'t read the NEAR contract right now', { verbatim: errorWords(err) });
    setTimeout(() => {
      setState('boot', 'none');
      loadVault();
    }, 5000);
    return undefined;
  }
  if (S.requestId !== null) {
    recall();
    S.flung = true;
    root.dataset.fling = 'done';
    return startPolling();
  }
  return startArmed();
}

$('key').addEventListener('input', onFieldInput);
$('to').addEventListener('input', onFieldInput);
$('send').addEventListener('click', () => {
  pressSend().catch((err) => plain('no_answer', 'This tab hit an error and sent nothing further:', { verbatim: errorWords(err), retry: retryFromTop }));
});
document.addEventListener('mousemove', (event) => {
  if (S.cursor) $('cursor').style.transform = `translate(${event.clientX}px, ${event.clientY}px)`;
});

boot().catch((err) => plain('no_config', 'This tab could not start.', { verbatim: errorWords(err) }));
