// The phone page. Everything it says about a request comes from the contract, read here over public RPC. Nothing
// connects it to the thief tab but the contract, which is the claim the film's shot makes.
//
// data-state on <html> and data-clock on the digits are what tests and the recorder wait on.
import {
  bitcoinReader, btcAddressLabel, btcAddressLink, btcTxLabel, btcTxLink, cancelButton, clock, contractViews, credentialToFragment, advanceState,
  credentialsFor, fromBase64Url, loadConfig, NearReader, nearTxLabel, nearTxLink, refusalOf, RelayClient, RelayRefused, requestState, rotateArgs,
  rotateDigest, RpcDown, rpIdHashOf, SkewTracker, spendKeys, spkToAddress, StaleRead, ViewRefused,
} from '/site/lib/index.mjs';
import { parseTx, txid as txidOf } from '/tools/lib/btc.mjs';
import { fromHex, toHex } from '/tools/lib/bytes.mjs';
import { randomBytes } from '/tools/lib/crypto.mjs';
import { buildRecovery } from '/tools/lib/recovery.mjs';
import { runH7 } from './h7.mjs';
import { ClockFace, h, hashBlock, satsText, setState, show, sumInputs } from './kit.mjs';
import { askAssertion, askNewPasskey, PasskeyFailed } from './passkey-ask.mjs';
import { parsePhoneFragment, recallCredential, rememberCredential, writeFragment } from './phone-fragment.mjs';
import { openElsewhere, passkeyProblem, problemWords, screenAwake, sensePasskeys } from './sense.mjs';
import { chainNowOf, confirmVault, prepareVault, sendVault } from './vault-make.mjs';

const POLL_MS = 1000;
const FAST_POLL_MS = 400;
const SKEW_MS = 5000;
const STATUS_MS = 30_000;
const STATUS_DOWN_MS = 5000;
const OUTCOME_MS = 8000;
const SEND_GIVE_UP_MS = 30_000;
const COIN_MS = 15_000;
const INTENT_MS = 10 * 60_000;
const READ_FAILS_TO_SAY = 3;
// A node a few blocks behind answers null for a request it has not reached, and that is within what a reader lets
// through. So a seen request reads as gone only when it stays gone. A stamp cannot be taken back.
const NULL_READS_TO_BELIEVE = 3;

const P = {
  screen: null, v: null, r: null, fragment: {}, vault: null, vaultRead: false, request: null, lastKnown: null, rs: null,
  relay: null, readFails: 0, readWords: null, notice: null, tap: null, prep: null, credential: null, blocked: false,
  rpBad: false, frozenText: null, stampLive: false, coinStill: false, coinCheckedAt: 0, tooLateTxid: null, face: null,
  skewAt: 0, statusAt: 0, timer: null, touch: null, seed: null, cold: null, balance: null, fundedTxid: null, stopped: false,
  sheetNote: null, hang: false,
};
let ctx;

// ---------------------------------------------------------------- boot

async function main() {
  let config;
  try {
    config = await loadConfig();
  } catch (err) {
    setState('no_config');
    show(h('p', { class: 'say' }, 'This page could not load its settings, so it shows nothing.'), h('p', { class: 'words' }, err.message));
    return;
  }
  document.getElementById('chip').textContent = config.labels.chip;

  const reader = new NearReader({ urls: config.rpc, timeoutMs: 6000 });
  ctx = {
    config, reader, views: contractViews(reader, config.contract), relay: new RelayClient({ relay: config.relay, funds: config.funds }),
    skew: new SkewTracker(), esplora: bitcoinReader(config.esplora), instance: null, credentials: null, sense: await sensePasskeys(window), awake: screenAwake(window),
  };
  try {
    const browser = window.navigator?.credentials;
    ctx.credentials = await credentialsFor(config, { browser, soft: config.softPasskey ? { secret: randomBytes(32), origin: location.origin } : null });
  } catch {
    ctx.credentials = null;
  }
  P.relay = await ctx.relay.status();
  P.statusAt = Date.now();

  for (;;) {
    try {
      ctx.instance = await ctx.views.instance();
      ctx.skew.add(await reader.blockTime());
      P.skewAt = Date.now();
      break;
    } catch (err) {
      setState('read_down');
      show(h('p', { class: 'say' }, 'Can\'t read the NEAR contract right now.'), h('p', { class: 'words' }, err.verbatim ?? err.message));
      await new Promise((r) => { setTimeout(r, 3000); });
    }
  }

  P.fragment = parsePhoneFragment(location.hash);
  window.addEventListener('hashchange', () => location.reload());
  if (P.fragment.h7) {
    runH7(ctx, P.fragment, P.relay);
    return;
  }
  if (P.fragment.refused.includes('v')) {
    setState('wrong_vault');
    show(h('p', { class: 'say' }, 'This link\'s vault id can\'t be read.'), h('p', { class: 'line dim' }, 'Check the link. Nothing here can act on it.'));
    return;
  }
  if (!P.fragment.v) {
    drawNoVault();
    return;
  }
  watchVault(P.fragment.v);
}

function watchVault(v) {
  P.v = v;
  P.r = P.fragment.r ?? null;
  P.frozenText = P.fragment.f ?? null;
  const known = P.fragment.c ?? recallCredential(v);
  if (known) {
    P.credential = fromBase64Url(known);
    rememberCredential(v, known);
    if (!P.fragment.c) saveFragment({ c: known });
  }
  document.addEventListener('visibilitychange', () => { if (!document.hidden) pollSoon(0); });
  window.addEventListener('pageshow', (event) => { if (event.persisted) pollSoon(0); });
  document.addEventListener('pointerdown', () => { P.touch = performance.now(); }, { capture: true, passive: true });
  requestAnimationFrame(frame);
  tick();
}

function saveFragment(fields) {
  Object.assign(P.fragment, fields);
  writeFragment(P.fragment);
}

function credentialB64() {
  return P.credential ? credentialToFragment(P.credential) : null;
}

// ---------------------------------------------------------------- reads

function pollSoon(ms) {
  if (P.stopped) return;
  clearTimeout(P.timer);
  P.timer = setTimeout(tick, ms);
}

/** The highest request that is still alive, since `pending` keeps dead ones until the next state change. */
async function pickRequest(vault) {
  const ids = [...vault.pending].sort((a, b) => b - a);
  let newest = null;
  for (const id of ids) {
    const request = await ctx.views.request(P.v, id);
    if (!request) continue;
    newest ??= request;
    const s = requestState({ request, vault, chainNow: chainNowOf(ctx.skew) ?? 0 });
    if (s.cancellable || s.kind === 'signing') return request;
  }
  return newest;
}

async function tick() {
  P.timer = null;
  try {
    const skewing = Date.now() - P.skewAt >= SKEW_MS
      ? ctx.reader.blockTime().then((sample) => {
        ctx.skew.add(sample);
        P.skewAt = Date.now();
      })
      : null;
    let vault;
    let request = null;
    if (P.r !== null) {
      ({ vault, request } = await ctx.views.both(P.v, P.r));
      // A newer request than the one on screen is what this phone is for.
      const newest = vault ? Math.max(-1, ...vault.pending) : -1;
      if (newest > P.r) {
        const next = await ctx.views.request(P.v, newest);
        if (next && requestState({ request: next, vault, chainNow: chainNowOf(ctx.skew) ?? 0 }).cancellable) startRequest(next);
        request = next ?? request;
      }
    } else {
      vault = await ctx.views.vault(P.v);
      if (vault) {
        request = await pickRequest(vault);
        if (request) startRequest(request);
      }
    }
    await skewing;
    // A lagging node also answers null for a vault it has not heard of. Null only means no vault until one is seen.
    if (vault) P.vault = vault;
    P.vaultRead = true;
    P.request = request;
    P.readFails = 0;
    P.readWords = null;
  } catch (err) {
    if (err instanceof StaleRead || err instanceof RpcDown) P.readFails += 1;
    else {
      P.readFails += 1;
      P.readWords = err.verbatim ?? err.message;
    }
  }
  if (Date.now() - P.statusAt >= (P.relay.reachable && P.relay.owner.up ? STATUS_MS : STATUS_DOWN_MS)) {
    P.statusAt = Date.now();
    ctx.relay.status().then((status) => {
      P.relay = status;
      judge();
    });
  }
  judge();
  if (P.rs?.kind === 'cancelled' && !P.coinStill) checkCoin();
  if (P.vault && !P.rs) readBalance();
  pollSoon(P.tap?.phase === 'sending' ? FAST_POLL_MS : POLL_MS);
}

function startRequest(request) {
  if (P.r === request.id && P.lastKnown) return;
  const fresh = P.r !== request.id;
  P.r = request.id;
  if (fresh) {
    P.face?.dispose();
    P.face = null;
    P.lastKnown = null;
    P.rs = null;
    P.prep = null;
    P.frozenText = null;
    P.tooLateTxid = null;
    P.coinStill = false;
    P.stampLive = false;
    P.notice = null;
    saveFragment({ tx: null, f: null });
  }
  saveFragment({ r: request.id });
}

// ---------------------------------------------------------------- what the reads mean

function chainNow() {
  return chainNowOf(ctx.skew) ?? 0;
}

function passkeyState() {
  const problem = passkeyProblem(ctx.sense, P.blocked) ?? (ctx.credentials ? null : 'no_webauthn');
  return { problem, canAssert: problem === null, rpMatches: !P.rpBad && rpOk() };
}

function rpOk() {
  if (!P.vault) return true;
  const host = location.hostname;
  const { rpId } = ctx.config;
  const hostFits = host === rpId || host.endsWith(`.${rpId}`);
  return hostFits && toHex(rpIdHashOf(rpId)) === P.vault.rp_id_hash;
}

function judge() {
  if (P.vaultRead && !P.vault) {
    render('wrong_vault');
    return;
  }
  if (!P.vault) {
    if (P.readFails >= READ_FAILS_TO_SAY) render('read_down');
    return;
  }
  const { vault } = P;
  if (!vault.active) {
    render('inactive');
    return;
  }
  if (P.r !== null) {
    let lastKnown = P.lastKnown;
    P.nullReads = P.request ? 0 : (P.nullReads ?? 0) + 1;
    if (P.request) {
      P.lastKnown = P.request;
      lastKnown = P.request;
    } else if (!lastKnown && P.fragment.tx) {
      // This page sent the cancel and kept its hash, then the row was swept: a sighting, carried across a reload.
      lastKnown = { status: 'Pending', epoch: vault.spend_epoch - 1, expires_at: 0, inputs: [] };
    }
    const raw = requestState({ request: P.request, vault, chainNow: chainNow(), lastKnown });
    const unsure = !P.request && P.nullReads < NULL_READS_TO_BELIEVE;
    if (raw.kind !== 'unseen' && !unsure) {
      const before = P.rs;
      P.rs = advanceState(before, raw);
      if (P.rs.kind === 'cancelled' && before?.kind !== 'cancelled') onCancelled(Boolean(before && before.kind !== 'cancelled'));
    }
  }
  const s = P.rs;
  if (P.r === null || !s) {
    render('idle');
    return;
  }
  switch (s.kind) {
    case 'waiting':
    case 'unlocked':
      if (P.tap) render(P.tap.phase);
      else {
        P.button = cancelButton({
          state: s, relay: P.relay, passkey: passkeyState(), originAllowed: ctx.instance.origins.includes(location.origin),
          frozen: vault.frozen_until !== null && vault.frozen_until > chainNow(),
        });
        if (P.button.show) ensurePrep();
        render(P.button.show ? 'request' : 'no_button');
      }
      break;
    case 'cancelled':
      P.tap = null;
      render('cancelled');
      break;
    case 'signing':
    case 'signed':
      P.tap = null;
      if (s.kind === 'signed' && !P.tooLateTxid) readFinalTx();
      render('too_late');
      break;
    case 'expired':
      P.tap = null;
      render('expired');
      break;
    default:
      render('idle');
  }
}

function onCancelled(live) {
  if (window.undoTimings && window.undoTimings.readCancelled === null) window.undoTimings.readCancelled = performance.now();
  const reading = P.face?.text ?? null;
  if (reading && !P.frozenText) P.frozenText = reading;
  P.stampLive = live;
  if (P.frozenText) saveFragment({ f: P.frozenText });
}

/** The new K_s and the digest, ready before the tap, so a tap goes straight to the sheet. The seed is dropped here. */
function ensurePrep() {
  const now = chainNow();
  const nonce = P.vault.passkey_nonce;
  if (P.prep && P.prep.nonce === nonce && P.prep.expiresAt - now > INTENT_MS / 2) return P.prep;
  const newKs = spendKeys(randomBytes(32)).ks.pub;
  const expiresAt = Math.floor(now) + INTENT_MS;
  P.prep = { newKs, nonce, expiresAt, digest: rotateDigest({ contract: ctx.config.contract, vaultHex: P.v, newKs, nonce, expiresAt }) };
  return P.prep;
}

async function readFinalTx() {
  if (P.finalReading) return;
  P.finalReading = true;
  try {
    const hex = await ctx.views.finalTx(P.v, P.r);
    if (hex) {
      P.tooLateTxid = txidOf(parseTx(fromHex(hex)));
      render('too_late', true);
    }
  } catch {
    // Read again next tick.
  } finally {
    P.finalReading = false;
  }
}

/** `The coin never moved` needs both answers: an Esplora that knows the coin, and says its output is unspent. */
async function checkCoin() {
  const inputs = P.lastKnown?.inputs;
  if (!inputs?.length || Date.now() - P.coinCheckedAt < COIN_MS) return;
  P.coinCheckedAt = Date.now();
  try {
    for (const coin of inputs) {
      const [tx, out] = await Promise.all([ctx.esplora.tx(coin.txid), ctx.esplora.outspend(coin.txid, coin.vout)]);
      if (!tx || !out || out.spent !== false) return;
    }
    P.coinStill = true;
    render('cancelled', true);
  } catch {
    // Mutinynet did not answer. The line stays off until it does.
  }
}

async function readBalance() {
  if (P.balanceReading || Date.now() - (P.balanceAt ?? 0) < COIN_MS) return;
  P.balanceReading = true;
  P.balanceAt = Date.now();
  try {
    const list = await ctx.esplora.utxos(P.vault.address);
    P.balance = list.reduce((sum, c) => sum + c.value, 0);
    P.balanceWords = null;
  } catch (err) {
    P.balanceWords = err.message;
  } finally {
    P.balanceReading = false;
    render('idle', true);
  }
}

// ---------------------------------------------------------------- the tap

function onCancelTap() {
  if (P.tap || !P.vault) return;
  const prep = ensurePrep();
  P.notice = null;
  P.hang = false;
  P.tap = { phase: 'tapped', sentAt: null };
  window.undoTimings = { tap: performance.now(), touch: P.touch, assertion: null, sent: null, included: null, readCancelled: null, sForm: null, sheet: null };
  // Straight to the browser: no await may come before this, or iOS Safari drops the gesture.
  const asking = askAssertion(ctx, { digest: prep.digest, credentialId: P.credential, onHang: () => { P.hang = true; render(P.tap?.phase ?? P.screen, true); } });
  render('tapped');
  finishTap(asking, prep);
}

async function finishTap(asking, prep) {
  const timings = window.undoTimings;
  let assertion;
  try {
    const got = await asking;
    assertion = got.assertion;
    timings.assertion = performance.now();
    P.hang = false;
    timings.sForm = assertion.highS ? 'high' : 'low';
    timings.sheet = got.evidence;
    document.documentElement.dataset.sForm = timings.sForm;
    console.log(`undo: S form of this tap: ${timings.sForm}`);
    P.sheetNote = got.evidence.seen && got.evidence.stallMs >= 1000 ? `The sheet covered this page for ${(got.evidence.stallMs / 1000).toFixed(1)} s. The contract's clock kept running.` : null;
  } catch (err) {
    onTapFailed(err);
    return;
  }
  if (assertion.credentialId?.length && !P.credential) {
    P.credential = assertion.credentialId;
    rememberCredential(P.v, credentialB64());
    saveFragment({ c: credentialB64() });
  }
  if (P.rs?.terminal) {
    P.tap = null;
    judge();
    return;
  }
  const refusal = refusalOf({
    assertion: assertion.args, digest: prep.digest, pubkey: fromHex(P.vault.passkey), rpIdHash: fromHex(P.vault.rp_id_hash), origins: ctx.instance.origins,
  });
  if (refusal) {
    P.tap = null;
    P.notice = { warn: true, say: 'Not cancelled.', words: refusal };
    judge();
    return;
  }
  P.tap.phase = 'sending';
  P.tap.sentAt = Date.now();
  render('sending');
  pollSoon(FAST_POLL_MS);
  timings.sent = performance.now();
  let sent;
  try {
    sent = await ctx.relay.call('cancel_all_and_rotate', rotateArgs({ vaultHex: P.v, newKs: prep.newKs, nonce: prep.nonce, expiresAt: prep.expiresAt, assertion: assertion.args }));
  } catch (err) {
    onRelayRefused(err);
    return;
  }
  timings.included = performance.now();
  saveFragment({ tx: sent.hash });
  if (P.tap) P.tap.hash = sent.hash;
  watchOutcome(sent.hash);
}

function onTapFailed(err) {
  P.tap = null;
  P.hang = false;
  if (err instanceof PasskeyFailed) {
    if (err.kind === 'blocked') P.blocked = true;
    else if (err.kind === 'wrong_site') P.rpBad = true;
    else if (err.kind === 'dismissed') P.notice = { say: 'Not cancelled. The sheet closed.', words: null, line: P.credential ? null : 'If it offered no passkey, this phone doesn\'t hold this vault\'s.' };
    else P.notice = { warn: true, say: 'Not cancelled.', words: err.message };
  } else {
    P.notice = { warn: true, say: 'Not cancelled.', words: err.message };
  }
  P.prep = null;
  judge();
}

function onRelayRefused(err) {
  P.tap = null;
  P.prep = null;
  if (err instanceof RelayRefused) {
    if (err.code === 'relay_down') P.relay = { ...P.relay, reachable: false, owner: { up: false, why: 'relay_down' } };
    else if (err.code === 'daily_ceiling') P.relay = { ...P.relay, owner: { up: false, why: 'daily_ceiling', resets_at: err.resetsAt } };
    else if (err.code === 'rate_limited') P.notice = { warn: true, say: `Not cancelled. Too many tries on this vault. Wait ${err.retryAfterS ?? 10} s and tap again.`, words: null };
    else P.notice = { warn: true, say: 'Not cancelled.', words: err.verbatim ?? `${err.code}: ${err.message}` };
    P.statusAt = 0;
  } else {
    P.notice = { warn: true, say: 'Not cancelled.', words: err.message };
  }
  judge();
}

/** Inclusion says nothing about what the contract did: the contract is read, and a failure here shows why. */
async function watchOutcome(hash) {
  const deadline = Date.now() + OUTCOME_MS;
  while (P.tap && Date.now() < deadline && P.relay.relayAccount) {
    try {
      const outcome = await ctx.reader.txOutcome(hash, P.relay.relayAccount);
      if (outcome.known && outcome.failure) {
        P.tap = null;
        P.prep = null;
        saveFragment({ tx: null });
        P.notice = { warn: true, say: 'Not cancelled. The contract refused it.', words: outcome.failure };
        judge();
        return;
      }
      if (outcome.known) break;
    } catch {
      // Not readable yet. Reads of the request go on regardless.
    }
    await new Promise((r) => { setTimeout(r, 500); });
  }
  const giveUp = Math.max(0, SEND_GIVE_UP_MS - (Date.now() - (P.tap?.sentAt ?? Date.now())));
  setTimeout(() => {
    if (P.tap?.hash === hash) {
      P.tap = null;
      P.prep = null;
      P.notice = { warn: true, say: 'The relay sent it, but the contract doesn\'t show it yet.', words: nearTxLabel(ctx.config, hash) };
      judge();
    }
  }, giveUp);
}

// ---------------------------------------------------------------- drawing

function frame() {
  requestAnimationFrame(frame);
  const face = P.face;
  const request = P.lastKnown;
  if (!face || !request || P.screen === 'cancelled' || P.screen === 'too_late' || P.screen === 'expired') return;
  if (P.readFails >= READ_FAILS_TO_SAY) return; // Frozen and dimmed: never free-running past what was read.
  if (!P.rs?.cancellable) return;
  const c = clock(request.unlock, ctx.skew.sample(), Date.now(), request.proposed_at);
  if (!c) return;
  face.set(c.text);
  face.setFuse(c.fuse);
}

const NO_BUTTON_WORDS = {
  relay_down: 'The relay is down, so this page can\'t send a cancel.',
  relay_owner_down: 'The relay is down, so this page can\'t send a cancel.',
  rpc_down: 'The relay can\'t reach NEAR right now, so this page can\'t send a cancel.',
  relay_not_configured: 'The relay is not set up, so this page can\'t send a cancel.',
  daily_ceiling: 'The relay hit today\'s limit.',
  no_passkey_here: 'This phone doesn\'t hold this vault\'s passkey.',
  origin_not_allowed: 'This page isn\'t allowed to cancel for this vault.',
  wrong_site_for_passkey: 'This page isn\'t allowed to cancel for this vault.',
  frozen: 'The cold key has frozen this vault.',
};

function noButtonWords() {
  const { why } = P.button;
  const problem = passkeyState().problem;
  if (why === 'no_passkey_here' && problem) return problemWords(problem) ?? NO_BUTTON_WORDS.no_passkey_here;
  return NO_BUTTON_WORDS[why] ?? `This page can't send a cancel right now: ${why}.`;
}

function resetLine() {
  const at = P.relay.owner?.resets_at;
  return P.button.why === 'daily_ceiling' && at ? `It resets at ${new Date(at).toISOString().slice(11, 16)} UTC.` : null;
}

function destination(request, vault) {
  if (request.to === vault.script_pubkey) return 'this vault\'s own address';
  return spkToAddress(ctx.instance.network, request.to) ?? `script ${request.to}`;
}

function faceFor(text, { stopped = false } = {}) {
  if (!P.face) P.face = new ClockFace();
  if (text) P.face.set(text);
  if (stopped) P.face.stop();
  return P.face;
}

function askedBlock(request) {
  const total = sumInputs(request);
  return [
    h('div', { class: 'label' }, 'to'),
    h('div', { class: 'addr', id: 'to' }, destination(request, P.vault)),
    h('div', { class: 'sats', id: 'amount' }, satsText(total)),
    total - request.amount > 0 ? h('p', { class: 'small fee' }, `${satsText(total - request.amount)} of it is the Bitcoin fee.`) : null,
  ];
}

/** Notices sit under the clock, and only ever hold a true thing the screen would otherwise hide. */
function noticeNodes() {
  const out = [];
  if (P.readFails >= READ_FAILS_TO_SAY) {
    out.push(h('p', { class: 'notice warn', id: 'read-down' }, 'Can\'t read the NEAR contract right now.'));
    if (P.readWords) out.push(h('p', { class: 'words' }, P.readWords));
  }
  if (P.notice) {
    out.push(h('p', { class: `notice${P.notice.warn ? ' warn' : ''}`, id: 'notice' }, P.notice.say));
    if (P.notice.line) out.push(h('p', { class: 'small' }, P.notice.line));
    if (P.notice.words) out.push(h('p', { class: 'words', id: 'verbatim' }, P.notice.words));
  }
  if (P.hang) out.push(h('p', { class: 'notice warn', id: 'hang' }, 'No passkey sheet yet? This browser may be blocking passkeys. Open this page in Safari or Chrome.'));
  if (P.sheetNote) out.push(h('p', { class: 'small', id: 'sheet-note' }, P.sheetNote));
  if (P.lastKnown?.hold_active) out.push(h('p', { class: 'notice', id: 'hold' }, `Held: ${P.lastKnown.assess_reason}`));
  if (P.vault && (P.vault.backup_eligible || P.vault.backup_state)) out.push(h('p', { class: 'small', id: 'synced' }, 'This passkey can sync, so your other devices can use it too.'));
  const elsewhere = openElsewhere(ctx.sense);
  if (elsewhere) out.push(h('p', { class: 'small', id: 'in-app' }, elsewhere));
  if (ctx.config.softPasskey) out.push(h('p', { class: 'small' }, ctx.config.softPasskeyLabel ?? 'Signed by a test key in this browser.'));
  return out;
}

function clockBlock(s) {
  const face = faceFor(null);
  if (s?.kind === 'unlocked') {
    face.set('0:00.0');
    face.setFuse(0);
  }
  face.dim(P.readFails >= READ_FAILS_TO_SAY);
  return [face.wrap, face.fuse];
}

function afterAttach() {
  P.face?.fit();
}

const drawers = {
  request() {
    const s = P.rs;
    const under = s.kind === 'unlocked' ? h('p', { class: 'notice', id: 'at-zero' }, 'Anyone can send it now. Cancel works until they do.') : null;
    return [
      askedBlock(P.lastKnown), h('div', { class: 'grow' }), clockBlock(s), under, noticeNodes(), h('div', { class: 'grow' }),
      h('button', { id: 'cancel', type: 'button', onclick: onCancelTap }, 'Cancel'),
    ];
  },
  no_button() {
    const words = noButtonWords();
    const showTool = P.button.why !== 'not_cancellable';
    const retry = P.blocked ? h('button', { class: 'go quiet', type: 'button', id: 'retry-passkey', onclick: () => { P.blocked = false; judge(); } }, 'Try the passkey again') : null;
    return [
      askedBlock(P.lastKnown), clockBlock(P.rs), noticeNodes(), h('div', { class: 'grow' }),
      h('p', { class: 'say', id: 'why', 'data-why': P.button.why }, words),
      resetLine() ? h('p', { class: 'line' }, resetLine()) : null,
      showTool ? h('p', { class: 'small', id: 'tool' }, 'If you hold this vault\'s recovery file, any NEAR testnet account can send the cancel: tools/freeze.mjs --method cancel') : null,
      retry,
    ];
  },
  tapped() {
    return [askedBlock(P.lastKnown), h('div', { class: 'grow' }), clockBlock(P.rs), noticeNodes(), h('div', { class: 'grow' }), h('div', { class: 'slot', id: 'waiting' }, 'Waiting for your passkey')];
  },
  sending() {
    return [askedBlock(P.lastKnown), h('div', { class: 'grow' }), clockBlock(P.rs), noticeNodes(), h('div', { class: 'grow' }), h('div', { class: 'slot', id: 'sending' }, 'Sending')];
  },
  cancelled() {
    const out = [];
    if (P.frozenText) {
      const face = faceFor(P.frozenText, { stopped: true });
      face.dim(false);
      out.push(face.wrap);
    }
    out.push(h('div', { class: `stamp${P.stampLive ? ' slam' : ''}`, id: 'stamp' }, 'CANCELLED'));
    P.stampLive = false;
    if (P.fragment.tx) out.push(hashBlock(nearTxLabel(ctx.config, P.fragment.tx), P.fragment.tx, nearTxLink(ctx.config, P.fragment.tx)));
    if (P.rs.reason === 'rotated') out.push(h('p', { class: 'say', id: 'key-line' }, 'That key can\'t ask again.'));
    else if (P.rs.reason === 'frozen') out.push(h('p', { class: 'say' }, 'The cold key froze this vault.'));
    if (P.coinStill) {
      out.push(h('p', { class: 'say', id: 'coin-line' }, 'The coin never moved.'));
      out.push(hashBlock(btcAddressLabel(ctx.config, P.vault.address), P.vault.address, btcAddressLink(ctx.config, P.vault.address)));
    }
    return out;
  },
  too_late() {
    const out = [h('p', { class: 'say big', id: 'too-late' }, 'Too late. The contract signed.')];
    if (P.tooLateTxid) out.push(hashBlock(btcTxLabel(ctx.config, P.tooLateTxid), P.tooLateTxid, btcTxLink(ctx.config, P.tooLateTxid)));
    else if (P.lastKnown) out.push(h('p', { class: 'line dim' }, P.rs.kind === 'signing' ? 'Waiting for the signature.' : 'Reading the transaction.'));
    return out;
  },
  expired() {
    return [h('p', { class: 'say big', id: 'expired' }, 'This request expired.'), h('p', { class: 'line dim' }, 'Nobody signed it, and nobody can now. Its coin stays where it was.')];
  },
  wrong_vault() {
    return [h('p', { class: 'say big' }, 'No vault with this id on this contract.'), h('p', { class: 'words' }, `${ctx.config.labels.near} contract ${ctx.config.contract}`)];
  },
  inactive() {
    return [h('p', { class: 'say big' }, 'This vault is not active yet.'), h('p', { class: 'line dim' }, 'The contract is still checking its second key.')];
  },
  read_down() {
    return [h('p', { class: 'say big' }, 'Can\'t read the NEAR contract right now.'), P.readWords ? h('p', { class: 'words' }, P.readWords) : null];
  },
  idle() {
    const { vault } = P;
    const out = [hashBlock(btcAddressLabel(ctx.config, vault.address), vault.address, btcAddressLink(ctx.config, vault.address))];
    if (P.balance !== null) out.push(h('div', { class: 'sats', id: 'balance' }, P.balance > 0 ? satsText(P.balance) : 'No coins yet'));
    else if (P.balanceWords) out.push(h('p', { class: 'line dim', id: 'balance-down' }, 'Can\'t read Mutinynet right now.'));
    out.push(h('p', { class: 'say big', id: 'nothing' }, 'Nothing is waiting.'));
    out.push(noticeNodes(), h('div', { class: 'grow' }));
    if (P.fundedTxid) out.push(hashBlock(btcTxLabel(ctx.config, P.fundedTxid), P.fundedTxid, btcTxLink(ctx.config, P.fundedTxid)));
    if (P.relay.funds?.up && !P.fundedTxid && P.balance === 0) out.push(h('button', { class: 'go', type: 'button', id: 'fund', onclick: onFund }, 'Get test coins'));
    if (P.seed) {
      out.push(h('button', { class: 'go quiet', type: 'button', id: 'thief-link', onclick: copyThiefLink }, 'Copy the thief link'));
      out.push(h('button', { class: 'go quiet', type: 'button', id: 'recovery', onclick: downloadRecovery }, 'Recovery file'));
    }
    return out;
  },
};

function render(id, force = false) {
  const key = `${id}|${JSON.stringify(P.notice)}|${P.hang}|${P.sheetNote}|${P.readFails >= READ_FAILS_TO_SAY}|${P.readWords}|${P.button?.why}|${P.lastKnown?.hold_active}|${P.lastKnown?.assess_reason}|${P.lastKnown?.unlock}|${P.relay?.owner?.why}|${P.blocked}|${P.rs?.kind}`;
  if (!force && key === P.renderKey) return;
  P.renderKey = key;
  P.screen = id;
  setState(id);
  if (P.rs?.clockRuns || P.rs?.cancellable) ctx.awake.start();
  else ctx.awake.stop();
  show(drawers[id]());
  afterAttach();
}

// ---------------------------------------------------------------- no vault, and making one

function drawNoVault(words = null) {
  setState('no_vault');
  const problem = passkeyProblem(ctx.sense) ?? (ctx.credentials ? null : 'no_webauthn');
  const can = !problem && P.relay.general?.up;
  const elsewhere = openElsewhere(ctx.sense);
  show(
    h('p', { class: 'say big' }, 'A cancel button for test Bitcoin.'),
    h('p', { class: 'line' }, 'Open the link from a vault, or make one here.'),
    can ? null : h('p', { class: 'notice warn', id: 'why', 'data-why': problem ?? P.relay.general?.why ?? 'relay_down' }, problem ? problemWords(problem) : generalDownWords()),
    elsewhere ? h('p', { class: 'small', id: 'in-app' }, elsewhere) : null,
    words ? h('p', { class: 'words', id: 'verbatim' }, words) : null,
    h('div', { class: 'grow' }),
    can ? h('button', { class: 'go', type: 'button', id: 'make', onclick: onMakeVault }, 'Make a test vault') : null,
    h('p', { class: 'foot' }, 'Test coins only. The address starts with tb1. This page holds your spend key, so a changed page could take it. The operator can upgrade this test contract after 1 hour. The signing network can refuse, not take.'),
  );
}

function generalDownWords() {
  const why = P.relay.general?.why;
  if (why === 'daily_ceiling') return 'The relay hit today\'s limit, so this page can\'t make a vault right now.';
  return 'The relay is down, so this page can\'t make a vault right now.';
}

function creating(lines, button = null, words = null) {
  setState('creating');
  show(
    h('p', { class: 'say big' }, 'Making your test vault'),
    lines.map((text) => h('p', { class: 'line' }, text)),
    words ? h('p', { class: 'words', id: 'verbatim' }, words) : null,
    P.hangMaking ? h('p', { class: 'notice warn', id: 'hang' }, 'No passkey sheet yet? This browser may be blocking passkeys. Open this page in Safari or Chrome.') : null,
    h('div', { class: 'grow' }),
    button,
  );
}

function onMakeVault() {
  P.hangMaking = false;
  const asking = askNewPasskey(ctx, { label: 'test vault', onHang: () => { P.hangMaking = true; creating(['Waiting for your passkey']); } });
  creating(['Waiting for your passkey']);
  continueMake(asking);
}

async function continueMake(asking) {
  const lines = [];
  let passkey;
  try {
    ({ passkey } = await asking);
  } catch (err) {
    makeFailed(err);
    return;
  }
  lines.push('Passkey made.');
  if (passkey.flags?.backupEligible) lines.push('It can sync to your other devices.');
  creating(lines);
  let prepared;
  try {
    prepared = await prepareVault(ctx, passkey);
  } catch (err) {
    drawNoVault(err.verbatim ?? err.message);
    return;
  }
  lines.push('Second key read from the signer.');
  creating(lines, h('button', {
    class: 'go',
    type: 'button',
    id: 'confirm',
    onclick: () => {
      P.hangMaking = false;
      const confirming = confirmVault(ctx, prepared, { guard: P.relay.relayAccount, onHang: () => { P.hangMaking = true; creating(lines); } });
      creating(lines);
      finishMake(confirming, prepared, lines);
    },
  }, 'Confirm with your passkey'));
}

async function finishMake(confirming, prepared, lines) {
  try {
    const { args } = await confirming;
    lines.push('Signed.');
    creating(lines);
    const made = await sendVault(ctx, prepared, args, {
      powBits: P.relay.powBits,
      onLine: (step, hash) => {
        if (step === 'work') lines.push('Proof of work done.');
        if (step === 'sent') lines.push(nearTxLabel(ctx.config, hash));
        creating(lines);
      },
    });
    P.seed = prepared.keys.seed;
    P.cold = prepared.keys.cold;
    P.credential = prepared.passkey.credentialId;
    rememberCredential(made.vault.id, credentialB64());
    P.fragment = { refused: [], v: made.vault.id, c: credentialB64() };
    writeFragment(P.fragment);
    watchVault(made.vault.id);
  } catch (err) {
    makeFailed(err);
  }
}

function makeFailed(err) {
  if (err instanceof PasskeyFailed && err.kind === 'blocked') {
    P.blocked = true;
    ctx.sense = { ...ctx.sense };
    setState('no_vault');
    show(
      h('p', { class: 'say', id: 'why', 'data-why': 'webauthn_blocked' }, problemWords('webauthn_blocked')),
      h('p', { class: 'words', id: 'verbatim' }, err.message),
      h('div', { class: 'grow' }),
      h('button', { class: 'go quiet', type: 'button', id: 'retry-passkey', onclick: onMakeVault }, 'Try the passkey again'),
    );
    return;
  }
  if (err instanceof PasskeyFailed && err.kind === 'dismissed') {
    drawNoVault('The sheet closed. Nothing was made.');
    return;
  }
  drawNoVault(err.verbatim ? err.verbatim : `${err.code ?? err.name}: ${err.message}`);
}

async function onFund() {
  try {
    const paid = await ctx.relay.fund(P.v);
    P.fundedTxid = paid.txid;
    P.balanceAt = 0;
    render('idle', true);
  } catch (err) {
    P.notice = { warn: true, say: 'No coins sent.', words: err.verbatim ?? `${err.code}: ${err.message}` };
    render('idle', true);
  }
}

async function copyThiefLink() {
  const link = `${location.origin}/t/#v=${P.v}&k=${toHex(P.seed)}`;
  try {
    await navigator.clipboard.writeText(link);
    P.notice = { say: 'Copied. This link holds this vault\'s spend key.', words: null };
  } catch {
    P.notice = { say: 'Copy this link. It holds this vault\'s spend key.', words: link };
  }
  render('idle', true);
}

async function downloadRecovery() {
  const script = fromHex(await ctx.views.script(P.v));
  const text = buildRecovery({ network: ctx.instance.network, vaultId: P.v, script, cold: P.cold });
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  const link = h('a', { href: url, download: `undo-recovery-${P.v.slice(0, 8)}.json` });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

main().catch((err) => {
  setState('crashed');
  show(h('p', { class: 'say' }, 'This page hit an error it did not expect.'), h('p', { class: 'words' }, `${err.name}: ${err.message}`));
});
