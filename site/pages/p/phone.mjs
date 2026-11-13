// The phone page. Everything it says about a request comes from the contract, read here over public RPC. Nothing
// connects it to the thief tab but the contract, which is the claim the film's shot makes.
//
// data-state on <html> and data-clock on the digits are what tests and the recorder wait on.
import {
  bitcoinReader, configWords, btcAddressLabel, btcAddressLink, btcTxLabel, btcTxLink, cancelButton, chooseOnScreen, clock, coinCheck, contractViews, contractWords,
  credentialToFragment, advanceState, credentialsFor, fromBase64Url, fundsPowTarget, loadConfig, logRaw, NearReader, nearTxLabel, nearTxLink, passkeyErrorWords,
  newVaultKeys, PAGE_READS, passkeyWords, refusalOf, RELAY_METHODS, RelayClient, RelayRefused, relayClause, relaySentNothing, relayWords, requestState, resetWords, rotateArgs, rotateDigest, RpcDown,
  rpIdHashOf, SkewTracker, solvePow, spendKeys, spkToAddress, StaleRead, triedWords, unreadRelayWords, upgradeWords, ViewRefused, waitWords,
} from '/site/lib/index.mjs';
import { addressPrefix, parseTx, txid as txidOf } from '/tools/lib/btc.mjs';
import { fromHex, toHex } from '/tools/lib/bytes.mjs';
import { randomBytes } from '/tools/lib/crypto.mjs';
import { buildRecovery } from '/tools/lib/recovery.mjs';
import { runH7 } from './h7.mjs';
import { runOperatorCheck } from './operator-check.mjs';
import { ClockFace, h, hashBlock, satsText, screen, setState, show, sumInputs } from './kit.mjs';
import { OWN_PATH_PARTS, ownCancelFile, ownCancelFileName, ownCancelParts, RECOVERY_PATH_PARTS, relayIsWhy, relayRefusedIt } from './own-cancel.mjs';
import { askAssertion, askNewPasskey, PasskeyFailed } from './passkey-ask.mjs';
import { parsePhoneFragment, recallCredential, recallSeen, rememberCredential, rememberSeen, thiefLink, writeFragment } from './phone-fragment.mjs';
import { hangWords, openElsewhere, passkeyProblem, platformHint, problemWords, screenAwake, sensePasskeys } from './sense.mjs';
import { chainNowOf, confirmVault, prepareVault, sendVault, waitActive } from './vault-make.mjs';

const POLL_MS = 1000;
const FAST_POLL_MS = 400;
const SKEW_MS = 5000;
const STATUS_MS = 30_000;
// While a clock runs, a Cancel that can no longer work must not stay up for long.
const STATUS_DOWN_MS = 5000;
// A block time this far behind this machine's clock is a stuck node, or a wrong clock. Either way, say so.
const STALE_NODE_MS = 60_000;
const OUTCOME_MS = 8000;
const SEND_GIVE_UP_MS = 30_000;
const COIN_MS = 15_000;
const FINAL_MS = 3000;
const INTENT_MS = 10 * 60_000;
const READ_FAILS_TO_SAY = 3;
// A vault read sent with the boot reads stands in for the first tick's only while it is about as fresh as a tick's own.
const EARLY_READ_MS = 3000;
// A node a few blocks behind answers null for a request it has not reached, and that is within what a reader lets
// through. So a seen request reads as gone only when it stays gone. A stamp cannot be taken back.
const NULL_READS_TO_BELIEVE = 3;
// How long the first screen waits for the contract account's key list. Without it the footer says the cautious sentence.
const CODE_KEYS_MS = 2500;
// Under the Recovery file button's own words. The README's row for the owner's phone says why at length.
const RECOVERY_WHY = 'Save it before your first Cancel';
// With no vault and a relay that is down or out of reach, its status is read again after these waits, the last one
// repeating, and only while the page is on screen. The status is a Pages Function with a daily allowance of requests,
// so a tab left open must not ask every few seconds for as long as an outage lasts.
const RELAY_AGAIN_MS = [5000, 10_000, 20_000, 60_000];
// Coming back to the page, a restored page and a connection coming back each ask at once, but not more often than this.
const RELAY_AGAIN_GAP_MS = 2000;
// How long the idle screen of the page that holds the spend key keeps the screen on after it came up or was last
// touched. Long enough to send a theft from a laptop; a phone left on that screen then sleeps (keepAwake).
const IDLE_AWAKE_MS = 10 * 60_000;
// Before each of the two sheets: what the device is about to ask, and why.
const BEFORE_MAKE = (rpId) => `Next, this device asks to save a passkey named "test vault" for ${rpId}: this vault's cancel key. You can delete it afterwards.`;
const BEFORE_CONFIRM = 'One more sheet: your passkey signs this vault\'s creation, and the contract checks it.';

const P = {
  screen: null, v: null, r: null, fragment: {}, vault: null, vaultRead: false, lastKnown: null, rs: null, items: new Map(), hintR: null,
  moreWaiting: 0, alreadySigned: 0, relay: null, readFails: 0, notice: null, tap: null, prep: null,
  credential: null, credentialTrusted: false, blocked: false, rpBad: false, frozenText: null, stampLive: false, coinStill: false, coinCheckedAt: 0,
  coinFacts: new Map(), coinFactsAt: 0, coinsDown: false, tooLateTxid: null, tooLateUnsent: false, finalAt: 0, face: null, skewAt: 0, statusAt: 0, timer: null, touch: null, seed: null, cold: null,
  balance: null, fundedTxid: null, stopped: false, sheetNote: null, hang: false, tx: null, txSent: null, ksSeen: null, frozenBy: {}, pin: null,
  // A cancel this page signed and the relay did not send, for tools/cancel.mjs. And whether this relay refused this vault.
  signed: null, notOurs: false,
  // The contract account's access keys, as public RPC listed them for the footer. Null: not read, or no node answered.
  codeKeys: null,
  // The first tick's vault and request reads, sent with the boot reads.
  early: null,
  // The screen with no vault, while it is the one on screen: { words }. Null once a vault is being made or watched.
  noVault: null,
  // The passkey call a vault in the making is waiting on: { abort }. A later tap replaces it, and its answer is then dropped.
  making: null,
  // The button a sheet that has not shown puts back, by its name, or null. And the same for the two making taps.
  hangMaking: null,
  // The relay's status read again while there is no vault: how many times, the timer for the next, and one in flight.
  relayReads: 0, relayTimer: null, relayReading: false,
  // A passkey call has answered on this page, so what the browser reported of its passkeys beforehand no longer matters.
  passkeyOk: false,
  // Whether the screen wake lock is wanted, and until when the idle screen wants it (keepAwake).
  awake: null, idleAwakeUntil: 0,
};
let ctx;

// ---------------------------------------------------------------- boot

/** One sentence for anything that went wrong, never its raw words: those go to the console, with `logRaw`. */
function failureWords(err) {
  if (err instanceof RelayRefused) return relayWords(err);
  if (err instanceof ViewRefused) return contractWords(err.verbatim);
  if (err instanceof RpcDown || err instanceof StaleRead) return 'Can\'t read the NEAR contract right now.';
  if (err instanceof PasskeyFailed) return passkeyErrorWords(err.kind);
  return 'This page hit an error it did not expect.';
}

/** The raw words of an error, for the console only. */
const rawWords = (err) => [err?.code, err?.verbatim ?? (err?.name && err?.message ? `${err.name}: ${err.message}` : err?.message) ?? String(err), triedWords(err)].filter(Boolean).join(': ');

async function main() {
  fitWordmark();
  window.addEventListener('resize', fitWordmark);
  let config;
  try {
    config = await loadConfig();
  } catch (err) {
    setState('no_config');
    logRaw('the settings', rawWords(err));
    show(h('p', { class: 'say' }, 'This page could not load its settings, so it shows nothing.'), h('p', { class: 'words' }, configWords(err)));
    return;
  }
  document.getElementById('chip').textContent = config.labels.chip;
  fitWordmark();

  const reader = new NearReader({ urls: config.rpc, ...PAGE_READS });
  const views = contractViews(reader, config.contract);
  const relay = new RelayClient({ relay: config.relay, funds: config.funds });
  // Needs no contract and no relay: the contract this config names may already be gone when a deploy asks for it.
  const asked = parsePhoneFragment(location.hash);
  const operatorCheck = Boolean(asked.opproof && asked.opfor);
  // None of these first reads waits on another, so they all go out now, and each is awaited where the page used to
  // send it: the relay's status, the contract's instance and clock, and the vault the link names with its request.
  const status = operatorCheck ? null : relay.status();
  let reads = operatorCheck ? null : contractReads(views, reader);
  // Only the screen with no vault says how an upgrade waits, so only a link with no vault asks for the account's keys.
  const footer = !operatorCheck && !asked.v && !(asked.h7 && config.h7);
  let codeKeys = footer ? started(reader.accessKeys(config.contract)) : null;
  P.early = operatorCheck || (asked.h7 && config.h7) ? null : earlyVaultReads(views, asked);
  ctx = {
    config, reader, views, relay,
    skew: new SkewTracker(), esplora: bitcoinReader(config.esplora), instance: null, credentials: null, sense: await sensePasskeys(window), awake: screenAwake(window),
  };
  try {
    const browser = window.navigator?.credentials;
    ctx.credentials = await credentialsFor(config, { browser, soft: config.softPasskey ? { secret: randomBytes(32), origin: location.origin } : null });
  } catch {
    ctx.credentials = null;
  }
  if (operatorCheck) {
    runOperatorCheck(ctx, { nonce: asked.opproof, instance: asked.opfor });
    return;
  }
  P.relay = await status;
  P.statusAt = Date.now();
  // What a browser says of its passkeys can change while the page is away: a passkey manager turned on in Settings. And
  // a relay that was out of reach when the page loaded is asked again when the page, or the connection, comes back.
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) return;
    senseAgain();
    readRelayAgain();
  });
  window.addEventListener('pageshow', () => readRelayAgain());
  window.addEventListener('online', () => readRelayAgain());

  for (;;) {
    try {
      // In this order, so a failure shows the same words it did when the reads went one after another.
      ctx.instance = await reads.instance;
      ctx.skew.add(await reads.block);
      P.skewAt = Date.now();
      break;
    } catch (err) {
      setState('read_down');
      logRaw('reading the NEAR contract', rawWords(err));
      show(h('p', { class: 'say' }, 'Can\'t read the NEAR contract right now.'));
      await new Promise((r) => { setTimeout(r, 3000); });
      reads = contractReads(views, reader);
      if (footer) codeKeys = started(reader.accessKeys(config.contract));
      P.early = null;
    }
  }

  P.fragment = parsePhoneFragment(location.hash);
  window.addEventListener('hashchange', () => location.reload());
  // A turned phone or a browser bar that comes and goes changes the room, so the control is fitted again.
  let refit = 0;
  window.addEventListener('resize', () => {
    cancelAnimationFrame(refit);
    refit = requestAnimationFrame(() => {
      if (!P.screen) return;
      if (P.screen !== 'cancelled') keepControlOnScreen();
      // The stamp's held frame is for a screen that stays put: a turn or a browser bar settles the digits at once,
      // where a reload at the new size draws them.
      else if (P.pin && !P.pin.settled) settleDigits(P.pin);
    });
  });
  // Test mode is for one phone check, and a final build sets this off, so `#h7=1` is then only an ignored field.
  if (P.fragment.h7 && config.h7) {
    runH7(ctx, P.fragment, P.relay);
    return;
  }
  if (P.fragment.refused.includes('v')) {
    setState('wrong_vault');
    show(h('p', { class: 'say' }, 'This link\'s vault id can\'t be read.'), h('p', { class: 'line dim' }, 'Check the link. Nothing here can act on it.'));
    return;
  }
  if (!P.fragment.v) {
    P.codeKeys = codeKeys ? await answerWithin(codeKeys, CODE_KEYS_MS) : null;
    drawNoVault();
    return;
  }
  watchVault(P.fragment.v);
}

/** A read's answer, or null when it failed or is not here after `ms`. */
function answerWithin(promise, ms) {
  return Promise.race([promise.catch(() => null), new Promise((r) => { setTimeout(() => r(null), ms); })]);
}

/** Asked again whenever the page comes back. The screen is drawn again only if what it would say has changed. */
async function senseAgain() {
  const sense = await sensePasskeys(window);
  const changed = platformHint(sense) !== platformHint(ctx.sense) || passkeyProblem(sense) !== passkeyProblem(ctx.sense);
  ctx.sense = sense;
  if (!changed) return;
  if (P.noVault) drawNoVault(P.noVault.words);
  else if (P.screen) judge();
}

/**
 * The hint for a phone whose browser reports no passkey manager or screen lock, while that report is all the page has
 * to go on. Once a passkey call has answered here, or this browser has used this vault's passkey before, it says nothing.
 */
const hintNow = () => (P.passkeyOk || P.credentialTrusted ? null : platformHint(ctx.sense));

/** A passkey call answered: the sheet came. Whatever an earlier tap or the browser's own report suggested no longer holds. */
function passkeyAnswered() {
  P.passkeyOk = true;
  P.blocked = false;
}

/** Whether the screen with no vault is waiting on the relay: it could not be reached, or it cannot make a vault now. */
const relayHoldsMake = () => Boolean(P.noVault) && (!P.relay.reachable || !P.relay.general?.up);

/** The next read of the relay's status for the screen with no vault: backed off, and never while the page is hidden. */
function relayAgainLater() {
  clearTimeout(P.relayTimer);
  P.relayTimer = null;
  if (!relayHoldsMake()) return;
  let wait = RELAY_AGAIN_MS[Math.min(P.relayReads, RELAY_AGAIN_MS.length - 1)];
  // A daily limit says when it ends, so nothing is asked before then: coming back to the page still asks at once.
  const resets = P.relay.reachable && P.relay.general?.why === 'daily_ceiling' ? P.relay.general.resets_at : null;
  if (Number.isFinite(resets) && resets > Date.now()) wait = Math.max(wait, Math.min(resets - Date.now() + 1000, 0x7fffffff));
  P.relayTimer = setTimeout(() => readRelayAgain(true), wait);
}

/** Reads the relay's status again for the screen with no vault, and draws that screen again with what it says. */
async function readRelayAgain(timed = false) {
  if (!relayHoldsMake() || P.relayReading || document.hidden) return;
  if (!timed && Date.now() - P.statusAt < RELAY_AGAIN_GAP_MS) return;
  clearTimeout(P.relayTimer);
  P.relayTimer = null;
  P.relayReading = true;
  P.statusAt = Date.now();
  const status = await ctx.relay.status();
  P.relayReading = false;
  P.relayReads += 1;
  // A vault may be in the making by now, or the page watching one: this read was for a screen that is gone.
  if (!P.noVault) return;
  P.relay = status;
  drawNoVault(P.noVault.words);
}

/** "Undo for Bitcoin" where it fits beside the chip, as on the landing page; only "Undo" where the chip leaves no room. */
function fitWordmark() {
  const mark = document.querySelector('.top .wordmark');
  const chip = document.getElementById('chip');
  if (!mark || !chip) return;
  mark.classList.remove('short');
  const row = mark.parentElement.getBoundingClientRect();
  const box = mark.getBoundingClientRect();
  if (box.right > row.right + 0.5 || chip.getBoundingClientRect().right + 12 > box.left) mark.classList.add('short');
}

/** A read started now and awaited later. Marked handled here, so one the page never waits for raises no alarm. */
function started(promise) {
  promise.catch(() => {});
  return promise;
}

/** The contract's instance and its clock, both at once. */
function contractReads(views, reader) {
  return { instance: started(views.instance()), block: started(reader.blockTime()) };
}

/** The first tick's reads of the vault a link names and its request, sent with the boot reads. Null without a vault. */
function earlyVaultReads(views, fragment) {
  if (!fragment.v || fragment.refused.includes('v')) return null;
  const reads = new Map([['vault', started(views.vault(fragment.v))]]);
  if (fragment.r !== undefined && fragment.r !== null) reads.set(`request:${fragment.r}`, started(views.request(fragment.v, fragment.r)));
  return { v: fragment.v, reads, at: Date.now() };
}

/** The first tick takes what boot already asked for, once, if it is recent. Every later read is fresh. */
function readOnce(key, read) {
  const early = P.early?.v === P.v && Date.now() - P.early.at <= EARLY_READ_MS ? P.early.reads.get(key) : undefined;
  if (early) {
    P.early.reads.delete(key);
    return early;
  }
  return read();
}

function watchVault(v) {
  P.v = v;
  P.noVault = null;
  P.making = null;
  clearTimeout(P.relayTimer);
  // Only a place to look. A number in a link says nothing about what is waiting.
  P.hintR = P.fragment.r ?? null;
  const saved = recallSeen(v);
  if (saved) {
    for (const [id, request] of Object.entries(saved.seen ?? {})) P.items.set(Number(id), { id: Number(id), request, current: request, nulls: 0, state: null });
    P.tx = saved.tx ?? null;
    P.frozenBy = saved.frozen ?? {};
    P.ksSeen = saved.ks ?? null;
  }
  // A stored id has made an assertion on this phone. One a link names is only a guess until it does.
  const stored = recallCredential(v);
  const known = stored ?? P.fragment.c ?? null;
  if (known) {
    P.credential = fromBase64Url(known);
    P.credentialTrusted = Boolean(stored);
    if (P.fragment.c !== known) saveFragment({ c: known });
  }
  document.addEventListener('visibilitychange', () => { if (!document.hidden) pollSoon(0); });
  window.addEventListener('pageshow', (event) => { if (event.persisted) pollSoon(0); });
  document.addEventListener('pointerdown', () => {
    P.touch = performance.now();
    // A person is looking at the idle screen: it keeps the screen on for its full time again.
    if (P.screen === 'idle') {
      P.idleAwakeUntil = Date.now() + IDLE_AWAKE_MS;
      keepAwake('idle');
    }
  }, { capture: true, passive: true });
  requestAnimationFrame(frame);
  tick();
}

function saveFragment(fields) {
  Object.assign(P.fragment, fields);
  writeFragment(P.fragment);
}

/** What this tab saw and sent, for a reload. A link cannot write this. */
function saveSeen() {
  const seen = {};
  for (const item of P.items.values()) seen[item.id] = item.request;
  rememberSeen(P.v, { seen, tx: P.tx, frozen: P.frozenBy, ks: P.ksSeen });
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

/** What to read this tick: everything the vault lists, whatever is still undecided, and the one on screen. */
function idsToRead() {
  const ids = new Set();
  if (P.hintR !== null) ids.add(P.hintR);
  for (const item of P.items.values()) if (!item.state?.terminal || item.id === P.r) ids.add(item.id);
  return [...ids];
}

function noteRead(id, row) {
  let item = P.items.get(id);
  if (!item) {
    if (!row) return;
    item = { id, request: row, current: row, nulls: 0, state: null };
    P.items.set(id, item);
    saveSeen();
  }
  item.current = row;
  if (row) {
    const moved = item.request.status !== row.status;
    item.request = row;
    item.nulls = 0;
    if (moved) saveSeen();
  } else {
    item.nulls += 1;
  }
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
    const known = idsToRead();
    const reading = Promise.all([readOnce('vault', () => ctx.views.vault(P.v)), ...known.map((id) => readOnce(`request:${id}`, () => ctx.views.request(P.v, id)))]);
    P.early = null;
    const [vault, ...rows] = await reading;
    // A lagging node also answers null for a vault it has not heard of. Null only means no vault until one is seen.
    if (vault) {
      known.forEach((id, i) => noteRead(id, rows[i]));
      P.hintR = null;
      const fresh = vault.pending.filter((id) => !known.includes(id) && !P.items.get(id)?.state?.terminal);
      const freshRows = await Promise.all(fresh.map((id) => ctx.views.request(P.v, id)));
      fresh.forEach((id, i) => noteRead(id, freshRows[i]));
      P.vault = vault;
      P.ksSeen ??= vault.k_s;
    }
    await skewing;
    P.vaultRead = true;
    P.readFails = 0;
  } catch (err) {
    P.readFails += 1;
    // The screen says it can't read; what the node or the contract said is for the console.
    if (!(err instanceof StaleRead || err instanceof RpcDown)) logRaw('reading the vault', rawWords(err));
  }
  const statusEvery = !P.relay.reachable || !P.relay.owner.up || P.rs?.cancellable ? STATUS_DOWN_MS : STATUS_MS;
  if (Date.now() - P.statusAt >= statusEvery) {
    P.statusAt = Date.now();
    ctx.relay.status().then((status) => {
      P.relay = status;
      judge();
    });
  }
  judge();
  checkCoins();
  if (P.rs?.kind === 'cancelled' && !P.coinStill) checkCoin();
  if (P.vault && !P.rs) readBalance();
  pollSoon(P.tap?.phase === 'sending' ? FAST_POLL_MS : POLL_MS);
}

function startRequest(id) {
  if (P.r === id) return;
  P.face?.dispose();
  P.face = null;
  P.lastKnown = null;
  P.rs = null;
  P.prep = null;
  P.frozenText = P.frozenBy[id] ?? null;
  P.tooLateTxid = null;
  P.tooLateUnsent = false;
  P.finalAt = 0;
  P.coinStill = false;
  P.stampLive = false;
  P.pin = null;
  // A notice belongs to the request or the screen that set it. A new request starts with none, so nothing said on the
  // idle screen, or about another request, stands over its clock.
  P.notice = null;
  P.r = id;
  saveFragment({ r: id });
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

/** Every request's state, from what was last read of it. A null counts only once it has stayed null. */
function judgeItems(vault) {
  const now = chainNow();
  for (const item of P.items.values()) {
    const raw = requestState({ request: item.current, vault, chainNow: now, lastKnown: item.request });
    if (raw.kind === 'unseen' || raw.kind === 'no_vault') continue;
    if (!item.current && item.nulls < NULL_READS_TO_BELIEVE) continue;
    item.state = advanceState(item.state, raw);
  }
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
  judgeItems(vault);
  const { focus, moreWaiting, alreadySigned } = chooseOnScreen([...P.items.values()], {
    selfSpk: vault.script_pubkey,
    realValue: (request) => coinCheck(request, P.coinFacts).real,
  });
  P.moreWaiting = moreWaiting;
  P.alreadySigned = alreadySigned;
  if (!focus) {
    render('idle');
    return;
  }
  startRequest(focus.id);
  const before = P.rs;
  P.lastKnown = focus.request;
  P.rs = focus.state;
  const s = P.rs;
  if (s.kind === 'cancelled' && before?.kind !== 'cancelled') onCancelled(Boolean(before));
  switch (s.kind) {
    case 'waiting':
    case 'unlocked':
      if (P.tap) render(P.tap.phase);
      else {
        P.button = cancelButton({
          state: s, relay: P.notOurs ? { ...P.relay, owner: { up: false, why: 'not_this_relays' } } : P.relay, passkey: passkeyState(), originAllowed: ctx.instance.origins.includes(location.origin),
          frozen: vault.frozen_until !== null && vault.frozen_until > chainNow(),
        });
        if (P.button.show) ensurePrep();
        render(P.button.show ? 'request' : 'no_button');
      }
      break;
    case 'cancelled':
      endTap();
      render('cancelled');
      break;
    case 'signing':
    case 'signed':
      endTap();
      if (s.kind === 'signed' && !P.tooLateTxid) readFinalTx();
      render('too_late');
      break;
    case 'expired':
      endTap();
      render('expired');
      break;
    default:
      render('idle');
  }
}

/**
 * The request on screen has ended, so its tap ends with it. A passkey call still out is ended too: no sheet can do
 * anything for this request now, and a call that never settles would otherwise stay out for as long as the page is
 * open, ahead of the next request's. Its line goes with it. An abort of a call that has answered does nothing.
 */
function endTap() {
  if (P.tap && !P.tap.answered) P.tap.abort.abort();
  P.tap = null;
  P.hang = false;
}

function onCancelled(live) {
  if (window.undoTimings && window.undoTimings.readCancelled === null) window.undoTimings.readCancelled = performance.now();
  const reading = P.face?.text ?? null;
  if (reading && !P.frozenText) P.frozenText = reading;
  P.stampLive = live;
  // The digits stay exactly where they were when the stamp lands, because this frame is on film. Then they settle
  // where a reload draws them, so the cancelled screen has one layout however it was reached.
  if (live && P.face?.wrap.isConnected) {
    const pin = { top: P.face.wrap.getBoundingClientRect().top };
    P.pin = pin;
    setTimeout(() => settleDigits(pin), STAMP_HOLD_MS);
  }
  if (P.frozenText) {
    P.frozenBy[P.r] = P.frozenText;
    saveSeen();
  }
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

/** A txid only once a node holds that transaction: until someone broadcasts it, it is only the contract's bytes. */
async function readFinalTx() {
  if (P.finalReading || Date.now() - P.finalAt < FINAL_MS) return;
  P.finalReading = true;
  P.finalAt = Date.now();
  try {
    const hex = await ctx.views.finalTx(P.v, P.r);
    if (hex) {
      const txid = txidOf(parseTx(fromHex(hex)));
      const held = (await ctx.esplora.tx(txid).catch(() => null))?.txid === txid;
      P.tooLateTxid = held ? txid : null;
      P.tooLateUnsent = !held;
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

/** A request's coins are only what its proposer declared. This asks a node about each, and the screen says what it hears. */
async function checkCoins() {
  if (P.coinsReading || Date.now() - P.coinFactsAt < 1000) return;
  const coins = [];
  for (const item of P.items.values()) {
    if (!item.state?.cancellable) continue;
    for (const coin of item.request.inputs) {
      const fact = P.coinFacts.get(`${coin.txid}:${coin.vout}`);
      if (!fact?.known && Date.now() - (fact?.at ?? 0) >= COIN_MS) coins.push(coin);
    }
  }
  if (!coins.length) return;
  P.coinsReading = true;
  P.coinFactsAt = Date.now();
  const wasDown = P.coinsDown;
  let changed = false;
  try {
    await Promise.all(coins.map(async (coin) => {
      const key = `${coin.txid}:${coin.vout}`;
      const tx = await ctx.esplora.tx(coin.txid);
      const value = tx?.vout?.[coin.vout]?.value;
      const known = Number.isSafeInteger(value);
      if (P.coinFacts.get(key)?.known !== known) changed = true;
      P.coinFacts.set(key, known ? { known, value } : { known, at: Date.now() });
    }));
    P.coinsDown = false;
  } catch {
    P.coinsDown = true;
  } finally {
    P.coinsReading = false;
  }
  if (changed || wasDown !== P.coinsDown) judge();
}

async function readBalance() {
  if (P.balanceReading || Date.now() - (P.balanceAt ?? 0) < COIN_MS) return;
  P.balanceReading = true;
  P.balanceAt = Date.now();
  try {
    const list = await ctx.esplora.utxos(P.vault.address);
    P.balance = list.reduce((sum, c) => sum + c.value, 0);
    P.balanceWords = null;
    // What a failed ask for a coin said is out of date once a coin is here.
    if (P.balance > 0 && P.notice?.fund) P.notice = null;
  } catch (err) {
    P.balanceWords = err.message;
  } finally {
    P.balanceReading = false;
    drawIdleAgain();
  }
}

// ---------------------------------------------------------------- the tap

/** `own`: sign the cancel for tools/cancel.mjs, and send nothing to the relay. */
function onCancelTap(own = false) {
  if (P.tap || !P.vault) return;
  const prep = ensurePrep();
  P.notice = null;
  P.hang = false;
  const tap = { phase: 'tapped', sentAt: null, own: own === true, abort: new AbortController(), answered: false };
  P.tap = tap;
  window.undoTimings = { tap: performance.now(), touch: P.touch, assertion: null, sent: null, included: null, readCancelled: null, sForm: null, sheet: null };
  // Straight to the browser: no await may come before this, or iOS Safari drops the gesture.
  const asking = askAssertion(ctx, {
    digest: prep.digest,
    credentialId: P.credential,
    signal: tap.abort.signal,
    onHang: () => {
      if (P.tap !== tap) return;
      P.hang = true;
      render(tap.phase, true);
    },
  });
  render('tapped');
  finishTap(asking, prep, tap);
}

/**
 * The button a sheet that never showed puts back. A passkey call can stay out for good (WebKit bug 273712), and the page
 * cannot tell that from a sheet a person is still reading, so nothing ends the call but this tap: it aborts the one that
 * is out and asks again, all inside this handler, because the new call needs this tap's gesture as the first one did.
 */
function onCancelAgain() {
  const old = P.tap;
  if (!old || old.phase !== 'tapped') return;
  P.tap = null;
  old.abort.abort();
  onCancelTap(old.own);
}

async function finishTap(asking, prep, tap) {
  const timings = window.undoTimings;
  let assertion;
  try {
    const got = await asking;
    tap.answered = true;
    // A call this page gave up on, answering late: a newer tap has the screen, and nothing of this one is sent or drawn.
    if (P.tap !== tap) return;
    assertion = got.assertion;
    timings.assertion = performance.now();
    P.hang = false;
    passkeyAnswered();
    timings.sForm = assertion.highS ? 'high' : 'low';
    timings.sheet = got.evidence;
    document.documentElement.dataset.sForm = timings.sForm;
    console.log(`undo: S form of this tap: ${timings.sForm}`);
    P.sheetNote = got.evidence.seen && got.evidence.stallMs >= 1000 ? `This page stopped drawing for ${(got.evidence.stallMs / 1000).toFixed(1)} s while the passkey was asked. The contract's clock kept running.` : null;
  } catch (err) {
    tap.answered = true;
    if (P.tap === tap) onTapFailed(err);
    return;
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
    logRaw('the passkey\'s answer', refusal);
    P.notice = { warn: true, say: `Not cancelled. ${passkeyWords(refusal)}`, words: null };
    judge();
    return;
  }
  // This id has now made an assertion this vault's passkey signed, so it is worth keeping. Nothing before this is.
  if (assertion.credentialId?.length) {
    P.credential = assertion.credentialId;
    P.credentialTrusted = true;
    rememberCredential(P.v, credentialB64());
    saveFragment({ c: credentialB64() });
  }
  const callArgs = rotateArgs({ vaultHex: P.v, newKs: prep.newKs, nonce: prep.nonce, expiresAt: prep.expiresAt, assertion: assertion.args });
  if (tap.own) {
    P.tap = null;
    P.prep = null;
    P.signed = { method: 'cancel_all_and_rotate', args: callArgs, expiresAt: prep.expiresAt };
    P.notice = { say: 'Signed. This page sent it nowhere.', words: null };
    judge();
    return;
  }
  tap.phase = 'sending';
  tap.sentAt = Date.now();
  render('sending');
  pollSoon(FAST_POLL_MS);
  timings.sent = performance.now();
  P.txSent = true; // Holds the hash's slot on the stamp, if the stamp lands before the relay answers.
  let sent;
  try {
    sent = await ctx.relay.call('cancel_all_and_rotate', callArgs);
  } catch (err) {
    onRelayRefused(err, { method: 'cancel_all_and_rotate', args: callArgs, expiresAt: prep.expiresAt });
    return;
  }
  timings.included = performance.now();
  P.txSent = sent.hash;
  if (P.tap === tap) tap.hash = sent.hash;
  watchOutcome(sent.hash);
}

/**
 * A link can name any hash, so a screen never takes one from it, and a failed read of a credential means little: a
 * link can name a junk id too, and a browser refuses that in the same words as a person closing the sheet. So an id
 * that has never made an assertion is dropped after one failed tap, and the next tap offers any passkey here. An id
 * this browser made or has used is kept whatever the refusal: without it the sheet offers every passkey for this site,
 * all named "test vault", to a person with a clock running.
 */
function forgetUntrustedCredential() {
  if (!P.credential || P.credentialTrusted) return false;
  P.credential = null;
  P.credentialTrusted = false;
  saveFragment({ c: null });
  return true;
}

function onTapFailed(err) {
  P.tap = null;
  P.hang = false;
  if (err instanceof PasskeyFailed) {
    const dropped = err.kind === 'blocked' || err.kind === 'dismissed' ? forgetUntrustedCredential() : false;
    // An id only a link named, refused at once: the next tap already offers any passkey here. Only what holds whether
    // there was no sheet, no passkey or a sheet shut at once, and the in-app line makes room as after a later refusal.
    if (dropped && err.kind === 'blocked') P.notice = { say: 'Not cancelled. The passkey did not sign.', words: null, inAppAside: true };
    else if (err.kind === 'blocked') P.blocked = true;
    else if (err.kind === 'wrong_site') P.rpBad = true;
    // A sheet a person closed, one that left no trace, or none at all: a trace (focus lost, a hidden page, a stalled
    // frame) can come from something else, so only what holds in every case, and the hint for a sheet that did not come
    // stays.
    else if (err.kind === 'dismissed') P.notice = { say: 'Not cancelled. The passkey did not sign.', words: null, inAppAside: true };
    else {
      logRaw('the passkey', rawWords(err));
      P.notice = { warn: true, say: `Not cancelled. ${passkeyErrorWords(err.kind)}`, words: null };
    }
  } else {
    logRaw('the tap', rawWords(err));
    P.notice = { warn: true, say: `Not cancelled. ${failureWords(err)}`, words: null };
  }
  P.prep = null;
  judge();
}

/** Refusals the no-button screen puts in its own headline, so the notice above it says only that nothing was cancelled. */
const SAID_BY_THE_SCREEN = new Set(['not_this_relays']);

/** `signed` is the call the relay was given. When the relay, not the cancel, was the problem, the page keeps it. */
function onRelayRefused(err, signed = null) {
  P.tap = null;
  P.prep = null;
  P.txSent = null;
  logRaw('the relay', rawWords(err));
  if (err instanceof RelayRefused) {
    // relay_down is a send with no answer from the relay (no connection, 20 s with nothing, or a page that is not the
    // relay's JSON): the cancel may have gone out all the same, so nothing on the screen may say it did not.
    const unanswered = err.code === 'relay_down';
    // Any code but a refusal before the relay's sender signed (relaySentNothing) can come after it put the cancel out: a
    // resend whose first send landed unseen, then a stale nonce, a node, the state store or the relay's own code that
    // failed. The relay answered, and says nothing of whether the cancel went.
    const erred = !unanswered && !relaySentNothing(err.code);
    if (signed && relayRefusedIt(err.code)) P.signed = { ...signed, unsure: unanswered || erred };
    if (err.code === 'not_this_relays') P.notOurs = true;
    if (unanswered) P.relay = { ...P.relay, reachable: false, cancelUnanswered: Boolean(signed), owner: { up: false, why: 'relay_down' } };
    // Not "Not cancelled": the line under it, for the signed cancel this page keeps, says only "If the relay didn't send".
    else if (erred) P.notice = { warn: true, say: relayWords(err), words: null };
    else if (err.code === 'daily_ceiling') P.relay = { ...P.relay, owner: { up: false, why: 'daily_ceiling', resets_at: err.resetsAt } };
    // The relay's limits on cancels are per vault, and also one allowance for calls it could not check, shared by all.
    else if (err.code === 'rate_limited') P.notice = { warn: true, say: `Not cancelled. Too many tries through the relay. Wait ${waitWords(err.retryAfterS ?? 10)} and tap again.`, words: null };
    // The screen that follows says this one in its own headline, so the relay's sentence would say it twice.
    else if (SAID_BY_THE_SCREEN.has(err.code)) P.notice = { warn: true, say: 'Not cancelled.', words: null };
    else P.notice = { warn: true, say: `Not cancelled. ${relayWords(err)}`, words: null };
    P.statusAt = 0;
  } else {
    P.notice = { warn: true, say: `Not cancelled. ${failureWords(err)}`, words: null };
  }
  judge();
}

/**
 * Inclusion says nothing about what the contract did: the contract is read, and a failure here shows why. A hash goes
 * on the screen only once the chain says this call ran, whichever came first, the stamp or the answer. A node can answer
 * before the receipt has run, so only a settled answer counts.
 */
async function watchOutcome(hash) {
  const deadline = Date.now() + OUTCOME_MS;
  while (Date.now() < deadline && P.relay.relayAccount) {
    let outcome = null;
    try {
      outcome = await ctx.reader.txOutcome(hash, P.relay.relayAccount, { wait: 'EXECUTED_OPTIMISTIC' });
    } catch {
      // Not readable yet. Reads of the request go on regardless.
    }
    if (outcome?.settled && outcome.failure) {
      P.txSent = null;
      if (P.tap?.hash === hash) {
        P.tap = null;
        P.prep = null;
        logRaw('the cancel', outcome.failure);
        P.notice = { warn: true, say: `Not cancelled. ${contractWords(outcome.failure)}`, words: null };
      }
      judge();
      return;
    }
    if (outcome?.settled) {
      P.tx = hash;
      saveSeen();
      if (P.screen === 'cancelled') render('cancelled', true);
      break;
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

// relay_down is worded from what this page saw (relayDownWords). relay_owner_down is a status the relay answered, with
// its cancel side down and no reason given.
const NO_BUTTON_WORDS = {
  relay_owner_down: 'The relay says it can\'t send a cancel right now, so this page can\'t send one.',
  rpc_down: 'The relay can\'t reach NEAR right now, so this page can\'t send a cancel.',
  owner_key_low: 'The relay\'s key can\'t pay for a cancel right now, so this page can\'t send one.',
  owner_key_missing: 'The relay\'s key can\'t pay for a cancel right now, so this page can\'t send one.',
  relay_not_configured: 'The relay is not set up, so this page can\'t send a cancel.',
  daily_ceiling: 'The relay hit today\'s limit.',
  not_this_relays: 'This relay sends cancels only for vaults it made.',
  no_passkey_here: 'This phone doesn\'t hold this vault\'s passkey.',
  origin_not_allowed: 'This page isn\'t allowed to cancel for this vault.',
  wrong_site_for_passkey: 'This page isn\'t allowed to cancel for this vault.',
  frozen: 'The cold key has frozen this vault.',
};

/** The signed call this page holds, while the contract would still take it. */
function heldSigned() {
  if (P.signed && P.signed.expiresAt <= chainNow()) P.signed = null;
  return P.signed;
}

function ownCancelNodes() {
  const held = heldSigned();
  if (!held) return null;
  return [
    h('p', { class: 'small', id: 'own-path' }, partNodes(ownCancelParts({ expiresAt: held.expiresAt, vaultHex: P.v, unsure: held.unsure }))),
    h('button', { class: 'go quiet', type: 'button', id: 'save-cancel', onclick: saveSigned }, 'Save the signed cancel'),
  ];
}

/** Words as text, and each command in one piece that never breaks inside a flag. */
function partNodes(parts) {
  return parts.map((p) => (typeof p === 'string' ? p : h('code', { class: 'cmd' }, p.cmd)));
}

function saveSigned() {
  const held = heldSigned();
  if (!held) return;
  const text = ownCancelFile({ contract: ctx.config.contract, method: held.method, args: held.args });
  const url = URL.createObjectURL(new Blob([text], { type: 'application/json' }));
  const link = h('a', { href: url, download: ownCancelFileName(P.v) });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10_000);
}

function noButtonWords() {
  const { why } = P.button;
  const problem = passkeyState().problem;
  if (why === 'no_passkey_here' && problem) return problemWords(problem) ?? NO_BUTTON_WORDS.no_passkey_here;
  // No answer is worded from what this page saw. A relay that answered and gave this as its own reason said only that
  // its cancel side is down, which relay_owner_down says.
  if (why === 'relay_down') return P.relay.reachable ? NO_BUTTON_WORDS.relay_owner_down : relayDownWords(P.relay);
  // Any other reason the relay gives, as its sentence and never its code.
  return NO_BUTTON_WORDS[why] ?? `${relayClause(why)}, so this page can't send a cancel.`;
}

/**
 * No Cancel because the relay's status could not be read, from what this page saw. A cancel this page sent with no
 * answer may have gone out, so until the status is read again that is what the page says; the status is read again
 * every STATUS_DOWN_MS while it can't be read (tick), so "Trying again" holds.
 */
function relayDownWords(relay) {
  if (relay.cancelUnanswered) return 'The relay did not answer, so this page can\'t tell whether the cancel went out.';
  return `${unreadRelayWords(relay)}, so this page can't send a cancel. Trying again.`;
}

function resetLine() {
  const at = P.relay.owner?.resets_at;
  return P.button.why === 'daily_ceiling' && at ? `It resets at ${new Date(at).toISOString().slice(11, 16)} UTC.` : null;
}

function destination(request, vault) {
  if (request.to === vault.script_pubkey) return 'this vault\'s own address';
  return spkToAddress(ctx.instance.network, request.to) ?? `script ${request.to}`;
}

function keyIsStopped() {
  return P.vault.k_s_suspended || (P.ksSeen !== null && P.vault.k_s !== P.ksSeen);
}

function faceFor(text, { stopped = false } = {}) {
  if (!P.face) P.face = new ClockFace();
  if (text) P.face.set(text);
  if (stopped) P.face.stop();
  return P.face;
}

/** The contract's numbers. With change, what leaves is the amount, and what comes back is said as such. */
function amountLines(request) {
  if (request.change === null) {
    return [
      h('div', { class: 'sats', id: 'amount' }, satsText(sumInputs(request))),
      request.fee > 0 ? h('p', { class: 'small fee' }, `${satsText(request.fee)} of it is the Bitcoin fee.`) : null,
    ];
  }
  return [
    h('div', { class: 'sats', id: 'amount' }, satsText(request.amount)),
    h('p', { class: 'small', id: 'change' }, `${satsText(request.change)} comes back to this vault. ${satsText(request.fee)} goes to the Bitcoin fee.`),
  ];
}

/** Null while a node agrees with what the request declares, or has not been asked. */
function coinWords(request) {
  const name = ctx.config.labels.bitcoin;
  const check = coinCheck(request, P.coinFacts);
  if (check.unknown) return `This page can't find ${request.inputs.length > 1 ? 'these coins' : 'this coin'} on ${name}. This amount is only what the request claims.`;
  if (check.differs) return `${name} says ${request.inputs.length > 1 ? 'these coins hold' : 'this coin holds'} ${satsText(check.real)}, not what the request claims.`;
  if (P.coinsDown) return `Can't check this amount with ${name} right now.`;
  return null;
}

function askedBlock(request) {
  const words = coinWords(request);
  return [
    h('div', { class: 'label' }, 'to'),
    h('div', { class: 'addr', id: 'to' }, destination(request, P.vault)),
    amountLines(request),
    words ? h('p', { class: 'small warnline', id: 'coin-check' }, words) : null,
    P.moreWaiting ? h('p', { class: 'small', id: 'more' }, `${P.moreWaiting} more ${P.moreWaiting === 1 ? 'request' : 'requests'} waiting. Cancel stops them all.`) : null,
  ];
}

/** Notices sit under the clock, and only ever hold a true thing the screen would otherwise hide. */
function noticeNodes() {
  const out = [];
  if (nodeLooksStuck()) out.push(h('p', { class: 'notice warn', id: 'stale-node' }, 'The node this page reads looks stuck, so this may be out of date.'));
  if (P.alreadySigned) out.push(h('p', { class: 'small', id: 'also-signed' }, `${P.alreadySigned} other ${P.alreadySigned === 1 ? 'request has' : 'requests have'} already been signed.`));
  if (needsThatPhone()) out.push(h('p', { class: 'small', id: 'that-phone' }, 'Cancel here works only with this vault\'s passkey.'));
  if (P.readFails >= READ_FAILS_TO_SAY) {
    out.push(h('p', { class: 'notice warn', id: 'read-down' }, 'Can\'t read the NEAR contract right now.'));
  }
  // A notice the idle screen set is said only there: an answer that lands after a request came up stays off its screen.
  if (P.notice && (!P.notice.screen || P.notice.screen === P.screen)) {
    out.push(h('p', { class: `notice${P.notice.warn ? ' warn' : ''}`, id: 'notice' }, P.notice.say));
    if (P.notice.words) out.push(h('p', { class: 'words', id: 'verbatim' }, P.notice.words));
  }
  if (P.hang) out.push(h('p', { class: 'notice warn', id: 'hang' }, hangWords(ctx.sense, P.tap?.own ? 'the button' : 'Cancel')));
  if (P.sheetNote) out.push(h('p', { class: 'small', id: 'sheet-note' }, P.sheetNote));
  // While the line about a sheet that has not shown is up, it is the one thing to read, and the button under it must
  // stay on a small screen: the hint comes back with the next screen, and inside an app that line says to leave it.
  const aside = P.hang;
  const hint = aside ? null : hintNow();
  if (hint) out.push(h('p', { class: 'small', id: 'platform-hint' }, hint));
  if (P.lastKnown?.hold_active) out.push(h('p', { class: 'notice', id: 'hold' }, `Held: ${P.lastKnown.assess_reason}`));
  if (P.vault && (P.vault.backup_eligible || P.vault.backup_state)) out.push(h('p', { class: 'small', id: 'synced' }, 'This passkey can sync, so your other devices may be able to use it too.'));
  // After a refusal with no trace of a sheet the hint stays, as a sheet may not have come; where the hint is up, the
  // in-app line, said before the tap and back with the next one, makes room for the notice, so Cancel stays on a small
  // screen. With no hint there is room, and inside an app it is the line to read.
  const elsewhere = aside || (P.notice?.inAppAside === true && hint) ? null : openElsewhere(ctx.sense);
  if (elsewhere) out.push(h('p', { class: 'small', id: 'in-app' }, elsewhere));
  if (ctx.config.softPasskey) out.push(h('p', { class: 'small' }, ctx.config.softPasskeyLabel ?? 'Signed by a test key in this browser.'));
  return out;
}

/** The chain's clock against this machine's. Only behind: a test chain's clock runs ahead, and that hides no cancel. */
function nodeLooksStuck() {
  const sample = ctx.skew.sample();
  return Boolean(sample) && sample.blockMs - sample.localMs < -STALE_NODE_MS;
}

/** A page can't ask a browser which passkeys it holds, so with no id to go on it says who this button is for. */
function needsThatPhone() {
  return !P.credential && !P.seed && P.rs?.cancellable;
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
  const root = document.documentElement;
  if (P.screen === 'cancelled') {
    screen().classList.remove('snug', 'packed');
    P.face?.fit();
    pinDigits();
    // What landed under the stamp while its frame held, say the coin line, needs the room: the digits settle now.
    if (P.pin && !P.pin.settled && overflowY() > 0) settleDigits(P.pin);
    root.dataset.digits = P.pin && !P.pin.settled ? 'held' : 'still';
    return;
  }
  delete root.dataset.digits;
  keepControlOnScreen();
}

/** The control a screen is for: Cancel, the slot standing in for it, or the last button in the column. */
function screenControl() {
  return document.getElementById('cancel') ?? screen().querySelector('.slot') ?? [...screen().querySelectorAll('button')].pop() ?? null;
}

const overflowY = () => document.documentElement.scrollHeight - window.innerHeight;

/**
 * Cancel, or what a screen offers in its place, whole on the screen, whatever else has something to say. The digits give
 * up size first, to 60% of what fits, then the sentences get smaller, then the digits go on down to 40%. If the control
 * is still cut, the small lines close up too and the digits are fitted again: every line stays, and a screen the
 * steps before already fit is drawn as it was. Each step is measured, because fonts and phones differ. A screen with no
 * control just gets the digits as large as they fit.
 */
function keepControlOnScreen() {
  const face = P.face;
  screen().classList.remove('snug', 'packed');
  if (!face) return;
  face.cap = null;
  face.fit();
  if (!screenControl() || !face.wrap.isConnected || overflowY() <= 0) return;
  const full = face.size;
  const shrinkTo = (floor) => {
    for (let i = 0; i < 4 && overflowY() > 0 && face.size > floor; i += 1) {
      face.cap = Math.max(floor, face.size - overflowY() - 2);
      face.fit();
    }
  };
  shrinkTo(Math.floor(full * 0.6));
  if (overflowY() <= 0) return;
  screen().classList.add('snug');
  shrinkTo(Math.floor(full * 0.4));
  // Whole with the page at its top, where a person first sees it: done. Still cut: the last step.
  if (screenControl().getBoundingClientRect().bottom + window.scrollY <= window.innerHeight) return;
  screen().classList.add('packed');
  face.cap = null;
  face.fit();
  shrinkTo(Math.floor(full * 0.4));
}

function pinDigits() {
  if (!P.pin || !P.face?.wrap.isConnected) return;
  const { wrap } = P.face;
  if (P.pin.settled) {
    wrap.style.marginTop = '';
    return;
  }
  if (P.pin.margin === undefined) {
    // All the room the screen has: the hash's slot is already on it, and a coin line that lands during the hold
    // settles the digits early (afterAttach), so nothing is kept back here. The screen's real height: the stamp no
    // longer widens the page, so the browser no longer zooms out to make more of it.
    const last = screen().lastElementChild?.getBoundingClientRect().bottom ?? 0;
    const room = window.innerHeight - last;
    const base = Number.parseFloat(getComputedStyle(wrap).marginTop) || 0;
    P.pin.margin = base + Math.max(0, Math.min(P.pin.top - wrap.getBoundingClientRect().top, room));
  }
  wrap.style.marginTop = `${P.pin.margin}px`;
}

/** How long the stamp's frame holds before the digits move up, and how long the move takes. */
const STAMP_HOLD_MS = 1600;
const SETTLE_MS = 450;

function settleDigits(pin) {
  if (P.pin !== pin || pin.settled) return;
  pin.settled = true;
  const wrap = P.face?.wrap;
  if (P.screen !== 'cancelled' || !wrap?.isConnected) return;
  const done = () => {
    wrap.classList.remove('settling');
    if (P.pin === pin) document.documentElement.dataset.digits = 'still';
  };
  wrap.classList.add('settling');
  if (P.face.cap !== null) {
    P.face.cap = null;
    P.face.fit();
  }
  wrap.style.marginTop = '';
  setTimeout(done, SETTLE_MS + 50);
}

const drawers = {
  request() {
    const s = P.rs;
    const under = s.kind === 'unlocked' ? h('p', { class: 'notice', id: 'at-zero' }, 'Anyone can send it now. Cancel works until they do.') : null;
    return [
      askedBlock(P.lastKnown), h('div', { class: 'grow' }), clockBlock(s), under, noticeNodes(), h('div', { class: 'grow' }),
      ownCancelNodes(),
      h('button', { id: 'cancel', type: 'button', onclick: () => onCancelTap() }, 'Cancel'),
    ];
  },
  no_button() {
    const words = noButtonWords();
    const showTool = P.button.why !== 'not_cancellable';
    const retry = P.blocked ? h('button', { class: 'go quiet', type: 'button', id: 'retry-passkey', onclick: () => { P.blocked = false; judge(); } }, 'Try the passkey again') : null;
    // The relay is the only thing in the way, and this phone holds the passkey: sign it here, send it from any account.
    const signHere = !heldSigned() && relayIsWhy(P.button.why) && passkeyState().canAssert && passkeyState().rpMatches && ctx.instance.origins.includes(location.origin);
    return [
      // The notice leads into the headline, so it sits right above it and not under the clock. After a passkey call that
      // came back at once, the way on is the button under the headline, so the lines on what to check go under it, where
      // a small screen still has room for them, and the button stays on it.
      askedBlock(P.lastKnown), clockBlock(P.rs), h('div', { class: 'grow' }), retry ? null : noticeNodes(),
      h('p', { class: 'say', id: 'why', 'data-why': P.button.why }, words),
      retry, retry ? noticeNodes() : null,
      resetLine() ? h('p', { class: 'line' }, resetLine()) : null,
      ownCancelNodes(),
      showTool && !heldSigned() ? h('p', { class: 'small', id: 'tool' }, partNodes(relayIsWhy(P.button.why) ? OWN_PATH_PARTS : RECOVERY_PATH_PARTS)) : null,
      signHere ? h('button', { class: 'go quiet', type: 'button', id: 'sign-own', onclick: () => onCancelTap(true) }, 'Sign a cancel to send yourself') : null,
    ];
  },
  tapped() {
    // Once the page has said no sheet came, the button is back in the slot's place: its tap ends the call that is out and
    // asks again. Until then nothing here can be tapped, so a second tap never lands on a sheet that is on its way.
    const again = !P.hang ? null : P.tap?.own
      ? h('button', { class: 'go quiet', type: 'button', id: 'sign-own', 'data-again': '1', onclick: onCancelAgain }, 'Sign a cancel to send yourself')
      : h('button', { id: 'cancel', type: 'button', 'data-again': '1', onclick: onCancelAgain }, 'Cancel');
    return [askedBlock(P.lastKnown), h('div', { class: 'grow' }), clockBlock(P.rs), noticeNodes(), h('div', { class: 'grow' }), again ?? h('div', { class: 'slot', id: 'waiting' }, 'Waiting for your passkey')];
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
    // The slam starts larger than the screen, and its box clips it there, so the page never scrolls sideways under it.
    out.push(h('div', { class: 'stampclip' }, h('div', { class: `stamp${P.stampLive ? ' slam' : ''}`, id: 'stamp' }, 'CANCELLED')));
    P.stampLive = false;
    // Its slot is kept from the moment this page has sent one, so the line under it does not jump when it arrives.
    if (P.tx) out.push(h('div', { class: 'hashslot', id: 'near-tx' }, hashBlock(nearTxLabel(ctx.config, P.tx), P.tx, nearTxLink(ctx.config, P.tx))));
    else if (P.txSent) out.push(h('div', { class: 'hashslot', id: 'near-tx' }));
    // Only what the contract says about the key now. A freeze that was lifted also moved the epoch, and stopped nothing.
    if (keyIsStopped()) out.push(h('p', { class: 'say', id: 'key-line' }, 'That key can\'t ask again.'));
    else if (P.rs.reason === 'frozen') out.push(h('p', { class: 'say' }, 'The cold key froze this vault.'));
    if (P.alreadySigned) out.push(h('p', { class: 'small', id: 'also-signed' }, `${P.alreadySigned} other ${P.alreadySigned === 1 ? 'request has' : 'requests have'} already been signed.`));
    if (P.coinStill) {
      out.push(h('p', { class: 'say', id: 'coin-line' }, 'The coin never moved.'));
      const address = hashBlock(btcAddressLabel(ctx.config, P.vault.address), P.vault.address, btcAddressLink(ctx.config, P.vault.address));
      address.classList.add('tight');
      out.push(address);
    }
    return out;
  },
  too_late() {
    const signing = P.rs.kind === 'signing';
    const out = [h('p', { class: 'say big', id: 'too-late' }, signing ? 'Too late. The contract asked for the signature.' : 'Too late. The contract signed.')];
    // Set as the request screen sets it: the label, then the address whole in mono, so one address reads one way.
    if (P.lastKnown) out.push(h('div', { class: 'label' }, 'to'), h('div', { class: 'addr', id: 'too-late-to' }, destination(P.lastKnown, P.vault)));
    if (P.tooLateTxid) out.push(hashBlock(btcTxLabel(ctx.config, P.tooLateTxid), P.tooLateTxid, btcTxLink(ctx.config, P.tooLateTxid)));
    else if (P.tooLateUnsent) out.push(h('p', { class: 'line dim', id: 'too-late-unsent' }, `This page can't find that transaction on ${ctx.config.labels.bitcoin} yet. Anyone can send it.`));
    else if (P.lastKnown) out.push(h('p', { class: 'line dim' }, signing ? 'Waiting for the signature.' : 'Reading the transaction.'));
    if (P.alreadySigned) out.push(h('p', { class: 'small', id: 'also-signed' }, `${P.alreadySigned} other ${P.alreadySigned === 1 ? 'request has' : 'requests have'} already been signed.`));
    return out;
  },
  expired() {
    return [h('p', { class: 'say big', id: 'expired' }, 'This request expired.'), h('p', { class: 'line dim' }, 'Nobody signed it, and nobody can now. Its coin stays where it was.')];
  },
  wrong_vault() {
    return [h('p', { class: 'say big' }, 'This page can\'t find a vault with this id on this contract.'), h('p', { class: 'words' }, `${ctx.config.labels.near} contract ${ctx.config.contract}`)];
  },
  inactive() {
    return [h('p', { class: 'say big' }, 'This vault is not active yet.'), h('p', { class: 'line dim' }, 'The contract has not checked its second key yet.')];
  },
  read_down() {
    return [h('p', { class: 'say big' }, 'Can\'t read the NEAR contract right now.')];
  },
  idle() {
    const { vault } = P;
    const out = [hashBlock(btcAddressLabel(ctx.config, vault.address), vault.address, btcAddressLink(ctx.config, vault.address))];
    // An amount is set big under its address. None is a line, so the screen has one headline: Nothing is waiting.
    if (P.balance > 0) out.push(h('div', { class: 'sats', id: 'balance' }, satsText(P.balance)));
    else if (P.balance === 0) out.push(h('p', { class: 'line dim', id: 'balance' }, 'No coins yet.'));
    else if (P.balanceWords) out.push(h('p', { class: 'line dim', id: 'balance-down' }, `Can't read ${ctx.config.labels.bitcoin} right now.`));
    out.push(h('p', { class: 'say big', id: 'nothing' }, 'Nothing is waiting.'));
    out.push(noticeNodes(), h('div', { class: 'grow' }));
    if (P.fundedTxid) out.push(hashBlock(btcTxLabel(ctx.config, P.fundedTxid), P.fundedTxid, btcTxLink(ctx.config, P.fundedTxid)));
    // A vault this browser's passkey is for, on a page that no longer holds its spend key: a reload, or a tab the phone
    // dropped and loaded again. A coin sent to it now could only be cancelled over, never asked for, so none is offered.
    const keyGone = !P.seed && P.credentialTrusted;
    if (!P.fundedTxid && P.balance === 0 && !keyGone) {
      if (P.relay.funds?.up) out.push(h('button', { class: 'go', type: 'button', id: 'fund', onclick: onFund }, 'Get test coins'));
      else out.push(h('p', { class: 'line', id: 'no-funds' }, `This page can't get a test coin from the relay right now.${resetWords(P.relay.funds?.why === 'daily_ceiling' ? P.relay.funds.resets_at : null)} A ${ctx.config.labels.bitcoin} coin you send to this address works too.`));
    }
    if (P.seed) {
      out.push(h('button', { class: 'go quiet', type: 'button', id: 'thief-link', onclick: copyThiefLink }, 'Copy the thief link'));
      // This page's Cancel swaps in a K_s whose secret it drops (ensurePrep), so after it the coins leave only by the cold
      // key, and that key is in this file and nowhere else once the page closes. Said inside the button, in the room it
      // already has, so nothing on the screen moves.
      out.push(h('button', { class: 'go quiet two', type: 'button', id: 'recovery', onclick: downloadRecovery }, 'Recovery file', h('span', { class: 'sub', id: 'recovery-why' }, RECOVERY_WHY)));
      out.push(h('p', { class: 'small', id: 'copy-now' }, 'Copy it now. A reload forgets the spend key.'));
    } else if (keyGone) {
      out.push(h('p', { class: 'small', id: 'no-seed' }, 'This page does not hold this vault\'s spend key (a reload forgets it), so it can\'t make a thief link. Cancel still works here. To try a theft, make a new test vault.'));
      out.push(h('button', { class: 'go quiet', type: 'button', id: 'new-vault', onclick: () => { location.assign(location.pathname); } }, 'Make a new test vault'));
    }
    return out;
  },
};

/**
 * The screen wake lock. Held while a clock runs. And on the idle screen of the page that holds a vault's spend key:
 * that phone is put down while the thief's laptop is used, and it should not be dark and locked when the request lands.
 * But not for ever: IDLE_AWAKE_MS after that screen came up or was last touched it is let go, and a phone left there
 * sleeps. A tap on the page takes it again, and so does a request coming up, since its clock holds it.
 */
function keepAwake(id) {
  if (id === 'idle' && P.screen !== 'idle') P.idleAwakeUntil = Date.now() + IDLE_AWAKE_MS;
  const want = Boolean(P.rs?.clockRuns || P.rs?.cancellable || (id === 'idle' && P.seed && Date.now() < P.idleAwakeUntil));
  if (want === P.awake) return;
  P.awake = want;
  if (want) ctx.awake.start();
  else ctx.awake.stop();
}

function render(id, force = false) {
  // Before the check below, which a screen that has not changed returns at: the idle screen's time can run out on it.
  keepAwake(id);
  const asked = P.lastKnown && P.vault ? `${P.r}|${coinWords(P.lastKnown)}|${P.moreWaiting}|${P.alreadySigned}|${keyIsStopped()}|${needsThatPhone()}|${nodeLooksStuck()}|${P.txSent}|${P.tooLateUnsent}` : '';
  const key = `${id}|${asked}|${JSON.stringify(P.notice)}|${P.hang}|${P.sheetNote}|${P.readFails >= READ_FAILS_TO_SAY}|${P.button?.why}|${P.lastKnown?.hold_active}|${P.lastKnown?.assess_reason}|${P.lastKnown?.unlock}|${P.relay?.owner?.why}|${P.blocked}|${P.rs?.kind}|${heldSigned()?.expiresAt ?? ''}|${hintNow() ? 1 : 0}|${P.relay?.funds?.up}|${P.relay?.funds?.resets_at}|${P.relay?.answered}|${P.relay?.code}|${P.relay?.cancelUnanswered}|${heldSigned()?.unsure}`;
  if (!force && key === P.renderKey) return;
  P.renderKey = key;
  P.screen = id;
  setState(id);
  // Asked again with each new drawing while it is wanted, as the page loses it whenever the browser lets it go.
  if (P.awake) ctx.awake.start();
  show(drawers[id]());
  afterAttach();
}

// ---------------------------------------------------------------- no vault, and making one

function drawNoVault(words = null) {
  P.noVault = { words };
  P.making = null;
  setState('no_vault');
  const problem = passkeyProblem(ctx.sense) ?? (ctx.credentials ? null : 'no_webauthn');
  const can = !problem && P.relay.general?.up;
  const elsewhere = openElsewhere(ctx.sense);
  const hint = hintNow();
  show(
    // Inside an app's own browser the first thing to know is to leave it, so that comes before the page's own headline.
    elsewhere ? h('p', { class: 'notice warn', id: 'in-app' }, elsewhere) : null,
    h('p', { class: 'say big' }, 'A cancel button for test Bitcoin.'),
    h('p', { class: 'line' }, 'Open the link from a vault, or make one here.'),
    can ? null : h('p', { class: 'notice warn', id: 'why', 'data-why': problem ?? P.relay.general?.why ?? 'relay_down' }, problem ? problemWords(problem) : generalDownWords()),
    words ? h('p', { class: 'notice warn', id: 'made-why' }, words) : null,
    h('div', { class: 'grow' }),
    can ? beforeSheet(BEFORE_MAKE(ctx.config.rpId)) : null,
    can ? makeButton() : null,
    // Under the button, so the button is where it is on any other phone: the hint is for after a tap that brought no sheet.
    can && hint ? h('p', { class: 'small', id: 'platform-hint' }, hint) : null,
    h('p', { class: 'foot', id: 'foot', 'data-network': ctx.instance?.network ?? '' }, `Test coins only. The address starts with ${addressPrefix(ctx.instance?.network) ?? 'tb1'}. This page makes your spend key and your cold key and holds them while it is open, so a changed page could take both. ${upgradeWords(P.codeKeys)} The signing network alone can refuse, not take.`),
  );
  relayAgainLater();
}

/** A status the page could not read, as only what it saw (unreadRelayWords). The page is asking again in every case. */
const unreadStatusWords = (relay) => `${unreadRelayWords(relay)}. Trying again.`;

function generalDownWords() {
  if (!P.relay.reachable) return unreadStatusWords(P.relay);
  const why = P.relay.general?.why;
  if (why === 'daily_ceiling') return `The relay hit today's limit, so this page can't make a vault right now.${resetWords(P.relay.general.resets_at)}`;
  if (why === 'relay_reserve') return 'The relay is keeping what it has left for cancels, so this page can\'t make a vault right now.';
  // The relay answered, so it is not down: its own reason, or with none (it never sends none) only that it can't.
  if (!why || why === 'relay_down') return 'The relay says it can\'t make a vault right now.';
  return `${relayClause(why)}, so this page can't make a vault.`;
}

/**
 * The screen while a vault is being made. `note` is a sentence about the step just tried; `before` is the line over a
 * button that opens a sheet, saying what the device is about to ask.
 */
function creating(lines, button = null, { note = null, before = null } = {}) {
  P.noVault = null;
  clearTimeout(P.relayTimer);
  setState('creating');
  show(
    h('p', { class: 'say big' }, 'Making your test vault'),
    lines.map((text) => h('p', { class: 'line made' }, text)),
    note ? h('p', { class: 'notice', id: 'made-note' }, note) : null,
    P.hangMaking ? h('p', { class: 'notice warn', id: 'hang' }, hangWords(ctx.sense, P.hangMaking)) : null,
    h('div', { class: 'grow' }),
    before ? beforeSheet(before) : null,
    button,
  );
}

/** The line over a button that opens a passkey sheet. A local run that signs with a test key in the browser has no sheet. */
const beforeSheet = (text) => (ctx.config.softPasskey ? null : h('p', { class: 'small', id: 'before-sheet' }, text));

const WAITING_FOR_PASSKEY = 'Waiting for your passkey';
const WORKING = 'Working: a small proof of work.';
// The line while K_m is read, shown only once the read has taken this long.
const READING_KM = 'Reading the second key from the signer.';
const READING_KM_MS = 4000;
// Read again gives each read 30 s, where a first try's reads get PAGE_READS' 15 s, so hosts slower than a first try allows
// (the first never answering, the others 13 s or more) still answer while the network stays that slow. A new pass starts
// only in the first 15 s, so Read again, like a first try, ends within 45 s.
const READ_AGAIN = { budgetMs: 30_000, patience: { deadlineMs: 15_000 } };
const makeButton = () => h('button', { class: 'go', type: 'button', id: 'make', onclick: onMakeVault }, 'Make a test vault');

/**
 * One passkey call of a vault in the making, and the only one whose answer counts. A tap that asks again ends the call
 * before it: that call may be one that never settles, and a browser takes one passkey request at a time.
 */
function newMakingCall() {
  const old = P.making;
  const call = { abort: new AbortController(), answered: false };
  P.making = call;
  if (old && !old.answered) old.abort.abort();
  P.hangMaking = null;
  return call;
}

/** The first tap. Nothing here may wait before askNewPasskey: Safari gives the sheet only to a call made in the tap. */
function onMakeVault() {
  const call = newMakingCall();
  const waiting = () => creating([WAITING_FOR_PASSKEY], P.hangMaking ? makeButton() : null);
  const asking = askNewPasskey(ctx, {
    label: 'test vault',
    signal: call.abort.signal,
    onHang: () => {
      if (P.making !== call) return;
      P.hangMaking = 'Make a test vault';
      waiting();
    },
  });
  waiting();
  continueMake(asking, call);
}

async function continueMake(asking, call) {
  const lines = [];
  let passkey;
  try {
    ({ passkey } = await asking);
  } catch (err) {
    call.answered = true;
    if (P.making === call) makeFailed(err);
    return;
  }
  call.answered = true;
  // A call this page gave up on, answering late: a newer tap is making the vault.
  if (P.making !== call) return;
  P.hangMaking = null;
  passkeyAnswered();
  lines.push('Passkey made.');
  if (passkey.flags?.backupEligible) lines.push('It can sync to your other devices.');
  readSecondKey(passkey, newVaultKeys(), lines, call);
}

/**
 * K_m for the passkey the first tap made: a read between the two sheets. When no node answers it in the time
 * prepareVault gives it, nothing has gone to the relay, and the passkey and the keys made for it still stand: the page
 * stays on this screen and Read again reads with the same ones, so no second sheet and no second passkey.
 */
async function readSecondKey(passkey, keys, lines, call, { again = false } = {}) {
  creating(lines);
  // A read that is not quick says so, while it reads. A quick one never shows the line. The line is about K_m alone, so
  // it goes once K_m is in, though prepareVault may wait a moment more for the clock read sent with it.
  let shown = false;
  const slow = setTimeout(() => {
    if (P.making !== call) return;
    shown = true;
    creating([...lines, READING_KM]);
  }, READING_KM_MS);
  const onKm = () => {
    clearTimeout(slow);
    if (shown && P.making === call) creating(lines);
  };
  let prepared;
  try {
    prepared = again
      ? await prepareVault({ ...ctx, reader: ctx.reader.withBudget(READ_AGAIN.budgetMs) }, passkey, { keys, onKm, patience: READ_AGAIN.patience })
      : await prepareVault(ctx, passkey, { keys, onKm });
  } catch (err) {
    clearTimeout(slow);
    if (P.making !== call) return;
    if (err instanceof RpcDown || err instanceof StaleRead) {
      logRaw('reading the second key', rawWords(err));
      creating(lines, h('button', { class: 'go', type: 'button', id: 'read-again', onclick: () => readSecondKey(passkey, keys, lines, call, { again: true }) }, 'Read again'), { note: `No vault was made. ${failureWords(err)}` });
      return;
    }
    makeFailed(err);
    return;
  }
  clearTimeout(slow);
  if (P.making !== call) return;
  lines.push('Second key read from the signer.');
  drawConfirm(prepared, lines);
}

const confirmButton = (prepared, lines) => h('button', { class: 'go', type: 'button', id: 'confirm', onclick: () => onConfirm(prepared, lines) }, 'Confirm with your passkey');

/** The second tap's screen. Drawn again, with the same keys, when its sheet closed or never came: nothing was sent. */
function drawConfirm(prepared, lines, note = null) {
  creating(lines, confirmButton(prepared, lines), { note, before: BEFORE_CONFIRM });
}

/**
 * The second tap. confirmVault signs with the four keys this page made and then asks the passkey, all before it first
 * waits, so the sheet is asked for inside this tap. Nothing here may wait before it.
 */
function onConfirm(prepared, lines) {
  const call = newMakingCall();
  const waiting = () => creating(lines, P.hangMaking ? confirmButton(prepared, lines) : null);
  const confirming = confirmVault(ctx, prepared, {
    guard: P.relay.relayAccount,
    signal: call.abort.signal,
    onHang: () => {
      if (P.making !== call) return;
      P.hangMaking = 'Confirm';
      waiting();
    },
  });
  waiting();
  finishMake(confirming, prepared, lines, call);
}

async function finishMake(confirming, prepared, lines, call) {
  let args;
  try {
    ({ args } = await confirming);
  } catch (err) {
    call.answered = true;
    if (P.making !== call) return;
    P.hangMaking = null;
    // The passkey from the first tap and the keys made for it still stand, and nothing has gone to the relay: the same
    // screen and the same button, not a second passkey. A sheet closed, one that left no trace, or none at all look alike
    // to the page, so the words are only what holds in each.
    if (err instanceof PasskeyFailed && (err.kind === 'dismissed' || err.kind === 'blocked')) {
      if (err.kind === 'blocked') logRaw('the passkey', rawWords(err));
      drawConfirm(prepared, lines, 'The passkey did not sign. Tap Confirm to try again.');
      return;
    }
    makeFailed(err);
    return;
  }
  call.answered = true;
  if (P.making !== call) return;
  P.hangMaking = null;
  passkeyAnswered();
  const said = [...lines, 'Signed.'];
  creating(said);
  let made;
  try {
    made = await sendVault(ctx, prepared, args, {
      powBits: P.relay.powBits,
      onLine: (step, hash) => {
        // The proof of work is the one step with no answer to wait for, and on a slow phone it is not short.
        if (step === 'working') said.push(WORKING);
        if (step === 'work') said[said.includes(WORKING) ? said.indexOf(WORKING) : said.length] = 'Proof of work done.';
        if (step === 'sent') said.push(nearTxLabel(ctx.config, hash));
        creating(said);
      },
    });
  } catch (err) {
    if (err?.sentHash) drawSent(prepared, said, err.sentHash);
    else makeFailed(err);
    return;
  }
  vaultMade(prepared, made);
}

/** The contract reads the vault active: this page now holds its keys, and watches it. */
function vaultMade(prepared, made) {
  P.seed = prepared.keys.seed;
  P.cold = prepared.keys.cold;
  P.credential = prepared.passkey.credentialId;
  P.credentialTrusted = true;
  rememberCredential(made.vault.id, credentialB64());
  P.fragment = { refused: [], v: made.vault.id, c: credentialB64() };
  writeFragment(P.fragment);
  watchVault(made.vault.id);
}

/**
 * The relay sent the creation and the contract has not read the vault active in the time this page gives it. The vault
 * may still come, and this page holds its keys, so it says what is true and reads again on a tap, with the hash on screen.
 */
function drawSent(prepared, lines, hash) {
  creating(lines, h('button', { class: 'go', type: 'button', id: 'check-again', onclick: () => checkAgain(prepared, lines, hash) }, 'Check again'), { note: 'The vault was sent, but the contract does not read it active yet.' });
}

async function checkAgain(prepared, lines, hash) {
  creating(lines, null, { note: 'Reading the contract again.' });
  let made;
  try {
    made = await waitActive(ctx, prepared, hash);
  } catch {
    drawSent(prepared, lines, hash);
    return;
  }
  vaultMade(prepared, made);
}

/** Why a vault was not made, in one sentence. The relay's hourly limit for one address gets its number and its way out. */
function makeWhy(err) {
  if (err instanceof RelayRefused && err.code === 'rate_limited' && err.retryAfterS >= 120) {
    return `This network address has used its ${RELAY_METHODS.create_vault.perIpHour} vault tries for this hour. Wait ${waitWords(err.retryAfterS)}, or use another network.`;
  }
  return failureWords(err);
}

/**
 * Why no vault was made, or that the page can't tell. Only "No vault was made": a failure at the first sheet can come
 * after the browser saved a passkey (one whose key this page can't read), so "nothing was made" may not hold.
 */
function makeFailed(err) {
  P.hangMaking = null;
  P.making = null;
  if (err instanceof PasskeyFailed && err.kind === 'blocked') {
    P.blocked = true;
    P.noVault = null;
    setState('no_vault');
    logRaw('the passkey', rawWords(err));
    const hint = hintNow();
    show(
      // No vault exists yet, so this is not the Cancel's sentence about a phone that lacks a vault's passkey.
      h('p', { class: 'say', id: 'why', 'data-why': 'webauthn_blocked' }, 'No passkey came back, so nothing was made. If you opened this inside an app, open it in Safari or Chrome.'),
      hint ? h('p', { class: 'small', id: 'platform-hint' }, hint) : null,
      h('div', { class: 'grow' }),
      h('button', { class: 'go quiet', type: 'button', id: 'retry-passkey', onclick: onMakeVault }, 'Try the passkey again'),
    );
    return;
  }
  if (err instanceof PasskeyFailed && err.kind === 'dismissed') {
    // A trace of a sheet can come from something else, and a sheet can leave none: no passkey came back holds either way.
    drawNoVault('No passkey came back, so nothing was made.');
    return;
  }
  logRaw('making a vault', rawWords(err));
  // A send that got no answer may still have gone out, so the page does not say what it has not read. relay_down is any
  // answer that is not the relay's own (none, the page's own 20 s, a page or JSON with no code: a proxy's), and any code
  // but a refusal before the relay's sender signed (relaySentNothing) can come after it sent the creation.
  if (err instanceof RelayRefused && !relaySentNothing(err.code)) {
    drawNoVault(`${err.code === 'relay_down' ? 'The relay did not answer' : relayClause(err.code)}, so this page can't tell whether a vault was made.`);
    return;
  }
  drawNoVault(`No vault was made. ${makeWhy(err)}`);
}

async function onFund() {
  if (P.funding) return;
  P.funding = true;
  P.notice = { say: 'Asking for a test coin.', words: null, screen: 'idle' };
  render('idle', true);
  try {
    const pow = await solvePow(fundsPowTarget(P.v), P.relay.powBits);
    const paid = await ctx.relay.fund(P.v, { pow });
    P.notice = null;
    P.fundedTxid = paid.txid;
    P.balanceAt = 0;
    drawIdleAgain();
  } catch (err) {
    logRaw('test coins', rawWords(err));
    // Only a refusal before the relay sent anything says no coin was sent. With no answer, or a code it can give after
    // the coin went out, the page can't tell. A short rate_limited is also the relay's answer while another ask for this
    // vault holds its claim (funds.mjs, undo-state funded()), and that ask's coin may be on its way; only the hourly
    // limit (over 120 s) is charged with no claim at all. Whatever the answer, the balance is read again at once: a coin
    // it reads ends the notice.
    const unsure = err instanceof RelayRefused && (!FUND_UNSENT.has(err.code) || (err.code === 'rate_limited' && !(err.retryAfterS > 120)));
    P.notice = { warn: true, say: unsure ? `${err.code === 'relay_down' ? 'The relay did not answer' : relayClause(err.code)}, so this page can't tell whether a coin was sent.` : `No coins sent. ${fundWhy(err)}`, words: null, screen: 'idle', fund: true };
    P.balanceAt = 0;
    drawIdleAgain();
  } finally {
    P.funding = false;
  }
}

// The codes /api/funds gives only before its coin goes out (funds.mjs): its checks, its limits, an empty dispenser, and a
// node's refusal of the funding. state_store_down, esplora_down and relay_error can come after the broadcast.
const FUND_UNSENT = new Set(['bad_origin', 'bad_request', 'relay_not_configured', 'pow_required', 'pow_bad', 'would_refuse', 'rpc_down', 'rate_limited', 'daily_ceiling', 'dispenser_empty', 'tx_refused']);

/**
 * Why no coin came, in one sentence. The dispenser's limits are the relay's, not the vault's: where one of them is the
 * reason, the sentence says when it ends and that a coin from anywhere else does the same job.
 */
function fundWhy(err) {
  if (!(err instanceof RelayRefused)) return failureWords(err);
  const own = ` A ${ctx.config.labels.bitcoin} coin you send to this address works too.`;
  // A wait of minutes is the hourly limit for one address; the relay's shorter waits are a coin that is still going out.
  if (err.code === 'rate_limited' && err.retryAfterS > 120) return `This network address has used its test coin tries for this hour. Wait ${waitWords(err.retryAfterS)}, or use another network.${own}`;
  if (err.code === 'daily_ceiling') return `${relayWords(err)}${resetWords(err.resetsAt)}${own}`;
  if (err.code === 'dispenser_empty') return `${relayWords(err)}${own}`;
  // The relay's /api/funds sends a coin on Bitcoin: its tx_refused is a node's refusal of that, not the NEAR contract's.
  if (err.code === 'tx_refused') return `A ${ctx.config.labels.bitcoin} node refused the relay's transaction.${own}`;
  return failureWords(err);
}

async function copyThiefLink() {
  const link = thiefLink(location.origin, P.v, toHex(P.seed), randomBytes(20), ctx.instance.network);
  try {
    await navigator.clipboard.writeText(link);
    P.notice = { say: 'Copied. This link holds this vault\'s spend key.', words: null, screen: 'idle' };
  } catch {
    P.notice = { say: 'Copy this link. It holds this vault\'s spend key.', words: link, screen: 'idle' };
  }
  drawIdleAgain();
}

/** An answer read for the idle screen redraws it, and only while it is still the screen: a request may have come up. */
function drawIdleAgain() {
  if (P.screen === 'idle') render('idle', true);
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
  logRaw('the page', rawWords(err));
  show(h('p', { class: 'say' }, 'This page hit an error it did not expect.'));
});
