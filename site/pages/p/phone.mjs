// The phone page. Everything it says about a request comes from the contract, read here over public RPC. Nothing
// connects it to the thief tab but the contract, which is the claim the film's shot makes.
//
// data-state on <html> and data-clock on the digits are what tests and the recorder wait on.
import {
  bitcoinReader, btcAddressLabel, btcAddressLink, btcTxLabel, btcTxLink, cancelButton, chooseOnScreen, clock, coinCheck, contractViews, credentialToFragment, advanceState,
  credentialsFor, fromBase64Url, fundsPowTarget, loadConfig, NearReader, nearTxLabel, nearTxLink, refusalOf, RelayClient, RelayRefused, requestState, rotateArgs,
  rotateDigest, RpcDown, rpIdHashOf, SkewTracker, solvePow, spendKeys, spkToAddress, StaleRead,
} from '/site/lib/index.mjs';
import { parseTx, txid as txidOf } from '/tools/lib/btc.mjs';
import { fromHex, toHex } from '/tools/lib/bytes.mjs';
import { randomBytes } from '/tools/lib/crypto.mjs';
import { buildRecovery } from '/tools/lib/recovery.mjs';
import { runH7 } from './h7.mjs';
import { runOperatorCheck } from './operator-check.mjs';
import { ClockFace, h, hashBlock, satsText, screen, setState, show, sumInputs } from './kit.mjs';
import { OWN_PATH_LINE, ownCancelFile, ownCancelFileName, ownCancelWords, relayIsWhy, relayRefusedIt } from './own-cancel.mjs';
import { askAssertion, askNewPasskey, PasskeyFailed } from './passkey-ask.mjs';
import { parsePhoneFragment, recallCredential, recallSeen, rememberCredential, rememberSeen, thiefLink, writeFragment } from './phone-fragment.mjs';
import { openElsewhere, passkeyProblem, problemWords, screenAwake, sensePasskeys } from './sense.mjs';
import { chainNowOf, confirmVault, prepareVault, sendVault } from './vault-make.mjs';

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

const P = {
  screen: null, v: null, r: null, fragment: {}, vault: null, vaultRead: false, lastKnown: null, rs: null, items: new Map(), hintR: null,
  moreWaiting: 0, alreadySigned: 0, relay: null, readFails: 0, readWords: null, notice: null, tap: null, prep: null,
  credential: null, credentialTrusted: false, blocked: false, rpBad: false, frozenText: null, stampLive: false, coinStill: false, coinCheckedAt: 0,
  coinFacts: new Map(), coinFactsAt: 0, coinsDown: false, tooLateTxid: null, tooLateUnsent: false, finalAt: 0, face: null, skewAt: 0, statusAt: 0, timer: null, touch: null, seed: null, cold: null,
  balance: null, fundedTxid: null, stopped: false, sheetNote: null, hang: false, tx: null, txSent: null, ksSeen: null, frozenBy: {}, pin: null,
  // A cancel this page signed and the relay did not send, for tools/cancel.mjs. And whether this relay refused this vault.
  signed: null, notOurs: false,
  // The first tick's vault and request reads, sent with the boot reads.
  early: null,
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
  const views = contractViews(reader, config.contract);
  const relay = new RelayClient({ relay: config.relay, funds: config.funds });
  // Needs no contract and no relay: the contract this config names may already be gone when a deploy asks for it.
  const asked = parsePhoneFragment(location.hash);
  const operatorCheck = Boolean(asked.opproof && asked.opfor);
  // None of these first reads waits on another, so they all go out now, and each is awaited where the page used to
  // send it: the relay's status, the contract's instance and clock, and the vault the link names with its request.
  const status = operatorCheck ? null : relay.status();
  let reads = operatorCheck ? null : contractReads(views, reader);
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

  for (;;) {
    try {
      // In this order, so a failure shows the same words it did when the reads went one after another.
      ctx.instance = await reads.instance;
      ctx.skew.add(await reads.block);
      P.skewAt = Date.now();
      break;
    } catch (err) {
      setState('read_down');
      show(h('p', { class: 'say' }, 'Can\'t read the NEAR contract right now.'), h('p', { class: 'words' }, err.verbatim ?? err.message));
      await new Promise((r) => { setTimeout(r, 3000); });
      reads = contractReads(views, reader);
      P.early = null;
    }
  }

  P.fragment = parsePhoneFragment(location.hash);
  window.addEventListener('hashchange', () => location.reload());
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
    drawNoVault();
    return;
  }
  watchVault(P.fragment.v);
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
  document.addEventListener('pointerdown', () => { P.touch = performance.now(); }, { capture: true, passive: true });
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
    P.readWords = null;
  } catch (err) {
    if (err instanceof StaleRead || err instanceof RpcDown) P.readFails += 1;
    else {
      P.readFails += 1;
      P.readWords = err.verbatim ?? err.message;
    }
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
  // The digits stay exactly where they were when the stamp lands, because this frame is on film.
  if (live && P.face?.wrap.isConnected) P.pin = { top: P.face.wrap.getBoundingClientRect().top };
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
  } catch (err) {
    P.balanceWords = err.message;
  } finally {
    P.balanceReading = false;
    render('idle', true);
  }
}

// ---------------------------------------------------------------- the tap

/** `own`: sign the cancel for tools/cancel.mjs, and send nothing to the relay. */
function onCancelTap(own = false) {
  if (P.tap || !P.vault) return;
  const prep = ensurePrep();
  P.notice = null;
  P.hang = false;
  P.tap = { phase: 'tapped', sentAt: null, own: own === true };
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
  // This id has now made an assertion this vault's passkey signed, so it is worth keeping. Nothing before this is.
  if (assertion.credentialId?.length) {
    P.credential = assertion.credentialId;
    P.credentialTrusted = true;
    rememberCredential(P.v, credentialB64());
    saveFragment({ c: credentialB64() });
  }
  const callArgs = rotateArgs({ vaultHex: P.v, newKs: prep.newKs, nonce: prep.nonce, expiresAt: prep.expiresAt, assertion: assertion.args });
  if (P.tap.own) {
    P.tap = null;
    P.prep = null;
    P.signed = { method: 'cancel_all_and_rotate', args: callArgs, expiresAt: prep.expiresAt };
    P.notice = { say: 'Signed. This page sent it nowhere.', words: null };
    judge();
    return;
  }
  P.tap.phase = 'sending';
  P.tap.sentAt = Date.now();
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
  if (P.tap) P.tap.hash = sent.hash;
  watchOutcome(sent.hash);
}

/**
 * A link can name any hash, so a screen never takes one from it, and a failed read of a credential means little: a
 * link can name a junk id too, and a browser refuses that in the same words as a person closing the sheet. So an id
 * that has never made an assertion is dropped after one failed tap, and the next tap offers any passkey here.
 */
function forgetUntrustedCredential(fast) {
  if (!P.credential || (P.credentialTrusted && !fast)) return false;
  P.credential = null;
  P.credentialTrusted = false;
  saveFragment({ c: null });
  return true;
}

function onTapFailed(err) {
  P.tap = null;
  P.hang = false;
  if (err instanceof PasskeyFailed) {
    const dropped = err.kind === 'blocked' || err.kind === 'dismissed' ? forgetUntrustedCredential(err.kind === 'blocked') : false;
    if (dropped && err.kind === 'blocked') P.notice = { say: 'Not cancelled. No passkey sheet came up, so the passkey this link names may not be on this phone. Tap Cancel to try any passkey here.', words: null };
    else if (err.kind === 'blocked') P.blocked = true;
    else if (err.kind === 'wrong_site') P.rpBad = true;
    else if (err.kind === 'dismissed') P.notice = { say: 'Not cancelled. The sheet closed.', words: null, line: P.credential ? null : 'If it offered no passkey, this phone doesn\'t hold this vault\'s.' };
    else P.notice = { warn: true, say: 'Not cancelled.', words: err.message };
  } else {
    P.notice = { warn: true, say: 'Not cancelled.', words: err.message };
  }
  P.prep = null;
  judge();
}

/** `signed` is the call the relay was given. When the relay, not the cancel, was the problem, the page keeps it. */
function onRelayRefused(err, signed = null) {
  P.tap = null;
  P.prep = null;
  P.txSent = null;
  if (err instanceof RelayRefused) {
    if (signed && relayRefusedIt(err.code)) P.signed = signed;
    if (err.code === 'not_this_relays') P.notOurs = true;
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
        P.notice = { warn: true, say: 'Not cancelled. The contract refused it.', words: outcome.failure };
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

const NO_BUTTON_WORDS = {
  relay_down: 'The relay is down, so this page can\'t send a cancel.',
  relay_owner_down: 'The relay is down, so this page can\'t send a cancel.',
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
    h('p', { class: 'small', id: 'own-path' }, ownCancelWords({ expiresAt: held.expiresAt, vaultHex: P.v })),
    h('button', { class: 'go quiet', type: 'button', id: 'save-cancel', onclick: saveSigned }, 'Save the signed cancel'),
  ];
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
  if (check.unknown) return `${name} doesn't know ${request.inputs.length > 1 ? 'these coins' : 'this coin'}. This amount is only what the request claims.`;
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
  if (needsThatPhone()) out.push(h('p', { class: 'small', id: 'that-phone' }, 'Only the phone holding this vault\'s passkey can cancel.'));
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
  P.face?.fit();
  if (P.screen === 'cancelled') pinDigits();
}

/** Room for what can still land under the stamp: the hash, and the coin line with its address. */
const ROOM_FOR_LATER = 130;

function pinDigits() {
  if (!P.pin || !P.face?.wrap.isConnected) return;
  const { wrap } = P.face;
  if (P.pin.margin === undefined) {
    const last = screen().lastElementChild?.getBoundingClientRect().bottom ?? 0;
    const room = window.innerHeight - last - (P.coinStill ? 0 : ROOM_FOR_LATER);
    const base = Number.parseFloat(getComputedStyle(wrap).marginTop) || 0;
    P.pin.margin = base + Math.max(0, Math.min(P.pin.top - wrap.getBoundingClientRect().top, room));
  }
  wrap.style.marginTop = `${P.pin.margin}px`;
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
      askedBlock(P.lastKnown), clockBlock(P.rs), noticeNodes(), h('div', { class: 'grow' }),
      h('p', { class: 'say', id: 'why', 'data-why': P.button.why }, words),
      resetLine() ? h('p', { class: 'line' }, resetLine()) : null,
      ownCancelNodes(),
      showTool && !heldSigned() ? h('p', { class: 'small', id: 'tool' }, relayIsWhy(P.button.why) ? OWN_PATH_LINE : 'If you hold this vault\'s recovery file, any NEAR testnet account can send the cancel: tools/freeze.mjs --method cancel') : null,
      signHere ? h('button', { class: 'go quiet', type: 'button', id: 'sign-own', onclick: () => onCancelTap(true) }, 'Sign a cancel to send yourself') : null,
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
    if (P.lastKnown) out.push(h('p', { class: 'line', id: 'too-late-to' }, `to ${destination(P.lastKnown, P.vault)}`));
    if (P.tooLateTxid) out.push(hashBlock(btcTxLabel(ctx.config, P.tooLateTxid), P.tooLateTxid, btcTxLink(ctx.config, P.tooLateTxid)));
    else if (P.tooLateUnsent) out.push(h('p', { class: 'line dim', id: 'too-late-unsent' }, `No ${ctx.config.labels.bitcoin} node has that transaction yet. Anyone can send it.`));
    else if (P.lastKnown) out.push(h('p', { class: 'line dim' }, signing ? 'Waiting for the signature.' : 'Reading the transaction.'));
    if (P.alreadySigned) out.push(h('p', { class: 'small', id: 'also-signed' }, `${P.alreadySigned} other ${P.alreadySigned === 1 ? 'request has' : 'requests have'} already been signed.`));
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
  const asked = P.lastKnown && P.vault ? `${P.r}|${coinWords(P.lastKnown)}|${P.moreWaiting}|${P.alreadySigned}|${keyIsStopped()}|${needsThatPhone()}|${nodeLooksStuck()}|${P.txSent}|${P.tooLateUnsent}` : '';
  const key = `${id}|${asked}|${JSON.stringify(P.notice)}|${P.hang}|${P.sheetNote}|${P.readFails >= READ_FAILS_TO_SAY}|${P.readWords}|${P.button?.why}|${P.lastKnown?.hold_active}|${P.lastKnown?.assess_reason}|${P.lastKnown?.unlock}|${P.relay?.owner?.why}|${P.blocked}|${P.rs?.kind}|${heldSigned()?.expiresAt ?? ''}`;
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
  if (why === 'relay_reserve') return 'The relay is keeping what it has left for cancels, so this page can\'t make a vault right now.';
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
    P.credentialTrusted = true;
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
  if (P.funding) return;
  P.funding = true;
  P.notice = { say: 'Asking for a test coin.', words: null };
  render('idle', true);
  try {
    const pow = await solvePow(fundsPowTarget(P.v), P.relay.powBits);
    const paid = await ctx.relay.fund(P.v, { pow });
    P.notice = null;
    P.fundedTxid = paid.txid;
    P.balanceAt = 0;
    render('idle', true);
  } catch (err) {
    P.notice = { warn: true, say: 'No coins sent.', words: err.verbatim ?? `${err.code}: ${err.message}` };
    render('idle', true);
  } finally {
    P.funding = false;
  }
}

async function copyThiefLink() {
  const link = thiefLink(location.origin, P.v, toHex(P.seed), randomBytes(20));
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
