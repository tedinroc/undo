// /try/: one phone, one tab. The page makes a test vault (two passkey sheets), asks the relay for a test coin, plays a
// thief who has the spend key (it holds that key: it made it), and is refused by Bitcoin; the thief asks the NEAR
// contract; then the owner half, which reads only the contract, finds the request and the person cancels it (the third
// sheet). Three taps, each a passkey sheet: iOS opens one only inside a tap, so each handler's first call is the passkey
// call, and nothing is awaited before it (THE RULE; try-source.test.mjs reads it).
//
// CANCEL_HERE true: the owner half (owner.mjs) draws the request, its clock and Cancel on this page, then CANCELLED and
// the recap. CANCEL_HERE false: when the contract has the request, this tab becomes the phone page (/p/#v&r&c), whose
// Cancel is the one already proven on a phone. Either way, every state this page does not draw itself goes there.
//
// <html data-step data-state data-fail>, #next, #dock and window.undoTimings / window.undoRun are what tests wait on.
import {
  bitcoinReader, btcAddressLabel, btcAddressLink, btcTxLabel, btcTxLink, configWords, contractViews, contractWords, credentialsFor, credentialToFragment,
  fundsPowTarget, loadConfig, logRaw, NearReader, nearTxLabel, nearTxLink, newVaultKeys, noNodeWords, nodeRefusalWords, PAGE_READS, RelayClient, RelayRefused,
  relayClause, relaySentNothing, relayWords, resetWords, RpcDown, SkewTracker, solvePow, StaleRead, unreadRelayWords, upgradeWords, ViewRefused,
} from '/site/lib/index.mjs';
import { addressPrefix } from '/tools/lib/btc.mjs';
import { toHex } from '/tools/lib/bytes.mjs';
import { randomBytes } from '/tools/lib/crypto.mjs';
import { h, hashBlock, satsText } from '../p/kit.mjs';
import { askNewPasskey, PasskeyFailed } from '../p/passkey-ask.mjs';
import { buildPhoneFragment, parsePhoneFragment, recallCredential, rememberCredential, writeFragment } from '../p/phone-fragment.mjs';
import { openElsewhere, passkeyProblem, platformHint, problemWords, screenAwake, sensePasskeys } from '../p/sense.mjs';
import { confirmVault, prepareVault, sendVault, waitActive } from '../p/vault-make.mjs';
import { ownerDrawing, READ_FAILS_TO_SAY, recapPlace, startOwner } from './owner.mjs';
import * as steps from './steps.mjs';
import {
  COIN_TRIES_PER_HOUR, FUND_UNSENT, fundWhy, failureWords, generalDownWords, makeWhy, nextOf, relayOrNone, runTime, say, unreadStatusWords, W,
} from './words.mjs';

/** v2 (true): Cancel on this page. v1 (false): the phone page's Cancel, in this same tab. Set by the gate. */
export const CANCEL_HERE = true;

const OWNER_EVERY_MS = 1000;
const SKEW_EVERY_MS = 5000;
const CARD_AFTER_MS = 3000;
const STILL_AFTER_MS = 15_000;
const COUNT_FROM = 3;
const REFUSED_HOLD_MS = 3000;
const SEEN_HOLD_MS = 1500;
const LIST_EVERY_MS = 1000;
const LIST_FOR_MS = 60_000;
const UNSURE_LIST_EVERY_MS = 2000;
const SLOW_EVERY_MS = 15_000;
const RETRY_EVERY_MS = 5000;
const NO_REQUEST_MS = 30_000;
const CODE_KEYS_MS = 2500;
const RELAY_AGAIN_MS = [5000, 10_000, 20_000, 60_000];
const HOUR_MS = 60 * 60_000;
const MADE_KEY = 'undo-try:made';
const KEY_PHRASE = 'finished with a false/empty top stack element';

const T = {
  step: 'intro', state: 'boot', fail: null, title: say(W.title), lines: [], stage: null, more: null, dock: null, aside: null, card: null, cardFrom: 0,
  countFrom: null, count: null, lineSince: 0, still: null, limit: null, kind: null,
  status: null, codeKeys: null, relayReads: 0,
  // M8 and M9: the row's sentence, said only after a read of the vault that answered; and the reads made since.
  stuckWords: null, vaultReads: 0,
  // The passkey call a tap is waiting on: { abort, answered }. A later tap replaces it, and its answer is then dropped.
  call: null,
  passkey: null, keys: null, prepared: null, fundPow: null,
  v: null, vault: null, credB64: null, seed: null, made: false, listed: false, address: null,
  theft: null, coins: null, spend: null, nodeWords: null, proposeHash: null, noRequestTimer: null,
  items: new Map(), ownerTimer: null, ownerReading: false, skewAt: 0, handing: false, ended: false, leaving: false, holdsKeys: false,
  // v1's watch: its failed reads in a row, and how many requests its last read of the vault listed (null: no vault in it).
  ownerFails: 0, ownerPending: null,
  countTimer: null,
  // v2: the owner half's controller and drawing, and whether it has the screen (S4 on).
  owner: null, drawing: null, ownerScreen: false, recapUp: false, took: null,
  // fitOwner: the digits' size before it made them smaller.
  clockBase: 0,
  // fitIntro: the size and the words S0 was last fitted for.
  introFit: null,
};
let ctx = null;

const $ = (id) => document.getElementById(id);
const sleep = (ms) => new Promise((r) => { setTimeout(r, ms); });
const rawWords = (err) => [err?.code, err?.verbatim ?? (err?.name && err?.message ? `${err.name}: ${err.message}` : err?.message) ?? String(err)].filter(Boolean).join(': ');
const bitcoin = () => ctx?.config?.labels.bitcoin ?? 'Bitcoin';
const near = () => ctx?.config?.labels.near ?? 'NEAR';

// ---------------------------------------------------------------- marks

function mark(name) {
  const t = window.undoTimings;
  if (t && (t[name] === null || t[name] === undefined)) t[name] = performance.now();
}

// ---------------------------------------------------------------- on screen or not (R10, L1)

const isVisible = () => document.visibilityState === 'visible';
const waiters = new Set();

/** Resolves when the page is on screen: at once if it is. */
function whenVisible() {
  if (isVisible()) return Promise.resolve();
  return new Promise((resolve) => {
    const done = () => {
      waiters.delete(done);
      resolve();
    };
    waiters.add(done);
  });
}

/**
 * A pause that ends early when the page comes back on screen, so every loop reads the chain first (L1). `onWake`, when
 * given, is handed the function that ends this pause now.
 */
function nap(ms, onWake = null) {
  return new Promise((resolve) => {
    let timer = null;
    const done = () => {
      clearTimeout(timer);
      waiters.delete(done);
      resolve();
    };
    timer = setTimeout(done, ms);
    waiters.add(done);
    onWake?.(done);
  });
}

/** Holds for `ms` of time the page was on screen. Measured on the monotonic clock: a hold, not a fact on the screen. */
async function holdVisible(ms) {
  let left = ms;
  while (left > 0) {
    await whenVisible();
    const from = performance.now();
    await sleep(Math.min(left, 200));
    if (isVisible()) left -= performance.now() - from;
  }
}

function onVisibility() {
  if (isVisible()) {
    for (const done of [...waiters]) done();
    if (T.state === 'count' && T.step === 'steal') restartCount();
    if (T.v && !T.ended && !CANCEL_HERE) ownerSoon(0);
  } else if (T.state === 'count' && T.step === 'steal') {
    clearTimeout(T.countTimer);
    T.count = COUNT_FROM;
    paint();
  }
}

// ---------------------------------------------------------------- drawing

/** One line under the title: `kind` is done, now, thief, warn, owner, words, big, hash, addr or key. */
function line(key, kind, text, extra = {}) {
  const at = T.lines.findIndex((l) => l.key === key);
  const entry = { key, kind, text, ...extra };
  if (at >= 0) T.lines[at] = entry;
  else T.lines.push(entry);
  if (kind === 'now') T.lineSince = Date.now();
}
const dropLine = (...keys) => { T.lines = T.lines.filter((l) => !keys.includes(l.key)); };
const hashLine = (key, labelled, value, link) => line(key, 'hash', labelled, { value, link });

function lineNode(l) {
  if (l.kind === 'hash' || l.kind === 'addr') return h('div', { class: `ln ${l.kind === 'hash' ? 'done' : 'addr'}` }, hashBlock(l.text, l.value, l.link));
  if (l.kind === 'key') return h('div', { class: 'ln keyline', id: 'spend-key' }, h('span', { class: 'label' }, say(W.spendKey)), h('span', { class: 'mono' }, l.text));
  return h('p', { class: `ln ${l.kind}`, ...(l.id ? { id: l.id } : {}) }, l.text);
}

function paintLines() {
  const box = $('lines');
  const have = new Map([...box.children].map((n) => [n.dataset.key, n]));
  const want = new Set(T.lines.map((l) => l.key));
  for (const [key, node] of have) if (!want.has(key)) node.remove();
  let prev = null;
  for (const l of T.lines) {
    const sig = `${l.kind}|${l.text}|${l.value ?? ''}`;
    let node = have.get(l.key);
    if (node && node.dataset.sig !== sig) {
      const fresh = lineNode(l);
      fresh.dataset.key = l.key;
      fresh.dataset.sig = sig;
      node.replaceWith(fresh);
      node = fresh;
    } else if (!node) {
      node = lineNode(l);
      node.dataset.key = l.key;
      node.dataset.sig = sig;
      node.classList.add('enter');
      node.addEventListener('animationend', () => node.classList.remove('enter'), { once: true });
    }
    const after = prev ? prev.nextSibling : box.firstChild;
    if (after !== node) box.insertBefore(node, after);
    prev = node;
  }
}

/** A region drawn once per key: what is in it stays put until the key changes. */
function keyed(el, spec) {
  if (!spec) {
    if (el.dataset.key) {
      el.replaceChildren();
      delete el.dataset.key;
    }
    return;
  }
  if (el.dataset.key === spec.key) return;
  el.replaceChildren(...[spec.build()].flat(Infinity).filter(Boolean));
  el.dataset.key = spec.key;
}

function setText(el, text) {
  if (el.textContent !== text) el.textContent = text;
}

function railFor() {
  const r = { 1: '', 2: '', 3: '', 4: '' };
  if (T.step === 'intro') return r;
  r[1] = T.made ? 'done' : 'now';
  if (T.step === 'make') return r;
  r[2] = T.listed ? 'done' : 'now';
  if (T.step === 'fund') return r;
  r[3] = 'red';
  if (T.step === 'steal') return r;
  if (T.step === 'cancel') {
    r[4] = 'now';
    return r;
  }
  r[3] = 'struck';
  r[4] = 'done';
  return r;
}

function paintRail() {
  const r = railFor();
  for (const li of $('rail').children) {
    const cls = r[li.dataset.n] ?? '';
    if (li.className !== cls) li.className = cls;
  }
}

const DOC_TITLES = { intro: 'Undo · try it', make: 'Undo · 1 Make', fund: 'Undo · 2 Fund', steal: 'Undo · 3 Steal', cancel: 'Undo · Cancel it', cancelled: 'Undo · Cancelled', recap: 'Undo · Cancelled' };

function viewNow() {
  return {
    step: T.step, state: T.state, fail: T.fail, rpId: ctx?.config?.rpId ?? '', bitcoin: bitcoin(), sense: { inApp: ctx?.sense?.inApp ?? null }, mobile: Boolean(ctx?.sense?.mobile),
    limit: T.limit, still: T.state === 'making' && T.lineSince && Date.now() - T.lineSince >= STILL_AFTER_MS ? T.still : null, here: CANCEL_HERE, kind: T.kind,
    took: T.took ?? null,
  };
}

function paintCount() {
  const n = $('dock').querySelector('.n');
  if (!n) return;
  const value = T.count !== null && T.state === 'count' ? String(T.count) : T.countFrom ? String(Math.max(0, Math.floor((Date.now() - T.countFrom) / 1000))) : '';
  setText(n, value);
}

function paintCard() {
  const card = $('card');
  const on = T.card && Date.now() - T.cardFrom >= CARD_AFTER_MS;
  if (!on) {
    if (!card.hidden) {
      card.hidden = true;
      card.textContent = '';
      delete card.dataset.key;
    }
    return;
  }
  if (card.dataset.key === T.card) return;
  card.dataset.key = T.card;
  card.textContent = say(W[T.card]);
  card.hidden = false;
  card.classList.add('enter');
}

function paint() {
  const root = document.documentElement;
  if (root.dataset.step !== T.step) root.dataset.step = T.step;
  if (root.dataset.state !== T.state) root.dataset.state = T.state;
  if (T.fail) root.dataset.fail = T.fail;
  else delete root.dataset.fail;
  const docTitle = DOC_TITLES[T.step] ?? DOC_TITLES.intro;
  if (document.title !== docTitle) document.title = docTitle;
  paintRail();
  setText($('title'), T.title);
  paintLines();
  if (!T.ownerScreen) keyed($('stage'), T.stage);
  paintCard();
  keyed($('more'), T.more);
  const next = nextOf(viewNow());
  setText($('next'), next.text);
  if (next.tag) $('next').dataset.tag = next.tag;
  else delete $('next').dataset.tag;
  if (!T.ownerScreen) {
    keyed($('dock'), T.dock);
    paintCount();
  }
  keyed($('aside'), T.aside);
  fitIntro();
}

/** The page's state, and with it the screen. */
function go(step, state, fail = null) {
  const moved = T.step !== step || T.state !== state;
  T.step = step;
  T.state = state;
  T.fail = fail;
  if (moved && ctx?.awake && T.holdsKeys) ctx.awake.start();
  paint();
}

// ---- dock controls

const subLine = (text) => h('span', { class: 'sub' }, text);
const slot = (key, text, { count = false } = {}) => ({
  key: `slot:${key}:${text}`,
  build: () => h('div', { class: 'slot', id: 'slot' }, h('span', { class: 'slot-text' }, text, count ? [' · ', h('span', { class: 'n' }, ''), ' s'] : [])),
});
// The count's digits sit in a fixed slot (tabular, two wide; the 3 s count one wide), so only they change.
const countSlot = (key, entry, { one = false } = {}) => ({
  key: `slot:${key}`,
  build: () => h('div', { class: 'slot', id: 'slot' }, h('span', { class: 'slot-text' }, entry.parts[0], h('span', { class: one ? 'n one' : 'n' }, ''), entry.parts[1] ?? '')),
});
const passkeyButton = (id, text, prompt, handler) => ({
  key: `button:${id}`,
  build: () => h('button', { class: 'go two', type: 'button', id, onclick: () => handler() }, text, subLine(prompt)),
});
const actionButton = (id, text, handler, quiet = false) => ({
  key: `button:${id}:${text}`,
  build: () => h('button', { class: `go${quiet ? ' quiet' : ''}`, type: 'button', id, onclick: () => handler() }, text),
});
const watchButton = () => ({ key: 'watch', build: () => h('a', { class: 'go', id: 'watch', href: '/replay/' }, say(W.watchRun)) });
const makeButton = () => passkeyButton('make', say(W.make), say(W.prompt1), onMake);
const confirmButton = () => passkeyButton('confirm', say(W.confirm), say(W.prompt2), onConfirm);

const startOverLink = () => ({ key: 'start-over', build: () => h('p', {}, h('a', { href: '/try/', id: 'start-over', onclick: (e) => { e.preventDefault(); leave('/try/', 'assign'); } }, say(W.startOver))) });

// ---------------------------------------------------------------- boot

async function main() {
  window.undoTimings = Object.fromEntries(['makeTap', 'km', 'confirmTap', 'signed', 'powDone', 'createSent', 'active', 'fundAsked', 'coinSent', 'coinListed', 'countStart', 'stealSent', 'refused', 'proposed', 'requestSeen', 'cancelShown', 'cancelTap', 'assertion', 'cancelSent', 'cancelled', 'coinChecked'].map((k) => [k, null]));
  window.undoRun = { startWall: null, endWall: null };
  fitWordmark();
  window.addEventListener('resize', () => {
    fitWordmark();
    fitIntro();
    // After every other resize listener (the clock's own fit among them) has run.
    if (T.ownerScreen) requestAnimationFrame(() => fitOwner());
    if (T.recapUp) placeRecap(document.getElementById('recap'));
  });
  setInterval(tick, 1000);
  document.addEventListener('visibilitychange', onVisibility);
  window.addEventListener('pageshow', (event) => { if (event.persisted) onVisibility(); });
  window.addEventListener('beforeunload', (event) => {
    if (!T.holdsKeys || T.leaving) return;
    event.preventDefault();
    event.returnValue = '';
  });
  T.dock = slot('boot', say(W.loading));
  paint();

  let config;
  try {
    config = await loadConfig();
  } catch (err) {
    logRaw('the settings', rawWords(err));
    T.lines = [];
    line('why', 'warn', say(W.noConfig));
    line('words', 'words', configWords(err));
    T.dock = watchButton();
    go('intro', 'no_config', 'no_config');
    return;
  }
  $('chip').textContent = config.labels.chip;
  fitWordmark();
  const reader = new NearReader({ urls: config.rpc, ...PAGE_READS });
  const views = contractViews(reader, config.contract);
  const relay = new RelayClient({ relay: config.relay, funds: config.funds });
  const fragment = parsePhoneFragment(location.hash);
  const status = relay.status();
  let reads = { instance: started(views.instance()), block: started(reader.blockTime()) };
  const codeKeys = fragment.v ? null : started(reader.accessKeys(config.contract));
  ctx = {
    config, reader, views, relay, skew: new SkewTracker(), esplora: bitcoinReader(config.esplora), instance: null, credentials: null,
    sense: await sensePasskeys(window), awake: screenAwake(window),
  };
  try {
    ctx.credentials = await credentialsFor(config, { browser: window.navigator?.credentials, soft: config.softPasskey ? { secret: randomBytes(32), origin: location.origin } : null });
  } catch {
    ctx.credentials = null;
  }
  T.status = await status;
  for (;;) {
    try {
      ctx.instance = await reads.instance;
      ctx.skew.add(await reads.block);
      T.skewAt = Date.now();
      break;
    } catch (err) {
      logRaw('reading the NEAR contract', rawWords(err));
      T.lines = [];
      line('why', 'warn', say(W.readDown));
      T.dock = slot('read-down', say(W.readDown));
      go('intro', 'read_down', 'read_down');
      await nap(RETRY_EVERY_MS);
      reads = { instance: started(views.instance()), block: started(reader.blockTime()) };
    }
  }
  if (fragment.v) {
    drawReloaded(fragment);
    return;
  }
  T.codeKeys = codeKeys ? await answerWithin(codeKeys, CODE_KEYS_MS) : null;
  drawIntro();
}

function started(promise) {
  promise.catch(() => {});
  return promise;
}

function answerWithin(promise, ms) {
  return Promise.race([promise.catch(() => null), new Promise((r) => { setTimeout(() => r(null), ms); })]);
}

/** "Undo for Bitcoin" where it fits beside the chip; only "Undo" where it does not (the phone page's rule). */
function fitWordmark() {
  const mark = document.querySelector('.top .wordmark');
  const chip = document.getElementById('chip');
  if (!mark || !chip) return;
  mark.classList.remove('short');
  const row = mark.parentElement.getBoundingClientRect();
  const box = mark.getBoundingClientRect();
  if (box.right > row.right + 0.5 || chip.getBoundingClientRect().right + 12 > box.left) mark.classList.add('short');
}

/** Once a second: the counts, and what a wait says after a while. Only text that changes is touched. */
function tick() {
  if (!ctx) return;
  // S0's hint counts the vaults this browser made in the past hour: counted again each second while S0 is up, and drawn
  // again when the count changes (a vault passes the hour, or another tab of this browser makes one).
  if (T.step === 'intro' && T.more?.made !== undefined) {
    const more = introMore(T.more.held);
    if (more.key !== T.more.key) T.more = more;
  }
  paint();
}

// ---------------------------------------------------------------- S0

/** What stands in the way of a run, in one sentence, or null. */
function blockedWords() {
  const s = T.status;
  if (ctx.instance?.network === 'mainnet') return { why: 'mainnet', text: say(W.mainnet), again: false };
  const problem = passkeyProblem(ctx.sense) ?? (ctx.credentials ? null : 'no_webauthn');
  if (problem) return { why: problem, text: problemWords(problem), again: false };
  if (!s.reachable) return { why: 'relay_unread', text: unreadStatusWords(s), again: true };
  if (!s.general?.up) return { why: 'general', text: generalDownWords({ relay: s }), again: true };
  if (!s.funds?.up) return { why: 'funds', text: `${say(W.fundsDown)}${resetWords(s.funds?.why === 'daily_ceiling' ? s.funds.resets_at : null)}${say(W.fundsDownEnd)}`, again: true };
  if (!s.owner?.up) return { why: 'owner', text: `${say(W.ownerDown)}${say(W.ownerDownEnd)}`, again: true };
  return null;
}

function madeLately() {
  try {
    const list = JSON.parse(localStorage.getItem(MADE_KEY) ?? '[]');
    return Array.isArray(list) ? list.filter((t) => Number.isFinite(t) && Date.now() - t < HOUR_MS) : [];
  } catch {
    return [];
  }
}

function rememberMade() {
  try {
    localStorage.setItem(MADE_KEY, JSON.stringify([...madeLately(), Date.now()]));
  } catch {
    // A private window: the hint is only a hint.
  }
}

/** S0's rows, links and footer, and the hint of vaults made in the past hour. `made` and `held` let tick() count again. */
function introMore(held = false) {
  // The hint warns that a new vault may get no coin: while the run is held back there is no Make button to warn of.
  const made = held ? 0 : madeLately().length;
  return {
    key: `intro:${made >= 2 ? made : 0}:${upgradeWords(T.codeKeys)}`,
    made,
    held,
    build: () => [
      h('ol', { class: 'rows', id: 'rows' },
        [['1', 'Make', W.row1], ['2', 'Fund', W.row2], ['3', 'Steal', W.row3], ['4', 'Cancel', W.row4]].map(([n, name, entry]) => h('li', {}, h('span', { class: 'n' }, n), h('span', { class: 't' }, h('b', {}, name), ' ', say(entry))))),
      h('p', { class: 'small', id: 'three' }, say(W.three)),
      made >= 2 ? h('p', { class: 'small', id: 'made-hint' }, say(W.madeHint, made, COIN_TRIES_PER_HOUR)) : null,
      h('p', { class: 'links' }, h('a', { href: '/replay/', id: 'replay-link' }, say(W.watchRun)), h('a', { href: '/p/', id: 'two-devices' }, say(W.twoDevices))),
      h('p', { class: 'foot', id: 'foot' }, say(W.foot, addressPrefix(ctx.instance?.network) ?? 'tb1', upgradeWords(T.codeKeys))),
    ],
  };
}

/** S0, ready or with something in the way. `notice` is what the last try said (M1, M2's words, a failure). */
function drawIntro(notice = null, fail = null) {
  T.title = say(W.title);
  T.lines = [];
  T.stage = null;
  T.card = null;
  T.countFrom = null;
  const elsewhere = openElsewhere(ctx.sense);
  if (elsewhere) line('in-app', 'warn', elsewhere, { id: 'in-app' });
  const blocked = blockedWords();
  if (blocked) line('why', 'warn', blocked.text, { id: 'why' });
  if (notice) line('notice', 'warn', notice, { id: 'notice' });
  T.more = introMore(Boolean(blocked));
  if (blocked) {
    T.dock = watchButton();
    T.aside = null;
    go('intro', 'blocked', 'blocked');
    if (blocked.again) relayAgainLater();
    return;
  }
  T.dock = makeButton();
  // Inside an app's own browser the line about the app comes first: passkeys may not work there, and how to leave. The
  // hint about this browser's passkey manager would be a second answer to the same thing, under the button, on a screen
  // with no room for both on a short phone.
  const hint = elsewhere ? null : platformHint(ctx.sense);
  const soft = ctx.config.softPasskey ? (ctx.config.softPasskeyLabel ?? 'Signed by a test key in this browser.') : null;
  T.aside = hint || soft ? { key: `hint:${hint}:${soft}`, build: () => [hint ? h('p', { id: 'platform-hint' }, hint) : null, soft ? h('p', {}, soft) : null] } : null;
  go('intro', 'ready', fail);
}

// fitIntro's steps, in the order it takes them (try.css: the gaps, the type, the header and the dock, the line spacing,
// the type again).
const INTRO_STEPS = ['tight', 'tighter', 'tightest', 'dense', 'densest'];

/**
 * S0 on a short screen: every line whole in #screen with no scrolling, the footer under the links included. Measured
 * after S0 is drawn, and again when its words or the screen's size change: a screen that fits as drawn keeps its sizes;
 * one that does not gets #frame.tight (the gaps close up), then .tighter (smaller type), then .tightest, then .dense,
 * then .densest, each only while the ones before still leave #screen taller than its box. No line is hidden. The
 * classes go when the page leaves S0. .tightest draws the wordmark smaller, so "Undo for Bitcoin" or "Undo" is measured
 * again (fitWordmark) after each fit and when the classes go: a resize on S0 measured it under the old fit's sizes.
 */
function fitIntro() {
  const frame = $('frame');
  const scr = $('screen');
  if (!frame || !scr) return;
  if (T.step !== 'intro') {
    if (T.introFit !== null) {
      frame.classList.remove(...INTRO_STEPS);
      T.introFit = null;
      fitWordmark();
    }
    return;
  }
  const fitFor = `${window.innerWidth}x${window.innerHeight}|${frame.textContent}`;
  if (T.introFit === fitFor) return;
  T.introFit = fitFor;
  frame.classList.remove(...INTRO_STEPS);
  try {
    const over = () => scr.scrollHeight - scr.clientHeight;
    if (!Number.isFinite(over())) return;
    for (const step of INTRO_STEPS) {
      if (over() <= 0) return;
      frame.classList.add(step);
    }
  } finally {
    fitWordmark();
  }
}

/** The relay's status read again while it holds the run back: backed off, and only while the page is on screen. */
async function relayAgainLater() {
  if (T.relayWaiting) return;
  T.relayWaiting = true;
  try {
    for (;;) {
      await nap(RELAY_AGAIN_MS[Math.min(T.relayReads, RELAY_AGAIN_MS.length - 1)]);
      await whenVisible();
      if (T.step !== 'intro' || T.state !== 'blocked') return;
      T.relayReads += 1;
      T.status = await ctx.relay.status();
      if (T.step !== 'intro' || T.state !== 'blocked') return;
      const blocked = blockedWords();
      drawIntro();
      if (!blocked) return;
    }
  } finally {
    T.relayWaiting = false;
  }
}

/** L2: this page loaded with a vault in its address. It made no keys this time, so the phone page takes the vault. */
function drawReloaded(fragment) {
  const c = recallCredential(fragment.v) ?? fragment.c ?? null;
  T.lines = [];
  line('why', 'warn', say(W.reloaded), { id: 'reloaded' });
  T.more = null;
  T.dock = actionButton('open-phone', say(W.openPhone), () => leave(`/p/${buildPhoneFragment({ v: fragment.v, c })}`));
  T.aside = { key: 'new-run', build: () => h('p', {}, h('a', { href: '/try/', id: 'new-run', onclick: (e) => { e.preventDefault(); leave('/try/', 'assign'); } }, say(W.newRun))) };
  go('intro', 'reloaded', 'L2');
}

/** Leaves this page: drops what it holds first, so a desktop does not ask whether to leave a page whose keys it drops. */
function leave(url, how = 'replace') {
  T.leaving = true;
  T.ended = true;
  T.seed = null;
  T.keys = null;
  T.prepared = null;
  T.holdsKeys = false;
  clearTimeout(T.ownerTimer);
  clearTimeout(T.countTimer);
  T.owner?.stop();
  T.drawing?.dispose();
  if (how === 'assign') location.assign(url);
  else location.replace(url);
}

// ---------------------------------------------------------------- one passkey call at a time

function newCall() {
  const old = T.call;
  const call = { abort: new AbortController(), answered: false };
  T.call = call;
  if (old && !old.answered) old.abort.abort();
  return call;
}

// ---------------------------------------------------------------- TAP 1: Make my test vault

/** The first tap, and the retries of it. Nothing here may wait before askNewPasskey: Safari gives the sheet only to a call made in the tap. */
function onMake() {
  const call = newCall();
  const asking = askNewPasskey(ctx, {
    label: 'test vault',
    signal: call.abort.signal,
    onHang: () => {
      if (T.call !== call || call.answered) return;
      T.dock = makeButton();
      go('make', 'sheet1', 'M3');
    },
  });
  mark('makeTap');
  window.undoRun.startWall = Date.now();
  window.undoRun.endWall = null;
  ctx.awake.start();
  T.title = say(W.stepMake);
  T.lines = [];
  T.more = null;
  T.aside = null;
  T.dock = slot('passkey', say(W.waitingPasskey));
  go('make', 'sheet1');
  continueMake(asking, call);
}

async function continueMake(asking, call) {
  let passkey;
  try {
    ({ passkey } = await asking);
  } catch (err) {
    call.answered = true;
    if (T.call === call) makeFailed(err);
    return;
  }
  call.answered = true;
  if (T.call !== call) return;
  T.passkey = passkey;
  T.keys = newVaultKeys();
  T.holdsKeys = true;
  line('made', 'done', say(W.passkeyMade));
  if (passkey.flags?.backupEligible) line('sync', 'done', say(W.canSync));
  readKm();
}

/** K_m, as the signer derives it for this vault: a read between the two sheets. Read again keeps the passkey and keys. */
async function readKm() {
  line('km', 'now', say(W.readingKm));
  dropLine('notice');
  T.dock = slot('km', say(W.slotKm));
  go('make', 'km');
  let prepared;
  try {
    prepared = await prepareVault(ctx, T.passkey, { keys: T.keys });
  } catch (err) {
    logRaw('the second key', rawWords(err));
    dropLine('km');
    line('notice', 'warn', `${say(W.noVault)}${failureWords(err)}`, { id: 'notice' });
    T.dock = actionButton('read-again', say(W.readAgain), readKm);
    go('make', 'stuck', 'M4');
    return;
  }
  T.prepared = prepared;
  mark('km');
  line('km', 'done', say(W.kmRead));
  T.dock = confirmButton();
  go('make', 'confirm');
}

/** The first sheet came back with no passkey, or the call failed. The page is back where it started. */
function makeFailed(err) {
  if (err instanceof PasskeyFailed && err.kind === 'blocked') {
    logRaw('the passkey', rawWords(err));
    T.title = say(W.title);
    T.lines = [];
    line('why', 'warn', say(W.noPasskeyApp), { id: 'why' });
    T.more = null;
    T.dock = passkeyButton('retry-passkey', say(W.retryPasskey), say(W.prompt1), onMake);
    const hint = platformHint(ctx.sense);
    T.aside = hint ? { key: `hint:${hint}`, build: () => h('p', { id: 'platform-hint' }, hint) } : null;
    go('intro', 'retry', 'M2');
    return;
  }
  if (err instanceof PasskeyFailed && err.kind === 'dismissed') {
    drawIntro(say(W.noPasskey), 'M1');
    return;
  }
  logRaw('making a vault', rawWords(err));
  drawIntro(`${say(W.noVault)}${failureWords(err)}`, 'M1');
}

// ---------------------------------------------------------------- TAP 2: Confirm with your passkey

/**
 * The second tap. confirmVault signs with the four keys this page made and then asks the passkey, all before it first
 * waits, so the sheet is asked for inside this tap. Nothing here may wait before it.
 */
function onConfirm() {
  const call = newCall();
  const confirming = confirmVault(ctx, T.prepared, {
    guard: T.status.relayAccount,
    signal: call.abort.signal,
    onHang: () => {
      if (T.call !== call || call.answered) return;
      T.dock = confirmButton();
      go('make', 'sheet2', 'M6');
    },
  });
  mark('confirmTap');
  ctx.awake.start();
  dropLine('notice');
  T.dock = slot('passkey', say(W.waitingPasskey));
  go('make', 'sheet2');
  finishMake(confirming, call);
}

async function finishMake(confirming, call) {
  let args;
  try {
    ({ args } = await confirming);
  } catch (err) {
    call.answered = true;
    if (T.call !== call) return;
    // The passkey and the keys still stand, and nothing has gone to the relay: the same button, not a second passkey.
    if (err instanceof PasskeyFailed && (err.kind === 'dismissed' || err.kind === 'blocked')) {
      if (err.kind === 'blocked') logRaw('the passkey', rawWords(err));
      line('notice', 'warn', say(W.didNotSign), { id: 'notice' });
      T.dock = confirmButton();
      go('make', 'confirm', 'M5');
      return;
    }
    makeStopped(err);
    return;
  }
  call.answered = true;
  if (T.call !== call) return;
  mark('signed');
  sendIt(args);
}

/** S2a: proof of work, the relay, and the contract read until it says active. */
async function sendIt(args) {
  const { prepared } = T;
  T.countFrom = Date.now();
  T.card = 'w1';
  T.cardFrom = Date.now();
  // Step 1 so far in one line, so the step keeps to five.
  T.lines = [];
  line('made', 'done', `${say(W.passkeyMade)} ${say(W.kmRead)}`);
  line('signed', 'done', say(W.signed));
  T.dock = countSlot('making', W.slotMaking);
  go('make', 'making');
  let made;
  try {
    made = await sendVault(ctx, prepared, args, {
      powBits: T.status.powBits,
      onLine: (step, hash) => {
        if (step === 'working') line('pow', 'now', say(W.working));
        if (step === 'work') {
          mark('powDone');
          line('pow', 'done', say(W.workDone));
          // The coin's own proof of work, while the vault is being made: one solve, used by every ask (steps.askCoin).
          T.fundPow ??= solvePow(fundsPowTarget(prepared.vaultHex), T.status.powBits);
          T.fundPow.catch(() => {});
          line('send', 'now', say(W.sendingVault));
          T.still = 'relay';
        }
        if (step === 'sent') {
          mark('createSent');
          hashLine('send', nearTxLabel(ctx.config, hash), hash, nearTxLink(ctx.config, hash));
          line('active', 'now', say(W.readingActive));
          T.still = 'contract';
        }
        paint();
      },
    });
  } catch (err) {
    if (err?.sentHash) {
      vaultSentNotActive(err.sentHash);
      return;
    }
    if (err instanceof RelayRefused && !relaySentNothing(err.code)) {
      vaultUnsure(err);
      return;
    }
    makeStopped(err);
    return;
  }
  vaultActive(made.vault);
}

/** M7 and any other failure before anything was sent: no vault, and the way on. */
function makeStopped(err) {
  logRaw('making a vault', rawWords(err));
  T.card = null;
  T.countFrom = null;
  dropLine('pow', 'send', 'active');
  line('notice', 'warn', `${say(W.noVault)}${makeWhy(err)}`, { id: 'notice' });
  T.limit = err instanceof RelayRefused && err.code === 'rate_limited' && err.retryAfterS >= 120 ? 'hourly' : null;
  T.dock = watchButton();
  T.aside = startOverLink();
  T.holdsKeys = false;
  go('make', 'stuck', 'M7');
}

/** M8: the relay gave no answer, or one it can give after sending. The chain decides. */
async function vaultUnsure(err) {
  logRaw('making a vault', rawWords(err));
  dropLine('send', 'active');
  line('active', 'now', say(W.readingVault));
  T.still = 'contract';
  paint();
  const got = await steps.vaultAfterNoAnswer(ctx, T.prepared, { waitActive });
  if (got.vault) {
    vaultActive(got.vault);
    return;
  }
  // waitActive's reads may all have failed: "does not read this vault active yet" needs a read that answered (R3).
  const read = await readVaultOnce();
  if (read.vault?.active && !T.made) {
    vaultActive(read.vault);
    return;
  }
  dropLine('active');
  T.stuckWords = say(W.notActiveYet, relayOrNone(err));
  stuckLine(read);
  T.card = null;
  T.dock = actionButton('check-again', say(W.checkAgain), () => readVaultNow());
  T.aside = startOverLink();
  go('make', 'stuck', 'M8');
  readVaultLater();
}

/** M9: the relay sent the creation, and the contract has not read it active in the time the page gives it. */
async function vaultSentNotActive(hash) {
  // As M8: the sentence is the answer of a read, so one is made here, and a read that fails says only that.
  const read = await readVaultOnce();
  if (read.vault?.active && !T.made) {
    vaultActive(read.vault);
    return;
  }
  dropLine('active');
  hashLine('send', nearTxLabel(ctx.config, hash), hash, nearTxLink(ctx.config, hash));
  T.stuckWords = say(W.sentNotActive);
  stuckLine(read);
  T.card = null;
  T.dock = actionButton('check-again', say(W.checkAgain), () => readVaultNow());
  go('make', 'stuck', 'M9');
  readVaultLater();
}

/**
 * M8 and M9's line, from the last read of the vault: the row's sentence when the node answered (the vault inactive, or
 * not there yet), "Can't read the NEAR contract right now." when it did not, since then nothing was read.
 */
function stuckLine(read) {
  line('notice', 'warn', read.ok ? T.stuckWords : say(W.readDown), { id: 'notice' });
}

/** Every 15 s while on screen, and on Check again: one read of the vault. Active goes on. */
async function readVaultLater() {
  while (T.step === 'make' && T.state === 'stuck' && !T.made) {
    await nap(SLOW_EVERY_MS);
    await whenVisible();
    if (await readVaultNow()) return;
  }
}

async function readVaultNow() {
  if (T.made || !T.prepared) return true;
  T.vaultReads += 1;
  const seq = T.vaultReads;
  const read = await readVaultOnce();
  if (T.made) return true;
  if (read.vault?.active) {
    vaultActive(read.vault);
    return true;
  }
  // M8, M9: the line follows the reads, as T7's does. Only the latest read's answer: an older one may come back after it.
  if (seq === T.vaultReads && T.step === 'make' && T.state === 'stuck' && (T.fail === 'M8' || T.fail === 'M9')) {
    stuckLine(read);
    paint();
  }
  return false;
}

/** One read of this vault: `ok` says whether the node answered (with the vault, or with none), `vault` what it gave. */
async function readVaultOnce() {
  try {
    return { ok: true, vault: await ctx.views.vault(T.prepared.vaultHex) };
  } catch {
    return { ok: false, vault: null };
  }
}

/** The contract reads the vault active: this page now holds its keys, and the address bar names it for a reload (R6). */
function vaultActive(vault) {
  const { prepared } = T;
  T.made = true;
  T.v = prepared.vaultHex;
  T.vault = vault;
  T.address = vault.address;
  T.seed = prepared.keys.seed;
  T.credB64 = credentialToFragment(prepared.passkey.credentialId);
  rememberCredential(T.v, T.credB64);
  writeFragment({ v: T.v, c: T.credB64 });
  rememberMade();
  mark('active');
  line('active', 'done', say(W.active, near()));
  dropLine('notice');
  paint();
  if (CANCEL_HERE) startOwnerHalf(prepared.passkey.credentialId);
  else ownerSoon(0);
  fund();
}

// ---------------------------------------------------------------- S2b: the coin

/** Step 2: the relay is asked for a test coin, only while the page is on screen (R10), and Esplora decides when it is here. */
async function fund() {
  T.title = say(W.stepFund);
  T.lines = [];
  line('active', 'done', say(W.active, near()));
  line('address', 'addr', btcAddressLabel(ctx.config, T.address), { value: T.address, link: btcAddressLink(ctx.config, T.address) });
  T.countFrom = Date.now();
  T.card = 'w2';
  T.cardFrom = Date.now();
  T.dock = countSlot('funding', W.slotFunding);
  T.aside = null;
  go('fund', 'funding');
  T.fundPow ??= solvePow(fundsPowTarget(T.v), T.status.powBits);
  T.theftReady = prepTheft();
  askForCoin();
}

async function askForCoin() {
  T.coinRun = null;
  line('coin', 'now', say(W.askingCoin));
  dropLine('notice', 'sent', 'list', 'nocoin', 'btc-down');
  T.dock = countSlot('funding', W.slotFunding);
  go('fund', 'funding');
  let paid;
  try {
    paid = await steps.askCoin(ctx, {
      vaultHex: T.v,
      pow: T.fundPow,
      whenVisible: async () => {
        await whenVisible();
        mark('fundAsked');
      },
    });
  } catch (err) {
    coinRefused(err);
    return;
  }
  mark('coinSent');
  hashLine('coin', btcTxLabel(ctx.config, paid.txid), paid.txid, btcTxLink(ctx.config, paid.txid));
  if (Number.isSafeInteger(paid.value)) line('sent', 'done', say(W.relaySent, satsText(paid.value)));
  awaitCoin({ everyMs: LIST_EVERY_MS, forMs: LIST_FOR_MS, then: 'D3' });
}

/** D1 or D2: the relay said no, or said nothing this page can read as no. */
function coinRefused(err) {
  logRaw('test coins', rawWords(err));
  // Only a refusal before the relay sent anything says no coin was sent. With no answer, a code it can give after the
  // coin went out, or a short rate_limited (another ask for this vault holds the relay's claim, and its coin may be on
  // its way), the page can't tell, and Esplora decides.
  const unsure = err instanceof RelayRefused && (!FUND_UNSENT.has(err.code) || (err.code === 'rate_limited' && !(err.retryAfterS > 120)));
  if (!unsure) {
    dropLine('coin');
    line('notice', 'warn', `${say(W.noCoins)}${fundWhy(err, ctx)}`, { id: 'notice' });
    T.dock = watchButton();
    go('fund', 'stuck', 'D1');
    awaitCoin({ everyMs: SLOW_EVERY_MS, forMs: Infinity, then: 'D1' });
    return;
  }
  dropLine('coin');
  line('notice', 'warn', say(W.cantTellCoin, err.code === 'relay_down' ? say(W.relayNoAnswer) : relayClause(err.code)), { id: 'notice' });
  go('fund', 'funding');
  awaitCoin({ everyMs: UNSURE_LIST_EVERY_MS, forMs: LIST_FOR_MS, then: 'D2' });
}

/**
 * Reads the vault's address until Esplora lists a coin there: every `everyMs` for `forMs`, then every 15 s while on
 * screen, saying what it can't find yet (`then`: D3 after a coin the relay sent, D2 after an answer the page can't
 * read as no, D1 after a refusal, which reads every 15 s from the start). A read that fails says so, and the next
 * comes in 5 s (D4).
 */
async function awaitCoin({ everyMs, forMs, then }) {
  const run = {};
  T.coinRun = run;
  const from = Date.now();
  let late = then === 'D1';
  for (;;) {
    if (T.coinRun !== run || T.step !== 'fund' || T.ended) return;
    let coins;
    try {
      coins = steps.coinsOf(await ctx.esplora.utxos(T.address));
    } catch (err) {
      if (T.coinRun !== run) return;
      if (T.fail !== 'D4') logRaw(`can't read ${bitcoin()}`, rawWords(err));
      dropLine('list');
      line('btc-down', 'warn', say(W.btcDown, bitcoin()), { id: 'btc-down' });
      go('fund', 'stuck', 'D4');
      await nap(RETRY_EVERY_MS);
      continue;
    }
    if (T.coinRun !== run || T.ended) return;
    if (coins.length) {
      coinListed(coins);
      return;
    }
    dropLine('btc-down');
    if (!late && Date.now() - from >= forMs) {
      late = true;
      if (then === 'D3') {
        dropLine('list');
        line('notice', 'warn', say(W.notListedYet, bitcoin()), { id: 'notice' });
      } else if (then === 'D2') {
        line('nocoin', 'warn', say(W.noCoinYet, bitcoin()), { id: 'nocoin' });
        T.dock = actionButton('ask-again', say(W.askAgain), () => askForCoin());
      }
    }
    if (!late && then === 'D3') line('list', 'now', say(W.waitingList, bitcoin()));
    if (late) go('fund', 'stuck', then);
    else go('fund', 'funding');
    if (late) {
      await nap(SLOW_EVERY_MS);
      await whenVisible();
    } else await nap(everyMs);
  }
}

function coinListed(coins) {
  T.coinRun = null;
  T.listed = true;
  T.coins = coins;
  mark('coinListed');
  dropLine('list', 'notice', 'nocoin', 'btc-down');
  const total = coins.reduce((sum, c) => sum + c.value, 0);
  line('balance', 'big', satsText(total), { id: 'balance' });
  T.card = null;
  // A step-2 read of the script or the fee that failed is waiting out its pause: it reads again now (prepTheft).
  T.prepWake?.();
  // armSteal draws step 3 before its first await, so step 2's screen, which waits for this listing, is never drawn
  // beside the listed coin.
  armSteal();
}

// ---------------------------------------------------------------- S3: the thief, played by this page

/** The thief half's checks that need no coin, started with step 2 (the script, a fee rate, a destination). */
async function prepTheft() {
  for (;;) {
    try {
      T.theft = await steps.theftPrep(ctx, { vaultHex: T.v, vault: T.vault, network: ctx.instance.network });
      return null;
    } catch (err) {
      if (err.code === 'script_mismatch') return err;
      if (T.listed) return err;
      // coinListed ends this pause, so step 3's checks read again the moment the coin is listed: step 2's Next line
      // says step 3 starts by itself then, and it does not sit out the rest of these 5 s first.
      await nap(RETRY_EVERY_MS, (wake) => { T.prepWake = wake; });
      T.prepWake = null;
    }
  }
}

/**
 * With the coin listed: every check, then the count, only while the page is on screen. Step 3's checking screen goes up
 * at once, the listed balance and "Checking before the theft · N s", while the checks' reads are out (the script and
 * the fee read again when step 2's failed, check_propose, the relay's status): step 2's lines wait for this listing.
 */
async function armSteal() {
  T.title = say(W.stepSteal);
  T.lines = T.lines.filter((l) => l.key === 'balance');
  T.countFrom = Date.now();
  T.dock = countSlot('checking', W.slotChecking);
  go('steal', 'checking');
  for (;;) {
    if (T.ended) return;
    const why = await stealChecks();
    if (!why) break;
    if (why.final) return;
    await nap(why.everyMs ?? RETRY_EVERY_MS);
    await whenVisible();
  }
  T.lines = [];
  line('thief', 'thief', say(W.thief), { id: 'thief' });
  line('key', 'key', `${toHex(T.seed).slice(0, 8)}…${toHex(T.seed).slice(-4)}`);
  line('sends', 'now', say(W.sendsTo));
  T.stage = null;
  T.countFrom = null;
  startCount();
}

/** Null when the theft can go, or what stops it now, drawn: T1, T1r (retried), T1b, T2 (final). */
async function stealChecks() {
  const stuck = (fail, text, { final = false, everyMs, dock } = {}) => {
    T.lines = T.lines.filter((l) => l.key === 'balance');
    line('notice', 'warn', text, { id: 'notice' });
    // "Checking before the theft · N s" counts from when step 3's checks began (armSteal's checking screen), and on
    // through their retries: not from step 2's start, whose coin wait is not this check.
    if (T.step !== 'steal' || (T.state !== 'stuck' && T.state !== 'checking')) T.countFrom = Date.now();
    T.dock = dock ?? (final ? actionButton('start-over', say(W.startOver), () => leave('/try/', 'assign')) : countSlot('checking', W.slotChecking));
    go('steal', 'stuck', fail);
    return { fail, final, everyMs };
  };
  // The fee rate this check uses was read in this call (not at step 2's start), so a sentence about it is about now.
  const fresh = !T.theft;
  if (!T.theft) {
    const err = await T.theftReady;
    if (err?.code === 'script_mismatch') return stuck('T1b', say(W.scriptWrong), { final: true });
    if (!T.theft) {
      T.theftReady = prepTheft();
      const again = await T.theftReady;
      if (again?.code === 'script_mismatch') return stuck('T1b', say(W.scriptWrong), { final: true });
      if (!T.theft) return stuck('T1', again?.code === 'btc_down' ? say(W.btcDown, bitcoin()) : say(W.readDown));
    }
  }
  try {
    const { spend } = await steps.checkTheft(ctx, { vaultHex: T.v, coins: T.coins, to: T.theft.to, script: T.theft.script, feeRate: T.theft.feeRate });
    if (spend.short) {
      // Listed, and at the theft's fee rate the fee would take every sat of it. Not step 2 again: Mutinynet lists the coin,
      // and reading it again at once would find the same coin with no pause. The rate is read again (prepTheft) before
      // this is said, and on each try every 5 s while the page is on screen; the theft goes on when the fee leaves sats.
      T.theft = null;
      if (!fresh) return stealChecks();
      return stuck('T1', say(W.feeTakesAll));
    }
    T.spend = spend;
  } catch (err) {
    if (err instanceof ViewRefused) {
      logRaw('check_propose refused', err.verbatim);
      return stuck('T2', contractWords(err.verbatim), { final: true });
    }
    return stuck('T1', say(W.readDown));
  }
  const status = await ctx.relay.status();
  T.status = status.reachable ? status : T.status;
  if (!status.reachable || !status.general?.up) {
    T.relayHolds = (T.relayHolds ?? 0) + 1;
    return stuck('T1r', status.reachable ? say(W.relaySaysNo) : say(W.relayHolds, unreadRelayWords(status)), { everyMs: RELAY_AGAIN_MS[Math.min(T.relayHolds - 1, RELAY_AGAIN_MS.length - 1)] });
  }
  return null;
}

/** A coin that is gone from the node's list, or too small to pay its fee: step 2 again, reading until one is there. */
function backToFund() {
  T.listed = false;
  T.title = say(W.stepFund);
  T.lines = [];
  line('active', 'done', say(W.active, near()));
  line('address', 'addr', btcAddressLabel(ctx.config, T.address), { value: T.address, link: btcAddressLink(ctx.config, T.address) });
  T.stage = null;
  T.dock = countSlot('funding', W.slotFunding);
  T.countFrom = Date.now();
  go('fund', 'funding');
  awaitCoin({ everyMs: LIST_EVERY_MS, forMs: LIST_FOR_MS, then: 'D3' });
}

/** S3a: 3, 2, 1, only while the page is on screen. Hidden stops it; shown again, it starts at 3. */
function startCount() {
  T.count = COUNT_FROM;
  T.dock = countSlot('count', W.slotCount, { one: true });
  go('steal', 'count');
  mark('countStart');
  clearTimeout(T.countTimer);
  if (isVisible()) T.countTimer = setTimeout(countTick, 1000);
}

function restartCount() {
  clearTimeout(T.countTimer);
  T.count = COUNT_FROM;
  paint();
  T.countTimer = setTimeout(countTick, 1000);
}

function countTick() {
  if (T.step !== 'steal' || T.state !== 'count' || T.ended) return;
  if (T.count > 1) {
    T.count -= 1;
    paint();
    T.countTimer = setTimeout(countTick, 1000);
    return;
  }
  steal();
}

/** S3b: everything, with the spend key alone, straight to Bitcoin. One POST. */
async function steal() {
  T.count = null;
  T.dock = slot('sending', say(W.slotSending));
  go('steal', 'sending');
  mark('stealSent');
  const answer = await steps.sendKeyAlone(ctx, { address: T.address, seed: T.seed, script: T.theft.script, to: T.theft.to, feeRate: T.theft.feeRate, visible: isVisible });
  if (T.ended) return;
  if (answer.hidden) {
    startCount();
    return;
  }
  if (answer.none) {
    backToFund();
    return;
  }
  T.spend = answer.spend;
  if (answer.kind === 'accepted') {
    // The kill line for the whole product. Nothing else runs on this page: the owner watch stops reading too.
    T.ended = true;
    clearTimeout(T.ownerTimer);
    T.owner?.stop();
    T.lines = [];
    line('accepted', 'warn', say(W.accepted), { id: 'accepted' });
    line('txid', 'words', btcTxLabel(ctx.config, answer.body));
    T.dock = null;
    T.card = null;
    go('steal', 'stuck', 'T3');
    return;
  }
  if (answer.kind === 'rejected' && answer.refusal === 'script') {
    mark('refused');
    showRefused(answer.body);
    return;
  }
  T.lines = [];
  if (answer.kind === 'rejected') {
    logRaw(`${bitcoin()} node`, answer.body);
    line('notice', 'warn', say(W.otherRefusal), { id: 'notice' });
    line('words', 'words', nodeRefusalWords(answer.body));
    T.dock = actionButton('try-again', say(W.tryAgain), () => retrySend());
    go('steal', 'stuck', 'T4');
    return;
  }
  logRaw(`no answer from the ${bitcoin()} node (HTTP ${answer.status ?? 'none'})`, answer.body || answer.error || 'an empty answer');
  line('notice', 'warn', say(W.noNode), { id: 'notice' });
  line('words', 'words', noNodeWords(answer));
  T.dock = actionButton('try-again', say(W.tryAgain), () => retrySend());
  go('steal', 'stuck', 'T5');
}

/** T4, T5: the coins read again, and one more POST. A tap, but no sheet: nothing here needs the gesture. */
function retrySend() {
  T.lines = [];
  line('thief', 'thief', say(W.thief), { id: 'thief' });
  steal();
}

/** S3c: the red bar and the node's own bytes, held 3 s, then the thief asks the NEAR contract. */
async function showRefused(body) {
  T.nodeWords = body;
  T.lines = [];
  T.stage = {
    key: 'refused',
    build: () => [
      h('div', { class: 'bar-red slide', id: 'bar' }, h('div', { class: 'b1' }, say(W.refused1)), h('div', { class: 'b2' }, say(W.refused2))),
      h('p', { class: 'caption', id: 'needs' }, say(W.needs)),
      h('div', { class: 'node', id: 'node' }, h('div', { class: 'node-label', id: 'node-label' }, say(W.nodeLabel, bitcoin())), nodeText(body)),
    ],
  };
  T.dock = slot('refused', say(W.slotRefused));
  go('steal', 'refused');
  await holdVisible(REFUSED_HOLD_MS);
  if (T.ended || T.step !== 'steal') return;
  ask();
}

/** The node's answer, byte for byte, with the phrase that is about the missing signature picked out. */
function nodeText(body) {
  const box = h('div', { class: 'node-text', id: 'node-text' });
  const at = body.indexOf(KEY_PHRASE);
  if (at >= 0) box.append(body.slice(0, at), h('span', { class: 'key-phrase' }, KEY_PHRASE), body.slice(at + KEY_PHRASE.length));
  else box.textContent = body;
  return box;
}

/** S3d: the thief asks the NEAR contract. What it finds out comes from its own reads; the owner half reads separately. */
async function ask() {
  T.stage = null;
  T.lines = [];
  line('node-row', 'done', say(W.refusedRow, bitcoin()), { id: 'node-row' });
  line('ask', 'now', say(W.askingNear));
  T.countFrom = Date.now();
  T.card = 'w3';
  T.cardFrom = Date.now();
  T.dock = countSlot('asking', W.slotAsking);
  clearTimeout(T.noRequestTimer);
  go('steal', 'asking');
  let sent;
  try {
    // R10: proposeTheft posts only while the page is on screen. Hidden after its reads, it holds with this screen as it
    // is (nothing here says the request was sent until the relay answers), and reads again once the page is shown.
    sent = await steps.proposeTheft(ctx, { vaultHex: T.v, script: T.theft.script, seed: T.seed, spend: T.spend, to: T.theft.to, visible: isVisible, whenVisible });
  } catch (err) {
    if (T.step === 'steal') askFailed(err);
    return;
  }
  mark('proposed');
  T.proposeHash = sent.hash;
  if (T.step !== 'steal') return;
  hashLine('ask', nearTxLabel(ctx.config, sent.hash), sent.hash, nearTxLink(ctx.config, sent.hash));
  paint();
  try {
    await steps.findRequest(ctx, { vaultHex: T.v, seenBefore: sent.seenBefore, hash: sent.hash, relayAccount: T.status.relayAccount, forMs: NO_REQUEST_MS, stop: () => T.step !== 'steal' || T.ended });
  } catch (err) {
    if (T.step === 'steal' && !T.ended) askFailed(err);
  }
}

/** The thief's two lines for a proposal that failed (thief.mjs showAskFailure), with this tab read as this page. */
function askTerm(err) {
  if (err?.code === 'relay_down') return say(W.proposeDown);
  if (err?.code === 'daily_ceiling') return say(W.proposeCeiling);
  const answered = err?.code === 'contract_refused' || (err?.code === 'would_refuse' && err?.verbatim);
  if (answered) return say(W.proposeRefused);
  if (err?.code === 'no_request') return say(W.proposeNoRequest);
  if (!err?.code || relaySentNothing(err.code)) return say(W.proposeNotAsked);
  return say(W.proposeCantTell);
}

function askWhy(err) {
  if (err?.code === 'relay_down' || err?.code === 'daily_ceiling' || err?.code === 'no_request') return '';
  if (err?.code === 'contract_refused') return contractWords(err.verbatim);
  if (err instanceof ViewRefused) return contractWords(err.verbatim);
  if (err instanceof RpcDown || err instanceof StaleRead) return say(W.readDown);
  if (err?.code) return relayWords(err);
  return say(W.proposeError);
}

/** T6, T7, T8. Try again asks the contract only: Bitcoin is not asked again. */
function askFailed(err) {
  logRaw('asking the NEAR contract', rawWords(err));
  if (T.proposeHash === null || err?.code !== 'no_request') dropLine('ask');
  line('term', 'warn', askTerm(err), { id: 'term' });
  const why = askWhy(err);
  if (why) line('ask-why', 'words', why, { id: 'ask-why' });
  else dropLine('ask-why');
  const retry = actionButton('try-again', say(W.tryAgain), () => {
    dropLine('term', 'ask-why', 'no-request');
    T.proposeHash = null;
    ask();
  });
  if (err?.code === 'relay_down') {
    // The chain decides: the owner half is reading the contract, and a request it finds goes on from here (T7).
    T.dock = countSlot('asking', W.slotAsking);
    go('steal', 'asking');
    clearTimeout(T.noRequestTimer);
    T.noRequestTimer = setTimeout(() => {
      if (T.step !== 'steal' || T.ended) return;
      noRequestLine();
      T.dock = retry;
      go('steal', 'stuck', 'T7');
    }, NO_REQUEST_MS);
    return;
  }
  T.dock = retry;
  go('steal', 'stuck', err?.code === 'no_request' || err?.code === 'contract_refused' ? 'T8' : 'T6');
}

/**
 * T7's second line, from the owner watch's own reads, and kept to them while T7 is up (each read that changes what they
 * say draws it again). "The contract lists no request for this vault yet." only when the last read got the vault and its
 * list of requests was empty. While the reads fail: only that the contract can't be read, since a request may be there.
 * A read with no vault in it (a node behind), or one that lists an id the watch has not read yet: no line.
 */
function noRequestLine() {
  const watch = CANCEL_HERE ? T.owner?.view() : { readDown: T.ownerFails >= READ_FAILS_TO_SAY, pendingListed: T.ownerPending };
  if (watch?.readDown) line('no-request', 'warn', say(W.readDown), { id: 'no-request' });
  else if (watch?.pendingListed === 0) line('no-request', 'warn', say(W.noRequestYet), { id: 'no-request' });
  else dropLine('no-request');
}

/** While T7 is up, its second line follows the owner watch's reads. */
function noRequestFollows() {
  if (T.step !== 'steal' || T.fail !== 'T7' || T.ended) return;
  noRequestLine();
  paint();
}

// ---------------------------------------------------------------- the owner half: only the contract (R4)

function ownerSoon(ms) {
  clearTimeout(T.ownerTimer);
  if (T.ended) return;
  T.ownerTimer = setTimeout(ownerTick, ms);
}

async function ownerTick() {
  if (T.ended || !T.v) return;
  if (!isVisible()) return; // visibilitychange reads again at once
  if (T.ownerReading) return;
  T.ownerReading = true;
  try {
    if (Date.now() - T.skewAt >= SKEW_EVERY_MS) {
      ctx.skew.add(await ctx.reader.blockTime());
      T.skewAt = Date.now();
    }
    const { vault } = await steps.readOwner(ctx, { vaultHex: T.v, items: T.items });
    T.ownerFails = 0;
    T.ownerPending = vault ? vault.pending.length : null;
    noRequestFollows();
    onOwnerRead(steps.ownerFocus(T.items));
  } catch {
    // A node that did not answer: the next tick reads again.
    T.ownerFails = (T.ownerFails ?? 0) + 1;
    noRequestFollows();
  } finally {
    T.ownerReading = false;
  }
  ownerSoon(OWNER_EVERY_MS);
}

/** What the contract says, and only that, moves the page to step 4. */
function onOwnerRead(focus) {
  if (T.ended || T.handing || focus.kind === 'none') return;
  mark('requestSeen');
  if (focus.kind === 'request' || focus.why === 'second') {
    const id = focus.item?.id ?? Math.max(...[...T.items.values()].filter((i) => i.state?.cancellable).map((i) => i.id));
    handOff(Number.isSafeInteger(id) ? id : null);
    return;
  }
  // The request moved on (C11): only the phone page draws that.
  T.handing = true;
  stopThief();
  T.title = say(W.stepCancel);
  T.lines = [];
  T.stage = null;
  line('notice', 'warn', say(W.notWaiting), { id: 'notice' });
  T.dock = actionButton('open-phone', say(W.openPhone), () => leave(`/p/${buildPhoneFragment({ v: T.v, r: focus.item?.id ?? null, c: T.credB64 })}`));
  go('cancel', 'stuck', 'C11');
}

/** The thief half stops where it is: its key is dropped, and its loops end. */
function stopThief() {
  T.seed = null;
  clearTimeout(T.countTimer);
  clearTimeout(T.noRequestTimer);
  T.coinRun = null;
}

/** v1, S4: seen on the contract, then this tab becomes the phone page for this request. */
async function handOff(id) {
  T.handing = true;
  stopThief();
  T.title = say(W.stepCancel);
  T.stage = null;
  T.card = null;
  T.countFrom = null;
  T.lines = T.lines.filter((l) => l.key === 'node-row' || l.key === 'ask');
  if (T.lines.find((l) => l.key === 'ask')?.kind === 'now') dropLine('ask');
  line('seen', 'owner', say(W.seen), { id: 'seen' });
  T.dock = slot('opening', say(W.slotOpening));
  go('cancel', 'handoff');
  await holdVisible(SEEN_HOLD_MS);
  leave(`/p/${buildPhoneFragment({ v: T.v, r: id, c: T.credB64 })}`);
}

// ---------------------------------------------------------------- v2: the owner half on this page (owner.mjs)

/** Starts the owner watch on the vault the contract reads active. What it draws comes only from the contract (R4). */
function startOwnerHalf(credentialId) {
  T.owner = startOwner(ctx, { vaultHex: T.v, credentialId, status: T.status, cancelHere: true, onView: onOwnerView, mark });
}

/** TAP 3. The owner half's cancelTap is the first thing it does: the digest was made before the tap (THE RULE). */
function onCancel() {
  T.owner.cancelTap();
}

/** Each view of the owner half. While it only watches, the thief half has the screen; from the request on, it does. */
function onOwnerView(view) {
  if (T.ended) return;
  if (view.state === 'watching') {
    noRequestFollows();
    return;
  }
  if (!T.ownerScreen) takeScreen();
  if (view.step === 'cancelled' && window.undoRun.endWall === null && !T.cancelledSeen) {
    T.cancelledSeen = true;
    window.undoRun.endWall = view.cancelledWall ?? Date.now();
    // Only a time both of whose ends this page measured: the Make tap and the read of CANCELLED, on the wall clock.
    if (window.undoRun.startWall !== null) T.took = runTime(window.undoRun.endWall - window.undoRun.startWall);
  }
  T.drawing.draw(view);
  T.kind = view.kind;
  if (T.recapUp) go('recap', 'recap');
  else go(view.step ?? 'cancel', view.state, view.fail ?? null);
  fitOwner();
}

/**
 * S4 to S7: every line of the owner half's block whole in #screen at its top, with no scrolling (the control is in the
 * dock, under it). Measured, step by step, because fonts and phones differ, and a screen the drawing already fits is left
 * as it is. While the request waits, from scratch at each view and size: the two empty slots under the clock, made for
 * CANCELLED's two lines, give up their room; then the digits get smaller, to 60% of their size; then the small lines
 * close up, and the digits are fitted again, down to 40%. Once CANCELLED it only tightens: the two slots are back for
 * their lines, and the digits stay the size they stopped at, with everything above them where it was, unless the lines
 * need more room. No line is hidden, and the line under the clock starts below the stamp.
 */
function fitOwner() {
  const scr = $('screen');
  const digits = $('digits');
  if (!T.ownerScreen || !scr || !digits) return;
  const over = () => scr.scrollHeight - scr.clientHeight;
  if (!Number.isFinite(over())) return;
  const frozen = Boolean($('stamp'));
  if (!frozen) {
    scr.classList.remove('roomy', 'small-digits', 'packed');
    // The clock's own fit may have measured while this one's size held the digits (a resize, a new minute digit): it
    // measures again now, with nothing of this fit's on.
    T.drawing?.fitClock?.();
    T.clockBase = Number.parseFloat(getComputedStyle(digits).fontSize) || 0;
  } else {
    scr.classList.remove('roomy');
    T.clockBase ||= Number.parseFloat(getComputedStyle(digits).fontSize) || 0;
  }
  clearStamp();
  if (over() <= 0) return;
  const shrinkTo = (fraction) => {
    const floor = Math.floor(T.clockBase * fraction);
    for (let i = 0; i < 6 && over() > 0; i += 1) {
      const now = Number.parseFloat(getComputedStyle(digits).fontSize);
      const to = Math.max(floor, Math.floor(now - over()));
      if (!(to < now)) return;
      scr.style.setProperty('--owner-clock', `${to}px`);
      scr.classList.add('small-digits');
      clearStamp();
    }
  };
  if (frozen) {
    scr.classList.add('packed');
    clearStamp();
    shrinkTo(0.4);
    return;
  }
  scr.classList.add('roomy');
  if (over() <= 0) return;
  shrinkTo(0.6);
  if (over() <= 0) return;
  scr.classList.add('packed');
  scr.classList.remove('small-digits');
  shrinkTo(0.4);
}

/**
 * CANCELLED: the stamp sits from the middle of the clock's box down, so it hangs under the box by its own height less
 * half the box's. The first line under the clock (the key line) starts under it. Layout sizes, not the slam's transform.
 */
function clearStamp() {
  const clip = $('stamp')?.parentElement;
  const block = $('clockblock');
  const key = $('key-line');
  if (!clip || !block || !key) return;
  key.style.marginTop = '';
  const hang = clip.offsetTop + clip.offsetHeight - block.offsetHeight;
  const margin = Number.parseFloat(getComputedStyle(key).marginTop) || 0;
  if (hang + 2 > margin) key.style.marginTop = `${Math.ceil(hang + 2)}px`;
}

/**
 * The recap sheet's place (owner.mjs recapPlace): under the stamp and above the Done line where the screen has the room,
 * else over the request's lines above the clock, so the stamp, the digits and the Done line stay in sight. Placed again
 * when the screen's height changes (the browser's bars).
 */
function placeRecap(sheet) {
  if (!sheet) return;
  const box = (id) => document.getElementById(id)?.getBoundingClientRect() ?? null;
  const frame = box('frame');
  const next = box('next');
  const stamp = box('stamp');
  const clock = box('clockblock');
  const at = recapPlace({
    frame, screenTop: box('screen').top, nextTop: next.top, stampBottom: stamp?.bottom ?? clock?.bottom ?? frame.top, clockTop: clock?.top ?? frame.top,
  });
  sheet.classList.toggle('above', at.where === 'above');
  sheet.style.top = at.top === null ? 'auto' : `${at.top}px`;
  sheet.style.bottom = at.bottom === null ? 'auto' : `${at.bottom}px`;
  sheet.style.maxHeight = `${at.maxHeight}px`;
}

/** S4: the thief half stops, its lines go, and the owner half's block and dock take the stage. */
function takeScreen() {
  T.ownerScreen = true;
  T.handing = true;
  stopThief();
  clearTimeout(T.noRequestTimer);
  T.title = '';
  T.lines = [];
  T.stage = null;
  T.card = null;
  T.countFrom = null;
  T.aside = null;
  T.more = null;
  for (const id of ['stage', 'dock']) {
    $(id).replaceChildren();
    delete $(id).dataset.key;
  }
  T.drawing = ownerDrawing({
    owner: T.owner,
    config: ctx.config,
    block: $('stage'),
    dock: $('dock'),
    sheet: $('frame'),
    onCancel,
    onHandoff: () => leave(T.owner.handoffPath()),
    onRecap: (sheet) => {
      placeRecap(sheet);
      T.recapUp = true;
      // The run is over: the screen may sleep, and leaving needs no question.
      T.holdsKeys = false;
      ctx.awake.stop();
      go('recap', 'recap');
    },
    thief: () => ({ refused: Boolean(T.nodeWords), nodeWords: T.nodeWords, proposeHash: T.proposeHash }),
    mark,
  });
}

main().catch((err) => {
  logRaw('the page', rawWords(err));
  T.lines = [];
  line('why', 'warn', say(W.crashed));
  T.dock = T.v ? actionButton('open-phone', say(W.openPhone), () => leave(`/p/${buildPhoneFragment({ v: T.v, c: T.credB64 })}`)) : watchButton();
  go(T.step, 'crashed', T.v ? 'crashed' : 'blocked');
});
