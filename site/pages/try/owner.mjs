// The owner half of /try/, and its Cancel. What it says of the theft comes only from the NEAR contract, read here: the
// vault, the ids it lists and each request, never anything the thief half of this page holds (R4). It handles one
// request, the first the contract lists for this vault; anything else is the phone page's (C11).
//
// startOwner is DOM-free, so try-owner.test.mjs runs it in Node with made-up reads, relay, passkey and clock. It reads with
// steps.mjs readOwner, judges with site/lib's requestState, advanceState and cancelButton, and signs lib's rotateDigest:
// none of that is written again here. ownerDrawing, at the end, draws S4 to S7 with kit.mjs; try.mjs calls it only when
// CANCEL_HERE is true. In v1 try.mjs uses the same watch and hands off to /p/ when it reads a request.
//
// THE RULE. cancelTap is the Cancel button's work, called first thing by the button's listener (try.mjs onCancel).
// Nothing in it awaits, fetches or sets a timer before askAssertion: the digest it signs was made before the tap
// (ensurePrep, renewed by each read while the request waits), and the rest is plain bookkeeping.
import {
  btcAddressLabel, btcAddressLink, cancelButton, clock, contractWords, credentialToFragment, digits, logRaw, nearTxLabel, nearTxLink,
  passkeyWords, refusalOf, RelayRefused, relaySentNothing, relayWords, rotateArgs, rotateDigest, rpIdHashOf, RpcDown, spendKeys,
  spkToAddress, StaleRead, waitWords,
} from '/site/lib/index.mjs';
import { fromHex, toHex } from '/tools/lib/bytes.mjs';
import { randomBytes } from '/tools/lib/crypto.mjs';
import { ClockFace, h, hashBlock, satsText, sumInputs } from '../p/kit.mjs';
import { askAssertion, PasskeyFailed } from '../p/passkey-ask.mjs';
import { buildPhoneFragment } from '../p/phone-fragment.mjs';
import { passkeyProblem, problemWords } from '../p/sense.mjs';
import { chainNowOf } from '../p/vault-make.mjs';
import { coinStill, readOwner } from './steps.mjs';
import { failureWords, noCancelWords, say, W } from './words.mjs';

const POLL_MS = 1000;
// While a cancel is out, the contract is read faster, as /p/ does.
const FAST_POLL_MS = 400;
const SKEW_MS = 5000;
const STATUS_MS = 30_000;
// While a request can be cancelled, a Cancel that can no longer work must not stay up for long (phone.mjs).
const STATUS_DOWN_MS = 5000;
// The cancel's signature is good for this long on the contract's clock, and is made again once half of it is gone.
export const INTENT_MS = 10 * 60_000;
export const READ_FAILS_TO_SAY = 3;
const OUTCOME_EVERY_MS = 500;
// A cancel the relay sent and the contract does not show settled by then: the page says so (C9).
export const SEND_GIVE_UP_MS = 30_000;
// A cancel this page can't tell went out (C7, C9) stands this long after it was sent. If the contract still reads the
// request waiting then, Cancel comes back with the line still up: it went out unseen, or not at all.
export const CANCEL_AGAIN_MS = 60_000;
const COIN_MS = 15_000;
// After CANCELLED the contract is read until it shows the key changed, or for this long.
const AFTER_CANCELLED_MS = 30_000;
// How long the stamp holds before the recap rises (the film's frame).
export const RECAP_AFTER_MS = 2500;
// The recap sheet goes under the stamp where it can be at least this tall there.
export const RECAP_ROOM_PX = 120;

/**
 * Where the recap sheet goes, from the boxes on the screen (viewport px): over the lower half, between the stamp and the
 * Done line, where that has RECAP_ROOM_PX; on a shorter screen, over the request's lines between the rail and the clock
 * when that has more room. Either way it covers none of the stamp, the digits or the Done line; its own box scrolls.
 *   frame { top, bottom }: the box the sheet is placed in; screenTop: the top of the lines under the rail; clockTop: the
 *   digits' box; stampBottom: the stamp's; nextTop: the Done line's.
 * Answers { where: 'below' | 'above', top, bottom, maxHeight }: px for the sheet's style, null where it is not set.
 */
export function recapPlace({ frame, screenTop, clockTop, stampBottom, nextTop, gap = 8 }) {
  const below = Math.floor(nextTop - stampBottom - gap);
  const above = Math.floor(clockTop - screenTop - gap);
  if (below >= RECAP_ROOM_PX || below >= above) return { where: 'below', top: null, bottom: Math.max(0, frame.bottom - nextTop), maxHeight: Math.max(0, below) };
  return { where: 'above', top: Math.max(0, screenTop - frame.top), bottom: null, maxHeight: Math.max(0, above) };
}
// NEW, and not yet in words.mjs: the dock's slot while the page reads the contract for a cancel it can't tell went out.
// True there: the watch reads the contract every second while the page is open.
export const READING_SLOT = 'Reading the contract';

/** The raw words of an error, for the console only (phone.mjs rawWords). */
const rawWords = (err) => [err?.code, err?.verbatim ?? (err?.name && err?.message ? `${err.name}: ${err.message}` : err?.message) ?? String(err)].filter(Boolean).join(': ');

/** A read started now and awaited later, marked handled so one that is never awaited raises no alarm. */
const handled = (promise) => {
  promise.catch(() => {});
  return promise;
};

function defaultEnv() {
  const doc = globalThis.document;
  const visible = () => !(doc && (doc.hidden === true || doc.visibilityState === 'hidden'));
  return {
    now: () => Date.now(),
    setTimeout: (fn, ms) => globalThis.setTimeout(fn, ms),
    clearTimeout: (id) => globalThis.clearTimeout(id),
    visible,
    onShow: (fn) => {
      doc?.addEventListener?.('visibilitychange', () => { if (visible()) fn(); });
      globalThis.addEventListener?.('pageshow', (event) => { if (event?.persisted) fn(); });
    },
    origin: globalThis.location?.origin ?? null,
    hostname: globalThis.location?.hostname ?? '',
  };
}

/**
 * Starts the owner watch on a vault the contract reads active. It reads every POLL_MS while the page is visible, and at
 * once when the page is shown again (L1).
 *   ctx           try.mjs's: { config, reader, views, relay, skew, esplora, instance, credentials, sense, awake }
 *   vaultHex      the vault this page made
 *   credentialId  the passkey made at TAP 1 (Uint8Array): the only one the cancel asks for
 *   status        the relay's status as boot read it; read again here while a request waits
 *   onView(view)  called whenever what the owner half would draw changes
 *   mark(name)    performance marks: requestSeen, cancelTap, assertion, cancelSent, cancelled, coinChecked
 *   cancelHere    false for v1: the watch only, no digest made and no Cancel
 *   env           the clock, timers and visibility, for a test
 * Returns { tick, view, cancelTap, retryPasskey, clock, handoffPath, stop }.
 *
 * view(): plain data, in the words nextOf(view) of words.mjs reads.
 *   step      null before a request; 'cancel'; 'cancelled' (try.mjs makes it 'recap' when the recap is up)
 *   state     'watching' (no request on the contract yet), 'request' (S4, and the rows that keep its screen),
 *             'tapped', 'cancel_sending' (S5), 'cancelled' (S6), 'other' (C11)
 *   fail      null or the row of section 7 in force: 'C1' to 'C11'
 *   kind      the request's state from requestState: 'waiting', 'unlocked', 'cancelled', 'signed', ...
 *   control   the one thing in the dock: 'cancel', 'retry-passkey', 'handoff', 'waiting', 'sending', 'reading', 'hash'
 *   link      'handoff' when "Open the phone page" goes under the control, else null
 *   line      the row's sentence, or null (C9's while readDown); words: a second line (C9's tx), or null
 *   request   the request as views.request last gave it, with `destination` and `total` worked out; null before one
 *   readDown  three reads in a row failed; pendingListed: how many requests the last read that got the vault listed on
 *             it (null when the node gave no vault), for try.mjs's T7 line
 *   cancelSent, cancelHash (this page's cancel, once the chain says it ran), keyStopped, coinStill, cancelledWall
 */
export function startOwner(ctx, { vaultHex, credentialId, status = null, onView = () => {}, mark = () => {}, cancelHere = true, env: given = {} }) {
  const env = { ...defaultEnv(), ...given };
  const S = {
    vault: null, items: new Map(), id: null, ksSeen: null, readFails: 0, skewAt: 0, pendingListed: null,
    relay: status, statusAt: status ? env.now() : 0, statusReading: false,
    prep: null, tap: null, blocked: false, rpBad: false, row: null,
    sentAt: null, cancelHash: null, coinStill: false, coinCheckedAt: 0, coinReading: false,
    cancelledAt: null, cancelledWall: null,
    timer: null, ticking: false, stopped: false, view: null, viewKey: null, once: new Set(),
  };
  const markOnce = (name) => {
    if (S.once.has(name)) return;
    S.once.add(name);
    mark(name);
  };
  const sleep = (ms) => new Promise((r) => { env.setTimeout(r, ms); });
  const chainNow = () => chainNowOf(ctx.skew) ?? 0;
  const focus = () => (S.id === null ? null : S.items.get(S.id) ?? null);

  // ------------------------------------------------------------ reads

  async function tick() {
    if (S.stopped) return;
    env.clearTimeout(S.timer);
    S.timer = null;
    // One read at a time: the one that is out schedules the next.
    if (S.ticking) return;
    S.ticking = true;
    try {
      const skewing = env.now() - S.skewAt >= SKEW_MS ? handled(ctx.reader.blockTime()) : null;
      const { vault } = await readOwner(ctx, { vaultHex, items: S.items });
      // A lagging node answers null for a vault it has not reached. This page read this one active, so it keeps the last.
      // Kept before the clock's read is awaited: the requests were just judged against this vault.
      if (vault) {
        S.vault = vault;
        S.ksSeen ??= vault.k_s;
      }
      // How many requests this read listed on the vault; null when the node gave no vault (behind), which says nothing.
      S.pendingListed = vault ? vault.pending.length : null;
      if (skewing) {
        ctx.skew.add(await skewing);
        S.skewAt = env.now();
      }
      S.readFails = 0;
    } catch (err) {
      S.readFails += 1;
      if (!(err instanceof StaleRead || err instanceof RpcDown)) logRaw('reading the vault', rawWords(err));
    } finally {
      S.ticking = false;
    }
    readStatusWhenDue();
    judge();
    checkCoin();
    schedule();
  }

  /** Done reading: CANCELLED, the coin checked, and the key read changed (or long enough after). */
  const finished = () => S.cancelledAt !== null && S.coinStill && (keyStopped() || env.now() - S.cancelledAt >= AFTER_CANCELLED_MS);

  function schedule() {
    env.clearTimeout(S.timer);
    S.timer = null;
    if (S.stopped || finished()) return;
    // Hidden, nothing is read: the page reads at once when it is shown again (resume).
    if (!env.visible()) return;
    const every = S.tap?.phase === 'sending' ? FAST_POLL_MS : S.cancelledAt !== null && keyStopped() ? COIN_MS : POLL_MS;
    S.timer = env.setTimeout(tick, every);
  }

  function resume() {
    if (S.stopped || finished()) return;
    tick();
  }

  /** The relay's status, read again while a request waits: a Cancel that can't go must not stay up (phone.mjs tick). */
  function readStatusWhenDue() {
    if (!cancelHere || S.statusReading || S.cancelledAt !== null) return;
    const every = !S.relay?.reachable || !S.relay?.owner?.up || focus()?.state?.cancellable ? STATUS_DOWN_MS : STATUS_MS;
    if (S.relay && env.now() - S.statusAt < every) return;
    S.statusReading = true;
    S.statusAt = env.now();
    Promise.resolve(ctx.relay.status())
      .then((answer) => { S.relay = answer; })
      .catch(() => {})
      .finally(() => {
        S.statusReading = false;
        judge();
      });
  }

  /** "The coin never moved." needs a node that knows each coin and says it is unspent (steps.mjs coinStill). */
  async function checkCoin() {
    if (S.cancelledAt === null || S.coinStill || S.coinReading || env.now() - S.coinCheckedAt < COIN_MS) return;
    const inputs = focus()?.request?.inputs;
    if (!inputs?.length) return;
    S.coinReading = true;
    S.coinCheckedAt = env.now();
    try {
      if (await coinStill(ctx, inputs)) {
        S.coinStill = true;
        markOnce('coinChecked');
        emit();
      }
    } catch {
      // Mutinynet did not answer. The line stays off until it does.
    } finally {
      S.coinReading = false;
    }
  }

  // ------------------------------------------------------------ what the reads mean

  const keyStopped = () => Boolean(S.vault && (S.vault.k_s_suspended || (S.ksSeen !== null && S.vault.k_s !== S.ksSeen)));

  function rpOk() {
    const host = env.hostname ?? '';
    const { rpId } = ctx.config;
    return (host === rpId || host.endsWith(`.${rpId}`)) && toHex(rpIdHashOf(rpId)) === S.vault.rp_id_hash;
  }

  function passkeyState() {
    const problem = passkeyProblem(ctx.sense, S.blocked) ?? (ctx.credentials ? null : 'no_webauthn');
    return { problem, canAssert: problem === null, rpMatches: !S.rpBad && rpOk() };
  }

  /** A second request on this vault while no cancel is out: the phone page shows them all (C11). */
  const another = () => [...S.items.values()].some((item) => item.state && item.id !== S.id);

  function judge() {
    const judged = [...S.items.values()].filter((item) => item.state);
    if (S.id === null && judged.length) {
      // The first the contract listed. Nothing the thief half sent picks it.
      S.id = Math.min(...judged.map((item) => item.id));
      markOnce('requestSeen');
    }
    const s = focus()?.state;
    // The request has ended or moved on: a passkey call still out can do nothing for it now.
    if (s && !s.cancellable) endTap();
    if (s?.kind === 'cancelled' && S.cancelledAt === null) {
      S.cancelledAt = env.now();
      // Wall time, as the run line is (G-A2): a monotonic clock may stop while a phone sleeps.
      S.cancelledWall = Date.now();
      markOnce('cancelled');
    }
    emit();
  }

  function endTap() {
    if (S.tap && !S.tap.answered) S.tap.abort.abort();
    S.tap = null;
  }

  /** The request as the contract gave it, with what the screen works out from it. */
  function requestFacts(request) {
    const { id, to, inputs, amount, change, fee, unlock, proposed_at: proposedAt, expires_at: expiresAt } = request;
    return {
      id, to, inputs, amount, change, fee, unlock, proposed_at: proposedAt, expires_at: expiresAt,
      destination: spkToAddress(ctx.instance.network, to) ?? to,
      total: sumInputs(request),
    };
  }

  function compute() {
    const view = {
      step: null, state: 'watching', fail: null, kind: null, here: cancelHere, control: null, link: null, line: null, words: null, hang: false,
      readDown: S.readFails >= READ_FAILS_TO_SAY, pendingListed: S.pendingListed, request: null, address: S.vault?.address ?? null, requestId: S.id,
      cancelSent: S.sentAt !== null, cancelHash: S.cancelHash, keyStopped: keyStopped(), coinStill: S.coinStill, cancelledWall: S.cancelledWall,
    };
    const item = focus();
    if (!item?.state || !S.vault) return view;
    const s = item.state;
    Object.assign(view, { step: 'cancel', kind: s.kind, request: requestFacts(item.request) });
    if (s.kind === 'cancelled') return { ...view, step: 'cancelled', state: 'cancelled', control: 'hash' };
    if (!s.cancellable) return { ...view, state: 'other', fail: 'C11', control: 'handoff', line: say(W.notWaiting) };
    if (S.tap?.phase === 'sending') return { ...view, state: 'cancel_sending', control: 'sending' };
    if (S.tap?.hang) return { ...view, state: 'tapped', fail: 'C3', control: 'cancel', link: 'handoff', hang: true };
    if (S.tap) return { ...view, state: 'tapped', control: 'waiting' };
    // Not "That request is no longer waiting.": this one still waits. The phone page names them all.
    if (another()) return { ...view, state: 'other', fail: 'C11', control: 'handoff' };
    if (S.row?.sticky && S.row.until !== undefined && env.now() >= S.row.until) S.row = { ...S.row, sticky: false, fail: null, control: null, link: null };
    const row = S.row;
    // C9's "the contract doesn't show it yet" is what a read answered: while three reads in a row have failed, none did, and
    // the read-down line says what is known (R3). Its tx stays: the relay did send it.
    const rowLine = row?.fromRead && view.readDown ? null : row?.line ?? null;
    if (row?.sticky) return { ...view, state: 'request', fail: row.fail, control: row.control, link: row.link ?? null, line: rowLine, words: row.words ?? null };
    if (!cancelHere) return { ...view, state: 'request' };
    const button = cancelButton({
      state: s, relay: S.relay ?? { reachable: false, owner: { up: false } }, passkey: passkeyState(), originAllowed: ctx.instance.origins.includes(env.origin),
      frozen: S.vault.frozen_until !== null && S.vault.frozen_until > chainNow(),
    });
    if (!button.show) {
      if (button.why === 'no_passkey_here' && passkeyState().problem === 'webauthn_blocked') {
        return { ...view, state: 'request', fail: 'C2', control: 'retry-passkey', line: problemWords('webauthn_blocked') };
      }
      // A relay that answered and says its cancel side is down said only that (phone.mjs noButtonWords).
      const why = button.why === 'relay_down' && S.relay?.reachable ? 'relay_owner_down' : button.why;
      return { ...view, state: 'request', fail: 'C10', control: 'handoff', line: noCancelWords(why) };
    }
    return { ...view, state: 'request', fail: row?.fail ?? null, control: 'cancel', line: rowLine, words: row?.words ?? null };
  }

  function emit() {
    const view = compute();
    // The digest is made while the request is drawn, never in the tap, and again before half its time is gone.
    if (view.control === 'cancel' && cancelHere && S.vault) ensurePrep();
    S.view = view;
    const key = JSON.stringify(view);
    if (key === S.viewKey) return;
    S.viewKey = key;
    onView(view);
  }

  /** The new K_s and the digest, ready before the tap, so a tap goes straight to the sheet (phone.mjs ensurePrep). */
  function ensurePrep() {
    const now = chainNow();
    const nonce = S.vault.passkey_nonce;
    if (S.prep && S.prep.nonce === nonce && S.prep.expiresAt - now > INTENT_MS / 2) return S.prep;
    const newKs = spendKeys(randomBytes(32)).ks.pub;
    const expiresAt = Math.floor(now) + INTENT_MS;
    S.prep = { newKs, nonce, expiresAt, digest: rotateDigest({ contract: ctx.config.contract, vaultHex, newKs, nonce, expiresAt }) };
    return S.prep;
  }

  // ------------------------------------------------------------ the tap

  /**
   * TAP 3. Only while Cancel is on the screen, or when the sheet of the last tap has not shown (C3): then this tap ends
   * that call and asks again, inside this tap, because the new call needs this tap's gesture as the first one did.
   */
  function cancelTap() {
    const old = S.tap;
    if (old && !(old.phase === 'tapped' && old.hang)) return;
    if (!old && S.view?.control !== 'cancel') return;
    if (!cancelHere || !S.vault) return;
    const prep = ensurePrep();
    const tap = { phase: 'tapped', abort: new AbortController(), answered: false, hang: false, hash: null };
    S.tap = tap;
    if (old) old.abort.abort();
    // Straight to the browser: no await may come before this, or iOS Safari drops the gesture.
    const asking = askAssertion(ctx, {
      digest: prep.digest,
      credentialId,
      signal: tap.abort.signal,
      onHang: () => {
        if (S.tap !== tap) return;
        tap.hang = true;
        emit();
      },
    });
    mark('cancelTap');
    ctx.awake?.start?.();
    S.row = null;
    emit();
    finishTap(asking, prep, tap);
  }

  async function finishTap(asking, prep, tap) {
    let assertion;
    try {
      ({ assertion } = await asking);
    } catch (err) {
      tap.answered = true;
      if (S.tap === tap) tapFailed(err);
      return;
    }
    tap.answered = true;
    // A call this page gave up on, answering late: a newer tap has the screen, or the request has ended.
    if (S.tap !== tap) return;
    mark('assertion');
    if (!focus()?.state?.cancellable) {
      S.tap = null;
      judge();
      return;
    }
    const refusal = refusalOf({
      assertion: assertion.args, digest: prep.digest, pubkey: fromHex(S.vault.passkey), rpIdHash: fromHex(S.vault.rp_id_hash), origins: ctx.instance.origins,
    });
    if (refusal) {
      S.tap = null;
      S.prep = null;
      logRaw('the passkey\'s answer', refusal);
      S.row = { fail: 'C4', sticky: true, control: 'handoff', line: say(W.notCancelled) + passkeyWords(refusal) };
      judge();
      return;
    }
    const args = rotateArgs({ vaultHex, newKs: prep.newKs, nonce: prep.nonce, expiresAt: prep.expiresAt, assertion: assertion.args });
    tap.phase = 'sending';
    S.sentAt = env.now();
    mark('cancelSent');
    emit();
    schedule();
    let sent;
    try {
      sent = await ctx.relay.call('cancel_all_and_rotate', args);
    } catch (err) {
      relayRefused(err, tap);
      return;
    }
    tap.hash = sent.hash;
    watchOutcome(sent.hash, tap);
  }

  /** The sheet closed, never came back, or the browser refused (phone.mjs onTapFailed, for a credential this page made). */
  function tapFailed(err) {
    S.tap = null;
    S.prep = null;
    if (err instanceof PasskeyFailed) {
      if (err.kind === 'blocked') {
        // C2: cancelButton now says no_passkey_here, and "Try the passkey again" puts Cancel back.
        S.blocked = true;
        logRaw('the passkey', rawWords(err));
      } else if (err.kind === 'wrong_site') {
        S.rpBad = true;
        logRaw('the passkey', rawWords(err));
      } else if (err.kind === 'dismissed') {
        S.row = { fail: 'C1', line: say(W.notCancelledNoSign) };
      } else {
        logRaw('the passkey', rawWords(err));
        S.row = { fail: 'C1', line: say(W.notCancelled) + failureWords(err) };
      }
    } else {
      logRaw('the tap', rawWords(err));
      S.row = { fail: 'C1', line: say(W.notCancelled) + failureWords(err) };
    }
    judge();
  }

  /** The relay's answer to the cancel, when it was not ok (phone.mjs onRelayRefused). */
  function relayRefused(err, tap) {
    // The contract read the request cancelled while the cancel was out: nothing to say about this answer.
    if (S.tap !== tap) return;
    S.tap = null;
    S.prep = null;
    logRaw('the relay', rawWords(err));
    const until = S.sentAt + CANCEL_AGAIN_MS;
    const reading = { sticky: true, until, control: 'reading', link: 'handoff' };
    if (err instanceof RelayRefused && err.code === 'relay_down') {
      // No answer: the cancel may have gone out all the same, so nothing may say it did not. The contract decides.
      S.row = { ...reading, fail: 'C7', line: say(W.cancelNoAnswer) };
    } else if (err instanceof RelayRefused && !relaySentNothing(err.code)) {
      // A code the relay can give after its sender put the cancel out: its sentence, and never "Not cancelled".
      S.row = { ...reading, fail: 'C7', line: relayWords(err) };
    } else if (err instanceof RelayRefused && err.code === 'rate_limited') {
      S.row = { fail: 'C5', line: say(W.tooMany, waitWords(err.retryAfterS ?? 10)) };
    } else {
      S.row = { fail: 'C6', sticky: true, control: 'handoff', line: say(W.notCancelled) + failureWords(err) };
    }
    judge();
  }

  /**
   * Inclusion says nothing of what the contract did, so the outcome is read, and only a settled one counts. A hash goes
   * on the screen only once the chain says the call ran (phone.mjs watchOutcome).
   */
  async function watchOutcome(hash, tap) {
    const giveUpAt = S.sentAt + SEND_GIVE_UP_MS;
    while (env.now() < giveUpAt && !S.stopped && S.relay?.relayAccount) {
      let outcome = null;
      try {
        outcome = await ctx.reader.txOutcome(hash, S.relay.relayAccount, { wait: 'EXECUTED_OPTIMISTIC' });
      } catch {
        // Not readable yet. Reads of the request go on regardless.
      }
      if (outcome?.settled && outcome.failure) {
        if (S.tap === tap) {
          S.tap = null;
          S.prep = null;
          logRaw('the cancel', outcome.failure);
          S.row = { fail: 'C8', sticky: true, control: 'handoff', line: say(W.notCancelled) + contractWords(outcome.failure) };
        }
        judge();
        return;
      }
      if (outcome?.settled) {
        S.cancelHash = hash;
        emit();
        break;
      }
      await sleep(OUTCOME_EVERY_MS);
    }
    const left = giveUpAt - env.now();
    if (left > 0) await sleep(left);
    if (S.tap === tap) {
      S.tap = null;
      S.prep = null;
      S.row = { fail: 'C9', sticky: true, until: S.sentAt + CANCEL_AGAIN_MS, control: 'reading', link: 'handoff', line: say(W.sentNotShown), fromRead: true, words: nearTxLabel(ctx.config, hash) };
      judge();
    }
  }

  /** "Try the passkey again" on C2. It opens no sheet: it puts Cancel back, whose tap does. */
  function retryPasskey() {
    S.blocked = false;
    S.row = null;
    judge();
  }

  /** The digits for the request on screen, or null where none may run: no request, ended, or reads failing (L3). */
  function ownerClock() {
    const item = focus();
    if (!item?.state?.cancellable || S.readFails >= READ_FAILS_TO_SAY) return null;
    return clock(item.request.unlock, ctx.skew.sample(), Date.now(), item.request.proposed_at);
  }

  /** The phone page for this vault, its request and this page's passkey, for the same tab (R7). No key goes in it. */
  const handoffPath = () => `/p/${buildPhoneFragment({ v: vaultHex, r: S.id, c: credentialId ? credentialToFragment(credentialId) : null })}`;

  function stop() {
    S.stopped = true;
    env.clearTimeout(S.timer);
    S.timer = null;
    // The call it ends answers nothing on a page that has stopped watching.
    endTap();
  }

  env.onShow?.(resume);
  tick();
  return {
    tick, cancelTap, retryPasskey, handoffPath, stop, clock: ownerClock,
    view: () => S.view ?? compute(),
    /** For a test: the digest the next tap signs. */
    prep: () => S.prep,
  };
}

// ---------------------------------------------------------------- S4 to S7, drawn (v2: CANCEL_HERE)

/**
 * Draws what startOwner's views say, into two boxes try.mjs owns: `block`, inside the stage, under its title and lines,
 * and `dock`, the one control under the thumb. It changes only what a new view changes, so text on the screen never
 * moves at rest (R12): the request block is made once, the digits change in place, the stamp lands over the clock, the
 * dock's Cancel becomes the hash slot, and the two result lines fill slots made when S4 was drawn. The recap sheet goes
 * into `sheet` RECAP_AFTER_MS after the stamp, and the dock then takes "Back to the start page".
 *   owner           startOwner's controller
 *   onCancel        try.mjs onCancel, whose first statement is owner.cancelTap(); the button's listener calls it first
 *   onHandoff       try.mjs's hand-off to /p/ (default: location.replace of owner.handoffPath())
 *   onRetryPasskey  default owner.retryPasskey
 *   onRecap(sheet)  after the recap is up: try.mjs sets data-step=recap and lets the screen sleep
 *   thief()         the thief half's own facts for the recap: { refused, nodeWords, proposeHash }
 *   mark(name)      'cancelShown', the first time Cancel is in the dock
 * Returns { draw(view), frame(), dispose(), fitClock() }. try.mjs calls draw on each onView.
 */
export function ownerDrawing({ owner, config, block, dock, sheet = null, onCancel = null, onHandoff = null, onRetryPasskey = null, onRecap = () => {}, thief = () => ({}), mark = () => {}, timers = globalThis }) {
  const cancel = onCancel ?? (() => owner.cancelTap());
  const handoff = onHandoff ?? (() => globalThis.location.replace(owner.handoffPath()));
  const retry = onRetryPasskey ?? (() => owner.retryPasskey());
  const D = { el: null, face: null, view: null, dockKey: null, frozen: false, recap: null, recapTimer: null, raf: null, cancelShown: false, gone: false };

  const setText = (node, text) => {
    if (node.textContent !== text) node.textContent = text;
  };

  function build() {
    const face = new ClockFace();
    D.face = face;
    const el = {
      role: h('p', { class: 'line owner-role', id: 'owner-role' }, say(W.owner)),
      seen: h('div', { class: 'label', id: 'seen-label' }, say(W.seenLabel)),
      toLabel: h('div', { class: 'label' }, say(W.to)),
      to: h('div', { class: 'addr', id: 'to' }),
      amount: h('div', { class: 'sats', id: 'amount' }),
      fee: h('p', { class: 'small fee', id: 'fee', hidden: true }),
      waitLabel: h('div', { class: 'label wait-label', id: 'wait-label' }, say(W.unlocksIn)),
      clock: h('div', { class: 'clockblock', id: 'clockblock' }, face.wrap, face.fuse),
      // Reserved under the clock when S4 is drawn, so the result lines enter where nothing has to move for them.
      key: h('p', { class: 'say reserve', id: 'key-line' }),
      coin: h('p', { class: 'say reserve', id: 'coin-line' }),
      atZero: h('p', { class: 'notice', id: 'at-zero', hidden: true }, say(W.atZero)),
      readDown: h('p', { class: 'notice warn', id: 'read-down', hidden: true }, say(W.readDown)),
      line: h('p', { class: 'notice warn', id: 'owner-line', hidden: true }),
      words: h('p', { class: 'words', id: 'owner-words', hidden: true }),
    };
    el.root = h('section', { class: 'owner', id: 'owner' }, el.role, el.seen, el.toLabel, el.to, el.amount, el.fee, el.waitLabel, el.clock, el.key, el.coin, el.atZero, el.readDown, el.line, el.words);
    D.el = el;
    block.replaceChildren(el.root);
    loop();
  }

  function draw(view) {
    if (D.gone) return;
    D.view = view;
    if (view.state === 'watching' || !view.request) return;
    if (!D.el) build();
    const { el, face } = D;
    const r = view.request;
    setText(el.to, r.destination);
    // phone.mjs amountLines: with no change, all of it leaves, and the fee is part of it.
    if (r.change === null) {
      setText(el.amount, satsText(r.total));
      setText(el.fee, r.fee > 0 ? say(W.fee, satsText(r.fee)) : '');
      el.fee.hidden = !(r.fee > 0);
    } else {
      setText(el.amount, satsText(r.amount));
      el.fee.hidden = true;
    }
    if (view.state === 'cancelled') freeze(view);
    else {
      // Signed, signing or expired: no clock is true for it any more.
      const ended = view.kind !== 'waiting' && view.kind !== 'unlocked';
      el.clock.hidden = ended;
      el.waitLabel.hidden = ended;
      el.atZero.hidden = !(view.control === 'cancel' && view.kind === 'unlocked');
      el.readDown.hidden = !view.readDown;
      face.dim(view.readDown);
      setText(el.line, view.line ?? '');
      el.line.hidden = !view.line;
      setText(el.words, view.words ?? '');
      el.words.hidden = !view.words;
    }
    if (D.recap) updateRecap(view);
    else drawDock(view);
  }

  /** CANCELLED: the digits stop where they are, the stamp lands over them, and nothing above the result lines moves. */
  function freeze(view) {
    const { el, face } = D;
    if (!D.frozen) {
      D.frozen = true;
      face.stop();
      face.dim(false);
      // Its room stays, so nothing under it moves.
      face.fuse.hidden = false;
      face.fuse.style.visibility = 'hidden';
      // "unlocks in" is no longer true of a cancelled request; its box stays.
      el.waitLabel.style.visibility = 'hidden';
      for (const node of [el.atZero, el.readDown, el.line, el.words]) node.hidden = true;
      el.clock.append(h('div', { class: 'stampclip' }, h('div', { class: 'stamp slam', id: 'stamp' }, say(W.stamp))));
      D.recapTimer = timers.setTimeout(showRecap, RECAP_AFTER_MS);
    }
    if (view.keyStopped) setText(el.key, say(W.keyStopped));
    if (view.coinStill) setText(el.coin, say(W.coinStill));
  }

  function controlNode(view) {
    switch (view.control) {
      case 'cancel':
        return h('button', { id: 'cancel', type: 'button', 'data-again': view.hang ? '1' : null, onclick: () => cancel() }, say(W.cancel), h('span', { class: 'sub' }, say(W.prompt3)));
      case 'retry-passkey':
        return h('button', { class: 'go quiet', type: 'button', id: 'retry-passkey', onclick: () => retry() }, say(W.retryPasskey));
      case 'handoff':
        return h('button', { class: 'go', type: 'button', id: 'open-phone', onclick: () => handoff() }, say(W.openPhone));
      case 'waiting':
        return h('div', { class: 'slot', id: 'waiting' }, say(W.waitingPasskey));
      case 'sending':
        return h('div', { class: 'slot', id: 'sending' }, say(W.sending));
      case 'reading':
        return h('div', { class: 'slot', id: 'reading' }, READING_SLOT);
      case 'hash':
        return h('div', { class: 'hashslot', id: 'near-tx' }, view.cancelHash ? hashBlock(nearTxLabel(config, view.cancelHash), view.cancelHash, nearTxLink(config, view.cancelHash)) : null);
      default:
        return null;
    }
  }

  function drawDock(view) {
    const key = `${view.control}|${view.link}|${view.hang}|${view.cancelHash}`;
    if (key === D.dockKey) return;
    D.dockKey = key;
    const link = view.link === 'handoff'
      ? h('a', { class: 'textlink', id: 'open-phone-link', href: owner.handoffPath(), onclick: (event) => { event?.preventDefault?.(); handoff(); } }, say(W.openPhone))
      : null;
    dock.replaceChildren(...[controlNode(view), link].filter(Boolean));
    if (view.control === 'cancel' && !D.cancelShown) {
      D.cancelShown = true;
      mark('cancelShown');
    }
  }

  function showRecap() {
    if (D.recap || D.gone) return;
    const view = D.view;
    const facts = thief() ?? {};
    const r = view.request;
    const nodeBox = facts.nodeWords ? h('pre', { class: 'words', id: 'node-words', hidden: true }, facts.nodeWords) : null;
    const row1 = facts.refused
      ? h('li', { id: 'row-refused' },
        h('p', { class: 'say' }, say(W.refusedRow, config.labels.bitcoin)),
        nodeBox ? h('button', { class: 'textbtn', type: 'button', id: 'node-toggle', onclick: () => { nodeBox.hidden = !nodeBox.hidden; } }, say(W.nodeWords)) : null,
        nodeBox)
      : null;
    const row2 = h('li', { id: 'row-wait' },
      h('p', { class: 'say' }, say(W.recapWait, digits(r.unlock - r.proposed_at).short)),
      facts.proposeHash ? hashBlock(nearTxLabel(config, facts.proposeHash), facts.proposeHash, nearTxLink(config, facts.proposeHash)) : null);
    const rec = {
      row3Text: h('p', { class: 'say', id: 'row-cancel-text' }),
      // Kept from the start when this page sent a cancel, so the line under it does not jump when the hash arrives.
      row3Hash: view.cancelSent ? h('div', { class: 'hashslot', id: 'cancel-tx' }) : null,
      row3Key: h('p', { class: 'small', id: 'row-key' }),
      list: null,
      coinRow: null,
      hashShown: false,
    };
    const row3 = h('li', { id: 'row-cancel' }, rec.row3Text, rec.row3Hash, rec.row3Key);
    rec.list = h('ol', { class: 'receipts' }, row1, row2, row3);
    rec.root = h('section', { class: 'recap', id: 'recap' },
      h('h2', { class: 'recap-title' }, say(W.recapTitle)),
      rec.list,
      h('p', { class: 'foot' }, say(W.recapFoot)),
      h('a', { class: 'textlink', id: 'other-device', href: '/p/' }, say(W.otherDevice)));
    D.recap = rec;
    updateRecap(view);
    (sheet ?? block.parentElement ?? globalThis.document?.body)?.append(rec.root);
    dock.replaceChildren(h('a', { class: 'go', id: 'back-start', href: '/' }, say(W.backStart)));
    D.dockKey = 'recap';
    onRecap(rec.root);
  }

  function updateRecap(view) {
    const rec = D.recap;
    // Only a cancel of this page that the chain says ran is "your passkey"; otherwise only what the contract reads.
    setText(rec.row3Text, view.cancelHash ? say(W.recapPasskey) : say(W.recapRead));
    if (view.cancelHash && rec.row3Hash && !rec.hashShown) {
      rec.hashShown = true;
      rec.row3Hash.replaceChildren(hashBlock(nearTxLabel(config, view.cancelHash), view.cancelHash, nearTxLink(config, view.cancelHash)));
    }
    if (view.keyStopped) setText(rec.row3Key, say(W.keyStopped));
    if (view.coinStill && !rec.coinRow && view.address) {
      rec.coinRow = h('li', { id: 'row-coin' }, h('p', { class: 'say' }, say(W.coinStill)), hashBlock(btcAddressLabel(config, view.address), view.address, btcAddressLink(config, view.address)));
      rec.list.append(rec.coinRow);
    }
  }

  /** One frame: the digits and the fuse, in place. Nothing at all once CANCELLED, or while reads fail (L3). */
  function frame() {
    const view = D.view;
    if (!D.face || !view || D.frozen || view.state === 'cancelled') return;
    if (!D.face.size) D.face.fit();
    const c = owner.clock();
    if (!c) return;
    D.face.set(c.text);
    D.face.setFuse(c.fuse);
  }

  function loop() {
    const raf = globalThis.requestAnimationFrame;
    if (typeof raf !== 'function') return;
    const step = () => {
      if (D.gone) return;
      D.raf = raf(step);
      frame();
    };
    step();
  }

  function dispose() {
    D.gone = true;
    if (D.raf !== null) globalThis.cancelAnimationFrame?.(D.raf);
    if (D.recapTimer !== null) timers.clearTimeout(D.recapTimer);
    D.face?.dispose();
  }

  /** The digits fitted to the column again (ClockFace.fit), for try.mjs's fit once it has taken its own sizes off. */
  function fitClock() {
    D.face?.fit();
  }

  return { draw, frame, dispose, fitClock };
}
