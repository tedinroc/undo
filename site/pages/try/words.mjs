// Every sentence /try/ can show, in one table, each tagged with where it comes from. `from` names the file a sentence is
// copied from, byte for byte (try-words.test.mjs holds each one to that file's source, so when the lane rewords one, the
// test fails and the copy follows); 'new' is a sentence this page says first, and the inventory says why each is true.
// A sentence with values in it is kept as its fixed parts, and `say` puts the values between them.
//
// Also here: the phone page's private helpers that /try/ needs, copied with their bodies unchanged (the test compares
// each body with phone.mjs's), and nextOf(view), the one Next sentence over the dock in every state.
import {
  contractWords, passkeyErrorWords, RELAY_METHODS, RelayRefused, relayClause, relayWords, resetWords, RpcDown, StaleRead, unreadRelayWords, ViewRefused, waitWords,
} from '/site/lib/index.mjs';
import { PasskeyFailed } from '../p/passkey-ask.mjs';
import { hangWords } from '../p/sense.mjs';

const at = (from, ...parts) => Object.freeze({ from, parts: Object.freeze(parts) });
// The one allowed edit of a copied sentence: the thief tab's "this tab" is this page.
const asPage = (from, ...parts) => Object.freeze({ from, parts: Object.freeze(parts), tab: true });

/** A sentence with its values: the fixed parts with each value between two of them. */
export function say(entry, ...values) {
  let out = entry.parts[0];
  for (let i = 1; i < entry.parts.length; i += 1) out += String(values[i - 1] ?? '') + entry.parts[i];
  return out;
}

export const W = Object.freeze({
  // ---- S0
  title: at('new', 'Rob yourself. Then undo it.'),
  row1: at('new', 'A test vault. Your passkey is its cancel key.'),
  row2: at('new', 'This page asks the relay for a test coin.'),
  row3: at('new', 'This page plays a thief who has your spend key.'),
  row4: at('new', 'You cancel the theft with your passkey.'),
  three: at('new', 'Three passkey prompts. No wallet, no app, no second tab.'),
  beforeMake: at('p/phone.mjs', 'Next, this device asks to save a passkey named "test vault" for ', ': this vault\'s cancel key. You can delete it afterwards.'),
  make: at('new', 'Make my test vault'),
  prompt1: at('new', 'Passkey prompt 1 of 3'),
  prompt2: at('new', 'Passkey prompt 2 of 3'),
  prompt3: at('new', 'Passkey prompt 3 of 3'),
  watchRun: at('new', 'Watch a recorded run'),
  twoDevices: at('new', 'Two devices instead'),
  foot: at('p/phone.mjs', 'Test coins only. The address starts with ', '. This page makes your spend key and your cold key and holds them while it is open, so a changed page could take both. ', ' The signing network alone can refuse, not take.'),
  madeHint: at('new', 'This browser made ', ' test vaults in the past hour. One network address gets ', ' test coin tries an hour, so a new one may get none.'),
  fundsDown: at('p/phone.mjs', 'This page can\'t get a test coin from the relay right now.'),
  fundsDownEnd: at('new', ' Without one, step 3 has nothing to steal.'),
  ownerDown: at('p/phone.mjs', 'The relay says it can\'t send a cancel right now'),
  ownerDownEnd: at('new', ', so step 4 would have no Cancel.'),
  mainnet: at('t/thief.mjs', 'This page is a demo for test coins only, and this contract is not on a test network.'),
  noConfig: at('p/phone.mjs', 'This page could not load its settings, so it shows nothing.'),
  readDown: at('p/phone.mjs', 'Can\'t read the NEAR contract right now.'),
  crashed: at('p/phone.mjs', 'This page hit an error it did not expect.'),
  loading: at('new', 'Loading the page'),

  // ---- S1
  stepMake: at('new', '1 · Make'),
  stepFund: at('new', '2 · Fund'),
  stepSteal: at('new', '3 · Steal'),
  stepCancel: at('new', '4 · Cancel'),
  waitingPasskey: at('p/phone.mjs', 'Waiting for your passkey'),
  passkeyMade: at('p/phone.mjs', 'Passkey made.'),
  canSync: at('p/phone.mjs', 'It can sync to your other devices.'),
  readingKm: at('new', 'Reading the second key from the signer.'),
  kmRead: at('p/phone.mjs', 'Second key read from the signer.'),
  slotKm: at('new', 'Reading the second key'),
  confirm: at('p/phone.mjs', 'Confirm with your passkey'),
  beforeConfirm: at('p/phone.mjs', 'One more sheet: your passkey signs this vault\'s creation, and the contract checks it.'),

  // ---- S2a
  slotMaking: at('new', 'Making the vault · ', ' s'),
  signed: at('p/phone.mjs', 'Signed.'),
  working: at('p/phone.mjs', 'Working: a small proof of work.'),
  workDone: at('p/phone.mjs', 'Proof of work done.'),
  sendingVault: at('new', 'Sending the vault through the relay.'),
  readingActive: at('new', 'Reading the contract until this vault is active.'),
  active: at('new', 'Vault active on ', '.'),
  // ---- S2b
  slotFunding: at('new', 'Getting a test coin · ', ' s'),
  askingCoin: at('p/phone.mjs', 'Asking for a test coin.'),
  relaySent: at('new', 'The relay sent ', ' to this vault\'s address.'),
  waitingList: at('new', 'Waiting for ', ' to list it.'),
  // ---- S3
  thief: at('new', 'This page now plays a thief who has your spend key.'),
  spendKey: at('new', 'your spend key'),
  sendsTo: at('new', 'It sends everything to a fresh test address that nobody holds.'),
  slotCount: at('new', 'The thief sends in ', ''),
  slotSending: at('t/thief.mjs', 'Sending everything straight to Bitcoin'),
  refused1: at('t/index.html', 'REFUSED'),
  refused2: at('t/index.html', 'BY BITCOIN'),
  needs: at('t/index.html', 'It needs a second signature.'),
  nodeLabel: at('t/thief.mjs', '', ' node:'),
  slotRefused: at('new', 'Refused by Bitcoin'),
  refusedRow: at('t/thief.mjs', '', ' refused the key alone.'),
  askingNear: at('t/thief.mjs', 'Asking the NEAR contract'),
  slotAsking: at('new', 'Asking NEAR · ', ' s'),
  // ---- S4, one way (v1)
  seen: at('new', 'Seen on the NEAR contract.'),
  slotOpening: at('new', 'Opening your phone page'),
  // ---- S4 to S7, here (v2)
  owner: at('new', 'Back to you, the owner.'),
  seenLabel: at('new', 'Seen on the NEAR contract'),
  to: at('p/phone.mjs', 'to'),
  fee: at('p/phone.mjs', '', ' of it is the Bitcoin fee.'),
  unlocksIn: at('t/index.html', 'unlocks in'),
  atZero: at('p/phone.mjs', 'Anyone can send it now. Cancel works until they do.'),
  cancel: at('p/phone.mjs', 'Cancel'),
  sending: at('p/phone.mjs', 'Sending'),
  // owner.mjs READING_SLOT, the dock on C7 and C9 while the watch reads the contract (try-words holds the two equal).
  slotReading: at('new', 'Reading the contract'),
  stamp: at('p/phone.mjs', 'CANCELLED'),
  keyStopped: at('p/phone.mjs', 'That key can\'t ask again.'),
  coinStill: at('p/phone.mjs', 'The coin never moved.'),
  recapTitle: at('new', 'What just happened'),
  nodeWords: at('new', 'the node\'s words'),
  recapWait: at('new', 'The NEAR contract set a ', ' public wait on the request.'),
  recapPasskey: at('new', 'Your passkey cancelled it.'),
  recapRead: at('new', 'The contract reads this request cancelled.'),
  recapFoot: at('landing', 'If NEAR goes away, your cold key gets the coins out after a timelock.'),
  backStart: at('new', 'Back to the start page'),
  otherDevice: at('new', 'Try it with the thief on another device'),

  // ---- the cards: why each long wait matters. One sentence each, unchanged while it is up.
  w1: at('new', 'A coin at this vault\'s address sits in a Bitcoin script. Your spend key can move it only together with a second key, which NEAR\'s Chain Signatures network controls.'),
  w2: at('new', 'The second signature comes only when this vault\'s NEAR contract asks for it, and the contract asks only after a public wait. Your passkey can cancel during the wait.'),
  w3: at('new', 'Every request waits in public: anyone can read its amount and destination before Bitcoin moves.'),

  // ---- failures: making a vault
  noPasskey: at('p/phone.mjs', 'No passkey came back, so nothing was made.'),
  noPasskeyApp: at('p/phone.mjs', 'No passkey came back, so nothing was made. If you opened this inside an app, open it in Safari or Chrome.'),
  retryPasskey: at('p/phone.mjs', 'Try the passkey again'),
  noVault: at('p/phone.mjs', 'No vault was made. '),
  readAgain: at('new', 'Read again'),
  didNotSign: at('p/phone.mjs', 'The passkey did not sign. Tap Confirm to try again.'),
  startOver: at('new', 'Start over'),
  readingVault: at('new', 'Reading the contract for this vault.'),
  relayNoAnswer: at('p/phone.mjs', 'The relay did not answer'),
  notActiveYet: at('new', '', ', and the contract does not read this vault active yet.'),
  sentNotActive: at('p/phone.mjs', 'The vault was sent, but the contract does not read it active yet.'),
  checkAgain: at('p/phone.mjs', 'Check again'),
  // ---- failures: the coin
  noCoins: at('p/phone.mjs', 'No coins sent. '),
  cantTellCoin: at('p/phone.mjs', '', ', so this page can\'t tell whether a coin was sent.'),
  noCoinYet: at('new', '', ' lists no coin at this vault\'s address yet.'),
  notListedYet: at('new', '', ' does not list this coin at the vault\'s address yet.'),
  btcDown: at('p/phone.mjs', 'Can\'t read ', ' right now.'),
  askAgain: at('new', 'Ask again'),
  // ---- failures: the theft
  scriptWrong: at('t/thief.mjs', 'The contract\'s script does not pay this vault\'s address, so this page stops.'),
  relayHolds: at('new', '', ', so this page can\'t ask the NEAR contract yet. Trying again.'),
  relaySaysNo: at('new', 'The relay says it can\'t ask the NEAR contract for this page right now. Trying again.'),
  slotChecking: at('new', 'Checking before the theft · ', ' s'),
  feeTakesAll: at('new', 'The fee would take all of these sats right now, so the thief waits.'),
  accepted: at('t/thief.mjs', 'A NODE ACCEPTED THIS'),
  otherRefusal: at('t/thief.mjs', 'A node said no, but not about the signature.'),
  noNode: at('t/thief.mjs', 'The node did not answer.'),
  tryAgain: at('t/index.html', 'Try again'),
  proposeDown: asPage('t/thief.mjs', 'The relay did not answer, so this page can\'t tell whether the call went out.'),
  proposeCeiling: asPage('t/logic.mjs', 'The relay hit today\'s limit, so this page can\'t ask the NEAR contract or call execute.'),
  proposeRefused: at('t/thief.mjs', 'The NEAR contract refused this.'),
  proposeNoRequest: at('t/thief.mjs', 'Sent to the NEAR contract, and no request appeared.'),
  proposeNotAsked: at('t/thief.mjs', 'The NEAR contract was not asked.'),
  proposeCantTell: asPage('t/thief.mjs', 'This page can\'t tell whether the call went out.'),
  proposeError: asPage('t/thief.mjs', 'This page hit an error it did not expect.'),
  noRequestYet: at('new', 'The contract lists no request for this vault yet.'),
  // ---- failures: the cancel (the page that cancels here)
  notCancelledNoSign: at('p/phone.mjs', 'Not cancelled. The passkey did not sign.'),
  notCancelled: at('p/phone.mjs', 'Not cancelled. '),
  tooMany: at('p/phone.mjs', 'Not cancelled. Too many tries through the relay. Wait ', ' and tap again.'),
  cancelNoAnswer: at('p/phone.mjs', 'The relay did not answer, so this page can\'t tell whether the cancel went out.'),
  sentNotShown: at('p/phone.mjs', 'The relay sent it, but the contract doesn\'t show it yet.'),
  cantCancel: at('new', 'This page can\'t send a cancel right now.'),
  notWaiting: at('lib', 'That request is no longer waiting.'),
  openPhone: at('new', 'Open the phone page'),
  // ---- lifecycle
  reloaded: at('new', 'This page reloaded, so it no longer holds this vault\'s keys. The phone page can still watch this vault and cancel with your passkey.'),
  newRun: at('new', 'Start a new run'),
});

// ---------------------------------------------------------------- copied from p/phone.mjs, bodies unchanged

/** One sentence for anything that went wrong, never its raw words: those go to the console, with `logRaw`. phone.mjs failureWords. */
export function failureWords(err) {
  if (err instanceof RelayRefused) return relayWords(err);
  if (err instanceof ViewRefused) return contractWords(err.verbatim);
  if (err instanceof RpcDown || err instanceof StaleRead) return 'Can\'t read the NEAR contract right now.';
  if (err instanceof PasskeyFailed) return passkeyErrorWords(err.kind);
  return 'This page hit an error it did not expect.';
}

/** Why a vault was not made, in one sentence. phone.mjs makeWhy. */
export function makeWhy(err) {
  if (err instanceof RelayRefused && err.code === 'rate_limited' && err.retryAfterS >= 120) {
    return `This network address has used its ${RELAY_METHODS.create_vault.perIpHour} vault tries for this hour. Wait ${waitWords(err.retryAfterS)}, or use another network.`;
  }
  return failureWords(err);
}

/** Why no coin came, in one sentence. phone.mjs fundWhy; its `ctx` is passed in. */
export function fundWhy(err, ctx) {
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

/** A status the page could not read. phone.mjs unreadStatusWords. */
export const unreadStatusWords = (relay) => `${unreadRelayWords(relay)}. Trying again.`;

/** Why the relay can't make a vault now. phone.mjs generalDownWords; its `P` (P.relay, the status) is passed in. */
export function generalDownWords(P) {
  if (!P.relay.reachable) return unreadStatusWords(P.relay);
  const why = P.relay.general?.why;
  if (why === 'daily_ceiling') return `The relay hit today's limit, so this page can't make a vault right now.${resetWords(P.relay.general.resets_at)}`;
  if (why === 'relay_reserve') return 'The relay is keeping what it has left for cancels, so this page can\'t make a vault right now.';
  // The relay answered, so it is not down: its own reason, or with none (it never sends none) only that it can't.
  if (!why || why === 'relay_down') return 'The relay says it can\'t make a vault right now.';
  return `${relayClause(why)}, so this page can't make a vault.`;
}

/** No Cancel because the relay's status could not be read. phone.mjs relayDownWords. */
export function relayDownWords(relay) {
  if (relay.cancelUnanswered) return 'The relay did not answer, so this page can\'t tell whether the cancel went out.';
  return `${unreadRelayWords(relay)}, so this page can't send a cancel. Trying again.`;
}

/** The codes /api/funds gives only before its coin goes out. phone.mjs FUND_UNSENT. */
export const FUND_UNSENT = new Set(['bad_origin', 'bad_request', 'relay_not_configured', 'pow_required', 'pow_bad', 'would_refuse', 'rpc_down', 'rate_limited', 'daily_ceiling', 'dispenser_empty', 'tx_refused']);

/** One network address's test coin tries an hour: worker/undo-cron's FUNDS_PER_IP_HOUR (try-words.test.mjs reads it). */
export const COIN_TRIES_PER_HOUR = 2;

/** Four rows of phone.mjs NO_BUTTON_WORDS: the reasons a cancel can't go that /try/ names itself. */
export const NO_BUTTON_WORDS = Object.freeze({
  relay_owner_down: 'The relay says it can\'t send a cancel right now, so this page can\'t send one.',
  daily_ceiling: 'The relay hit today\'s limit.',
  origin_not_allowed: 'This page isn\'t allowed to cancel for this vault.',
  frozen: 'The cold key has frozen this vault.',
});

/** The one Cancel sentence for a reason the relay or the contract gives, or this page's own when it is not one of the four. */
export const noCancelWords = (why) => NO_BUTTON_WORDS[why] ?? say(W.cantCancel);

/** A vault-making failure that may have come after the relay sent it: what the relay said, or that it said nothing. */
export const relayOrNone = (err) => (err?.code === 'relay_down' || !err?.code ? say(W.relayNoAnswer) : relayClause(err.code));

// ---------------------------------------------------------------- the Next line

/** Rows of nextOf's own words: each new, each true wherever nextOf gives it. */
export const NEXT = Object.freeze({
  boot: at('new', 'Nothing to tap yet.'),
  blocked: at('new', 'Next, watch a recorded run, or come back later.'),
  retryMake: at('new', 'Next, tap Make my test vault to try again.'),
  retryPasskey: at('new', 'Next, tap Try the passkey again.'),
  approve: at('new', 'Next, approve the passkey sheet.'),
  km: at('new', 'Nothing to tap yet. The Confirm button comes up here.'),
  readAgain: at('new', 'Next, tap Read again. It keeps the passkey you just made.'),
  confirm: at('new', 'Next, tap Confirm. '),
  retryConfirm: at('new', 'Next, tap Confirm with your passkey.'),
  limitPhone: at('new', 'Next, wait, or turn Wi-Fi off to use mobile data, then start over.'),
  limitOther: at('new', 'Next, wait, or use another network, then start over.'),
  laterOrRun: at('new', 'Next, watch a recorded run, or start over later.'),
  making: at('new', 'Nothing to tap yet. Keep this page open: it holds this vault\'s keys.'),
  stillRelay: at('new', 'Nothing to tap yet. Still waiting for the relay.'),
  stillContract: at('new', 'Nothing to tap yet. Still reading the contract.'),
  every15Contract: at('new', 'Nothing to tap. This page reads the contract again every 15 s.'),
  funding: at('new', 'Nothing to tap yet. Step 3 starts by itself when ', ' lists the coin.'),
  fundRefused: at('new', 'Nothing to tap. Step 3 starts by itself when ', ' lists a coin at this address.'),
  every15Address: at('new', 'Nothing to tap. This page reads the address again every 15 s.'),
  every5: at('new', 'Nothing to tap. This page tries again every 5 s.'),
  relayAgain: at('new', 'Nothing to tap. This page asks the relay again by itself.'),
  watch: at('new', 'Nothing to tap. Watch what Bitcoin says.'),
  refused: at('new', 'Nothing to tap. Next, the thief asks the NEAR contract for that signature.'),
  askingHere: at('new', 'Nothing to tap yet. Cancel comes up here when the contract has the request.'),
  askingPhone: at('new', 'Nothing to tap yet. Your phone page opens here when the contract has the request.'),
  startOver: at('new', 'Next, start over.'),
  startOverOrRun: at('new', 'Next, start over, or watch a recorded run.'),
  nothingFurther: at('new', 'Nothing further runs on this page.'),
  tryAgain: at('new', 'Next, tap Try again.'),
  tryAgainContract: at('new', 'Next, tap Try again. It asks the contract only.'),
  opening: at('new', 'Nothing to tap. Opening your phone page, which reads this request from the contract.'),
  cancelWaiting: at('new', 'Next, tap Cancel before the clock runs out, and approve the passkey sheet.'),
  cancelNow: at('new', 'Next, tap Cancel now.'),
  sendingCancel: at('new', 'Nothing to tap. The relay sends your cancel, and the contract checks your passkey.'),
  doneTime: at('new', 'Done. This run took ', ' on this page, from Make my test vault to CANCELLED.'),
  done: at('new', 'Done.'),
  cancelHang: at('new', 'No passkey sheet yet? Tap Cancel again. If none comes, open the phone page: it can cancel this too.'),
  openPhone: at('new', 'Next, open the phone page.'),
  openPhoneWhy: at('new', 'Next, open the phone page: it reads this request and says what can cancel it.'),
  waitThenCancel: at('new', 'Next, wait, then tap Cancel.'),
  keepsReading: at('new', 'Nothing to tap. This page keeps reading the contract.'),
});

/**
 * The one Next sentence for what is on the screen. Pure: everything it needs is in `view`.
 *   view.step, view.state: the data-step and data-state the page shows. view.fail: a failure row of the spec (M1..C11,
 *   L2, T1r), or null; a sheet that has not shown is M3, M6 or C3. view.sense: { inApp }. view.rpId,
 *   view.bitcoin: the config's. view.mobile, view.limit ('hourly' or null) for M7. view.still: 'relay' or 'contract'
 *   after 15 s on one line. view.here: v2's Cancel on this page. view.kind: 'waiting' or 'unlocked'. view.took: m:ss.
 * Answers { text, tag }: one sentence, and 'Done' only for CANCELLED and the recap.
 */
export function nextOf(view) {
  const text = nextText(view);
  const tag = view.step === 'cancelled' || view.step === 'recap' ? 'Done' : null;
  return { text, tag };
}

function nextText(v) {
  const hang = (button) => hangWords(v.sense ?? {}, button);
  switch (v.fail ?? null) {
    case 'M1': return say(NEXT.retryMake);
    case 'M2': return say(NEXT.retryPasskey);
    case 'M3': return hang('Make my test vault');
    case 'M4': return say(NEXT.readAgain);
    case 'M5': return say(NEXT.retryConfirm);
    case 'M6': return hang('Confirm');
    case 'M7': return v.limit === 'hourly' ? say(v.mobile ? NEXT.limitPhone : NEXT.limitOther) : say(NEXT.laterOrRun);
    case 'M8': case 'M9': return say(NEXT.every15Contract);
    case 'D1': return say(NEXT.fundRefused, v.bitcoin);
    case 'D2': case 'D3': return say(NEXT.every15Address);
    case 'D4': case 'T1': return say(NEXT.every5);
    case 'T1r': return say(NEXT.relayAgain);
    case 'T1b': return say(NEXT.startOver);
    case 'T2': return say(NEXT.startOverOrRun);
    case 'T3': return say(NEXT.nothingFurther);
    case 'T4': case 'T5': case 'T6': case 'T8': return say(NEXT.tryAgain);
    case 'T7': return say(NEXT.tryAgainContract);
    case 'C1': return v.kind === 'unlocked' ? say(NEXT.cancelNow) : say(NEXT.cancelWaiting);
    case 'C2': return say(NEXT.retryPasskey);
    case 'C3': return say(NEXT.cancelHang);
    case 'C4': case 'C8': case 'C11': case 'L2': case 'crashed': return say(NEXT.openPhone);
    case 'C5': return say(NEXT.waitThenCancel);
    case 'C6': case 'C10': return say(NEXT.openPhoneWhy);
    case 'C7': case 'C9': return say(NEXT.keepsReading);
    case 'blocked': case 'no_config': return say(NEXT.blocked);
    case 'read_down': return say(NEXT.every5);
    default: break;
  }
  switch (v.state) {
    case 'boot': return say(NEXT.boot);
    case 'ready': return say(W.beforeMake, v.rpId);
    case 'sheet1': case 'sheet2': case 'tapped': return say(NEXT.approve);
    case 'km': return say(NEXT.km);
    case 'confirm': return say(NEXT.confirm) + say(W.beforeConfirm);
    case 'making':
      if (v.still === 'relay') return say(NEXT.stillRelay);
      if (v.still === 'contract') return say(NEXT.stillContract);
      return say(NEXT.making);
    case 'funding': return say(NEXT.funding, v.bitcoin);
    case 'count': case 'sending': return say(NEXT.watch);
    case 'refused': return say(NEXT.refused);
    case 'asking': return v.here ? say(NEXT.askingHere) : say(NEXT.askingPhone);
    case 'handoff': return say(NEXT.opening);
    case 'request': return v.kind === 'unlocked' ? say(NEXT.cancelNow) : say(NEXT.cancelWaiting);
    case 'cancel_sending': return say(NEXT.sendingCancel);
    case 'cancelled': case 'recap': return v.took ? say(NEXT.doneTime, v.took) : say(NEXT.done);
    default: return say(NEXT.boot);
  }
}

/** m:ss of a number of ms, whole seconds rounded down. */
export function runTime(ms) {
  const s = Math.max(0, Math.floor(ms / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`;
}
