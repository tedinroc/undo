// What a page says in place of a contract's panic, a Bitcoin node's JSON or the relay's code: one plain sentence for
// each. A screen shows the sentence once, and the page logs the raw text beside it with `logRaw`, so the console and
// any log still hold the exact words. The one exception is the refused frame, whose whole point is the node's own
// bytes: the thief tab shows those there, and nowhere else.
import { refusalKind } from '../../tools/lib/esplora.mjs';
import { ConfigError } from './config.mjs';

/** The contract's own name for why it refused, from any shape a refusal arrives in. Null when there is none. */
export function panicOf(raw) {
  const text = String(raw ?? '');
  // A view: HostError(GuestPanic { panic_msg: "SpendKeySuspended" }), or the same as JSON with escaped quotes.
  const view = /panic_msg\\?"?\s*:\s*\\?"([^"\\]+)/.exec(text);
  if (view) return view[1].trim();
  // A transaction: {"ActionError":{…"ExecutionError":"Smart contract panicked: NotUnlocked { unlock: 1 }"}}.
  const tx = /Smart contract panicked: ([^"\\]+)/.exec(text);
  return tx ? tx[1].replace(/[}\s]+$/, '').trim() : null;
}

// The contract's errors a page can meet, by name (crates/undo-core/src/error.rs). Any other refusal reads as the last line.
const CONTRACT_WORDS = {
  SpendKeySuspended: 'That key can\'t ask again.',
  Unauthorized: 'The contract did not take that signature.',
  BadNonce: 'The vault changed after this was signed.',
  IntentExpired: 'That signature ran out of time before the contract read it.',
  Frozen: 'The cold key has frozen this vault.',
  Inactive: 'This vault is not active yet.',
  NoInputs: 'There is no coin in it to send.',
  DustOutput: 'That amount is too small to send.',
  OutputsExceedInputs: 'It sends more than its coins hold.',
  FeeRateTooLow: 'Its fee is under the contract\'s floor.',
  FeeOverCap: 'Its fee is over what the contract will sign.',
  FeeBudgetExceeded: 'Its fee is over what the contract will sign today.',
  BadDestination: 'The contract does not send to that address.',
  OutpointBusy: 'That coin is already in another request.',
  PinnedInMultiInput: 'That coin is already in another request.',
  PendingCap: 'This vault already has as many requests waiting as it takes.',
  RequestNotFound: 'That request is not on the contract.',
  NotPending: 'That request is no longer waiting.',
  NotUnlocked: 'It is not unlocked yet.',
  AlreadySigned: 'The contract already signed it.',
  InFlight: 'The signer is already working on it.',
  RetryWindowClosed: 'The contract asks the signer for nothing more on this request.',
  NothingToSign: 'There is nothing left to sign.',
};

/** One sentence for a contract refusal, whatever shape it came in. */
export function contractWords(raw) {
  const name = /^[A-Za-z]+/.exec(panicOf(raw) ?? '')?.[0];
  return (name && Object.hasOwn(CONTRACT_WORDS, name) ? CONTRACT_WORDS[name] : null) ?? 'The NEAR contract refused it.';
}

/** One sentence for a Bitcoin node's refusal of a transaction, by what the refusal means. */
export function nodeRefusalWords(text) {
  const kind = refusalKind(String(text ?? ''));
  if (kind === 'script') return 'It needs a second signature.';
  if (kind === 'already') return 'The node already has this transaction.';
  if (kind === 'inputs_gone') return 'Its coin is already spent, or the node does not know it.';
  if (kind === 'bip68') return 'Its coin has not waited long enough for that path yet.';
  if (/min relay fee|mempool min fee|insufficient fee|fee not met/i.test(text)) return 'Its fee is too low for the node to pass it on.';
  if (/dust/i.test(text)) return 'An output is too small for the node to pass it on.';
  return 'The node refused it for another reason.';
}

// What answered in place of a node, by its HTTP status, in words. The status itself is in the console (logRaw).
const NOT_A_NODE = {
  429: 'Something on the way to the node said too many tries.',
  500: 'Something on the way to the node hit an error.',
  502: 'Something on the way to the node got no good answer from it.',
  503: 'Something on the way to the node said it isn\'t available right now.',
  504: 'Something on the way to the node gave up waiting for it.',
};

/** A sentence from the words esplora.mjs gives a fetch that got no answer: "the connection failed." */
const asSentence = (words) => {
  const text = String(words ?? 'no answer').trim();
  return `${text.charAt(0).toUpperCase()}${text.slice(1)}${/[.!?]$/.test(text) ? '' : '.'}`;
};

/**
 * One sentence for a POST that no node answered (postTxOnce's no_answer and transient): what answered, if anything.
 * A page, a proxy's status or a busy node says nothing about the transaction, and the sentence says only that.
 */
export function noNodeWords(answer) {
  if (!answer || answer.kind === 'no_answer') return asSentence(answer?.error);
  const { status } = answer;
  if (status >= 200 && status < 300) return 'Something answered, but not with this transaction.';
  if (status === 400 && !/<html/i.test(answer.body ?? '')) return 'The node was too busy to look at it.';
  return Object.hasOwn(NOT_A_NODE, status) ? NOT_A_NODE[status] : 'Something on the way to the node answered instead of it.';
}

// The relay's codes (site/lib/relay-table.mjs RELAY_ERRORS), each as a sentence.
const RELAY_WORDS = {
  relay_down: 'The relay is down.',
  bad_request: 'The relay did not take what this page sent.',
  would_refuse: 'The relay checked it first and did not send it.',
  bad_origin: 'The relay takes calls only from its own site.',
  unknown_method: 'The relay does not send that call.',
  pow_required: 'The relay wanted proof of work this page did not send.',
  pow_bad: 'The relay did not take this page\'s proof of work.',
  wrong_guard: 'This vault\'s guard is not this relay.',
  rate_limited: 'Too many tries through the relay. Wait a few seconds and try again.',
  daily_ceiling: 'The relay hit today\'s limit.',
  relay_not_configured: 'The relay is not set up.',
  state_store_down: 'The relay can\'t reach its records right now.',
  rpc_down: 'The relay can\'t reach NEAR right now.',
  stale_nonce: 'The relay\'s key was busy. Try again.',
  tx_refused: 'A NEAR node refused the transaction.',
  assertion_refused: 'The relay did not take that passkey signature.',
  not_this_relays: 'This relay sends cancels only for vaults it made.',
  already_sent: 'The relay already sent this one.',
  relay_reserve: 'The relay is keeping what it has left for cancels.',
  relay_error: 'The relay hit an error.',
  dispenser_empty: 'The relay has no test coins left.',
  esplora_down: 'The relay can\'t reach Bitcoin right now.',
};

/**
 * A wait the relay names, in the unit a person reads it in: seconds under two minutes, then minutes, then hours. The
 * relay's hourly and daily limits answer with thousands of seconds, and "2400 s" is not something to read on a phone.
 */
export function waitWords(seconds) {
  const s = Math.max(1, Math.ceil(Number(seconds) || 0));
  if (s < 120) return `${s} s`;
  if (s < 7200) return `about ${Math.ceil(s / 60)} minutes`;
  return `about ${Math.ceil(s / 3600)} hours`;
}

/** " It resets at 00:00 UTC.", from a status or a refusal that carries the time, and nothing from one that does not. */
export const resetWords = (at) => (Number.isFinite(at) && at > 0 ? ` It resets at ${new Date(at).toISOString().slice(11, 16)} UTC.` : '');

/**
 * One sentence for a relay refusal. A refusal that carries the contract's words reads as the contract's sentence. The
 * sender's tx_refused carries a node's refusal of the transaction, which never reached the contract, unless it names a
 * contract panic.
 */
export function relayWords(err) {
  if ((err?.code === 'would_refuse' || (err?.code === 'tx_refused' && panicOf(err.verbatim))) && err.verbatim) return contractWords(err.verbatim);
  if (err?.code === 'rate_limited' && err.retryAfterS) return `Too many tries through the relay. Wait ${waitWords(err.retryAfterS)} and try again.`;
  return (err?.code && Object.hasOwn(RELAY_WORDS, err.code) ? RELAY_WORDS[err.code] : null) ?? 'The relay said no.';
}

// The relay's codes for a call it refused before its sender signed anything: the checks and limits ahead of
// NearSender.send in handler.mjs. Any other code, and no answer, can come after a transaction went out (a resend whose
// first send landed unseen, then a nonce, a node or the state store that failed), so a page says it can't tell.
const BEFORE_SEND = new Set([
  'bad_request', 'bad_origin', 'unknown_method', 'pow_required', 'pow_bad', 'wrong_guard', 'rate_limited', 'daily_ceiling',
  'not_this_relays', 'assertion_refused', 'would_refuse', 'relay_reserve',
]);

/** Whether the relay's code says it sent nothing for this call. */
export const relaySentNothing = (code) => BEFORE_SEND.has(code);

/**
 * The relay's sentence for a code as a clause for a sentence to go on from (", so this page ..."): its first sentence,
 * with no full stop. Two codes say two ("... busy. Try again."), and the advice would not read after a comma.
 */
export const relayClause = (code) => relayWords({ code }).split('. ')[0].replace(/\.$/, '');

/**
 * A relay status a page could not read (RelayClient.status with reachable false), as only what the page saw, and with
 * no full stop, for a sentence to go on from. No answer says nothing about the relay itself, so "down" would be more
 * than a page knows: a phone with no signal gets no answer from a relay that is up. An answer that is not the relay's
 * JSON (a proxy's error page) was not the relay saying anything. The relay's own no is its own sentence.
 */
export function unreadRelayWords(status) {
  if (!status?.answered) return 'Can\'t reach the relay';
  if (!status.code) return 'Something answered for the relay, but not with its status';
  return relayClause(status.code);
}

/** The passkey checks a page makes before sending (site/lib/webauthn.mjs refusalOf), as sentences. */
export function passkeyWords(refusal) {
  if (/wrong rp id|origin not allowed|cross origin/.test(refusal ?? '')) return 'That passkey is for another site.';
  if (/user not present|user not verified/.test(refusal ?? '')) return 'The passkey did not confirm it was you.';
  return 'That passkey\'s signature does not check out for this vault.';
}

/** A browser's passkey error, by the kind sense.mjs gives it. The browser's own words go to the console. */
export function passkeyErrorWords(kind) {
  if (kind === 'no_support') return 'This browser can\'t use a passkey here.';
  // A SecurityError: this page's site and the passkey's name for it do not fit, at Make as at Cancel.
  if (kind === 'wrong_site') return 'This page isn\'t allowed to use a passkey here.';
  // Any other failure, at Make too, where a passkey may have been saved before the page failed to read it.
  return 'The passkey call failed.';
}

/**
 * What a contract account's access-key list says of a key that could replace its code at once. `keys` is the list
 * public RPC gave (NearReader.accessKeys), or null when no node gave one. 'none' only when every key on the list is a
 * function-call key, or the list is empty; a key this page cannot read counts as not known.
 */
export function codeKeyState(keys) {
  if (!Array.isArray(keys)) return 'unknown';
  let state = 'none';
  for (const key of keys) {
    const permission = key?.access_key?.permission;
    if (permission === 'FullAccess') return 'present';
    if (permission === null || typeof permission !== 'object' || !Object.hasOwn(permission, 'FunctionCall')) state = 'unknown';
  }
  return state;
}

// The 1 hour is the test instance's upgrade wait (the contract's `status` view says it as 60 min).
const UPGRADE_WORDS = {
  none: 'The operator can upgrade this test contract after 1 hour.',
  present: 'The operator can upgrade this test contract after a 1 hour public wait. Today its deploy key is still on it, and that key could change the code at once.',
  unknown: 'The operator can upgrade this test contract after a 1 hour public wait. This page could not read whether its deploy key is still on it, and such a key could change the code at once.',
};

/** The phone page's sentence on upgrades: the short one only when the account's key list shows no full-access key. */
export const upgradeWords = (keys) => UPGRADE_WORDS[codeKeyState(keys)];

/** A config this page refused, in this project's own words for it ("config: rpc needs at least one URL"), or a sentence. */
export const configWords = (err) => (err instanceof ConfigError ? err.message : 'Its settings file is not one this page can read.');

let lastLogged = null;

/** The raw words beside the sentence, for whoever opens the console. The same line twice in a row is logged once. */
export function logRaw(where, raw) {
  if (raw === null || raw === undefined || raw === '') return;
  const line = `undo: ${where}: ${typeof raw === 'string' ? raw : JSON.stringify(raw)}`;
  if (line === lastLogged) return;
  lastLogged = line;
  globalThis.console?.info?.(line);
}
