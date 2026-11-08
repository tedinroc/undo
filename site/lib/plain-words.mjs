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
  bad_request: 'The relay could not read what this page sent.',
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
  tx_refused: 'The NEAR contract refused it.',
  assertion_refused: 'The relay did not take that passkey signature.',
  not_this_relays: 'This relay sends cancels only for vaults it made.',
  already_sent: 'The relay already sent this one.',
  relay_reserve: 'The relay is keeping what it has left for cancels.',
  relay_error: 'The relay hit an error.',
  dispenser_empty: 'The relay has no test coins left.',
  esplora_down: 'The relay can\'t reach Bitcoin right now.',
};

/** One sentence for a relay refusal. A refusal that carries the contract's words reads as the contract's sentence. */
export function relayWords(err) {
  if ((err?.code === 'tx_refused' || err?.code === 'would_refuse') && err.verbatim) return contractWords(err.verbatim);
  if (err?.code === 'rate_limited' && err.retryAfterS) return `Too many tries through the relay. Wait ${err.retryAfterS} s and try again.`;
  return (err?.code && Object.hasOwn(RELAY_WORDS, err.code) ? RELAY_WORDS[err.code] : null) ?? 'The relay said no.';
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
  if (kind === 'wrong_site') return 'That passkey is for another site.';
  return 'The passkey did not sign.';
}

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
