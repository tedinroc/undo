// The thief tab's rules with no page around them, so a test can hold each one down without a browser.
import { addressPrefix, addressToSpk } from '../../../tools/lib/btc.mjs';
import { fromHex } from '../../../tools/lib/bytes.mjs';
import { relayWords, unreadRelayWords } from '../../../site/lib/plain-words.mjs';
import { retryClosesAt } from '../../../site/lib/request-state.mjs';

/** The decoder's refusal of `text` on `network`, or null when it decodes. */
function refusalOf(text, network) {
  try {
    addressToSpk(network, String(text ?? '').trim());
    return null;
  } catch (err) {
    return err;
  }
}

/**
 * Refused before anything is signed: this is a demo for test coins, so only the vault's own network's segwit address
 * goes, `tb1` on Mutinynet and `bcrt1` on a local regtest, the same form the phone shows. `network` is the contract's.
 */
export function destinationProblem(text, network) {
  const address = String(text ?? '').trim();
  if (address === '') return 'empty';
  const prefix = addressPrefix(network);
  if (prefix === null || prefix === 'bc1') return 'no_network';
  const refused = refusalOf(address, network);
  if (refused?.code === 'other_network') return refused.hrp === 'bc' ? 'not_test_address' : 'other_network';
  if (refused?.code === 'uri') return 'uri';
  if (refused) return 'bad_address';
  // This network's own, and not in the one form both pages print: base58, or upper case.
  if (!address.startsWith(prefix)) return 'not_test_address';
  return null;
}

/** What the tab says under "send to": one plain sentence, or '' when nothing is wrong. `place` is the network's name on screen. */
export function destinationWords(text, network, place = network) {
  const problem = destinationProblem(text, network);
  if (problem === 'not_test_address') return `This demo only sends to test addresses that start with ${addressPrefix(network)}.`;
  if (problem === 'other_network') return `That is a ${refusalOf(text, network).networkName} address; this vault is on ${place}.`;
  if (problem === 'uri') return 'That is a bitcoin: link. Paste only the address in it.';
  if (problem === 'bad_address') return 'That address does not check out.';
  return '';
}

/** The output script, for the vault's own network: the same bytes the phone turns back into that one address. */
export const destinationSpk = (text, network) => addressToSpk(network, String(text).trim());

/** 32 bytes from what was pasted, or null. */
export function parseSeed(text) {
  const hex = String(text ?? '').replace(/\s+/g, '').toLowerCase();
  return /^[0-9a-f]{64}$/.test(hex) ? fromHex(hex) : null;
}

/** Same amount in S1, S4 and S7: the coins, before fee. `request.amount` alone would read less. */
export const sumOfInputs = (inputs) => inputs.reduce((sum, c) => sum + c.value, 0);
export const satsText = (value) => `${value.toLocaleString('en-US')} sats`;

/**
 * Where the fuse has burned to, 1 at the proposal and 0 at zero. The last 45 s take most of the track, so it visibly
 * burns in a 7 s shot, as the animatic has it, and it never sits still earlier. The ends are exact, and the mark is at 0:00.
 */
const KNEE_MS = 45_000;
const KNEE_FRACTION = 0.85;
export function fuseFraction(remainingMs, totalMs) {
  if (!(remainingMs > 0)) return 0;
  if (remainingMs <= KNEE_MS || !(totalMs > KNEE_MS)) return Math.min(1, (remainingMs / KNEE_MS) * KNEE_FRACTION);
  return Math.min(1, KNEE_FRACTION + (1 - KNEE_FRACTION) * ((remainingMs - KNEE_MS) / (totalMs - KNEE_MS)));
}

/** The film's beat: 1 right after a second boundary, falling away before the next. */
export function tickPulse(remainingMs) {
  const seconds = remainingMs / 1000;
  return (seconds - Math.floor(seconds)) ** 5;
}

/** A contract refusal that means only that this clock read zero a moment before the chain did. Worth sending again. */
export const isNotYetUnlocked = (failure) => typeof failure === 'string' && failure.includes('NotUnlocked');

/** What this tab can say about the relay, in its own words. Null while it can do its job. */
export function relaySentence(status) {
  if (!status) return null;
  if (!status.reachable) return `${unreadRelayWords(status)}, so this tab may not be able to ask the NEAR contract or call execute.`;
  if (status.general?.up || status.general?.calls_fit) return null;
  if (status.general?.why === 'daily_ceiling') return 'The relay hit today\'s limit, so this tab can\'t ask the NEAR contract or call execute.';
  if (status.general?.why === 'relay_reserve') return 'The relay is keeping what it has left for cancels, so this tab can\'t ask the NEAR contract or call execute.';
  // Any other reason, as the relay's own sentence and without its code.
  return `${relayWords({ code: status.general?.why }).replace(/\.$/, '')}, so this tab can't ask the NEAR contract or call execute.`;
}

/**
 * The request a link means when it names none. `pending` keeps dead requests until the next state change, so
 * each is judged by reading it. Newest first. `judge(id)` answers a state from requestState.
 */
export async function liveRequestIn(pending, judge) {
  for (const id of [...pending].sort((a, b) => b - a)) {
    const state = await judge(id);
    if (state?.kind === 'waiting' || state?.kind === 'unlocked' || state?.kind === 'signing') return id;
  }
  return null;
}

/**
 * A sign call can die on the signer, and `execute` asks again for what is missing, so while a request is signing this
 * tab sends it again every `everyMs`. It stops when the request leaves Signing, and when the contract will ask the
 * signer for nothing more (retryClosesAt), since every send after that would be refused. `read()`
 * answers { signing, request, chainNow } as the tab last read them. Answers 'left_signing' or 'retry_closed'.
 */
export async function resendWhileSigning({ read, send, sleep, everyMs }) {
  for (;;) {
    const before = signingStop(read());
    if (before) return before;
    await sleep(everyMs);
    const after = signingStop(read());
    if (after) return after;
    await send().catch(() => {});
  }
}

function signingStop({ signing, request, chainNow }) {
  if (!signing) return 'left_signing';
  const closesAt = retryClosesAt(request);
  return closesAt !== null && chainNow >= closesAt ? 'retry_closed' : null;
}

/**
 * The line under the digits (`text`) and root's data-auto (`auto`). `sentence` is relaySentence's for the status this tab
 * holds. "off" only on the relay's own word or the contract's: a status the relay answered that says it can't, or, at
 * zero, the relay's or the contract's refusal of the last execute (`blocked`). A status this tab could not read, or an
 * execute with no answer (`unanswered`), says no such thing, and at zero the tab sends execute all the same, again 2 s
 * after each call that failed.
 */
export function autoLine({ firing, status, sentence, blocked = null, unanswered = false }) {
  if ((sentence && status?.reachable) || (firing && blocked)) return { auto: 'off', text: 'auto-execute off' };
  if (!firing) return { auto: 'armed', text: 'auto-execute armed' };
  if (unanswered) return { auto: 'on', text: 'auto-execute on, retrying' };
  return sentence ? { auto: 'on', text: 'auto-execute on' } : { auto: 'firing', text: 'The contract signs' };
}
