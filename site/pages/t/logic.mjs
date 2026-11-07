// The thief tab's rules with no page around them, so a test can hold each one down without a browser.
import { addressToSpk } from '../../../tools/lib/btc.mjs';
import { fromHex } from '../../../tools/lib/bytes.mjs';

/** Refused before anything is signed: this is a demo for test coins, and a bc1 address is real money. */
export function destinationProblem(text) {
  const address = String(text ?? '').trim();
  if (address === '') return 'empty';
  if (!address.startsWith('tb1')) return 'not_test_address';
  try {
    addressToSpk('mutinynet', address);
  } catch {
    return 'bad_address';
  }
  return null;
}

/** Decodes as a tb1 address on every network: an output script is the same bytes on regtest and signet. */
export const destinationSpk = (text) => addressToSpk('mutinynet', String(text).trim());

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
  if (!status.reachable || status.general?.why === 'relay_down') return 'The relay is down, so this tab can\'t ask the NEAR contract or call execute.';
  if (status.general?.up || status.general?.calls_fit) return null;
  if (status.general?.why === 'daily_ceiling') return 'The relay hit today\'s limit, so this tab can\'t ask the NEAR contract or call execute.';
  if (status.general?.why === 'relay_reserve') return 'The relay is keeping what it has left for cancels, so this tab can\'t ask the NEAR contract or call execute.';
  return `The relay can't send for this tab right now: ${status.general?.why ?? 'no reason given'}`;
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
