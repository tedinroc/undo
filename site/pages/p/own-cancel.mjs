// The cancel that never needs the relay. When the relay will not send a cancel this page signed, the page keeps the
// signed call and offers it as a file, and any NEAR testnet account can send it with tools/cancel.mjs. The contract
// checks the passkey, not who sends it. The file holds no secret: the new spend key's seed was dropped when it was made.
// No imports, so Node tests can read this without a browser.

/** Refusals that say something about the relay, not about the cancel: the same signed call can go another way. */
const RELAY_SIDE = new Set([
  'not_this_relays', 'daily_ceiling', 'rate_limited', 'relay_down', 'rpc_down', 'stale_nonce', 'state_store_down',
  'relay_not_configured', 'relay_error', 'tx_refused', 'relay_reserve',
]);

/** The no-button reasons that are the relay's: the passkey here can still sign a cancel to send another way. */
const RELAY_WHYS = new Set([
  'relay_down', 'relay_owner_down', 'rpc_down', 'owner_key_low', 'owner_key_missing', 'relay_not_configured', 'daily_ceiling',
  'not_this_relays', 'state_store_down',
]);

export const relayRefusedIt = (code) => RELAY_SIDE.has(code);

export const relayIsWhy = (why) => RELAY_WHYS.has(why);

/** The file tools/cancel.mjs reads. Same arguments the relay was given, to the same contract. */
export function ownCancelFile({ contract, method, args }) {
  return `${JSON.stringify({ format: 'undo-owner-call-v1', contract, method, args }, null, 2)}\n`;
}

export const ownCancelFileName = (vaultHex) => `undo-cancel-${vaultHex.slice(0, 8)}.json`;

const utcTime = (ms) => `${new Date(ms).toISOString().slice(11, 16)} UTC`;

/** What the page says about a signed call it holds, in plain words. */
export function ownCancelWords({ expiresAt, vaultHex }) {
  return `This page signed a cancel that the relay did not send. Any NEAR testnet account can send it, until ${utcTime(expiresAt)}: save it, then run node tools/cancel.mjs --file ${ownCancelFileName(vaultHex)} --account YOUR-ACCOUNT`;
}

/** What it says with no signed call in hand. */
export const OWN_PATH_LINE = 'Any NEAR testnet account can send a cancel without this relay: tools/cancel.mjs sends one this page signs, and tools/freeze.mjs --method cancel signs one with the recovery file.';
