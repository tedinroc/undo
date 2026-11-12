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

// Words and commands, in order. A command is `{ cmd }`, which the page sets in one unbroken piece, so a line never
// breaks inside a flag and leaves "--" at the end of one line and "method" at the start of the next.
const cmd = (text) => ({ cmd: text });
export const partsText = (parts) => parts.map((p) => (typeof p === 'string' ? p : p.cmd)).join('');

/**
 * What the page says about a signed call it holds, in plain words, with the command to send it. `unsure`: the relay
 * did not answer, so it may have sent the cancel all the same, and the page does not say it did not.
 */
export function ownCancelParts({ expiresAt, vaultHex, unsure = false }) {
  return [
    unsure
      ? `If the relay didn't send the cancel this page signed, any NEAR testnet account can, until ${utcTime(expiresAt)}: save it, then run `
      : `The relay didn't send the cancel this page signed. Any NEAR testnet account can, until ${utcTime(expiresAt)}: save it, then run `,
    cmd('node tools/cancel.mjs'), ' ', cmd(`--file ${ownCancelFileName(vaultHex)}`), ' ', cmd('--account YOUR-ACCOUNT'),
  ];
}

export const ownCancelWords = (fields) => partsText(ownCancelParts(fields));

/** What it says with no signed call in hand. */
export const OWN_PATH_PARTS = [
  'The relay is a convenience, and its limits are shared. Any NEAR testnet account can send a cancel: ', cmd('tools/cancel.mjs'),
  ' sends one this page signs, ', cmd('tools/freeze.mjs --method cancel'), ' signs one with the recovery file, and the cold key always works.',
];
export const OWN_PATH_LINE = partsText(OWN_PATH_PARTS);

/** With no relay in the way, only the recovery file is left to this page to name. */
export const RECOVERY_PATH_PARTS = ['If you hold this vault\'s recovery file, any NEAR testnet account can send the cancel: ', cmd('tools/freeze.mjs --method cancel')];
