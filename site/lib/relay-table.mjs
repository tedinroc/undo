// The relay's contract, one table for the page and the Pages Function. Which contract methods it will send,
// on which key, with how much gas and at what cost against the daily ceilings. Anything not listed is
// refused, including every method that moves a key or a policy, until something on screen needs it.

export const OWNER = 'owner';
export const GENERAL = 'general';

/**
 * The attached deposit that becomes a vault's storage credit. Measured on the wasm: under 13 mN is refused at
 * create, 15 mN cannot pay for a proposal, 20 mN finishes one film loop with 1 mN left, and this leaves about
 * 11 mN, enough for two more proposals. See the `measure` test in site/test/sandbox.test.mjs.
 */
export const CREATE_DEPOSIT_MILLI = 30;

/**
 * tgas: attached, unused gas comes back. costMicro: what a call counts for against its key's daily
 * ceiling in millionths of a NEAR, from burnt gas in docs/measurements.md at 1e-4 NEAR per Tgas, rounded up.
 * perIpHour: limit per hashed IP. perVaultMinute: limit per vault. perVaultDay: shared across a key's methods.
 * unchecked*: the owner key's own, smaller limits for a call the relay could not check, because its read of the vault
 * failed and the signature did not match the keys the vault was made with. They are counted apart, so such calls can
 * never use up what a checked cancel on the same vault may send.
 * operatorOnly: off the public list. A stranger could otherwise make a vault read guard online, which halves
 * its wait, so it answers only to the BEAT_TOKEN binding, and with none set not at all.
 */
export const RELAY_METHODS = Object.freeze({
  create_vault: { key: GENERAL, tgas: 120, heartbeatTgas: 10, depositMilli: CREATE_DEPOSIT_MILLI, pow: true, costMicro: CREATE_DEPOSIT_MILLI * 1000 + 2000, perIpHour: 3 },
  activate: { key: GENERAL, tgas: 60, costMicro: 1500, perIpHour: 10 },
  heartbeat: { key: GENERAL, tgas: 10, costMicro: 400, perIpHour: 20, perVaultMinute: 2, operatorOnly: true },
  propose_btc: { key: GENERAL, tgas: 40, costMicro: 1200, perIpHour: 10 },
  execute: { key: GENERAL, tgas: null, costMicro: 3000, perIpHour: 20, perVaultMinute: 30 },
  // No per-IP limit: a phone on a shared address must still be able to cancel.
  cancel: { key: OWNER, tgas: 30, costMicro: 600, perVaultMinute: 6, perVaultDay: 12, uncheckedPerVaultMinute: 2, uncheckedPerVaultDay: 4 },
  cancel_all_and_rotate: { key: OWNER, tgas: 30, costMicro: 600, perVaultMinute: 6, perVaultDay: 12, uncheckedPerVaultMinute: 2, uncheckedPerVaultDay: 4 },
});

/**
 * Calls the relay could not check may take at most this share of the owner ceiling, so they never stop a checked cancel.
 * A vault's first such call of the day may go up to twice this, so junk on other vaults cannot use up the one cancel of
 * an owner whose new passkey the relay has not seen. Twice this is the most they ever take.
 */
export const OWNER_UNCHECKED_SHARE = 0.1;

/**
 * What the relay keeps of its account's balance for the owner key's cancels: the status floor, plus a whole day of
 * owner sends at the owner ceiling. The two keys sit on one account, so a general send that would leave less than
 * this is refused, and no amount of general traffic can spend what a cancel needs. In yoctoNEAR.
 */
export const OWNER_FLOOR_YOCTO = 50_000_000_000_000_000_000_000n;
export const ownerReserveYocto = (ownerCeilingMicro) => OWNER_FLOOR_YOCTO + BigInt(Math.ceil(ownerCeilingMicro)) * 1_000_000_000_000_000_000n;

/**
 * Where a cancel goes when this relay will not send it: from any NEAR testnet account, with no relay at all. The relay
 * is a convenience, and its limits are shared, so the words say so and do not promise it will send.
 */
export const OWN_ACCOUNT_PATH = 'This relay is a convenience: any NEAR testnet account can send the cancel without it. tools/cancel.mjs sends a cancel this page signed, tools/freeze.mjs --method cancel signs one with the recovery file, and the cold key always works, relay or not.';

/** Vaults may take this share of the general ceiling, so a day of them still leaves room for calls already under way. */
export const CREATE_SHARE = 0.7;

/**
 * What a 30 Tgas owner send holds of its key's allowance until its refund lands, measured: about 0.031 NEAR. One
 * vault can have 6 in flight at once, and the owner ceiling's worth of vaults, at 12 sends a day each, can all burst
 * together. OWNER_ALLOWANCE_NEAR must stay above that, or a burst of sends refuses an innocent cancel.
 */
export const OWNER_SEND_HOLD_MILLI = 31;
export const CEILING_OWNER_DEFAULT_MICRO = 300_000;
export const ownerAllowanceNeeded = (ceilingMicro, { costMicro, perVaultMinute, perVaultDay } = RELAY_METHODS.cancel_all_and_rotate) => {
  const vaults = Math.ceil(ceilingMicro / costMicro / perVaultDay);
  return (Math.min(vaults * perVaultMinute, Math.ceil(ceilingMicro / costMicro)) * OWNER_SEND_HOLD_MILLI) / 1000;
};
export const OWNER_ALLOWANCE_NEAR = 8;

/**
 * Prepaid gas for `execute`. Measured least: 46, 130, 344 and 688 Tgas at 1, 3, 8 and 16 inputs with 30 + 10
 * per input (docs/measurements.md), and the contract refuses less than it needs.
 */
export const executeTgas = (inputs, { signTgas, callbackTgas }) => inputs * (signTgas + callbackTgas + 4) + 6;

export const RELAY_ERRORS = Object.freeze({
  bad_request: 400,
  would_refuse: 422,
  bad_origin: 403,
  unknown_method: 400,
  pow_required: 400,
  pow_bad: 400,
  wrong_guard: 400,
  rate_limited: 429,
  daily_ceiling: 429,
  relay_not_configured: 503,
  state_store_down: 503,
  rpc_down: 503,
  stale_nonce: 503,
  tx_refused: 422,
  assertion_refused: 422,
  not_this_relays: 422,
  already_sent: 409,
  relay_reserve: 503,
  relay_error: 500,
  dispenser_empty: 503,
  esplora_down: 503,
});

const isHex = (v, bytes) => typeof v === 'string' && /^([0-9a-f]{2})+$/.test(v) && (bytes === undefined || v.length === bytes * 2);
const isU64 = (v) => Number.isSafeInteger(v) && v >= 0;
const only = (obj, fields) => obj && typeof obj === 'object' && !Array.isArray(obj) && Object.keys(obj).every((k) => fields.includes(k));
// Exactly the contract's fields: a body it could not parse would still cost the owner key a send.
const isWebAuthn = (a) => only(a, ['authenticator_data', 'client_data_json', 'signature']) && isHex(a.authenticator_data) && a.authenticator_data.length <= 2048
  && isHex(a.client_data_json) && a.client_data_json.length <= 4096 && isHex(a.signature, 64);
// One of the two, never both: the contract's enum takes exactly one.
const isCancelAuth = (auth) => only(auth, ['Passkey', 'Cold']) && Object.keys(auth).length === 1
  && (Object.hasOwn(auth, 'Passkey') ? isWebAuthn(auth.Passkey) : isHex(auth.Cold, 65));

const MAX_INPUTS = 16;

const SHAPES = {
  create_vault: (a) => only(a, ['k_s', 'k_u', 'k_m', 'k_e_leaf', 'k_e_intent', 'passkey', 'guard', 'csv', 'policy', 'expires_at', 'pop_s', 'pop_u', 'pop_e', 'pop_leaf', 'pop_p'])
    && isHex(a.k_s, 32) && isHex(a.k_u, 33) && isHex(a.k_m, 33) && isHex(a.k_e_leaf, 33) && isHex(a.k_e_intent, 33)
    && only(a.passkey, ['pubkey', 'rp_id_hash']) && isHex(a.passkey?.pubkey, 33) && isHex(a.passkey?.rp_id_hash, 32)
    && typeof a.guard === 'string' && Number.isInteger(a.csv) && a.csv >= 1 && a.csv <= 65535 && a.policy === null && isU64(a.expires_at)
    && isHex(a.pop_s, 64) && isHex(a.pop_u, 65) && isHex(a.pop_e, 65) && isHex(a.pop_leaf, 65) && isWebAuthn(a.pop_p),
  activate: (a) => only(a, ['vault']) && isHex(a.vault, 32),
  heartbeat: (a) => only(a, ['vault']) && isHex(a.vault, 32),
  propose_btc: (a) => only(a, ['vault', 'inputs', 'to', 'amount', 'change', 'half_sigs', 'nonce', 'expires_at', 'spend_sig', 'memo'])
    && isHex(a.vault, 32) && Array.isArray(a.inputs) && a.inputs.length >= 1 && a.inputs.length <= MAX_INPUTS
    && a.inputs.every((c) => only(c, ['txid', 'vout', 'value']) && isHex(c.txid, 32) && isU64(c.vout) && isU64(c.value))
    && isHex(a.to) && a.to.length <= 80 && isU64(a.amount) && (a.change === null || isU64(a.change))
    && Array.isArray(a.half_sigs) && a.half_sigs.length === a.inputs.length && a.half_sigs.every((s) => isHex(s, 65))
    && isU64(a.nonce) && isU64(a.expires_at) && isHex(a.spend_sig, 64) && (a.memo === null || (typeof a.memo === 'string' && a.memo.length <= 140)),
  execute: (a) => only(a, ['vault', 'request']) && isHex(a.vault, 32) && isU64(a.request),
  cancel: (a) => only(a, ['vault', 'request', 'expires_at', 'auth']) && isHex(a.vault, 32) && isU64(a.request) && isU64(a.expires_at)
    && isCancelAuth(a.auth),
  cancel_all_and_rotate: (a) => only(a, ['vault', 'new_k_s', 'nonce', 'expires_at', 'assertion']) && isHex(a.vault, 32) && isHex(a.new_k_s, 32) && isU64(a.nonce) && isU64(a.expires_at) && isWebAuthn(a.assertion),
};

/** Largest body the relay reads. Sixteen inputs and a long client_data_json fit well inside. */
export const MAX_RELAY_BODY = 24 * 1024;

/** Returns null, or the error code to answer with. */
export function relayBodyProblem(body) {
  if (!only(body, ['method', 'args', 'pow'])) return 'bad_request';
  // A string only: Object.hasOwn coerces, so ["cancel"] would pass here and miss every check keyed on the name.
  if (typeof body.method !== 'string' || !Object.hasOwn(RELAY_METHODS, body.method)) return 'unknown_method';
  if (!SHAPES[body.method](body.args)) return 'bad_request';
  if (RELAY_METHODS[body.method].pow && !Number.isSafeInteger(body.pow)) return 'pow_required';
  return null;
}
