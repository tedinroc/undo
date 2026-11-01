// Every encoding the contract checks a signature over, written from contracts/undo/src/auth.rs and
// the argument tuples in contracts/undo/src/lib.rs. A mismatch shows up as a refused call on the
// real wasm: tools/test/sandbox-intents.mjs runs each one there, and the cold-key digests also go
// through an independent Rust encoder in tools/rust-check.
import { b } from './borsh.mjs';
import { concat, fixedHex, reversed, toHex, utf8 } from './bytes.mjs';
import { ed25519, p256, secp256k1, sha256 } from './crypto.mjs';

export const SPEND_TAG = 'undo-spend-v1';
export const PASSKEY_TAG = 'undo-passkey-v1';
export const COLD_TAG = 'undo-cold-v1';
const CREATE_TAG = 'undo-create-v1';
const VAULT_ID_TAG = 'undo-vault-id-v1';
const LEAF_POP_TAG = 'undo-leaf-pop-v1';

export const POLICY_FIELDS = [
  't_known_ms', 't_new_ms', 't_new_unguarded_ms', 'hold_ms', 't_stuck_ms', 'fee_cap_tx', 'fee_budget_24h', 'outflow_cap_24h',
];

export function vaultId({ contract, ks, ku, keLeaf, keIntent, kp, csv }) {
  return sha256(concat(
    b.str(VAULT_ID_TAG),
    b.str(contract),
    b.raw(ks),
    b.bytes(ku),
    b.bytes(keLeaf),
    b.bytes(keIntent),
    b.bytes(kp),
    b.u32(csv),
  ));
}

export function createDigest({ contract, vault, km, rpIdHash, guard, policy, expiresAt }) {
  return sha256(concat(
    b.str(CREATE_TAG),
    b.str(contract),
    b.raw(vault),
    b.bytes(km),
    b.raw(rpIdHash),
    b.option(guard, b.str),
    ...POLICY_FIELDS.map((f) => b.u64(policy[f])),
    b.u64(expiresAt),
  ));
}

/**
 * What the Bitcoin escape key signs, once, when a vault is created, and the only thing it signs on
 * NEAR. A sighash is SHA-256 of exactly 32 bytes, and this is SHA-256 of 48, so the two cannot be
 * made equal. Built here from the create digest; there is no entry point that takes it from outside.
 */
export function leafPopDigest(createDigestBytes) {
  return sha256(concat(utf8(LEAF_POP_TAG), createDigestBytes));
}

export function intentDigest({ tag, contract, vault, method, args, expiresAt, nonce }) {
  return sha256(concat(
    b.str(tag),
    b.str(contract),
    b.raw(vault),
    b.str(method),
    b.raw(sha256(args)),
    b.u64(expiresAt),
    b.option(nonce, b.u64),
  ));
}

/** `txid` is display order in JSON and internal order in the signed bytes. */
function spendInputs(inputs) {
  return b.vec(inputs, (c) => concat(b.raw(reversed(fixedHex(c.txid, 32, 'txid'))), b.u32(c.vout), b.u64(c.value)));
}

// Arguments as each method commits to them. Keep these next to each other: they are the contract.
export const argBytes = {
  propose_btc: ({ inputs, to, amount, change, memo }) => concat(spendInputs(inputs), b.bytes(to), b.u64(amount), b.option(change, b.u64), b.option(memo ?? null, b.str)),
  reclaim: ({ inputs, fee }) => concat(spendInputs(inputs), b.u64(fee)),
  cancel: ({ request }) => b.u64(request),
  cancel_all_and_rotate: ({ newKs }) => b.raw(newKs),
  raise_fee_cap: ({ request, cap }) => concat(b.u64(request), b.u64(cap)),
  freeze: ({ until }) => b.u64(until),
  unfreeze: () => new Uint8Array(0),
  veto_grant: ({ grant }) => b.u64(grant),
  recover_begin: ({ newPasskey, rpIdHash }) => concat(b.bytes(newPasskey), b.raw(rpIdHash)),
  recover_cancel: () => new Uint8Array(0),
  add_destination: ({ script }) => b.bytes(script),
  remove_destination: ({ script }) => b.bytes(script),
  set_policy: ({ policy }) => concat(...POLICY_FIELDS.map((f) => b.u64(policy[f]))),
  set_guard: ({ guard }) => b.option(guard ?? null, b.str),
  clear_hold: ({ request }) => b.u64(request),
};

/** r || s || v, the form `env::ecrecover` takes. */
export function signSecp(digest, secret) {
  const sig = secp256k1.sign(digest, secret, { lowS: true, prehash: false });
  return concat(sig.toCompactRawBytes(), Uint8Array.of(sig.recovery));
}

export function signEd25519(digest, secret) {
  return ed25519.sign(digest, secret);
}

const base64url = (bytes) => Buffer.from(bytes).toString('base64url');

/**
 * A WebAuthn assertion from a software key. Labelled [software authenticator] wherever it matters.
 * `flags` 0x05 is UP and UV. `highS` returns the form a real authenticator often gives.
 */
export function softAssertion({ secret, digest, origin, rpId, flags = 0x05, highS = false }) {
  const auth = concat(sha256(utf8(rpId)), Uint8Array.of(flags), new Uint8Array([0, 0, 0, 1]));
  const client = utf8(JSON.stringify({ type: 'webauthn.get', challenge: base64url(digest), origin }));
  const prehash = sha256(concat(auth, sha256(client)));
  let sig = p256.sign(prehash, secret, { prehash: false, lowS: true });
  if (highS) sig = new p256.Signature(sig.r, p256.CURVE.n - sig.s);
  return {
    authenticator_data: toHex(auth),
    client_data_json: toHex(client),
    signature: toHex(sig.toCompactRawBytes()),
  };
}
