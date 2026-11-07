// The relay does not spend the owner key on a cancel that cannot work. Without this, anyone could send junk
// `cancel`s and use up a victim vault's per-minute limit, or the whole owner ceiling, for free, and that is
// the one thing the owner key exists to prevent. Each check is one the contract makes too, in a subset:
// nothing here may refuse a cancel the contract would take.
//
// A failed read lets the cancel through, but it is checked as far as it can be: against the keys the vault was made
// with, which this relay kept when it sent the create_vault. One that does not match them is marked unchecked, and
// is counted apart, so junk sent while the chain cannot be read never uses up what a real cancel may send.
//
// A signature alone is not enough: anyone can sign for their own vault. So a call that is well signed and still
// cannot work is refused as well: an expired intent, a nonce from far ahead, a request already past cancelling.
import { COLD_TAG, argBytes, intentDigest } from '../../../tools/lib/intent.mjs';
import { concat, fromHex } from '../../../tools/lib/bytes.mjs';
import { secp256k1, sha256 } from '../../../tools/lib/crypto.mjs';
import { toBase64Url } from '../../lib/base64.mjs';
import { cancelDigest, rotateDigest } from '../../lib/intents.mjs';

// P-256: y^2 = x^3 - 3x + b.
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;

function modPow(base, power) {
  let out = 1n;
  let b = base % P;
  for (let e = power; e > 0n; e >>= 1n) {
    if (e & 1n) out = (out * b) % P;
    b = (b * b) % P;
  }
  return out;
}

/** The 65-byte point WebCrypto takes, from the 33-byte key the contract stores. Null if it is on no curve. */
export function p256Uncompressed(compressed) {
  if (compressed.length !== 33 || (compressed[0] !== 2 && compressed[0] !== 3)) return null;
  const x = BigInt(`0x${[...compressed.slice(1)].map((v) => v.toString(16).padStart(2, '0')).join('')}`);
  if (x >= P) return null;
  const y2 = (((x * x * x - 3n * x + B) % P) + P) % P;
  let y = modPow(y2, (P + 1n) >> 2n);
  if ((y * y) % P !== y2) return null;
  if (Number(y & 1n) !== compressed[0] - 2) y = P - y;
  const out = new Uint8Array(65);
  out[0] = 4;
  out.set(compressed.slice(1), 1);
  out.set(fromHex(y.toString(16).padStart(64, '0')), 33);
  return out;
}

/** Null when the challenge is this digest, or the refusal text in the contract's words. Needs no read. */
function challengeProblem(assertion, digest) {
  const auth = fromHex(assertion.authenticator_data);
  if (auth.length < 37) return 'webauthn: short authenticator data';
  let client;
  try {
    client = JSON.parse(new TextDecoder().decode(fromHex(assertion.client_data_json)));
  } catch {
    return 'webauthn: bad client data';
  }
  if (client?.type !== 'webauthn.get') return 'webauthn: wrong type';
  if (client.challenge !== toBase64Url(digest)) return 'webauthn: wrong challenge';
  return null;
}

/** True, false, or null when the key is on no curve, so nothing here can tell. */
async function passkeySigned(assertion, passkeyHex) {
  const point = typeof passkeyHex === 'string' ? p256Uncompressed(fromHex(passkeyHex)) : null;
  if (!point) return null;
  const algorithm = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
  const key = await crypto.subtle.importKey('raw', point, algorithm, false, ['verify']);
  const message = concat(fromHex(assertion.authenticator_data), sha256(fromHex(assertion.client_data_json)));
  return crypto.subtle.verify(algorithm, key, fromHex(assertion.signature), message);
}

function coldSigned(args, contract, coldHex) {
  if (typeof coldHex !== 'string' || coldHex.length !== 66) return null;
  const digest = intentDigest({ tag: COLD_TAG, contract, vault: fromHex(args.vault), method: 'cancel', args: argBytes.cancel({ request: args.request }), expiresAt: args.expires_at, nonce: null });
  const signature = fromHex(args.auth.Cold);
  try {
    return secp256k1.verify(signature.slice(0, 64), digest, fromHex(coldHex), { prehash: false, lowS: true });
  } catch {
    return null;
  }
}

/** Whether the call is signed by these keys: true, false, or null when one of them cannot be read as a key. */
const signedBy = (passkey, args, contract, keys) => (passkey ? passkeySigned(passkey, keys.passkey) : coldSigned(args, contract, keys.k_e_intent));

/**
 * The row a signed owner call takes in the relay's state store: vault, method, signer, nonce or request, expiry. A
 * second body with all of these the same is the same call, so it is charged once.
 */
export function ownerCallKey(method, args) {
  if (method === 'cancel_all_and_rotate') return `${method}:passkey:${args.nonce}:${args.expires_at}`;
  return `${method}:${args.auth.Passkey ? 'passkey' : 'cold'}:${args.request}:${args.expires_at}`;
}

// The relay's clock against the chain's. The contract is the one that decides at the edge.
const EXPIRY_GRACE_MS = 60_000;
// A node may be a little behind on the nonce, never a thousand rotations.
const NONCE_AHEAD_LIMIT = 2;

const refuse = (problem) => ({ problem, checked: false });
const passkeyOf = (method, args) => (method === 'cancel_all_and_rotate' ? args.assertion : args.auth.Passkey ?? null);

/** What can be refused with no read and no state at all: an expired intent, a challenge that is not this call's. */
export function ownerQuickRefusal({ method, args, contract, now }) {
  if (args.expires_at + EXPIRY_GRACE_MS < now) return 'that intent has expired';
  const passkey = passkeyOf(method, args);
  if (!passkey) return null;
  const digest = method === 'cancel_all_and_rotate'
    ? rotateDigest({ contract, vaultHex: args.vault, newKs: fromHex(args.new_k_s), nonce: args.nonce, expiresAt: args.expires_at })
    : cancelDigest({ contract, vaultHex: args.vault, request: args.request, expiresAt: args.expires_at });
  return challengeProblem(passkey, digest);
}

/**
 * `{ problem, checked }`. `problem` is null, or why the owner key will not be spent on this. `checked` is true when the
 * signature was checked against the vault's keys: the chain's, or with no read, the ones `made` kept from its creation.
 * `read(method, args)` reads a view and throws when it cannot. The vault's keys are read, not taken from the caller.
 * `now` is this machine's clock.
 */
export async function ownerRefusal({ method, args, contract, read, now, made = null }) {
  const quick = ownerQuickRefusal({ method, args, contract, now });
  if (quick) return refuse(quick);
  const passkey = passkeyOf(method, args);
  let vault;
  try {
    vault = await read('vault', { vault: args.vault });
  } catch {
    // Let it through: the contract decides. Checked only if the keys it was made with signed it.
    return { problem: null, checked: made ? (await signedBy(passkey, args, contract, made)) === true : false };
  }
  if (vault === null) return refuse('no such vault');
  // A nonce ahead of what this node shows is a lagging node. One behind it has been used.
  if (method === 'cancel_all_and_rotate' && args.nonce < vault.passkey_nonce) return refuse('passkey nonce already used');
  if (method === 'cancel_all_and_rotate' && args.nonce > vault.passkey_nonce + NONCE_AHEAD_LIMIT) return refuse('that passkey nonce is too far ahead');
  if (method === 'cancel') {
    try {
      const request = await read('request', { vault: args.vault, request: args.request });
      if (request === null) return refuse('no such request');
      if (request.status !== undefined && request.status !== 'Pending') return refuse('that request is past cancelling');
    } catch {
      // Let it through.
    }
  }
  const signed = await signedBy(passkey, args, contract, vault);
  if (signed === false) return refuse(passkey ? 'webauthn: bad signature' : 'cold key: bad signature');
  return { problem: null, checked: signed === true };
}

