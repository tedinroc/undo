// The relay does not spend the owner key on a cancel that cannot work. Without this, anyone could send junk
// `cancel`s and use up a victim vault's per-minute limit, or the whole owner ceiling, for free, and that is
// the one thing the owner key exists to prevent. Each check is one the contract makes too, in a subset:
// nothing here may refuse a cancel the contract would take. A failed read lets the cancel through.
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

async function signatureProblem(assertion, passkeyHex) {
  const point = p256Uncompressed(fromHex(passkeyHex));
  if (!point) return null;
  const algorithm = { name: 'ECDSA', namedCurve: 'P-256', hash: 'SHA-256' };
  const key = await crypto.subtle.importKey('raw', point, algorithm, false, ['verify']);
  const message = concat(fromHex(assertion.authenticator_data), sha256(fromHex(assertion.client_data_json)));
  return (await crypto.subtle.verify(algorithm, key, fromHex(assertion.signature), message)) ? null : 'webauthn: bad signature';
}

function coldProblem(args, contract, vault) {
  const digest = intentDigest({ tag: COLD_TAG, contract, vault: fromHex(args.vault), method: 'cancel', args: argBytes.cancel({ request: args.request }), expiresAt: args.expires_at, nonce: null });
  const signature = fromHex(args.auth.Cold);
  return secp256k1.verify(signature.slice(0, 64), digest, fromHex(vault.k_e_intent), { prehash: false, lowS: true }) ? null : 'cold key: bad signature';
}

// The relay's clock against the chain's. The contract is the one that decides at the edge.
const EXPIRY_GRACE_MS = 60_000;
// A node may be a little behind on the nonce, never a thousand rotations.
const NONCE_AHEAD_LIMIT = 2;

/**
 * Null, or why the owner key will not be spent on this. `read(method, args)` reads a view and throws when it
 * cannot. The vault's passkey is read, not taken from the caller. `now` is this machine's clock.
 */
export async function ownerRefusal({ method, args, contract, read, now }) {
  if (args.expires_at + EXPIRY_GRACE_MS < now) return 'that intent has expired';
  const passkey = method === 'cancel_all_and_rotate' ? args.assertion : args.auth.Passkey ?? null;
  if (passkey) {
    const digest = method === 'cancel_all_and_rotate'
      ? rotateDigest({ contract, vaultHex: args.vault, newKs: fromHex(args.new_k_s), nonce: args.nonce, expiresAt: args.expires_at })
      : cancelDigest({ contract, vaultHex: args.vault, request: args.request, expiresAt: args.expires_at });
    const problem = challengeProblem(passkey, digest);
    if (problem) return problem;
  }
  let vault;
  try {
    vault = await read('vault', { vault: args.vault });
  } catch {
    return null;
  }
  if (vault === null) return 'no such vault';
  // A nonce ahead of what this node shows is a lagging node. One behind it has been used.
  if (method === 'cancel_all_and_rotate' && args.nonce < vault.passkey_nonce) return 'passkey nonce already used';
  if (method === 'cancel_all_and_rotate' && args.nonce > vault.passkey_nonce + NONCE_AHEAD_LIMIT) return 'that passkey nonce is too far ahead';
  if (method === 'cancel') {
    try {
      const request = await read('request', { vault: args.vault, request: args.request });
      if (request === null) return 'no such request';
      if (request.status !== undefined && request.status !== 'Pending') return 'that request is past cancelling';
    } catch {
      // Let it through.
    }
  }
  return passkey ? signatureProblem(passkey, vault.passkey) : coldProblem(args, contract, vault);
}

