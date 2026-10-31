// Key derivation. HKDF-SHA256 with public labels, so any tool in any language can do the same.
//
//   K_s, K_u   from one 32-byte seed, per SPEC 1.1
//   K_e intent from the cold key's secret, per SPEC 11. The leaf key signs no NEAR intent. Besides a
//              real escape it signs one thing, once: its proof of possession at creation.
//
// There is no retry on an out-of-range scalar: the odds are about 2^-128, and a refusal is honest.
import { utf8 } from './bytes.mjs';
import { ed25519, hkdf, p256, secp256k1, sha256 } from './crypto.mjs';

const SALT = utf8('undo-key-v1');

function derive(ikm, info) {
  if (ikm.length !== 32) throw new Error('key material must be 32 bytes');
  return hkdf(sha256, ikm, SALT, utf8(info), 32);
}

function secpKey(secret) {
  if (!secp256k1.utils.isValidPrivateKey(secret)) throw new Error('derived secret is out of range');
  return { secret, pub: secp256k1.getPublicKey(secret, true) };
}

export function spendKeys(seed) {
  const edSecret = derive(seed, 'undo-k_s-ed25519-v1');
  return {
    ks: { secret: edSecret, pub: ed25519.getPublicKey(edSecret) },
    ku: secpKey(derive(seed, 'undo-k_u-secp256k1-v1')),
  };
}

export function coldKeys(leafSecret) {
  return {
    leaf: secpKey(leafSecret),
    intent: secpKey(derive(leafSecret, 'undo-k_e-intent-secp256k1-v1')),
  };
}

export function publicSecp(secret) {
  if (!secp256k1.utils.isValidPrivateKey(secret)) throw new Error('secret is out of range');
  return secp256k1.getPublicKey(secret, true);
}

/** A software P-256 key for tests and the labelled fallback. Never call this a real passkey. */
export function softPasskeyKey(secret) {
  if (!p256.utils.isValidPrivateKey(secret)) throw new Error('secret is out of range');
  return { secret, pub: p256.getPublicKey(secret, true) };
}
