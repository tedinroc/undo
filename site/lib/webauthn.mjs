// A WebAuthn assertion into the arguments contracts/undo/src/auth.rs reads: authenticator_data and
// client_data_json as hex, and signature as r || s. The contract accepts either S form. This normalises
// to low S anyway, as SPEC 11 says, so what lands on chain has one form.
//
// One code path: getAssertion takes any object with a `get`, and that is navigator.credentials on a phone
// and the software authenticator in a test.
import { concat, equal, fromHex, toHex } from '../../tools/lib/bytes.mjs';
import { p256, sha256 } from '../../tools/lib/crypto.mjs';
import { fromBuffer, toArrayBuffer, toBase64Url } from './base64.mjs';

const N = p256.CURVE.n;
const HALF_N = N >> 1n;
const big = (bytes) => BigInt(`0x${toHex(bytes)}`);
const bytes32 = (value) => fromHex(value.toString(16).padStart(64, '0'));

export const FLAG_UP = 0x01;
export const FLAG_UV = 0x04;
export const FLAG_BE = 0x08;
export const FLAG_BS = 0x10;

/** r || s from the DER an authenticator returns. Strict: anything else is not a signature. */
export function derToRaw(der) {
  const fail = () => {
    throw new Error('webauthn: signature is not DER');
  };
  if (der.length < 8 || der[0] !== 0x30 || der[1] !== der.length - 2) fail();
  const read = (at) => {
    if (der[at] !== 0x02) fail();
    const len = der[at + 1];
    if (len === 0 || at + 2 + len > der.length) fail();
    let value = der.slice(at + 2, at + 2 + len);
    if (value[0] & 0x80) fail();
    if (value.length > 1 && value[0] === 0 && !(value[1] & 0x80)) fail();
    if (value[0] === 0) value = value.slice(1);
    if (value.length > 32) fail();
    return { value, next: at + 2 + len };
  };
  const r = read(2);
  const s = read(r.next);
  if (s.next !== der.length) fail();
  const pad = (x) => concat(new Uint8Array(32 - x.length), x);
  return concat(pad(r.value), pad(s.value));
}

export function isHighS(raw) {
  return big(raw.slice(32, 64)) > HALF_N;
}

export function lowS(raw) {
  if (raw.length !== 64) throw new Error('webauthn: signature must be 64 bytes');
  const s = big(raw.slice(32, 64));
  return s > HALF_N ? concat(raw.slice(0, 32), bytes32(N - s)) : raw;
}

export function flagsOf(authenticatorData) {
  const flags = authenticatorData[32];
  return {
    up: Boolean(flags & FLAG_UP),
    uv: Boolean(flags & FLAG_UV),
    backupEligible: Boolean(flags & FLAG_BE),
    backupState: Boolean(flags & FLAG_BS),
  };
}

/** The PublicKeyCredential a `get` returned, as the contract's `WebAuthn` struct. */
export function assertionToArgs(credential) {
  const { response } = credential;
  const authenticatorData = fromBuffer(response.authenticatorData);
  const clientDataJSON = fromBuffer(response.clientDataJSON);
  const raw = derToRaw(fromBuffer(response.signature));
  return {
    authenticator_data: toHex(authenticatorData),
    client_data_json: toHex(clientDataJSON),
    signature: toHex(lowS(raw)),
  };
}

/**
 * The passkey signs this digest. Returns the arguments and what the page should log, because G3 records
 * the S form of each real tap. `allowCredentials` narrows the sheet to one key, so a phone holding
 * several test vaults' keys does not add a chooser to the tap.
 */
export async function getAssertion({ credentials, digest, rpId, credentialId = null, timeoutMs = 60_000 }) {
  const credential = await credentials.get({
    publicKey: {
      challenge: toArrayBuffer(digest),
      rpId,
      allowCredentials: credentialId ? [{ type: 'public-key', id: toArrayBuffer(credentialId) }] : [],
      userVerification: 'required',
      timeout: timeoutMs,
    },
  });
  if (!credential) throw new Error('webauthn: no assertion');
  const raw = derToRaw(fromBuffer(credential.response.signature));
  return {
    args: assertionToArgs(credential),
    highS: isHighS(raw),
    credentialId: fromBuffer(credential.rawId),
    flags: flagsOf(fromBuffer(credential.response.authenticatorData)),
  };
}

// id-ecPublicKey, prime256v1, then a BIT STRING of 66 bytes. Every P-256 SPKI starts with exactly this.
const SPKI_PREFIX = fromHex('3059301306072a8648ce3d020106082a8648ce3d030107034200');

/** The compressed key the contract stores, from what `getPublicKey()` returns. */
export function p256FromSpki(spki) {
  const bytes = fromBuffer(spki);
  if (bytes.length !== SPKI_PREFIX.length + 65 || !equal(bytes.slice(0, SPKI_PREFIX.length), SPKI_PREFIX) || bytes[SPKI_PREFIX.length] !== 4) {
    throw new Error('webauthn: this is not a P-256 public key');
  }
  const x = bytes.slice(SPKI_PREFIX.length + 1, SPKI_PREFIX.length + 33);
  const y = bytes.slice(SPKI_PREFIX.length + 33);
  return concat(Uint8Array.of(2 + (y[31] & 1)), x);
}

/**
 * A new passkey on this device, labelled `test vault` in the OS sheet. ES256 only, because the contract's
 * p256_verify takes nothing else. User verification is required, because the contract refuses UV=0.
 */
export async function createPasskey({ credentials, rpId, rpName = 'Undo', label = 'test vault', timeoutMs = 120_000, random = (n) => crypto.getRandomValues(new Uint8Array(n)) }) {
  const credential = await credentials.create({
    publicKey: {
      rp: { id: rpId, name: rpName },
      user: { id: toArrayBuffer(random(16)), name: label, displayName: label },
      challenge: toArrayBuffer(random(32)),
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
      attestation: 'none',
      timeout: timeoutMs,
    },
  });
  if (!credential) throw new Error('webauthn: no credential');
  if (typeof credential.response.getPublicKey !== 'function') throw new Error('webauthn: this browser cannot read the passkey\'s public key');
  const spki = credential.response.getPublicKey();
  if (!spki) throw new Error('webauthn: this passkey is not ES256');
  const authData = typeof credential.response.getAuthenticatorData === 'function' ? fromBuffer(credential.response.getAuthenticatorData()) : null;
  return {
    pubkey: p256FromSpki(spki),
    credentialId: fromBuffer(credential.rawId),
    flags: authData ? flagsOf(authData) : null,
  };
}

/**
 * The contract's require_webauthn, step by step and with its words, so a page can stop before a relay
 * spends gas on an assertion that will be refused. The contract remains the check. Returns null or the
 * refusal text.
 */
export function refusalOf({ assertion, digest, pubkey, rpIdHash, origins }) {
  const auth = fromHex(assertion.authenticator_data);
  if (auth.length < 37) return 'webauthn: short authenticator data';
  if (!equal(auth.slice(0, 32), rpIdHash)) return 'webauthn: wrong rp id';
  if (!(auth[32] & FLAG_UP)) return 'webauthn: user not present';
  if (!(auth[32] & FLAG_UV)) return 'webauthn: user not verified';
  const clientBytes = fromHex(assertion.client_data_json);
  let client;
  try {
    client = JSON.parse(new TextDecoder().decode(clientBytes));
  } catch {
    return 'webauthn: bad client data';
  }
  if (client.type !== 'webauthn.get') return 'webauthn: wrong type';
  if (client.challenge !== toBase64Url(digest)) return 'webauthn: wrong challenge';
  if (client.crossOrigin === true) return 'webauthn: cross origin';
  if (!origins.includes(client.origin)) return 'webauthn: origin not allowed';
  const prehash = sha256(concat(auth, sha256(clientBytes)));
  const signature = fromHex(assertion.signature);
  if (signature.length !== 64) return 'webauthn signature must be 64 bytes';
  return p256.verify(signature, prehash, pubkey, { prehash: false, lowS: false }) ? null : 'webauthn: bad signature';
}
