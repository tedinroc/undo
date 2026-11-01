// A software P-256 authenticator, for tests. It has navigator.credentials' shape: DER signatures, ArrayBuffers,
// and clientDataJSON built the way a browser builds it, so a test goes through getAssertion,
// assertionToArgs and the contract exactly as a phone does. site/build.mjs leaves it out of a build
// unless the config sets softPasskey, and no result that rests on it may be called a real passkey.
import { concat } from '../../tools/lib/bytes.mjs';
import { p256, sha256 } from '../../tools/lib/crypto.mjs';
import { fromBuffer, toArrayBuffer, toBase64Url } from './base64.mjs';
import { FLAG_UP, FLAG_UV } from './webauthn.mjs';

const utf8 = (text) => new TextEncoder().encode(text);

const SPKI_PREFIX = Uint8Array.from([
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00,
]);

/**
 * @param secret 32 bytes. A test derives it from a label; `randomBytes` for a throwaway
 * @param highS emit the other S, as real authenticators often do
 * @param flags authenticator flags; UP and UV by default. Clear UV to test that refusal
 */
export function softCredentials({ secret, origin, rpId, flags = FLAG_UP | FLAG_UV, highS = false, crossOrigin = false, credentialId = sha256(concat(utf8('undo-soft-credential'), p256.getPublicKey(secret, true))) }) {
  const publicKey = p256.getPublicKey(secret, true);
  const rpIdHash = sha256(utf8(rpId));
  let signCount = 0;

  const authData = () => {
    signCount += 1;
    return concat(rpIdHash, Uint8Array.of(flags), new Uint8Array([(signCount >>> 24) & 0xff, (signCount >>> 16) & 0xff, (signCount >>> 8) & 0xff, signCount & 0xff]));
  };

  return {
    label: '[software authenticator]',
    publicKey,
    credentialId,
    async get({ publicKey: options }) {
      if (options.rpId !== rpId) throw new DOMException('rpId does not match', 'SecurityError');
      const allowed = options.allowCredentials ?? [];
      if (allowed.length > 0 && !allowed.some((c) => toBase64Url(fromBuffer(c.id)) === toBase64Url(credentialId))) {
        throw new DOMException('no credential', 'NotAllowedError');
      }
      const authenticatorData = authData();
      const clientDataJSON = utf8(JSON.stringify({ type: 'webauthn.get', challenge: toBase64Url(fromBuffer(options.challenge)), origin, crossOrigin }));
      const prehash = sha256(concat(authenticatorData, sha256(clientDataJSON)));
      let sig = p256.sign(prehash, secret, { prehash: false, lowS: true });
      if (highS) sig = new p256.Signature(sig.r, p256.CURVE.n - sig.s);
      return {
        type: 'public-key',
        id: toBase64Url(credentialId),
        rawId: toArrayBuffer(credentialId),
        response: {
          authenticatorData: toArrayBuffer(authenticatorData),
          clientDataJSON: toArrayBuffer(clientDataJSON),
          signature: toArrayBuffer(sig.toDERRawBytes()),
          userHandle: null,
        },
      };
    },
    async create({ publicKey: options }) {
      if (options.rp.id !== rpId) throw new DOMException('rpId does not match', 'SecurityError');
      const point = p256.ProjectivePoint.fromHex(publicKey).toRawBytes(false);
      const authenticatorData = authData();
      return {
        type: 'public-key',
        id: toBase64Url(credentialId),
        rawId: toArrayBuffer(credentialId),
        response: {
          getPublicKey: () => toArrayBuffer(concat(SPKI_PREFIX, point)),
          getAuthenticatorData: () => toArrayBuffer(authenticatorData),
          getPublicKeyAlgorithm: () => -7,
        },
      };
    },
  };
}
