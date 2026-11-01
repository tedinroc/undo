// Borsh transactions for the relay, in a form a Worker can load: tools/lib/near.mjs reads files at import,
// so it cannot. Signing is passed in, so a Worker can use WebCrypto and stay under its CPU limit. site/test
// checks that the bytes equal tools/lib/near.mjs's for the same inputs. A page never imports this.
import { b } from '../../tools/lib/borsh.mjs';
import { base58Decode, base58Encode, concat, u128le, utf8 } from '../../tools/lib/bytes.mjs';
import { sha256 } from '../../tools/lib/crypto.mjs';
import { toBase64 } from './base64.mjs';

export const TGAS = 1_000_000_000_000n;
export const NEAR = 10n ** 24n;
export const milliNear = (n) => (BigInt(n) * NEAR) / 1000n;

export const callAction = (method, args, tgas, deposit = 0n) => concat(
  Uint8Array.of(2),
  b.str(method),
  b.bytes(args instanceof Uint8Array ? args : utf8(JSON.stringify(args))),
  b.u64(BigInt(tgas) * TGAS),
  u128le(deposit),
);

const borshPublicKey = (pub) => concat(Uint8Array.of(0), pub);

/** The transaction's bytes and the hash its signature covers. */
export function encodeTransaction({ signerId, publicKey, nonce, receiverId, blockHash, actions }) {
  const tx = concat(
    b.str(signerId),
    borshPublicKey(publicKey),
    b.u64(nonce),
    b.str(receiverId),
    b.raw(typeof blockHash === 'string' ? base58Decode(blockHash) : blockHash),
    b.vec(actions, (a) => a),
  );
  return { bytes: tx, hash: sha256(tx) };
}

/** `sign` is `async (hash) => signature64`. Returns what `send_tx` takes and the hash to report. */
export async function signedTransaction(fields, sign) {
  const { bytes, hash } = encodeTransaction(fields);
  const signature = await sign(hash);
  if (signature.length !== 64) throw new Error('an ed25519 signature is 64 bytes');
  return { hash: base58Encode(hash), base64: toBase64(concat(bytes, Uint8Array.of(0), signature)) };
}
