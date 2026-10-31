// Builds and signs a cold-key intent from displayed fields. There is no entry point that takes a
// digest, because the same secret also signs the Bitcoin escape leaf and a page could otherwise feed
// the derived key a digest of its own choosing. The leaf key signs no intent here. Its one signature
// on NEAR is the proof of possession at creation, leafPopDigest in intent.mjs.
import { argBytes, COLD_TAG, intentDigest, signSecp } from './intent.mjs';
import { equal, fixedHex, toHex } from './bytes.mjs';
import { coldKeys } from './keys.mjs';

const NONCELESS = new Set(['cancel']);
export const COLD_METHODS = ['freeze', 'unfreeze', 'veto_grant', 'cancel'];

export function signColdIntent({ cold, contract, vault, method, fields, expiresAt, nonce }) {
  if (!COLD_METHODS.includes(method)) throw new Error(`the cold key signs no ${method} intent`);
  if (!/^[a-z0-9._-]{2,64}$/.test(contract)) throw new Error('bad contract account');
  const vaultBytes = fixedHex(vault, 32, 'vault id');
  if (!Number.isSafeInteger(expiresAt) || expiresAt <= 0) throw new Error('bad expiry');
  const keys = coldKeys(cold);
  if (equal(keys.intent.secret, keys.leaf.secret)) throw new Error('intent key must differ from the leaf key');
  const useNonce = NONCELESS.has(method) ? null : nonce;
  if (!NONCELESS.has(method) && (!Number.isSafeInteger(nonce) || nonce < 0)) throw new Error('this method needs the vault\'s cold nonce');
  const digest = intentDigest({
    tag: COLD_TAG,
    contract,
    vault: vaultBytes,
    method,
    args: argBytes[method](fields),
    expiresAt,
    nonce: useNonce,
  });
  return {
    digest: toHex(digest),
    signature: toHex(signSecp(digest, keys.intent.secret)),
    k_e_intent: toHex(keys.intent.pub),
  };
}
