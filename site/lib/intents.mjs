// Every signature a page makes, built from the tools' own encoders in tools/lib. Nothing in this file
// encodes bytes: if a digest here ever differs from the tools', one of those imports changed for both.
import { fixedHex, fromHex, toHex } from '../../tools/lib/bytes.mjs';
import { randomBytes, sha256 } from '../../tools/lib/crypto.mjs';
import { argBytes, COLD_TAG, createDigest, intentDigest, leafPopDigest, PASSKEY_TAG, signEd25519, signSecp, vaultId } from '../../tools/lib/intent.mjs';
import { coldKeys, spendKeys } from '../../tools/lib/keys.mjs';
import { signSpend } from '../../tools/lib/spend.mjs';

export { COLD_TAG, PASSKEY_TAG, spendKeys };

export const rpIdHashOf = (rpId) => sha256(new TextEncoder().encode(rpId));

/** A throwaway vault's keys, in memory. Everything else here derives from these two values. */
export function newVaultKeys({ seed = randomBytes(32), cold = randomBytes(32) } = {}) {
  const { ks, ku } = spendKeys(seed);
  const { leaf, intent } = coldKeys(cold);
  return { seed, cold, ks, ku, leaf, intent };
}

export const vaultIdOf = ({ contract, keys, passkeyPub, csv }) => vaultId({
  contract, ks: keys.ks.pub, ku: keys.ku.pub, keLeaf: keys.leaf.pub, keIntent: keys.intent.pub, kp: passkeyPub, csv,
});

/** The vault id `create_vault` arguments name, recomputed the way the contract does, for the relay. */
export const vaultIdOfCreateArgs = (contract, args) => vaultId({
  contract,
  ks: fixedHex(args.k_s, 32, 'k_s'),
  ku: fromHex(args.k_u),
  keLeaf: fromHex(args.k_e_leaf),
  keIntent: fromHex(args.k_e_intent),
  kp: fromHex(args.passkey.pubkey),
  csv: args.csv,
});

/**
 * `create_vault`'s arguments. `guard` is the relay's account, because a vault only reads the guarded
 * T_new if the account that beats is the one its creation digest named. `assert` is
 * `(digest) => Promise<assertion>`: a real passkey on the phone, or the software one in tests.
 */
export async function buildCreateArgs({ contract, keys, passkeyPub, rpIdHash, km, guard, policy, csv, expiresAt, assert }) {
  const id = vaultIdOf({ contract, keys, passkeyPub, csv });
  const digest = createDigest({ contract, vault: id, km, rpIdHash, guard, policy, expiresAt });
  return {
    id,
    vaultHex: toHex(id),
    digest,
    args: {
      k_s: toHex(keys.ks.pub),
      k_u: toHex(keys.ku.pub),
      k_m: toHex(km),
      k_e_leaf: toHex(keys.leaf.pub),
      k_e_intent: toHex(keys.intent.pub),
      passkey: { pubkey: toHex(passkeyPub), rp_id_hash: toHex(rpIdHash) },
      guard,
      csv,
      policy: null,
      expires_at: expiresAt,
      pop_s: toHex(signEd25519(digest, keys.ks.secret)),
      pop_u: toHex(signSecp(digest, keys.ku.secret)),
      pop_e: toHex(signSecp(digest, keys.intent.secret)),
      pop_leaf: toHex(signSecp(leafPopDigest(digest), keys.leaf.secret)),
      pop_p: await assert(digest),
    },
  };
}

/** Whether a pasted seed is this vault's. Compares what it derives with what the contract stores. */
export function seedMatchesVault(seed, vault) {
  const { ks, ku } = spendKeys(seed);
  return { ks: toHex(ks.pub) === vault.k_s, ku: toHex(ku.pub) === vault.k_u };
}

/**
 * `propose_btc`'s arguments: K_s over the intent, K_u over each input's sighash, signed by
 * tools/lib/spend.mjs. Refuses a seed that is not this vault's key, or a script that is not its script,
 * because either would only come back as a refusal from the contract, and it has cost gas by then.
 */
export function buildPropose({ contract, vault, script, seed, inputs, to, amount, change = null, nonce, expiresAt, memo = null }) {
  const { args, signer } = signSpend.propose({
    seed,
    contract,
    vault: fromHex(vault.id),
    script,
    spk: fromHex(vault.script_pubkey),
    inputs,
    to,
    amount,
    change,
    nonce,
    expiresAt,
    memo,
  });
  if (signer !== vault.k_s) throw new Error('that seed does not give this vault\'s spend key');
  return args;
}

/** What the phone's passkey signs for `cancel_all_and_rotate`. Binds the new key and the passkey nonce. */
export const rotateDigest = ({ contract, vaultHex, newKs, nonce, expiresAt }) => intentDigest({
  tag: PASSKEY_TAG, contract, vault: fromHex(vaultHex), method: 'cancel_all_and_rotate', args: argBytes.cancel_all_and_rotate({ newKs }), expiresAt, nonce,
});

export const rotateArgs = ({ vaultHex, newKs, nonce, expiresAt, assertion }) => ({
  vault: vaultHex, new_k_s: toHex(newKs), nonce, expires_at: expiresAt, assertion,
});

/** What `cancel` signs. No nonce, by design: it cannot go stale in a crisis. */
export const cancelDigest = ({ contract, vaultHex, request, expiresAt }) => intentDigest({
  tag: PASSKEY_TAG, contract, vault: fromHex(vaultHex), method: 'cancel', args: argBytes.cancel({ request }), expiresAt, nonce: null,
});

export const cancelArgs = ({ vaultHex, request, expiresAt, assertion }) => ({
  vault: vaultHex, request, expires_at: expiresAt, auth: { Passkey: assertion },
});
