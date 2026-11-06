// Talks to a deployed Undo contract as a vault's owner, with fresh keys held in memory. Used by the
// G1 driver and the sandbox tests, which run the same calls. Nothing here is persisted: the coins are
// made up, so a lost run costs a few transactions and nothing else.
import { makeTx, p2wshSpk, SEQUENCE_COSIGNED, sighash, witnessScript } from './btc.mjs';
import { base58Decode, concat, fromHex, toHex, utf8 } from './bytes.mjs';
import { p256, randomBytes, secp256k1, sha256 } from './crypto.mjs';
import { argBytes, COLD_TAG, createDigest, intentDigest, leafPopDigest, PASSKEY_TAG, signEd25519, signSecp, softAssertion, vaultId } from './intent.mjs';
import { coldKeys, softPasskeyKey, spendKeys } from './keys.mjs';
import { signSpend } from './spend.mjs';
import { action, failureOf, milliNear, returnValue, TGAS } from './near.mjs';

export const PATH_PREFIX = 'undo/';
export const CREATE_TGAS = 100n;

/** `secp256k1:<base58 of x || y>`, as the signer's view returns it, compressed. */
export function parseSignerKey(text) {
  if (typeof text !== 'string' || !text.startsWith('secp256k1:')) throw new Error('signer returned something that is not a key');
  const xy = base58Decode(text.slice('secp256k1:'.length));
  if (xy.length !== 64) throw new Error('signer key is not 64 bytes');
  return concat(Uint8Array.of(2 + (xy[63] & 1)), xy.slice(0, 32));
}

/**
 * What a relay attaches to a `K_p` or `K_e` method, and to `apply_grant` and `recover_finish`, either of which
 * can be the call that sweeps a dead queue. The heaviest measured is in docs/measurements.md, on the worst row and
 * the largest queue. Unused gas comes back.
 */
export const OWNER_ATTACH_TGAS = 30n;

/**
 * The operator passkey `new` asks for: a software key whose secret is dropped here, so nobody can cancel
 * an upgrade on an instance deployed with it. Fit for a test or gate deployment that never upgrades. A
 * real instance takes the operator's real passkey instead.
 */
export function throwawayOperatorPasskey(rpId) {
  const secret = randomBytes(32);
  return { pubkey: toHex(p256.getPublicKey(secret, true)), rp_id_hash: toHex(sha256(utf8(rpId))) };
}

export function newOwnerKeys({ seed = randomBytes(32), cold = randomBytes(32), passkey = randomBytes(32) } = {}) {
  const { ks, ku } = spendKeys(seed);
  const { leaf, intent } = coldKeys(cold);
  return { seed, cold, ks, ku, leaf, intent, kp: softPasskeyKey(passkey) };
}

export class VaultClient {
  constructor({ near, contract, signer, instance, origin, rpId }) {
    Object.assign(this, { near, contract, signer, instance, origin, rpId });
    this.rpIdHash = sha256(utf8(rpId));
  }

  idFor(keys, csv) {
    return vaultId({ contract: this.contract, ks: keys.ks.pub, ku: keys.ku.pub, keLeaf: keys.leaf.pub, keIntent: keys.intent.pub, kp: keys.kp.pub, csv });
  }

  async derivedKey(id) {
    const text = await this.near.view(this.signer, 'derived_public_key', {
      path: `${PATH_PREFIX}${toHex(id)}`,
      predecessor: this.contract,
      domain_id: this.instance.domain_id,
    });
    return parseSignerKey(text);
  }

  /** The arguments of create_vault, with every proof of possession. `km` overrides the signer's answer. */
  async createArgs(keys, { csv = 6, km, expiresAt }) {
    const id = this.idFor(keys, csv);
    const k_m = km ?? (await this.derivedKey(id));
    const expires = expiresAt ?? (await this.near.nowMs()) + 30 * 60_000;
    const digest = createDigest({ contract: this.contract, vault: id, km: k_m, rpIdHash: this.rpIdHash, guard: null, policy: this.instance.policy, expiresAt: expires });
    return {
      id,
      km: k_m,
      args: {
        k_s: toHex(keys.ks.pub),
        k_u: toHex(keys.ku.pub),
        k_m: toHex(k_m),
        k_e_leaf: toHex(keys.leaf.pub),
        k_e_intent: toHex(keys.intent.pub),
        passkey: { pubkey: toHex(keys.kp.pub), rp_id_hash: toHex(this.rpIdHash) },
        guard: null,
        csv,
        policy: null,
        expires_at: expires,
        pop_s: toHex(signEd25519(digest, keys.ks.secret)),
        pop_u: toHex(signSecp(digest, keys.ku.secret)),
        pop_e: toHex(signSecp(digest, keys.intent.secret)),
        pop_leaf: toHex(signSecp(leafPopDigest(digest), keys.leaf.secret)),
        pop_p: softAssertion({ secret: keys.kp.secret, digest, origin: this.origin, rpId: this.rpId }),
      },
    };
  }

  /** Sends create_vault and reads state: transaction status cannot say whether the callback matched. */
  async create(payer, keys, { csv = 6, km, depositMilli = 50 } = {}) {
    const { id, km: k_m, args } = await this.createArgs(keys, { csv, km });
    const sent = await this.near.sendAndWait(payer, this.contract, [
      action.call('create_vault', { args }, CREATE_TGAS * TGAS, milliNear(depositMilli)),
    ]);
    const view = await this.viewVault(id);
    const script = witnessScript(keys.ku.pub, k_m, keys.leaf.pub, csv);
    return { id, hex: toHex(id), keys, km: k_m, csv, script, spk: p2wshSpk(script), view, tx: sent.hash, result: sent.result, spendNonce: 0, passkeyNonce: 0 };
  }

  viewVault(id) {
    return this.near.view(this.contract, 'vault', { vault: toHex(id) });
  }

  viewRequest(vault, request) {
    return this.near.view(this.contract, 'request', { vault: vault.hex, request });
  }

  /** A self-spend of made-up coins. Self-spends use T_known, the shortest wait on the instance. */
  selfSpendArgs(vault, coins, fee) {
    const total = coins.reduce((s, c) => s + c.value, 0);
    return this.proposeArgs(vault, { coins, to: vault.spk, amount: total - fee, change: null });
  }

  async proposeArgs(vault, { coins, to, amount, change = null, expiresAt }) {
    const expires = expiresAt ?? (await this.near.nowMs()) + 30 * 60_000;
    const { args, signer } = signSpend.propose({
      seed: vault.keys.seed,
      contract: this.contract,
      vault: vault.id,
      script: vault.script,
      spk: vault.spk,
      inputs: coins,
      to,
      amount,
      change,
      nonce: vault.spendNonce,
      expiresAt: expires,
    });
    if (signer !== toHex(vault.keys.ks.pub)) throw new Error('seed does not give this vault\'s spend key');
    return args;
  }

  async propose(sender, vault, args, gasTgas = 40n) {
    const sent = await this.near.sendAndWait(sender, this.contract, [action.call('propose_btc', args, gasTgas * TGAS, 0n)]);
    const failure = failureOf(sent.result);
    if (failure) throw new Error(`propose refused: ${failure}`);
    vault.spendNonce += 1;
    return { request: returnValue(sent.result), tx: sent.hash, result: sent.result };
  }

  passkeyAssertion(vault, method, args, expiresAt, nonce) {
    const digest = intentDigest({ tag: PASSKEY_TAG, contract: this.contract, vault: vault.id, method, args, expiresAt, nonce });
    return softAssertion({ secret: vault.keys.kp.secret, digest, origin: this.origin, rpId: this.rpId });
  }

  async raiseFeeCap(sender, vault, request, cap) {
    const expires = (await this.near.nowMs()) + 30 * 60_000;
    const assertion = this.passkeyAssertion(vault, 'raise_fee_cap', argBytes.raise_fee_cap({ request, cap }), expires, vault.passkeyNonce);
    const sent = await this.near.sendAndWait(sender, this.contract, [
      action.call('raise_fee_cap', { vault: vault.hex, request, cap, nonce: vault.passkeyNonce, expires_at: expires, assertion }, 40n * TGAS, 0n),
    ]);
    const failure = failureOf(sent.result);
    if (failure) throw new Error(`raise_fee_cap refused: ${failure}`);
    vault.passkeyNonce += 1;
    return sent.hash;
  }

  cancelArgsPasskey(vault, request, expiresAt) {
    const assertion = this.passkeyAssertion(vault, 'cancel', argBytes.cancel({ request }), expiresAt, null);
    return { vault: vault.hex, request, expires_at: expiresAt, auth: { Passkey: assertion } };
  }

  /** Waits for the chain's clock. A sandbox skips ahead; a real network really waits. */
  async waitUntil(targetMs, { fastForward = false, pollMs = 2000, log } = {}) {
    for (let i = 0; i < 2000; i += 1) {
      const now = await this.near.nowMs();
      if (now >= targetMs) return;
      if (fastForward) {
        await this.near.sandboxFastForward(Math.min(Math.ceil((targetMs - now) / 500) + 5, 5000));
      } else {
        if (log && i % 15 === 0) log(`waiting ${Math.ceil((targetMs - now) / 1000)} s for the unlock`);
        await new Promise((r) => setTimeout(r, pollMs));
      }
    }
    throw new Error('the clock never reached the target');
  }

  /** Checks a final transaction without trusting the contract: both signatures, over locally built digests. */
  checkFinalTx({ vault, coins, parsed, to, amount }) {
    if (parsed.inputs.length !== coins.length) return 'wrong input count';
    const tx = makeTx(coins, SEQUENCE_COSIGNED, [{ value: amount, spk: to }]);
    return coins.reduce((problem, c, i) => problem ?? checkInput({ parsed, tx, i, c, vault }), null);
  }
}

function checkInput({ parsed, tx, i, c, vault }) {
  const digest = sighash(tx, i, vault.script, c.value);
  const w = parsed.inputs[i].witness;
  if (w.length !== 4 || w[2].length !== 1 || w[2][0] !== 1) return `input ${i}: wrong witness shape`;
  if (toHex(w[3]) !== toHex(vault.script)) return `input ${i}: wrong script`;
  return verifyDer(w[0], digest, vault.km) ? (verifyDer(w[1], digest, vault.keys.ku.pub) ? null : `input ${i}: K_u signature fails`) : `input ${i}: K_m signature fails`;
}

export function verifyDer(der, digest, pub) {
  const rs = derToCompact(der);
  return secp256k1.verify(rs, digest, pub, { lowS: true, prehash: false });
}

function derToCompact(sig) {
  const r = readInt(sig, 2);
  const s = readInt(sig, r.next);
  return concat(r.value, s.value);
}

function readInt(sig, at) {
  const len = sig[at + 1];
  let v = sig.slice(at + 2, at + 2 + len);
  if (v[0] === 0) v = v.slice(1);
  return { value: concat(new Uint8Array(32 - v.length), v), next: at + 2 + len };
}

export function fakeCoins(count, value = 100_000) {
  return Array.from({ length: count }, (_, i) => ({ txid: toHex(randomBytes(32)), vout: i, value }));
}

/** Above the contract's 1 sat/vB floor at any input count. Above 1,000 needs raise_fee_cap. */
export function feeFor(inputs) {
  return Math.max(950, 120 * inputs + 100);
}

export const coldCancelDigest = ({ contract, vault, request, expiresAt }) => intentDigest({ tag: COLD_TAG, contract, vault, method: 'cancel', args: argBytes.cancel({ request }), expiresAt, nonce: null });

export { fromHex };
