// A test vault as a phone makes it: passkey, K_m from the signer, a second tap over the creation digest, proof of
// work, relay. Two real taps, because the first sheet uses up the user gesture and K_m is a network read between them.
import { buildCreateArgs, derivedKey, newVaultKeys, rpIdHashOf, solvePow, vaultIdOf } from '/site/lib/index.mjs';
import { toHex } from '/tools/lib/bytes.mjs';
import { askAssertion } from './passkey-ask.mjs';

const CSV = 6;
const CREATE_WINDOW_MS = 30 * 60_000;
const ACTIVE_WAIT_MS = 45_000;

export const chainNowOf = (skew) => {
  const s = skew.sample();
  return s ? s.blockMs + (Date.now() - s.localMs) : null;
};

/** After the first tap: the keys, and K_m as the signer derives it for this vault. */
export async function prepareVault(ctx, passkey, { keys = newVaultKeys() } = {}) {
  const { config, reader, instance } = ctx;
  const vaultHex = toHex(vaultIdOf({ contract: config.contract, keys, passkeyPub: passkey.pubkey, csv: CSV }));
  const km = await derivedKey(reader, { signer: instance.signer, domainId: instance.domain_id, contract: config.contract, vaultHex });
  ctx.skew.add(await reader.blockTime());
  return { keys, vaultHex, km, passkey };
}

/**
 * The second tap. Everything before the sheet is computed synchronously. Resolves to { args, highS } once the
 * passkey has signed the creation digest.
 */
export function confirmVault(ctx, prepared, { guard, onHang = null }) {
  const { config, instance, skew } = ctx;
  let highS = null;
  const expiresAt = Math.floor(chainNowOf(skew)) + CREATE_WINDOW_MS;
  return buildCreateArgs({
    contract: config.contract,
    keys: prepared.keys,
    passkeyPub: prepared.passkey.pubkey,
    rpIdHash: rpIdHashOf(config.rpId),
    km: prepared.km,
    guard,
    policy: instance.policy,
    csv: CSV,
    expiresAt,
    assert: async (digest) => {
      const { assertion } = await askAssertion(ctx, { digest, credentialId: prepared.passkey.credentialId, onHang });
      highS = assertion.highS;
      return assertion.args;
    },
  }).then((built) => ({ args: built.args, highS }));
}

/** Proof of work, the relay, and a wait until the contract reads the vault active. Each step reports only when done. */
export async function sendVault(ctx, prepared, args, { powBits, onLine = () => {} }) {
  const { relay, views } = ctx;
  const pow = await solvePow(prepared.vaultHex, powBits);
  onLine('work');
  const sent = await relay.call('create_vault', args, { pow });
  onLine('sent', sent.hash);
  const deadline = Date.now() + ACTIVE_WAIT_MS;
  let activated = false;
  for (;;) {
    let vault = null;
    try {
      vault = await views.vault(prepared.vaultHex);
    } catch {
      // A lagging or down node. The deadline below is what ends this.
    }
    if (vault?.active) return { vault, hash: sent.hash };
    if (Date.now() > deadline) throw new Error('the contract has not read this vault active yet');
    if (vault && !activated && Date.now() > deadline - ACTIVE_WAIT_MS / 2) {
      activated = true;
      await relay.call('activate', { vault: prepared.vaultHex }).catch(() => {});
    }
    await new Promise((r) => { setTimeout(r, 600); });
  }
}
