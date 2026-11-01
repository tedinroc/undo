// A small proof of work on create_vault, so making vaults costs a visitor seconds and not the relay's NEAR.
// It binds the vault id, and a vault id can be created once, so a solution cannot be used twice.
import { sha256 } from '../../tools/lib/crypto.mjs';

const encoder = new TextEncoder();

function leadingZeroBits(digest) {
  let bits = 0;
  for (const byte of digest) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    return bits + Math.clz32(byte) - 24;
  }
  return bits;
}

const digestOf = (vaultHex, nonce) => sha256(encoder.encode(`undo-pow-v1:${vaultHex}:${nonce}`));

/** What /api/funds' work is over, so the work that made a vault cannot also pay out a coin to it. */
export const fundsPowTarget = (vaultHex) => `funds:${vaultHex}`;

export const checkPow = (vaultHex, nonce, bits) => Number.isSafeInteger(nonce) && nonce >= 0 && leadingZeroBits(digestOf(vaultHex, nonce)) >= bits;

/** Yields between batches, so a phone keeps drawing while it works. */
export async function solvePow(vaultHex, bits, { batch = 4096, onProgress } = {}) {
  for (let nonce = 0; ; nonce += 1) {
    if (leadingZeroBits(digestOf(vaultHex, nonce)) >= bits) return nonce;
    if (nonce % batch === batch - 1) {
      onProgress?.(nonce + 1);
      await new Promise((resolve) => setTimeout(resolve, 0));
    }
  }
}
