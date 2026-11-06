// Which coins to spend and what fee to pay. The contract can't see Bitcoin, so the coin list comes
// from an Esplora read of the vault's address, and the contract then says whether each coin is free.
import { Esplora } from '../../tools/lib/esplora.mjs';

/** The contract's own size estimate (crates/undo-core/src/types.rs `estimate_vsize`). */
export function estimateVsize(inputs, destLen, withChange) {
  return 11 + 107 * inputs + 9 + destLen + (withChange ? 9 + 34 : 0);
}

const DUST = { 22: 294, 34: 330 };
export const dustFor = (spkLen) => DUST[spkLen] ?? 330;
export const MAX_INPUTS = 16;

/** Fee at `rate` sat/vB of the contract's estimate, never under its 1 sat/vB floor or over the cap. */
export function feeFor({ inputs, destLen, withChange, rate, cap }) {
  const vsize = estimateVsize(inputs, destLen, withChange);
  const fee = Math.max(vsize, Math.ceil(vsize * rate));
  return Math.min(fee, Math.max(vsize, cap));
}

export class CoinError extends Error {}

/**
 * Largest coins first. `amount` is a number of sats or 'all'. 'all' sends every free coin with no
 * change. A change below dust is given to the fee rather than refused, and the contract's cap still
 * decides whether that fee is allowed.
 */
export function selectCoins({ coins, amount, destLen, rate, cap }) {
  const free = [...coins].sort((a, b) => b.value - a.value || a.txid.localeCompare(b.txid) || a.vout - b.vout).slice(0, MAX_INPUTS);
  if (free.length === 0) throw new CoinError('the vault has no free confirmed coin');
  if (amount === 'all') {
    const total = free.reduce((s, c) => s + c.value, 0);
    const fee = feeFor({ inputs: free.length, destLen, withChange: false, rate, cap });
    const send = total - fee;
    if (send < dustFor(destLen)) throw new CoinError(`all free coins come to ${total} sats, too little after a ${fee} sat fee`);
    return { inputs: free, amount: send, change: null, fee, total };
  }
  const picked = [];
  let total = 0;
  let noChange = null;
  for (const coin of free) {
    picked.push(coin);
    total += coin.value;
    const fee = feeFor({ inputs: picked.length, destLen, withChange: true, rate, cap });
    const change = total - amount - fee;
    if (change >= dustFor(34)) return { inputs: [...picked], amount, change, fee, total };
    // Change below dust: give it to the fee if the cap allows, else try one more coin.
    const exactFee = total - amount;
    if (noChange === null && exactFee >= feeFor({ inputs: picked.length, destLen, withChange: false, rate, cap })) {
      noChange = { inputs: [...picked], amount, change: null, fee: exactFee, total };
      if (exactFee <= cap) return noChange;
    }
  }
  // Over the cap: the contract's check says so in its own words.
  if (noChange) return noChange;
  const all = free.reduce((s, c) => s + c.value, 0);
  throw new CoinError(`not enough free coins: ${amount} sats asked, ${all} sats free before the fee`);
}

/** Confirmed coins at the vault's address that the contract reports Free. */
export async function freeCoins({ esploraUrl, address, isFree }) {
  const esplora = new Esplora(esploraUrl, { attempts: 3, backoffMs: 1000, timeoutMs: 15_000 });
  const listed = await esplora.utxos(address);
  const confirmed = listed.filter((u) => u?.status?.confirmed === true);
  const coins = [];
  for (const u of confirmed) {
    if (typeof u.txid !== 'string' || !/^[0-9a-f]{64}$/.test(u.txid) || !Number.isSafeInteger(u.value) || !Number.isInteger(u.vout)) continue;
    if (await isFree(u)) coins.push({ txid: u.txid, vout: u.vout, value: u.value });
  }
  return { coins, listed: listed.length, unconfirmed: listed.length - confirmed.length };
}
