// Plain text for a terminal and a film: short lines, real values, every hash named by its chain.
import { segwitAddress } from '../../tools/lib/btc.mjs';
import { fromHex } from '../../tools/lib/bytes.mjs';

/** `5:00`, `14:59`, `1:00:00`. Rounds up, as a countdown does: it reads 5:00 until a whole second passes. */
export function clock(ms) {
  const total = Math.max(0, Math.ceil(ms / 1000));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  const s = String(total % 60).padStart(2, '0');
  return h > 0 ? `${h}:${String(m).padStart(2, '0')}:${s}` : `${m}:${s}`;
}

export const sats = (n) => `${Number(n).toLocaleString('en-US')} sats`;

export const TIERS = {
  SelfSpend: 'SelfSpend: back to this vault',
  Known: 'Known: a destination the owner approved',
  New: 'New: a destination the owner has not approved',
};

export const tierText = (tier) => TIERS[tier] ?? tier;

/** The address an output script pays. The contract takes segwit outputs only. */
export function spkToAddress(network, spkHex) {
  const spk = fromHex(spkHex, 'script');
  if (spk.length === 22 && spk[0] === 0x00 && spk[1] === 0x14) return segwitAddress(network, 0, spk.slice(2));
  if (spk.length === 34 && spk[0] === 0x00 && spk[1] === 0x20) return segwitAddress(network, 0, spk.slice(2));
  if (spk.length === 34 && spk[0] === 0x51 && spk[1] === 0x20) return segwitAddress(network, 1, spk.slice(2));
  return `script ${spkHex}`;
}

/** What Bitcoin network the coins are on, as the screen must say it. */
export function coinLabel(networkInfo, btcNetwork) {
  if (networkInfo.local) return 'made-up coins, mock signer';
  if (btcNetwork === 'mutinynet') return 'Mutinynet signet test coins';
  return `${btcNetwork} test coins`;
}

/**
 * The contract's own words from a failed call: `Smart contract panicked: SpendKeySuspended`. Anything
 * not shaped like a contract panic comes back whole, so nothing is ever paraphrased.
 */
export function contractWords(failureJson) {
  try {
    const f = JSON.parse(failureJson);
    const exec = f?.ActionError?.kind?.FunctionCallError?.ExecutionError;
    if (typeof exec === 'string') return exec;
  } catch {
    // Not JSON: return it as it came.
  }
  return failureJson;
}

/** A view's refusal: the panic message inside the RPC error text, or the whole text. */
export function viewWords(message) {
  const text = String(message);
  const panic = text.match(/panic_msg: "((?:[^"\\]|\\.)*)"/);
  if (panic) return panic[1].replace(/\\"/g, '"');
  const smart = text.match(/Smart contract panicked: (.*)$/s);
  if (smart) return smart[1].trim();
  return text;
}

/** NEAR's refusal of a transaction before any contract ran: the runtime's error, verbatim. */
export function runtimeWords(err) {
  const tx = err?.data?.data?.TxExecutionError;
  if (tx) return JSON.stringify(tx.InvalidTxError ?? tx);
  const info = err?.data?.cause?.info;
  if (info) return JSON.stringify(info);
  return err?.message ?? String(err);
}
