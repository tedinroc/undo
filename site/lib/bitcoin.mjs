// Mutinynet reads and the one POST the film needs. The client is tools/lib/esplora.mjs itself, so a page
// and G2's driver sort a node's answer by the same rule. What differs is the POST: a page shows the
// answer, so it sends once, and keeps the bytes a node sent, untouched and untrimmed.
import { derSig, makeTx, p2wpkhSpk, p2wshSpk, SEQUENCE_COSIGNED, segwitAddress, serialize, sighash, txid as txidOf, vsize } from '../../tools/lib/btc.mjs';
import { equal, fromHex, toHex } from '../../tools/lib/bytes.mjs';
import { classifyBroadcast, Esplora } from '../../tools/lib/esplora.mjs';
import { signSecp } from '../../tools/lib/intent.mjs';
import { spendKeys } from '../../tools/lib/keys.mjs';

export { classifyBroadcast, p2wpkhSpk, p2wshSpk };

/** A page waits seconds, not the minute a driver can afford. */
export const bitcoinReader = (base, { timeoutMs = 6000, backoffMs = 300, attempts = 2 } = {}) => new Esplora(base, { timeoutMs, backoffMs, attempts });

/**
 * One POST /tx. Never retried here: a second POST of a refused transaction is a different thing to show.
 *
 * `kind` is accepted, rejected, transient (something on the way answered, not a node) or no_answer.
 * `body` is exactly what came back. A screen shows `body`, and only a `rejected` with `refusal: 'script'`
 * may read as Bitcoin refusing the script.
 */
export async function postTxOnce(base, hex, txid, { fetchFn = (...a) => globalThis.fetch(...a), timeoutMs = 15_000 } = {}) {
  let res;
  let body;
  try {
    res = await fetchFn(`${base}/tx`, { method: 'POST', headers: { 'content-type': 'text/plain' }, body: hex, redirect: 'error', signal: AbortSignal.timeout(timeoutMs) });
    body = await res.text();
  } catch (err) {
    return { kind: 'no_answer', status: res?.status ?? null, body: null, error: err.name };
  }
  const { kind, refusal = null } = classifyBroadcast(res.status, body, txid);
  return { kind, refusal, status: res.status, body };
}

/** The address an output script pays, for the three templates the contract allows. Null otherwise. */
export function spkToAddress(network, spk) {
  const bytes = typeof spk === 'string' ? fromHex(spk) : spk;
  if (bytes.length === 22 && bytes[0] === 0x00 && bytes[1] === 0x14) return segwitAddress(network, 0, bytes.slice(2));
  if (bytes.length === 34 && bytes[0] === 0x00 && bytes[1] === 0x20) return segwitAddress(network, 0, bytes.slice(2));
  if (bytes.length === 34 && bytes[0] === 0x51 && bytes[1] === 0x20) return segwitAddress(network, 1, bytes.slice(2));
  return null;
}

const worstSig = new Uint8Array(73);

/** Worst-case vsize of a co-signed spend to one output. */
export function cosignedVsizeOf({ coins, to, script }) {
  const tx = makeTx(coins, SEQUENCE_COSIGNED, [{ value: 1, spk: to }]);
  for (const input of tx.inputs) input.witness = [worstSig, worstSig, Uint8Array.of(1), script];
  return vsize(tx);
}

/** Every coin to one output with no change, which is what `Send everything` means. */
export function sendEverything({ coins, to, script, feeRate }) {
  const total = coins.reduce((sum, c) => sum + c.value, 0);
  const fee = Math.ceil(cosignedVsizeOf({ coins, to, script }) * feeRate);
  const amount = total - fee;
  if (coins.length === 0 || amount <= 0) return { short: true, total, fee, amount: 0 };
  return { short: false, total, fee, amount, inputs: coins.map((c) => ({ txid: c.txid, vout: c.vout, value: c.value })) };
}

/**
 * The spend key alone: K_u's real signature on each input and nothing where K_m's goes, since only the
 * signer can make that one. All a thief can send without NEAR, for tools/lib/spend.mjs's same digest.
 * `tools/lib/g2-check.mjs withoutKmSig` is the one-coin form, and site/test checks they match.
 */
export function keyAloneSpend({ seed, script, coins, to, amount }) {
  const { ku } = spendKeys(seed);
  const tx = makeTx(coins, SEQUENCE_COSIGNED, [{ value: amount, spk: to }]);
  tx.inputs.forEach((input, i) => {
    const half = signSecp(sighash(tx, i, script, coins[i].value), ku.secret);
    input.witness = [new Uint8Array(0), derSig(half.slice(0, 64)), Uint8Array.of(1), script];
  });
  return { raw: toHex(serialize(tx)), txid: txidOf(tx), vsize: vsize(tx) };
}

/** Whether a script is really the one the vault says it pays. */
export const scriptMatchesVault = (script, vault) => equal(p2wshSpk(script), fromHex(vault.script_pubkey));
