// Spends from the P2WPKH dispenser file made by human-key.mjs. No error here carries the file's text,
// and the secret is not enumerable, so a stray console.log or JSON.stringify cannot print it.
import { readFileSync } from 'node:fs';
import { addressToSpk, derSig, makeTx, p2wpkhAddress, p2wpkhSpk, serialize, sighash, txid, vsize } from './btc.mjs';
import { concat, fromHex, toHex } from './bytes.mjs';
import { secp256k1 } from './crypto.mjs';
import { publicSecp } from './keys.mjs';

const FORMAT = 'undo-dispenser-v1';
const SEQUENCE = 0xfffffffd;
const WORST_SIG = new Uint8Array(72);

export function parseDispenser(text, network) {
  let w;
  try {
    w = JSON.parse(text);
  } catch {
    throw new Error('dispenser file is not JSON');
  }
  if (w?.format !== FORMAT) throw new Error('dispenser file has an unknown format');
  if (w.network !== network) throw new Error(`dispenser file is not for ${network}`);
  let secret;
  let pub;
  try {
    secret = fromHex(w.secret);
    pub = publicSecp(secret);
  } catch {
    throw new Error('dispenser file holds no valid key');
  }
  if (p2wpkhAddress(network, pub) !== w.address) throw new Error('dispenser address is not the key\'s address');
  const out = { network, address: w.address, pub, spk: p2wpkhSpk(pub) };
  Object.defineProperty(out, 'secret', { value: secret, enumerable: false });
  return out;
}

export const loadDispenser = (path, network) => parseDispenser(readFileSync(path, 'utf8'), network);

/** Confirmed coins only. Smallest single coin that covers it, otherwise largest first. */
export function selectCoins(utxos, need) {
  const confirmed = utxos.filter((u) => u.status?.confirmed).sort((a, b) => a.value - b.value);
  const single = confirmed.find((u) => u.value >= need);
  if (single) return [single];
  const picked = [];
  let total = 0;
  for (const u of [...confirmed].reverse()) {
    picked.push(u);
    total += u.value;
    if (total >= need) return picked;
  }
  return null;
}

const DUST = 294;

export function fundingVsize(inputs, payTo, changeTo) {
  const tx = makeTx(inputs, SEQUENCE, [{ value: 1, spk: payTo }, { value: 1, spk: changeTo }]);
  for (const input of tx.inputs) input.witness = [WORST_SIG, new Uint8Array(33)];
  return vsize(tx);
}

/**
 * One payment and change back to the dispenser, signed. Returns the raw hex and the coin it makes, so
 * the caller can record the coin before anything is broadcast. Change under dust goes to the fee.
 */
export function buildFunding({ dispenser, utxos, payTo, value, feeRate }) {
  const firstGuess = value + feeRate * fundingVsize(utxos.slice(0, 1), payTo, dispenser.spk);
  const picked = selectCoins(utxos, firstGuess);
  if (!picked) return { short: true };
  let fee = feeRate * fundingVsize(picked, payTo, dispenser.spk);
  const total = picked.reduce((s, c) => s + c.value, 0);
  if (total < value + fee) return { short: true };
  let change = total - value - fee;
  const outputs = [{ value, spk: payTo }];
  if (change >= DUST) {
    outputs.push({ value: change, spk: dispenser.spk });
  } else {
    fee += change;
    change = 0;
  }
  const coins = picked.map((c) => ({ txid: c.txid, vout: c.vout, value: c.value }));
  const tx = makeTx(coins, SEQUENCE, outputs);
  // P2WPKH signs over the old pay-to-pubkey-hash script.
  const scriptCode = concat(Uint8Array.of(0x76, 0xa9, 0x14), dispenser.spk.slice(2), Uint8Array.of(0x88, 0xac));
  tx.inputs.forEach((input, i) => {
    const digest = sighash(tx, i, scriptCode, coins[i].value);
    const sig = secp256k1.sign(digest, dispenser.secret, { lowS: true, prehash: false });
    input.witness = [derSig(sig.toCompactRawBytes()), dispenser.pub];
  });
  return { raw: toHex(serialize(tx)), txid: txid(tx), vout: 0, value, fee, vsize: vsize(tx), inputs: coins.map((c) => `${c.txid}:${c.vout}`), change };
}

export { addressToSpk };
