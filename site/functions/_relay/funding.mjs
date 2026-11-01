// A copy of buildFunding from tools/lib/dispenser.mjs, which reads the disk at import and so cannot load in a
// Worker. site/test/relay.test.mjs checks that both give the same transaction on the same inputs.
import { derSig, makeTx, p2wpkhAddress, p2wpkhSpk, serialize, sighash, txid, vsize } from '../../../tools/lib/btc.mjs';
import { concat, fromHex, toHex } from '../../../tools/lib/bytes.mjs';
import { secp256k1 } from '../../../tools/lib/crypto.mjs';
import { publicSecp } from '../../../tools/lib/keys.mjs';

const SEQUENCE = 0xfffffffd;
const WORST_SIG = new Uint8Array(72);
const DUST = 294;

// The first secp256k1 signature in a new isolate builds noble's tables: 14 ms against a 10 ms limit, in local
// workerd. Doing one now moves that into startup, which has its own limit, and leaves about 2 ms for a request.
// Fixed public values, signing nothing. Cloudflare's own accounting of this is unmeasured.
secp256k1.sign(new Uint8Array(32).fill(2), new Uint8Array(32).fill(1), { lowS: true, prehash: false });

/** The dispenser from a hex secret. No error here repeats it, and the secret is not enumerable. */
export function dispenserFromSecret(hex, network) {
  let secret;
  let pub;
  try {
    secret = fromHex(hex);
    pub = publicSecp(secret);
  } catch {
    throw new Error('dispenser secret is not a key');
  }
  const out = { network, address: p2wpkhAddress(network, pub), pub, spk: p2wpkhSpk(pub) };
  Object.defineProperty(out, 'secret', { value: secret, enumerable: false });
  return out;
}

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

export function fundingVsize(inputs, payTo, changeTo) {
  const tx = makeTx(inputs, SEQUENCE, [{ value: 1, spk: payTo }, { value: 1, spk: changeTo }]);
  for (const input of tx.inputs) input.witness = [WORST_SIG, new Uint8Array(33)];
  return vsize(tx);
}

/** One payment and change back to the dispenser, signed. Change under dust goes to the fee. */
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
