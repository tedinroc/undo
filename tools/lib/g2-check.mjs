// What gate G2 checks about a Bitcoin transaction, with no trust in whoever built it. Every problem
// comes back with its own reason, because a bad signature and a high S mean different things.
import { derSig, makeTx, parseTx, SEQUENCE_COSIGNED, serialize, sighash, txid, vsize } from './btc.mjs';
import { concat, equal, fromHex, toHex } from './bytes.mjs';
import { secp256k1 } from './crypto.mjs';

const HALF_ORDER = secp256k1.CURVE.n >> 1n;
const toBig = (bytes) => BigInt(`0x${toHex(bytes) || '00'}`);

// A signature's largest honest size: strict DER, low S, sighash byte.
const WORST_SIG = new Uint8Array(72);

/** The first thing BIP-66 refuses in this signature, or null. Byte for byte what a node checks. */
export function strictDerProblem(sig) {
  if (sig.length < 9 || sig.length > 73) return 'length';
  if (sig[0] !== 0x30) return 'no sequence tag';
  if (sig[1] !== sig.length - 3) return 'sequence length';
  const lenR = sig[3];
  if (5 + lenR >= sig.length) return 'r length';
  const lenS = sig[5 + lenR];
  if (lenR + lenS + 7 !== sig.length) return 'total length';
  if (sig[2] !== 0x02) return 'r tag';
  if (lenR === 0) return 'empty r';
  if (sig[4] & 0x80) return 'negative r';
  if (lenR > 1 && sig[4] === 0 && !(sig[5] & 0x80)) return 'padded r';
  if (sig[lenR + 4] !== 0x02) return 's tag';
  if (lenS === 0) return 'empty s';
  if (sig[lenR + 6] & 0x80) return 'negative s';
  if (lenS > 1 && sig[lenR + 6] === 0 && !(sig[lenR + 7] & 0x80)) return 'padded s';
  return null;
}

function compactOf(sig) {
  const lenR = sig[3];
  const lenS = sig[5 + lenR];
  const pad = (x) => {
    const trimmed = x[0] === 0 ? x.slice(1) : x;
    return trimmed.length > 32 ? null : concat(new Uint8Array(32 - trimmed.length), trimmed);
  };
  return { r: pad(sig.slice(4, 4 + lenR)), s: pad(sig.slice(6 + lenR, 6 + lenR + lenS)) };
}

function verifies(r, s, digest, pub) {
  try {
    return secp256k1.verify(concat(r, s), digest, pub, { lowS: true, prehash: false });
  } catch {
    return false;
  }
}

/** Strict DER, SIGHASH_ALL, low S, and a real signature by `pub` over `digest`. */
export function checkSig(sig, digest, pub, name) {
  const der = strictDerProblem(sig);
  if (der) return { reason: 'bad_der', detail: `${name}: ${der}` };
  if (sig[sig.length - 1] !== 1) return { reason: 'bad_sighash_type', detail: name };
  const { r, s } = compactOf(sig);
  if (!r || !s) return { reason: 'bad_der', detail: `${name}: integer too long` };
  if (toBig(s) > HALF_ORDER) return { reason: 'high_s', detail: name };
  if (!verifies(r, s, digest, pub)) return { reason: 'bad_signature', detail: name };
  return null;
}

export const isHighS = (rs) => toBig(rs.slice(32, 64)) > HALF_ORDER;

/** The size this co-signed spend will have, from worst-case signatures, before anyone has signed. */
export function cosignedVsize({ coin, to, amount, script }) {
  const tx = makeTx([coin], SEQUENCE_COSIGNED, [{ value: amount, spk: to }]);
  tx.inputs[0].witness = [WORST_SIG, WORST_SIG, Uint8Array.of(1), script];
  return vsize(tx);
}

/** Likewise for an escape of these coins to one output. */
export function escapeVsize({ coins, to, script, csv }) {
  const tx = makeTx(coins, csv, [{ value: 1, spk: to }]);
  for (const input of tx.inputs) input.witness = [WORST_SIG, new Uint8Array(0), script];
  return vsize(tx);
}

/** Builds the witness from the signer's r || s and the half-signature, without the contract's encoder. */
export function assembleCosigned({ coin, to, amount, mpcRs, halfRs, script }) {
  const tx = makeTx([coin], SEQUENCE_COSIGNED, [{ value: amount, spk: to }]);
  tx.inputs[0].witness = [derSig(mpcRs), derSig(halfRs.slice(0, 64)), Uint8Array.of(1), script];
  return toHex(serialize(tx));
}

/** The co-signed spend with K_u's signature taken out. A sound script refuses it. Same txid: only the witness changed. */
export function withoutKuSig(rawHex) {
  const tx = parseTx(fromHex(rawHex));
  tx.inputs[0].witness[1] = new Uint8Array(0);
  return toHex(serialize(tx));
}

/**
 * What a thief holding the spend key alone can send: K_u's real signature, and nothing where K_m's goes,
 * because only the signer can make that one. K_u's check passes, so a sound script refuses it at K_m's.
 */
export function withoutKmSig({ coin, to, amount, halfRs, script }) {
  const tx = makeTx([coin], SEQUENCE_COSIGNED, [{ value: amount, spk: to }]);
  tx.inputs[0].witness = [new Uint8Array(0), derSig(halfRs.slice(0, 64)), Uint8Array.of(1), script];
  return { raw: toHex(serialize(tx)), id: txid(tx) };
}

/** An honest escape signed for nSequence csv-1. BIP-68 lets it through on a mature coin, so only OP_CSV can refuse it. */
export function escapeOneShort({ file, coin, to, amount }) {
  const tx = makeTx([coin], file.csv - 1, [{ value: amount, spk: to }]);
  const sig = secp256k1.sign(sighash(tx, 0, file.script, coin.value), file.cold, { lowS: true, prehash: false });
  tx.inputs[0].witness = [derSig(sig.toCompactRawBytes()), new Uint8Array(0), file.script];
  return { raw: toHex(serialize(tx)), id: txid(tx) };
}

function parseOr(rawHex) {
  try {
    return { tx: parseTx(fromHex(rawHex)) };
  } catch (err) {
    return { problem: { reason: 'unparsable_tx', detail: err.message } };
  }
}

function shapeProblem(tx, { coin, to, amount, sequence, witnessItems, script }) {
  if (tx.version !== 2 || tx.lockTime !== 0) return { reason: 'wrong_tx_header', detail: `version ${tx.version}, locktime ${tx.lockTime}` };
  if (tx.inputs.length !== 1 || tx.outputs.length !== 1) return { reason: 'wrong_tx_shape', detail: `${tx.inputs.length} inputs, ${tx.outputs.length} outputs` };
  const [input] = tx.inputs;
  if (input.coin.txid !== coin.txid || input.coin.vout !== coin.vout) return { reason: 'wrong_input', detail: `${input.coin.txid}:${input.coin.vout}` };
  if (input.sequence !== sequence) return { reason: 'wrong_sequence', detail: String(input.sequence) };
  const [output] = tx.outputs;
  if (!equal(output.spk, to)) return { reason: 'wrong_output', detail: toHex(output.spk) };
  if (Number(output.value) !== amount) return { reason: 'wrong_amount', detail: String(output.value) };
  if (input.witness.length !== witnessItems) return { reason: 'wrong_witness', detail: `${input.witness.length} items` };
  if (!equal(input.witness[witnessItems - 1], script)) return { reason: 'wrong_witness_script', detail: 'not the vault script' };
  return null;
}

/** A co-signed spend, read from hex. Digest computed here, from the coin and the outputs asked for. */
export function checkCosigned({ rawHex, coin, to, amount, script, km, ku }) {
  const { tx, problem } = parseOr(rawHex);
  if (problem) return { problem };
  const shape = shapeProblem(tx, { coin, to, amount, sequence: SEQUENCE_COSIGNED, witnessItems: 4, script });
  if (shape) return { problem: shape };
  const w = tx.inputs[0].witness;
  if (w[2].length !== 1 || w[2][0] !== 1) return { problem: { reason: 'wrong_witness', detail: 'the branch selector is not 1' } };
  const digest = sighash(makeTx([coin], SEQUENCE_COSIGNED, [{ value: amount, spk: to }]), 0, script, coin.value);
  const bad = checkSig(w[0], digest, km, 'K_m') ?? checkSig(w[1], digest, ku, 'K_u');
  if (bad) return { problem: bad };
  return { facts: sigFacts(rawHex, tx, [['K_m', w[0]], ['K_u', w[1]]]) };
}

/** An escape of one coin. No trust in escape.mjs: the digest comes from the same fields, recomputed. */
export function checkEscape({ rawHex, coin, to, amount, script, csv, ke }) {
  const { tx, problem } = parseOr(rawHex);
  if (problem) return { problem };
  const shape = shapeProblem(tx, { coin, to, amount, sequence: csv, witnessItems: 3, script });
  if (shape) return { problem: shape };
  const w = tx.inputs[0].witness;
  if (w[1].length !== 0) return { problem: { reason: 'wrong_witness', detail: 'the branch selector is not empty' } };
  const digest = sighash(makeTx([coin], csv, [{ value: amount, spk: to }]), 0, script, coin.value);
  const bad = checkSig(w[0], digest, ke, 'K_e');
  if (bad) return { problem: bad };
  return { facts: sigFacts(rawHex, tx, [['K_e', w[0]]]) };
}

function sigFacts(rawHex, tx, sigs) {
  return {
    txid: txid(tx),
    vsize: vsize(tx),
    signatures: sigs.map(([key, sig]) => ({ key, der_bytes: sig.length - 1, strict_der: true, low_s: true, sighash_all: true, verified: true })),
    raw_bytes: rawHex.length / 2,
  };
}

/** What Esplora says it has, against the bytes that were sent and the outputs that were asked for. */
export function checkReadback({ apiTx, status, hexBack, rawHex, id, coin, toHexSpk, amount, sequence, witnessHex }) {
  if (!apiTx) return { reason: 'readback_missing', detail: 'Esplora does not have it' };
  if (apiTx.txid !== id) return { reason: 'readback_txid', detail: apiTx.txid };
  if (hexBack !== rawHex) return { reason: 'readback_bytes', detail: 'the mined bytes differ from the bytes sent' };
  if (!status?.confirmed || !Number.isInteger(status.block_height)) return { reason: 'readback_not_mined', detail: 'not confirmed' };
  if (apiTx.vin?.length !== 1 || apiTx.vout?.length !== 1) return { reason: 'readback_shape', detail: `${apiTx.vin?.length} in, ${apiTx.vout?.length} out` };
  const [vin] = apiTx.vin;
  if (vin.txid !== coin.txid || vin.vout !== coin.vout) return { reason: 'readback_input', detail: `${vin.txid}:${vin.vout}` };
  if (vin.sequence !== sequence) return { reason: 'readback_sequence', detail: String(vin.sequence) };
  // An API may write an empty witness item in more than one way. The bytes were compared above.
  const items = (w) => JSON.stringify((w ?? []).filter(Boolean));
  if (items(vin.witness) !== items(witnessHex)) return { reason: 'readback_witness', detail: 'witness differs' };
  const [vout] = apiTx.vout;
  if (vout.scriptpubkey !== toHexSpk) return { reason: 'readback_output', detail: vout.scriptpubkey };
  if (vout.value !== amount) return { reason: 'readback_amount', detail: String(vout.value) };
  return null;
}

/** A coin at this height can be spent by the escape once the tip reaches this. */
export const matureTip = (coinHeight, csv) => coinHeight + csv - 1;

export const witnessHexOf = (rawHex) => parseTx(fromHex(rawHex)).inputs[0].witness.map(toHex);
