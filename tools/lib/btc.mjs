// Bitcoin bytes: the two-branch script, addresses, BIP-143 and transaction encoding. Written against
// crates/undo-btc, and tools/test checks it byte for byte against that crate and against a node.
import { concat, equal, fixedHex, fromHex, reversed, toHex, u32le, u64le, utf8, base58Decode } from './bytes.mjs';
import { ripemd160, sha256 } from './crypto.mjs';

export const SEQUENCE_COSIGNED = 0xfffffffd;
const ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const HALF_ORDER = ORDER >> 1n;

export const sha256d = (bytes) => sha256(sha256(bytes));
export const hash160 = (bytes) => ripemd160(sha256(bytes));

// ---------------------------------------------------------------- script

function csvPush(v) {
  if (!Number.isInteger(v) || v < 1 || v > 65535) throw new Error('csv must be 1 to 65535');
  if (v <= 16) return Uint8Array.of(0x51 + v - 1);
  if (v <= 127) return Uint8Array.of(1, v);
  if (v <= 255) return Uint8Array.of(2, v, 0);
  if (v <= 32767) return Uint8Array.of(2, v & 0xff, v >> 8);
  return Uint8Array.of(3, v & 0xff, v >> 8, 0);
}

function checkKey(key) {
  if (key.length !== 33 || (key[0] !== 2 && key[0] !== 3)) throw new Error('not a compressed public key');
}

export function witnessScript(ku, km, ke, csv) {
  [ku, km, ke].forEach(checkKey);
  if (equal(ku, km) || equal(ku, ke) || equal(km, ke)) throw new Error('script keys must all differ');
  return concat(
    Uint8Array.of(0x63, 0x21), ku, Uint8Array.of(0xad, 0x21), km, Uint8Array.of(0xac, 0x67),
    csvPush(csv), Uint8Array.of(0xb2, 0x75, 0x21), ke, Uint8Array.of(0xac, 0x68),
  );
}

/** Reads the fields, then requires that building from them gives the same bytes. One encoding only. */
export function parseWitnessScript(bytes) {
  if (bytes.length < 111 || bytes.length > 114) throw new Error('not an Undo script');
  const ku = bytes.slice(2, 35);
  const km = bytes.slice(37, 70);
  const first = bytes[72];
  let csv;
  let used;
  if (first >= 0x51 && first <= 0x60) {
    csv = first - 0x51 + 1;
    used = 1;
  } else if (first >= 1 && first <= 3) {
    csv = 0;
    for (let i = 0; i < first; i += 1) csv |= bytes[73 + i] << (8 * i);
    used = 1 + first;
  } else {
    throw new Error('not an Undo script');
  }
  const start = 72 + used + 3;
  const ke = bytes.slice(start, start + 33);
  const built = witnessScript(ku, km, ke, csv);
  if (!equal(built, bytes)) throw new Error('not an Undo script');
  return { ku, km, ke, csv };
}

export const p2wshProgram = (script) => sha256(script);
export const p2wshSpk = (script) => concat(Uint8Array.of(0x00, 0x20), p2wshProgram(script));
export const p2wpkhSpk = (pub) => concat(Uint8Array.of(0x00, 0x14), hash160(pub));

// ---------------------------------------------------------------- addresses

const NETWORKS = {
  mainnet: { hrp: 'bc', p2pkh: 0x00, p2sh: 0x05 },
  mutinynet: { hrp: 'tb', p2pkh: 0x6f, p2sh: 0xc4 },
  signet: { hrp: 'tb', p2pkh: 0x6f, p2sh: 0xc4 },
  testnet4: { hrp: 'tb', p2pkh: 0x6f, p2sh: 0xc4 },
  regtest: { hrp: 'bcrt', p2pkh: 0x6f, p2sh: 0xc4 },
};

export const isNetwork = (name) => Object.hasOwn(NETWORKS, name);

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32 = 1;
const BECH32M = 0x2bc830a3;

function polymod(values) {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = (((chk & 0x1ffffff) << 5) ^ v) >>> 0;
    for (let i = 0; i < 5; i += 1) if ((top >>> i) & 1) chk = (chk ^ GEN[i]) >>> 0;
  }
  return chk;
}

function hrpExpand(hrp) {
  const codes = Array.from(hrp, (c) => c.charCodeAt(0));
  return [...codes.map((c) => c >> 5), 0, ...codes.map((c) => c & 31)];
}

function convertBits(data, from, to, pad) {
  let acc = 0;
  let bits = 0;
  const out = [];
  const max = (1 << to) - 1;
  for (const v of data) {
    acc = (acc << from) | v;
    bits += from;
    while (bits >= to) {
      bits -= to;
      out.push((acc >> bits) & max);
    }
    acc &= (1 << bits) - 1;
  }
  if (pad) {
    if (bits > 0) out.push((acc << (to - bits)) & max);
  } else if (bits >= from || ((acc << (to - bits)) & max) !== 0) {
    throw new AddressError('padding', 'its last character carries bits an address never has');
  }
  return out;
}

export function segwitAddress(network, version, program) {
  const { hrp } = NETWORKS[network];
  const data = [version, ...convertBits(program, 8, 5, true)];
  const spec = version === 0 ? BECH32 : BECH32M;
  const mod = polymod([...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0]) ^ spec;
  let out = `${hrp}1`;
  for (const d of data) out += CHARSET[d];
  for (let i = 0; i < 6; i += 1) out += CHARSET[(mod >>> (5 * (5 - i))) & 31];
  return out;
}

export const p2wshAddress = (network, script) => segwitAddress(network, 0, p2wshProgram(script));
export const p2wpkhAddress = (network, pub) => segwitAddress(network, 0, hash160(pub));

/** An address refused, with a short code a test can hold and words a person can read. */
export class AddressError extends Error {
  constructor(code, message, extra = {}) {
    super(message);
    this.code = code;
    Object.assign(this, extra);
  }
}

/** What a person calls the networks behind each prefix, for a refusal that names the other one. */
const HRP_NAMES = { bc: 'mainnet', tb: 'signet or testnet', bcrt: 'regtest' };

/** `tb1` or `bcrt1`: how this network's own segwit addresses start. Null for a network this file does not know. */
export const addressPrefix = (network) => (Object.hasOwn(NETWORKS, network) ? `${NETWORKS[network].hrp}1` : null);

/**
 * BIP-173 and BIP-350 for the whole string: printable ASCII, one case, at most 90 characters, an hrp before the last
 * `1`, at least a checksum after it, only charset letters there, and a checksum that is bech32's or bech32m's. Nothing
 * is skipped, so text in front of a valid address changes the hrp and is refused.
 */
export function bech32Decode(text) {
  if (typeof text !== 'string') throw new AddressError('not_text', 'not text');
  if (/[^\x21-\x7e]/.test(text)) throw new AddressError('range', 'it has a character outside printable ASCII');
  if (text !== text.toLowerCase() && text !== text.toUpperCase()) throw new AddressError('mixed_case', 'it mixes upper and lower case');
  if (text.length > 90) throw new AddressError('length', 'it is longer than 90 characters');
  const lower = text.toLowerCase();
  const sep = lower.lastIndexOf('1');
  if (sep < 1) throw new AddressError('separator', 'it has no network prefix before a 1');
  if (lower.length - sep - 1 < 6) throw new AddressError('short', 'it is too short to hold a checksum');
  const data = Array.from(lower.slice(sep + 1), (c) => CHARSET.indexOf(c));
  if (data.includes(-1)) throw new AddressError('charset', 'it has a character an address never uses, such as b, i or o');
  const hrp = lower.slice(0, sep);
  const residue = polymod([...hrpExpand(hrp), ...data]);
  const spec = residue === BECH32 ? 'bech32' : residue === BECH32M ? 'bech32m' : null;
  if (spec === null) throw new AddressError('checksum', 'its checksum does not match, so a character is wrong');
  return { hrp, data: data.slice(0, -6), spec };
}

/** A segwit address for exactly `hrp`, by the rules of BIP-173, BIP-141 and BIP-350. Returns the output script. */
export function decodeSegwit(hrp, address) {
  const got = bech32Decode(address);
  if (got.hrp !== hrp) throw new AddressError('hrp', `it is not a ${hrp}1 address`);
  const program = Uint8Array.from(convertBits(got.data.slice(1), 5, 8, false));
  if (program.length < 2 || program.length > 40) throw new AddressError('program_length', 'it holds a program of the wrong length');
  const version = got.data[0];
  if (version > 16) throw new AddressError('version', 'its witness version is above 16');
  if (version === 0 && program.length !== 20 && program.length !== 32) throw new AddressError('v0_length', 'a version 0 program must be 20 or 32 bytes');
  if (got.spec !== (version === 0 ? 'bech32' : 'bech32m')) throw new AddressError('checksum_type', `its checksum is ${got.spec}, and version ${version} takes ${version === 0 ? 'bech32' : 'bech32m'}`);
  return concat(Uint8Array.of(version === 0 ? 0 : 0x50 + version, program.length), program);
}

/**
 * The output script an address pays, for this network and no other. Every refusal is an AddressError whose message
 * reads after "not a <network> address: ": another network's valid address says which network it is, a `bitcoin:`
 * link says so, and anything else says what is wrong with it.
 */
export function addressToSpk(network, address) {
  const net = NETWORKS[network];
  if (!net) throw new Error('unknown network');
  if (typeof address !== 'string') throw new AddressError('not_text', 'not text');
  if (address === '') throw new AddressError('empty', 'it is empty');
  const lower = address.toLowerCase();
  if (lower.startsWith(`${net.hrp}1`)) return decodeSegwit(net.hrp, address);
  if (lower.startsWith('bitcoin:')) throw new AddressError('uri', 'it is a bitcoin: link, and only the address in it goes here');
  const other = Object.keys(HRP_NAMES).find((hrp) => lower.startsWith(`${hrp}1`));
  if (other) {
    // Read by that network's rules first, so a broken string is called broken and only a good one is named.
    decodeSegwit(other, address);
    throw new AddressError('other_network', `it is a ${HRP_NAMES[other]} address`, { hrp: other, networkName: HRP_NAMES[other] });
  }
  let raw;
  try {
    raw = base58Decode(address);
  } catch {
    raw = null;
  }
  if (raw?.length !== 25) throw new AddressError('not_address', 'it is not a bitcoin address');
  const check = sha256d(raw.slice(0, 21)).slice(0, 4);
  if (!equal(check, raw.slice(21))) throw new AddressError('base58_checksum', 'its checksum does not match, so a character is wrong');
  const hash = raw.slice(1, 21);
  if (raw[0] === net.p2pkh) return concat(Uint8Array.of(0x76, 0xa9, 0x14), hash, Uint8Array.of(0x88, 0xac));
  if (raw[0] === net.p2sh) return concat(Uint8Array.of(0xa9, 0x14), hash, Uint8Array.of(0x87));
  // Every test network shares one pair of base58 version bytes, so such an address names no test network in particular.
  const owner = Object.values(NETWORKS).find((n) => raw[0] === n.p2pkh || raw[0] === n.p2sh);
  const ownerName = owner?.hrp === 'bc' ? 'mainnet' : 'test-network';
  if (owner) throw new AddressError('other_network', `it is a ${ownerName} address`, { hrp: owner.hrp, networkName: ownerName });
  throw new AddressError('not_address', 'it is not a bitcoin address');
}

// ---------------------------------------------------------------- transactions

function compactSize(n) {
  if (n <= 0xfc) return Uint8Array.of(n);
  if (n <= 0xffff) return Uint8Array.of(0xfd, n & 0xff, n >> 8);
  return concat(Uint8Array.of(0xfe), u32le(n));
}

const writeOutpoint = (coin) => concat(reversed(fixedHex(coin.txid, 32, 'txid')), u32le(coin.vout));
const writeOutput = (o) => concat(u64le(o.value), compactSize(o.spk.length), o.spk);

export function makeTx(coins, sequence, outputs) {
  return { version: 2, lockTime: 0, inputs: coins.map((c) => ({ coin: c, sequence, witness: [] })), outputs };
}

/** BIP-143 under SIGHASH_ALL. The script code is the whole witness script. */
export function sighash(tx, index, script, value) {
  const prevouts = sha256d(concat(...tx.inputs.map((i) => writeOutpoint(i.coin))));
  const sequences = sha256d(concat(...tx.inputs.map((i) => u32le(i.sequence))));
  const outputs = sha256d(concat(...tx.outputs.map(writeOutput)));
  const input = tx.inputs[index];
  return sha256d(concat(
    u32le(tx.version), prevouts, sequences, writeOutpoint(input.coin),
    compactSize(script.length), script, u64le(value), u32le(input.sequence),
    outputs, u32le(tx.lockTime), u32le(1),
  ));
}

function body(tx) {
  return [
    compactSize(tx.inputs.length),
    ...tx.inputs.flatMap((i) => [writeOutpoint(i.coin), Uint8Array.of(0), u32le(i.sequence)]),
    compactSize(tx.outputs.length),
    ...tx.outputs.map(writeOutput),
  ];
}

export function serializeStripped(tx) {
  return concat(u32le(tx.version), ...body(tx), u32le(tx.lockTime));
}

export function serialize(tx) {
  if (!tx.inputs.some((i) => i.witness.length)) return serializeStripped(tx);
  const witness = tx.inputs.flatMap((i) => [compactSize(i.witness.length), ...i.witness.flatMap((w) => [compactSize(w.length), w])]);
  return concat(u32le(tx.version), Uint8Array.of(0, 1), ...body(tx), ...witness, u32le(tx.lockTime));
}

export const txid = (tx) => toHex(reversed(sha256d(serializeStripped(tx))));
export const weight = (tx) => serializeStripped(tx).length * 3 + serialize(tx).length;
export const vsize = (tx) => Math.ceil(weight(tx) / 4);

function derInt(x) {
  let start = 0;
  while (start < 31 && x[start] === 0) start += 1;
  const part = x.slice(start);
  const pad = part[0] & 0x80 ? Uint8Array.of(0) : new Uint8Array(0);
  return concat(Uint8Array.of(2, part.length + pad.length), pad, part);
}

const toBig = (bytes) => BigInt(`0x${toHex(bytes)}`);

/** Strict DER, low S, with the SIGHASH_ALL byte. r and s are 32 bytes each. */
export function derSig(rs) {
  const r = toBig(rs.slice(0, 32));
  const s = toBig(rs.slice(32, 64));
  if (r === 0n || s === 0n || r >= ORDER || s >= ORDER) throw new Error('signature out of range');
  const low = s > HALF_ORDER ? ORDER - s : s;
  const lowBytes = fromHex(low.toString(16).padStart(64, '0'));
  const inner = concat(derInt(rs.slice(0, 32)), derInt(lowBytes));
  return concat(Uint8Array.of(0x30, inner.length), inner, Uint8Array.of(1));
}

/** A strict reader for what `derSig` writes, for checking a final transaction. Returns r || s. */
export function parseDer(sig) {
  if (sig[0] !== 0x30 || sig[1] !== sig.length - 3 || sig[sig.length - 1] !== 1) throw new Error('bad DER');
  const read = (at) => {
    if (sig[at] !== 2) throw new Error('bad DER');
    const len = sig[at + 1];
    return { value: sig.slice(at + 2, at + 2 + len), next: at + 2 + len };
  };
  const r = read(2);
  const s = read(r.next);
  const pad = (x) => {
    const trimmed = x[0] === 0 ? x.slice(1) : x;
    return concat(new Uint8Array(32 - trimmed.length), trimmed);
  };
  return concat(pad(r.value), pad(s.value));
}

/** Reads a witness transaction, enough to check what `final_tx` returned. */
export function parseTx(bytes) {
  let at = 0;
  const take = (n) => {
    const out = bytes.slice(at, at + n);
    if (out.length !== n) throw new Error('short transaction');
    at += n;
    return out;
  };
  const size = () => {
    const first = take(1)[0];
    if (first < 0xfd) return first;
    if (first === 0xfd) return new DataView(take(2).buffer).getUint16(0, true);
    if (first === 0xfe) return new DataView(take(4).buffer).getUint32(0, true);
    throw new Error('huge count');
  };
  const u32 = () => new DataView(take(4).buffer).getUint32(0, true);
  const version = u32();
  const marker = bytes[at] === 0 && bytes[at + 1] === 1;
  if (marker) at += 2;
  const inputs = [];
  for (let n = size(); n > 0; n -= 1) {
    const hash = take(32);
    const vout = u32();
    if (size() !== 0) throw new Error('script_sig must be empty');
    inputs.push({ coin: { txid: toHex(reversed(hash)), vout }, sequence: u32(), witness: [] });
  }
  const outputs = [];
  for (let n = size(); n > 0; n -= 1) {
    const value = new DataView(take(8).buffer).getBigUint64(0, true);
    outputs.push({ value, spk: take(size()) });
  }
  if (marker) {
    for (const input of inputs) {
      for (let n = size(); n > 0; n -= 1) input.witness.push(take(size()));
    }
  }
  const lockTime = u32();
  if (at !== bytes.length) throw new Error('trailing bytes');
  return { version, lockTime, inputs, outputs };
}

export { utf8 };
