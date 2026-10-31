// The recovery file, in the format crates/undo-btc/src/recovery.rs defines. Same fields, same
// checksum, same refusals in the same order. No error carries text from the file, and nothing here
// prints `cold_key`.
import { addressToSpk, derSig, isNetwork, makeTx, p2wshAddress, parseWitnessScript, sighash, witnessScript } from './btc.mjs';
import { equal, fixedHex, fromHex, toHex, utf8 } from './bytes.mjs';
import { secp256k1, sha256 } from './crypto.mjs';
import { publicSecp } from './keys.mjs';

const FORMAT = 'undo-recovery-v1';
const DUST_LIMIT = 546;
const FIELDS = ['format', 'network', 'vault_id', 'csv', 'witness_script', 'address', 'cold_key', 'checksum'];

export class RecoveryError extends Error {
  constructor(code, message) {
    super(message);
    this.code = code;
  }
}
const fail = (code, message) => {
  throw new RecoveryError(code, message);
};

function checksumText(w) {
  return `${FORMAT}\n${w.network}\n${w.vault_id}\n${w.csv}\n${w.witness_script}\n${w.address}\n${w.cold_key}\n`;
}

function checkVaultId(id) {
  if (typeof id !== 'string' || id.length === 0 || id.length > 128 || !/^[A-Za-z0-9._-]+$/.test(id)) fail('VaultId', 'bad vault id');
}

export function parseRecovery(text) {
  let w;
  try {
    w = JSON.parse(text);
  } catch {
    fail('Malformed', 'not a valid recovery file');
  }
  if (typeof w !== 'object' || w === null || Array.isArray(w)) fail('Malformed', 'not a valid recovery file');
  const keys = Object.keys(w);
  if (keys.length !== FIELDS.length || !FIELDS.every((f) => keys.includes(f))) fail('Malformed', 'not a valid recovery file');
  for (const f of FIELDS) {
    const want = f === 'csv' ? 'number' : 'string';
    if (typeof w[f] !== want) fail('Malformed', 'not a valid recovery file');
  }
  if (!Number.isInteger(w.csv) || w.csv < 0 || w.csv > 0xffffffff) fail('Malformed', 'not a valid recovery file');
  if (w.format !== FORMAT) fail('UnknownFormat', 'unknown recovery file format');
  if (toHex(sha256(utf8(checksumText(w)))) !== w.checksum) fail('Checksum', 'checksum does not match, the file is damaged');
  if (!isNetwork(w.network)) fail('Network', 'unknown network');
  checkVaultId(w.vault_id);

  let script;
  let parts;
  try {
    script = fromHex(w.witness_script);
    parts = parseWitnessScript(script);
  } catch {
    fail('Script', 'witness script is not an Undo script');
  }
  if (parts.csv !== w.csv) fail('CsvMismatch', 'csv does not match the script');
  if (p2wshAddress(w.network, script) !== w.address) fail('AddressMismatch', 'address does not match the script and network');

  let cold;
  let coldPub;
  try {
    cold = fixedHex(w.cold_key, 32, 'cold key');
    coldPub = publicSecp(cold);
  } catch {
    fail('ColdKey', 'cold key is not a valid secret');
  }
  if (!equal(coldPub, parts.ke)) fail('ColdKeyMismatch', 'cold key is not the one in the script');

  return makeFile({ network: w.network, vaultId: w.vault_id, script, parts, cold });
}

function makeFile({ network, vaultId, script, parts, cold }) {
  const file = { network, vaultId, script, csv: parts.csv, ku: parts.ku, km: parts.km, ke: parts.ke, address: p2wshAddress(network, script) };
  // Not enumerable, so a stray console.log or JSON.stringify of this object cannot print it.
  Object.defineProperty(file, 'cold', { value: cold, enumerable: false });
  return file;
}

/** Writes a file from its parts. Refuses a cold key the script does not name. */
export function buildRecovery({ network, vaultId, script, cold }) {
  checkVaultId(vaultId);
  if (!isNetwork(network)) fail('Network', 'unknown network');
  const parts = parseWitnessScript(script);
  if (!equal(publicSecp(cold), parts.ke)) fail('ColdKeyMismatch', 'cold key is not the one in the script');
  const w = {
    format: FORMAT,
    network,
    vault_id: vaultId,
    csv: parts.csv,
    witness_script: toHex(script),
    address: p2wshAddress(network, script),
    cold_key: toHex(cold),
  };
  w.checksum = toHex(sha256(utf8(checksumText(w))));
  return JSON.stringify(w, null, 2);
}

/** Everything but `fee` to one destination, version 2, nSequence = csv on every input. */
export function buildEscape(file, coins, destination, fee) {
  if (destination.length === 0 || destination[0] === 0x6a) fail('Destination', 'destination would burn the coins');
  if (coins.length === 0) fail('NoCoins', 'no coins to spend, or their values overflow');
  const total = coins.reduce((sum, c) => sum + c.value, 0);
  if (!Number.isSafeInteger(total)) fail('NoCoins', 'no coins to spend, or their values overflow');
  const send = total - fee;
  if (!Number.isSafeInteger(fee) || fee < 0 || send < DUST_LIMIT) fail('Fee', 'fee leaves too little to send');
  const tx = makeTx(coins, file.csv, [{ value: send, spk: destination }]);
  tx.inputs.forEach((input, i) => {
    const digest = sighash(tx, i, file.script, coins[i].value);
    const sig = secp256k1.sign(digest, file.cold, { lowS: true, prehash: false });
    input.witness = [derSig(sig.toCompactRawBytes()), new Uint8Array(0), file.script];
  });
  return tx;
}

/** A UTXO list as the contract's `Utxo` or an esplora `/utxo` answer has it. Extra fields are ignored. */
export function parseUtxos(text) {
  let list;
  try {
    list = JSON.parse(text);
  } catch {
    throw new Error('UTXO list is not JSON');
  }
  if (!Array.isArray(list) || list.length === 0) throw new Error('UTXO list is empty');
  const seen = new Set();
  return list.map((c, i) => {
    if (typeof c?.txid !== 'string' || !/^[0-9a-f]{64}$/.test(c.txid)) throw new Error(`UTXO ${i}: bad txid`);
    if (!Number.isInteger(c.vout) || c.vout < 0 || c.vout > 0xffffffff) throw new Error(`UTXO ${i}: bad vout`);
    if (!Number.isSafeInteger(c.value) || c.value <= 0) throw new Error(`UTXO ${i}: bad value`);
    const key = `${c.txid}:${c.vout}`;
    if (seen.has(key)) throw new Error(`UTXO ${i}: listed twice`);
    seen.add(key);
    return { txid: c.txid, vout: c.vout, value: c.value, confirmations: Number.isInteger(c.confirmations) ? c.confirmations : undefined };
  });
}

export { addressToSpk, witnessScript };
