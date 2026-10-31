#!/usr/bin/env node
// The way out when NEAR, the contract or the signer is gone. Offline: reads the recovery file and a
// UTXO list, prints a signed transaction, and touches no network. Any node or block explorer can
// broadcast the result.
//
//   node tools/escape.mjs --recovery FILE --utxos FILE --to ADDRESS --fee SATS [--out FILE]
//
// --utxos is JSON: [{"txid":"...","vout":0,"value":100000}, ...]. An esplora /address/<a>/utxo answer
// works as it is. --to-script HEX replaces --to for a raw output script.
//
// A coin younger than the CSV gives a transaction nodes refuse as not final. It cannot leave early,
// and the signature stays good for when it can. This tool cannot see a coin's age or check that a
// coin exists: a wrong value gives a signature consensus refuses.
//
// Exit 0: printed a transaction. 1: refused. 2: bad usage.
import { readFileSync, writeFileSync } from 'node:fs';
import { parseArgs, UsageError } from './lib/args.mjs';
import { serialize, txid, vsize, addressToSpk } from './lib/btc.mjs';
import { fromHex, toHex } from './lib/bytes.mjs';
import { buildEscape, parseRecovery, parseUtxos, RecoveryError } from './lib/recovery.mjs';

const USAGE = 'usage: escape.mjs --recovery FILE --utxos FILE (--to ADDRESS | --to-script HEX) --fee SATS [--out FILE] [--allow-high-fee]';
// A typo in --fee is the likeliest way to lose coins here, so a large one must be asked for.
const HIGH_FEE_PERCENT = 5;

function run() {
  const a = parseArgs(process.argv.slice(2), { recovery: 'text', utxos: 'text', to: 'text', 'to-script': 'text', fee: 'int', out: 'text', 'allow-high-fee': 'flag' });
  if (!a.recovery || !a.utxos || a.fee === undefined || Boolean(a.to) === Boolean(a['to-script'])) throw new UsageError(USAGE);

  const file = parseRecovery(readFileSync(a.recovery, 'utf8'));
  const coins = parseUtxos(readFileSync(a.utxos, 'utf8'));
  let destination;
  try {
    destination = a.to ? addressToSpk(file.network, a.to) : fromHex(a['to-script'], '--to-script');
  } catch (err) {
    throw new Error(`destination refused on ${file.network}: ${err.message}`);
  }

  const total = coins.reduce((sum, c) => sum + c.value, 0);
  if (a.fee * 100 > total * HIGH_FEE_PERCENT && !a['allow-high-fee']) {
    throw new Error(`fee is above ${HIGH_FEE_PERCENT}% of the coins. Check it, then pass --allow-high-fee if you mean it`);
  }

  const tx = buildEscape(file, coins, destination, a.fee);
  const raw = toHex(serialize(tx));
  const size = vsize(tx);
  if (a.out) writeFileSync(a.out, `${raw}\n`, { mode: 0o644 });

  console.log(`network      ${file.network}`);
  console.log(`vault        ${file.address}`);
  console.log(`coins        ${coins.length}, ${total} sats declared`);
  console.log(`sends        ${total - a.fee} sats`);
  console.log(`fee          ${a.fee} sats, ${(a.fee / size).toFixed(2)} sat/vB at ${size} vB`);
  console.log(`csv          ${file.csv} blocks`);
  console.log(`txid         ${txid(tx)}`);
  for (const c of coins) {
    if (c.confirmations !== undefined && c.confirmations < file.csv) {
      console.log(`too young    ${c.txid}:${c.vout} has ${c.confirmations} of ${file.csv} confirmations. Nodes refuse this transaction until it matures.`);
    }
  }
  if (a.fee < size) console.log('low fee      under 1 sat/vB. Nodes may not relay this.');
  console.log('not checked  coin existence, coin age, real values. Those need a node.');
  console.log(a.out ? 'written      to --out' : `hex          ${raw}`);
}

try {
  run();
} catch (err) {
  if (err instanceof UsageError) {
    console.error(err.message);
    process.exit(2);
  }
  // RecoveryError text comes from a fixed list and quotes nothing from the file. Anything else is
  // reduced to its message, never a stack with arguments.
  console.error(`escape refused: ${err instanceof RecoveryError ? err.message : err.message}`);
  process.exit(1);
}
