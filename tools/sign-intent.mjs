#!/usr/bin/env node
// The spend-key signer: turns a seed and a spend into the arguments of propose_btc or reclaim. Offline.
// It prints JSON for any relay to send. The seed stays in its file, outside the repo.
//
//   node tools/sign-intent.mjs propose_btc --contract ACCOUNT --vault-view FILE --seed-file FILE \
//        --inputs FILE --to-script HEX --amount SATS [--change SATS] --nonce N --expires-at MS
//   node tools/sign-intent.mjs reclaim --contract ACCOUNT --vault-view FILE --seed-file FILE \
//        --inputs FILE --fee SATS --nonce N --expires-at MS
//
// --vault-view is the JSON of the contract's `vault` view plus its `script` view as "script". --inputs
// is [{"txid":"...","vout":0,"value":100000}, ...]; reclaim takes exactly one.
//
// Exit 0: printed the arguments. 1: refused. 2: bad usage.
import { readFileSync } from 'node:fs';
import { parseArgs, UsageError } from './lib/args.mjs';
import { signSpend } from './lib/spend.mjs';
import { fixedHex, fromHex } from './lib/bytes.mjs';
import { parseUtxos } from './lib/recovery.mjs';

function run() {
  const [method, ...rest] = process.argv.slice(2);
  if (method !== 'propose_btc' && method !== 'reclaim') throw new UsageError('usage: sign-intent.mjs propose_btc|reclaim --contract ... (see the file header)');
  const a = parseArgs(rest, {
    contract: 'text', 'vault-view': 'text', 'seed-file': 'text', inputs: 'text', 'to-script': 'text', amount: 'int', change: 'int', fee: 'int', nonce: 'int', 'expires-at': 'int',
  });
  for (const need of ['contract', 'vault-view', 'seed-file', 'inputs', 'nonce', 'expires-at']) {
    if (a[need] === undefined) throw new UsageError(`missing --${need}`);
  }
  const view = JSON.parse(readFileSync(a['vault-view'], 'utf8'));
  const seed = fixedHex(readFileSync(a['seed-file'], 'utf8').trim(), 32, 'seed file');
  const inputs = parseUtxos(readFileSync(a.inputs, 'utf8'));
  const script = fromHex(view.script, 'script');
  const spk = fromHex(view.script_pubkey, 'script_pubkey');
  const vault = fixedHex(view.id, 32, 'vault id');
  const common = { seed, contract: a.contract, vault, script, spk, inputs, nonce: a.nonce, expiresAt: a['expires-at'] };

  let out;
  if (method === 'propose_btc') {
    if (!a['to-script'] || a.amount === undefined) throw new UsageError('propose_btc needs --to-script and --amount');
    out = signSpend.propose({ ...common, to: fromHex(a['to-script'], '--to-script'), amount: a.amount, change: a.change ?? null });
  } else {
    if (a.fee === undefined) throw new UsageError('reclaim needs --fee');
    out = signSpend.reclaim({ ...common, fee: a.fee });
  }
  // The key that signed is public. Show it so a wrong seed file is visible before anything is sent.
  if (out.signer !== view.k_s) throw new Error('this seed does not hold the vault\'s spend key');
  console.log(JSON.stringify({ method, args: out.args }, null, 2));
}

try {
  run();
} catch (err) {
  if (err instanceof UsageError) {
    console.error(err.message);
    process.exit(2);
  }
  console.error(`sign-intent refused: ${err.message}`);
  process.exit(1);
}

