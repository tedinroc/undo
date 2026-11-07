#!/usr/bin/env node
// Sends one signed cancel from your own NEAR testnet account, with no relay. The contract checks the passkey or the
// cold key, never who sends the call, so any account can. The file is one of:
//
//   - what the phone page saves when its relay will not send a cancel (format undo-owner-call-v1): `cancel` or
//     `cancel_all_and_rotate`, signed by the vault's passkey on the phone;
//   - what tools/freeze.mjs --method cancel writes (format undo-cold-intent-v1), signed by the cold key.
//
// Neither holds a secret. This sends the file's arguments as they are, to the contract the file names, with 30 Tgas
// and no deposit, and only those two methods.
//
//   node tools/cancel.mjs --file FILE --account ACCOUNT [--key-file FILE] [--rpc URL[,URL...]] [--yes]
//
// The key is ACCOUNT's own: --key-file, or near-cli's legacy file for ACCOUNT under ~/.near-credentials/testnet. It
// never leaves this process and is never printed. It reads the chain first and refuses mainnet, a vault the contract
// does not hold, a request already gone, a rotation whose nonce was used, and a signed call past its expiry.
//
// Exit 0: the contract took it. 1: refused, or answered no. 2: bad usage.
import { readFileSync } from 'node:fs';
import { askYes, parseArgs, UsageError } from './lib/args.mjs';
import { action, failureOf, loadCredentials, loadKeyFile, Near, TGAS } from './lib/near.mjs';
import { OWNER_ATTACH_TGAS } from './lib/vault-client.mjs';
import { TESTNET_RPC } from './lib/watch.mjs';
import { relayBodyProblem } from '../site/lib/relay-table.mjs';

const USAGE = 'usage: cancel.mjs --file FILE --account ACCOUNT [--key-file FILE] [--rpc URL[,URL...]] [--yes]';
const FORMATS = { 'undo-owner-call-v1': ['cancel', 'cancel_all_and_rotate'], 'undo-cold-intent-v1': ['cancel'] };
const ACCOUNT_ID = /^(?=.{2,64}$)([a-z0-9]+[-_])*[a-z0-9]+(\.([a-z0-9]+[-_])*[a-z0-9]+)*$/;

class Refused extends Error {}

/** The call in the file, checked against the relay's own table: a body it could not parse, the contract cannot either. */
function readCall(text) {
  let file;
  try {
    file = JSON.parse(text);
  } catch {
    throw new Refused('the file is not JSON');
  }
  const methods = FORMATS[file?.format];
  if (!methods) throw new Refused('the file is not a signed cancel: its format is neither undo-owner-call-v1 nor undo-cold-intent-v1');
  if (!methods.includes(file.method)) throw new Refused(`this tool sends only ${methods.join(' or ')} from a file of this format`);
  if (typeof file.contract !== 'string' || !ACCOUNT_ID.test(file.contract)) throw new Refused('the file names no contract account');
  if (relayBodyProblem({ method: file.method, args: file.args })) throw new Refused(`the file's ${file.method} arguments are not the shape the contract takes`);
  return { contract: file.contract, method: file.method, args: file.args };
}

async function run() {
  const a = parseArgs(process.argv.slice(2), { file: 'text', account: 'text', 'key-file': 'text', rpc: 'text', yes: 'flag' });
  if (!a.file || !a.account) throw new UsageError(USAGE);
  if (!ACCOUNT_ID.test(a.account)) throw new UsageError('--account must be a NEAR account id');
  let text;
  try {
    text = readFileSync(a.file, 'utf8');
  } catch (err) {
    throw new Refused(`cannot read the file: ${err.code ?? 'error'}`);
  }
  const call = readCall(text);
  const urls = a.rpc ? a.rpc.split(',').map((u) => u.trim()).filter(Boolean) : [...TESTNET_RPC];
  const near = new Near(urls, { timeoutMs: 20_000 });

  const status = await near.status();
  if (status.chain_id === 'mainnet') throw new Refused('that RPC is NEAR mainnet. This tool is for test coins only');
  const [vault, now] = await Promise.all([near.view(call.contract, 'vault', { vault: call.args.vault }), near.nowMs()]);
  if (vault === null) throw new Refused(`${call.contract} holds no vault ${call.args.vault}`);
  if (call.args.expires_at < now) throw new Refused(`this signed ${call.method} expired at ${new Date(call.args.expires_at).toISOString()}. Sign a new one`);
  // A used nonce is refused here, so a body already sent does not cost your account a second transaction.
  if (call.method === 'cancel_all_and_rotate' && call.args.nonce < vault.passkey_nonce) {
    throw new Refused(`this rotation's passkey nonce ${call.args.nonce} was used already (the vault reads ${vault.passkey_nonce}). Sign a new one`);
  }
  let request = null;
  if (call.method === 'cancel') {
    request = await near.view(call.contract, 'request', { vault: call.args.vault, request: call.args.request });
    if (request === null) throw new Refused(`request ${call.args.request} is gone: there is nothing left to cancel`);
  }

  console.log('You are about to send, from your own account:');
  const shown = [
    ['network', status.chain_id ?? 'unknown'], ['from', a.account], ['contract', call.contract], ['vault', call.args.vault], ['method', call.method],
    call.method === 'cancel' ? ['request', `${call.args.request} (${request.status ?? 'unknown'})`] : ['passkey nonce', `${call.args.nonce} (the vault reads ${vault.passkey_nonce})`],
    ['signed by', call.method === 'cancel' && call.args.auth.Cold ? 'the cold key' : 'the passkey'],
    ['expires', new Date(call.args.expires_at).toISOString()], ['gas', `${OWNER_ATTACH_TGAS} Tgas, no deposit`],
  ];
  for (const [k, v] of shown) console.log(`  ${k.padEnd(14)}${v}`);
  if (!a.yes && !(await askYes('Type yes to send:'))) {
    console.log('Nothing sent.');
    process.exit(1);
  }

  let key;
  try {
    key = a['key-file'] ? loadKeyFile(a['key-file']) : loadCredentials('testnet', a.account);
  } catch (err) {
    throw new Refused(`no key for ${a.account}: ${err.code ?? err.message}`);
  }
  if (key.accountId && key.accountId !== a.account) throw new Refused(`that key file is for another account, not ${a.account}`);
  const sent = await near.sendAndWait({ ...key, accountId: a.account }, call.contract, [action.call(call.method, call.args, OWNER_ATTACH_TGAS * TGAS, 0n)]);
  const failure = failureOf(sent.result);
  if (failure) {
    console.log(`Sent, and the contract refused it. NEAR tx ${sent.hash}`);
    console.log(`The contract said: ${failure}`);
    process.exit(1);
  }
  console.log(`Sent. The contract took it. NEAR tx ${sent.hash}`);
  if (call.method === 'cancel') {
    const after = await near.view(call.contract, 'request', { vault: call.args.vault, request: call.args.request }).catch(() => undefined);
    if (after === null) console.log(`Request ${call.args.request} is gone.`);
  } else {
    const after = await near.view(call.contract, 'vault', { vault: call.args.vault }).catch(() => null);
    if (after) console.log(`The rotation landed: the vault's passkey nonce reads ${after.passkey_nonce}, and every request that was still Pending is dead.`);
  }
}

run().catch((err) => {
  if (err instanceof UsageError) {
    console.error(err.message);
    process.exit(2);
  }
  console.error(`cancel refused: ${err.message}`);
  process.exit(1);
});
