#!/usr/bin/env node
// Makes the two Bitcoin keys the human scripts need. Called by scripts/human/02 and 03. Prints
// addresses, never secrets. Never overwrites a key: a replaced key is lost coins.
//
//   node tools/human-key.mjs dispenser --file FILE    Mutinynet test key, in a file, for unattended use
//   node tools/human-key.mjs funding                  Bitcoin mainnet key, in the macOS Keychain
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { p2wpkhAddress } from './lib/btc.mjs';
import { fixedHex, toHex } from './lib/bytes.mjs';
import { randomBytes, secp256k1 } from './lib/crypto.mjs';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const SERVICE = 'undo-funding-key';
const ACCOUNT = 'bitcoin-mainnet';

function addressOf(network, secret) {
  if (!secp256k1.utils.isValidPrivateKey(secret)) throw new Error('secret is out of range');
  return p2wpkhAddress(network, secp256k1.getPublicKey(secret, true));
}

function refuseInsideRepo(path) {
  const parent = resolve(dirname(path));
  const real = existsSync(parent) ? realpathSync(parent) : parent;
  if (real === realpathSync(REPO) || real.startsWith(`${realpathSync(REPO)}${sep}`)) throw new Error('keys never live inside the repo');
}

function dispenser(path) {
  refuseInsideRepo(path);
  if (existsSync(path)) {
    const data = JSON.parse(readFileSync(path, 'utf8'));
    return { address: addressOf('mutinynet', fixedHex(data.secret, 32, 'key file')), created: false };
  }
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const secret = randomBytes(32);
  const address = addressOf('mutinynet', secret);
  // wx: fail if the file appeared meanwhile, rather than replace it.
  writeFileSync(path, `${JSON.stringify({ format: 'undo-dispenser-v1', network: 'mutinynet', secret: toHex(secret), address }, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  return { address, created: true };
}

function keychainRead() {
  const r = spawnSync('security', ['find-generic-password', '-s', SERVICE, '-a', ACCOUNT, '-w'], { encoding: 'utf8' });
  return r.status === 0 ? r.stdout.trim() : null;
}

function funding() {
  const existing = keychainRead();
  if (existing) return { address: addressOf('mainnet', fixedHex(existing, 32, 'keychain item')), created: false };
  const secret = randomBytes(32);
  const address = addressOf('mainnet', secret);
  // Over stdin, because a command-line argument is visible to every process on the machine.
  const added = spawnSync('security', ['-i'], {
    input: `add-generic-password -s ${SERVICE} -a ${ACCOUNT} -w ${toHex(secret)}\n`,
    encoding: 'utf8',
  });
  if (added.error) throw new Error('could not run security');
  // Its exit code does not report a failed inner command, so read the item back. No address is
  // shown until the key that gives it can be retrieved: coins sent to anything else would be lost.
  const back = keychainRead();
  if (!back || addressOf('mainnet', fixedHex(back, 32, 'keychain item')) !== address) throw new Error('the Keychain did not keep the key. Nothing to fund');
  return { address, created: true };
}

try {
  const [command, flag, value] = process.argv.slice(2);
  let result;
  if (command === 'dispenser' && flag === '--file' && value) result = dispenser(value);
  else if (command === 'funding' && !flag) result = funding();
  else {
    console.error('usage: human-key.mjs dispenser --file FILE | funding');
    process.exit(2);
  }
  console.log(result.created ? 'Created a new key.' : 'Key already there, not changed.');
  console.log(`ADDRESS ${result.address}`);
} catch (err) {
  console.error(`refused: ${err.message}`);
  process.exit(1);
}
