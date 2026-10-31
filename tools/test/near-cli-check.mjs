#!/usr/bin/env node
// Checks every near-cli command the plan and the scripts use against the binary's own --help, one
// token at a time. Runs under a macOS sandbox with the network denied and a throwaway HOME, so it
// cannot write to any chain and cannot touch the real near-cli config.
//
//   UNDO_NEAR_BIN=near node tools/test/near-cli-check.mjs [FILE]
//
// FILE is extra commands, one JSON array of strings per line, for example what the human scripts
// really ran under a shim. Exit 0 when all pass. A pass means near-cli 0.30.1 parses the command. It
// says nothing about what the command does when run for real.
import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const BIN = process.env.UNDO_NEAR_BIN;
if (!BIN) throw new Error('set UNDO_NEAR_BIN');
const HOME = mkdtempSync(join(tmpdir(), 'near-cli-home-'));
const NETWORKLESS = '(version 1)(allow default)(deny network*)';
const FOLDER = '/tmp/undo-placeholder-folder';
const WASM = 'undo_vault.wasm';
const INIT = '{"preset":"TestCoin"}';
const KEY_FILE = 'deployer.json';
const PUBKEY = 'ed25519:6E8sCci9badyRkXb3JoRpBj5p8C6Tw41ELDZoiihKEtp';

const COMMANDS = [
  ['testnet account', ...'account create-account sponsor-by-faucet-service undo-btc.testnet autogenerate-new-keypair save-to-legacy-keychain network-config testnet create'.split(' ')],
  ['testnet account', ...'account create-account sponsor-by-faucet-service undo-relay.testnet autogenerate-new-keypair save-to-legacy-keychain network-config testnet create'.split(' ')],
  ['testnet account', ...'account create-account sponsor-by-faucet-service undo-guard.testnet autogenerate-new-keypair save-to-legacy-keychain network-config testnet create'.split(' ')],
  ['testnet account', ...'account view-account-summary undo-btc.testnet network-config testnet now'.split(' ')],
  ['human step, human/03', 'account', 'create-account', 'fund-later', 'use-auto-generation', 'save-to-folder', FOLDER],
  ['earlier run', ...'account create-account sponsor-by-faucet-service undo-g0-replace.testnet autogenerate-new-keypair save-to-keychain network-config testnet create'.split(' ')],
  ['earlier run, deploy', 'contract', 'deploy', 'undo-g0-replace.testnet', 'use-file', WASM, 'with-init-call', 'new', 'json-args', INIT, 'prepaid-gas', '100 TGas', 'attached-deposit', '0 NEAR', 'network-config', 'testnet', 'sign-with-keychain', 'send'],
  ['step B1, deploy with the legacy key', 'contract', 'deploy', 'undo-btc.testnet', 'use-file', WASM, 'with-init-call', 'new', 'json-args', INIT, 'prepaid-gas', '100 TGas', 'attached-deposit', '0 NEAR', 'network-config', 'testnet', 'sign-with-legacy-keychain', 'send'],
  ['human step, deployer signs from its file', 'contract', 'deploy', 'undo-btc.near', 'use-file', WASM, 'with-init-call', 'new', 'json-args', INIT, 'prepaid-gas', '100 TGas', 'attached-deposit', '0 NEAR', 'network-config', 'mainnet', 'sign-with-access-key-file', KEY_FILE, 'send'],
  ['PLAN 10 and 14, list keys', ...'account list-keys undo-btc.testnet network-config testnet now'.split(' ')],
  ['human step, delete the full-access key', 'account', 'delete-keys', 'undo-btc.testnet', 'public-keys', PUBKEY, 'network-config', 'testnet', 'sign-with-legacy-keychain', 'send'],
  ['relay of a signed intent', 'contract', 'call-function', 'as-transaction', 'undo-btc.testnet', 'cancel', 'json-args', '{}', 'prepaid-gas', '40 Tgas', 'attached-deposit', '0 NEAR', 'sign-as', 'undo-relay.testnet', 'network-config', 'testnet', 'sign-with-legacy-keychain', 'send'],
  ['read a view', 'contract', 'call-function', 'as-read-only', 'undo-btc.testnet', 'instance', 'json-args', '{}', 'network-config', 'testnet', 'now'],
];

function help(tokens) {
  const r = spawnSync('sandbox-exec', ['-p', NETWORKLESS, BIN, ...tokens, '--help'], {
    encoding: 'utf8',
    env: { HOME, PATH: '/usr/bin:/bin' },
    input: '',
    timeout: 20000,
  });
  return { status: r.status, text: `${r.stdout ?? ''}${r.stderr ?? ''}` };
}

function section(text, name) {
  const lines = text.split('\n');
  const start = lines.findIndex((l) => l.trim() === `${name}:`);
  if (start < 0) return [];
  const out = [];
  for (let i = start + 1; i < lines.length; i += 1) {
    const line = lines[i];
    if (/^\S/.test(line)) break;
    if (/^ {2}\S/.test(line)) out.push(line.trim().split(/\s+/)[0]);
  }
  return out;
}

function check(tokens) {
  const trail = [];
  for (let i = 0; i < tokens.length; i += 1) {
    const here = help(tokens.slice(0, i));
    if (here.status !== 0) return { ok: false, why: `--help failed after: ${tokens.slice(0, i).join(' ')}` };
    const token = tokens[i];
    const commands = section(here.text, 'Commands');
    const args = section(here.text, 'Arguments');
    if (commands.includes(token)) {
      trail.push('cmd');
    } else if (args.length > 0) {
      trail.push('arg');
    } else {
      return { ok: false, why: `"${token}" is not offered after "${tokens.slice(0, i).join(' ')}". Offered: ${commands.join(', ') || 'nothing'}` };
    }
  }
  const last = help(tokens);
  if (last.status !== 0) return { ok: false, why: 'the whole command does not parse' };
  return { ok: true, trail };
}

const extra = process.argv[2] && existsSync(process.argv[2])
  ? readFileSync(process.argv[2], 'utf8').split('\n').filter(Boolean).map((l) => ['ran under the shim in tools/test/human-scripts.test.mjs', ...JSON.parse(l)])
  : [];
const canSandbox = spawnSync('sandbox-exec', ['-p', NETWORKLESS, '/usr/bin/true']).status === 0;
if (!canSandbox) {
  console.log('NOT CHECKED: sandbox-exec is not available here, and this check does not run without the network denied.');
  process.exit(2);
}
const denied = spawnSync('sandbox-exec', ['-p', NETWORKLESS, '/usr/bin/curl', '-s', '-m', '5', 'https://example.com'], { encoding: 'utf8' });
if (denied.status === 0) {
  console.log('NOT CHECKED: the sandbox did not stop a network call.');
  process.exit(2);
}
console.log('network really denied: a control curl failed under the same sandbox');
const version = spawnSync('sandbox-exec', ['-p', NETWORKLESS, BIN, '--version'], { encoding: 'utf8', env: { HOME, PATH: '/usr/bin:/bin' } });
console.log(`binary: ${(version.stdout.match(/near-cli-rs [0-9.]+/) ?? ['unknown'])[0]}`);

// Controls: a checker that cannot say no proves nothing.
for (const tokens of [
  'account create-account sponsor-by-faucet-service x.testnet autogenerate-new-keypair save-to-nowhere network-config testnet create'.split(' '),
  'account view-account-summary x.testnet network-config testnet never'.split(' '),
  'account create-account sponsor-by-faucet-service UPPER.testnet autogenerate-new-keypair save-to-legacy-keychain network-config testnet create'.split(' '),
  'contract deploy x.testnet use-file a.wasm with-init-call new json-args {} prepaid-gas 100 attached-deposit 0 network-config testnet sign-with-legacy-keychain send'.split(' '),
]) {
  if (check(tokens).ok) {
    console.log(`NOT CHECKED: control passed when it must fail: ${tokens.join(' ')}`);
    process.exit(2);
  }
}
console.log('controls: four wrong commands were refused');

let bad = 0;
for (const [where, ...tokens] of [...COMMANDS, ...extra]) {
  const result = check(tokens);
  console.log(`${result.ok ? 'OK  ' : 'FAIL'} near ${tokens.join(' ').replaceAll(INIT, "'...'")}   [${where}]${result.ok ? '' : `\n     ${result.why}`}`);
  if (!result.ok) bad += 1;
}
rmSync(HOME, { recursive: true, force: true });
console.log(bad ? `${bad} commands failed` : `all ${COMMANDS.length + extra.length} commands parse`);
process.exit(bad ? 1 : 0);
