#!/usr/bin/env node
// Called by 30-secrets.sh. Hands each value to `wrangler … secret put NAME` on its stdin, so a value is never an
// argument (a process listing would show it) and never echoed. Whatever wrangler prints is searched for every value
// before it is shown, and a value found is replaced, so even a wrangler that echoed would print nothing secret.
//
//   node secrets-put.mjs --target worker|pages --secrets FILE [--dispenser FILE] [--canary VAULT] (--dry-run | --live)
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs, UsageError } from '../../tools/lib/args.mjs';
import { parseDispenser } from '../../tools/lib/dispenser.mjs';
import { modeIsPrivate, Refused, REPO } from './lib.mjs';
import { loadSecretsFile } from './20-relay-keys.mjs';

const USAGE = 'usage: secrets-put.mjs --target worker|pages --secrets FILE [--dispenser FILE] [--canary VAULT] (--dry-run | --live)';
export const PROJECT = 'undo-btc';

/** Which names each deployable needs, in the order they are set. What its deploy script checks for, and more. */
export const NAMES = Object.freeze({
  worker: ['CONTRACT_ID', 'RELAY_ACCOUNT', 'RELAY_CRON_KEY'],
  pages: ['CONTRACT_ID', 'RELAY_ACCOUNT', 'RELAY_GENERAL_KEY', 'RELAY_OWNER_KEY', 'DISPENSER_SECRET', 'IP_SALT', 'BEAT_TOKEN'],
});

/** name -> { value, from }. Values live in this map and in wrangler's stdin, nowhere else. */
export function valuesFor(target, { secrets, dispenserPath, canary }) {
  const file = loadSecretsFile(secrets);
  const out = new Map();
  const put = (name, value, from) => out.set(name, { value, from });
  put('CONTRACT_ID', file.contract, 'the secrets file');
  put('RELAY_ACCOUNT', file.relay_account, 'the secrets file');
  if (target === 'worker') {
    put('RELAY_CRON_KEY', file.keys.RELAY_CRON_KEY.secret_key, 'the secrets file');
    if (canary) {
      if (!/^[0-9a-f]{64}$/.test(canary)) throw new Refused('--canary is a vault id, 64 hex');
      put('CANARY_VAULT', canary, '--canary');
    }
  } else {
    put('RELAY_GENERAL_KEY', file.keys.RELAY_GENERAL_KEY.secret_key, 'the secrets file');
    put('RELAY_OWNER_KEY', file.keys.RELAY_OWNER_KEY.secret_key, 'the secrets file');
    if (!dispenserPath) throw new Refused('the Pages project needs --dispenser FILE for DISPENSER_SECRET');
    if (!modeIsPrivate(dispenserPath)) throw new Refused('the dispenser file is readable by others: chmod 600 it first');
    let dispenser;
    try {
      dispenser = parseDispenser(readFileSync(dispenserPath, 'utf8'), 'mutinynet');
    } catch (err) {
      throw new Refused(`dispenser file: ${err.message}`);
    }
    put('DISPENSER_SECRET', Buffer.from(dispenser.secret).toString('hex'), `the dispenser file, address ${dispenser.address}`);
    put('IP_SALT', file.values.IP_SALT, 'the secrets file');
    put('BEAT_TOKEN', file.values.BEAT_TOKEN, 'the secrets file');
  }
  return out;
}

export function redact(text, values) {
  let out = text;
  for (const { value } of values.values()) {
    if (value.length >= 8) out = out.split(value).join('<redacted>');
  }
  return out;
}

const wranglerCmd = () => process.env.WRANGLER;

function run(target, args, { input = '' } = {}) {
  const cwd = target === 'worker' ? join(REPO, 'worker', 'undo-cron') : join(REPO, 'site');
  // WRANGLER may be a command with arguments, as the deploy scripts allow, so it goes through sh. The names and
  // flags after it are fixed strings from this file; no value is ever on this line.
  return spawnSync('/bin/sh', ['-c', `${wranglerCmd()} ${args}`], { cwd, input, encoding: 'utf8', env: process.env });
}

function main() {
  const a = parseArgs(process.argv.slice(2), { target: 'text', secrets: 'text', dispenser: 'text', canary: 'text', 'dry-run': 'flag', live: 'flag' });
  if (!['worker', 'pages'].includes(a.target) || !a.secrets || Boolean(a['dry-run']) === Boolean(a.live)) throw new UsageError(USAGE);
  const values = valuesFor(a.target, { secrets: a.secrets, dispenserPath: a.dispenser, canary: a.canary });
  const where = a.target === 'worker' ? 'Worker undo-cron' : `Pages project ${PROJECT}`;
  const put = (name) => (a.target === 'worker' ? `secret put ${name}` : `pages secret put ${name} --project-name ${PROJECT}`);
  for (const [name, { value, from }] of values) {
    console.log(`PLAN ${where}: ${put(name)}   <- ${value.length} characters on stdin, from ${from}`);
  }
  if (!a.live) {
    console.log(`DRY RUN: no secret set on the ${where}.`);
    return 0;
  }
  if (!wranglerCmd()) throw new Refused('WRANGLER is not set: run this through 30-secrets.sh');
  let failed = 0;
  for (const [name, { value }] of values) {
    const out = run(a.target, put(name), { input: value });
    const said = redact(`${out.stdout ?? ''}${out.stderr ?? ''}`, values).trim().split('\n').slice(-3).join(' | ');
    if (out.status === 0) console.log(`SET  [live-cloudflare] ${where}: ${name}`);
    else {
      failed += 1;
      console.log(`FAIL [live-cloudflare] ${where}: ${name}, wrangler said: ${said}`);
    }
  }
  const listed = run(a.target, a.target === 'worker' ? 'secret list' : `pages secret list --project-name ${PROJECT}`);
  const text = redact(`${listed.stdout ?? ''}`, values);
  for (const name of values.keys()) {
    const there = text.includes(name);
    if (!there) failed += 1;
    console.log(`${there ? 'PASS' : 'FAIL'} [live-cloudflare] ${where} lists ${name}`);
  }
  return failed ? 1 : 0;
}

if (process.argv[1]?.endsWith('secrets-put.mjs')) {
  try {
    process.exitCode = main();
  } catch (err) {
    if (err instanceof UsageError) {
      console.error(err.message);
      process.exitCode = 2;
    } else if (err instanceof Refused) {
      console.error(`REFUSED: ${err.message}`);
      process.exitCode = 3;
    } else {
      console.error(`ERROR: ${err.message}`);
      process.exitCode = 1;
    }
  }
}
