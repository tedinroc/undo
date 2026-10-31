#!/usr/bin/env node
// Signs one cold-key intent offline and writes it to a file that any device can relay.
//
//   node tools/freeze.mjs --recovery FILE --contract ACCOUNT --vault HEX --method freeze \
//        --minutes N --nonce N --out FILE [--expires-in-minutes N] [--yes]
//
// Methods: freeze (--minutes or --until-ms), unfreeze, veto_grant (--grant), cancel (--request).
// cancel takes no --nonce, so it cannot go stale in a crisis. The others need the vault's current
// cold nonce, which the vault view shows, because this tool stays offline.
//
// It builds the digest from the fields it displays, and takes no digest from anyone. It signs with a
// key derived from the cold secret, never the leaf key that spends on Bitcoin. The longest freeze is
// the CSV period, counted from when you sign. The contract checks again when the intent lands.
//
// Exit 0: wrote the intent. 1: refused or answered no. 2: bad usage.
import { readFileSync, realpathSync, writeFileSync, existsSync } from 'node:fs';
import { parseArgs, UsageError, askYes } from './lib/args.mjs';
import { COLD_METHODS, signColdIntent } from './lib/cold-intent.mjs';
import { parseRecovery } from './lib/recovery.mjs';

const USAGE = 'usage: freeze.mjs --recovery FILE --contract ACCOUNT --vault HEX --method freeze|unfreeze|veto_grant|cancel --out FILE [--minutes N | --until-ms N] [--grant N] [--request N] [--nonce N] [--expires-in-minutes N] [--now-ms N] [--yes]';
// Same block intervals as undo-core's Fixed presets.
const BLOCK_MS = { mainnet: 600_000, mutinynet: 30_000, signet: 600_000, testnet4: 600_000, regtest: 600_000 };
const DEFAULT_EXPIRY_MIN = 60;

async function run() {
  const raw = process.argv.slice(2);
  if (raw.includes('--digest')) throw new Error('this tool never signs a digest handed to it. Give it the fields');
  const a = parseArgs(raw, {
    recovery: 'text', contract: 'text', vault: 'text', method: 'text', out: 'text', minutes: 'int', 'until-ms': 'int',
    grant: 'int', request: 'int', nonce: 'int', 'expires-in-minutes': 'int', 'now-ms': 'int', yes: 'flag',
  });
  if (!a.recovery || !a.contract || !a.method || !a.out) throw new UsageError(USAGE);
  if (!COLD_METHODS.includes(a.method)) throw new UsageError(USAGE);
  if (existsSync(a.out) && realpathSync(a.out) === realpathSync(a.recovery)) throw new Error('--out would overwrite the recovery file');

  const file = parseRecovery(readFileSync(a.recovery, 'utf8'));
  const vault = a.vault ?? file.vaultId;
  if (!/^[0-9a-f]{64}$/.test(vault)) throw new Error('--vault must be the 64-character vault id');
  if (a.vault && /^[0-9a-f]{64}$/.test(file.vaultId) && a.vault !== file.vaultId) {
    throw new Error('--vault is not the vault this recovery file names');
  }

  const now = a['now-ms'] ?? Date.now();
  const expiresAt = now + (a['expires-in-minutes'] ?? DEFAULT_EXPIRY_MIN) * 60_000;
  const fields = {};
  const shown = [];
  if (a.method === 'freeze') {
    const max = now + file.csv * BLOCK_MS[file.network];
    fields.until = a['until-ms'] ?? (a.minutes !== undefined ? now + a.minutes * 60_000 : max);
    if (fields.until <= now) throw new Error('until is in the past');
    if (fields.until > max) throw new Error(`a freeze lasts at most the CSV period, ${file.csv} blocks on ${file.network}`);
    shown.push(['freeze until', `${new Date(fields.until).toISOString()} (${fields.until})`]);
  }
  if (a.method === 'veto_grant') {
    if (a.grant === undefined) throw new UsageError('veto_grant needs --grant');
    fields.grant = a.grant;
    shown.push(['grant', String(a.grant)]);
  }
  if (a.method === 'cancel') {
    if (a.request === undefined) throw new UsageError('cancel needs --request');
    if (a.nonce !== undefined) throw new UsageError('cancel takes no --nonce');
    fields.request = a.request;
    shown.push(['request', String(a.request)]);
  } else if (a.nonce === undefined) {
    throw new UsageError(`${a.method} needs --nonce, the vault's cold_nonce`);
  }

  console.log('You are about to sign with the cold key:');
  for (const [k, v] of [['contract', a.contract], ['vault', vault], ['method', a.method], ...shown, ['nonce', a.nonce === undefined ? 'none' : String(a.nonce)], ['expires', new Date(expiresAt).toISOString()]]) {
    console.log(`  ${k.padEnd(13)}${v}`);
  }
  if (!a.yes && !(await askYes('Type yes to sign:'))) {
    console.log('Nothing signed.');
    process.exit(1);
  }

  const signed = signColdIntent({ cold: file.cold, contract: a.contract, vault, method: a.method, fields, expiresAt, nonce: a.nonce });
  const callArgs = { vault, ...fields, expires_at: expiresAt };
  if (a.method === 'cancel') {
    callArgs.auth = { Cold: signed.signature };
  } else {
    callArgs.nonce = a.nonce;
    callArgs.signature = signed.signature;
  }
  const out = { format: 'undo-cold-intent-v1', contract: a.contract, method: a.method, args: callArgs, digest: signed.digest, k_e_intent: signed.k_e_intent };
  writeFileSync(a.out, `${JSON.stringify(out, null, 2)}\n`, { mode: 0o644 });
  console.log(`Signed. Anyone can relay this file. It holds no secret. Compare k_e_intent ${signed.k_e_intent} with the vault view if you can.`);
}

run().catch((err) => {
  if (err instanceof UsageError) {
    console.error(err.message);
    process.exit(2);
  }
  console.error(`freeze refused: ${err.message}`);
  process.exit(1);
});
