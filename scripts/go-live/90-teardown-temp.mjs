#!/usr/bin/env node
// Step 90. Deletes a temporary instance's account, and its whole balance (the code's storage included) goes back to
// the deployer. Only an instance 10-deploy-instance.mjs made with --temp: the name must start with tmp-, sit under
// the deployer, be in the private instance record as temporary, and not be the contract the site's config names.
//
//   node scripts/go-live/90-teardown-temp.mjs --dry-run --name tmp-20261107-1000
//   node scripts/go-live/90-teardown-temp.mjs --live    --name tmp-20261107-1000 [--relay-keys FILE]
//
// --relay-keys FILE also deletes, from the relay account, the three keys 20-relay-keys.mjs made for this instance.
// The function-call keys can call nothing once the contract is gone. The general key is full access, so delete it
// only after the Pages secrets name the new keys (step 30 for the real instance), or the relay stops.
//
// Vault coins on Mutinynet do not depend on this account: each vault's cold key leaves after its timelock. The
// signer derives K_m from this account's name, so a vault of a deleted instance has only that exit left.
// Exit 0: deleted and read back gone. 1: a readback failed. 2: usage. 3: refused before any write.
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs, UsageError } from '../../tools/lib/args.mjs';
import { failureOf, action, parseSecretKey } from '../../tools/lib/near.mjs';
import {
  accessKey, connect, deleteAccountAction, ownFailure, describe, formatNear, line, modeOf, note, plan, planTx, privateDir, readJson, Refused, REPO,
  signingKey, TEMP_PREFIX,
} from './lib.mjs';
import { loadSecretsFile } from './20-relay-keys.mjs';

const USAGE = `usage: 90-teardown-temp.mjs (--dry-run | --live) --name ${TEMP_PREFIX}LABEL [--parent ACCOUNT] [--beneficiary ACCOUNT]
  [--relay-keys FILE] [--record FILE] [--config FILE] [--network testnet|sandbox] [--rpc URL] [--offline]`;

async function main() {
  const a = parseArgs(process.argv.slice(2), {
    'dry-run': 'flag', live: 'flag', network: 'text', rpc: 'text', name: 'text', parent: 'text', beneficiary: 'text',
    'relay-keys': 'text', record: 'text', config: 'text', offline: 'flag',
  });
  const { network, live, defaults } = modeOf(a, USAGE);
  if (live && a.offline) throw new Refused('--offline is for a dry run');
  const parent = a.parent ?? defaults.parent;
  if (!parent) throw new Refused('--network sandbox needs --parent');
  if (!a.name || !a.name.startsWith(TEMP_PREFIX) || a.name.includes('.')) throw new Refused(`--name is the label of a temporary instance, starting with ${TEMP_PREFIX}`);
  const account = `${a.name}.${parent}`;
  const beneficiary = a.beneficiary ?? parent;
  const label = defaults.label;

  // The record 10-deploy-instance.mjs wrote: this must be an instance it made as temporary.
  const recordPath = a.record ?? join(privateDir(), 'instances.json');
  if (!existsSync(recordPath)) throw new Refused(`no instance record at ${recordPath}: only an instance 10-deploy-instance.mjs recorded can be torn down`);
  const entry = readJson(recordPath, 'instance record').instances?.find((i) => i.account === account);
  if (!entry) throw new Refused(`${account} is not in the instance record`);
  if (entry.temp !== true) throw new Refused(`${account} is recorded as a real instance. This script never deletes one`);
  const configPath = a.config ?? join(REPO, 'site', 'config', 'testnet.json');
  if (existsSync(configPath) && readJson(configPath, 'site config').contract === account) {
    throw new Refused(`site/config/testnet.json still names ${account}: deploy the site on the real instance first`);
  }

  let keys = null;
  if (a['relay-keys']) {
    keys = loadSecretsFile(a['relay-keys']);
    if (keys.contract !== account) throw new Refused(`that relay keys file is for ${keys.contract}, not ${account}`);
  }

  console.log(`90-teardown-temp: ${live ? 'LIVE' : 'DRY RUN'} on ${network} [${label}]`);
  note(`delete ${account}, recorded ${entry.created_at}, balance to ${beneficiary}`);
  const { near } = await connect(network, a.rpc, { offline: Boolean(a.offline) });
  let before = null;
  if (!a.offline) {
    const [acct, ben] = await Promise.all([near.account(account), near.account(beneficiary)]);
    if (!acct) throw new Refused(`${account} does not exist: nothing to tear down`);
    if (!ben) throw new Refused(`${beneficiary} does not exist`);
    if (acct.code_hash !== entry.code_hash) throw new Refused(`${account} holds code ${acct.code_hash}, the record says ${entry.code_hash}`);
    before = { account: BigInt(acct.amount), beneficiary: BigInt(ben.amount) };
    note(`read: ${account} holds ${formatNear(acct.amount)} NEAR; ${beneficiary} holds ${formatNear(ben.amount)} NEAR`);
    const stats = await near.view(account, 'stats').catch(() => null);
    if (stats) note(`stats: ${JSON.stringify(stats)}`);
    if (stats?.vaults_active > 0) line('WARN', label, `${stats.vaults_active} vaults are active on it. Their coins leave only by each cold key after the timelock once this is gone`);
  }

  planTx(1, { signer: account, receiver: account, actions: [describe.deleteAccount(beneficiary)] });
  if (keys) planTx(2, { signer: keys.relay_account, receiver: keys.relay_account, actions: Object.values(keys.keys).map((k) => describe.deleteKey(k.public_key)) });
  plan(`then: read back that ${account} is gone${before ? ` and ${beneficiary} gained its balance` : ''}`);
  if (!live) {
    console.log('DRY RUN: nothing sent.');
    return 0;
  }

  // The temporary account carries the deployer's own key, added at creation.
  const payer = signingKey(network, parent);
  const own = { ...payer, accountId: account };
  const gone = await near.sendAndWait(own, account, [deleteAccountAction(beneficiary)]);
  if (ownFailure(gone.result)) throw new Error(`delete failed: ${ownFailure(gone.result)}`);
  const chain = network === 'testnet' ? 'NEAR testnet' : 'local NEAR sandbox';
  line('SENT', label, `delete ${account}: ${chain} tx ${gone.hash}`);
  let failed = 0;
  if (keys) {
    const signer = signingKey(network, keys.relay_account);
    const deleted = await near.sendAndWait(signer, keys.relay_account, Object.values(keys.keys).map((k) => action.deleteKey(parseSecretKey(k.secret_key).pub)));
    if (failureOf(deleted.result)) {
      line('FAIL', label, `the relay keys were not deleted: ${failureOf(deleted.result)}`);
      failed += 1;
    } else line('SENT', label, `deleted ${Object.keys(keys.keys).join(', ')} from ${keys.relay_account}: ${chain} tx ${deleted.hash}`);
    for (const [name, k] of Object.entries(keys.keys)) {
      let left = await accessKey(near, keys.relay_account, k.public_key);
      for (let i = 0; i < 30 && left; i += 1) {
        await new Promise((r) => setTimeout(r, 500));
        left = await accessKey(near, keys.relay_account, k.public_key);
      }
      line(left ? 'FAIL' : 'PASS', label, `${name} ${left ? 'is still on' : 'is gone from'} ${keys.relay_account}`);
      if (left) failed += 1;
    }
  }

  for (let i = 0; i < 30 && (await near.account(account)) !== null; i += 1) await new Promise((r) => setTimeout(r, 500));
  const after = await near.account(account);
  line(after === null ? 'PASS' : 'FAIL', label, `${account} ${after === null ? 'is gone' : 'still exists'}`);
  if (after !== null) failed += 1;
  const ben = await near.account(beneficiary);
  const gained = BigInt(ben.amount) - before.beneficiary;
  const ok = gained > (before.account * 9n) / 10n;
  line(ok ? 'PASS' : 'FAIL', label, `${beneficiary} gained ${formatNear(gained)} NEAR of the ${formatNear(before.account)} it held`);
  if (!ok) failed += 1;
  return failed ? 1 : 0;
}

main().then((code) => process.exit(code)).catch((err) => {
  if (err instanceof UsageError) {
    console.error(`${err.message}\n${USAGE}`);
    process.exit(2);
  }
  if (err instanceof Refused) {
    console.error(`REFUSED: ${err.message}`);
    process.exit(3);
  }
  console.error(`ERROR: ${err.message}`);
  process.exit(1);
});
