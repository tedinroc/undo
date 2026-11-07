#!/usr/bin/env node
// Step 60. Removes the deployer's full-access key from the real instance, so the contract account ends with no
// full-access key (SPEC 5, CLAIMS C11): after this, its code changes only through upgrade_propose and its public wait,
// and nobody can delete the account. This cannot be undone, so --live also needs --yes-delete-the-last-key, given
// only after Ted says yes.
//
//   node scripts/go-live/60-lock-instance.mjs --dry-run --name v1
//   node scripts/go-live/60-lock-instance.mjs --live    --name v1 --yes-delete-the-last-key
//
// Only the real instance 10-deploy-instance.mjs recorded: never a tmp- one, which step 90 must still be able to
// delete. Before it sends, the account must hold the recorded code, read back every instance field, have no pending
// upgrade, and hold exactly one full-access key, the deployer's. Afterwards the key list is read back.
// Exit 0: no full-access key left (or none was there). 1: a readback failed. 2: usage. 3: refused before any write.
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs, UsageError } from '../../tools/lib/args.mjs';
import { action, failureOf } from '../../tools/lib/near.mjs';
import { fullAccessKeys, readBack } from './checks.mjs';
import { checkLabel, connect, line, modeOf, note, plan, planTx, privateDir, readJson, Refused, describe, signingKey, TEMP_PREFIX, writePrivate } from './lib.mjs';

const USAGE = `usage: 60-lock-instance.mjs (--dry-run | --live) --name LABEL [--yes-delete-the-last-key] [--parent ACCOUNT]
  [--sign-tgas N] [--record FILE] [--network testnet|sandbox] [--rpc URL] [--offline]
  --live needs --yes-delete-the-last-key: the deployer key cannot be added back.`;

async function main() {
  const a = parseArgs(process.argv.slice(2), {
    'dry-run': 'flag', live: 'flag', network: 'text', rpc: 'text', name: 'text', parent: 'text', record: 'text', offline: 'flag',
    'sign-tgas': 'int', 'yes-delete-the-last-key': 'flag',
  });
  const { network, live, defaults } = modeOf(a, USAGE);
  if (live && a.offline) throw new Refused('--offline is for a dry run');
  if (live && !a['yes-delete-the-last-key']) throw new Refused(`--live deletes the last full-access key, which cannot be undone: add --yes-delete-the-last-key once Ted has said yes\n${USAGE}`);
  const parent = a.parent ?? defaults.parent;
  if (!parent) throw new Refused('--network sandbox needs --parent');
  if (!a.name) throw new Refused('give --name, the real instance\'s label');
  if (a.name.startsWith(TEMP_PREFIX)) throw new Refused(`${a.name} is a temporary instance: it keeps the deployer key so 90-teardown-temp.mjs can delete it`);
  checkLabel(a.name, { temp: false });
  const contract = `${a.name}.${parent}`;
  const label = defaults.label;

  const recordPath = a.record ?? join(privateDir(), 'instances.json');
  if (!existsSync(recordPath)) throw new Refused('no instance record: only an instance 10-deploy-instance.mjs recorded can be locked');
  const record = readJson(recordPath, 'instance record');
  const entry = record.instances?.find((i) => i.account === contract);
  if (!entry) throw new Refused(`${contract} is not in the instance record`);
  if (entry.temp !== false) throw new Refused(`${contract} is not recorded as the real instance`);

  console.log(`60-lock-instance: ${live ? 'LIVE' : 'DRY RUN'} on ${network} [${label}]`);
  note(`lock ${contract}, recorded ${entry.created_at}, code hash ${entry.code_hash}`);
  const { near } = await connect(network, a.rpc, { offline: Boolean(a.offline) });
  let keys = null;
  let instance = null;
  if (!a.offline) {
    const account = await near.account(contract);
    if (!account) throw new Refused(`${contract} does not exist`);
    if (account.code_hash !== entry.code_hash) throw new Refused(`${contract} holds code ${account.code_hash}, the record says ${entry.code_hash}. Locking would freeze the wrong code`);
    instance = await near.view(contract, 'instance').catch((err) => { throw new Refused(`the instance view does not answer: ${err.message}`); });
    if (defaults.signer && instance.signer !== defaults.signer) throw new Refused(`the instance names signer ${instance.signer}, not ${defaults.signer}`);
    if (instance.operator !== parent) throw new Refused(`the instance names operator ${instance.operator}, not ${parent}: nobody could propose an upgrade after the lock`);
    if (instance.operator_passkey !== entry.operator_passkey) throw new Refused('the instance\'s operator passkey is not the one recorded at deploy');
    if ((instance.pending_upgrade ?? null) !== null) throw new Refused('an upgrade is pending: settle it first');
    keys = await fullAccessKeys(near, contract);
    note(`read: ${contract} holds the recorded code; full-access keys: ${keys.length ? keys.join(', ') : 'none'}`);
    if (keys.length === 0) {
      console.log(`NOTHING TO SEND: ${contract} has no full-access key.`);
      line('PASS', label, `${contract} has no full-access key: its code changes only through upgrade_propose and its public wait`);
      return 0;
    }
    if (keys.length > 1) throw new Refused(`${contract} has ${keys.length} full-access keys (${keys.join(', ')}), and the deploy added one. Find out who added the others before anything else`);
  } else note('offline: nothing read');

  planTx(1, { signer: contract, receiver: contract, actions: [describe.deleteKey(keys ? keys[0] : `<${parent}'s own public key, the one 10-deploy-instance.mjs added>`)] });
  plan(`then: read back that ${contract} has no full-access key, and that the instance still reads as deployed`);
  if (!live) {
    console.log('DRY RUN: nothing sent. This step cannot be undone: --live needs --yes-delete-the-last-key, after Ted\'s yes.');
    return 0;
  }

  const payer = signingKey(network, parent);
  if (keys[0] !== payer.publicKey) throw new Refused(`the full-access key on ${contract} is ${keys[0]}, not the deployer's ${payer.publicKey}: this script deletes only the key it can sign with`);
  const own = { ...payer, accountId: contract };
  const sent = await near.sendAndWait(own, contract, [action.deleteKey(payer.pub)]);
  if (failureOf(sent.result)) throw new Error(`DeleteKey failed: ${failureOf(sent.result)}`);
  const chain = network === 'testnet' ? 'NEAR testnet' : 'local NEAR sandbox';
  line('SENT', label, `deleted the deployer's full-access key from ${contract}: ${chain} tx ${sent.hash}`);
  entry.locked_tx = sent.hash;
  entry.locked_at = new Date().toISOString();
  writePrivate(recordPath, record);

  let left = await fullAccessKeys(near, contract);
  for (let i = 0; i < 30 && left.length; i += 1) {
    await new Promise((r) => setTimeout(r, 500));
    left = await fullAccessKeys(near, contract);
  }
  const verdicts = await readBack({
    near, contract, label,
    expect: { signer: defaults.signer ?? instance.signer, parent, signTgas: a['sign-tgas'] ?? 30, operatorPasskey: { pubkey: entry.operator_passkey }, fullAccess: 'require-none' },
    facts: null,
  });
  return verdicts.includes('FAIL') ? 1 : 0;
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
