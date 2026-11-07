#!/usr/bin/env node
// Deploys the contract to a fresh sub-account of the deployer, with the real signer, and prints what the instance
// view reads back. The origin, rp id and network are fixed at creation and the contract has no setter for them, so a
// wrong value here means a new name.
//
//   node scripts/go-live/10-deploy-instance.mjs --dry-run --name v1 --operator-passkey FILE
//   node scripts/go-live/10-deploy-instance.mjs --live    --name v1 --operator-passkey FILE
//   node scripts/go-live/10-deploy-instance.mjs --live    --temp             a throwaway software operator key
//   node scripts/go-live/10-deploy-instance.mjs --network sandbox --rpc URL --parent A --signer M --live --temp
//
// Refuses to overwrite code: an account that already holds code is only read back, and other code than this wasm
// stops the run. Exit 0: deployed or already there, every readback line PASS. 1: a readback line failed. 2: usage.
// 3: refused before any write. A dry run sends nothing and exits 0 when its plan could run.
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs, UsageError } from '../../tools/lib/args.mjs';
import { action, failureOf, NEAR, TGAS } from '../../tools/lib/near.mjs';
import { PATH_PREFIX, throwawayOperatorPasskey } from '../../tools/lib/vault-client.mjs';
import {
  checkLabel, connect, defaultWasm, describe, EMPTY_CODE, formatNear, line, modeOf, nearOf, note, plan, planTx, privateDir,
  readJson, readOperatorPasskey, Refused, REPO, signingKey, SITE, TEMP_PREFIX, utcStamp, wasmFacts, writePrivate,
} from './lib.mjs';
import { readBack } from './checks.mjs';

const USAGE = `usage: 10-deploy-instance.mjs (--dry-run | --live) (--operator-passkey FILE | --temp) [--name LABEL]
  [--network testnet|sandbox] [--rpc URL] [--parent ACCOUNT] [--signer ACCOUNT] [--wasm FILE] [--fund-near N]
  [--sign-tgas N] [--outflow-cap SATS] [--record FILE] [--offline]
  --name is the sub-account label: v1 makes v1.<parent>. --temp names it ${TEMP_PREFIX}<utc stamp> unless given.`;

const STORAGE_YOCTO_PER_BYTE = 10n ** 19n;
// What `new` writes, the account row and its key, and gas for the deploy, on top of the code's own bytes.
const FUND_MARGIN = NEAR / 5n;
const PARENT_KEEP = NEAR / 20n;
const SIGN_TGAS = 30;
const CALLBACK_TGAS = 10;
const DERIVE_TGAS = 30;
const OUTFLOW_CAP_SATS = 1_000_000;
const INIT_TGAS = 100n;

function initArgs({ parent, signer, signTgas, outflowCap, operatorPasskey }) {
  return {
    preset: 'TestCoin', operator: parent, restrict_create: false, signer, domain_id: 0,
    sign_tgas: signTgas, callback_tgas: CALLBACK_TGAS, derive_tgas: DERIVE_TGAS,
    network: SITE.btcNetwork, origins: [SITE.origin], outflow_cap_24h: outflowCap,
    operator_passkey: operatorPasskey,
  };
}

/** Rounded up to a tenth of a NEAR: the code's storage plus the margin. */
function fundFor(size) {
  const need = BigInt(size) * STORAGE_YOCTO_PER_BYTE + FUND_MARGIN;
  const tenth = NEAR / 10n;
  return ((need + tenth - 1n) / tenth) * tenth;
}

function outwardCheck(wasm) {
  const result = spawnSync(join(REPO, 'scripts', 'outward-check.sh'), ['--wasm', wasm], { encoding: 'utf8' });
  process.stdout.write(result.stdout ?? '');
  process.stderr.write(result.stderr ?? '');
  return result.status === 0;
}

function record(path, entry) {
  const list = existsSync(path) ? readJson(path, 'instance record') : { schema: 'undo-golive-instances-v1', instances: [] };
  list.instances = list.instances.filter((i) => i.account !== entry.account).concat([entry]);
  writePrivate(path, list);
}

async function main() {
  const a = parseArgs(process.argv.slice(2), {
    'dry-run': 'flag', live: 'flag', network: 'text', rpc: 'text', parent: 'text', signer: 'text', name: 'text', temp: 'flag',
    'operator-passkey': 'text', wasm: 'text', 'fund-near': 'text', 'sign-tgas': 'int', 'outflow-cap': 'int', record: 'text', offline: 'flag',
  });
  const { network, live, defaults } = modeOf(a, USAGE);
  if (live && a.offline) throw new Refused('--offline is for a dry run');
  if (Boolean(a.temp) === Boolean(a['operator-passkey'])) throw new Refused(`give --operator-passkey FILE or --temp, one of them\n${USAGE}`);
  const parent = a.parent ?? defaults.parent;
  const signer = a.signer ?? defaults.signer;
  if (!parent || !signer) throw new Refused('--network sandbox needs --parent and --signer');
  const temp = Boolean(a.temp);
  const name = a.name ?? (temp ? `${TEMP_PREFIX}${utcStamp()}` : null);
  if (!name) throw new Refused('give --name for the real instance: it becomes the contract the site names for good');
  checkLabel(name, { temp });
  const contract = `${name}.${parent}`;
  const wasm = a.wasm ?? defaultWasm();
  const facts = wasmFacts(wasm);
  const operatorPasskey = temp ? throwawayOperatorPasskey(SITE.rpId) : readOperatorPasskey(a['operator-passkey'], SITE.rpId);
  const signTgas = a['sign-tgas'] ?? SIGN_TGAS;
  const outflowCap = a['outflow-cap'] ?? OUTFLOW_CAP_SATS;
  const fund = a['fund-near'] ? nearOf(a['fund-near']) : fundFor(facts.size);
  const label = defaults.label;
  const recordPath = a.record ?? join(privateDir(), 'instances.json');
  const init = initArgs({ parent, signer, signTgas, outflowCap, operatorPasskey });

  console.log(`10-deploy-instance: ${live ? 'LIVE' : 'DRY RUN'} on ${network} [${label}]`);
  note(`contract ${contract}${temp ? ' (temporary: a throwaway software operator passkey, and the deployer key stays on it, so the deployer can replace or delete it at any time; step 90 deletes it)' : ' (the real instance: the deployer key added here stays on it until 60-lock-instance.mjs removes it, after Ted\'s yes)'}`);
  note(`wasm ${facts.size} bytes, sha256 ${facts.sha256}`);
  note(`signer ${signer}, origins [${SITE.origin}], rp id ${SITE.rpId}, network ${SITE.btcNetwork}`);
  note(`operator ${parent}, operator passkey ${operatorPasskey.pubkey}`);
  if (fund < BigInt(facts.size) * STORAGE_YOCTO_PER_BYTE) throw new Refused(`--fund-near ${formatNear(fund)} cannot pay for ${facts.size} bytes of code`);

  const { near } = await connect(network, a.rpc, { offline: Boolean(a.offline) });
  let existing = null;
  let parentAccount = null;
  if (!a.offline) {
    [existing, parentAccount] = await Promise.all([near.account(contract), near.account(parent)]);
    if (!parentAccount) throw new Refused(`${parent} does not exist on this network`);
    // The view the contract's own activation asks, with a path as long as a vault's. The mock answers it too.
    const derived = await near.view(signer, 'derived_public_key', { path: `${PATH_PREFIX}${'0'.repeat(64)}`, predecessor: contract, domain_id: 0 }).catch(() => null);
    const version = await near.view(signer, 'version').catch(() => null);
    note(`read: ${parent} holds ${formatNear(parentAccount.amount)} NEAR; signer ${signer} version ${version === null ? '(no version view)' : JSON.stringify(version)}, derived_public_key ${derived === null ? 'did not answer' : 'answers'}`);
    if (derived === null) throw new Refused(`${signer} does not answer derived_public_key, so no vault could activate`);
  } else note('offline: nothing read, so the plan assumes a fresh name');

  if (existing && existing.code_hash !== EMPTY_CODE) {
    if (existing.code_hash !== facts.codeHash) throw new Refused(`${contract} holds other code (${existing.code_hash}). Refusing to overwrite it: use a fresh --name`);
    console.log(`NOTHING TO SEND: ${contract} already holds this wasm. Reading it back.`);
    // A re-run with --temp makes a new throwaway key, which cannot match the first one's.
    const verdicts = await readBack({ near, contract, expect: { signer, parent, signTgas, operatorPasskey: temp ? null : operatorPasskey, fullAccess: temp ? 'temp' : 'before-lock' }, facts, label });
    if (!temp) console.log(`NEXT: 60-lock-instance.mjs --dry-run --name ${name}, then --live with Ted's yes, so ${contract} ends with no full-access key`);
    process.exit(verdicts.includes('FAIL') ? 1 : 0);
  }

  const deployActions = [describe.deploy(facts), describe.call('new', init, Number(INIT_TGAS))];
  const txs = [];
  if (!existing) {
    if (!a.offline && parentAccount && BigInt(parentAccount.amount) < fund + PARENT_KEEP) {
      throw new Refused(`${parent} holds ${formatNear(parentAccount.amount)} NEAR and this needs ${formatNear(fund + PARENT_KEEP)}: ${formatNear(fund)} for the account, the rest for gas. Top it up first`);
    }
    txs.push({ signer: parent, receiver: contract, actions: [describe.createAccount(), describe.transfer(fund), describe.addFullKey(`<${parent}'s own public key, read at --live>`)] });
  } else note(`${contract} exists with no code: a run that stopped before deploying. Only the deploy goes out, signed with ${parent}'s key on it`);
  txs.push({ signer: contract, receiver: contract, actions: deployActions });
  txs.forEach((tx, i) => planTx(i + 1, tx));
  plan(`then: read back the instance view, and record ${contract} in ${recordPath}`);

  if (!live) {
    console.log('DRY RUN: nothing sent.');
    return;
  }

  if (network === 'testnet') {
    console.log('Outward check on the exact wasm:');
    if (!outwardCheck(wasm)) throw new Refused('the outward check failed, so nothing was sent');
  }
  const payer = signingKey(network, parent);
  const sent = {};
  if (!existing) {
    const made = await near.sendAndWait(payer, contract, [action.createAccount(), action.transfer(fund), action.addFullKey(payer.pub)]);
    if (failureOf(made.result)) throw new Error(`could not create ${contract}: ${failureOf(made.result)}`);
    sent.create_tx = made.hash;
    line('SENT', label, `create ${contract}: ${network === 'testnet' ? 'NEAR testnet' : 'local NEAR sandbox'} tx ${made.hash}`);
  }
  const own = { ...payer, accountId: contract };
  const deployed = await near.sendAndWait(own, contract, [action.deploy(facts.bytes), action.call('new', init, INIT_TGAS * TGAS, 0n)]);
  if (failureOf(deployed.result)) throw new Error(`deploy failed: ${failureOf(deployed.result)}`);
  sent.deploy_tx = deployed.hash;
  line('SENT', label, `deploy and new on ${contract}: ${network === 'testnet' ? 'NEAR testnet' : 'local NEAR sandbox'} tx ${deployed.hash}`);
  record(recordPath, { account: contract, temp, network, code_hash: facts.codeHash, wasm_sha256: facts.sha256, operator_passkey: operatorPasskey.pubkey, created_at: new Date().toISOString(), ...sent });

  // The code hash reads at final, a block or two behind the deploy.
  for (let i = 0; (await near.account(contract))?.code_hash === EMPTY_CODE; i += 1) {
    if (i > 60) break;
    await new Promise((r) => setTimeout(r, 500));
  }
  const verdicts = await readBack({ near, contract, expect: { signer, parent, signTgas, operatorPasskey, fullAccess: temp ? 'temp' : 'before-lock' }, facts, label });
  if (!temp) console.log(`NEXT: 60-lock-instance.mjs --dry-run --name ${name}, then --live with Ted's yes, so ${contract} ends with no full-access key`);
  process.exit(verdicts.includes('FAIL') ? 1 : 0);
}

main().catch((err) => {
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
