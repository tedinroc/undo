#!/usr/bin/env node
// Makes the relay's three keys and adds them to the relay account in one transaction from that account:
//
//   RELAY_GENERAL_KEY  full access, because create_vault attaches a deposit and the guard's heartbeat must come from
//                      the account a vault named. The relay account holds only budget for that reason.
//   RELAY_OWNER_KEY    function call, receiver the contract, cancel and cancel_all_and_rotate only, 8 NEAR allowance
//   RELAY_CRON_KEY     function call, receiver the contract, heartbeat only, for the undo-cron Worker
//
// Plus IP_SALT and BEAT_TOKEN, two random values the Pages Functions need. Everything goes to one private file
// outside every repo, written before the transaction, so a crash after sending cannot lose a key that is on chain.
// A public copy (public keys only) sits next to it for 50-readback.
//
//   node scripts/go-live/20-relay-keys.mjs --dry-run --contract v1.s.undo-btc.testnet
//   node scripts/go-live/20-relay-keys.mjs --live    --contract v1.s.undo-btc.testnet [--out FILE]
//   node scripts/go-live/20-relay-keys.mjs --live    --contract … --resume     adds what the file has and the chain lacks
//
// Exit 0: every key reads back with its permission. 1: a readback failed. 2: usage. 3: refused before any write.
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs, UsageError } from '../../tools/lib/args.mjs';
import { base58Encode, concat, toHex } from '../../tools/lib/bytes.mjs';
import { randomBytes } from '../../tools/lib/crypto.mjs';
import { action, failureOf, keyFromSecret, NEAR, parseSecretKey } from '../../tools/lib/near.mjs';
import {
  accessKey, connect, untilFinal, CRON_ALLOWANCE_NEAR, CRON_METHODS, describe, formatNear, line, modeIsPrivate, modeOf, nearOf, note,
  OWNER_ALLOWANCE_NEAR, OWNER_METHODS, permissionProblem, plan, planTx, privateDir, readJson, Refused, signingKey, writePrivate,
} from './lib.mjs';

const USAGE = `usage: 20-relay-keys.mjs (--dry-run | --live) --contract ACCOUNT [--relay ACCOUNT] [--out FILE] [--resume]
  [--owner-allowance-near N] [--cron-allowance-near N] [--network testnet|sandbox] [--rpc URL] [--offline]`;

export const SCHEMA = 'undo-relay-secrets-v1';
// Below this the relay account cannot pay for a day of vaults and cancels. A warning, not a refusal.
const RELAY_FLOOR = 5n * NEAR;

const secretText = (key) => `ed25519:${base58Encode(concat(key.secret, key.pub))}`;

/** The permission each key must have on chain. */
export function wanted(contract, { ownerAllowance, cronAllowance }) {
  return {
    RELAY_GENERAL_KEY: { full: true },
    RELAY_OWNER_KEY: { receiver: contract, methods: [...OWNER_METHODS], allowance: ownerAllowance },
    RELAY_CRON_KEY: { receiver: contract, methods: [...CRON_METHODS], allowance: cronAllowance },
  };
}

function freshFile({ network, relay, contract, want }) {
  const keys = {};
  for (const [name, perm] of Object.entries(want)) {
    const key = keyFromSecret(randomBytes(32));
    keys[name] = {
      public_key: key.publicKey,
      secret_key: secretText(key),
      permission: perm.full ? 'FullAccess' : { receiver: perm.receiver, methods: perm.methods, allowance_yocto: perm.allowance.toString() },
    };
  }
  return {
    schema: SCHEMA, network, relay_account: relay, contract, created_at: new Date().toISOString(), keys,
    values: { IP_SALT: toHex(randomBytes(32)), BEAT_TOKEN: toHex(randomBytes(24)) },
    sent: [],
  };
}

export const publicCopyPath = (path) => path.replace(/\.json$/, '') + '.public.json';

export function publicCopy(file) {
  return {
    schema: `${SCHEMA}-public`, network: file.network, relay_account: file.relay_account, contract: file.contract,
    keys: Object.fromEntries(Object.entries(file.keys).map(([name, k]) => [name, { public_key: k.public_key, permission: k.permission }])),
    sent: file.sent,
  };
}

/** Reads a secrets file and checks every key in it is the key its public half says. Never prints a value. */
export function loadSecretsFile(path) {
  if (!modeIsPrivate(path)) throw new Refused('the secrets file is readable by others: chmod 600 it first');
  const file = readJson(path, 'secrets file');
  if (file.schema !== SCHEMA) throw new Refused('the secrets file has an unknown schema');
  for (const [name, k] of Object.entries(file.keys ?? {})) {
    let key;
    try {
      key = parseSecretKey(k.secret_key);
    } catch {
      throw new Refused(`${name} in the secrets file is not an ed25519 key`);
    }
    if (key.publicKey !== k.public_key) throw new Refused(`${name}'s secret does not make its public key`);
  }
  return file;
}

function permissionText(perm) {
  return perm === 'FullAccess' ? 'FullAccess' : `FunctionCall receiver=${perm.receiver} methods=[${perm.methods.join(', ')}] allowance=${formatNear(perm.allowance_yocto)} NEAR`;
}

async function main() {
  const a = parseArgs(process.argv.slice(2), {
    'dry-run': 'flag', live: 'flag', network: 'text', rpc: 'text', relay: 'text', contract: 'text', out: 'text', resume: 'flag',
    'owner-allowance-near': 'text', 'cron-allowance-near': 'text', offline: 'flag',
  });
  const { network, live, defaults } = modeOf(a, USAGE);
  if (live && a.offline) throw new Refused('--offline is for a dry run');
  const relay = a.relay ?? defaults.relay;
  const contract = a.contract;
  if (!relay || !contract) throw new Refused(`give --contract${network === 'sandbox' ? ' and --relay' : ''}\n${USAGE}`);
  const ownerAllowance = nearOf(a['owner-allowance-near'] ?? OWNER_ALLOWANCE_NEAR);
  const cronAllowance = nearOf(a['cron-allowance-near'] ?? CRON_ALLOWANCE_NEAR);
  if (ownerAllowance > nearOf(OWNER_ALLOWANCE_NEAR)) throw new Refused(`the owner key's allowance stays at or under ${OWNER_ALLOWANCE_NEAR} NEAR`);
  const want = wanted(contract, { ownerAllowance, cronAllowance });
  const out = a.out ?? join(privateDir(), `relay-${contract}.json`);
  const label = defaults.label;

  console.log(`20-relay-keys: ${live ? 'LIVE' : 'DRY RUN'} on ${network} [${label}]`);
  note(`relay account ${relay}, contract ${contract}`);
  note(`private file ${out} (0600, outside every repo), public copy ${publicCopyPath(out)}`);

  let file = null;
  if (existsSync(out)) {
    if (!a.resume) throw new Refused('that private file exists. Keys in it may be on chain already: pass --resume to add only what is missing, or pick another --out');
    file = loadSecretsFile(out);
    if (file.contract !== contract || file.relay_account !== relay || file.network !== network) throw new Refused('that private file is for another contract, relay or network');
  } else if (a.resume) throw new Refused('--resume needs the private file from the first run');

  const { near } = await connect(network, a.rpc, { offline: Boolean(a.offline) });
  if (!a.offline) {
    const [relayAccount, instance] = await Promise.all([near.account(relay), near.view(contract, 'instance').catch(() => null)]);
    if (!relayAccount) throw new Refused(`${relay} does not exist on this network`);
    if (!instance) throw new Refused(`${contract} answers no instance view. Deploy it first (10-deploy-instance)`);
    note(`read: ${relay} holds ${formatNear(relayAccount.amount)} NEAR; ${contract} is a ${instance.preset} instance on ${instance.network}`);
    if (BigInt(relayAccount.amount) < RELAY_FLOOR) line('WARN', label, `${relay} holds under ${formatNear(RELAY_FLOOR)} NEAR, which is about two weeks of relay traffic`);
  }

  // What goes on chain. A dry run shows the permissions with placeholder keys; nothing is made or kept.
  const names = Object.keys(want);
  let missing = names;
  if (file && !a.offline) {
    missing = [];
    for (const name of names) {
      const problem = permissionProblem(await accessKey(near, relay, file.keys[name].public_key), want[name]);
      if (problem === 'not on the account') missing.push(name);
      else if (problem) throw new Refused(`${name} is on ${relay} with the wrong permission: ${problem}. Delete it and start a new file`);
    }
  }
  const shown = (name) => (file ? file.keys[name].public_key : `<new ${name}>`);
  const actions = missing.map((name) => (want[name].full
    ? describe.addFullKey(shown(name))
    : describe.addCallKey(shown(name), want[name].receiver, want[name].methods, want[name].allowance)));
  if (missing.length === 0) console.log('NOTHING TO SEND: every key in the file is on chain.');
  else planTx(1, { signer: relay, receiver: relay, actions });
  plan(`also kept in the file, never on chain: IP_SALT (32 random bytes), BEAT_TOKEN (24 random bytes)`);
  plan('then: read back each key with view_access_key');

  if (!live) {
    console.log('DRY RUN: nothing made, nothing written, nothing sent.');
    return;
  }

  if (!file) {
    file = freshFile({ network, relay, contract, want });
    writePrivate(out, file);
    writePrivate(publicCopyPath(out), publicCopy(file));
    line('KEPT', label, `the private file is written before anything is sent`);
  }
  if (missing.length > 0) {
    const signer = signingKey(network, relay);
    const onChain = missing.map((name) => {
      const k = parseSecretKey(file.keys[name].secret_key);
      return want[name].full ? action.addFullKey(k.pub) : action.addCallKey(k.pub, want[name].receiver, want[name].methods, want[name].allowance);
    });
    const sent = await near.sendAndWait(signer, relay, onChain);
    if (failureOf(sent.result)) throw new Error(`the keys were not added: ${failureOf(sent.result)}`);
    file.sent.push({ tx: sent.hash, added: missing, at: new Date().toISOString() });
    writePrivate(out, file);
    writePrivate(publicCopyPath(out), publicCopy(file));
    line('SENT', label, `added ${missing.join(', ')}: ${network === 'testnet' ? 'NEAR testnet' : 'local NEAR sandbox'} tx ${sent.hash}`);
    await untilFinal(near, relay, missing.map((name) => file.keys[name].public_key));
  }

  let failed = 0;
  for (const name of names) {
    const access = await accessKey(near, relay, file.keys[name].public_key);
    const problem = permissionProblem(access, want[name]);
    line(problem ? 'FAIL' : 'PASS', label, `${name} ${file.keys[name].public_key} on ${relay}: ${problem ?? permissionText(file.keys[name].permission)}`);
    if (problem) failed += 1;
  }
  process.exit(failed ? 1 : 0);
}

if (process.argv[1]?.endsWith('20-relay-keys.mjs')) {
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
}
