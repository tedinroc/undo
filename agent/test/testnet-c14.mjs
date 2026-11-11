#!/usr/bin/env node
// The agent CLI on NEAR testnet, once, with real transactions: what agent/test/sandbox-e2e.mjs shows on a
// local node, shown on the contract deploy/testnet.json names, through its live relay, with a Mutinynet
// test coin. It writes proofs/c14-agent.json, and ./verify.sh A fetches the recorded transactions again.
//
//   node agent/test/testnet-c14.mjs --live --payer ACCOUNT --agent-account ID --work DIR [--out FILE] [--config FILE]
//
// Without --live it prints this plan and sends nothing.
//
//   1. --payer, a NEAR testnet account whose key near-cli keeps (it never leaves this process), makes
//      --agent-account, a sub-account of itself, with the payer's own key as its full-access key. That key
//      is the owner's: it adds the agent's key and never goes into the agent file.
//   2. A throwaway vault through the relay, as the phone page makes one, with a software passkey
//      [software authenticator]; the relay's dispenser sends it one Mutinynet test coin.
//   3. The agent CLI, run as its own process with its agent file and a home folder that is --work, not
//      the payer's, so near-cli's keys are out of its reach: init, keys, check, propose, status. The
//      owner adds the key `undo keys` prints, scoped to the contract and to propose_btc and execute.
//   4. The agent's NEAR key signs cancel, cancel_all_and_rotate, set_policy, clear_hold and add_destination,
//      a call with a deposit, and a call to another account. NEAR refuses each before any contract runs, so
//      none of them is ever on chain: the record keeps the RPC's own error and the key's unchanged nonce.
//   5. What the agent can sign for those methods (a passkey assertion from a P-256 key it made, a cold-key
//      cancel signed with K_u), sent by the payer's full-access key. These land, and the contract refuses each.
//   6. The owner's passkey cancels the agent's request through the relay.
//   7. The agent proposes again, the owner's passkey rotates the spend key through the relay, and the
//      contract refuses the agent from then on: SpendKeySuspended, then bad K_s signature once the new key lands.
//
// --work is a private folder, never inside a repository: it keeps this run's secrets (the vault's keys,
// the agent file) and its progress, so a run that stops can be started again and goes on where it was.
// Relay limits: one vault and one test coin, of the 3 and 2 an IP address gets in a UTC hour.
import { spawn } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs, UsageError } from '../../tools/lib/args.mjs';
import { addressToSpk, segwitAddress } from '../../tools/lib/btc.mjs';
import { base58Decode, base58Encode, fromHex, toHex } from '../../tools/lib/bytes.mjs';
import { p256, randomBytes } from '../../tools/lib/crypto.mjs';
import { Esplora } from '../../tools/lib/esplora.mjs';
import { argBytes, intentDigest, PASSKEY_TAG, signSecp, softAssertion } from '../../tools/lib/intent.mjs';
import { spendKeys } from '../../tools/lib/keys.mjs';
import { action, failureOf, loadCredentials, NEAR, Near, parseSecretKey, RpcError, signTransaction, TGAS } from '../../tools/lib/near.mjs';
import { signSpend } from '../../tools/lib/spend.mjs';
import { coldCancelDigest, OWNER_ATTACH_TGAS } from '../../tools/lib/vault-client.mjs';
import { feeFor } from '../lib/coins.mjs';
import { AGENT_METHODS } from '../lib/config.mjs';
import { contractWords, runtimeWords } from '../lib/format.mjs';

const AGENT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const REPO = resolve(AGENT, '..');
const SCHEMA = 'undo-c14-agent-v1';
const ACCOUNT_ID = /^(?=.{2,64}$)([a-z0-9]+[-_])*[a-z0-9]+(\.([a-z0-9]+[-_])*[a-z0-9]+)*$/;
const FUND_NEAR_TENTHS = 5n;
const ALLOWANCE = (NEAR * 25n) / 100n;
const CSV = 6;
const sleep = (ms) => new Promise((r) => { setTimeout(r, ms); });
const nowIso = () => new Date().toISOString().replace(/\.\d+Z$/, 'Z');

class Stop extends Error {}

let a;
try {
  a = parseArgs(process.argv.slice(2), { live: 'flag', payer: 'text', 'agent-account': 'text', work: 'text', out: 'text', config: 'text' });
} catch (err) {
  if (!(err instanceof UsageError)) throw err;
  console.error(err.message);
  process.exit(2);
}
if (!a.live) {
  const head = readFileSync(fileURLToPath(import.meta.url), 'utf8').split('\n').slice(1).filter((l) => l.startsWith('//'));
  for (const l of head.slice(0, head.findIndex((l) => l.startsWith('// Relay limits')) + 1)) console.log(l.replace(/^\/\/ ?/, ''));
  console.log('\nNothing was sent: this run had no --live.');
  process.exit(0);
}
for (const need of ['payer', 'agent-account', 'work']) {
  if (!a[need]) {
    console.error(`needs --${need}`);
    process.exit(2);
  }
}
if (!ACCOUNT_ID.test(a.payer) || !ACCOUNT_ID.test(a['agent-account']) || !a['agent-account'].endsWith(`.${a.payer}`)) {
  console.error('--agent-account must be a sub-account of --payer');
  process.exit(2);
}
const work = resolve(a.work);
if (work.startsWith(`${REPO}/`) || work === REPO) {
  console.error('--work must be outside the repository: it holds this run\'s secrets');
  process.exit(2);
}
mkdirSync(work, { recursive: true, mode: 0o700 });
chmodSync(work, 0o700);
const configPath = resolve(a.config ?? join(REPO, 'deploy/testnet.json'));
const outPath = resolve(a.out ?? join(REPO, 'proofs/c14-agent.json'));
const config = JSON.parse(readFileSync(configPath, 'utf8'));
if (config.placeholder || config.network !== 'testnet' || config.label !== 'live-testnet') {
  console.error('the config does not name a NEAR testnet instance');
  process.exit(2);
}

// ---------------------------------------------------------------- this run's private state

const statePath = join(work, 'state.json');
const state = existsSync(statePath) ? JSON.parse(readFileSync(statePath, 'utf8')) : { schema: SCHEMA, started_utc: nowIso(), secret: {}, pub: {} };
function save() {
  const tmp = `${statePath}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(state, null, 2)}\n`, { mode: 0o600 });
  renameSync(tmp, statePath);
}
const transcriptPath = join(work, 'transcript.txt');
const say = (line) => {
  console.log(line);
  writeFileSync(transcriptPath, `${line}\n`, { flag: 'a', mode: 0o600 });
};
/** Runs a step once. What it returns is its public record; a later run reads it back and skips the step. */
async function step(name, fn) {
  if (state.pub[name] !== undefined) {
    say(`-- ${name}: done in an earlier run`);
    return state.pub[name];
  }
  say(`-- ${name}`);
  const out = await fn();
  state.pub[name] = out ?? true;
  save();
  return state.pub[name];
}

// ---------------------------------------------------------------- the chain, the relay, the pages' own code

const near = new Near(config.rpc, { timeoutMs: 30_000 });
const lib = async (name) => import(pathToFileURL(join(REPO, 'site/lib', name)).href);
const { RelayClient } = await lib('relay-client.mjs');
const { NearReader } = await lib('near-read.mjs');
const { contractViews, derivedKey } = await lib('views.mjs');
const { softCredentials } = await lib('soft-authenticator.mjs');
const { createPasskey, getAssertion } = await lib('webauthn.mjs');
const { buildCreateArgs, cancelArgs, cancelDigest, newVaultKeys, rotateArgs, rotateDigest, rpIdHashOf, vaultIdOf } = await lib('intents.mjs');
const { fundsPowTarget, solvePow } = await lib('pow.mjs');

const relay = new RelayClient({ relay: config.relay, funds: config.relay.replace(/\/relay$/, '/funds'), timeoutMs: 60_000 });
const reader = new NearReader({ urls: config.rpc, timeoutMs: 15_000 });
const views = contractViews(reader, config.contract);
const esplora = new Esplora(config.replay.mutinynet_esplora, { attempts: 4, backoffMs: 2000, timeoutMs: 20_000 });
const contract = config.contract;
const agentAccount = a['agent-account'];

async function until(what, fn, { timeoutMs = 60_000, everyMs = 800 } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    let out = null;
    try {
      out = await fn();
    } catch {
      // A lagging node. The deadline ends this.
    }
    if (out) return out;
    if (Date.now() > deadline) throw new Stop(`timed out waiting for ${what}`);
    await sleep(everyMs);
  }
}

/** A send from the payer's key that waits for the whole receipt tree. Another process may share the key, so a used nonce is tried again. */
async function paid(key, receiver, actions) {
  for (let i = 0; ; i += 1) {
    try {
      return await near.sendAndWait(key, receiver, actions);
    } catch (err) {
      const text = JSON.stringify(err.data ?? {});
      if (i < 3 && /InvalidNonce/.test(text)) {
        await sleep(1500);
        continue;
      }
      throw err;
    }
  }
}

/** The agent CLI as its own process: its agent file, and a home that is the work folder, where no near-cli key is. */
function undo(args, file) {
  return new Promise((done) => {
    const child = spawn(process.execPath, [join(AGENT, 'undo.mjs'), ...args, '--file', file], {
      env: { PATH: process.env.PATH, HOME: work, TMPDIR: work },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    const timer = setTimeout(() => child.kill('SIGKILL'), 180_000);
    child.on('close', (code) => {
      clearTimeout(timer);
      say(`$ undo ${args.map((t) => (/\s/.test(t) ? `"${t}"` : t)).join(' ')}`);
      for (const l of out.trimEnd().split('\n')) say(l);
      if (err) say(`[stderr] ${err.trimEnd()}`);
      say(`[exit ${code}]`);
      done({ code, out, err, lines: out.trimEnd().split('\n') });
    });
  });
}

const accessKey = async (account, publicKey) => near.rpc('query', { request_type: 'view_access_key', account_id: account, public_key: publicKey, finality: 'optimistic' });

/** Whether the chain knows a transaction hash. A refused transaction was never broadcast, so it must not. */
async function knownToChain(hash, sender) {
  for (const url of [...config.rpc, ...config.replay.near_archival_rpc]) {
    try {
      await near.rpcOnce(url, 'tx', { tx_hash: hash, sender_account_id: sender, wait_until: 'NONE' });
      return { known: true, by: new URL(url).host };
    } catch (err) {
      const cause = err.data?.cause?.name;
      if (cause === 'UNKNOWN_TRANSACTION') return { known: false, by: new URL(url).host, answer: cause };
    }
  }
  throw new Stop(`no node answered about transaction ${hash}`);
}

/**
 * Signs one call with the agent's NEAR key and hands it to a node. Returns the node's refusal verbatim, or
 * throws if the node took it: then the key is wider than the claim, and the run must stop.
 */
async function nearRefuses(key, receiver, method, args, deposit = 0n) {
  const access = await accessKey(key.accountId, key.publicKey);
  const block = await near.block('final');
  const signed = signTransaction({
    signerId: key.accountId, key, nonce: BigInt(access.nonce) + 1n, receiverId: receiver, blockHash: base58Decode(block.header.hash),
    actions: [action.call(method, args, 30n * TGAS, deposit)],
  });
  let last = null;
  for (let i = 0; i < 6; i += 1) {
    const url = config.rpc[i % config.rpc.length];
    try {
      await near.rpcOnce(url, 'send_tx', { signed_tx_base64: signed.base64, wait_until: 'INCLUDED' });
      throw new Stop(`NEAR took the agent key's ${method}: transaction ${signed.hash}. The key is wider than it should be`);
    } catch (err) {
      if (err instanceof Stop) throw err;
      if (err instanceof RpcError && err.data?.cause?.name === 'INVALID_TRANSACTION') {
        return { method, receiver, deposit: deposit.toString(), signed_hash: signed.hash, rpc: new URL(url).host, error: err.data, words: runtimeWords(err) };
      }
      last = err;
      await sleep(1500);
    }
  }
  throw new Stop(`no node judged the agent key's ${method}: ${last?.message}`);
}

const fromNearSecret = (text) => parseSecretKey(text);
const tbAddress = () => segwitAddress(config.bitcoin_network, 0, randomBytes(20));
const requestIdFrom = (out) => Number((out.match(/^request +#(\d+)$/m) ?? [])[1]);
const txFrom = (out) => (out.match(/^NEAR testnet tx ([1-9A-HJ-NP-Za-km-z]{43,44})$/m) ?? [])[1] ?? null;

// ---------------------------------------------------------------- the run

async function main() {
  say(`== agent CLI on NEAR testnet: contract ${contract}, relay ${config.relay}, ${nowIso()}`);
  say('   Passkey: [software authenticator] in this process. Coins: Mutinynet signet test coins. Nothing here is mainnet.');

  const instance = await views.instance();
  if (instance.network !== config.bitcoin_network || instance.preset !== 'TestCoin') throw new Stop('the contract is not the test-coin instance the config names');
  if (!instance.origins.includes(config.site_origin)) throw new Stop('the contract does not list the config\'s site origin');
  const status = await relay.status();
  if (!status.reachable) throw new Stop(`no answer from the relay: ${status.why}`);
  const payer = loadCredentials('testnet', a.payer);
  const ownerOfAgent = { ...payer, accountId: agentAccount };

  const code = await step('contract', async () => {
    const account = await near.account(contract);
    const want = base58Encode(fromHex(config.wasm_sha256));
    if (account.code_hash !== want) throw new Stop(`${contract} does not run the wasm the config records`);
    return { account: contract, code_hash: account.code_hash, wasm_sha256: config.wasm_sha256, signer: instance.signer, policy: instance.policy };
  });
  say(`   ${contract} runs code hash ${code.code_hash}`);

  // 1. The agent's account. Its full-access key is the payer's key: the owner's, never the agent's.
  await step('agent_account', async () => {
    if (await near.account(agentAccount)) throw new Stop(`${agentAccount} exists already: name a new one`);
    const sent = await paid(payer, agentAccount, [action.createAccount(), action.transfer((NEAR * FUND_NEAR_TENTHS) / 10n), action.addFullKey(payer.pub)]);
    if (failureOf(sent.result)) throw new Stop(`create ${agentAccount}: ${failureOf(sent.result)}`);
    say(`   made ${agentAccount}, NEAR testnet tx ${sent.hash}`);
    return { account: agentAccount, created_tx: sent.hash, created_by: a.payer, funded_near: `0.${FUND_NEAR_TENTHS}`, full_access_key: payer.publicKey };
  });

  // 2. The vault, as the phone page makes it, and one test coin.
  if (!state.secret.vault) {
    state.secret.vault = { seed: toHex(randomBytes(32)), cold: toHex(randomBytes(32)), passkey: toHex(randomBytes(32)) };
    save();
  }
  const secret = state.secret.vault;
  const soft = softCredentials({ secret: fromHex(secret.passkey), origin: config.site_origin, rpId: config.rp_id });
  const passkeyPub = p256.getPublicKey(fromHex(secret.passkey), true);
  const keys = newVaultKeys({ seed: fromHex(secret.seed), cold: fromHex(secret.cold) });
  const vaultHex = toHex(vaultIdOf({ contract, keys, passkeyPub, csv: CSV }));
  const vaultId = fromHex(vaultHex);
  const assert = async (digest) => (await getAssertion({ credentials: soft, digest, rpId: config.rp_id, credentialId: soft.credentialId })).args;

  const made = await step('vault', async () => {
    if (!status.general?.up) throw new Stop(`the relay is not taking new vaults now: ${status.general?.why}`);
    const passkey = await createPasskey({ credentials: soft, rpId: config.rp_id, label: 'agent run throwaway' });
    if (toHex(passkey.pubkey) !== toHex(passkeyPub)) throw new Stop('the software authenticator made another key than its secret gives');
    const km = await derivedKey(reader, { signer: instance.signer, domainId: instance.domain_id, contract, vaultHex });
    const built = await buildCreateArgs({
      contract, keys, passkeyPub, rpIdHash: rpIdHashOf(config.rp_id), km, guard: status.relayAccount, policy: instance.policy, csv: CSV,
      expiresAt: (await near.nowMs()) + 30 * 60_000, assert,
    });
    // A run that stopped after the relay sent this must not send it twice: the vault id can be made once.
    if (!state.sent_create_tx && !(await views.vault(vaultHex).catch(() => null))) {
      const pow = await solvePow(vaultHex, status.powBits);
      state.sent_create_tx = (await relay.call('create_vault', built.args, { pow })).hash;
      save();
    }
    const created = { hash: state.sent_create_tx ?? null };
    const vault = await until('the vault to read active', async () => {
      const v = await views.vault(vaultHex);
      return v?.active ? v : null;
    }, { timeoutMs: 90_000 });
    say(`   vault ${vaultHex} active at ${vault.address}, NEAR testnet tx ${created.hash}`);
    return { id: vaultHex, address: vault.address, script_pubkey: vault.script_pubkey, created_tx: created.hash, created_through: config.relay, guard: status.relayAccount, created_utc: nowIso() };
  });

  const coin = await step('coin', async () => {
    if (!status.funds?.up) throw new Stop(`the relay's dispenser is not paying now: ${status.funds?.why}`);
    // The same for the coin: one ask, however often this run is started again.
    if (!state.sent_coin_txid) {
      const pow = await solvePow(fundsPowTarget(vaultHex), status.powBits);
      state.sent_coin_txid = (await relay.fund(vaultHex, { pow })).txid;
      save();
    }
    const paidCoin = { txid: state.sent_coin_txid };
    say(`   test coin sent: Mutinynet txid ${paidCoin.txid}. Waiting for a block`);
    const utxo = await until('the coin to confirm on Mutinynet', async () => {
      const list = await esplora.utxos(made.address);
      return list.find((u) => u.txid === paidCoin.txid && u.status?.confirmed) ?? null;
    }, { timeoutMs: 8 * 60_000, everyMs: 5000 });
    say(`   confirmed at height ${utxo.status.block_height}: ${utxo.value} sats`);
    return { mutinynet_txid: utxo.txid, vout: utxo.vout, value_sats: utxo.value, height: utxo.status.block_height, from: 'the relay\'s dispenser' };
  });

  // 3. The agent's side: init, keys, the owner adds the key, check, propose, status.
  const file = join(work, 'undo-agent.json');
  const seedFile = join(work, 'agent.seed');
  await step('agent_init', async () => {
    writeFileSync(seedFile, `${secret.seed}\n`, { mode: 0o600 });
    const init = await undo(['init', '--near-network', 'testnet', '--rpc', config.rpc[0], '--contract', contract, '--vault', vaultHex, '--account', agentAccount, '--seed-file', seedFile], file);
    if (init.code !== 0) throw new Stop('undo init failed');
    const saved = JSON.parse(readFileSync(file, 'utf8'));
    const fields = Object.keys(saved).sort().join(',');
    if (fields !== 'account_id,contract,near_network,private_key,rpc,seed,undo_agent,vault') throw new Stop(`the agent file holds other fields: ${fields}`);
    return { agent_file_fields: fields.split(','), holds: 'the vault\'s spend seed and one NEAR key: no passkey, no cold key, no full-access key' };
  });
  const saved = JSON.parse(readFileSync(file, 'utf8'));
  const fcKey = { ...fromNearSecret(saved.private_key), accountId: agentAccount };

  const key = await step('agent_key', async () => {
    const before = JSON.parse((await undo(['keys', '--json'], file)).out);
    if (before.on_chain.ok || !/not on chain/.test(before.on_chain.text)) throw new Stop(`undo keys reads the new key as ${before.on_chain.text}`);
    if (before.public_key !== fcKey.publicKey || before.methods.join(',') !== AGENT_METHODS.join(',') || before.contract !== contract) throw new Stop('undo keys printed another key, contract or method list');
    const text = (await undo(['keys'], file)).out;
    if (text.includes(saved.private_key) || text.includes(saved.seed)) throw new Stop('undo keys printed a secret');
    // The owner's step. The key, contract, methods and allowance are the ones the printed near-cli command names.
    const added = await paid(ownerOfAgent, agentAccount, [action.addCallKey(fcKey.pub, contract, AGENT_METHODS, ALLOWANCE)]);
    if (failureOf(added.result)) throw new Stop(`add the agent's key: ${failureOf(added.result)}`);
    const after = JSON.parse((await undo(['keys', '--json'], file)).out);
    if (!after.on_chain.ok) throw new Stop(`undo keys reads the added key as ${after.on_chain.text}`);
    const onChain = await accessKey(agentAccount, fcKey.publicKey);
    say(`   the owner added ${fcKey.publicKey} to ${agentAccount}, NEAR testnet tx ${added.hash}`);
    return {
      public_key: fcKey.publicKey, add_key_tx: added.hash, added_by: 'the agent account\'s full-access key, which is the payer\'s and is not in the agent file',
      permission: onChain.permission, undo_keys_reads: after.on_chain.text, near_cli_command_printed: before.near_cli,
      near_cli_command_note: 'undo keys prints this near-cli-rs command for the owner. This run added the same key with the same contract, methods and allowance through tools/lib/near.mjs; the near-cli command itself has not run on testnet',
    };
  });

  const dest1 = await step('dest1', async () => tbAddress());
  const first = await step('propose', async () => {
    const chk = await undo(['check', '--to', dest1, '--amount', '1000'], file);
    if (chk.code !== 0 || !/^tier +New/m.test(chk.out)) throw new Stop('undo check did not read tier New');
    const nonceBefore = (await views.vault(vaultHex)).spend_nonce;
    const prop = await undo(['propose', '--to', dest1, '--amount', '1000', '--memo', 'agent run on testnet'], file);
    const id = requestIdFrom(prop.out);
    const tx = txFrom(prop.out);
    if (prop.code !== 0 || !Number.isInteger(id) || !tx) throw new Stop('undo propose did not print a request and a transaction');
    if (prop.out.includes(saved.seed) || prop.out.includes(saved.private_key)) throw new Stop('undo propose printed a secret');
    const request = await until('the request to read Pending', async () => {
      const r = await views.request(vaultHex, id);
      return r?.status === 'Pending' ? r : null;
    });
    if (request.tier !== 'New' || request.amount !== 1000 || request.to !== toHex(addressToSpk(config.bitcoin_network, dest1))) throw new Stop('the request on chain is not the one the agent asked for');
    const st = await undo(['status'], file);
    if (st.code !== 0 || !new RegExp(`#${id}  New  1,000 sats to ${dest1}  waiting, unlocks in \\d+:\\d\\d`).test(st.out)) throw new Stop('undo status does not list the request as waiting');
    return {
      tx, request: id, to: dest1, amount_sats: 1000, tier: request.tier, proposed_at: request.proposed_at, unlock: request.unlock, wait_ms: request.unlock - request.proposed_at,
      spend_nonce_before: nonceBefore, signed_by: fcKey.publicKey, undo_check: chk.lines, undo_propose: prop.lines, undo_status: st.lines, at_utc: nowIso(),
    };
  });
  const r1 = first.request;
  const far = (await near.nowMs()) + 30 * 60_000;
  const view0 = await views.vault(vaultHex);

  // 4. NEAR refuses the agent's key for everything but its two methods. Nothing here is ever on chain.
  const refusals = await step('near_refusals', async () => {
    const keyBefore = await accessKey(agentAccount, fcKey.publicKey);
    const fake = { authenticator_data: '00', client_data_json: '00', signature: '00' };
    const spk1 = toHex(addressToSpk(config.bitcoin_network, dest1));
    const calls = [
      ['cancel', { vault: vaultHex, request: r1, expires_at: far, auth: { Passkey: fake } }, 'MethodNameMismatch'],
      ['cancel_all_and_rotate', { vault: vaultHex, new_k_s: toHex(randomBytes(32)), nonce: 0, expires_at: far, assertion: fake }, 'MethodNameMismatch'],
      ['set_policy', { vault: vaultHex, policy: { ...instance.policy, t_new_ms: 60_000 }, nonce: 0, expires_at: far, assertion: fake }, 'MethodNameMismatch'],
      ['clear_hold', { vault: vaultHex, request: r1, nonce: 0, expires_at: far, assertion: fake }, 'MethodNameMismatch'],
      ['add_destination', { vault: vaultHex, script: spk1, nonce: 0, expires_at: far, assertion: fake }, 'MethodNameMismatch'],
    ];
    const list = [];
    for (const [method, args, needle] of calls) {
      const out = await nearRefuses(fcKey, contract, method, args);
      if (!out.words.includes(needle)) throw new Stop(`NEAR refused ${method} with other words: ${out.words}`);
      say(`   NEAR refuses the agent key's ${method}: ${out.words}`);
      list.push({ ...out, what: `${method}, signed by the agent's NEAR key` });
    }
    const deposit = await nearRefuses(fcKey, contract, 'propose_btc', {}, 1n);
    if (!deposit.words.includes('DepositWithFunctionCall')) throw new Stop(`NEAR refused the deposit with other words: ${deposit.words}`);
    say(`   NEAR refuses a deposit from the agent's key: ${deposit.words}`);
    list.push({ ...deposit, what: 'propose_btc with 1 yoctoNEAR attached' });
    const elsewhere = await nearRefuses(fcKey, a.payer, 'propose_btc', {});
    if (!elsewhere.words.includes('ReceiverMismatch')) throw new Stop(`NEAR refused the other receiver with other words: ${elsewhere.words}`);
    say(`   NEAR refuses a call to another account from the agent's key: ${elsewhere.words}`);
    list.push({ ...elsewhere, what: 'a call to another account' });
    for (const r of list) {
      const seen = await knownToChain(r.signed_hash, agentAccount);
      if (seen.known) throw new Stop(`the refused transaction ${r.signed_hash} is on chain`);
      r.chain_knows_it = false;
      r.asked = `${seen.by}: ${seen.answer}`;
    }
    await sleep(4000);
    const keyAfter = await accessKey(agentAccount, fcKey.publicKey);
    if (keyAfter.nonce !== keyBefore.nonce) throw new Stop('the agent key\'s nonce moved: one of the refused calls landed');
    return { at_utc: nowIso(), key_nonce_before: keyBefore.nonce, key_nonce_after: keyAfter.nonce, key_allowance_before: keyBefore.permission.FunctionCall.allowance, key_allowance_after: keyAfter.permission.FunctionCall.allowance, calls: list };
  });

  // 5. What the agent can sign for those methods, sent by a full-access account. The contract refuses each.
  await step('contract_refusals', async () => {
    const agentP256 = randomBytes(32);
    const agentAssertion = (method, argsBytes, nonce) => softAssertion({
      secret: agentP256, origin: config.site_origin, rpId: config.rp_id,
      digest: intentDigest({ tag: PASSKEY_TAG, contract, vault: vaultId, method, args: argsBytes, expiresAt: far, nonce }),
    });
    const pk = view0.passkey_nonce;
    const newKs = randomBytes(32);
    const shorter = { ...view0.policy, t_known_ms: 30_000, t_new_ms: 60_000, t_new_unguarded_ms: 60_000 };
    const spk1 = addressToSpk(config.bitcoin_network, dest1);
    const attempts = [
      ['cancel, with a passkey assertion from a P-256 key the agent made', 'cancel',
        { vault: vaultHex, request: r1, expires_at: far, auth: { Passkey: agentAssertion('cancel', argBytes.cancel({ request: r1 }), null) } }, 'webauthn: bad signature'],
      ['cancel, as the cold key, signed with the agent\'s K_u', 'cancel',
        { vault: vaultHex, request: r1, expires_at: far, auth: { Cold: toHex(signSecp(coldCancelDigest({ contract, vault: vaultId, request: r1, expiresAt: far }), keys.ku.secret)) } }, 'bad K_e signature'],
      ['cancel_all_and_rotate to a spend key the agent chose', 'cancel_all_and_rotate',
        { vault: vaultHex, new_k_s: toHex(newKs), nonce: pk, expires_at: far, assertion: agentAssertion('cancel_all_and_rotate', argBytes.cancel_all_and_rotate({ newKs }), pk) }, 'webauthn: bad signature'],
      ['set_policy to shorten every wait', 'set_policy',
        { vault: vaultHex, policy: shorter, nonce: pk, expires_at: far, assertion: agentAssertion('set_policy', argBytes.set_policy({ policy: shorter }), pk) }, 'webauthn: bad signature'],
      ['add_destination, to make its own destination fast', 'add_destination',
        { vault: vaultHex, script: toHex(spk1), nonce: pk, expires_at: far, assertion: agentAssertion('add_destination', argBytes.add_destination({ script: spk1 }), pk) }, 'webauthn: bad signature'],
      ['clear_hold', 'clear_hold',
        { vault: vaultHex, request: r1, nonce: pk, expires_at: far, assertion: agentAssertion('clear_hold', argBytes.clear_hold({ request: r1 }), pk) }, 'webauthn: bad signature'],
    ];
    const list = [];
    for (const [what, method, args, needle] of attempts) {
      const sent = await paid(payer, contract, [action.call(method, args, OWNER_ATTACH_TGAS * TGAS, 0n)]);
      const failure = failureOf(sent.result);
      if (!failure || !failure.includes(needle)) throw new Stop(`the contract did not refuse the agent's ${what}: ${failure ?? 'it was accepted'}, NEAR testnet tx ${sent.hash}`);
      say(`   contract refuses the agent's ${what}: ${contractWords(failure)}, NEAR testnet tx ${sent.hash}`);
      list.push({ what, method, tx: sent.hash, sent_by: a.payer, refusal: contractWords(failure), needle });
    }
    const still = await views.request(vaultHex, r1);
    const v = await views.vault(vaultHex);
    const unchanged = still?.status === 'Pending' && still.unlock === first.unlock && JSON.stringify(v.policy) === JSON.stringify(view0.policy)
      && v.k_s === toHex(keys.ks.pub) && !v.k_s_suspended && v.known.length === 0 && v.passkey_nonce === view0.passkey_nonce;
    if (!unchanged) throw new Stop('after the attempts the request, policy or key changed');
    say('   after every attempt: the request still waits with the same unlock; the policy, the spend key and the known destinations are unchanged');
    return { at_utc: nowIso(), attempts: list, after: { request_status: still.status, request_unlock: still.unlock, policy: v.policy, spend_key_unchanged: true, spend_key_suspended: v.k_s_suspended, known_destinations: v.known.length } };
  });

  // 6. The owner's passkey cancels, through the relay.
  await step('owner_cancel', async () => {
    const expires = (await near.nowMs()) + 10 * 60_000;
    const digest = cancelDigest({ contract, vaultHex, request: r1, expiresAt: expires });
    const cancelled = await relay.call('cancel', cancelArgs({ vaultHex, request: r1, expiresAt: expires, assertion: await assert(digest) }));
    await until('the request to be gone', async () => ((await views.request(vaultHex, r1)) === null ? true : null));
    const blockNow = await near.nowMs();
    const gone = await undo(['status', '--request', String(r1)], file);
    if (gone.code !== 0 || !new RegExp(`#${r1}  not in the queue`).test(gone.out)) throw new Stop('undo status does not read the request gone');
    say(`   the owner's passkey cancelled request ${r1} through the relay, NEAR testnet tx ${cancelled.hash} [software authenticator]`);
    return { tx: cancelled.hash, through: config.relay, relay_account: status.relayAccount, request: r1, ms_before_unlock: first.unlock - blockNow, passkey: 'software authenticator', undo_status: gone.lines, at_utc: nowIso() };
  });

  // 7. A second request, then the owner rotates: the agent is refused from then on.
  if (!state.secret.rotate_seed) {
    state.secret.rotate_seed = toHex(randomBytes(32));
    save();
  }
  const newKs = spendKeys(fromHex(state.secret.rotate_seed)).ks.pub;
  const dest2 = await step('dest2', async () => tbAddress());
  const second = await step('propose_again', async () => {
    const all = await undo(['propose', '--to', dest2, '--amount', 'all'], file);
    const id = requestIdFrom(all.out);
    const tx = txFrom(all.out);
    if (all.code !== 0 || !Number.isInteger(id) || !tx) throw new Stop('the second undo propose did not print a request and a transaction');
    const request = await until('the second request to read Pending', async () => {
      const r = await views.request(vaultHex, id);
      return r?.status === 'Pending' ? r : null;
    });
    return { tx, request: id, to: dest2, amount_sats: request.amount, fee_sats: request.fee, tier: request.tier, wait_ms: request.unlock - request.proposed_at, unlock: request.unlock, undo_propose: all.lines, at_utc: nowIso() };
  });
  const r2 = second.request;

  const rotated = await step('owner_rotate', async () => {
    const v = await views.vault(vaultHex);
    const expires = (await near.nowMs()) + 10 * 60_000;
    const digest = rotateDigest({ contract, vaultHex, newKs, nonce: v.passkey_nonce, expiresAt: expires });
    const sent = await relay.call('cancel_all_and_rotate', rotateArgs({ vaultHex, newKs, nonce: v.passkey_nonce, expiresAt: expires, assertion: await assert(digest) }));
    const after = await until('the spend key to read suspended', async () => {
      const w = await views.vault(vaultHex);
      return w.k_s_suspended ? w : null;
    });
    const grant = after.grant_list.at(-1);
    if (!Number.isInteger(grant?.id) || !Number.isInteger(grant?.ready_at)) throw new Stop('the vault lists no grant for the rotation');
    const st = await undo(['status'], file);
    const one = await undo(['status', '--request', String(r2)], file);
    if (!/^spend key: suspended by the owner's rotation/m.test(st.out) || !new RegExp(`#${r2}  .*(not in the queue|dead: the owner's rotation)`).test(one.out)) throw new Stop('undo status does not read the key suspended and the request dead');
    say(`   the owner's passkey rotated the spend key through the relay, NEAR testnet tx ${sent.hash} [software authenticator]`);
    return { tx: sent.hash, through: config.relay, relay_account: status.relayAccount, grant: grant.id, grant_ready_at: grant.ready_at, new_k_s: toHex(newKs), passkey: 'software authenticator', undo_status: st.lines, undo_status_request: one.lines, at_utc: nowIso() };
  });

  await step('after_rotation', async () => {
    const v = await views.vault(vaultHex);
    const nonce = v.spend_nonce;
    const refused = await undo(['propose', '--to', dest1, '--amount', '1000'], file);
    const viaCheck = /^refused by the contract: SpendKeySuspended$/m.test(refused.out) && /^its free check_propose view said so: nothing signed, nothing sent$/m.test(refused.out);
    if (refused.code !== 1 || !viaCheck || (await views.vault(vaultHex)).spend_nonce !== nonce) throw new Stop('undo propose after the rotation was not refused in check_propose');
    // An agent that skips the check and sends anyway, with its own function-call key. This one lands, and fails.
    const script = fromHex(await views.script(vaultHex));
    const fee = feeFor({ inputs: 1, destLen: 22, withChange: false, rate: 2, cap: v.policy.fee_cap_tx });
    const direct = signSpend.propose({
      seed: fromHex(secret.seed), contract, vault: vaultId, script, spk: fromHex(v.script_pubkey), inputs: [{ txid: coin.mutinynet_txid, vout: coin.vout, value: coin.value_sats }],
      to: addressToSpk(config.bitcoin_network, dest1), amount: coin.value_sats - fee, change: null, nonce, expiresAt: (await near.nowMs()) + 10 * 60_000, memo: null,
    });
    const skipped = await near.sendAndWait(fcKey, contract, [action.call('propose_btc', direct.args, 30n * TGAS, 0n)]);
    const failure = failureOf(skipped.result);
    if (!failure || !failure.includes('SpendKeySuspended')) throw new Stop(`propose_btc from the agent's key after the rotation: ${failure ?? 'it was accepted'}, NEAR testnet tx ${skipped.hash}`);
    say(`   propose_btc sent straight from the agent's key, skipping the check, is refused by the contract: ${contractWords(failure)}, NEAR testnet tx ${skipped.hash}`);
    return { undo_propose: refused.lines, direct_tx: skipped.hash, direct_refusal: contractWords(failure), signed_by: fcKey.publicKey, at_utc: nowIso() };
  });

  await step('after_the_new_key_lands', async () => {
    say(`   waiting for the rotation's wait to end on the contract's clock (T_known, ${instance.policy.t_known_ms / 1000} s)`);
    await until('the grant to be ready', async () => ((await near.nowMs()) >= rotated.grant_ready_at + 1000 ? true : null), { timeoutMs: instance.policy.t_known_ms + 180_000, everyMs: 3000 });
    if (!state.sent_apply_tx) {
      const sent = await paid(payer, contract, [action.call('apply_grant', { vault: vaultHex, grant: rotated.grant }, OWNER_ATTACH_TGAS * TGAS, 0n)]);
      if (failureOf(sent.result)) throw new Stop(`apply_grant: ${failureOf(sent.result)}, NEAR testnet tx ${sent.hash}`);
      state.sent_apply_tx = sent.hash;
      save();
    }
    const landed = { hash: state.sent_apply_tx };
    const v = await until('the new spend key to read installed', async () => {
      const w = await views.vault(vaultHex);
      return w.k_s === toHex(newKs) && !w.k_s_suspended ? w : null;
    });
    const late = await undo(['propose', '--to', dest1, '--amount', '1000'], file);
    const tx = txFrom(late.out);
    if (late.code !== 1 || !/^refused by the contract: Smart contract panicked: bad K_s signature$/m.test(late.out) || !tx) throw new Stop('undo propose after the new key landed was not refused with bad K_s signature');
    const st = await undo(['status'], file);
    if (!/^spend key: not this agent's/m.test(st.out)) throw new Stop('undo status does not say the key is no longer the agent\'s');
    say(`   after the new key landed (NEAR testnet tx ${landed.hash}), the agent's propose is refused: bad K_s signature, NEAR testnet tx ${tx}`);
    return { apply_grant_tx: landed.hash, apply_grant_sent_by: a.payer, vault_spend_key_is_the_new_one: v.k_s === toHex(newKs), propose_tx: tx, propose_refusal: 'Smart contract panicked: bad K_s signature', undo_propose: late.lines, undo_status: st.lines, at_utc: nowIso() };
  });

  await step('coin_after', async () => {
    const out = await esplora.outspend(coin.mutinynet_txid, coin.vout);
    if (out?.spent !== false) throw new Stop('the vault\'s coin does not read unspent');
    return { mutinynet_txid: coin.mutinynet_txid, vout: coin.vout, spent: false, read_utc: nowIso() };
  });

  state.finished_utc = state.finished_utc ?? nowIso();
  save();
  writeProof();
}

/** The public record. Built field by field from the steps' own records, then checked for this run's secrets. */
function writeProof() {
  const p = state.pub;
  const proof = {
    schema: SCHEMA,
    what: 'CLAIMS C14 on NEAR testnet: an agent holding a vault\'s spend seed and one NEAR function-call key proposes a spend, and cannot cancel, rotate or shorten the wait. Written by agent/test/testnet-c14.mjs from one live run',
    labels: ['live-testnet', 'live-mutinynet'],
    notes: [
      'The owner\'s passkey in this run is a software authenticator in the driver\'s process, not a phone.',
      'A transaction NEAR refuses for its access key is never broadcast, so near_refusals holds no transaction on chain: each entry keeps the hash it was signed with, the RPC\'s error as it came, and the nodes\' answer that they do not know that hash.',
      'Every other hash here is a NEAR testnet transaction or a Mutinynet txid, and ./verify.sh A fetches the NEAR ones again from archival RPC.',
    ],
    ran_utc: { started: state.started_utc, finished: state.finished_utc },
    contract: p.contract,
    relay: { url: config.relay, account: p.vault.guard },
    agent: { ...p.agent_account, file: p.agent_init, function_call_key: p.agent_key },
    vault: { ...p.vault, coin: p.coin },
    propose: p.propose,
    near_refusals: p.near_refusals,
    contract_refusals: p.contract_refusals,
    owner_cancel: p.owner_cancel,
    rotation: { propose_again: p.propose_again, owner_rotate: p.owner_rotate, after_rotation: p.after_rotation, after_the_new_key_lands: p.after_the_new_key_lands },
    coin_after: p.coin_after,
  };
  const text = `${JSON.stringify(proof, null, 2)}\n`;
  const secrets = [state.secret.vault.seed, state.secret.vault.cold, state.secret.vault.passkey, state.secret.rotate_seed];
  const agentFile = join(work, 'undo-agent.json');
  if (existsSync(agentFile)) {
    const saved = JSON.parse(readFileSync(agentFile, 'utf8'));
    secrets.push(saved.private_key, saved.private_key.slice('ed25519:'.length));
  }
  for (const s of secrets) if (s && text.includes(s)) throw new Stop('the proof would hold one of this run\'s secrets: nothing written');
  if (text.includes(work)) throw new Stop('the proof would hold a local folder: nothing written');
  writeFileSync(outPath, text);
  say(`wrote ${outPath.startsWith(REPO) ? relative(REPO, outPath) : 'the proof file'}`);
}

try {
  await main();
  say('AGENT TESTNET RUN OK [live-testnet] [live-mutinynet]');
} catch (err) {
  const why = err.code ? `${err.code}: ${err.message}${err.verbatim ? ` | ${err.verbatim}` : ''}${err.resetsAt ? ` (resets ${new Date(err.resetsAt).toISOString()})` : ''}` : err.message;
  say(`AGENT TESTNET RUN STOPPED: ${why}`);
  if (!(err instanceof Stop) && !err.code) console.error(err.stack);
  process.exit(1);
}
