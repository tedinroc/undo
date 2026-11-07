#!/usr/bin/env node
// The watcher against the real wasm on a local NEAR node, with the mock signer and tools/test/mock-ntfy.mjs. It
// proposes three ways and wants exactly one alert for each: with near-cli from a stranger's account and no relay,
// through the relay's own handler, and directly from tools/lib. Then a restart must send nothing twice, and a dry
// run must send nothing at all. It records each alert's latency: the propose's block time to the mock ntfy's
// answer. Labelled [mock-signer]. It says nothing about public RPC, ntfy.sh, a phone or iOS.
//
//   node tools/test/watch-sandbox.mjs [--relay-tree DIR] [--samples N] [--poll-ms N] [--report FILE] [--keep]
//
// Needs NEAR_SANDBOX_BIN_PATH, UNDO_WASM_DIR (undo_vault.wasm and mock_signer.wasm, default <target>/near), UNDO_NEAR_BIN (near-cli),
// and UNDO_LIBLZMA_DIR where the sandbox binary links an outside liblzma. The relay leg imports
// site/functions/_relay/handler.mjs from --relay-tree, default this repo; a tree without it prints SKIP for that
// leg. near-cli runs with a throwaway HOME whose only network is this sandbox, under sandbox-exec on macOS with
// all but localhost denied. Starts one NEAR node and stops it on exit and on SIGINT or SIGTERM. Run it with
// NODE_USE_SYSTEM_CA unset: under a sandbox that blocks the keychain, Node 22 hangs at exit after any fetch.
import { spawn, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { parseArgs } from '../lib/args.mjs';
import { base58Encode, concat, fromHex, toHex, utf8 } from '../lib/bytes.mjs';
import { randomBytes, sha256 } from '../lib/crypto.mjs';
import { action, failureOf, keyFromSecret, loadKeyFile, NEAR, Near, TGAS } from '../lib/near.mjs';
import { newOwnerKeys, throwawayOperatorPasskey, VaultClient } from '../lib/vault-client.mjs';
import { addressOf, PREFIX_CHARS } from '../lib/watch.mjs';
import { startMockNtfy } from './mock-ntfy.mjs';

const TOOLS = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const REPO = resolve(TOOLS, '..');
const WATCH = join(TOOLS, 'watch.mjs');
const a = parseArgs(process.argv.slice(2), { 'relay-tree': 'text', samples: 'int', 'poll-ms': 'int', report: 'text', keep: 'flag', protocol: 'int' });
const SAMPLES = a.samples ?? 4;
const POLL_MS = a['poll-ms'] ?? 2000;
const PROTOCOL = a.protocol ?? 88;
const RELAY_TREE = resolve(a['relay-tree'] ?? REPO);
const PAGE_ORIGIN = 'http://localhost:8788';
const RP_ID = 'localhost';
const B58 = '[1-9A-HJ-NP-Za-km-z]';

if (!process.env.NEAR_SANDBOX_BIN_PATH) {
  console.log('SKIP watch sandbox: set NEAR_SANDBOX_BIN_PATH');
  process.exit(0);
}
// The same default as tools/test/run-sandbox.sh.
const WASM_DIR = process.env.UNDO_WASM_DIR || join(process.env.CARGO_TARGET_DIR || join(REPO, 'target'), 'near');
for (const f of ['undo_vault.wasm', 'mock_signer.wasm']) {
  if (!existsSync(join(WASM_DIR, f))) {
    console.log(`FAIL watch sandbox: no ${f}, run scripts/build.sh or set UNDO_WASM_DIR`);
    process.exit(2);
  }
}

const results = [];
const check = (id, name, ok, detail = '') => {
  results.push({ id, name, ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'} ${id} [mock-signer] ${name}${ok ? (detail ? `: ${detail}` : '') : ` -- ${detail}`}`);
  return ok;
};
const skip = (id, name, why) => {
  results.push({ id, name, ok: null, detail: why });
  console.log(`SKIP ${id} [mock-signer] ${name}: ${why}`);
};
const sleep = (ms) => new Promise((r) => { setTimeout(r, ms); });
const childEnv = () => {
  const env = { ...process.env };
  // Under a sandbox that blocks the keychain this makes Node 22 hang at exit after any fetch.
  delete env.NODE_USE_SYSTEM_CA;
  return env;
};
const freePort = () => new Promise((res) => {
  const s = createServer().listen(0, '127.0.0.1', () => {
    const { port } = s.address();
    s.close(() => res(port));
  });
});

const work = mkdtempSync(join(tmpdir(), 'undo-watch-sandbox-'));
const children = new Set();
let ntfy = null;
async function cleanup() {
  for (const c of children) c.kill('SIGKILL');
  await ntfy?.stop();
  if (!a.keep) rmSync(work, { recursive: true, force: true });
}
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { cleanup().finally(() => process.exit(130)); });

// ---------------------------------------------------------------- the node

async function startNode() {
  const bin = process.env.NEAR_SANDBOX_BIN_PATH;
  const env = { ...process.env, ...(process.env.UNDO_LIBLZMA_DIR ? { DYLD_LIBRARY_PATH: process.env.UNDO_LIBLZMA_DIR } : {}) };
  const home = join(work, 'near-home');
  const init = spawnSync(bin, ['--home', home, 'init', '--fast'], { env, encoding: 'utf8' });
  if (init.status !== 0) throw new Error(`sandbox init failed: ${init.stderr.slice(-400)}`);
  const genesisPath = join(home, 'genesis.json');
  const genesis = JSON.parse(readFileSync(genesisPath, 'utf8'));
  genesis.protocol_version = PROTOCOL;
  genesis.epoch_length = 100000;
  writeFileSync(genesisPath, JSON.stringify(genesis));
  const rpcPort = await freePort();
  const netPort = await freePort();
  const child = spawn(bin, ['--home', home, 'run', '--rpc-addr', `127.0.0.1:${rpcPort}`, '--network-addr', `127.0.0.1:${netPort}`], { env, stdio: ['ignore', 'ignore', 'pipe'] });
  children.add(child);
  const rpc = `http://127.0.0.1:${rpcPort}`;
  for (let i = 0; i < 120; i += 1) {
    try {
      const status = await (await fetch(`${rpc}/status`)).json();
      if (status.protocol_version === PROTOCOL && status.sync_info?.latest_block_height > 1) return { rpc, home, chainId: status.chain_id, version: status.version?.version };
    } catch {
      // Not up yet.
    }
    await sleep(500);
  }
  throw new Error('the sandbox node did not come up');
}

// ---------------------------------------------------------------- the watcher, as a child

function startWatcher(config, statePath, extra = []) {
  const child = spawn(process.execPath, [WATCH, 'run', '--config', config, '--state', statePath, '--poll-ms', String(POLL_MS), ...extra], { stdio: ['ignore', 'pipe', 'pipe'], env: childEnv() });
  children.add(child);
  const out = { text: '', err: '' };
  child.stdout.on('data', (d) => { out.text += d; });
  child.stderr.on('data', (d) => { out.err += d; });
  const closed = new Promise((r) => child.on('close', (status, signal) => { children.delete(child); r({ status, signal }); }));
  return { child, out, closed };
}

async function until(fn, timeoutMs, what) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    const v = await fn();
    if (v) return v;
    await sleep(100);
  }
  throw new Error(`timed out: ${what}`);
}

const readLog = (statePath) => {
  const path = statePath.replace(/\.json$/, '.log.jsonl');
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
};
const fileHash = (path) => (existsSync(path) ? createHash('sha256').update(readFileSync(path)).digest('hex') : null);

// ---------------------------------------------------------------- near-cli, boxed in

function nearCli({ rpc, cliHome }) {
  const bin = process.env.UNDO_NEAR_BIN;
  if (!bin) return null;
  const toml = `version = "5"\ncredentials_home_dir = "${join(cliHome, '.near-credentials')}"\n\n[network_connection.sandbox]\nnetwork_name = "sandbox"\nrpc_url = "${rpc}/"\nwallet_url = "${rpc}/"\nexplorer_transaction_url = "${rpc}/"\n`;
  // macOS keeps near-cli's config under Application Support, Linux under .config. Only this one network exists.
  for (const dir of [join(cliHome, 'Library', 'Application Support', 'near-cli'), join(cliHome, '.config', 'near-cli')]) {
    mkdirSync(dir, { recursive: true });
    writeFileSync(join(dir, 'config.toml'), toml);
  }
  const boxed = process.platform === 'darwin' && existsSync('/usr/bin/sandbox-exec');
  const profile = '(version 1)(allow default)(deny network*)(allow network* (remote ip "localhost:*"))(allow network* (local ip "localhost:*"))';
  return {
    boxed,
    version: spawnSync(bin, ['--version'], { encoding: 'utf8', env: { HOME: cliHome, PATH: '/usr/bin:/bin' } }).stdout.trim(),
    run(args) {
      const cmd = boxed ? ['/usr/bin/sandbox-exec', ['-p', profile, bin, ...args]] : [bin, args];
      return spawnSync(cmd[0], cmd[1], { encoding: 'utf8', timeout: 90_000, input: '', env: { HOME: cliHome, XDG_CONFIG_HOME: join(cliHome, '.config'), PATH: '/usr/bin:/bin' } });
    },
  };
}

// ---------------------------------------------------------------- main

async function main() {
  const wasm = readFileSync(join(WASM_DIR, 'undo_vault.wasm'));
  const mockWasm = readFileSync(join(WASM_DIR, 'mock_signer.wasm'));
  const wasmSha = createHash('sha256').update(wasm).digest('hex');
  console.log(`watch sandbox: undo_vault.wasm sha256 ${wasmSha.slice(0, 8)}, protocol ${PROTOCOL}, poll ${POLL_MS} ms`);
  const nodeInfo = await startNode();
  const near = new Near([nodeInfo.rpc], { timeoutMs: 30_000 });
  const root = loadKeyFile(join(nodeInfo.home, 'validator_key.json'));
  const account = async (name, amount) => {
    const key = keyFromSecret(randomBytes(32));
    const accountId = `${name}${toHex(randomBytes(3))}.${root.accountId}`;
    const sent = await near.sendAndWait(root, accountId, [action.createAccount(), action.transfer(BigInt(amount) * NEAR), action.addFullKey(key.pub)]);
    if (failureOf(sent.result)) throw new Error(failureOf(sent.result));
    return { ...key, accountId };
  };
  const mock = await account('mock', 30);
  await near.sendAndWait(mock, mock.accountId, [action.deploy(mockWasm), action.call('new', { secret_hex: toHex(randomBytes(32)), mode: 'Yield' }, 100n * TGAS, 0n)]);
  const undo = await account('undo', 40);
  const relay = await account('relay', 30);
  const thief = await account('thief', 10);
  const deployed = await near.sendAndWait(undo, undo.accountId, [
    action.deploy(wasm),
    action.call('new', {
      preset: 'TestCoin', operator: relay.accountId, restrict_create: false, signer: mock.accountId, domain_id: 0, sign_tgas: 30, callback_tgas: 10,
      derive_tgas: 30, network: 'regtest', origins: [PAGE_ORIGIN], outflow_cap_24h: 1_000_000, operator_passkey: throwawayOperatorPasskey(RP_ID),
    }, 100n * TGAS, 0n),
  ]);
  if (failureOf(deployed.result)) throw new Error(`deploy failed: ${failureOf(deployed.result)}`);
  const instance = await near.view(undo.accountId, 'instance');
  const client = new VaultClient({ near, contract: undo.accountId, signer: mock.accountId, instance, origin: PAGE_ORIGIN, rpId: RP_ID });
  const vault = await client.create(relay, newOwnerKeys(), { depositMilli: 300 });
  if (vault.view?.active !== true) throw new Error(`the vault did not activate: ${failureOf(vault.result)}`);
  const thiefSpk = fromHex(`0014${toHex(sha256(utf8('undo-test-only:watch-sandbox-thief'))).slice(0, 40)}`);
  const thiefPrefix = addressOf('regtest', toHex(thiefSpk)).slice(0, PREFIX_CHARS);

  ntfy = await startMockNtfy();
  const cfgDir = join(work, 'watch');
  const config = join(cfgDir, 'config.json');
  const init = spawnSync(process.execPath, [WATCH, 'init', '--network', 'local', '--contract', undo.accountId, '--vault', vault.hex, '--rpc', nodeInfo.rpc,
    '--page-origin', PAGE_ORIGIN, '--ntfy-server', ntfy.url, '--config', config, '--poll-ms', String(POLL_MS)], { encoding: 'utf8', env: childEnv() });
  check('W01', 'init wrote a config for this vault, mode 600, with a 22-character topic', init.status === 0 && /^[A-Za-z0-9]{22}$/.test(JSON.parse(readFileSync(config, 'utf8')).ntfy_topic), init.stderr);
  const topic = JSON.parse(readFileSync(config, 'utf8')).ntfy_topic;
  const statePath = join(cfgDir, 'state.json');

  let watcher = startWatcher(config, statePath);
  await until(() => /READY/.test(watcher.out.text), 30_000, 'the watcher\'s first read');

  /** A made-up coin, every coin to the thief, signed with the vault's spend seed: what a stolen key proposes. */
  const proposal = async (label) => {
    const coin = { txid: toHex(sha256(utf8(`undo-test-only:watch-coin:${label}:${vault.spendNonce}`))), vout: 0, value: 2000 };
    return client.proposeArgs(vault, { coins: [coin], to: thiefSpk, amount: 2000 - 950, change: null });
  };
  // Wrapped, because the first request's id is 0.
  const newestPending = async (before) => (await until(async () => {
    const v = await near.view(undo.accountId, 'vault', { vault: vault.hex });
    const fresh = v.pending.filter((id) => !before.includes(id));
    return fresh.length === 1 ? { id: fresh[0] } : null;
  }, 20_000, 'the new request in the queue')).id;
  const pendingNow = async () => (await near.view(undo.accountId, 'vault', { vault: vault.hex })).pending;
  const alertsFor = (id) => ntfy.messages.filter((m) => m.click === `${PAGE_ORIGIN}/p/#v=${vault.hex}&r=${id}`);
  const cancel = async (id) => {
    const expires = (await near.nowMs()) + 10 * 60_000;
    const sent = await near.sendAndWait(relay, undo.accountId, [action.call('cancel', client.cancelArgsPasskey(vault, id, expires), 30n * TGAS, 0n)]);
    if (failureOf(sent.result)) throw new Error(`cancel failed: ${failureOf(sent.result)}`);
  };
  /** Waits for the alert, then two more polls, and checks there is still exactly one. */
  const oneAlert = async (id, timeoutMs = 20_000) => {
    const msg = await ntfy.waitFor((m) => m.click === `${PAGE_ORIGIN}/p/#v=${vault.hex}&r=${id}`, timeoutMs);
    await sleep(POLL_MS * 2 + 300);
    return { msg, count: alertsFor(id).length };
  };
  const words = (msg, id) => {
    const [first, second, third] = msg.message.split('\n');
    const req = /^2,000 sats to (\S+)… unlocks in ([0-9]+):([0-9]{2})$/.exec(first);
    return {
      ok: Boolean(req) && req[1] === thiefPrefix && second === 'local test coins, mock signer. Not you? Tap to cancel.' && third === `${PAGE_ORIGIN}/p/#v=${vault.hex}&r=${id}`
        && msg.title === 'Undo for Bitcoin: a spend is waiting' && msg.topic === topic && !msg.click.includes('?'),
      left: req ? Number(req[2]) * 60 + Number(req[3]) : null,
      first,
    };
  };

  // ---- 1. near-cli, from a stranger's account, no relay anywhere
  const cli = nearCli({ rpc: nodeInfo.rpc, cliHome: join(work, 'cli-home') });
  if (!cli) {
    skip('W02', 'a propose_btc sent with near-cli alerts once', 'set UNDO_NEAR_BIN');
  } else {
    const before = await pendingNow();
    const args = await proposal('cli');
    const keyFile = join(work, 'cli-home', 'thief-key.json');
    writeFileSync(keyFile, JSON.stringify({ account_id: thief.accountId, public_key: thief.publicKey, private_key: `ed25519:${base58Encode(concat(thief.secret, thief.pub))}` }), { mode: 0o600 });
    const out = cli.run(['contract', 'call-function', 'as-transaction', undo.accountId, 'propose_btc', 'json-args', JSON.stringify(args), 'prepaid-gas', '40 Tgas', 'attached-deposit', '0 NEAR',
      'sign-as', thief.accountId, 'network-config', 'sandbox', 'sign-with-access-key-file', keyFile, 'send']);
    const text = `${out.stdout}${out.stderr}`;
    writeFileSync(join(work, 'near-cli.out'), text);
    const hash = new RegExp(`Transaction ID:\\s*(${B58}{43,44})`).exec(text)?.[1] ?? null;
    const tx = hash ? await near.txStatus(hash, thief.accountId, 'EXECUTED_OPTIMISTIC').catch((err) => ({ error: err.message })) : null;
    const failed = tx ? (tx.error ?? failureOf(tx)) : 'no transaction id in near-cli\'s output';
    if (check('W02', `near-cli ${cli.version}${cli.boxed ? ', localhost only under sandbox-exec' : ''} sent propose_btc signed by a stranger's account, and the contract took it`, out.status === 0 && !failed, `local NEAR sandbox tx ${hash ?? 'none'}${failed ? `: ${String(failed).slice(0, 400)}` : ''}`)) {
      vault.spendNonce += 1;
      const id = await newestPending(before);
      check('W03', 'its signer was the stranger, not the relay', tx.transaction.signer_id === thief.accountId && tx.transaction.signer_id !== relay.accountId, `signer ${tx.transaction.signer_id}`);
      const { msg, count } = await oneAlert(id);
      const w = words(msg, id);
      check('W04', 'the watcher sent exactly one alert for the near-cli request, with the amount, destination prefix, unlocks in M:SS and the phone link', count === 1 && w.ok, `${count} alert(s): "${w.first}"`);
      await cancel(id);
    }
  }

  // ---- 2. through the relay's handler, from the web branch
  const handlerPath = join(RELAY_TREE, 'site/functions/_relay/handler.mjs');
  const shimPath = join(RELAY_TREE, 'site/test/do-shim.mjs');
  if (!existsSync(handlerPath) || !existsSync(shimPath)) {
    skip('W05', 'a propose_btc through the relay alerts once', 'this tree has no site/functions/_relay: merge the web branch or pass --relay-tree');
  } else {
    const { makeRelay } = await import(pathToFileURL(handlerPath).href);
    const { localStateNamespace } = await import(pathToFileURL(shimPath).href);
    // Its own key on the relay account, as on the live relay: two senders on one key would trip each other's nonces.
    const relayKey = keyFromSecret(randomBytes(32));
    const added = await near.sendAndWait(relay, relay.accountId, [action.addFullKey(relayKey.pub)]);
    if (failureOf(added.result)) throw new Error(`relay key: ${failureOf(added.result)}`);
    const handler = makeRelay({
      local: true, CONTRACT_ID: undo.accountId, NEAR_RPC_URLS: nodeInfo.rpc, RELAY_ACCOUNT: relay.accountId,
      RELAY_GENERAL_KEY: `ed25519:${base58Encode(relayKey.secret)}`, RELAY_OWNER_KEY: `ed25519:${base58Encode(relayKey.secret)}`,
      IP_SALT: 'undo-test-only:watch-sandbox', POW_BITS: 8, UNDO_STATE: localStateNamespace(),
    });
    const before = await pendingNow();
    const args = await proposal('relay');
    const res = await handler(new Request(`${PAGE_ORIGIN}/api/relay`, {
      method: 'POST', headers: { 'content-type': 'application/json', origin: PAGE_ORIGIN, 'cf-connecting-ip': '127.0.0.1' }, body: JSON.stringify({ method: 'propose_btc', args }),
    }));
    const answer = await res.json();
    if (check('W05', `the relay handler (${RELAY_TREE === REPO ? 'this tree' : 'from --relay-tree'}, in Node, not workerd) took propose_btc and sent it from the relay's account`, res.status === 200 && answer.ok === true, JSON.stringify(answer))) {
      vault.spendNonce += 1;
      const id = await newestPending(before);
      const tx = await near.txStatus(answer.hash, relay.accountId, 'EXECUTED_OPTIMISTIC');
      check('W06', 'its signer was the relay', tx.transaction.signer_id === relay.accountId, `local NEAR sandbox tx ${answer.hash}`);
      const { msg, count } = await oneAlert(id);
      const w = words(msg, id);
      check('W07', 'the watcher sent exactly one alert for the relayed request, worded the same', count === 1 && w.ok, `${count} alert(s): "${w.first}"`);
      await cancel(id);
    }
  }

  // ---- 3. more proposals straight from tools/lib, for the latency numbers
  let samplesOk = 0;
  for (let i = 0; i < SAMPLES; i += 1) {
    const { request: id } = await client.propose(thief, vault, await proposal(`sample-${i}`));
    const { count } = await oneAlert(id);
    if (count === 1) samplesOk += 1;
    await cancel(id);
  }
  check('W08', `${SAMPLES} more proposals sent straight from tools/lib each got exactly one alert`, samplesOk === SAMPLES, `${samplesOk}/${SAMPLES}`);

  const pushedSoFar = readLog(statePath).filter((e) => e.event === 'pushed');
  const gone = readLog(statePath).filter((e) => e.event === 'gone');
  await until(() => readLog(statePath).filter((e) => e.event === 'gone').length >= pushedSoFar.length, POLL_MS * 3 + 2000, 'the GONE lines').catch(() => null);
  const goneNow = readLog(statePath).filter((e) => e.event === 'gone');
  check('W09', 'every cancelled request was logged as gone, cancelled, with the time from alert to cancel', goneNow.length === pushedSoFar.length && goneNow.every((e) => e.why === 'cancelled or swept' && e.after_push_ms >= 0), `${goneNow.length}/${pushedSoFar.length} (had ${gone.length} before the wait)`);

  // ---- 4. a restart sends nothing twice
  const before = await pendingNow();
  const { request: kept } = await client.propose(thief, vault, await proposal('kept'));
  const keptAlert = await oneAlert(kept);
  watcher.child.kill('SIGTERM');
  const stopped = await watcher.closed;
  check('W10', 'the watcher stops cleanly on SIGTERM and keeps its state', stopped.status === 0 && /STOPPED/.test(watcher.out.text), `exit ${stopped.status} ${stopped.signal ?? ''} ${watcher.out.err.slice(-200)}`);
  const firstRunText = watcher.out.text + watcher.out.err;
  const countBefore = ntfy.messages.length;
  watcher = startWatcher(config, statePath);
  await until(() => /READY/.test(watcher.out.text), 30_000, 'the restarted watcher\'s first read');
  await sleep(POLL_MS * 3 + 500);
  check('W11', 'after a restart, with the alerted request still pending, nothing is sent again', ntfy.messages.length === countBefore && alertsFor(kept).length === 1 && keptAlert.count === 1, `${ntfy.messages.length - countBefore} new`);
  const after = await pendingNow();
  const { request: fresh } = await client.propose(thief, vault, await proposal('after-restart'));
  const freshAlert = await oneAlert(fresh);
  check('W12', 'the restarted watcher sends exactly one alert for a new request', freshAlert.count === 1 && ntfy.messages.length === countBefore + 1, `pending before ${JSON.stringify(before)} then ${JSON.stringify(after)}`);
  watcher.child.kill('SIGTERM');
  await watcher.closed;
  const secondRunText = watcher.out.text + watcher.out.err;

  // ---- 5. a dry run prints and sends nothing
  const realBefore = fileHash(statePath);
  const sentBefore = ntfy.messages.length;
  const dry = spawnSync(process.execPath, [WATCH, 'run', '--config', config, '--dry-run', '--once'], { encoding: 'utf8', env: childEnv(), timeout: 60_000 });
  const printed = [kept, fresh].every((id) => dry.stdout.includes(`DRY RUN r=${id} [mock-signer] would push:`)) && dry.stdout.includes(`${thiefPrefix}…`) && /unlocks in [0-9]+:[0-9]{2}/.test(dry.stdout);
  check('W13', 'a dry run prints both pending alerts, sends nothing and leaves the real state file as it was', dry.status === 0 && printed && ntfy.messages.length === sentBefore && fileHash(statePath) === realBefore, dry.stderr.slice(-300));
  await cancel(kept);
  await cancel(fresh);

  // ---- the topic stays in the config
  const outputs = [firstRunText, secondRunText, dry.stdout, dry.stderr, readFileSync(statePath, 'utf8'), readFileSync(statePath.replace(/\.json$/, '.log.jsonl'), 'utf8')];
  check('W14', 'no watcher output, state file or JSON log holds the topic', outputs.every((t) => !t.includes(topic)));

  // ---- latency
  const pushed = readLog(statePath).filter((e) => e.event === 'pushed');
  const lat = pushed.map((e) => e.latency_ms).sort((x, y) => x - y);
  const det = pushed.map((e) => e.detect_ms).sort((x, y) => x - y);
  const pus = pushed.map((e) => e.push_ms).sort((x, y) => x - y);
  const mockSide = pushed.map((e) => {
    const m = ntfy.messages.find((x) => x.click === `${PAGE_ORIGIN}/p/#v=${vault.hex}&r=${e.request}`);
    return m ? m.receivedAt - e.proposed_at : null;
  });
  const median = (xs) => (xs.length ? (xs.length % 2 ? xs[(xs.length - 1) / 2] : (xs[xs.length / 2 - 1] + xs[xs.length / 2]) / 2) : null);
  const s = (ms) => (ms === null ? '-' : `${(ms / 1000).toFixed(2)} s`);
  console.log('');
  console.log(`LATENCY [mock-signer] ${pushed.length} alerts, poll ${POLL_MS} ms, the propose's block time (local NEAR sandbox) to the mock ntfy's answer:`);
  console.log(`  total  median ${s(median(lat))}, min ${s(lat[0] ?? null)}, max ${s(lat.at(-1) ?? null)}`);
  console.log(`  until the watcher's read saw it  median ${s(median(det))}, max ${s(det.at(-1) ?? null)}`);
  console.log(`  from that read to ntfy's answer  median ${s(median(pus))}, max ${s(pus.at(-1) ?? null)}`);
  console.log(`  each: ${pushed.map((e) => `r=${e.request} ${s(e.latency_ms)}`).join(', ')}`);
  check('W15', 'the latency log agrees with the mock: each alert arrived after its block and before the watcher heard back', pushed.every((e, i) => mockSide[i] !== null && mockSide[i] >= 0 && mockSide[i] <= e.latency_ms));

  const fails = results.filter((r) => r.ok === false).length;
  const skips = results.filter((r) => r.ok === null).length;
  const passes = results.filter((r) => r.ok === true).length;
  const report = {
    label: 'mock-signer', note: 'local NEAR sandbox and a mock ntfy on 127.0.0.1. Says nothing about public RPC, ntfy.sh, a phone or iOS.',
    at: new Date().toISOString(), wasm_sha256: wasmSha, protocol: PROTOCOL, near_node: nodeInfo.version ?? null, near_cli: cli?.version ?? null, near_cli_boxed: cli?.boxed ?? null,
    relay_tree: RELAY_TREE === REPO ? 'this tree' : 'another tree', poll_ms: POLL_MS, passes, fails, skips, results,
    latency_ms: pushed.map((e) => ({ request: e.request, total: e.latency_ms, detect: e.detect_ms, push: e.push_ms, mock_received: mockSide[pushed.indexOf(e)] })),
    median_ms: { total: median(lat), detect: median(det), push: median(pus) },
  };
  if (a.report) writeFileSync(a.report, `${JSON.stringify(report, null, 1)}\n`);
  console.log('');
  console.log(`WATCH SANDBOX ${fails === 0 ? 'OK' : 'FAILED'} [mock-signer]: ${passes} pass, ${fails} fail, ${skips} skip`);
  return fails === 0 ? 0 : 1;
}

let code = 1;
try {
  code = await main();
} catch (err) {
  console.log(`FAIL watch sandbox stopped: ${err.message}`);
  code = 1;
} finally {
  await cleanup();
}
process.exit(code);
