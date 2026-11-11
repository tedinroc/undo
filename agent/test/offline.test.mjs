// The agent CLI's own logic with no network: the agent file's rules, coin choice, the words it prints,
// and the near-cli command `undo keys` prints, checked against near-cli's own --help when it is here.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { segwitAddress } from '../../tools/lib/btc.mjs';
import { toHex } from '../../tools/lib/bytes.mjs';
import { randomBytes } from '../../tools/lib/crypto.mjs';
import { CoinError, estimateVsize, feeFor, selectCoins } from '../lib/coins.mjs';
import { addKeyTokens, AGENT_METHODS, ConfigError, loadAgent, newNearKey, parseAgent } from '../lib/config.mjs';
import { clock, contractWords, runtimeWords, spkToAddress, viewWords } from '../lib/format.mjs';

const AGENT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const good = () => ({
  undo_agent: 1,
  near_network: 'testnet',
  contract: 'undo-btc.testnet',
  vault: toHex(randomBytes(32)),
  account_id: 'agent-one.testnet',
  seed: toHex(randomBytes(32)),
  private_key: newNearKey(randomBytes).text,
});
const coin = (value, i = 0) => ({ txid: toHex(randomBytes(32)), vout: i, value });

test('a good agent file loads, with the testnet defaults', () => {
  const agent = parseAgent(JSON.stringify(good()));
  assert.equal(agent.network.label, 'NEAR testnet');
  assert.deepEqual(agent.rpc, ['https://rpc.testnet.near.org', 'https://test.rpc.fastnear.com']);
  assert.equal(agent.esplora, 'https://mutinynet.com/api');
  assert.equal(agent.nearKey.accountId, 'agent-one.testnet');
});

test('an agent file with any owner key field is refused, naming the field', () => {
  for (const field of ['cold_key', 'passkey_secret', 'k_e', 'leaf_secret', 'recovery', 'k_p']) {
    assert.throws(() => parseAgent(JSON.stringify({ ...good(), [field]: 'x' })), (e) => e instanceof ConfigError && e.message.includes(field) && /never holds/.test(e.message));
  }
  assert.throws(() => parseAgent(JSON.stringify({ ...good(), color: 'blue' })), /unknown field "color"/);
});

test('mainnet, an unknown network and off-list hosts are refused', () => {
  assert.throws(() => parseAgent(JSON.stringify({ ...good(), near_network: 'mainnet' })), /mainnet is refused/);
  assert.throws(() => parseAgent(JSON.stringify({ ...good(), near_network: 'betanet' })), /testnet or sandbox/);
  assert.throws(() => parseAgent(JSON.stringify({ ...good(), rpc: ['https://rpc.mainnet.near.org'] })), /allow list/);
  assert.throws(() => parseAgent(JSON.stringify({ ...good(), esplora: 'https://mempool.space/api' })), /allow list/);
  assert.throws(() => parseAgent(JSON.stringify({ ...good(), near_network: 'sandbox', rpc: ['https://rpc.testnet.near.org'], esplora: 'http://127.0.0.1:1' })), /allow list/);
  assert.doesNotThrow(() => parseAgent(JSON.stringify({ ...good(), near_network: 'sandbox', rpc: ['http://127.0.0.1:3030'], esplora: 'http://127.0.0.1:1' })));
});

test('bad JSON is refused without quoting the text, which holds a key', () => {
  const text = `{"seed": "${toHex(randomBytes(32))}",`;
  assert.throws(() => parseAgent(text), (e) => e.message === 'agent file is not JSON');
});

test('a file others can read is refused', () => {
  const dir = mkdtempSync(join(tmpdir(), 'undo-agent-'));
  try {
    const file = join(dir, 'a.json');
    writeFileSync(file, JSON.stringify(good()), { mode: 0o644 });
    chmodSync(file, 0o644);
    assert.throws(() => loadAgent(file), /chmod 600/);
    chmodSync(file, 0o600);
    assert.equal(loadAgent(file).contract, 'undo-btc.testnet');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('clock reads like a countdown', () => {
  assert.equal(clock(300_000), '5:00');
  assert.equal(clock(299_001), '5:00');
  assert.equal(clock(299_000), '4:59');
  assert.equal(clock(59_999), '1:00');
  assert.equal(clock(0), '0:00');
  assert.equal(clock(-5), '0:00');
  assert.equal(clock(3_600_000), '1:00:00');
});

test('fee: the contract\'s estimate, never under its floor, never over the cap', () => {
  assert.equal(estimateVsize(1, 22, true), 11 + 107 + 31 + 43);
  assert.equal(feeFor({ inputs: 1, destLen: 22, withChange: true, rate: 2, cap: 1000 }), 384);
  assert.equal(feeFor({ inputs: 1, destLen: 22, withChange: true, rate: 1, cap: 1000 }), 192);
  assert.equal(feeFor({ inputs: 8, destLen: 22, withChange: true, rate: 2, cap: 1000 }), 1000);
  // A cap under the floor is left for the contract to refuse in its own words.
  assert.equal(feeFor({ inputs: 16, destLen: 22, withChange: true, rate: 2, cap: 1000 }), estimateVsize(16, 22, true));
});

test('coins: largest first, change back to the vault, all sweeps with no change', () => {
  const big = coin(150_000);
  const small = coin(60_000, 1);
  const one = selectCoins({ coins: [small, big], amount: 50_000, destLen: 22, rate: 2, cap: 1000 });
  assert.deepEqual(one.inputs, [big]);
  assert.equal(one.change, 150_000 - 50_000 - 384);
  const two = selectCoins({ coins: [small, big], amount: 180_000, destLen: 22, rate: 2, cap: 1000 });
  assert.equal(two.inputs.length, 2);
  assert.equal(two.amount + two.change + two.fee, 210_000);
  const all = selectCoins({ coins: [small, big], amount: 'all', destLen: 22, rate: 2, cap: 1000 });
  assert.equal(all.change, null);
  assert.equal(all.amount + all.fee, 210_000);
  assert.throws(() => selectCoins({ coins: [small], amount: 70_000, destLen: 22, rate: 2, cap: 1000 }), CoinError);
  assert.throws(() => selectCoins({ coins: [], amount: 'all', destLen: 22, rate: 2, cap: 1000 }), /no free confirmed coin/);
});

test('coins: change under dust goes to the fee rather than making a dust output', () => {
  const c = coin(50_500);
  const s = selectCoins({ coins: [c], amount: 50_000, destLen: 22, rate: 1, cap: 1000 });
  assert.equal(s.change, null);
  assert.equal(s.fee, 500);
});

test('the contract\'s words come back verbatim', () => {
  const failure = JSON.stringify({ ActionError: { index: 0, kind: { FunctionCallError: { ExecutionError: 'Smart contract panicked: SpendKeySuspended' } } } });
  assert.equal(contractWords(failure), 'Smart contract panicked: SpendKeySuspended');
  assert.equal(contractWords('{"other":1}'), '{"other":1}');
  assert.equal(viewWords('wasm execution failed with error: HostError(GuestPanic { panic_msg: "FeeOverCap { fee: 1200, cap: 1000 }" })'), 'FeeOverCap { fee: 1200, cap: 1000 }');
  const err = { data: { data: { TxExecutionError: { InvalidTxError: { InvalidAccessKeyError: { MethodNameMismatch: { method_name: 'cancel' } } } } } } };
  assert.equal(runtimeWords(err), '{"InvalidAccessKeyError":{"MethodNameMismatch":{"method_name":"cancel"}}}');
});

test('output scripts read back as the addresses they pay', () => {
  const program = randomBytes(20);
  const address = segwitAddress('mutinynet', 0, program);
  assert.equal(spkToAddress('mutinynet', `0014${toHex(program)}`), address);
  assert.ok(address.startsWith('tb1q'));
});

test('undo keys asks for exactly two methods, on one contract', () => {
  assert.deepEqual(AGENT_METHODS, ['propose_btc', 'execute']);
  const t = addKeyTokens({ account: 'a.testnet', publicKey: 'ed25519:x', contract: 'undo-btc.testnet', allowance: '0.25 NEAR', network: 'testnet' });
  assert.equal(t[t.indexOf('--function-names') + 1], 'propose_btc,execute');
  assert.equal(t[t.indexOf('--contract-account-id') + 1], 'undo-btc.testnet');
  assert.ok(!t.includes('grant-full-access'));
});

// near-cli 0.30.1 parses the printed command. Same method as tools/test/near-cli-check.mjs: --help
// under a macOS sandbox with the network denied and a throwaway HOME. It says nothing about a real run.
test('the near-cli command undo keys prints parses with near-cli-rs', (t) => {
  const bin = process.env.UNDO_NEAR_BIN;
  const policy = '(version 1)(allow default)(deny network*)';
  if (!bin || spawnSync('sandbox-exec', ['-p', policy, '/usr/bin/true']).status !== 0) {
    t.skip('SKIP (no UNDO_NEAR_BIN or no sandbox-exec)');
    return;
  }
  const home = mkdtempSync(join(tmpdir(), 'near-cli-home-'));
  const help = (tokens) => spawnSync('sandbox-exec', ['-p', policy, bin, ...tokens, '--help'], { encoding: 'utf8', env: { HOME: home, PATH: '/usr/bin:/bin' }, input: '', timeout: 20_000 });
  try {
    const pub = newNearKey(randomBytes).key.publicKey;
    const tokens = addKeyTokens({ account: 'agent-one.testnet', publicKey: pub, contract: 'undo-btc.testnet', allowance: '0.25 NEAR', network: 'testnet' });
    const ok = help(tokens);
    assert.equal(ok.status, 0, ok.stderr);
    assert.match(ok.stdout, /Usage: near account add-key grant-function-call-access use-manually-provided-public-key network-config sign-with-legacy-keychain send/);
    // Control: the same check refuses a bad allowance, so a pass means something.
    const bad = help(tokens.map((x) => (x === '0.25 NEAR' ? '0.25' : x)));
    assert.notEqual(bad.status, 0);
  } finally {
    rmSync(home, { recursive: true, force: true });
  }
});

test('the CLI prints usage and exits 2 on a bad command, and refuses a missing agent file', () => {
  const r = spawnSync(process.execPath, [join(AGENT, 'undo.mjs'), 'cancel'], { encoding: 'utf8' });
  assert.equal(r.status, 2);
  assert.match(r.stderr, /usage:/);
  assert.doesNotMatch(r.stderr, /undo cancel/);
  const missing = spawnSync(process.execPath, [join(AGENT, 'undo.mjs'), 'status', '--file', join(tmpdir(), `none-${toHex(randomBytes(4))}.json`)], { encoding: 'utf8' });
  assert.equal(missing.status, 2);
  assert.match(missing.stderr, /no agent file/);
});

test('the testnet driver sends nothing without --live, and with it refuses a work folder in the repository or an agent account that is not the payer\'s', () => {
  const driver = join(AGENT, 'test/testnet-c14.mjs');
  const dir = mkdtempSync(join(tmpdir(), 'undo-agent-driver-'));
  // No network is reachable from these runs' arguments, and no key: the home is an empty folder.
  const run = (...args) => spawnSync(process.execPath, [driver, ...args], { encoding: 'utf8', timeout: 30_000, env: { PATH: process.env.PATH, HOME: dir, TMPDIR: dir, NEAR_CREDENTIALS_DIR: join(dir, 'no-keys') } });
  try {
    const plan = run();
    assert.equal(plan.status, 0, plan.stderr);
    assert.match(plan.stdout, /--live --payer ACCOUNT --agent-account ID --work DIR/);
    assert.match(plan.stdout, /NEAR refuses each before any contract runs, so\n\s+none of them is ever on chain/);
    assert.match(plan.stdout, /Nothing was sent: this run had no --live\.\n$/);
    const half = run('--payer', 'a.testnet', '--agent-account', 'agent.a.testnet', '--work', join(dir, 'w'));
    assert.equal(half.status, 0);
    assert.match(half.stdout, /Nothing was sent/);
    const inside = join(AGENT, 'test', `never-${toHex(randomBytes(4))}`);
    const inRepo = run('--live', '--payer', 'a.testnet', '--agent-account', 'agent.a.testnet', '--work', inside);
    assert.equal(inRepo.status, 2);
    assert.match(inRepo.stderr, /--work must be outside the repository: it holds this run's secrets/);
    assert.equal(existsSync(inside), false);
    const stranger = run('--live', '--payer', 'a.testnet', '--agent-account', 'agent.b.testnet', '--work', join(dir, 'w'));
    assert.equal(stranger.status, 2);
    assert.match(stranger.stderr, /--agent-account must be a sub-account of --payer/);
    const typo = run('--liev');
    assert.equal(typo.status, 2);
    assert.match(typo.stderr, /unknown argument --liev/);
    assert.deepEqual(readdirSync(dir), [], 'none of these runs wrote a file');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
