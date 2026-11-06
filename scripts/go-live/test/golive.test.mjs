// The go-live scripts, rehearsed with nothing live: dry runs, refusals, a stub wrangler that records what it was
// handed, and a local NEAR node with the mock signer for every step that writes. Nothing here can reach Cloudflare,
// testnet or Mutinynet: the only RPC is a local one, and wrangler is a stub.
//
//   node --test --test-concurrency=1 scripts/go-live/test/
//
// The sandbox tests need NEAR_SANDBOX_BIN_PATH and UNDO_WASM_DIR (and UNDO_LIBLZMA_DIR where the binary links one).
// The steps that need the site (00 live, 30 live, 40, 50) need site/ and worker/undo-cron/ in this tree, which the
// web branch brings; 50 also needs UNDO_WRANGLER_MODULES for the relay in real workerd. Each says why it skipped.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { createServer as tcpServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { p2wpkhAddress } from '../../../tools/lib/btc.mjs';
import { base58Encode, concat, toHex, utf8 } from '../../../tools/lib/bytes.mjs';
import { p256, sha256 } from '../../../tools/lib/crypto.mjs';
import { publicSecp } from '../../../tools/lib/keys.mjs';
import { action, failureOf, keyFromSecret, loadKeyFile, NEAR, Near, TGAS } from '../../../tools/lib/near.mjs';
import { insideGitTree, Refused, writePrivate } from '../lib.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const GOLIVE = resolve(HERE, '..');
const REPO = resolve(GOLIVE, '../..');
const WORK = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'undo-golive-test-'));
const label = (t) => sha256(utf8(`undo-test-only:golive:${t}`));
const RP_HASH = toHex(sha256(utf8('undo-btc.pages.dev')));
const hasSite = existsSync(join(REPO, 'site', 'build.mjs')) && existsSync(join(REPO, 'worker', 'undo-cron', 'require-account.sh'));
const noSite = hasSite ? false : 'needs site/ and worker/undo-cron/ in this tree: run it after the web branch is merged';
const hasSandbox = Boolean(process.env.NEAR_SANDBOX_BIN_PATH && process.env.UNDO_WASM_DIR);
const noSandbox = hasSandbox ? false : 'set NEAR_SANDBOX_BIN_PATH and UNDO_WASM_DIR to rehearse the writes on a local node';
const WASM = process.env.UNDO_WASM_DIR ? join(process.env.UNDO_WASM_DIR, 'undo_vault.wasm') : null;

after(() => rmSync(WORK, { recursive: true, force: true }));

function node(script, args, env = {}) {
  const out = spawnSync(process.execPath, [join(GOLIVE, script), ...args], { encoding: 'utf8', env: { ...process.env, UNDO_GOLIVE_DIR: join(WORK, 'private'), ...env }, timeout: 180_000 });
  return { code: out.status, out: `${out.stdout}${out.stderr}` };
}

/** For a script that talks to a server in this process: spawnSync would block the server from answering. */
function nodeAsync(script, args, env = {}) {
  return new Promise((resolveRun) => {
    const child = spawn(process.execPath, [join(GOLIVE, script), ...args], { env: { ...process.env, UNDO_GOLIVE_DIR: join(WORK, 'private'), ...env } });
    let out = '';
    child.stdout.on('data', (c) => { out += c; });
    child.stderr.on('data', (c) => { out += c; });
    const timer = setTimeout(() => child.kill("SIGKILL"), 120_000);
    child.on('close', (code) => {
      clearTimeout(timer);
      resolveRun({ code, out });
    });
  });
}

function sh(script, args, env = {}) {
  const out = spawnSync('bash', [join(GOLIVE, script), ...args], { encoding: 'utf8', env: { ...process.env, ...env }, timeout: 300_000 });
  return { code: out.status, out: `${out.stdout}${out.stderr}` };
}

const opFile = (name, { rp = RP_HASH } = {}) => {
  const path = join(WORK, `${name}.json`);
  const pub = toHex(p256.getPublicKey(label(`operator-${name}`), true));
  writeFileSync(path, JSON.stringify({ pubkey: pub, rp_id_hash: rp }));
  return { path, pub };
};

// ---------------------------------------------------------------- a fake RPC, for the chain guard

function fakeRpc(chainId) {
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const { id } = JSON.parse(body);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ jsonrpc: '2.0', id, result: { chain_id: chainId, protocol_version: 88, sync_info: { latest_block_height: 9 } } }));
    });
  });
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r({ url: `http://127.0.0.1:${server.address().port}`, close: () => server.close() })));
}

// ---------------------------------------------------------------- offline

test('10 dry run: both transactions, the fixed origin, rp id, network and real signer, and nothing sent', () => {
  const op = opFile('dry');
  const r = node('10-deploy-instance.mjs', ['--dry-run', '--offline', '--name', 'v1', '--operator-passkey', op.path, '--wasm', WASM ?? join(GOLIVE, 'lib.mjs')]);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /PLAN tx 1: signer s\.undo-btc\.testnet -> receiver v1\.s\.undo-btc\.testnet/);
  assert.match(r.out, /CreateAccount[\s\S]*Transfer [0-9.]+ NEAR[\s\S]*AddKey <s\.undo-btc\.testnet's own public key, read at --live> FullAccess/);
  assert.match(r.out, /PLAN tx 2: signer v1\.s\.undo-btc\.testnet -> receiver v1\.s\.undo-btc\.testnet/);
  assert.match(r.out, /"signer":"v1\.signer-prod\.testnet"/);
  assert.match(r.out, /"network":"mutinynet","origins":\["https:\/\/undo-btc\.pages\.dev"\]/);
  assert.match(r.out, new RegExp(`"operator_passkey":\\{"pubkey":"${op.pub}","rp_id_hash":"${RP_HASH}"\\}`));
  assert.match(r.out, /"sign_tgas":30/);
  assert.match(r.out, /DRY RUN: nothing sent\./);
  assert.equal(existsSync(join(WORK, 'private', 'instances.json')), false, 'a dry run records nothing');
});

test('10 refuses before anything: no mode, both modes, a tmp- name for the real one, a temp without tmp-, a foreign passkey, a bad key', () => {
  const wasm = WASM ?? join(GOLIVE, 'lib.mjs');
  const good = opFile('good');
  const foreign = opFile('foreign', { rp: toHex(sha256(utf8('example.com'))) });
  const bad = join(WORK, 'bad-op.json');
  writeFileSync(bad, JSON.stringify({ pubkey: '04aa', rp_id_hash: RP_HASH }));
  const cases = [
    [['--offline', '--name', 'v1', '--operator-passkey', good.path], /give --dry-run or --live/],
    [['--dry-run', '--live', '--offline', '--temp'], /not both/],
    [['--dry-run', '--offline', '--name', 'tmp-x', '--operator-passkey', good.path], /kept for temporary instances/],
    [['--dry-run', '--offline', '--temp', '--name', 'v2'], /starts with tmp-/],
    [['--dry-run', '--offline', '--name', 'v1', '--operator-passkey', foreign.path], /rp_id_hash is not sha256/],
    [['--dry-run', '--offline', '--name', 'v1', '--operator-passkey', bad], /compressed P-256/],
    [['--dry-run', '--offline', '--name', 'v1'], /--operator-passkey FILE or --temp/],
    [['--dry-run', '--offline', '--operator-passkey', good.path], /give --name/],
    [['--live', '--offline', '--temp'], /--offline is for a dry run/],
    [['--dry-run', '--offline', '--name', 'v1.evil', '--operator-passkey', good.path], /no dots/],
  ];
  for (const [args, why] of cases) {
    const r = node('10-deploy-instance.mjs', [...args, '--wasm', wasm]);
    assert.equal(r.code, 3, `${args.join(' ')}\n${r.out}`);
    assert.match(r.out, why);
  }
});

test('every script that reads a chain refuses mainnet, and a sandbox flag pointed at testnet', async () => {
  const main = await fakeRpc('mainnet');
  const testnet = await fakeRpc('testnet');
  try {
    const wasm = WASM ?? join(GOLIVE, 'lib.mjs');
    const record = join(WORK, 'guard-record.json');
    writeFileSync(record, JSON.stringify({ instances: [{ account: 'tmp-a.s.undo-btc.testnet', temp: true, code_hash: 'x', created_at: 'then' }, { account: 'tmp-a.p.test.near', temp: true, code_hash: 'x', created_at: 'then' }] }));
    const runs = {
      '10-deploy-instance.mjs': [['--dry-run', '--temp', '--wasm', wasm], ['--parent', 'p.test.near', '--signer', 'm.test.near']],
      '20-relay-keys.mjs': [['--dry-run', '--contract', 'v1.s.undo-btc.testnet'], ['--relay', 'r.test.near']],
      '50-readback.mjs': [['--live', '--public-keys', writePublicKeys()], []],
      '90-teardown-temp.mjs': [['--dry-run', '--name', 'tmp-a', '--record', record, '--config', join(WORK, 'none.json')], ['--parent', 'p.test.near']],
    };
    for (const [script, [args, sandboxArgs]] of Object.entries(runs)) {
      for (const network of ['testnet', 'sandbox']) {
        const r = await nodeAsync(script, [...args, '--network', network, '--rpc', main.url, ...(network === 'sandbox' ? sandboxArgs : [])]);
        assert.equal(r.code, 3, `${script} ${network}\n${r.out}`);
        assert.match(r.out, /mainnet/);
      }
    }
    const r = await nodeAsync('10-deploy-instance.mjs', ['--dry-run', '--temp', '--wasm', wasm, '--network', 'sandbox', '--rpc', testnet.url, '--parent', 'p.test.near', '--signer', 'm.test.near']);
    assert.equal(r.code, 3, r.out);
    assert.match(r.out, /--network sandbox pointed at testnet/);
  } finally {
    main.close();
    testnet.close();
  }
});

function writePublicKeys(contract = 'v1.s.undo-btc.testnet') {
  const path = join(WORK, `public-${contract}.json`);
  writeFileSync(path, JSON.stringify({ schema: 'undo-relay-secrets-v1-public', network: 'testnet', relay_account: 's.undo-relay.testnet', contract, keys: {} }));
  return path;
}

test('20 dry run: three keys with exact permissions, placeholders only, and no file written', () => {
  const out = join(WORK, 'dry-keys', 'relay.json');
  const r = node('20-relay-keys.mjs', ['--dry-run', '--offline', '--contract', 'v1.s.undo-btc.testnet', '--out', out]);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /PLAN tx 1: signer s\.undo-relay\.testnet -> receiver s\.undo-relay\.testnet/);
  assert.match(r.out, /AddKey <new RELAY_GENERAL_KEY> FullAccess/);
  assert.match(r.out, /AddKey <new RELAY_OWNER_KEY> FunctionCall receiver=v1\.s\.undo-btc\.testnet methods=\[cancel, cancel_all_and_rotate\] allowance=8\.0000 NEAR/);
  assert.match(r.out, /AddKey <new RELAY_CRON_KEY> FunctionCall receiver=v1\.s\.undo-btc\.testnet methods=\[heartbeat\] allowance=2\.0000 NEAR/);
  assert.match(r.out, /DRY RUN: nothing made, nothing written, nothing sent\./);
  assert.equal(existsSync(out), false);
  assert.doesNotMatch(r.out, /ed25519:[1-9A-HJ-NP-Za-km-z]{60,}/, 'no key of any kind in a dry run');
  const over = node('20-relay-keys.mjs', ['--dry-run', '--offline', '--contract', 'v1.s.undo-btc.testnet', '--owner-allowance-near', '9']);
  assert.equal(over.code, 3, over.out);
});

test('a private file is refused inside a git work tree, and written 0600 outside one', () => {
  assert.equal(insideGitTree(join(REPO, 'x.json')), true);
  assert.throws(() => writePrivate(join(REPO, 'target', 'golive-should-not-exist.json'), { a: 1 }), Refused);
  assert.equal(existsSync(join(REPO, 'target', 'golive-should-not-exist.json')), false);
  const path = join(WORK, 'outside', 'f.json');
  writePrivate(path, { a: 1 });
  assert.equal(spawnSync('stat', ['-f', '%Lp', path], { encoding: 'utf8' }).stdout.trim(), '600');
});

test('90 refuses: a name without tmp-, one not in the record, one recorded as real, one the site still names', () => {
  const record = join(WORK, 'record.json');
  writeFileSync(record, JSON.stringify({ instances: [
    { account: 'tmp-a.s.undo-btc.testnet', temp: true, code_hash: 'x', created_at: 'then' },
    { account: 'tmp-real.s.undo-btc.testnet', temp: false, code_hash: 'x', created_at: 'then' },
  ] }));
  const config = join(WORK, 'config.json');
  writeFileSync(config, JSON.stringify({ contract: 'tmp-a.s.undo-btc.testnet' }));
  const base = ['--dry-run', '--offline', '--record', record];
  const cases = [
    [['--name', 'v1'], /starting with tmp-/],
    [['--name', 'tmp-b'], /not in the instance record/],
    [['--name', 'tmp-real'], /recorded as a real instance/],
    [['--name', 'tmp-a', '--config', config], /still names tmp-a/],
  ];
  for (const [args, why] of cases) {
    const r = node('90-teardown-temp.mjs', [...base, ...args]);
    assert.equal(r.code, 3, `${args.join(' ')}\n${r.out}`);
    assert.match(r.out, why);
  }
  const ok = node('90-teardown-temp.mjs', [...base, '--name', 'tmp-a', '--config', join(WORK, 'none.json')]);
  assert.equal(ok.code, 0, ok.out);
  assert.match(ok.out, /PLAN tx 1: signer tmp-a\.s\.undo-btc\.testnet -> receiver tmp-a\.s\.undo-btc\.testnet\n\s+- DeleteAccount beneficiary=s\.undo-btc\.testnet/);
});

test('50 dry run lists every read and every refused POST, and reads nothing', () => {
  const r = node('50-readback.mjs', ['--dry-run', '--public-keys', writePublicKeys()]);
  assert.equal(r.code, 0, r.out);
  for (const want of [/GET https:\/\/undo-btc\.pages\.dev\/api\/relay/, /POST \/api\/relay: a browser Origin that is not this site, must answer 403 bad_origin/, /heartbeat without the operator token/, /PUT \/api\/relay/, /headers on \/, \/replay\/, \/p\/, \/t\//]) assert.match(r.out, want);
  const secretFile = join(WORK, 'has-secret.json');
  writeFileSync(secretFile, JSON.stringify({ contract: 'c', relay_account: 'r', keys: { RELAY_GENERAL_KEY: { secret_key: 'ed25519:x' } } }));
  const refused = node('50-readback.mjs', ['--dry-run', '--public-keys', secretFile]);
  assert.equal(refused.code, 3, refused.out);
  assert.match(refused.out, /Pass the \.public\.json copy/);
});

// ---------------------------------------------------------------- fixtures for wrangler steps

/** A secrets file as 20-relay-keys writes it, from labelled test keys, and a Mutinynet dispenser file. */
function fixtureFiles(contract = 'v1.s.undo-btc.testnet') {
  const dir = join(WORK, 'files');
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const key = (name) => {
    const k = keyFromSecret(label(name));
    return { public_key: k.publicKey, secret_key: `ed25519:${base58Encode(concat(k.secret, k.pub))}`, permission: 'FullAccess' };
  };
  const secrets = {
    schema: 'undo-relay-secrets-v1', network: 'testnet', relay_account: 's.undo-relay.testnet', contract, created_at: 'test',
    keys: { RELAY_GENERAL_KEY: key('general'), RELAY_OWNER_KEY: key('owner'), RELAY_CRON_KEY: key('cron') },
    values: { IP_SALT: toHex(label('salt')), BEAT_TOKEN: toHex(label('beat')).slice(0, 48) },
    sent: [],
  };
  const dSecret = label('dispenser');
  const dispenser = { format: 'undo-dispenser-v1', network: 'mutinynet', address: p2wpkhAddress('mutinynet', publicSecp(dSecret)), secret: toHex(dSecret) };
  const secretsPath = join(dir, 'relay-secrets.json');
  const dispenserPath = join(dir, 'dispense.json');
  writeFileSync(secretsPath, JSON.stringify(secrets), { mode: 0o600 });
  writeFileSync(dispenserPath, JSON.stringify(dispenser), { mode: 0o600 });
  chmodSync(secretsPath, 0o600);
  chmodSync(dispenserPath, 0o600);
  const values = [...Object.values(secrets.keys).map((k) => k.secret_key), secrets.values.IP_SALT, secrets.values.BEAT_TOKEN, dispenser.secret];
  return { secretsPath, dispenserPath, values, secrets };
}

const ACCOUNT_ID = toHex(label('cf-account')).slice(0, 32);

/** A wrangler that writes down each call's arguments, stdin and environment names, and answers like wrangler 3. */
function stubWrangler(name, { whoamiShows = 'tedinroc', failOn = null } = {}) {
  const log = join(WORK, `stub-${name}`);
  rmSync(log, { recursive: true, force: true });
  mkdirSync(log, { recursive: true });
  const path = join(WORK, `wrangler-${name}.sh`);
  writeFileSync(path, `#!/usr/bin/env bash
log='${log}'
n="$(ls "$log" | grep -c argv || true)"
printf '%s\\n' "$*" > "$log/$n.argv"
env | cut -d= -f1 | sort > "$log/$n.env"
pwd > "$log/$n.cwd"
${failOn ? `case "$*" in *'${failOn}'*) echo "stub refused: ${failOn}"; exit 1 ;; esac` : ''}
case "$*" in
  --version) echo " ⛅️ wrangler 3.114.17" ;;
  whoami) echo "You are logged in with an OAuth Token, associated with the email ${whoamiShows}@users.example." ; echo "| Account Name | Account ID |"; echo "| ${whoamiShows} | $CLOUDFLARE_ACCOUNT_ID |" ;;
  *"secret put"*) cat > "$log/$n.stdin"; echo "Success! Uploaded secret" ;;
  *"secret list"*) cat "$log"/*.argv | grep 'secret put' | sed -E 's/^(pages )?secret put ([A-Z_]+).*/\\2/' | sed 's/^/{"name":"/;s/$/"}/' ;;
  *"functions build"*) out="$(printf '%s\\n' "$@" | grep -A1 -- '--outdir' | tail -1)"; mkdir -p "$out"; echo 'export default {};' > "$out/index.js" ;;
  *deploy*) echo "stub deployed" ;;
esac
`);
  chmodSync(path, 0o755);
  const calls = () => readdirSync(log).filter((f) => f.endsWith('.argv')).sort((x, y) => parseInt(x, 10) - parseInt(y, 10)).map((f) => {
    const n = parseInt(f, 10);
    const read = (ext) => (existsSync(join(log, `${n}.${ext}`)) ? readFileSync(join(log, `${n}.${ext}`), 'utf8') : '');
    return { argv: read('argv').trim(), stdin: read('stdin'), env: read('env').trim().split('\n'), cwd: read('cwd').trim() };
  });
  return { path, calls };
}

const cfEnv = (stub, extra = {}) => ({
  CLOUDFLARE_ACCOUNT_ID: ACCOUNT_ID, GOLIVE_XDG_CONFIG_HOME: join(WORK, 'xdg'), GOLIVE_NPM_CACHE: join(WORK, 'npm'),
  GOLIVE_WRANGLER_BIN: stub.path, WRANGLER: '', UNDO_GOLIVE_TEST_LEAK: 'should-not-reach-wrangler', ...extra,
});
mkdirSync(join(WORK, 'xdg'), { recursive: true });
mkdirSync(join(WORK, 'npm'), { recursive: true });

test('30 dry run: each name for each deployable, with its length and source, and no value anywhere in the output', () => {
  const f = fixtureFiles();
  const r = sh('30-secrets.sh', ['--dry-run', '--secrets', f.secretsPath, '--dispenser', f.dispenserPath]);
  assert.equal(r.code, 0, r.out);
  for (const name of ['CONTRACT_ID', 'RELAY_ACCOUNT', 'RELAY_CRON_KEY']) assert.match(r.out, new RegExp(`PLAN Worker undo-cron: secret put ${name}\\s`));
  for (const name of ['RELAY_GENERAL_KEY', 'RELAY_OWNER_KEY', 'DISPENSER_SECRET', 'IP_SALT', 'BEAT_TOKEN']) assert.match(r.out, new RegExp(`PLAN Pages project undo-btc: pages secret put ${name} --project-name undo-btc\\s`));
  for (const v of f.values) assert.equal(r.out.includes(v), false, 'a value reached the output');
  const loose = join(WORK, 'files', 'loose.json');
  writeFileSync(loose, readFileSync(f.secretsPath));
  chmodSync(loose, 0o644);
  const refused = sh('30-secrets.sh', ['--dry-run', '--secrets', loose, '--dispenser', f.dispenserPath]);
  assert.notEqual(refused.code, 0);
  assert.match(refused.out, /readable by others/);
});

test('30 live through a stub wrangler: values only on stdin, never in an argument or the output; wrangler sees a clean environment', { skip: noSite }, () => {
  const f = fixtureFiles();
  const stub = stubWrangler('secrets');
  const r = sh('30-secrets.sh', ['--live', '--secrets', f.secretsPath, '--dispenser', f.dispenserPath, '--canary', 'ab'.repeat(32)], cfEnv(stub));
  assert.equal(r.code, 0, r.out);
  for (const v of f.values) assert.equal(r.out.includes(v), false, 'a value reached the output');
  const calls = stub.calls();
  const puts = calls.filter((c) => c.argv.includes('secret put'));
  assert.deepEqual(puts.map((c) => c.argv.split(' ').find((w) => /^[A-Z_]+$/.test(w))), ['CONTRACT_ID', 'RELAY_ACCOUNT', 'RELAY_CRON_KEY', 'CANARY_VAULT', 'CONTRACT_ID', 'RELAY_ACCOUNT', 'RELAY_GENERAL_KEY', 'RELAY_OWNER_KEY', 'DISPENSER_SECRET', 'IP_SALT', 'BEAT_TOKEN']);
  for (const c of calls) for (const v of f.values) assert.equal(c.argv.includes(v), false, 'a value was an argument');
  assert.equal(puts.find((c) => c.argv.includes('RELAY_OWNER_KEY')).stdin, f.secrets.keys.RELAY_OWNER_KEY.secret_key);
  assert.equal(puts.find((c) => c.argv.includes('DISPENSER_SECRET')).stdin, f.values.at(-1));
  assert.ok(puts.slice(0, 4).every((c) => c.cwd.endsWith('/worker/undo-cron')) && puts.slice(4).every((c) => c.cwd.endsWith('/site')));
  for (const c of calls) {
    assert.equal(c.env.includes('UNDO_GOLIVE_TEST_LEAK'), false, 'the calling shell leaked into wrangler');
    assert.ok(c.env.includes('XDG_CONFIG_HOME') && c.env.includes('CLOUDFLARE_ACCOUNT_ID'));
  }
  assert.match(r.out, /PASS \[live-cloudflare\] Pages project undo-btc lists BEAT_TOKEN/);
});

test('30 live stops before any secret when whoami shows another account', { skip: noSite }, () => {
  const f = fixtureFiles();
  const stub = stubWrangler('other', { whoamiShows: 'someoneelse' });
  const r = sh('30-secrets.sh', ['--live', '--secrets', f.secretsPath, '--dispenser', f.dispenserPath], cfEnv(stub));
  assert.notEqual(r.code, 0, r.out);
  assert.equal(stub.calls().filter((c) => c.argv.includes('secret put')).length, 0);
});

test('00 env check: the dry run names what is missing; live passes on the right account and fails on another', { skip: noSite }, () => {
  const bare = sh('00-env-check.sh', ['--dry-run'], { CLOUDFLARE_ACCOUNT_ID: '', GOLIVE_XDG_CONFIG_HOME: '', GOLIVE_NPM_CACHE: '' });
  assert.equal(bare.code, 1, bare.out);
  assert.match(bare.out, /FAIL \[static\] CLOUDFLARE_ACCOUNT_ID is not set/);
  assert.match(bare.out, /DRY RUN: wrangler was not run\./);
  const good = stubWrangler('env-good');
  const ok = sh('00-env-check.sh', ['--live'], cfEnv(good));
  assert.equal(ok.code, 0, ok.out);
  assert.match(ok.out, /PASS \[live-cloudflare\] wrangler 3\.114\.17/);
  assert.match(ok.out, /PASS \[live-cloudflare\] wrangler whoami shows the tedinroc account/);
  assert.equal(ok.out.includes(ACCOUNT_ID), false, 'the account id is never printed whole');
  const other = stubWrangler('env-other', { whoamiShows: 'someoneelse' });
  const no = sh('00-env-check.sh', ['--live'], cfEnv(other));
  assert.equal(no.code, 1, no.out);
});

/** A copy of this tree with the config naming a contract, as a git repo of its own so the scans can list it. */
function deployTree(contract) {
  const dir = join(WORK, `tree-${toHex(label(contract)).slice(0, 6)}`);
  rmSync(dir, { recursive: true, force: true });
  const skip = new Set(['target', 'node_modules', '.git', 'dist', '.wrangler']);
  cpSync(REPO, dir, { recursive: true, filter: (src) => !skip.has(src.split('/').pop()) });
  const config = JSON.parse(readFileSync(join(dir, 'site/config/testnet.json'), 'utf8'));
  writeFileSync(join(dir, 'site/config/testnet.json'), `${JSON.stringify({ ...config, contract }, null, 2)}\n`);
  // The outward check reads the built wasm in target/near, as it does before any real deploy.
  mkdirSync(join(dir, 'target', 'near'), { recursive: true });
  for (const f of ['undo_vault.wasm', 'mock_signer.wasm']) cpSync(join(process.env.UNDO_WASM_DIR, f), join(dir, 'target', 'near', f));
  spawnSync('git', ['init', '-q'], { cwd: dir });
  spawnSync('git', ['add', '-A'], { cwd: dir });
  return dir;
}

test('40: dry run builds and scans offline; live runs both checks, then the Worker, then Pages; a failed check sends nothing', { skip: noSite || (process.env.UNDO_WASM_DIR ? false : 'set UNDO_WASM_DIR: the outward check reads the built wasm'), timeout: 600_000 }, () => {
  const tree = deployTree('v1.s.undo-btc.testnet');
  const run = (args, env) => {
    const out = spawnSync('bash', [join(tree, 'scripts/go-live/40-deploy.sh'), ...args], { encoding: 'utf8', env: { ...process.env, ...env }, timeout: 300_000 });
    return { code: out.status, out: `${out.stdout}${out.stderr}` };
  };
  const dry = run(['--dry-run', '--contract', 'v1.s.undo-btc.testnet'], {});
  assert.equal(dry.code, 0, dry.out);
  assert.match(dry.out, /PASS \[static\] BUILT testnet/);
  assert.match(dry.out, /PASS \[static\] outward check on the built site: OUTWARD OK/);
  assert.match(dry.out, /deploy\.sh --check-only[\s\S]*site\/deploy\.sh --check-only[\s\S]*undo-cron\/deploy\.sh {2,}[\s\S]*site\/deploy\.sh {2,}/);
  const wrong = run(['--dry-run', '--contract', 'v2.s.undo-btc.testnet'], {});
  assert.equal(wrong.code, 1, wrong.out);

  const secrets = ['CONTRACT_ID', 'RELAY_ACCOUNT', 'RELAY_CRON_KEY', 'RELAY_GENERAL_KEY', 'RELAY_OWNER_KEY', 'DISPENSER_SECRET', 'IP_SALT'];
  const seeded = (stub) => {
    // The stub lists what was put: put each name once, as step 30 would have.
    for (const name of secrets) spawnSync(stub.path, ['secret', 'put', name], { input: 'x', env: { ...process.env, CLOUDFLARE_ACCOUNT_ID: ACCOUNT_ID } });
  };
  const stub = stubWrangler('deploy');
  seeded(stub);
  const live = run(['--live', '--contract', 'v1.s.undo-btc.testnet'], cfEnv(stub));
  assert.equal(live.code, 0, live.out);
  const order = stub.calls().map((c) => c.argv).filter((a) => /^(deploy|pages deploy)/.test(a));
  assert.deepEqual(order.map((a) => a.split(' ').slice(0, 2).join(' ')), ['deploy', 'pages deploy']);
  assert.match(order[1], /pages deploy dist --project-name undo-btc --branch main/);

  const failing = stubWrangler('deploy-fail', { failOn: 'pages secret list' });
  seeded(failing);
  const stopped = run(['--live', '--contract', 'v1.s.undo-btc.testnet'], cfEnv(failing));
  assert.notEqual(stopped.code, 0, stopped.out);
  assert.equal(failing.calls().filter((c) => /^(deploy|pages deploy)/.test(c.argv)).length, 0, 'nothing deployed after a failed check');
  rmSync(tree, { recursive: true, force: true });
});

// ---------------------------------------------------------------- one local node, mock signer

const freePort = () => new Promise((res) => {
  const s = tcpServer().listen(0, '127.0.0.1', () => {
    const { port } = s.address();
    s.close(() => res(port));
  });
});

let sb = null;

async function startSandbox() {
  if (process.env.UNDO_LIBLZMA_DIR) process.env.DYLD_LIBRARY_PATH = process.env.UNDO_LIBLZMA_DIR;
  const bin = process.env.NEAR_SANDBOX_BIN_PATH;
  const home = join(WORK, 'near');
  await new Promise((res, rej) => {
    const init = spawn(bin, ['--home', home, 'init', '--fast'], { stdio: 'ignore' });
    init.on('exit', (code) => (code === 0 ? res() : rej(new Error('sandbox init failed'))));
  });
  const genesis = JSON.parse(readFileSync(join(home, 'genesis.json'), 'utf8'));
  genesis.epoch_length = 100000;
  writeFileSync(join(home, 'genesis.json'), JSON.stringify(genesis));
  const rpcPort = await freePort();
  const child = spawn(bin, ['--home', home, 'run', '--rpc-addr', `127.0.0.1:${rpcPort}`, '--network-addr', `127.0.0.1:${await freePort()}`], { stdio: 'ignore' });
  const rpc = `http://127.0.0.1:${rpcPort}`;
  const near = new Near([rpc], { timeoutMs: 30_000 });
  for (let i = 0; ; i += 1) {
    try {
      if ((await near.rpcOnce(rpc, 'status', [])).sync_info.latest_block_height > 2) break;
    } catch {
      // Still starting.
    }
    if (i > 300) throw new Error('the local node did not start');
    await new Promise((r) => setTimeout(r, 200));
  }
  const root = loadKeyFile(join(home, 'validator_key.json'));
  const creds = join(WORK, 'creds');
  mkdirSync(join(creds, 'sandbox'), { recursive: true });
  const make = async (name, balance) => {
    const accountId = `${name}.${root.accountId}`;
    const key = keyFromSecret(label(`account-${name}`));
    const sent = await near.sendAndWait(root, accountId, [action.createAccount(), action.transfer(BigInt(balance) * NEAR), action.addFullKey(key.pub)]);
    if (failureOf(sent.result)) throw new Error(`could not make ${accountId}`);
    const file = join(creds, 'sandbox', `${accountId}.json`);
    writeFileSync(file, JSON.stringify({ account_id: accountId, private_key: `ed25519:${base58Encode(key.secret)}` }), { mode: 0o600 });
    chmodSync(file, 0o600);
    return { ...key, accountId };
  };
  const mock = await make('mock', 30);
  const deployed = await near.sendAndWait(mock, mock.accountId, [
    action.deploy(readFileSync(join(process.env.UNDO_WASM_DIR, 'mock_signer.wasm'))),
    action.call('new', { secret_hex: toHex(label('mock-root')), mode: 'Yield' }, 100n * TGAS, 0n),
  ]);
  if (failureOf(deployed.result)) throw new Error('mock signer deploy failed');
  const parent = await make('btc', 30);
  const relay = await make('relay', 30);
  const env = { NEAR_CREDENTIALS_DIR: creds };
  const common = ['--network', 'sandbox', '--rpc', rpc];
  return { child, rpc, near, root, mock, parent, relay, env, common, record: join(WORK, 'private', 'sandbox-instances.json') };
}

before(async () => {
  if (hasSandbox) sb = await startSandbox();
}, { timeout: 120_000 });

after(() => {
  sb?.child.kill('SIGKILL');
});

const deploy = (args, wasm = WASM) => node('10-deploy-instance.mjs', [...sb.common, '--parent', sb.parent.accountId, '--signer', sb.mock.accountId, '--wasm', wasm, '--record', sb.record, ...args], sb.env);

test('sandbox 10: a temporary instance deploys, reads back PASS on every field, is recorded as temporary; a rerun sends nothing; other code is refused', { skip: noSandbox, timeout: 180_000 }, async () => {
  const r = deploy(['--live', '--temp', '--name', 'tmp-one']);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /SENT \[mock-signer\] create tmp-one\.btc\.test\.near: local NEAR sandbox tx \w+/);
  assert.match(r.out, /SENT \[mock-signer\] deploy and new on tmp-one\.btc\.test\.near/);
  assert.doesNotMatch(r.out, /^FAIL/m);
  for (const field of ['code hash', 'preset', 'signer', 'network', 'origins', 'operator', 'restrict_create', 'sign_tgas', 'operator_passkey', 'pending_upgrade']) assert.match(r.out, new RegExp(`PASS \\[mock-signer\\] ${field}`));
  const recorded = JSON.parse(readFileSync(sb.record, 'utf8')).instances.find((i) => i.account === 'tmp-one.btc.test.near');
  assert.equal(recorded.temp, true);
  const again = deploy(['--live', '--temp', '--name', 'tmp-one']);
  assert.equal(again.code, 0, again.out);
  assert.match(again.out, /NOTHING TO SEND: tmp-one\.btc\.test\.near already holds this wasm/);
  const other = deploy(['--live', '--temp', '--name', 'tmp-one'], join(process.env.UNDO_WASM_DIR, 'mock_signer.wasm'));
  assert.equal(other.code, 3, other.out);
  assert.match(other.out, /holds other code[\s\S]*Refusing to overwrite it/);
});

test('sandbox 10: the real instance takes the operator passkey from its file, and the instance view shows it', { skip: noSandbox, timeout: 180_000 }, async () => {
  const op = opFile('real');
  const r = deploy(['--live', '--name', 'v1', '--operator-passkey', op.path]);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, new RegExp(`PASS \\[mock-signer\\] operator_passkey reads "${op.pub}"`));
  const instance = await sb.near.view('v1.btc.test.near', 'instance');
  assert.deepEqual(instance.origins, ['https://undo-btc.pages.dev']);
  assert.equal(instance.network, 'mutinynet');
  assert.equal(instance.operator_passkey, op.pub);
  const poor = deploy(['--live', '--name', 'v9', '--operator-passkey', op.path, '--fund-near', '3']);
  assert.equal(poor.code, 3, poor.out);
  assert.match(poor.out, /cannot pay for \d+ bytes of code/);
});

const keysFile = (contract) => join(WORK, 'private', `relay-${contract}.json`);
const keys = (contract, args) => node('20-relay-keys.mjs', [...sb.common, '--relay', sb.relay.accountId, '--contract', contract, '--out', keysFile(contract), ...args], sb.env);

test('sandbox 20: three keys in one transaction with exact permissions, the file 0600 and written first; a rerun is refused; --resume sends nothing', { skip: noSandbox, timeout: 120_000 }, async () => {
  const contract = 'tmp-one.btc.test.near';
  const r = keys(contract, ['--live']);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /KEPT \[mock-signer\] the private file is written before anything is sent[\s\S]*SENT \[mock-signer\] added RELAY_GENERAL_KEY, RELAY_OWNER_KEY, RELAY_CRON_KEY/);
  for (const name of ['RELAY_GENERAL_KEY', 'RELAY_OWNER_KEY', 'RELAY_CRON_KEY']) assert.match(r.out, new RegExp(`PASS \\[mock-signer\\] ${name} ed25519:\\w+ on ${sb.relay.accountId}`));
  assert.match(r.out, /RELAY_OWNER_KEY .*FunctionCall receiver=tmp-one\.btc\.test\.near methods=\[cancel, cancel_all_and_rotate\] allowance=8\.0000 NEAR/);
  assert.equal(spawnSync('stat', ['-f', '%Lp', keysFile(contract)], { encoding: 'utf8' }).stdout.trim(), '600');
  const file = JSON.parse(readFileSync(keysFile(contract), 'utf8'));
  for (const k of Object.values(file.keys)) assert.equal(r.out.includes(k.secret_key), false, 'a secret reached the output');
  const pub = JSON.parse(readFileSync(keysFile(contract).replace(/\.json$/, '.public.json'), 'utf8'));
  assert.equal(JSON.stringify(pub).includes('secret_key'), false);
  for (const k of Object.values(file.keys)) assert.equal(JSON.stringify(pub).includes(k.secret_key), false);
  const access = await sb.near.rpc('query', { request_type: 'view_access_key', account_id: sb.relay.accountId, public_key: file.keys.RELAY_OWNER_KEY.public_key, finality: 'final' });
  assert.deepEqual(access.permission.FunctionCall.method_names, ['cancel', 'cancel_all_and_rotate']);
  assert.equal(access.permission.FunctionCall.allowance, (8n * NEAR).toString());
  const again = keys(contract, ['--live']);
  assert.equal(again.code, 3, again.out);
  assert.match(again.out, /pass --resume/);
  const resumed = keys(contract, ['--live', '--resume']);
  assert.equal(resumed.code, 0, resumed.out);
  assert.match(resumed.out, /NOTHING TO SEND: every key in the file is on chain\./);
});

test('sandbox 50: the relay in real workerd with the keys step 20 made, behind the built site, reads back with no FAIL', { skip: noSandbox || noSite || (process.env.UNDO_WRANGLER_MODULES ? false : 'set UNDO_WRANGLER_MODULES for the relay in workerd'), timeout: 300_000 }, async () => {
  const contract = 'tmp-one.btc.test.near';
  const file = JSON.parse(readFileSync(keysFile(contract), 'utf8'));
  const workerd = await import(pathToFileURL(join(REPO, 'site/test/workerd.mjs')).href);
  const { staticServer } = await import(pathToFileURL(join(REPO, 'site/test/stage.mjs')).href);
  const { build } = await import(pathToFileURL(join(REPO, 'site/build.mjs')).href);
  const port = await freePort();
  const config = { mode: 'local', contract, rpc: [sb.rpc], esplora: `http://127.0.0.1:${await freePort()}`, relay: '/api/relay', funds: '/api/funds', btcTxUrl: null, btcAddressUrl: null, nearTxUrl: null, rpId: 'localhost', softPasskey: false, h7: false };
  const configPath = join(WORK, 'local-config.json');
  writeFileSync(configPath, JSON.stringify(config));
  const dist = join(WORK, 'dist');
  build({ configPath, out: dist });
  const dSecret = label('local-dispenser');
  const bundles = workerd.bundleBoth();
  const { Miniflare } = workerd.loadMiniflare();
  const bindings = {
    CONTRACT_ID: contract, RELAY_ACCOUNT: sb.relay.accountId, NEAR_RPC_URLS: sb.rpc, ESPLORA_URL: config.esplora,
    RELAY_GENERAL_KEY: file.keys.RELAY_GENERAL_KEY.secret_key, RELAY_OWNER_KEY: file.keys.RELAY_OWNER_KEY.secret_key,
    DISPENSER_SECRET: toHex(dSecret), DISPENSER_NETWORK: 'regtest', IP_SALT: file.values.IP_SALT, BEAT_TOKEN: file.values.BEAT_TOKEN,
    POW_BITS: '8', SITE_ORIGIN: `http://127.0.0.1:${port}`, UNDO_STATE_NAME: 'golive',
  };
  const mf = workerd.startWorkerd({ Miniflare }, { bundles, cronEnv: { CONTRACT_ID: contract, RELAY_ACCOUNT: sb.relay.accountId, NEAR_RPC_URLS: sb.rpc, RELAY_CRON_KEY: file.keys.RELAY_CRON_KEY.secret_key }, pages: { main: { bindings } } });
  await mf.ready;
  const relayWorker = await mf.getWorker('main');
  const server = await staticServer({
    dir: dist,
    port,
    onApi: async (req, res, url) => {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      const headers = { ...req.headers, 'cf-connecting-ip': '10.9.0.1' };
      delete headers['content-length'];
      delete headers.connection;
      const send = () => relayWorker.fetch(`http://127.0.0.1:${port}${url.pathname}`, { method: req.method, headers, body: chunks.length ? Buffer.concat(chunks) : undefined });
      let answer;
      try {
        answer = await send();
      } catch {
        // Miniflare's own socket to workerd can be reset between calls: that is this harness, not the relay. Once more.
        try {
          answer = await send();
        } catch (err) {
          res.writeHead(502, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ ok: false, code: 'harness_error', message: err.message }));
          return;
        }
      }
      res.writeHead(answer.status, Object.fromEntries(answer.headers));
      res.end(Buffer.from(await answer.arrayBuffer()));
    },
  });
  try {
    // Async: the site and the relay answer from this process, which spawnSync would block.
    const r = await nodeAsync('50-readback.mjs', [...sb.common, '--live', '--site', `http://127.0.0.1:${port}`, '--config', configPath, '--public-keys', keysFile(contract).replace(/\.json$/, '.public.json'), '--wasm', WASM], sb.env);
    console.log(r.out);
    assert.doesNotMatch(r.out, /^FAIL/m, r.out);
    assert.doesNotMatch(r.out, /^SKIP/m, r.out);
    assert.match(r.out, /PASS \[mock-signer\] refused a browser Origin that is not this site: 403 bad_origin/);
    assert.match(r.out, /PASS \[mock-signer\] RELAY_OWNER_KEY nonce \d+ before the refused POSTs, \d+ after: it signed nothing/);
    assert.match(r.out, /PASS \[mock-signer\] \/ content-security-policy as built/);
    assert.match(r.out, /PASS \[mock-signer\] the landing page is titled Undo for Bitcoin/);
    assert.equal(r.code, 0, r.out);
  } finally {
    server.close();
    await mf.dispose();
    bundles.remove();
  }
});

test('sandbox 90: the temporary instance and its relay keys are deleted and its balance comes home; a real instance is refused', { skip: noSandbox, timeout: 120_000 }, async () => {
  const contract = 'tmp-one.btc.test.near';
  const file = JSON.parse(readFileSync(keysFile(contract), 'utf8'));
  const teardown = (args) => node('90-teardown-temp.mjs', [...sb.common, '--parent', sb.parent.accountId, '--record', sb.record, '--config', join(WORK, 'none.json'), ...args], sb.env);
  const before = BigInt((await sb.near.account(sb.parent.accountId)).amount);
  const r = teardown(['--live', '--name', 'tmp-one', '--relay-keys', keysFile(contract)]);
  assert.equal(r.code, 0, r.out);
  assert.match(r.out, /SENT \[mock-signer\] delete tmp-one\.btc\.test\.near: local NEAR sandbox tx \w+/);
  assert.match(r.out, /PASS \[mock-signer\] tmp-one\.btc\.test\.near is gone/);
  assert.match(r.out, /PASS \[mock-signer\] btc\.test\.near gained/);
  assert.ok(BigInt((await sb.near.account(sb.parent.accountId)).amount) - before > 3n * NEAR);
  assert.match(r.out, /PASS \[mock-signer\] RELAY_OWNER_KEY is gone from relay\.test\.near/);
  for (const k of Object.values(file.keys)) {
    const gone = await sb.near.rpc('query', { request_type: 'view_access_key', account_id: sb.relay.accountId, public_key: k.public_key, finality: 'final' }, { attempts: 1 }).then((out) => Boolean(out?.error), () => true);
    assert.equal(gone, true, 'a relay key of the deleted instance is still there');
  }
  const real = teardown(['--live', '--name', 'v1']);
  assert.equal(real.code, 3, real.out);
  assert.ok(await sb.near.account('v1.btc.test.near'));
});
