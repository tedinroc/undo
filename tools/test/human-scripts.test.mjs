// The human scripts, under a throwaway HOME and shims for near, curl and security. Nothing here makes
// a real key, contacts a network or touches the real Keychain. What each script passed to `near` is
// written to UNDO_NEAR_RECORD, and near-cli-check.mjs then checks those exact arguments against the
// real binary's --help.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';

const HUMAN = resolve(dirname(fileURLToPath(import.meta.url)), '../../scripts/human');
const REPO = resolve(HUMAN, '../..');
// Every test home sits in here, so a test that stops early (a mutant run makes them) leaves nothing behind.
const TMP = mkdtempSync(join(tmpdir(), 'undo-human-tests-'));
after(() => rmSync(TMP, { recursive: true, force: true }));

function shimDir(root) {
  const bin = join(root, 'shim');
  mkdirSync(bin, { recursive: true });
  const write = (name, body) => {
    writeFileSync(join(bin, name), `#!/bin/sh\n${body}\n`);
    chmodSync(join(bin, name), 0o755);
  };
  // near: records its arguments, and does the file writes the real one would.
  write('near', `
if [ "$1" = "--version" ]; then echo "near-cli-rs \${SHIM_NEAR_VERSION:-0.30.1}"; exit 0; fi
node -e 'const fs=require("fs"),l=JSON.stringify(process.argv.slice(1))+"\\n";fs.appendFileSync(process.env.SHIM_RECORD,l);if(process.env.SHIM_RECORD_ALL)fs.appendFileSync(process.env.SHIM_RECORD_ALL,l)' -- "$@"
case "$1 $2 $3" in
  "account create-account sponsor-by-faucet-service")
    [ -n "$SHIM_NEAR_FAIL" ] && { echo "faucet said no" >&2; exit 1; }
    mkdir -p "$HOME/.near-credentials/testnet"
    printf '{"public_key":"p","private_key":"shimkey"}' > "$HOME/.near-credentials/testnet/$4.json"
    chmod 644 "$HOME/.near-credentials/testnet/$4.json" ;;
  "account create-account fund-later")
    f="$6/$(printf 'ab%.0s' $(seq 1 32)).json"
    printf '{"public_key":"p","private_key":"shimkey"}' > "$f"
    chmod 644 "$f" ;;
esac`);
  // curl: answers the view_account query. SHIM_TAKEN names one account that exists.
  write('curl', `
case "$*" in
  *"\${SHIM_TAKEN:-no-such-account}"*) echo '{"result":{"amount":"1"}}' ;;
  *) echo '{"error":{"cause":{"name":"UNKNOWN_ACCOUNT"}}}' ;;
esac`);
  // security: a one-item Keychain in a file. Records its arguments, so a secret on the command line shows.
  write('security', `
echo "$*" >> "$SHIM_SECURITY_LOG"
if [ "$1" = "-i" ]; then
  [ -n "$SHIM_KEYCHAIN_BROKEN" ] && exit 0
  while read -r line; do
    case "$line" in add-generic-password*) printf '%s' "$line" | sed 's/.*-w //' > "$SHIM_KEYCHAIN" ;; esac
  done
  exit 0
fi
[ -f "$SHIM_KEYCHAIN" ] || exit 44
cat "$SHIM_KEYCHAIN"; echo`);
  return bin;
}

function run(script, answer, extra = {}) {
  const home = extra.home ?? mkdtempSync(join(TMP, 'undo-human-'));
  const bin = shimDir(home);
  const env = {
    HOME: home,
    PATH: `${bin}:${dirname(process.execPath)}:/usr/bin:/bin`,
    SHIM_RECORD: join(home, 'near-args'),
    ...(process.env.UNDO_NEAR_RECORD ? { SHIM_RECORD_ALL: process.env.UNDO_NEAR_RECORD } : {}),
    SHIM_SECURITY_LOG: join(home, 'security-args'),
    SHIM_KEYCHAIN: join(home, 'keychain-item'),
    UNDO_PRIVATE_DIR: join(home, 'private-folder'),
    UNDO_BLOCKED_SOURCE: join(home, 'blocked-source'),
    ...extra.env,
  };
  writeFileSync(join(home, 'blocked-source'), 'one-blocked-word\n');
  const r = spawnSync(join(HUMAN, script), extra.args ?? [], { encoding: 'utf8', input: answer, env, cwd: home });
  return { ...r, home, out: r.stdout + r.stderr, env };
}
const mode = (path) => (statSync(path).mode & 0o777).toString(8);
const clean = (home) => rmSync(home, { recursive: true, force: true });
const nearCalls = (r) => (existsSync(join(r.home, 'near-args')) ? readFileSync(join(r.home, 'near-args'), 'utf8') : '');

for (const script of ['01-testnet-accounts.sh', '02-dispenser-address.sh', '03-funding-key.sh']) {
  test(`${script}: prints the plan, stops without yes, changes nothing`, () => {
    for (const answer of ['no\n', '\n', 'y\n', 'YES\n', '']) {
      const r = run(script, answer);
      assert.equal(r.status, 0);
      assert.match(r.stdout, /This (will|makes)/);
      assert.match(r.stdout, /Stopped\. Nothing was changed\./);
      assert.equal(existsSync(join(r.home, '.config')), false);
      assert.equal(existsSync(join(r.home, '.near-credentials')), false);
      assert.equal(existsSync(join(r.home, 'private-folder')), false);
      assert.equal(existsSync(join(r.home, 'near-args')), false, 'near must not run');
      assert.equal(existsSync(join(r.home, 'security-args')), false, 'security must not run');
      clean(r.home);
    }
  });
}

test('01 creates the three accounts, in the legacy keychain, with private files', () => {
  const r = run('01-testnet-accounts.sh', 'yes\n');
  assert.equal(r.status, 0, r.out);
  const calls = nearCalls(r).trim().split('\n').map((l) => JSON.parse(l));
  const creates = calls.filter((c) => c[1] === 'create-account');
  assert.deepEqual(creates.map((c) => c[3]), ['undo-btc.testnet', 'undo-relay.testnet', 'undo-guard.testnet']);
  for (const c of creates) assert.deepEqual(c.slice(4), ['autogenerate-new-keypair', 'save-to-legacy-keychain', 'network-config', 'testnet', 'create']);
  assert.equal(calls.filter((c) => c[1] === 'view-account-summary').length, 3);
  const dir = join(r.home, '.near-credentials/testnet');
  for (const f of readdirSync(dir)) assert.equal(mode(join(dir, f)), '600');
  assert.ok(!r.out.includes('shimkey'));
  clean(r.home);
});

test('01 takes an extra account name, and refuses a malformed one before doing anything', () => {
  const r = run('01-testnet-accounts.sh', 'yes\n', { args: ['other-name'] });
  assert.equal(r.status, 0, r.out);
  const creates = nearCalls(r).trim().split('\n').map((l) => JSON.parse(l)).filter((c) => c[1] === 'create-account');
  assert.deepEqual(creates.map((c) => c[3]), ['undo-btc.testnet', 'undo-relay.testnet', 'undo-guard.testnet', 'other-name.testnet']);
  clean(r.home);
  const bad = run('01-testnet-accounts.sh', 'yes\n', { args: ['x.testnet; rm'] });
  assert.equal(bad.status, 1);
  assert.equal(existsSync(join(bad.home, 'near-args')), false);
  assert.equal(existsSync(join(bad.home, 'private-folder')), false);
  clean(bad.home);
});

test('01 makes the private folder first, and a second run keeps what is in it', () => {
  const r = run('01-testnet-accounts.sh', 'yes\n');
  assert.equal(r.status, 0, r.out);
  const dir = join(r.home, 'private-folder');
  for (const f of ['blocked-names.txt', 'quota-log.csv', 'HANDOFF.md']) assert.ok(existsSync(join(dir, f)), f);
  assert.equal(statSync(dir).mode & 0o077, 0);
  writeFileSync(join(dir, 'quota-log.csv'), 'kept\n');
  const again = run('01-testnet-accounts.sh', 'yes\n', { home: r.home, env: { SHIM_TAKEN: '.testnet' } });
  assert.equal(again.status, 0, again.out);
  assert.equal(readFileSync(join(dir, 'quota-log.csv'), 'utf8'), 'kept\n');
  clean(r.home);
});

test('01 run again skips what exists; a taken name with no local key stops it', () => {
  const r = run('01-testnet-accounts.sh', 'yes\n');
  assert.equal(r.status, 0);
  const again = run('01-testnet-accounts.sh', 'yes\n', { home: r.home, env: { SHIM_TAKEN: '.testnet' } });
  assert.equal(again.status, 0, again.out);
  assert.match(again.stdout, /already exists and its key is here/);
  clean(r.home);

  const taken = run('01-testnet-accounts.sh', 'yes\n', { env: { SHIM_TAKEN: 'undo-relay.testnet' } });
  assert.equal(taken.status, 1);
  assert.match(taken.out, /Someone else may hold it/);
  clean(taken.home);

  const faucet = run('01-testnet-accounts.sh', 'yes\n', { env: { SHIM_NEAR_FAIL: '1' } });
  assert.equal(faucet.status, 1, 'a failed create stops the script');
  clean(faucet.home);

  const version = run('01-testnet-accounts.sh', 'yes\n', { env: { SHIM_NEAR_VERSION: '0.31.0' } });
  assert.equal(version.status, 1);
  assert.match(version.out, /another version/);
  clean(version.home);
});

test('02 makes one key, outside the repo, private, and never replaces it', () => {
  const r = run('02-dispenser-address.sh', 'yes\n');
  assert.equal(r.status, 0, r.out);
  const address = r.stdout.match(/^ADDRESS (tb1q[0-9a-z]+)$/m)?.[1];
  assert.ok(address, r.stdout);
  const path = join(r.home, '.config/undo/dispenser-mutinynet.json');
  assert.equal(mode(path), '600');
  assert.equal(mode(dirname(path)), '700');
  const { secret } = JSON.parse(readFileSync(path, 'utf8'));
  assert.equal(secret.length, 64);
  assert.ok(!r.out.includes(secret), 'no secret on the screen');
  assert.ok(!path.startsWith(REPO));

  const before = readFileSync(path, 'utf8');
  const again = run('02-dispenser-address.sh', 'yes\n', { home: r.home });
  assert.equal(again.status, 0);
  assert.match(again.stdout, /already there/);
  assert.match(again.stdout, new RegExp(`ADDRESS ${address}`));
  assert.equal(readFileSync(path, 'utf8'), before);
  clean(r.home);
});

test('human-key refuses a key file inside the repo', () => {
  const r = spawnSync('node', [join(REPO, 'tools/human-key.mjs'), 'dispenser', '--file', join(REPO, 'tools/oops.json')], { encoding: 'utf8' });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /inside the repo/);
  assert.equal(existsSync(join(REPO, 'tools/oops.json')), false);
});

test('03 makes both keys, keeps the secret off every command line, and never replaces it', () => {
  const r = run('03-funding-key.sh', 'yes\n');
  assert.equal(r.status, 0, r.out);
  const calls = nearCalls(r).trim().split('\n').map((l) => JSON.parse(l));
  assert.equal(calls.length, 1);
  assert.deepEqual(calls[0].slice(0, 5), ['account', 'create-account', 'fund-later', 'use-auto-generation', 'save-to-folder']);
  const folder = join(r.home, '.config/undo/mainnet-deployer');
  assert.equal(mode(folder), '700');
  const [file] = readdirSync(folder);
  assert.equal(mode(join(folder, file)), '600');
  assert.match(r.stdout, new RegExp(`NEAR to the deployer: ${file.replace('.json', '')}`));
  const address = r.stdout.match(/BTC to the funding key: (bc1q[0-9a-z]+)/)?.[1];
  assert.ok(address, r.stdout);
  const secret = readFileSync(join(r.home, 'keychain-item'), 'utf8').trim();
  assert.equal(secret.length, 64);
  assert.ok(!r.out.includes(secret), 'no secret on the screen');
  assert.ok(!readFileSync(join(r.home, 'security-args'), 'utf8').includes(secret), 'no secret in any command line');

  const again = run('03-funding-key.sh', 'yes\n', { home: r.home });
  assert.equal(again.status, 0, again.out);
  assert.match(again.stdout, new RegExp(`BTC to the funding key: ${address}`));
  assert.equal(readFileSync(join(r.home, 'keychain-item'), 'utf8').trim(), secret);
  assert.equal(nearCalls(again).trim().split('\n').length, 1, 'near is not asked for a second key');
  clean(r.home);
});

test('03 tightens a folder that was already there', () => {
  const home = mkdtempSync(join(TMP, 'undo-human-'));
  mkdirSync(join(home, '.config/undo/mainnet-deployer'), { recursive: true, mode: 0o755 });
  chmodSync(join(home, '.config/undo/mainnet-deployer'), 0o755);
  const r = run('03-funding-key.sh', 'yes\n', { home });
  assert.equal(r.status, 0, r.out);
  assert.equal(mode(join(home, '.config/undo/mainnet-deployer')), '700');
  clean(home);
});

test('03 shows no address when the Keychain did not keep the key', () => {
  const r = run('03-funding-key.sh', 'yes\n', { env: { SHIM_KEYCHAIN_BROKEN: '1' } });
  assert.notEqual(r.status, 0);
  assert.doesNotMatch(r.stdout, /bc1q/);
  assert.match(r.out, /did not keep the key/);
  clean(r.home);
});

test('the install script checks the release checksum before installing', () => {
  const home = mkdtempSync(join(TMP, 'undo-install-'));
  const bin = join(home, 'shim');
  mkdirSync(bin);
  const tarDir = join(home, 'pack/near-cli-rs-aarch64-apple-darwin');
  mkdirSync(tarDir, { recursive: true });
  writeFileSync(join(tarDir, 'near'), '#!/bin/sh\necho placeholder\n');
  chmodSync(join(tarDir, 'near'), 0o755);
  const tgz = join(home, 'asset.tgz');
  spawnSync('tar', ['czf', tgz, '-C', join(home, 'pack'), 'near-cli-rs-aarch64-apple-darwin']);
  const sum = spawnSync('shasum', ['-a', '256', tgz], { encoding: 'utf8' }).stdout.split(' ')[0];
  const shim = (hash) => {
    writeFileSync(join(bin, 'curl'), `#!/bin/sh
out="$3"; url="$4"
case "$url" in
  *.sha256) echo "${hash} *asset" > "$out" ;;
  *) cp "${tgz}" "$out" ;;
esac
`);
    chmodSync(join(bin, 'curl'), 0o755);
  };
  const env = { HOME: home, PATH: `${bin}:/usr/bin:/bin` };
  shim('00'.repeat(32));
  let r = spawnSync(join(HUMAN, 'install-near-cli.sh'), [], { encoding: 'utf8', env });
  assert.equal(r.status, 1, r.stdout + r.stderr);
  assert.match(r.stderr, /does not match/);
  assert.equal(existsSync(join(home, '.local/bin/near')), false);
  shim(sum);
  r = spawnSync(join(HUMAN, 'install-near-cli.sh'), [], { encoding: 'utf8', env });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  assert.equal(mode(join(home, '.local/bin/near')), '755');
  clean(home);
});

test('00 makes the private folder outside the repo, private, and keeps what is there', () => {
  const root = mkdtempSync(join(TMP, 'undo-private-'));
  const source = join(root, 'source.txt');
  writeFileSync(source, 'one-blocked-word\n');
  const dir = join(root, 'private');
  const env = { ...process.env, UNDO_PRIVATE_DIR: dir, UNDO_BLOCKED_SOURCE: source };
  const run = (extra = {}) => spawnSync(join(HUMAN, '00-private-setup.sh'), [], { encoding: 'utf8', env: { ...env, ...extra } });
  const first = run();
  assert.equal(first.status, 0, first.stderr);
  assert.equal(readFileSync(join(dir, 'blocked-names.txt'), 'utf8'), 'one-blocked-word\n');
  assert.equal(readFileSync(join(dir, 'quota-log.csv'), 'utf8').split('\n')[0], 'date,workflow,entry,tokens,card_percent');
  const note = readFileSync(join(dir, 'HANDOFF.md'), 'utf8');
  assert.match(note, /Wrangler environment/);
  assert.match(note, new RegExp(`XDG_CONFIG_HOME=${process.env.HOME}/Library/Preferences `), 'the value is this machine\'s, worked out when it runs');
  assert.match(note, /CLOUDFLARE_ACCOUNT_ID=<fill in>/);
  assert.match(note, /`wrangler whoami`/, 'the backticks survive the heredoc');
  assert.equal(statSync(dir).mode & 0o077, 0, 'the folder is private');
  assert.equal(statSync(join(dir, 'blocked-names.txt')).mode & 0o077, 0, 'the list is private');

  writeFileSync(join(dir, 'quota-log.csv'), 'kept\n');
  writeFileSync(join(dir, 'blocked-names.txt'), 'kept\n');
  assert.equal(run().status, 0);
  assert.equal(readFileSync(join(dir, 'quota-log.csv'), 'utf8'), 'kept\n', 'a second run keeps the log');
  assert.equal(readFileSync(join(dir, 'blocked-names.txt'), 'utf8'), 'kept\n', 'a second run keeps the list');

  chmodSync(dir, 0o755);
  assert.equal(run().status, 0);
  assert.equal(statSync(dir).mode & 0o077, 0, 'a folder left open is closed again');

  const named = run({ UNDO_PRIVATE_DIR: join(root, 'with-account'), UNDO_CF_ACCOUNT_ID: 'abc123' });
  assert.equal(named.status, 0, named.stderr);
  assert.match(readFileSync(join(root, 'with-account', 'HANDOFF.md'), 'utf8'), /CLOUDFLARE_ACCOUNT_ID=abc123/);

  const inside = run({ UNDO_PRIVATE_DIR: join(REPO, 'proofs', 'private-test') });
  assert.equal(inside.status, 1, 'a folder inside the repo is refused');
  assert.equal(existsSync(join(REPO, 'proofs', 'private-test')), false);
  assert.equal(run({ UNDO_PRIVATE_DIR: join(root, 'other'), UNDO_BLOCKED_SOURCE: join(root, 'missing') }).status, 1, 'no list to start from is refused');
  rmSync(root, { recursive: true, force: true });
});

test('the scripts hold no secret, path or handle', () => {
  const files = readdirSync(HUMAN).map((f) => join(HUMAN, f));
  const secret = spawnSync(join(REPO, 'scripts/secret-scan.sh'), ['--files', ...files], { encoding: 'utf8' });
  assert.equal(secret.status, 0, secret.stdout);
  const identity = spawnSync(join(REPO, 'scripts/check-identity.sh'), ['--files', ...files], { encoding: 'utf8' });
  assert.equal(identity.status, 0, identity.stdout);
});
