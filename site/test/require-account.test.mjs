// worker/undo-cron/require-account.sh: the account id a deploy uses must be the public account's own, not just an id
// the login can see. Offline: wrangler is a stub that prints a whoami answer and records that it was asked.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { after, test } from 'node:test';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const LIB = join(REPO, 'worker', 'undo-cron', 'require-account.sh');
const dir = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'undo-require-account-'));
after(() => rmSync(dir, { recursive: true, force: true }));

const PUBLIC_ID = '1'.repeat(32);
const OTHER_ID = '2'.repeat(32);

function check(whoami, id) {
  const stub = join(dir, `wrangler-${Math.random().toString(36).slice(2)}`);
  writeFileSync(stub, `#!/bin/sh\ncat <<'T'\n${whoami}\nT\n`);
  chmodSync(stub, 0o755);
  const out = spawnSync('bash', ['-c', 'source "$1" && require_account', 'check', LIB], {
    encoding: 'utf8', env: { PATH: process.env.PATH, WRANGLER: stub, CLOUDFLARE_ACCOUNT_ID: id },
  });
  return { ok: out.status === 0, text: `${out.stdout}${out.stderr}` };
}

const table = (rows, email = 'someone-else@example.com') => [
  `You are logged in with an OAuth Token, associated with the email ${email}.`,
  '| Account Name                  | Account ID                       |',
  ...rows.map(([name, id]) => `| ${name.padEnd(29)} | ${id} |`),
].join('\n');

test('a login that sees two accounts: the id on the other account\'s row is refused, even with the public name elsewhere', () => {
  const two = table([['tedinroc\'s Account (member)', PUBLIC_ID], ['other-handle\'s Account', OTHER_ID]]);
  const other = check(two, OTHER_ID);
  assert.equal(other.ok, false, other.text);
  assert.match(other.text, /the row for CLOUDFLARE_ACCOUNT_ID does not name the tedinroc account/);
  assert.doesNotMatch(other.text, /other-handle|someone-else/, 'it never repeats what whoami said');
  const own = check(two, PUBLIC_ID);
  assert.equal(own.ok, true, own.text);
});

test('a login with one account whose name does not carry the public name passes only on the public login, and only for that id', () => {
  const one = table([['Main Account', PUBLIC_ID]], 'tedinroc@example.com');
  assert.equal(check(one, PUBLIC_ID).ok, true);
  assert.equal(check(one, OTHER_ID).ok, false, 'an id the login cannot see');
  const stranger = table([['Main Account', PUBLIC_ID]], 'someone-else@example.com');
  assert.equal(check(stranger, PUBLIC_ID).ok, false, 'no public name anywhere');
  const two = table([['Main Account', PUBLIC_ID], ['Another Account', OTHER_ID]], 'tedinroc@example.com');
  assert.equal(check(two, OTHER_ID).ok, false, 'two accounts, neither row named: refused');
  assert.equal(check(two, PUBLIC_ID).ok, false, 'two accounts, neither row named: refused for both');
});

test('no id set: refused before wrangler is asked', () => {
  const r = check(table([['tedinroc', PUBLIC_ID]]), '');
  assert.equal(r.ok, false);
  assert.match(r.text, /set CLOUDFLARE_ACCOUNT_ID/);
});
