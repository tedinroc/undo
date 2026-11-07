// The phone page's first reads, in Node: the page's own module under a made-up DOM, and a fetch that answers each
// request after a delay (phone-boot-page.mjs). The reads that do not wait on one another go out together, and the
// screen they lead to does not depend on which answer comes first.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const PAGE = join(dirname(fileURLToPath(import.meta.url)), 'phone-boot-page.mjs');
const VAULT = 'ab'.repeat(32);
const BOOT = ['relay', 'instance', 'block', 'vault', 'request'];

function load(opts) {
  const out = spawnSync(process.execPath, [PAGE, JSON.stringify(opts)], { encoding: 'utf8', timeout: 60_000 });
  assert.equal(out.status, 0, out.stderr);
  return JSON.parse(out.stdout.trim().split('\n').pop());
}

const firstOf = (fetched, kind) => fetched.find((f) => f.kind === kind);

test('phone boot: the relay status, the instance, the block time, and the linked vault and request go out together, after the config', () => {
  const delayMs = 400;
  const page = load({ hash: `#v=${VAULT}&r=1`, delayMs, waitMs: 3000 });
  const config = firstOf(page.fetched, 'config');
  const boot = BOOT.map((kind) => firstOf(page.fetched, kind));
  for (const [i, f] of boot.entries()) {
    assert.ok(f, `${BOOT[i]} was read`);
    assert.ok(f.start >= config.end, `${BOOT[i]} waits for the config, which names where to read`);
  }
  const lastStart = Math.max(...boot.map((f) => f.start));
  const firstEnd = Math.min(...boot.map((f) => f.end));
  assert.ok(lastStart < firstEnd, `every boot read started before the first answered: ${JSON.stringify(boot)}`);
  assert.ok(lastStart - config.end < delayMs / 2, 'none waited a round trip for another');
  assert.equal(page.fetched.filter((f) => f.kind === 'vault' && f.start < firstEnd).length, 1, 'the first tick used the vault read boot sent, and sent no second one');
  assert.equal(page.state, 'no_button');
  assert.match(page.text, /Only the phone holding this vault's passkey can cancel\./);
});

test('phone boot: answers arriving in any order draw the same screen', () => {
  const even = load({ hash: `#v=${VAULT}&r=1`, delayMs: 300, waitMs: 3000 });
  const reversed = load({ hash: `#v=${VAULT}&r=1`, delayMs: 300, delays: { relay: 1200, instance: 900, block: 600, vault: 100, request: 150 }, waitMs: 3500 });
  const order = (page) => BOOT.map((kind) => firstOf(page.fetched, kind)).sort((a, b) => a.end - b.end).map((f) => f.kind);
  assert.deepEqual(order(reversed), ['vault', 'request', 'block', 'instance', 'relay'], 'the vault answered first and the relay last');
  assert.deepEqual([reversed.state, reversed.text], [even.state, even.text]);
});

test('phone boot: a vault read older than a tick\'s own is read again, and a link with no vault reads none early', () => {
  const slowRelay = load({ hash: `#v=${VAULT}&r=1`, delayMs: 200, delays: { relay: 3600 }, waitMs: 4500 });
  const relay = firstOf(slowRelay.fetched, 'relay');
  assert.ok(slowRelay.fetched.some((f) => f.kind === 'vault' && f.start >= relay.end), 'the first tick read the vault after the status came');
  assert.equal(slowRelay.state, 'no_button');
  const noVault = load({ hash: '', delayMs: 200, waitMs: 1500 });
  assert.equal(noVault.fetched.filter((f) => f.kind === 'vault' || f.kind === 'request').length, 0);
  assert.ok(firstOf(noVault.fetched, 'relay') && firstOf(noVault.fetched, 'instance'));
});

test('phone boot: the operator check reads no relay and no contract, and test mode reads the vault only after the status, as before', () => {
  const nonce = 'cd'.repeat(32);
  const check = load({ hash: `#opproof=${nonce}&opfor=tmp-1108a.example.testnet`, delayMs: 200, waitMs: 1200 });
  assert.deepEqual(check.fetched.map((f) => f.kind), ['config']);
  const h7 = load({ hash: `#h7=1&v=${VAULT}`, delayMs: 200, waitMs: 2000 });
  const relay = firstOf(h7.fetched, 'relay');
  assert.ok(relay);
  for (const f of h7.fetched.filter((x) => x.kind === 'vault')) assert.ok(f.start >= relay.end, 'test mode makes its own reads, after boot');
});
