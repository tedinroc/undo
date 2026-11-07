// The phone's "Copy the thief link", followed the way the thief tab reads it, with no browser: the link must carry a
// destination the tab accepts, or "Send everything" stays greyed out with no word on screen. The modules are the ones
// the site ships.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { register } from 'node:module';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { p2wshSpk } from '../../tools/lib/btc.mjs';
import { toHex } from '../../tools/lib/bytes.mjs';
import { sha256 } from '../../tools/lib/crypto.mjs';
import { destinationProblem, destinationSpk, parseSeed } from '../pages/t/logic.mjs';

register('./page-hooks.mjs', import.meta.url);

const { thiefLink } = await import('../pages/p/phone-fragment.mjs');
const { parseFragment } = await import('../lib/fragment.mjs');

const PAGES = join(dirname(fileURLToPath(import.meta.url)), '../pages');
const label = (text) => sha256(new TextEncoder().encode(`undo-test-only:thief-link:${text}`));
const VAULT = toHex(label('vault'));
const SEED = toHex(label('seed'));

test('the copied thief link opens the thief tab with the vault, the key and a destination it accepts', () => {
  const link = new URL(thiefLink('https://undo-btc.pages.dev', VAULT, SEED, label('to-1').slice(0, 20)));
  assert.equal(link.origin, 'https://undo-btc.pages.dev');
  assert.equal(link.pathname, '/t/');
  assert.equal(link.search, '');
  // What the thief tab's boot reads, then what its checkTo and checkKey ask of each field.
  const fields = parseFragment(link.hash);
  assert.deepEqual(fields.refused, []);
  assert.equal(fields.v, VAULT);
  assert.equal(toHex(parseSeed(fields.k)), SEED);
  assert.equal(destinationProblem(fields.to), null, `send to would stay ${destinationProblem(fields.to)}, so Send everything stays off`);
  assert.equal(toHex(destinationSpk(fields.to)).slice(0, 4), '0014', 'a P2WPKH program');
});

test('each link gets its own destination, never a vault\'s own script, so the send is the stolen-key case and waits as one', () => {
  const a = parseFragment(new URL(thiefLink('https://undo-btc.pages.dev', VAULT, SEED, label('to-1').slice(0, 20))).hash).to;
  const b = parseFragment(new URL(thiefLink('https://undo-btc.pages.dev', VAULT, SEED, label('to-2').slice(0, 20))).hash).to;
  assert.notEqual(a, b);
  assert.ok(a.startsWith('tb1q') && b.startsWith('tb1q'), 'a test address on every network, as the thief tab requires');
  // A vault pays to P2WSH; this is 22 bytes of P2WPKH, so it can never be the vault's own address.
  assert.notEqual(toHex(destinationSpk(a)), toHex(p2wshSpk(label('script'))));
  assert.equal(destinationSpk(a).length, 22);
  assert.throws(() => thiefLink('https://undo-btc.pages.dev', VAULT, SEED, label('short').slice(0, 19)), /20 bytes/);
});

test('the phone page copies the link thiefLink builds, with fresh random bytes for the destination', () => {
  const phone = readFileSync(join(PAGES, 'p/phone.mjs'), 'utf8');
  const body = /async function copyThiefLink\(\) \{([\s\S]*?)\n\}/.exec(phone)?.[1] ?? '';
  assert.match(body, /const link = thiefLink\(location\.origin, P\.v, toHex\(P\.seed\), randomBytes\(20\)\);/);
  assert.doesNotMatch(body, /\/t\/#/, 'no hand-built link beside it');
});
