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
import { spkToAddress } from '../lib/bitcoin.mjs';
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

const LINK = (bytes, network = 'mutinynet') => new URL(thiefLink('https://undo-btc.pages.dev', VAULT, SEED, bytes, network));

test('the copied thief link opens the thief tab with the vault, the key and a destination it accepts, on each network', () => {
  for (const [network, prefix] of [['mutinynet', 'tb1q'], ['signet', 'tb1q'], ['regtest', 'bcrt1q']]) {
    const link = LINK(label('to-1').slice(0, 20), network);
    assert.equal(link.origin, 'https://undo-btc.pages.dev');
    assert.equal(link.pathname, '/t/');
    assert.equal(link.search, '');
    // What the thief tab's boot reads, then what its checkTo and checkKey ask of each field.
    const fields = parseFragment(link.hash);
    assert.deepEqual(fields.refused, []);
    assert.equal(fields.v, VAULT);
    assert.equal(toHex(parseSeed(fields.k)), SEED);
    assert.ok(fields.to.startsWith(prefix), `${network}: the network's own form, as the phone prints it: ${fields.to}`);
    assert.equal(destinationProblem(fields.to, network), null, `send to would stay ${destinationProblem(fields.to, network)}, so Send everything stays off`);
    assert.equal(toHex(destinationSpk(fields.to, network)).slice(0, 4), '0014', 'a P2WPKH program');
    // One destination, one string: the phone prints the request's script back in this same form.
    assert.equal(spkToAddress(network, destinationSpk(fields.to, network)), fields.to);
  }
  // The same bytes on each network, so nothing a link chooses changes what is paid.
  assert.equal(toHex(destinationSpk(parseFragment(LINK(label('to-1').slice(0, 20), 'regtest').hash).to, 'regtest')), toHex(destinationSpk(parseFragment(LINK(label('to-1').slice(0, 20)).hash).to, 'mutinynet')));
  assert.throws(() => thiefLink('https://undo-btc.pages.dev', VAULT, SEED, label('to-1').slice(0, 20)), undefined, 'no network, no link');
});

test('each link gets its own destination, never a vault\'s own script, so the send is the stolen-key case and waits as one', () => {
  const a = parseFragment(LINK(label('to-1').slice(0, 20)).hash).to;
  const b = parseFragment(LINK(label('to-2').slice(0, 20)).hash).to;
  assert.notEqual(a, b);
  assert.ok(a.startsWith('tb1q') && b.startsWith('tb1q'), 'a test address, as the thief tab requires');
  // A vault pays to P2WSH; this is 22 bytes of P2WPKH, so it can never be the vault's own address.
  assert.notEqual(toHex(destinationSpk(a, 'mutinynet')), toHex(p2wshSpk(label('script'))));
  assert.equal(destinationSpk(a, 'mutinynet').length, 22);
  assert.throws(() => thiefLink('https://undo-btc.pages.dev', VAULT, SEED, label('short').slice(0, 19), 'mutinynet'), /20 bytes/);
});

test('the phone page copies the link thiefLink builds, with fresh random bytes for the destination', () => {
  const phone = readFileSync(join(PAGES, 'p/phone.mjs'), 'utf8');
  const body = /async function copyThiefLink\(\) \{([\s\S]*?)\n\}/.exec(phone)?.[1] ?? '';
  assert.match(body, /const link = thiefLink\(location\.origin, P\.v, toHex\(P\.seed\), randomBytes\(20\), ctx\.instance\.network\);/, 'in the network the contract names, as the phone prints its addresses');
  assert.doesNotMatch(body, /\/t\/#/, 'no hand-built link beside it');
});

test('a link whose destination has a valid address at its end and junk in front is not taken as that address', () => {
  for (const network of ['mutinynet', 'regtest']) {
    const good = parseFragment(LINK(label('to-1').slice(0, 20), network).hash).to;
    const other = parseFragment(LINK(label('to-2').slice(0, 20), network).hash).to;
    const fields = parseFragment(`#v=${VAULT}&k=${SEED}&to=${other}${good}`);
    assert.equal(fields.to, `${other}${good}`, 'the link\'s own rule lets it through, so the tab\'s check is the one that must refuse it');
    assert.equal(destinationProblem(fields.to, network), 'bad_address');
    assert.throws(() => destinationSpk(fields.to, network));
  }
});
