// /try/'s words. T6: every sentence words.mjs says it copied is still in the file it names, byte for byte (as that file
// writes it in JavaScript or HTML), and every helper it copied from the phone page still has phone.mjs's body; so when the
// reword lane changes one, this fails and the copy follows. T5: nextOf gives exactly one Next sentence in every state and
// failure row of the spec, short, and never a promise this page can't keep.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { register } from 'node:module';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

register('./page-hooks.mjs', import.meta.url);
const words = await import('../pages/try/words.mjs');
const { FUND_UNSENT, NEXT, NO_BUTTON_WORDS, W, nextOf, say } = words;

const SITE = join(dirname(fileURLToPath(import.meta.url)), '..');
const REPO = join(SITE, '..');
const read = (path) => readFileSync(join(REPO, path), 'utf8');
const FILES = {
  'p/phone.mjs': 'site/pages/p/phone.mjs',
  'p/sense.mjs': 'site/pages/p/sense.mjs',
  't/thief.mjs': 'site/pages/t/thief.mjs',
  't/logic.mjs': 'site/pages/t/logic.mjs',
  't/index.html': 'site/pages/t/index.html',
  landing: 'site/pages/index.html',
  lib: 'site/lib/plain-words.mjs',
};
const TRY = read('site/pages/try/words.mjs');
const PHONE = read(FILES['p/phone.mjs']);

/** A sentence as a source file can hold it: as is, with its apostrophes escaped for a single-quoted string, or in HTML. */
const forms = (text) => [text, text.replace(/'/g, '\\\''), text.replace(/'/g, '&#39;'), text.replace(/'/g, '&rsquo;')];
const unswap = (text) => text.replace(/\bthis page\b/g, 'this tab').replace(/\bThis page\b/g, 'This tab');

test('T6: every sentence copied from another file is in that file, word for word', () => {
  let checked = 0;
  for (const [table, entries] of [['W', W], ['NEXT', NEXT]]) {
    for (const [name, entry] of Object.entries(entries)) {
      assert.ok(entry.from === 'new' || Object.hasOwn(FILES, entry.from), `${table}.${name}: unknown source ${entry.from}`);
      assert.ok(Array.isArray(entry.parts) && entry.parts.length >= 1, `${table}.${name}: no words`);
      if (entry.from === 'new') {
        assert.equal(entry.tab, undefined, `${table}.${name}: only a copied sentence may swap tab for page`);
        continue;
      }
      const source = read(FILES[entry.from]);
      for (const part of entry.parts) {
        if (part === '') continue;
        const wanted = entry.tab ? unswap(part) : part;
        if (entry.tab) assert.notEqual(wanted, part, `${table}.${name}: marked as the tab-to-page swap, and it has no "this page"`);
        assert.ok(forms(wanted).some((form) => source.includes(form)), `${table}.${name}: "${wanted}" is not in ${FILES[entry.from]}`);
        checked += 1;
      }
    }
  }
  assert.ok(checked >= 60, `only ${checked} copied parts checked`);
});

test('T6: the only edit of a copied sentence is the thief tab\'s "this tab" read as "this page"', () => {
  for (const [name, entry] of Object.entries(W)) {
    if (!entry.tab) continue;
    assert.ok(['t/thief.mjs', 't/logic.mjs'].includes(entry.from), `${name}: the swap is the thief tab's alone`);
    const swapped = entry.parts.map(unswap).join('');
    assert.equal(swapped.replace(/\bthis tab\b/g, 'this page').replace(/\bThis tab\b/g, 'This page'), entry.parts.join(''));
  }
});

/** A function's body in a file: everything between the braces after `function name(`. */
function bodyOf(source, name) {
  const at = source.search(new RegExp(`(?:^|\\n)\\s*(?:export\\s+)?(?:async\\s+)?function ${name}\\(`));
  assert.ok(at >= 0, `no function ${name}`);
  const open = source.indexOf('{', source.indexOf(')', at));
  let depth = 0;
  for (let i = open; i < source.length; i += 1) {
    if (source[i] === '{') depth += 1;
    if (source[i] === '}') depth -= 1;
    if (depth === 0) return source.slice(open + 1, i);
  }
  throw new Error(`function ${name} does not close`);
}
const squash = (text) => text.replace(/\s+/g, ' ').trim();
/** The line `const name = ...;` and what it is set to. */
const constOf = (source, name) => {
  const m = new RegExp(`const ${name} = ([^\\n]+)`).exec(source);
  assert.ok(m, `no const ${name}`);
  return squash(m[1]);
};

test('T6: the phone page\'s helpers this page copied still have phone.mjs\'s bodies', () => {
  for (const name of ['failureWords', 'makeWhy', 'fundWhy', 'generalDownWords', 'relayDownWords']) {
    assert.equal(squash(bodyOf(TRY, name)), squash(bodyOf(PHONE, name)), `${name} differs from phone.mjs`);
  }
  assert.equal(constOf(TRY, 'unreadStatusWords'), constOf(PHONE, 'unreadStatusWords'));
  assert.equal(constOf(TRY, 'FUND_UNSENT'), constOf(PHONE, 'FUND_UNSENT'));
  const block = /const NO_BUTTON_WORDS = \{([\s\S]*?)\n\};/.exec(PHONE)[1];
  for (const [why, text] of Object.entries(NO_BUTTON_WORDS)) {
    const row = new RegExp(`\\n\\s*${why}: '((?:[^'\\\\]|\\\\.)*)',`).exec(block);
    assert.ok(row, `phone.mjs NO_BUTTON_WORDS has no ${why}`);
    assert.equal(text, row[1].replace(/\\'/g, '\''), `NO_BUTTON_WORDS.${why}`);
  }
});

test('T6: the line index.html shows with JavaScript off is the phone page\'s, word for word', () => {
  const line = (path) => /<noscript>([\s\S]*?)<\/noscript>/.exec(read(path))?.[1];
  assert.ok(line('site/pages/try/index.html'), 'try/index.html has no noscript line');
  assert.equal(line('site/pages/try/index.html'), line('site/pages/p/index.html'));
});

test('the owner half\'s one sentence of its own is this table\'s', async () => {
  const { READING_SLOT } = await import('../pages/try/owner.mjs');
  assert.equal(READING_SLOT, say(W.slotReading));
});

test('T6: the hint\'s 2 coin tries an hour is the relay\'s own number', () => {
  const m = /export const FUNDS_PER_IP_HOUR = (\d+);/.exec(read('worker/undo-cron/src/undo-state.mjs'));
  assert.ok(m, 'undo-state.mjs no longer names FUNDS_PER_IP_HOUR');
  assert.equal(words.COIN_TRIES_PER_HOUR, Number(m[1]));
});

// ---------------------------------------------------------------- T5

const IN_APP = { inApp: 'the X app' };
const BASE = { rpId: 'undo-btc.pages.dev', bitcoin: 'Mutinynet', sense: {}, mobile: true };
/** Every state of section 5 and every failure row of section 7, as the page puts them in a view. */
const ROWS = [
  { step: 'intro', state: 'boot' }, { step: 'intro', state: 'ready' }, { step: 'intro', state: 'blocked', fail: 'blocked' },
  { step: 'intro', state: 'no_config', fail: 'no_config' }, { step: 'intro', state: 'read_down', fail: 'read_down' }, { step: 'intro', state: 'crashed', fail: 'crashed' },
  { step: 'intro', state: 'ready', fail: 'M1' }, { step: 'intro', state: 'retry', fail: 'M2' },
  { step: 'make', state: 'sheet1' }, { step: 'make', state: 'sheet1', fail: 'M3' }, { step: 'make', state: 'sheet1', fail: 'M3', sense: IN_APP },
  { step: 'make', state: 'km' }, { step: 'make', state: 'stuck', fail: 'M4' }, { step: 'make', state: 'confirm' }, { step: 'make', state: 'confirm', fail: 'M5' },
  { step: 'make', state: 'sheet2' }, { step: 'make', state: 'sheet2', fail: 'M6' }, { step: 'make', state: 'sheet2', fail: 'M6', sense: IN_APP },
  { step: 'make', state: 'stuck', fail: 'M7', limit: 'hourly', mobile: true }, { step: 'make', state: 'stuck', fail: 'M7', limit: 'hourly', mobile: false },
  { step: 'make', state: 'stuck', fail: 'M7' }, { step: 'make', state: 'making' }, { step: 'make', state: 'making', still: 'relay' },
  { step: 'make', state: 'making', still: 'contract' }, { step: 'make', state: 'stuck', fail: 'M8' }, { step: 'make', state: 'stuck', fail: 'M9' },
  { step: 'fund', state: 'funding' }, { step: 'fund', state: 'stuck', fail: 'D1' }, { step: 'fund', state: 'stuck', fail: 'D2' },
  { step: 'fund', state: 'stuck', fail: 'D3' }, { step: 'fund', state: 'stuck', fail: 'D4' },
  { step: 'steal', state: 'count' }, { step: 'steal', state: 'sending' }, { step: 'steal', state: 'refused' },
  { step: 'steal', state: 'asking', here: true }, { step: 'steal', state: 'asking', here: false },
  { step: 'steal', state: 'stuck', fail: 'T1' }, { step: 'steal', state: 'stuck', fail: 'T1r' }, { step: 'steal', state: 'stuck', fail: 'T1b' },
  { step: 'steal', state: 'stuck', fail: 'T2' }, { step: 'steal', state: 'stuck', fail: 'T3' }, { step: 'steal', state: 'stuck', fail: 'T4' },
  { step: 'steal', state: 'stuck', fail: 'T5' }, { step: 'steal', state: 'stuck', fail: 'T6' }, { step: 'steal', state: 'stuck', fail: 'T7' },
  { step: 'steal', state: 'stuck', fail: 'T8' },
  { step: 'cancel', state: 'handoff' }, { step: 'cancel', state: 'request', kind: 'waiting' }, { step: 'cancel', state: 'request', kind: 'unlocked' },
  { step: 'cancel', state: 'tapped' }, { step: 'cancel', state: 'cancel_sending' },
  { step: 'cancel', state: 'request', kind: 'waiting', fail: 'C1' }, { step: 'cancel', state: 'stuck', fail: 'C2' }, { step: 'cancel', state: 'tapped', fail: 'C3' },
  { step: 'cancel', state: 'stuck', fail: 'C4' }, { step: 'cancel', state: 'request', fail: 'C5' }, { step: 'cancel', state: 'stuck', fail: 'C6' },
  { step: 'cancel', state: 'stuck', fail: 'C7' }, { step: 'cancel', state: 'stuck', fail: 'C8' }, { step: 'cancel', state: 'stuck', fail: 'C9' },
  { step: 'cancel', state: 'stuck', fail: 'C10' }, { step: 'cancel', state: 'stuck', fail: 'C11' },
  { step: 'cancelled', state: 'cancelled', took: '1:07' }, { step: 'cancelled', state: 'cancelled' }, { step: 'recap', state: 'recap', took: '1:07' },
  { step: 'intro', state: 'reloaded', fail: 'L2' },
];

test('T5: every state and failure row has exactly one Next sentence, short, with no promise in it', () => {
  const seen = new Set();
  for (const row of ROWS) {
    const view = { ...BASE, ...row };
    const next = nextOf(view);
    const label = `${row.step}/${row.state}/${row.fail ?? '-'}`;
    assert.equal(typeof next.text, 'string', `${label}: not one sentence`);
    assert.ok(next.text.length > 0, `${label}: no Next`);
    assert.ok(!next.text.includes('\n'), `${label}: two lines`);
    assert.ok(next.text.length <= 160, `${label}: ${next.text.length} characters: ${next.text}`);
    assert.doesNotMatch(next.text, /5:00|users|one tap|!/i, `${label}: ${next.text}`);
    assert.equal(next.tag === 'Done', row.step === 'cancelled' || row.step === 'recap', `${label}: the Done tag`);
    seen.add(next.text);
  }
  // The walk reaches every sentence nextOf has.
  for (const [name, entry] of Object.entries(NEXT)) {
    assert.ok([...seen].some((text) => text.startsWith(entry.parts[0])), `NEXT.${name} is never reached by the walk`);
  }
});

test('T5: the run time is said only when it was measured', () => {
  assert.equal(nextOf({ ...BASE, step: 'cancelled', state: 'cancelled', took: '0:58' }).text, 'Done. This run took 0:58 on this page, from Make my test vault to CANCELLED.');
  assert.equal(nextOf({ ...BASE, step: 'cancelled', state: 'cancelled', took: null }).text, 'Done.');
  assert.equal(words.runTime(58_999), '0:58');
  assert.equal(words.runTime(61_000), '1:01');
});

test('T5: a sheet that has not shown says so in the Next line, with the button it put back', () => {
  assert.match(nextOf({ ...BASE, step: 'make', state: 'sheet1', fail: 'M3' }).text, /Tap Make my test vault again/);
  assert.match(nextOf({ ...BASE, step: 'make', state: 'sheet2', fail: 'M6' }).text, /Tap Confirm again/);
  assert.match(nextOf({ ...BASE, step: 'cancel', state: 'tapped', fail: 'C3' }).text, /open the phone page/);
  assert.equal(say(W.beforeMake, 'undo-btc.pages.dev'), 'Next, this device asks to save a passkey named "test vault" for undo-btc.pages.dev: this vault\'s cancel key. You can delete it afterwards.');
});
