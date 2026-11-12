// T1, THE RULE, read from the source: iOS Safari opens a passkey sheet only for a call made inside the tap, so in every
// handler that opens one, the passkey call comes first. Before it, only synchronous bookkeeping (a new call, ending the
// old one, a guard return, a digest made before the tap); no await, promise chain, timer, microtask, fetch or frame. The
// listeners that call the handlers are not async, and nothing on the way from the handler to navigator.credentials waits.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const SITE = join(dirname(fileURLToPath(import.meta.url)), '..');
const REPO = join(SITE, '..');
const read = (path) => readFileSync(join(REPO, path), 'utf8');
const TRY = read('site/pages/try/try.mjs');
const FORBIDDEN = /\bawait\b|\.then\(|\.catch\(|\.finally\(|\bsetTimeout\b|\bsetInterval\b|\bqueueMicrotask\b|\bfetch\(|\brequestAnimationFrame\b|\bPromise\b|\bnap\(|\bsleep\(|\bwhenVisible\(/;

/** A function's text: its head (to tell async apart) and its body. */
function fn(source, name) {
  const m = new RegExp(`(^|\\n)([ \\t]*(?:export\\s+)?(async\\s+)?function\\s+${name}\\s*\\()`).exec(source);
  assert.ok(m, `no function ${name}`);
  const at = m.index + m[1].length;
  const open = source.indexOf('{', source.indexOf(')', at));
  let depth = 0;
  for (let i = open; i < source.length; i += 1) {
    if (source[i] === '{') depth += 1;
    if (source[i] === '}') depth -= 1;
    if (depth === 0) return { async: Boolean(m[3]), body: source.slice(open + 1, i) };
  }
  throw new Error(`${name} does not close`);
}

/** Comments out, so a word in a comment is not read as code. Strings stay: none of the words below sits in one here. */
const code = (text) => text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:'"`])\/\/.*$/gm, '$1');

/** Everything a handler does before `call(`: allowed only when it is synchronous bookkeeping. */
function before(body, call) {
  const at = code(body).indexOf(`${call}(`);
  assert.ok(at >= 0, `${call} is not called`);
  return code(body).slice(0, at);
}
const callsIn = (text) => [...text.matchAll(/([A-Za-z_$][\w$]*)\s*\(/g)].map((m) => m[1]).filter((n) => !['if', 'for', 'while', 'switch', 'return', 'function'].includes(n));

const HANDLERS = [
  { name: 'onMake', call: 'askNewPasskey', allowed: ['newCall'] },
  { name: 'onConfirm', call: 'confirmVault', allowed: ['newCall'] },
];

test('T1: each passkey handler is not async, and its passkey call is the first thing it does', () => {
  for (const { name, call, allowed } of HANDLERS) {
    const { async, body } = fn(TRY, name);
    assert.equal(async, false, `${name} is async`);
    const head = before(body, call);
    assert.doesNotMatch(head, FORBIDDEN, `${name}: something waits before ${call}`);
    for (const c of callsIn(head)) assert.ok(allowed.includes(c), `${name}: ${c}() runs before ${call}`);
  }
  // newCall itself: ends the old call and makes a new one, and waits for nothing.
  const { async, body } = fn(TRY, 'newCall');
  assert.equal(async, false);
  assert.doesNotMatch(code(body), FORBIDDEN);
});

test('T1: Cancel (v2): onCancel\'s first statement is owner.cancelTap(), and cancelTap asks the passkey before anything waits', () => {
  if (!/export const CANCEL_HERE = true;/.test(TRY)) return;
  const onCancel = fn(TRY, 'onCancel');
  assert.equal(onCancel.async, false);
  assert.match(code(onCancel.body).trim(), /^T\.owner\.cancelTap\(\);/, 'cancelTap is the first statement');
  const OWNER = read('site/pages/try/owner.mjs');
  const tap = fn(OWNER, 'cancelTap');
  assert.equal(tap.async, false, 'cancelTap is async');
  const head = before(tap.body, 'askAssertion');
  assert.doesNotMatch(head, FORBIDDEN, 'something waits before askAssertion');
  for (const c of callsIn(head)) assert.ok(['ensurePrep', 'AbortController', 'abort'].includes(c), `${c}() runs before askAssertion`);
  const prep = fn(OWNER, 'ensurePrep');
  assert.equal(prep.async, false, 'ensurePrep is async');
  assert.doesNotMatch(code(prep.body), FORBIDDEN);
  // The Cancel button's listener calls straight through: () => cancel(), and cancel is onCancel.
  assert.match(OWNER, /id: 'cancel', type: 'button', [^\n]*onclick: \(\) => cancel\(\)/);
  assert.match(TRY, /\n\s+onCancel,\n/);
});

test('T1: the buttons that open a sheet call their handler straight from a listener that is not async', () => {
  const button = /const passkeyButton = \(id, text, prompt, handler\) => \(\{[\s\S]*?onclick: \(\) => handler\(\)/.exec(TRY);
  assert.ok(button, 'passkeyButton\'s listener is () => handler()');
  assert.doesNotMatch(TRY, /onclick:\s*async/, 'an async click listener');
  assert.doesNotMatch(TRY, /addEventListener\(\s*'click'\s*,\s*async/);
  assert.match(TRY, /const makeButton = \(\) => passkeyButton\('make', [^\n]*, onMake\);/);
  assert.match(TRY, /const confirmButton = \(\) => passkeyButton\('confirm', [^\n]*, onConfirm\);/);
  assert.match(TRY, /passkeyButton\('retry-passkey', [^\n]*, onMake\)/);
  // Every button that opens a sheet is made by passkeyButton, and no other button's handler calls a passkey function.
  for (const m of TRY.matchAll(/actionButton\('([\w-]+)'/g)) assert.ok(!['make', 'confirm', 'retry-passkey', 'cancel'].includes(m[1]), `${m[1]} is a passkey button made as an action button`);
});

test('T1: nothing on the way from confirmVault and the passkey calls to navigator.credentials waits', () => {
  const vm = read('site/pages/p/vault-make.mjs');
  const confirm = fn(vm, 'confirmVault');
  assert.equal(confirm.async, false);
  assert.doesNotMatch(before(confirm.body, 'buildCreateArgs'), FORBIDDEN);
  // buildCreateArgs makes the digest and four signatures, then calls assert(digest) before its first await.
  const intents = read('site/lib/intents.mjs');
  const build = fn(intents, 'buildCreateArgs');
  const firstAwait = code(build.body).indexOf('await');
  assert.ok(firstAwait >= 0 && code(build.body).slice(firstAwait).startsWith('await assert(digest)'), 'buildCreateArgs waits before it asks the passkey');
  const ask = read('site/pages/p/passkey-ask.mjs');
  const watched = fn(ask, 'watched');
  assert.doesNotMatch(before(watched.body, 'start').replace(/setTimeout\(\(\) => \{[\s\S]*?\}, SHEET_HANG_MS\);/, ''), /\bawait\b|\.then\(|\bqueueMicrotask\b|\bfetch\(/);
  for (const name of ['askAssertion', 'askNewPasskey']) assert.equal(fn(ask, name).async, false, name);
  const webauthn = read('site/lib/webauthn.mjs');
  // The one await there is on the browser's own call: it waits for the sheet's answer, after the sheet was asked for.
  const upTo = (name, call) => before(fn(webauthn, name).body, call).replace(/await\s*$/, '');
  assert.doesNotMatch(upTo('getAssertion', 'credentials.get'), /\bawait\b/);
  assert.doesNotMatch(upTo('createPasskey', 'credentials.create'), /\bawait\b/);
});

test('T1: no window.open anywhere on the page, and the hand-off stays in this tab', () => {
  for (const file of ['try.mjs', 'steps.mjs', 'words.mjs']) assert.doesNotMatch(read(`site/pages/try/${file}`), /window\.open|\bopen\(/, file);
  assert.match(TRY, /location\.replace\(url\)/);
});

test('S0: the fit that keeps S0 whole on a short screen hides no line, holds to S0, and steps only while #screen is taller than its box', () => {
  const css = read('site/pages/try/try.css');
  const rules = [...css.matchAll(/([^{}]+)\{([^{}]*)\}/g)].map((m) => ({ selector: m[1].replace(/\/\*[\s\S]*?\*\//g, '').trim(), body: m[2] }));
  const fit = rules.filter((r) => /#frame\.(tight|tighter|tightest|dense|densest)\b/.test(r.selector));
  assert.ok(fit.length >= 20, 'the S0 fit\'s rules are not in try.css');
  for (const r of fit) {
    assert.match(r.selector, /^html\[data-step="intro"\] #frame\.(tight|tighter|tightest|dense|densest)\b/, `${r.selector} is not held to S0`);
    assert.doesNotMatch(r.body, /display|visibility|opacity|max-height|overflow|(^|[^-])height\s*:\s*0|clip|position/, `${r.selector} may take a line away`);
    for (const [, px] of r.body.matchAll(/font-size\s*:\s*([\d.]+)px/g)) assert.ok(Number(px) >= 11, `${r.selector}: ${px}px`);
  }
  const body = code(fn(TRY, 'fitIntro').body);
  assert.doesNotMatch(body, /\.hidden\s*=|display|remove\(\)|replaceChildren|\.style\b/, 'fitIntro takes a line away');
  // Each step only while the ones before leave #screen taller than its box; a screen that fits as drawn gets none.
  assert.match(body, /const over = \(\) => scr\.scrollHeight - scr\.clientHeight;/);
  assert.match(body, /for \(const step of INTRO_STEPS\) \{\s*if \(over\(\) <= 0\) return;\s*frame\.classList\.add\(step\);\s*\}/);
  assert.match(body, /if \(T\.step !== 'intro'\) \{\s*if \(T\.introFit !== null\) \{\s*frame\.classList\.remove\(\.\.\.INTRO_STEPS\);/, 'the classes stay after S0');
  // Each fit starts from S0 as drawn.
  assert.match(body, /T\.introFit = fitFor;\s*frame\.classList\.remove\(\.\.\.INTRO_STEPS\);/);
  assert.match(code(TRY), /const INTRO_STEPS = \['tight', 'tighter', 'tightest', 'dense', 'densest'\];/);
  // After every paint (S0's words drawn) and on a resize.
  assert.match(code(fn(TRY, 'paint').body), /fitIntro\(\);\s*$/);
  assert.match(code(TRY), /addEventListener\('resize', \(\) => \{[^}]*fitIntro\(\);/);
});

test('S0: the fit draws the hint under the button smaller too', () => {
  const css = read('site/pages/try/try.css');
  const rules = [...css.matchAll(/([^{}]+)\{([^{}]*)\}/g)].map((m) => ({ selector: m[1].replace(/\/\*[\s\S]*?\*\//g, '').trim(), body: m[2] }));
  // #aside sits under the dock, outside #screen: every line it takes is a line #screen loses.
  const aside = rules.filter((r) => /^html\[data-step="intro"\] #frame\.(tightest|dense) \.aside\b/.test(r.selector));
  assert.ok(aside.some((r) => /#frame\.tightest \.aside$/.test(r.selector) && /font-size\s*:\s*12px/.test(r.body)), 'the hint under the button keeps its 14 px at .tightest');
  assert.ok(aside.some((r) => /#frame\.dense \.aside$/.test(r.selector) && /line-height/.test(r.body)), 'the hint under the button keeps its line spacing at .dense');
});

test('S0: the last step draws the type a size smaller again, none under 11 px, the hint under the button included', () => {
  // Safari on an iPhone that names iOS 18 or later draws the long hint under the button (the AutoFill path); with the
  // hint of vaults made in the past hour and M1's line, a 320 px wide screen in WebKit is still over after .dense.
  const css = read('site/pages/try/try.css');
  const rules = [...css.matchAll(/([^{}]+)\{([^{}]*)\}/g)].map((m) => ({ selector: m[1].replace(/\/\*[\s\S]*?\*\//g, '').trim(), body: m[2] }));
  const densest = rules.filter((r) => /#frame\.densest\b/.test(r.selector));
  const size = (part) => {
    const r = densest.find((x) => x.selector === `html[data-step="intro"] #frame.densest ${part}`);
    assert.ok(r, `no .densest rule for ${part}`);
    return Number(r.body.match(/font-size\s*:\s*([\d.]+)px/)?.[1]);
  };
  assert.equal(size('.title'), 18);
  assert.equal(size('.ln.warn'), 13);
  assert.equal(size('.rows li'), 12);
  assert.equal(size('.more .small'), 11);
  assert.equal(size('.aside'), 11);
  for (const r of densest) assert.doesNotMatch(r.body, /line-height|margin|padding|display|visibility|opacity|color/, `${r.selector}: the type only`);
  // The last step, taken only when .dense leaves #screen taller than its box.
  assert.equal(code(TRY).match(/const INTRO_STEPS = \[([^\]]*)\];/)?.[1].split(',').at(-1).trim(), "'densest'");
});

test('S0: the fit measures the wordmark again at the size each step draws it, and when the steps come off', () => {
  // .tightest draws the chip and the wordmark smaller: "Undo for Bitcoin" or "Undo" is decided at the size it is drawn,
  // after the steps are taken and when they come off on leaving S0 (a resize on S0 measured it under the old steps).
  const body = code(fn(TRY, 'fitIntro').body);
  assert.match(body, /if \(T\.introFit !== null\) \{\s*frame\.classList\.remove\(\.\.\.INTRO_STEPS\);\s*T\.introFit = null;\s*fitWordmark\(\);\s*\}/, 'the wordmark is not measured again off S0');
  assert.match(body, /\} finally \{\s*fitWordmark\(\);\s*\}\s*$/, 'the wordmark is not measured again after the steps');
});

test('S4-S7: the fit that keeps the owner block on screen hides no line: its CSS takes room only from empty slots', () => {
  const css = read('site/pages/try/try.css');
  const rules = [...css.matchAll(/([^{}]+)\{([^{}]*)\}/g)].map((m) => ({ selector: m[1].replace(/\/\*[\s\S]*?\*\//g, '').trim(), body: m[2] }));
  const fit = rules.filter((r) => /#screen\.(roomy|small-digits|packed)/.test(r.selector));
  assert.ok(fit.length >= 5, 'the fit\'s rules are not in try.css');
  for (const r of fit) {
    if (/display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0(?![.\d])|max-height\s*:\s*0|overflow\s*:\s*hidden/.test(r.body)) {
      assert.match(r.selector, /:empty$/, `${r.selector} hides what may hold a line`);
    }
  }
  // phone.css hides the fee line on a short phone; this page shows it.
  assert.ok(rules.some((r) => r.selector === '.owner .fee:not([hidden])' && /display\s*:\s*block/.test(r.body)));
  const body = fn(TRY, 'fitOwner').body;
  assert.doesNotMatch(code(body), /\.hidden\s*=|display|remove\(\)|replaceChildren/, 'fitOwner takes a line away');
});
