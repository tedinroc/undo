// A built page's modulepreload links, read back against what its module scripts import as V8 parses them. The links are
// what let a slow phone network ask for every module in the first round trip, not one import level at a time. They
// come from site/build.mjs's own walk, so this holds them to another parser: a link missing, one too many, or one after
// the script fails here, on every page the build writes.
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, sep } from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { build, importGraph } from '../build.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const SITE = join(HERE, '..');
const SCRIPT = /<script type="module" src="([^"]+)"><\/script>/g;
const PRELOAD = /<link rel="modulepreload" href="([^"]+)">/g;

/** Every module the entries reach in a built folder, the entries included, as V8 parses each file. */
const closureOf = (out, entries) => JSON.parse(execFileSync(process.execPath, ['--experimental-vm-modules', '--no-warnings', join(HERE, 'module-closure.mjs'), out, ...entries], { encoding: 'utf8' }));

/** What is wrong with a page's links, one line each; none when they are exactly its scripts' imports, all before them. */
function preloadProblems(html, closure) {
  const scripts = [...html.matchAll(SCRIPT)].map((m) => m[1]);
  const links = [...html.matchAll(PRELOAD)].map((m) => m[1]);
  const want = closure.filter((url) => !scripts.includes(url));
  const problems = [];
  for (const url of want) if (!links.includes(url)) problems.push(`not preloaded: ${url}`);
  for (const url of links) if (!want.includes(url)) problems.push(`preloaded, and no script imports it: ${url}`);
  for (const url of new Set(links.filter((u, i) => links.indexOf(u) !== i))) problems.push(`preloaded twice: ${url}`);
  const firstScript = html.search(/<script type="module" /);
  if (links.length > 0 && html.lastIndexOf('<link rel="modulepreload"') > firstScript) problems.push('a link comes after the module script');
  return problems;
}

const walk = (dir) => readdirSync(dir).flatMap((name) => (statSync(join(dir, name)).isDirectory() ? walk(join(dir, name)) : [join(dir, name)]));

let out;
before(() => {
  out = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'undo-preload-'));
  build({ configPath: join(SITE, 'config/testnet.json'), out });
});
after(() => rmSync(out, { recursive: true, force: true }));

test('every built page preloads exactly the modules its scripts import, as V8 parses them, and all before the script', () => {
  const pages = walk(out).filter((f) => f.endsWith('.html')).map((f) => relative(out, f).split(sep).join('/')).sort();
  const counts = {};
  for (const page of pages) {
    const html = readFileSync(join(out, page), 'utf8');
    const scripts = [...html.matchAll(SCRIPT)].map((m) => m[1]);
    const closure = scripts.length > 0 ? closureOf(out, scripts) : [];
    assert.deepEqual(preloadProblems(html, closure), [], page);
    counts[page] = [...html.matchAll(PRELOAD)].length;
  }
  // The pages a judge opens, each with a deep graph, so each with its whole list.
  for (const page of ['p/index.html', 'phone/index.html', 't/index.html', 'thief/index.html', 'index.html', 'replay/index.html']) {
    assert.ok(counts[page] > 40, `${page}: ${counts[page]} links`);
  }
});

test('the check can fail: a link taken out, one added, or one moved after the script is each caught', () => {
  const html = readFileSync(join(out, 'p/index.html'), 'utf8');
  const closure = closureOf(out, ['/p/phone.mjs']);
  assert.deepEqual(preloadProblems(html, closure), []);
  const gone = html.replace('<link rel="modulepreload" href="/site/lib/near-read.mjs">\n', '');
  assert.deepEqual(preloadProblems(gone, closure), ['not preloaded: /site/lib/near-read.mjs']);
  const extra = html.replace('<script type="module"', '<link rel="modulepreload" href="/site/lib/soft-authenticator.mjs">\n<script type="module"');
  assert.deepEqual(preloadProblems(extra, closure), ['preloaded, and no script imports it: /site/lib/soft-authenticator.mjs']);
  const late = gone.replace('</head>', '<link rel="modulepreload" href="/site/lib/near-read.mjs">\n</head>');
  assert.deepEqual(preloadProblems(late, closure), ['a link comes after the module script']);
});

test('the parser is V8\'s, not the build\'s: an import written over lines the build\'s walk does not read is still found', () => {
  const dir = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'undo-closure-'));
  try {
    writeFileSync(join(dir, 'entry.mjs'), 'import {\n  a,\n  b } from \'./two.mjs\';\nexport const sum = a + b;\n');
    writeFileSync(join(dir, 'two.mjs'), 'export const a = 1;\nexport const b = 2;\n');
    assert.deepEqual(closureOf(dir, ['/entry.mjs']), ['/entry.mjs', '/two.mjs']);
    assert.deepEqual([...importGraph([join(dir, 'entry.mjs')], dir)].map((f) => relative(dir, f)), ['entry.mjs'], 'the walk misses it, so a page written so would fail the test above');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
