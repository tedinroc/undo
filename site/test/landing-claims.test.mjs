// What the landing page and the replay may claim, from the attack on them: no film is named before one is
// published, a step from another run says so in its title, and the status line prints the RPC's refusal instead of a
// Python traceback. Offline: python3 runs the status line's decoder on recorded answer shapes.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { buildRun } from '../../tools/replay-run.mjs';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const PAGES = join(REPO, 'site', 'pages');
const landing = readFileSync(join(PAGES, 'index.html'), 'utf8');
const landingJs = readFileSync(join(PAGES, 'landing', 'landing.mjs'), 'utf8');
const run = buildRun();
const unescape = (html) => html.replaceAll('&lt;', '<').replaceAll('&gt;', '>').replaceAll('&amp;', '&');

test('with no film published, the landing page names no film: no "From the film" list, and the slot\'s label says so', () => {
  assert.equal(existsSync(join(PAGES, 'film', 'undo-for-bitcoin.mp4')), false, 'a film file is here: replace this test with one that checks the film\'s own capture record');
  assert.doesNotMatch(landing, /From the film/i);
  assert.doesNotMatch(landing, /aria-label="The film/);
  assert.match(landing, /<video id="film"[^>]*aria-label="[^"]*not published yet[^"]*"/);
  assert.equal('film' in run, false, 'run.json has no list named for a film');
  assert.ok(Array.isArray(run.earlier) && run.earlier.length > 0);
  assert.match(landingJs, /addEventListener\('playing'[\s\S]*?setAttribute\('aria-label'/, 'once a film plays, the not-published label is replaced');
});

test('replay: a step from another run than the refusal says so in its title, with that run\'s date, and that it was the owner\'s test spend', () => {
  const refusal = run.steps.find((s) => s.id === 'refused');
  assert.match(refusal.title, /thief/i);
  const thiefDate = run.runs[refusal.run].date;
  const others = run.steps.filter((s) => s.run && s.run !== refusal.run);
  assert.deepEqual(others.map((s) => s.id), ['wait', 'signed', 'exit']);
  for (const s of others.filter((x) => x.id !== 'exit')) {
    const date = run.runs[s.run].date;
    assert.notEqual(date, thiefDate);
    assert.ok(s.title.includes(date), `${s.id}: its title names ${date}`);
    assert.match(s.title, /^(Another request on this vault|That same request)/, s.id);
    assert.match(s.title, /the owner's own test spend/, s.id);
    assert.doesNotMatch(s.title, /thief/i, s.id);
  }
});

/** The python3 -c program a status line pipes into. */
const decoderOf = (line) => {
  const m = /python3 -c '([^']+)'/.exec(line);
  assert.ok(m, 'the status line pipes into python3 -c');
  return m[1];
};

test('the status line prints the contract\'s words, or the RPC\'s refusal, and never a traceback; the page and its script agree', () => {
  const pageLine = unescape(/<pre id="curl"[^>]*>([\s\S]*?)<\/pre>/.exec(landing)[1]);
  const scriptCode = /python3 -c '([^']+)'`/.exec(landingJs)?.[1];
  const code = decoderOf(pageLine);
  assert.equal(scriptCode, code, 'landing.mjs writes the same decoder the HTML shows');
  const rpc = JSON.parse(readFileSync(join(REPO, 'site', 'config', 'testnet.json'), 'utf8')).rpc[0];
  assert.ok(pageLine.startsWith(`curl -s ${rpc} `), 'the static line asks the RPC the script swaps in, and the README names');
  const decode = (answer) => spawnSync('python3', ['-c', code], { input: JSON.stringify(answer), encoding: 'utf8' });
  const words = Buffer.from(JSON.stringify({ ok: true, lines: ['guard online'] }));
  const ok = decode({ jsonrpc: '2.0', id: 'u', result: { result: [...words], logs: [] } });
  assert.equal(ok.status, 0, ok.stderr);
  assert.equal(ok.stdout.trim(), words.toString());
  // Shapes recorded from public testnet RPC on 2026-11-07: an account that does not exist, and one with no status view.
  const unknown = decode({ jsonrpc: '2.0', id: 'u', error: { name: 'HANDLER_ERROR', cause: { name: 'UNKNOWN_ACCOUNT', info: { requested_account_id: 'not-deployed-yet' } } } });
  assert.equal(unknown.status, 0, unknown.stderr);
  assert.match(unknown.stdout, /^RPC refused: .*UNKNOWN_ACCOUNT/);
  assert.equal(unknown.stderr, '');
  const noView = decode({ jsonrpc: '2.0', id: 'u', result: { error: 'wasm execution failed with error: MethodResolveError(MethodNotFound)', logs: [] } });
  assert.equal(noView.status, 0, noView.stderr);
  assert.match(noView.stdout, /^RPC refused: .*MethodNotFound/);
});
