// What the landing page and the replay may claim, from the attack on them: the film it shows is the file its own
// capture record names, and the page lists that take's hashes and says what the take was; a step from another run says
// so in its title, and the status line prints the RPC's refusal instead of a Python traceback. Offline: python3 runs
// the status line's decoder on recorded answer shapes.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
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

test('the film is published with its own capture record: the file that record names, a "From the film" list that is the record\'s, and a label and a note that say what it is', () => {
  const take = JSON.parse(readFileSync(join(REPO, 'proofs', 'film-take.json'), 'utf8'));
  const film = readFileSync(join(PAGES, 'film', 'undo-for-bitcoin.mp4'));
  assert.equal(take.film.file, 'site/pages/film/undo-for-bitcoin.mp4');
  assert.equal(createHash('sha256').update(film).digest('hex'), take.film.sha256, 'proofs/film-take.json names another cut: after a new cut, write its sha256 and its length there');
  assert.ok(take.film.seconds >= 60 && take.film.seconds <= 75);
  // What the take was, said the same way everywhere: test networks, Chrome's virtual authenticator, a synthetic voice.
  assert.deepEqual(take.labels, ['live-testnet', 'live-mutinynet', 'virtual authenticator']);
  assert.match(take.what, /virtual authenticator, not a phone's/);
  assert.match(take.film.narration, /synthetic voice/);
  // The record holds no key: every 64-hex string in it is the vault id, the film's hash, or a Bitcoin txid it names.
  const named = new Set([take.vault.id, take.film.sha256, take.coin.mutinynet_txid, ...take.thief.node_answer_verbatim.match(/\b[0-9a-f]{64}\b/g)]);
  for (const h of JSON.stringify(take).match(/\b[0-9a-f]{64}\b/g)) assert.ok(named.has(h), `an unnamed 32-byte hex string in the record: ${h.slice(0, 8)}…`);
  assert.doesNotMatch(JSON.stringify(take), /"[^"]*(seed|secret|private|spend_key)[^"]*":/i);
  assert.ok(take.thief.node_answer_verbatim.includes(take.coin.mutinynet_txid), 'the node refused a spend of the film\'s coin');
  assert.equal(take.thief.unlock_ms - take.thief.proposed_at_ms, take.thief.wait_ms);
  // The landing page's list is the record's, in the film's order, and nothing else on the page is named for the film.
  assert.deepEqual(run.film.hashes.map((l) => l.hash), [take.vault.address, take.coin.mutinynet_txid, take.thief.propose_tx, take.cancel.tx, take.after.execute_after_the_wait_tx]);
  assert.equal(run.film.date, take.started_utc.slice(0, 10));
  assert.equal(landing.match(/From the film/g).length, 1);
  assert.match(landing, /<h2 id="from-film" class="h2">From the film:<\/h2>/);
  const note = /<p id="film-note" class="small">([^<]+)<\/p>/.exec(landing)[1];
  assert.ok(note.includes(`one take of these pages, ${run.film.date}, on NEAR testnet and Mutinynet`));
  assert.ok(note.includes(run.film.note), 'the note says a virtual authenticator stood in for the phone');
  assert.match(note, /from a real phone that path has not yet run/);
  assert.match(note, /Where the recording was cut for time, the film says so on that shot\./);
  assert.match(note, /The narration is a synthetic voice \(AI text-to-speech\)\./);
  // The slot's label says what plays, and that it starts muted with its words on screen; no script has to correct it.
  assert.match(landing, /<video id="film"[^>]*aria-label="The film, about a minute: [^"]*It starts muted, and every spoken line is also on screen\."/);
  assert.doesNotMatch(landing, /not published yet/);
  assert.doesNotMatch(landingJs, /setAttribute\('aria-label'/);
  assert.match(landing, /<meta property="og:image:alt" content="The film's headline, large type on black: Your Bitcoin key was just stolen\. Under it: Undo for Bitcoin, a cancel button for Bitcoin\.">/);
  // The README says the same of the voice, next to the line about AI coding assistance.
  const readme = readFileSync(join(REPO, 'README.md'), 'utf8');
  assert.match(readme, /with AI coding assistance \(Claude\)\. The film's narration is a synthetic voice \(AI text-to-speech\), not a recording of a person\./);
  // The replay still claims no cancel of its own vault: the film's take is another vault on another day.
  assert.equal(run.steps.find((s) => s.id === 'cancel').recorded, false);
  assert.notEqual(take.vault.id, run.vault.id);
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
