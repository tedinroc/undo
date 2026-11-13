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
const readme0 = () => readFileSync(join(REPO, 'README.md'), 'utf8');
const unescape = (html) => html.replaceAll('&lt;', '<').replaceAll('&gt;', '>').replaceAll('&amp;', '&');

test('the film is published with its own capture record: the file that record names, a "From the film" list that is the record\'s, and a label and a note that say what it is', () => {
  const take = JSON.parse(readFileSync(join(REPO, 'proofs', 'film-take.json'), 'utf8'));
  const film = readFileSync(join(PAGES, 'film', 'undo-for-bitcoin.mp4'));
  assert.equal(take.film.file, 'site/pages/film/undo-for-bitcoin.mp4');
  assert.equal(createHash('sha256').update(film).digest('hex'), take.film.sha256, 'proofs/film-take.json names another cut: after a new cut, write its sha256 and its length there');
  assert.ok(take.film.seconds >= 60 && take.film.seconds <= 75);
  assert.equal(take.film.sha256, 'e779a40e2cf2113739aab761c9190e154a8c72ce11733b6110bae9a01d78f696', 'film v3, the cut e1 its author approved');
  // What the take was, said the same way everywhere: test networks, a real phone whose device and browser are its
  // author's report, the thief tab in headless Chrome on a second device, a synthetic voice.
  assert.deepEqual(take.labels, ['live-testnet', 'live-mutinynet', 'real device', 'iPhone screen recording', 'thief tab: headless Chrome on a Mac']);
  assert.match(take.what, /device_as_reported is the author's report, not the chain's: an iPhone, in Safari, with Face ID\./);
  assert.match(take.what, /the thief tab of the same site in headless Chrome on a Mac, a second device/);
  assert.match(take.device_as_reported.by, /^the author, /);
  assert.match(take.device_as_reported.what_the_chain_says_of_it, /user verified says the authenticator verified the user, not how/);
  assert.match(take.film.narration, /synthetic voice/);
  // The film's corner clock stops on the phone page's CANCELLED; the cancel's block came earlier, and the record says so.
  assert.match(take.film.chip, /the cancel's block came earlier/);
  // The earlier film's take is kept, renamed, and says it is no longer the film on the landing page.
  const earlierTake = JSON.parse(readFileSync(join(REPO, 'proofs', 'chrome-take.json'), 'utf8'));
  assert.match(earlierTake.what, /^The live take film v2 was cut from, 2026-11-11\. Film v2 was the film on the landing page until film v3 replaced it; /);
  assert.notEqual(earlierTake.film.sha256, take.film.sha256);
  assert.notEqual(earlierTake.vault.id, take.vault.id);
  // The record holds no key: every 64-hex string in it is the vault id, the film's hash, a recording's hash, or a
  // Bitcoin txid it names.
  const named = new Set([take.vault.id, take.film.sha256, take.thief_cam.video.sha256, take.phone_recording.sha256_ingested, take.coin.mutinynet_txid, ...take.thief.node_answer_verbatim.match(/\b[0-9a-f]{64}\b/g)]);
  for (const h of JSON.stringify(take).match(/\b[0-9a-f]{64}\b/g)) assert.ok(named.has(h), `an unnamed 32-byte hex string in the record: ${h.slice(0, 8)}…`);
  assert.doesNotMatch(JSON.stringify(take), /"[^"]*(seed|secret|private|spend_key)[^"]*":/i);
  assert.ok(take.thief.node_answer_verbatim.includes(take.coin.mutinynet_txid), 'the node refused a spend of the film\'s coin');
  assert.equal(take.thief.unlock_ms - take.thief.proposed_at_ms, take.thief.wait_ms);
  // The landing page's list is the record's, in the film's order, and nothing else on the page is named for the film.
  assert.deepEqual(run.film.hashes.map((l) => l.hash), [take.vault.address, take.coin.mutinynet_txid, take.thief.propose_tx, take.cancel.tx]);
  assert.equal(run.film.date, take.started_utc.slice(0, 10));
  assert.equal(landing.match(/From the film/g).length, 1);
  assert.match(landing, /<h2 id="from-film" class="h2">From the film:<\/h2>/);
  const note = /<p id="film-note" class="small">([^<]+)<\/p>/.exec(landing)[1];
  assert.ok(note.includes(`one take of these pages, ${run.film.date}, on NEAR testnet and Mutinynet`));
  assert.ok(note.includes(`${run.film.note}.`), 'the note says where the phone page and the thief tab ran');
  assert.equal(run.film.note, 'The phone page ran in Safari on an iPhone, as the author reported it, and the film\'s phone shots are that phone\'s own screen recording; the thief tab ran in headless Chrome on a Mac, a second device');
  assert.doesNotMatch(note, /virtual authenticator|Face ID|\b41 s\b/);
  // The one-device run from a real phone, on another vault: the note says so, with the device and the browser as the
  // author's report.
  const phone = JSON.parse(readFileSync(join(REPO, 'proofs', 'phone-take.json'), 'utf8'));
  assert.ok(note.includes(`${run.film.note}. From the thief's Send to the phone page's CANCELLED it runs in real time, but for two cuts of under 0.2 s. A Cancel from a real phone also ran ${phone.vault_made_block_utc.slice(0, 10)}, on another vault: one iPhone, with the phone page and the thief tab as two ${phone.device_as_reported.browser} tabs on it, as the author reported it; the README links its hash.`), note);
  // The two cuts are the record's, each under 0.2 s.
  assert.equal(take.film.cut_for_time.length, 2);
  for (const cut of take.film.cut_for_time) assert.ok(Number(/^(\d+\.\d+) s /.exec(cut)[1]) < 0.2, cut);
  assert.equal(phone.device_as_reported.browser, 'Safari');
  assert.notEqual(phone.vault.id, take.vault.id);
  assert.doesNotMatch(note, /not yet run/);
  assert.match(readme0(), new RegExp(`\\[\`${phone.cancel.tx}\`\\]\\(https://testnet\\.near\\.rocks/tx/${phone.cancel.tx}\\)`), 'the README links that hash');
  assert.match(note, /The narration is a synthetic voice \(AI text-to-speech\)\./);
  // The slot's label says what plays, and that it starts muted with what each line says on screen, not that every word is
  // (the voice's "Bitcoin says no" is the page's REFUSED BY BITCOIN); no script has to correct it.
  assert.match(landing, /<video id="film"[^>]*aria-label="The film, about a minute: [^"]*It starts muted, and what each spoken line says is also on screen\."/);
  assert.doesNotMatch(landing, /every spoken line/);
  assert.doesNotMatch(landing, /not published yet/);
  assert.doesNotMatch(landingJs, /setAttribute\('aria-label'/);
  // The link card's words and the poster's, as they are drawn: the card is the headline, the name and the line under it;
  // the poster, the film's first frame, is the headline over the thief tab with the stolen-key field blurred: a blurred row
  // of random characters, never the key, whose glyphs were never painted (proofs/film-take.json, redaction).
  for (const prop of ['property="og:image:alt"', 'name="twitter:image:alt"']) {
    assert.match(landing, new RegExp(`<meta ${prop} content="The film's headline, large type on black: Your Bitcoin key was just stolen\\. Under it: Undo for Bitcoin\\. A cancel button for Bitcoin\\. NEAR can refuse; it can't take\\.">`));
  }
  assert.match(landing, /aria-label="The film, about a minute: [^"]*Its first frame is the headline over the thief tab, the stolen-key field blurred\. /);
  assert.match(take.redaction.method, /^key glyphs never painted .*a blurred row of random characters \(never the key\)/);
  // The README says the same of the voice, next to the line about AI coding assistance.
  const readme = readFileSync(join(REPO, 'README.md'), 'utf8');
  assert.match(readme, /with AI coding assistance \(Claude\)\. The film's narration is a synthetic voice \(AI text-to-speech\), not a recording of a person\./);
  // The replay claims no cancel on its own vault: its cancel step is this take, another vault, and the step says so.
  const cancel = run.steps.find((s) => s.id === 'cancel');
  assert.equal(cancel.run, 'take');
  assert.match(cancel.title, /Another test vault of the same contract/);
  assert.notEqual(take.vault.id, run.vault.id);
});

test('replay: a step from another run than the refusal says so in its title: the owner\'s own request by its date and time, the take as another vault', () => {
  const refusal = run.steps.find((s) => s.id === 'refused');
  assert.match(refusal.title, /thief/i);
  const others = run.steps.filter((s) => s.run && s.run !== refusal.run);
  assert.deepEqual(others.map((s) => s.id), ['wait', 'cancel', 'signed', 'exit']);
  // The owner's request is named the same way in both of its steps, by a date and a time that are not the refusal's.
  const request = `${run.runs.g2.date} at ${run.steps.find((s) => s.id === 'wait').at.slice(11, 16)} UTC`;
  assert.notEqual(request, `${run.runs[refusal.run].date} at ${refusal.at.slice(11, 16)} UTC`);
  for (const s of others.filter((x) => x.run === 'g2' && x.id !== 'exit')) {
    assert.ok(s.title.includes(request), `${s.id}: its title names ${request}`);
    assert.match(s.title, /^(Another request on this vault, |Back on the first vault, the request of )/, s.id);
    assert.match(s.title, /the owner's own test spend/, s.id);
    assert.doesNotMatch(s.title, /thief/i, s.id);
  }
  // The take's step is the only other one with a thief in it, and its title says it is another vault.
  const taken = others.filter((x) => x.run === 'take');
  assert.deepEqual(taken.map((s) => s.id), ['cancel']);
  assert.match(taken[0].title, /thief's request\. Another test vault of the same contract/);
  // The step after it says the story is back on the first vault, so a reader does not take its request for the thief's.
  assert.match(run.steps[run.steps.indexOf(taken[0]) + 1].title, /^Back on the first vault, /);
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
