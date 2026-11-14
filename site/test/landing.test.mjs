// The landing page and the replay. Static checks first: every hash on either page is one proofs/ recorded, under its
// chain's name, and the replay's record is exactly what tools/replay-run.mjs builds from proofs/: the final build's
// runs, with the cancel from the take of the live pages, which is another vault and says so. Then one headless
// Chrome on a built site: the first screen at 390x844 and 375x667, and from 320 to 1080 wide, the film playing muted in
// its slot, the Steal button opening /try/, the status line naming the config's contract, the replay stepping through,
// and no CSP complaint. Screenshots go to UNDO_SHOT_DIR
// when it is set. Skipped, and it says so, without Chrome.
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { buildRun, runText } from '../../tools/replay-run.mjs';
import { build } from '../build.mjs';
import { chromeAvailable, startChrome } from './chrome.mjs';
import { staticServer } from './stage.mjs';

const SITE = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const REPO = resolve(SITE, '..');
const PAGES = join(SITE, 'pages');
const read = (path) => readFileSync(join(PAGES, path), 'utf8');
const landing = read('index.html');
const replayHtml = read('replay/index.html');
const run = JSON.parse(read('replay/run.json'));
const proof = (name) => JSON.parse(readFileSync(join(REPO, 'proofs', name), 'utf8'));
const proofs = ['g2-v1.json', 's2-refusal-v1.json', 'film-take.json', 'g2.json'].map((name) => readFileSync(join(REPO, 'proofs', name), 'utf8')).join('\n');
const FILM = join(PAGES, 'film/undo-for-bitcoin.mp4');
const PAGES_FILE_LIMIT = 25 * 1024 * 1024;   // Cloudflare Pages refuses a larger file
const skip = chromeAvailable() ? false : 'set CHROME_BIN to run this in a real browser';
const SHOTS = process.env.UNDO_SHOT_DIR ?? null;

const EXPLORER = { 'Mutinynet txid': 'https://mutinynet.com/tx/', 'Mutinynet address': 'https://mutinynet.com/address/', 'NEAR testnet tx': 'https://testnet.near.rocks/tx/' };
const label = (l) => `${l.chain} ${l.type}`;

/** [{href, chain, hash, what}] for each hash card on the landing page, in page order. */
function landingHashes(html) {
  return [...html.matchAll(/<a class="hash" href="([^"]+)"><span class="chain">([^<]+)<\/span> <span class="mono h">([^<]+)<\/span><\/a><span class="what">([^<]+)<\/span>/g)]
    .map(([, href, chain, hash, what]) => ({ href, chain, hash, what }));
}

test('replay: run.json is exactly what tools/replay-run.mjs builds from proofs/, so no hash on it was typed by hand; its runs are the final build\'s', () => {
  assert.equal(read('replay/run.json'), runText());
  assert.equal(run.label, 'replay');
  assert.deepEqual(run.steps.map((s) => s.id), ['coin', 'refused', 'wait', 'cancel', 'signed', 'exit']);
  // The vault of the replay is the final build's: the contract and the wasm deploy/testnet.json names, which is also
  // the contract this site's config names. The earlier build's run is on the landing page only, under its own heading.
  const g2 = proof('g2-v1.json');
  const deploy = JSON.parse(readFileSync(join(REPO, 'deploy/testnet.json'), 'utf8'));
  assert.equal(run.title, 'Replay of the final build\'s runs');
  assert.equal(run.vault.contract, deploy.contract);
  assert.equal(run.vault.wasm_sha256, deploy.wasm_sha256);
  assert.equal(run.vault.contract, JSON.parse(readFileSync(join(SITE, 'config/testnet.json'), 'utf8')).contract);
  assert.equal(run.vault.id, g2.vault.id);
  const hashesOf = (step) => step.lines.filter((l) => l.kind === 'hash').map((l) => l.hash);
  const byId = Object.fromEntries(run.steps.map((s) => [s.id, s]));
  assert.deepEqual(hashesOf(byId.wait), [g2.cosigned.propose_tx]);
  assert.deepEqual(hashesOf(byId.signed), [g2.cosigned.attempts.find((x) => x.outcome === 'signed').execute_tx, g2.cosigned.txid]);
  assert.deepEqual(hashesOf(byId.exit), [g2.escape.txid]);
  const earlier = proof('g2.json');
  for (const s of run.steps) for (const h of hashesOf(s)) assert.equal([earlier.cosigned.txid, earlier.escape.txid, earlier.cosigned.propose_tx, earlier.vault.address].includes(h), false, `${s.id} holds a hash of the earlier build's run`);
});

test('replay: the cancel step is the take of the live pages the film is cut from, with that take\'s hashes, and says it is another vault, that its phone and browser are the author\'s report with the thief tab on a second device, and that the one-device run from a real phone, on another vault, is the author\'s report too', () => {
  const take = proof('film-take.json');
  const cancel = run.steps.find((s) => s.id === 'cancel');
  assert.notEqual(cancel.recorded, false, 'the step is a recorded one now');
  assert.equal(cancel.run, 'take');
  assert.equal(run.runs.take.date, take.started_utc.slice(0, 10));
  assert.match(run.runs.take.label, /another vault/);
  // The film's take records no execute after its wait, so the step names none.
  assert.deepEqual(cancel.lines.filter((l) => l.kind === 'hash').map((l) => l.hash), [take.thief.propose_tx, take.cancel.tx, take.coin.mutinynet_txid]);
  assert.equal(take.schema, 'undo-film-take-v2');
  assert.equal(JSON.stringify(take).includes('execute_after_the_wait_tx'), false);
  // Another vault than the replay's, on the same contract: the title says so, and so does the page's note.
  assert.notEqual(take.vault.id, run.vault.id);
  assert.equal(take.contract, run.vault.contract);
  assert.match(cancel.title, /^The phone page's Cancel stops a thief's request\. Another test vault of the same contract, (the same day|\d{4}-\d\d-\d\d)\.$/);
  assert.match(run.note, /the cancel in step 4 is from another vault of that contract and says so/);
  assert.equal(run.steps.indexOf(cancel), 3, 'the note calls it step 4');
  const said = cancel.lines.filter((l) => l.kind === 'text').map((l) => l.text).join(' ');
  assert.match(said, /^From the live pages, in the take the film is cut from: /);
  // The take's phone and browser are what its author reported, with the thief tab on a second device; the one-device run
  // from a real phone ran the day before, on another vault, from proofs/phone-take.json. Its hash is not a line of this step.
  const phone = proof('phone-take.json');
  assert.deepEqual([take.device_as_reported.device, take.device_as_reported.browser], ['an iPhone', 'Safari']);
  assert.ok(take.labels.includes('real device') && !take.labels.includes('virtual authenticator'));
  assert.ok(said.endsWith(`The phone page ran in Safari on an iPhone, as the author reported it, and the film's phone shots are that phone's own screen recording; the thief tab ran in headless Chrome on a Mac, a second device. A Cancel from a real phone also ran ${phone.vault_made_block_utc.slice(0, 10)}, on another vault of the same contract: one ${phone.device_as_reported.device}, with the phone page and the thief tab as two ${phone.device_as_reported.browser} tabs on it, as the author reported it.`), said);
  assert.doesNotMatch(said, /virtual authenticator|Face ID/);
  assert.deepEqual([phone.device_as_reported.device, phone.device_as_reported.browser], ['iPhone 13 Pro Max', 'Safari']);
  assert.ok(![take.vault.id, run.vault.id].includes(phone.vault.id) && phone.contract === run.vault.contract);
  assert.doesNotMatch(said, /not yet run/);
  assert.equal(JSON.stringify(run).includes(phone.cancel.tx), false, 'the real phone\'s cancel is not a hash line of the replay');
  const whats = cancel.lines.filter((l) => l.kind === 'hash').map((l) => l.what);
  assert.equal(whats[0], 'the thief tab\'s request, made to wait 5:00');
  // The time is the chain's: the cancel's block against the unlock in the proposal's log, as the record holds it.
  assert.equal(take.thief.unlock_ms - take.cancel.block_before_the_unlock_ms - take.cancel.block_after_the_proposal_ms, take.thief.proposed_at_ms);
  assert.equal(whats[1], `the phone page's Cancel (${take.cancel.method}), in a block ${Math.floor(take.cancel.block_before_the_unlock_ms / 1000)} s before the request would have unlocked`);
  assert.equal(Math.floor(take.cancel.block_before_the_unlock_ms / 1000), 271);
  assert.match(whats[2], /^that vault's coin: 2,000 sats, unspent when read again on \d{4}-\d\d-\d\d$/);
  // No other step borrows from the take, and the take's step holds nothing of the replay's vault.
  const takes = new Set([take.thief.propose_tx, take.cancel.tx, take.coin.mutinynet_txid, take.vault.address]);
  for (const s of run.steps.filter((x) => x.id !== 'cancel')) for (const l of s.lines.filter((x) => x.kind === 'hash')) assert.equal(takes.has(l.hash), false, `${s.id} borrows a hash of the take`);
  // Nowhere does the replay say a phone did it.
  assert.doesNotMatch(JSON.stringify(run.steps), /[Yy]our phone cancel|a phone cancelled|from a phone,/);
});

test('replay: a node\'s words are the recorded bytes, untouched', () => {
  const g2 = proof('g2-v1.json');
  const s2 = proof('s2-refusal-v1.json');
  const nodes = run.steps.flatMap((s) => s.lines.filter((l) => l.kind === 'node').map((l) => l.text));
  assert.deepEqual(nodes, [s2.node_answer.text_verbatim, g2.escape.early.text]);
});

test('landing: "From the film:", "From the final build\'s run" and "From an earlier build" are run.json\'s lists, each hash under its chain, linked to that chain\'s explorer', () => {
  const cards = landingHashes(landing);
  const want = [
    ...run.film.hashes.map((l) => ({ ...l, tail: `the film's take, ${run.film.date}` })),
    ...run.final.hashes.map((l) => ({ ...l, tail: `final build, ${run.final.date}` })),
    ...run.earlier.hashes.map((l) => ({ ...l, tail: `earlier build, ${run.earlier.date}` })),
  ];
  assert.equal(cards.length, want.length);
  cards.forEach((card, i) => {
    assert.equal(card.chain, label(want[i]));
    assert.equal(card.hash, want[i].hash);
    assert.equal(card.href, `${EXPLORER[card.chain]}${card.hash}`);
    assert.equal(card.what, `${want[i].what} · ${want[i].tail}`);
  });
  // The film's own take first, then the final build's run under its own heading, then the earlier build's, smaller.
  const film = '<h2 id="from-film" class="h2">From the film:</h2>';
  // Each date is kept on one line, so a narrow screen does not break it at a hyphen.
  const final = `<h2 id="from-final" class="h2">From the final build's run, <span class="nb">${run.final.date}</span>:</h2>`;
  const earlier = `<h3 id="from-earlier" class="h3">From an earlier build, <span class="nb">${run.earlier.date}</span>:</h3>`;
  for (const heading of [film, final, earlier]) assert.equal(landing.split(heading).length, 2, heading);
  assert.ok(landing.indexOf(film) < landing.indexOf(final) && landing.indexOf(final) < landing.indexOf(earlier));
  assert.doesNotMatch(landing, /From earlier runs|earlier run</);
  // The final build's three are the spend it co-signed, the execute that asked for the signature, and the escape.
  const g2 = proof('g2-v1.json');
  assert.deepEqual(run.final.hashes.map((l) => l.hash), [g2.cosigned.txid, g2.cosigned.attempts.find((x) => x.outcome === 'signed').execute_tx, g2.escape.txid]);
  assert.equal(run.final.hashes[0].what, 'the spend it co-signed after a 10:00 wait');
  assert.equal(g2.cosigned.check.delay_ms, 600_000);
  assert.notEqual(run.earlier.contract, run.final.contract);
  // The words under the replay button and under the Steal button say what each is.
  assert.match(landing, /<p class="small">A replay of the final build's recorded runs, with their real hashes\. Test coins only, on Mutinynet and NEAR testnet\.<\/p>/);
  assert.match(landing, /<p id="try-note" class="small">Rob yourself, then undo it: one page, three passkey prompts, test coins only\. A relay pays the NEAR gas, and its daily limit is shared, so it can be full\. Two devices instead: <a id="phone-link" class="link" href="\/p\/">the phone page<\/a>\.<\/p>/);
});

test('landing: "Steal a test coin" is a white button to /try/ on the first screen, above "Watch a recorded run", and the two-device path stays linked under it', () => {
  const first = landing.slice(landing.indexOf('<section class="first">'), landing.indexOf('<section class="below"'));
  // One button, the same white .go as the replay's, its words the spec's, its link the one-page run.
  assert.equal(first.match(/<a id="try-link" /g)?.length, 1);
  assert.match(first, /<a id="try-link" class="go" href="\/try\/">Steal a test coin<\/a>\n\s*<p id="try-note" class="small">/);
  assert.ok(first.indexOf('id="try-link"') < first.indexOf('id="replay-link"'), 'the Steal button sits above the replay button');
  assert.match(first, /<p id="try-note" class="small">[^\n]*<\/p>\n\s*<a id="replay-link" class="go" href="\/replay\/">Watch a recorded run<\/a>/);
  // The two-device path is still one tap away; the old line that sent a phone to two tabs is gone.
  assert.match(first, /<a id="phone-link" class="link" href="\/p\/">the phone page<\/a>/);
  assert.doesNotMatch(landing, /Try a cancel yourself/);
  assert.equal(landing.match(/href="\/try\/"/g).length, 1, 'one link to /try/');
  // /try/ is a page the build ships.
  assert.ok(readFileSync(join(PAGES, 'try/index.html'), 'utf8').includes('<title>Undo · try it</title>'));
});

test('every hash on both pages is in proofs/, and every long hex or base58 string on them is one of those hashes', () => {
  const hashes = new Set(run.steps.flatMap((s) => s.lines.filter((l) => l.kind === 'hash').map((l) => l.hash)));
  for (const l of [...run.film.hashes, ...run.final.hashes, ...run.earlier.hashes]) hashes.add(l.hash);
  for (const h of hashes) assert.ok(proofs.includes(`"${h}"`) || proofs.includes(h), `${h} is not in proofs/`);
  const text = `${landing}\n${JSON.stringify(run.steps.map((s) => s.lines.filter((l) => l.kind !== 'node')))}`;
  const longStrings = new Set([...text.matchAll(/\b(?:[0-9a-f]{64}|[1-9A-HJ-NP-Za-km-z]{43,44}|tb1q[0-9a-z]{58})\b/g)].map((m) => m[0]));
  for (const s of longStrings) assert.ok(hashes.has(s), `${s} on a page is not a recorded hash`);
});

test('CSP: no inline script, no style element or attribute, no inline handler, on any page this adds', () => {
  for (const [name, html] of [['index.html', landing], ['replay/index.html', replayHtml], ['404.html', read('404.html')]]) {
    assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/, `${name}: inline script`);
    assert.doesNotMatch(html, /<style\b|\sstyle="/, `${name}: inline style`);
    assert.doesNotMatch(html, /\son[a-z]+="/, `${name}: inline handler`);
  }
});

test('landing: the name, the chip before any script, a 2:1 link card, and the film in its slot with its 4:5 poster: an MP4 Pages will take, muted, with controls for its sound', () => {
  assert.match(landing, /<title>Undo for Bitcoin<\/title>/);
  assert.ok(landing.indexOf('signet test coins') < landing.indexOf('<main'), 'the chip is drawn before the content');
  // A link card is drawn about 2:1, which crops the 4:5 poster to its middle lines, so the card has an image of its own.
  for (const [prop, value] of [['og:title', 'Undo for Bitcoin'], ['og:image', 'https://undo-btc.pages.dev/film/card.png'], ['og:image:width', '1200'], ['og:image:height', '630'], ['og:url', 'https://undo-btc.pages.dev/']]) {
    assert.match(landing, new RegExp(`<meta property="${prop}" content="${value.replace(/[./]/g, (c) => `\\${c}`)}">`));
  }
  assert.match(landing, /<meta name="twitter:card" content="summary_large_image">/);
  assert.match(landing, /<meta name="twitter:image" content="https:\/\/undo-btc\.pages\.dev\/film\/card\.png">/);
  assert.doesNotMatch(landing, /<meta (property|name)="(og|twitter):image" content="[^"]*poster\.png">/);
  assert.match(read('replay/index.html'), /<meta property="og:image" content="https:\/\/undo-btc\.pages\.dev\/film\/card\.png">/);
  const card = readFileSync(join(PAGES, 'film/card.png'));
  assert.equal(card.subarray(1, 4).toString(), 'PNG');
  assert.deepEqual([card.readUInt32BE(16), card.readUInt32BE(20)], [1200, 630], 'the link card is 1200x630');
  assert.ok(card.length < 600_000, `the link card is ${card.length} bytes`);
  // Muted so it may start by itself; controls so a visitor can turn the narration on.
  assert.match(landing, /<video id="film" class="film-video" muted playsinline autoplay loop controls preload="metadata" poster="\/film\/poster\.png"/);
  assert.match(landing, /<source id="film-source" src="\/film\/undo-for-bitcoin\.mp4" type="video\/mp4">/);
  const png = readFileSync(join(PAGES, 'film/poster.png'));
  assert.equal(png.subarray(1, 4).toString(), 'PNG');
  assert.deepEqual([png.readUInt32BE(16), png.readUInt32BE(20)], [1080, 1350], 'the poster is 4:5 like the film');
  const film = readFileSync(FILM);
  assert.equal(film.subarray(4, 8).toString(), 'ftyp', 'the film is an MP4');
  assert.ok(film.length > 500_000 && film.length < PAGES_FILE_LIMIT, `the film is ${film.length} bytes: Pages takes at most ${PAGES_FILE_LIMIT}`);
  assert.ok(film.indexOf('moov') < film.indexOf('mdat'), 'the index comes first, so it starts before it has all arrived');
});

test('landing: the story, the closing line, "Why not 2-of-3?", the privacy line, the status line and the repo; no AI line, no self-steal, no numbers', () => {
  // Inline spans join their words; every other tag is a break.
  const text = landing.replace(/<\/?span[^>]*>/g, '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
  for (const phrase of [
    'A cancel button for Bitcoin.', 'Your Bitcoin key is stolen. Bitcoin refuses that key alone. A public NEAR contract makes the thief wait, and your phone can cancel first.',
    'The second signature comes from NEAR Chain Signatures, when that contract asks.',
    'NEAR can refuse; it can\'t take.', 'If NEAR goes away, your cold key gets the coins out after a timelock.',
    'Why not 2-of-3?', 'If you can keep two keys in reach for every spend, use 2-of-3.',
    'anyone can read each waiting request\'s amount and destination, before Bitcoin moves', '"method_name":"status"', 'github.com/tedinroc/undo',
  ]) assert.ok(text.includes(phrase.replace(/'/g, '\'')), `missing: ${phrase}`);
  assert.match(landing, /href="https:\/\/github\.com\/tedinroc\/undo"/);
  // The first screen names what signs second, in the line under the story, and the contract is the one that asks: the
  // signers are never the subject of the wait.
  const first = landing.slice(landing.indexOf('<section class="first">'), landing.indexOf('<section class="below"'));
  assert.match(first, /<p class="trust">The second signature comes from NEAR Chain Signatures, when that contract asks\. /);
  assert.equal(first.match(/Chain Signatures/g).length, 1);
  assert.doesNotMatch(text, /Chain Signatures[^.]*\b(signs|waits)\b[^.]*\b(only|after)\b/i);
  assert.doesNotMatch(text, /AI agent|Let your/i);
  assert.doesNotMatch(text, /one tap/i);
  assert.doesNotMatch(text, /\b\d+ (vaults|cancels|strangers|users)\b/i);
});

test('build: the landing, the replay, its record, the poster and the 404 page all ship, under the same headers', () => {
  const out = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'undo-landing-build-'));
  try {
    const config = JSON.parse(readFileSync(join(SITE, 'config/testnet.json'), 'utf8'));
    build({ configObject: { ...config, contract: 'v1.s.undo-btc.testnet' }, out });
    for (const f of ['index.html', 'landing/landing.mjs', 'landing/landing.css', 'replay/index.html', 'replay/replay.mjs', 'replay/run.json', 'film/poster.png', 'film/card.png', 'film/undo-for-bitcoin.mp4', '404.html', 'site/lib/index.mjs', '_headers']) {
      assert.ok(readFileSync(join(out, f)).length > 0, f);
    }
    assert.ok(readFileSync(join(out, 'film/undo-for-bitcoin.mp4')).equals(readFileSync(FILM)), 'the film ships byte for byte');
    assert.match(readFileSync(join(out, '_headers'), 'utf8'), /media-src 'self'/, 'the page may play its own film and nothing else');
    assert.equal(readFileSync(join(out, 'replay/run.json'), 'utf8'), read('replay/run.json'));
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- one Chrome

const LOCAL = {
  mode: 'local', contract: 'landing.test.near', rpc: ['http://127.0.0.1:9'], esplora: 'http://127.0.0.1:9', relay: '/api/relay', funds: '/api/funds',
  btcTxUrl: null, btcAddressUrl: null, nearTxUrl: null, rpId: 'localhost', softPasskey: false,
};
const TESTNET = { ...JSON.parse(readFileSync(join(SITE, 'config/testnet.json'), 'utf8')), contract: 'v1.s.undo-btc.testnet' };

let browser;
let cdp;
const served = {};
const problems = [];

async function serve(name, config) {
  const dir = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), `undo-landing-${name}-`));
  build({ configObject: config, out: dir });
  const server = await staticServer({ dir, port: 0, onApi: (req, res) => {
    res.writeHead(503, { 'content-type': 'application/json' });
    res.end('{"ok":false,"code":"relay_not_configured"}');
  } });
  served[name] = { dir, server, origin: `http://localhost:${server.address().port}` };
}

before(async () => {
  if (skip) return;
  browser = await startChrome();
  ({ cdp } = browser);
  await cdp.send('Log.enable');
  // The film is there now, so a 404 for it is a problem like any other error in the log, CSP refusals above all.
  cdp.ws.addEventListener('message', (event) => {
    const data = JSON.parse(event.data);
    if (data.method === 'Log.entryAdded') {
      const { level, text, url = '' } = data.params.entry;
      if (level === 'error') problems.push(`${text} ${url}`);
    }
    if (data.method === 'Runtime.exceptionThrown') problems.push(data.params.exceptionDetails.text);
  });
  await serve('local', LOCAL);
  await serve('testnet', TESTNET);
  if (SHOTS) mkdirSync(SHOTS, { recursive: true });
}, { timeout: 60_000 });

after(async () => {
  await browser?.stop();
  for (const s of Object.values(served)) {
    s.server.close();
    s.server.closeAllConnections?.();
    rmSync(s.dir, { recursive: true, force: true });
  }
});

async function viewport(width, height, mobile = true) {
  await cdp.send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 2, mobile });
}

async function shot(name, { full = false } = {}) {
  if (!SHOTS) return;
  const params = { format: 'png' };
  if (full) {
    const { contentSize } = await cdp.send('Page.getLayoutMetrics');
    Object.assign(params, { captureBeyondViewport: true, clip: { x: 0, y: 0, width: contentSize.width, height: contentSize.height, scale: 1 } });
  }
  const { data } = await cdp.send('Page.captureScreenshot', params);
  writeFileSync(join(SHOTS, `${name}.png`), Buffer.from(data, 'base64'));
}

const box = (sel) => cdp.page(`const r = document.querySelector(${JSON.stringify(sel)}).getBoundingClientRect(); return { top: r.top, bottom: r.bottom, left: r.left, right: r.right, width: r.width, height: r.height };`);
const waitFor = async (expr, ms = 5000) => {
  for (let t = 0; t < ms; t += 50) {
    if (await cdp.page(`return Boolean(${expr});`)) return;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error(`timed out: ${expr}`);
};

test('Chrome 390x844: chip, film slot, sentence and the Steal button on the first screen, the replay link under it; no sideways scroll; the film plays in its slot, muted, 4:5, about a minute', { skip, timeout: 60_000 }, async () => {
  problems.length = 0;
  await viewport(390, 844);
  await cdp.open(`${served.testnet.origin}/`);
  await waitFor("document.documentElement.dataset.config === 'testnet'");
  await waitFor("document.getElementById('film-slot').dataset.film === 'playing'", 15000);
  await waitFor("document.getElementById('film').currentTime > 0.2", 15000);
  const playing = await cdp.page("const v = document.getElementById('film'); return { w: v.videoWidth, h: v.videoHeight, seconds: v.duration, muted: v.muted, controls: v.controls, loop: v.loop, paused: v.paused, error: v.error ? v.error.code : null };");
  assert.deepEqual([playing.w, playing.h], [1080, 1350], 'the film is 4:5, as its slot and its poster are');
  assert.ok(playing.seconds >= 60 && playing.seconds <= 75, `the film runs ${playing.seconds} s`);
  assert.deepEqual([playing.muted, playing.controls, playing.loop, playing.paused, playing.error], [true, true, true, false, null]);
  for (const sel of ['#chip', '#film-slot', '#sentence', '.trust', '#try-link']) {
    const b = await box(sel);
    assert.ok(b.top >= 0 && b.bottom <= 844 && b.width > 0, `${sel} is not on the first screen: ${JSON.stringify(b)}`);
  }
  // The replay button comes right under the Steal button's line.
  const [note, replay] = [await box('#try-note'), await box('#replay-link')];
  assert.ok(replay.top >= note.bottom && replay.top - note.bottom <= 24, `the replay link starts at ${replay.top}, the line above it ends at ${note.bottom}`);
  assert.match(await cdp.page("return document.querySelector('.trust').textContent;"), /^The second signature comes from NEAR Chain Signatures, when that contract asks\./, 'the first screen names Chain Signatures');
  // Nothing on the first screen moves by itself: no animation or transition on its text.
  assert.deepEqual(await cdp.page("return [...document.querySelectorAll('.copy *')].filter((e) => { const c = getComputedStyle(e); return c.animationName !== 'none' || parseFloat(c.transitionDuration) > 0; }).map((e) => e.className || e.id);"), []);
  const film = await box('#film-slot');
  assert.ok(Math.abs(film.width / film.height - 0.8) < 0.01, 'the slot is 4:5');
  assert.ok(film.width >= 300, 'the film slot is the width of the phone, near enough');
  assert.equal(await cdp.page("return document.getElementById('chip').textContent;"), 'signet test coins');
  assert.equal(await cdp.page("return document.getElementById('film').getAttribute('poster');"), '/film/poster.png');
  assert.equal(await cdp.page('return document.documentElement.scrollWidth;'), 390);
  assert.match(await cdp.page("return document.getElementById('curl').textContent;"), /"account_id":"v1\.s\.undo-btc\.testnet"/);
  assert.match(await cdp.page("return document.getElementById('curl').textContent;"), /^curl -s https:\/\/test\.rpc\.fastnear\.com /);
  await shot('landing-390x844');
  await shot('landing-390x844-full', { full: true });
  assert.deepEqual(problems, []);
});

test('Chrome 375x667: the film shrinks so the Steal button stays above the fold', { skip, timeout: 30_000 }, async () => {
  await viewport(375, 667);
  await cdp.open(`${served.testnet.origin}/`);
  const link = await box('#try-link');
  assert.ok(link.bottom <= 667, `the Steal button ends at ${link.bottom}`);
  // With room to spare, so a font a few pixels taller does not push it under the fold; and the line that names
  // Chain Signatures is above it.
  assert.ok(link.bottom <= 667 - 24, `the Steal button ends at ${link.bottom}, too near the fold`);
  const trust = await box('.trust');
  assert.ok(trust.top >= 0 && trust.bottom <= link.top, 'the Chain Signatures line is on the first screen, above the link');
  assert.ok((await box('#film-slot')).width >= 180, 'and the film is still a film');
  assert.equal(await cdp.page('return document.documentElement.scrollWidth;'), 375);
  await shot('landing-375x667');
});

test('Chrome 320 wide: the chip and the wordmark fit side by side on the landing page and on the replay, with no sideways scroll', { skip, timeout: 30_000 }, async () => {
  await viewport(320, 568);
  for (const path of ['/', '/replay/']) {
    await cdp.open(`${served.testnet.origin}${path}`);
    assert.equal(await cdp.page('return document.documentElement.scrollWidth;'), 320, `${path} is as wide as the screen`);
    const [chip, mark] = [await box('.top .chip'), await box('.top .wordmark')];
    assert.ok(mark.right <= 320 - 16 + 0.5, `${path}: the wordmark ends at ${mark.right}, inside the gutter`);
    assert.ok(chip.right < mark.left, `${path}: the chip ends before the wordmark starts`);
    assert.equal(await cdp.page('return getComputedStyle(document.querySelector(".top .wordmark")).fontSize;'), '17px');
    assert.equal(await cdp.page('return document.querySelector(".top .wordmark").innerText;'), 'Undo for Bitcoin', 'whole, not cut');
  }
  await shot('landing-320x568');
  // One pixel wider than the rule reaches, the header is the one every other phone has, and it fits there too.
  await viewport(346, 700);
  await cdp.open(`${served.testnet.origin}/`);
  assert.equal(await cdp.page('return getComputedStyle(document.querySelector(".top .wordmark")).fontSize;'), '19px');
  assert.equal(await cdp.page('return document.documentElement.scrollWidth;'), 346);
});

test('Chrome 1440x900: two columns, the whole first screen in view', { skip, timeout: 30_000 }, async () => {
  problems.length = 0;
  await viewport(1440, 900, false);
  await cdp.open(`${served.testnet.origin}/`);
  await waitFor("document.documentElement.dataset.config === 'testnet'");
  const film = await box('#film-slot');
  const copy = await box('#sentence');
  assert.ok(copy.left > film.right, 'the copy sits beside the film');
  for (const sel of ['#film-slot', '#sentence', '#try-link', '#replay-link']) assert.ok((await box(sel)).bottom <= 900, sel);
  await shot('landing-1440x900');
  assert.deepEqual(problems, []);
});

test('Chrome 320 to 1080 wide: no sideways scroll, the Steal button whole and on one line, on the first screen of every phone size the page is laid out for, the replay link under it', { skip, timeout: 90_000 }, async () => {
  const sizes = [[320, 568], [346, 700], [360, 640], [375, 667], [375, 812], [390, 664], [390, 844], [414, 896], [428, 926], [600, 900], [768, 1024], [899, 900], [900, 700], [1080, 800], [1080, 1350]];
  for (const [w, hgt] of sizes) {
    await viewport(w, hgt, w < 900);
    await cdp.open(`${served.testnet.origin}/`);
    const at = `${w}x${hgt}`;
    const width = await cdp.page('return document.documentElement.clientWidth;');
    assert.equal(await cdp.page('return document.documentElement.scrollWidth;'), width, `${at}: sideways scroll`);
    const [link, note, replay] = [await box('#try-link'), await box('#try-note'), await box('#replay-link')];
    assert.ok(link.left >= 16 - 0.5 && link.right <= width - 16 + 0.5, `${at}: the Steal button runs into the gutter: ${JSON.stringify(link)}`);
    assert.ok(link.height <= 49, `${at}: the Steal button wraps: ${link.height} px tall`);
    assert.ok(link.bottom <= note.top && note.bottom <= replay.top, `${at}: the Steal button, its line and the replay link are not in that order`);
    // The 320x568 screen is below the sizes the first screen is laid out for (the replay link did not fit there either).
    if (hgt >= 640) assert.ok(link.bottom <= hgt, `${at}: the Steal button ends at ${link.bottom}, under the fold`);
  }
});

test('Chrome: the Steal button opens /try/ in the same tab, and /try/\'s own script runs there', { skip, timeout: 60_000 }, async () => {
  // The local build: no relay (every /api/ answers 503) and no NEAR node (127.0.0.1:9), so nothing here reaches a network.
  problems.length = 0;
  await viewport(390, 844);
  await cdp.open(`${served.local.origin}/`);
  assert.equal(await cdp.page("return document.getElementById('try-link').href;"), `${served.local.origin}/try/`);
  assert.equal(await cdp.page("return document.getElementById('try-link').target;"), '');
  await cdp.page("document.getElementById('try-link').click(); return true;");
  await waitFor("location.pathname === '/try/' && document.title === 'Undo · try it' && document.documentElement.dataset.state !== 'boot'", 20000);
  assert.equal(await cdp.page('return document.documentElement.dataset.step;'), 'intro');
  await shot('landing-try-click-390x844');
  // What fails there is the relay and the node this build has none of; no script error, no CSP refusal of a page file.
  assert.deepEqual(problems.filter((p) => !/\/api\/|127\.0\.0\.1:9\b/.test(p)), []);
});

test('Chrome, local config: the chip says local, and the recorded hashes still name the chains they are on', { skip, timeout: 30_000 }, async () => {
  await viewport(390, 844);
  await cdp.open(`${served.local.origin}/`);
  await waitFor("document.documentElement.dataset.config === 'local'");
  assert.equal(await cdp.page("return document.getElementById('chip').textContent;"), 'local test coins, mock signer');
  assert.match(await cdp.page("return document.querySelector('.hashes .chain').textContent;"), /^Mutinynet/);
});

test('Chrome replay: labelled REPLAY, one step at a time on request, every hash under its chain and linked, each step naming its run, the cancel step marked as the live pages\' take on another vault, no clock', { skip, timeout: 60_000 }, async () => {
  problems.length = 0;
  await viewport(390, 844);
  await cdp.open(`${served.testnet.origin}/replay/`);
  await waitFor("document.documentElement.dataset.state === 'replay'");
  assert.equal(await cdp.page("return document.querySelector('.tag').textContent;"), 'REPLAY');
  assert.equal(await cdp.page("return document.getElementById('title').textContent;"), run.title);
  assert.equal(await cdp.page("return document.getElementById('note').textContent;"), run.note);
  assert.equal(await cdp.page('return document.querySelectorAll(".step:not([hidden])").length;'), 1);
  await shot('replay-390x844-step1');
  for (let i = 2; i <= run.steps.length; i += 1) {
    await cdp.page("document.getElementById('next').click(); return true;");
    assert.equal(await cdp.page('return document.querySelectorAll(".step:not([hidden])").length;'), i);
  }
  assert.equal(await cdp.page("return document.getElementById('next').disabled;"), true);
  assert.equal(await cdp.page("return document.getElementById('next').textContent;"), 'That was every step');
  const lines = await cdp.page('return [...document.querySelectorAll(".hash-line")].map((l) => [l.querySelector(".chain").textContent, l.dataset.hash, l.querySelector("a")?.href ?? null]);');
  assert.equal(lines.length, run.steps.flatMap((s) => s.lines.filter((l) => l.kind === 'hash')).length);
  for (const [chain, hash, href] of lines) assert.equal(href, `${EXPLORER[chain]}${hash}`);
  // The cancel is a recorded step with hashes of its own, and its head says whose: the live pages' take, another vault.
  assert.equal(await cdp.page('return document.querySelector("#step-cancel").dataset.recorded;'), 'true');
  assert.equal(await cdp.page('return document.querySelector("#step-cancel").dataset.run;'), 'take');
  assert.equal(await cdp.page('return document.querySelector("#step-cancel .when").textContent;'), `replay · the live pages, another vault · ${run.runs.take.date} UTC ${run.steps[3].at.slice(11, 19)}`);
  assert.equal(await cdp.page('return document.querySelectorAll("#step-cancel .hash-line").length;'), 3);
  assert.match(await cdp.page('return document.querySelector("#step-cancel").textContent;'), /The phone page ran in Safari on an iPhone, as the author reported it, and the film's phone shots are that phone's own screen recording; the thief tab ran in headless Chrome on a Mac, a second device\. A Cancel from a real phone also ran \d{4}-\d\d-\d\d, on another vault of the same contract: one iPhone 13 Pro Max, with the phone page and the thief tab as two Safari tabs on it, as the author reported it\./);
  assert.equal(await cdp.page('return document.querySelectorAll(".step .when").length;'), run.steps.length);
  assert.match(await cdp.page('return document.querySelector("#step-refused .when").textContent;'), new RegExp(`^replay · final build · ${run.runs.s2.date} UTC ${run.steps[1].at.slice(11, 19)}$`));
  assert.equal(await cdp.page('return document.querySelector("#step-signed .when").textContent.startsWith("replay · final build · ");'), true);
  assert.doesNotMatch(await cdp.page('return document.getElementById("replay").textContent;'), /earlier run|not in these runs/);
  assert.equal(await cdp.page('return document.querySelectorAll("[data-clock], [role=timer]").length;'), 0);
  assert.equal(await cdp.page('return document.documentElement.scrollWidth;'), 390);
  await shot('replay-390x844-all', { full: true });
  await viewport(1440, 900, false);
  await cdp.open(`${served.testnet.origin}/replay/#all`);
  await waitFor("document.documentElement.dataset.step === String(" + run.steps.length + ')');
  await shot('replay-1440x900');
  assert.deepEqual(problems, []);
});

test('build of the replay record refuses records that are not the final build\'s live run, a script refusal on its vault, a take on the same contract, a real phone\'s take on yet another vault, and an earlier build\'s run', () => {
  const g2 = proof('g2-v1.json');
  const s2 = proof('s2-refusal-v1.json');
  const take = proof('film-take.json');
  const earlier = proof('g2.json');
  assert.throws(() => buildRun({ g2: { ...g2, label: 'rehearsal-regtest-mock-signer' }, s2 }), /proofs\/g2-v1\.json is not the record of a live run/);
  assert.throws(() => buildRun({ g2: { ...g2, cosigned: { ...g2.cosigned, readback: undefined } }, s2 }), /holds no mined co-signed spend and escape/);
  // The earlier build's record in the final build's place: not the wasm deploy/testnet.json names.
  assert.throws(() => buildRun({ g2: earlier, s2: proof('s2-refusal.json') }), /not a run of the final build/);
  // Each half on its own: a run of another wasm on the same contract account, or a deploy config that names another wasm.
  const deploy = JSON.parse(readFileSync(join(REPO, 'deploy/testnet.json'), 'utf8'));
  assert.throws(() => buildRun({ g2: { ...g2, wasm: { ...g2.wasm, sha256: earlier.wasm.sha256 } } }), /not a run of the final build/);
  assert.throws(() => buildRun({ deploy: { ...deploy, wasm_sha256: earlier.wasm.sha256 } }), /not a run of the final build/);
  assert.throws(() => buildRun({ deploy: { ...deploy, contract: earlier.contract.account } }), /not a run of the final build/);
  assert.throws(() => buildRun({ site: { contract: 'other.testnet' } }), /not a run on the contract this site's config names/);
  assert.throws(() => buildRun({ g2, s2: { ...s2, node_answer: { ...s2.node_answer, refusal: 'transient' } } }), /not a script refusal/);
  assert.throws(() => buildRun({ g2, s2: { ...s2, vault: { ...s2.vault, id: '00' } } }), /not the same test vault/);
  assert.throws(() => buildRun({ take: { ...take, contract: earlier.contract.account } }), /not another vault of the same contract/);
  assert.throws(() => buildRun({ take: { ...take, vault: { ...take.vault, id: g2.vault.id } } }), /not another vault of the same contract/);
  // The film's take is a real device's, with its author's report, and names no execute the step would leave out.
  assert.throws(() => buildRun({ take: proof('chrome-take.json') }), /not the film's take/);
  assert.throws(() => buildRun({ take: { ...take, labels: [...take.labels, 'virtual authenticator'] } }), /not the film's take/);
  assert.throws(() => buildRun({ take: { ...take, labels: take.labels.filter((l) => l !== 'real device') } }), /not the film's take/);
  assert.throws(() => buildRun({ take: { ...take, device_as_reported: { ...take.device_as_reported, by: 'the chain' } } }), /film-take\.json does not say what its author reported/);
  assert.throws(() => buildRun({ take: { ...take, cancel: { ...take.cancel, block_before_the_unlock_ms: undefined } } }), /film-take\.json does not say what its author reported/);
  assert.throws(() => buildRun({ take: { ...take, after: { ...take.after, execute_refusal: 'RequestNotFound' } } }), /records an execute, and this step names none/);
  assert.throws(() => buildRun({ earlier: g2 }), /not an earlier build's run/);
  // The real phone's record: a real device's take, on another vault of the same contract, with its author's report.
  const phone = proof('phone-take.json');
  assert.throws(() => buildRun({ phone: { ...phone, labels: [...phone.labels, 'virtual authenticator'] } }), /not a real device's take/);
  assert.throws(() => buildRun({ phone: { ...phone, schema: 'undo-film-take-v1' } }), /not a real device's take/);
  assert.throws(() => buildRun({ phone: { ...phone, vault: { ...phone.vault, id: take.vault.id } } }), /phone-take\.json is not another vault of the same contract/);
  assert.throws(() => buildRun({ phone: { ...phone, contract: earlier.contract.account } }), /phone-take\.json is not another vault of the same contract/);
  assert.throws(() => buildRun({ phone: { ...phone, device_as_reported: { ...phone.device_as_reported, browser: undefined } } }), /does not say what its author reported/);
  // A mined spend whose record does not say both signatures verified is not shown as one with two.
  const oneSig = structuredClone(g2);
  oneSig.cosigned.readback.signatures[1].verified = false;
  assert.throws(() => buildRun({ g2: oneSig }), /does not record both signatures of the mined spend as verified/);
});
