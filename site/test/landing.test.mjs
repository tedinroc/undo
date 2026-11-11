// The landing page and the replay. Static checks first: every hash on either page is one proofs/ recorded, under its
// chain's name, and the replay's record is exactly what tools/replay-run.mjs builds from proofs/. Then one headless
// Chrome on a built site: the first screen at 390x844 and 375x667, the film playing muted in its slot, the status line
// naming the config's contract, the replay stepping through, and no CSP complaint. Screenshots go to UNDO_SHOT_DIR
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
const proofs = ['g2.json', 's2-refusal.json', 'film-take.json'].map((name) => readFileSync(join(REPO, 'proofs', name), 'utf8')).join('\n');
const FILM = join(PAGES, 'film/undo-for-bitcoin.mp4');
const PAGES_FILE_LIMIT = 25 * 1024 * 1024;   // Cloudflare Pages refuses a larger file
const skip = chromeAvailable() ? false : 'set CHROME_BIN to run this in a real browser';
const SHOTS = process.env.UNDO_SHOT_DIR ?? null;

const EXPLORER = { 'Mutinynet txid': 'https://mutinynet.com/tx/', 'Mutinynet address': 'https://mutinynet.com/address/', 'NEAR testnet tx': 'https://testnet.nearblocks.io/txns/' };
const label = (l) => `${l.chain} ${l.type}`;

/** [{href, chain, hash, what}] for each hash card on the landing page, in page order. */
function landingHashes(html) {
  return [...html.matchAll(/<a class="hash" href="([^"]+)"><span class="chain">([^<]+)<\/span> <span class="mono h">([^<]+)<\/span><\/a><span class="what">([^<]+)<\/span>/g)]
    .map(([, href, chain, hash, what]) => ({ href, chain, hash, what }));
}

test('replay: run.json is exactly what tools/replay-run.mjs builds from proofs/, so no hash on it was typed by hand', () => {
  assert.equal(read('replay/run.json'), runText());
  assert.equal(run.label, 'replay');
  assert.deepEqual(run.steps.map((s) => s.id), ['coin', 'refused', 'wait', 'cancel', 'signed', 'exit']);
  const cancel = run.steps.find((s) => s.id === 'cancel');
  assert.equal(cancel.recorded, false, 'neither replayed run holds a cancel, so the replay must not show one of its own');
  assert.equal(cancel.lines.some((l) => l.kind === 'hash'), false);
  // The landing page lists the film's cancel on NEAR testnet, so this step may not say that none is recorded: it says
  // what is true of these runs, names the film's take by its date, and points to that list without borrowing a hash.
  const said = cancel.lines.filter((l) => l.kind === 'text').map((l) => l.text).join(' ');
  assert.doesNotMatch(said, /no cancel on NEAR testnet is recorded|stays empty until/);
  assert.match(said, /^Not in these earlier runs: neither run replayed here holds a cancel/);
  assert.ok(said.includes(`recorded in the film's take of ${run.film.date}, on another test vault`));
  assert.match(said, /Chrome's virtual authenticator stood in for a phone's passkey there; from a real phone that path has not yet run\./);
  assert.deepEqual(cancel.lines.filter((l) => l.kind === 'link').map((l) => l.href), ['/#from-film']);
  assert.match(landing, /<h2 id="from-film" class="h2">From the film:<\/h2>/, 'the link\'s target is on the landing page');
  assert.ok(run.film.hashes.some((l) => l.what === 'the phone page\'s cancel'), 'and that list holds the cancel');
});

test('replay: a node\'s words are the recorded bytes, untouched', () => {
  const g2 = JSON.parse(readFileSync(join(REPO, 'proofs/g2.json'), 'utf8'));
  const s2 = JSON.parse(readFileSync(join(REPO, 'proofs/s2-refusal.json'), 'utf8'));
  const nodes = run.steps.flatMap((s) => s.lines.filter((l) => l.kind === 'node').map((l) => l.text));
  assert.deepEqual(nodes, [s2.node_answer.text_verbatim, g2.escape.early.text]);
});

test('landing: "From the film:", "From earlier runs:" and "From the same test vault:" are run.json\'s lists, each hash under its chain, linked to that chain\'s explorer', () => {
  const cards = landingHashes(landing);
  const want = [
    ...run.film.hashes.map((l) => ({ ...l, tail: `the film's take, ${run.film.date}` })),
    ...[...run.earlier, ...run.same_vault].map((l) => ({ ...l, tail: 'earlier run' })),
  ];
  assert.equal(cards.length, want.length);
  cards.forEach((card, i) => {
    assert.equal(card.chain, label(want[i]));
    assert.equal(card.hash, want[i].hash);
    assert.equal(card.href, `${EXPLORER[card.chain]}${card.hash}`);
    assert.equal(card.what, `${want[i].what} · ${want[i].tail}`);
  });
  assert.ok(landing.indexOf('<h2 id="from-film" class="h2">From the film:</h2>') < landing.indexOf('<h2 id="from-runs" class="h2">From earlier runs:</h2>'), 'the film\'s own take is listed first, then the earlier runs');
  assert.match(landing, /<h2 id="from-runs" class="h2">From earlier runs:<\/h2>/);
});

test('every hash on both pages is in proofs/, and every long hex or base58 string on them is one of those hashes', () => {
  const hashes = new Set(run.steps.flatMap((s) => s.lines.filter((l) => l.kind === 'hash').map((l) => l.hash)));
  for (const l of [...run.film.hashes, ...run.earlier, ...run.same_vault]) hashes.add(l.hash);
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
  assert.doesNotMatch(text, /Steal a test coin|one tap/i);
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

test('Chrome 390x844: chip, film slot, sentence and replay link on the first screen; no sideways scroll; the film plays in its slot, muted, 4:5, about a minute', { skip, timeout: 60_000 }, async () => {
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
  for (const sel of ['#chip', '#film-slot', '#sentence', '.trust', '#replay-link']) {
    const b = await box(sel);
    assert.ok(b.top >= 0 && b.bottom <= 844 && b.width > 0, `${sel} is not on the first screen: ${JSON.stringify(b)}`);
  }
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

test('Chrome 375x667: the film shrinks so the replay link stays above the fold', { skip, timeout: 30_000 }, async () => {
  await viewport(375, 667);
  await cdp.open(`${served.testnet.origin}/`);
  const link = await box('#replay-link');
  assert.ok(link.bottom <= 667, `the replay link ends at ${link.bottom}`);
  // With room to spare, so a font a few pixels taller does not push it under the fold; and the line that names
  // Chain Signatures is above it.
  assert.ok(link.bottom <= 667 - 24, `the replay link ends at ${link.bottom}, too near the fold`);
  const trust = await box('.trust');
  assert.ok(trust.top >= 0 && trust.bottom <= link.top, 'the Chain Signatures line is on the first screen, above the link');
  assert.ok((await box('#film-slot')).width >= 180, 'and the film is still a film');
  assert.equal(await cdp.page('return document.documentElement.scrollWidth;'), 375);
  await shot('landing-375x667');
});

test('Chrome 1440x900: two columns, the whole first screen in view', { skip, timeout: 30_000 }, async () => {
  problems.length = 0;
  await viewport(1440, 900, false);
  await cdp.open(`${served.testnet.origin}/`);
  await waitFor("document.documentElement.dataset.config === 'testnet'");
  const film = await box('#film-slot');
  const copy = await box('#sentence');
  assert.ok(copy.left > film.right, 'the copy sits beside the film');
  for (const sel of ['#film-slot', '#sentence', '#replay-link']) assert.ok((await box(sel)).bottom <= 900, sel);
  await shot('landing-1440x900');
  assert.deepEqual(problems, []);
});

test('Chrome, local config: the chip says local, and the recorded hashes still name the chains they are on', { skip, timeout: 30_000 }, async () => {
  await viewport(390, 844);
  await cdp.open(`${served.local.origin}/`);
  await waitFor("document.documentElement.dataset.config === 'local'");
  assert.equal(await cdp.page("return document.getElementById('chip').textContent;"), 'local test coins, mock signer');
  assert.match(await cdp.page("return document.querySelector('.hashes .chain').textContent;"), /^Mutinynet/);
});

test('Chrome replay: labelled REPLAY, one step at a time on request, every hash under its chain, the cancel step with no hash of its own and a link to the film\'s list, no clock', { skip, timeout: 60_000 }, async () => {
  problems.length = 0;
  await viewport(390, 844);
  await cdp.open(`${served.testnet.origin}/replay/`);
  await waitFor("document.documentElement.dataset.state === 'replay'");
  assert.equal(await cdp.page("return document.querySelector('.tag').textContent;"), 'REPLAY');
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
  assert.equal(await cdp.page('return document.querySelector("#step-cancel").dataset.recorded;'), 'false');
  assert.equal(await cdp.page('return document.querySelector("#step-cancel .when").textContent;'), 'not in these runs');
  assert.equal(await cdp.page('return document.querySelector("#step-cancel a.link").getAttribute("href");'), '/#from-film');
  assert.doesNotMatch(await cdp.page('return document.querySelector("#step-cancel").textContent;'), /no cancel on NEAR testnet is recorded/);
  assert.match(await cdp.page('return document.querySelector("#step-refused .when").textContent;'), /^replay · earlier run · 2026-11-01 UTC/);
  assert.equal(await cdp.page('return document.querySelectorAll("[data-clock], [role=timer]").length;'), 0);
  assert.equal(await cdp.page('return document.documentElement.scrollWidth;'), 390);
  await shot('replay-390x844-all', { full: true });
  await viewport(1440, 900, false);
  await cdp.open(`${served.testnet.origin}/replay/#all`);
  await waitFor("document.documentElement.dataset.step === String(" + run.steps.length + ')');
  await shot('replay-1440x900');
  assert.deepEqual(problems, []);
});

test('build of the replay record refuses records that are not the live G2 run and a script refusal', () => {
  const g2 = JSON.parse(readFileSync(join(REPO, 'proofs/g2.json'), 'utf8'));
  const s2 = JSON.parse(readFileSync(join(REPO, 'proofs/s2-refusal.json'), 'utf8'));
  assert.throws(() => buildRun({ g2: { ...g2, label: 'rehearsal-regtest-mock-signer' }, s2 }), /not the live G2 record/);
  assert.throws(() => buildRun({ g2, s2: { ...s2, node_answer: { ...s2.node_answer, refusal: 'transient' } } }), /not a script refusal/);
  assert.throws(() => buildRun({ g2, s2: { ...s2, vault: { ...s2.vault, id: '00' } } }), /not the same test vault/);
});
