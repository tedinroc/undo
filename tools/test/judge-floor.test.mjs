// The judge's path, from the attack and the screener pass on it: what verify.sh, the referee, build.sh,
// setup-repo.sh, the watcher, the README and CLAIMS.md may and may not say. Offline: every network a run here
// touches is a dead local port or a stand-in Esplora in this process.
//
//   node --test tools/test/judge-floor.test.mjs
//
// UNDO_TOOLS_CHECK_BIN names the built referee (tools/rust-check); without it the tests that need its real verdicts
// skip and say so.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { chmodSync, cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { homedir, tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { CONFIG_FORMAT, checkWatchConfig, makeTopic, StateStore, Watcher } from '../lib/watch.mjs';
import { consensusJudge, consensusVerdict } from '../verify/rust.mjs';
import { sha256 } from '../lib/crypto.mjs';
import { base58Decode, base58Encode, fromHex, toHex, utf8 } from '../lib/bytes.mjs';
import { addressToSpk, makeTx, serialize, txid as bitcoinTxid } from '../lib/btc.mjs';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const read = (p) => readFileSync(join(REPO, p), 'utf8');
const g2 = JSON.parse(read('proofs/g2.json'));
const s2 = JSON.parse(read('proofs/s2-refusal.json'));
// The later run, on the final build: its record, the spend key alone on its vault, and what the chain answered.
const g2v1 = JSON.parse(read('proofs/g2-v1.json'));
const s2v1 = JSON.parse(read('proofs/s2-refusal-v1.json'));
const g2v1Chain = JSON.parse(read('tools/test/fixtures/g2-v1-archival.json'));
// The take of the live pages the earlier film (v2) was cut from, in headless Chrome with its virtual authenticator: its
// record, and what NEAR testnet and Mutinynet answered about it.
const take = JSON.parse(read('proofs/chrome-take.json'));
const takeChain = JSON.parse(read('tools/test/fixtures/chrome-take-archival.json'));
// The take the film is cut from (v3): the phone page on a real phone, the thief tab on a second device; its record, and
// what the chains answered about it.
const filmTake = JSON.parse(read('proofs/film-take.json'));
const filmChain = JSON.parse(read('tools/test/fixtures/film-take-archival.json'));
// The run of the same pages with a real phone's passkey: its record, and what the chains answered about it.
const phone = JSON.parse(read('proofs/phone-take.json'));
const phoneChain = JSON.parse(read('tools/test/fixtures/phone-take-archival.json'));
const REFEREE = process.env.UNDO_TOOLS_CHECK_BIN && existsSync(process.env.UNDO_TOOLS_CHECK_BIN) ? process.env.UNDO_TOOLS_CHECK_BIN : null;
const noReferee = REFEREE ? false : 'set UNDO_TOOLS_CHECK_BIN to the built tools/rust-check referee';

let work;
before(() => { work = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'undo-judge-floor-')); });
after(() => rmSync(work, { recursive: true, force: true }));

const script = (name, body) => {
  const path = join(work, name);
  writeFileSync(path, `#!/bin/sh\n${body}\n`);
  chmodSync(path, 0o755);
  return path;
};

// ---------------------------------------------------------------- the referee: a crash is no verdict

test('referee: a crash or an answer without a verdict is null, never "refused"', () => {
  const crash = script('crash.sh', 'echo "thread main panicked at src/main.rs:76" >&2; exit 101');
  const mute = script('mute.sh', 'exit 1');
  const cosign = g2.cosigned;
  const value = g2.coins.find((c) => c.role === 'cosign').value;
  for (const bin of [crash, mute]) {
    process.env.UNDO_TOOLS_CHECK_BIN = bin;
    const j = consensusJudge(REPO, cosign.raw, g2.vault.spk, [value]);
    assert.equal(j.verdict, null, bin);
    assert.equal(j.crashed, true);
    assert.match(j.why, /without a verdict/);
    assert.equal(consensusVerdict(REPO, cosign.raw, g2.vault.spk, [value]), null);
  }
  if (REFEREE) process.env.UNDO_TOOLS_CHECK_BIN = REFEREE;
  else delete process.env.UNDO_TOOLS_CHECK_BIN;
});

test('referee, the real one: accepts the mined G2 spend, refuses a wrong value, and a value it cannot parse is a crash, not a refusal', { skip: noReferee }, () => {
  const value = g2.coins.find((c) => c.role === 'cosign').value;
  assert.deepEqual(consensusJudge(REPO, g2.cosigned.raw, g2.vault.spk, [value]), { verdict: true, why: null, crashed: false });
  assert.deepEqual(consensusJudge(REPO, g2.cosigned.raw, g2.vault.spk, [value + 1]), { verdict: false, why: null, crashed: false });
  // The attack's case: the referee panics on this (exit 101). Before the fix it read as "refused".
  const broken = consensusJudge(REPO, g2.cosigned.raw, g2.vault.spk, [undefined]);
  assert.equal(broken.verdict, null);
  assert.equal(broken.crashed, true);
  assert.match(broken.why, /exited 101/);
});

/** A referee that accepts exactly the (raw, values) pairs listed, and crashes (exit 101) on everything else. */
function pickyReferee(name, accept) {
  const list = join(work, `${name}.json`);
  writeFileSync(list, JSON.stringify(accept.map(([raw, values]) => `${raw}|${values.join(',')}`)));
  return script(name, `exec "${process.execPath}" -e 'const ok = new Set(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))); const [, , raw, , values] = process.argv; if (ok.has(raw + "|" + values)) { console.log("consensus ok"); process.exit(0); } console.error("panicked"); process.exit(101);' "${list}" "$@"`);
}

test('proof checkers: a referee that crashes on every control is no refusal, so the G1 and G2 proofs fail', () => {
  const cosign = g2.coins.find((c) => c.role === 'cosign').value;
  const escape = g2.coins.find((c) => c.role === 'escape').value;
  const g2bin = pickyReferee('picky-g2', [[g2.cosigned.raw, [cosign]], [g2.escape.raw, [escape]]]);
  const two = spawnSync(process.execPath, [join(REPO, 'tools/test/check-g2-proof.mjs'), join(REPO, 'proofs/g2.json')], { encoding: 'utf8', env: { ...process.env, UNDO_TOOLS_CHECK_BIN: g2bin } });
  assert.equal(two.status, 1, two.stdout);
  for (const why of ['a wrong value was not refused', 'does not refuse the spend with no K_u signature', 'does not refuse the escape one block short']) assert.match(two.stdout, new RegExp(`G2 PROOF FAIL: .*${why}`));
  // The later run's record is held to the same.
  const v1bin = pickyReferee('picky-g2-v1', [[g2v1.cosigned.raw, [g2v1.coins.find((c) => c.role === 'cosign').value]], [g2v1.escape.raw, [g2v1.coins.find((c) => c.role === 'escape').value]]]);
  const three = spawnSync(process.execPath, [join(REPO, 'tools/test/check-g2-proof.mjs'), join(REPO, 'proofs/g2-v1.json')], { encoding: 'utf8', env: { ...process.env, UNDO_TOOLS_CHECK_BIN: v1bin } });
  assert.equal(three.status, 1, three.stdout);
  for (const why of ['a wrong value was not refused', 'does not refuse the spend with no K_u signature', 'does not refuse the escape one block short']) assert.match(three.stdout, new RegExp(`G2 PROOF FAIL: .*${why}`));
  const g1 = JSON.parse(read('proofs/g1.json'));
  const runs = [];
  const walk = (n) => { if (Array.isArray(n)) n.forEach(walk); else if (n && typeof n === 'object') { if (n.final_tx && n.input_values) runs.push(n); Object.values(n).forEach(walk); } };
  walk(g1.stages);
  assert.ok(runs.length > 0);
  const g1bin = pickyReferee('picky-g1', runs.map((r) => [r.final_tx, r.input_values]));
  const one = spawnSync(process.execPath, [join(REPO, 'tools/test/check-g1-proof.mjs'), join(REPO, 'proofs/g1.json')], { encoding: 'utf8', env: { ...process.env, UNDO_TOOLS_CHECK_BIN: g1bin } });
  assert.equal(one.status, 1, one.stdout);
  assert.match(one.stdout, /FAIL control for request \d+: a wrong value must be refused, and the referee gave no verdict \(exit 101\)/);
  // The live drivers hold the same rule where a refusal is what they record.
  assert.match(read('tools/g2.mjs'), /if \(control\.status !== 1\) throw new Fail\(step, 'consensus_control_not_judged'/);
});

test('the key-alone tool records a refusal only on the referee\'s own refusal, never on a crash', { skip: existsSync(join(REPO, 'tools/s2-refusal.mjs')) ? false : 'tools/s2-refusal.mjs comes with the web branch' }, () => {
  assert.match(read('tools/s2-refusal.mjs'), /if \(local\.status !== 1\) throw new Stop\(`the consensus check gave no verdict/);
});

test('proof checkers, the real referee: the recorded G1 and G2 proofs still pass', { skip: noReferee }, () => {
  const v1Gate = new RegExp(`G2 PROOF OK: chain lines pass, gate_complete ${g2v1.summary.gate_complete}, consensus agrees`);
  for (const [checker, file, want] of [['check-g2-proof.mjs', 'g2.json', /G2 PROOF OK: chain lines pass, gate_complete true, consensus agrees/], ['check-g2-proof.mjs', 'g2-v1.json', v1Gate], ['check-g1-proof.mjs', 'g1.json', /^PASS \[consensus-lib\] \d+ final transactions accepted/m]]) {
    const r = spawnSync(process.execPath, [join(REPO, 'tools/test', checker), join(REPO, 'proofs', file)], { encoding: 'utf8', env: { ...process.env, UNDO_TOOLS_CHECK_BIN: REFEREE } });
    assert.equal(r.status, 0, r.stdout);
    assert.match(r.stdout, want);
  }
});

// ---------------------------------------------------------------- tier A against a stand-in Esplora

const DEAD = 'http://127.0.0.1:9';

/**
 * A stand-in for mutinynet.com/api that knows both runs' transactions and the take's coin, with the S2 coin's spender
 * chosen per test. `outspendV1` is the same for the later run's key-alone coin: as recorded unless a test says
 * otherwise. `outspendTake` is the earlier film's take's coin: unspent, as it was captured, unless a test says
 * otherwise; `outspendPhone` the same for the one-device run, and `outspendFilm` for the film's take. `change` edits
 * what it knows.
 */
function esplora({ outspend, outspendV1 = { spent: true, txid: s2v1.coin_return.mutinynet_txid, vin: 0 }, outspendTake = { spent: false }, outspendPhone = { spent: false }, outspendFilm = { spent: false }, change = () => {} }) {
  const known = new Map([g2, g2v1].flatMap((p) => [
    [p.cosigned.txid, { hex: p.cosigned.raw, height: p.cosigned.mined_height }],
    [p.escape.txid, { hex: p.escape.raw, height: p.escape.mined_height }],
    [p.escape.coin.split(':')[0], { hex: null, height: p.escape.coin_height }],
  ]));
  known.set(take.coin.mutinynet_txid, { hex: takeChain.bitcoin[take.coin.mutinynet_txid].hex, height: takeChain.bitcoin[take.coin.mutinynet_txid].status.block_height });
  known.set(phone.coin.mutinynet_txid, { hex: phoneChain.bitcoin[phone.coin.mutinynet_txid].hex, height: phoneChain.bitcoin[phone.coin.mutinynet_txid].status.block_height });
  known.set(filmTake.coin.mutinynet_txid, { hex: filmChain.bitcoin[filmTake.coin.mutinynet_txid].hex, height: filmChain.bitcoin[filmTake.coin.mutinynet_txid].status.block_height });
  change(known);
  const server = createServer((req, res) => {
    const m = /^\/api\/tx\/([0-9a-f]{64})\/(hex|status|outspend\/\d+)$/.exec(req.url);
    const send = (status, body) => {
      res.writeHead(status, { 'content-type': typeof body === 'string' ? 'text/plain' : 'application/json' });
      res.end(typeof body === 'string' ? body : JSON.stringify(body));
    };
    if (!m) return send(404, 'not found');
    const [, txid, what] = m;
    if (what.startsWith('outspend')) return txid === s2.funding_coin.mutinynet_txid ? send(200, outspend) : txid === s2v1.funding_coin.mutinynet_txid ? send(200, outspendV1) : txid === take.coin.mutinynet_txid ? send(200, outspendTake) : txid === phone.coin.mutinynet_txid ? send(200, outspendPhone) : txid === filmTake.coin.mutinynet_txid ? send(200, outspendFilm) : send(404, 'not found');
    const tx = known.get(txid);
    if (!tx) return send(404, 'Transaction not found');
    if (what === 'hex') return tx.hex ? send(200, tx.hex) : send(404, 'no hex here');
    return send(200, { confirmed: true, block_height: tx.height });
  });
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r({ url: `http://127.0.0.1:${server.address().port}/api`, close: () => server.close() })));
}

/**
 * tier-a.mjs with no cargo on PATH, NEAR at a dead port, and Esplora at `esploraUrl`. `archivalUrl` puts a stand-in
 * where the archival RPC is, and `rpcUrl` one where the replay's views go. `repo` runs a copy of this tree's tier A
 * instead, with the records that copy holds. Async: the stand-ins answer from here.
 */
function tierA({ esploraUrl, referee, archivalUrl = DEAD, rpcUrl = DEAD, repo = REPO }) {
  const config = JSON.parse(read('deploy/testnet.json'));
  config.rpc = [DEAD];
  config.replay = { ...config.replay, near_rpc: [rpcUrl], near_archival_rpc: [archivalUrl], mutinynet_esplora: esploraUrl };
  const path = join(work, `tier-a-${Math.random().toString(36).slice(2)}.json`);
  writeFileSync(path, JSON.stringify(config));
  const env = { PATH: `${dirname(process.execPath)}:/usr/bin:/bin`, HOME: work, TMPDIR: work };
  if (referee) env.UNDO_TOOLS_CHECK_BIN = referee;
  return new Promise((done) => {
    const child = spawn(process.execPath, [join(repo, 'tools/verify/tier-a.mjs'), '--config', path], { env });
    let out = '';
    child.stdout.on('data', (c) => { out += c; });
    child.stderr.on('data', (c) => { out += c; });
    const timer = setTimeout(() => child.kill('SIGKILL'), 120_000);
    child.on('close', (code) => {
      clearTimeout(timer);
      done({ code, out, lines: out.split('\n').filter((l) => /^(PASS|FAIL|SKIP|INFO) /.test(l)) });
    });
  });
}

const claimIds = new Set([...read('CLAIMS.md').matchAll(/^\| (C\d\d) \|/gm)].map((m) => m[1]));

function everyLineHasAClaim(lines) {
  for (const l of lines) {
    const m = /^(PASS|FAIL|SKIP|INFO) (\S+) \[/.exec(l);
    assert.ok(m, `not a result line: ${l}`);
    assert.ok(claimIds.has(m[2]), `${m[2]} is not a row of CLAIMS.md: ${l}`);
  }
}

test('tier A with a crashing referee: no consensus line passes, the controls say "no verdict", and the run fails', { timeout: 150_000 }, async () => {
  const api = await esplora({ outspend: { spent: true, txid: s2.coin_return.mutinynet_txid, vin: 0 } });
  try {
    const r = await tierA({ esploraUrl: api.url, referee: script('crash-a.sh', 'echo panicked >&2; exit 101') });
    assert.equal(r.code, 1, r.out);
    assert.equal(r.lines.filter((l) => /^PASS \S+ \[consensus-lib\]/.test(l)).length, 0, r.out);
    for (const id of ['C02', 'C03', 'C04']) assert.ok(r.lines.some((l) => new RegExp(`^FAIL ${id} \\[consensus-lib\\] .*no verdict: the referee exited 101`).test(l)), `${id}\n${r.out}`);
    everyLineHasAClaim(r.lines);
  } finally {
    api.close();
  }
});

test('tier A with every endpoint dead: no [replay] line passes, and the recorded early escape is INFO, not PASS', { skip: noReferee, timeout: 150_000 }, async () => {
  const r = await tierA({ esploraUrl: `${DEAD}/api`, referee: REFEREE });
  assert.equal(r.lines.filter((l) => /^PASS \S+ \[replay\]/.test(l)).length, 0, r.out);
  assert.ok(r.lines.some((l) => /^INFO C04 \[live-mutinynet, recorded in G2, 2026-10-31\] G2 escape sent before the coin was CSV old/.test(l)), r.out);
  assert.equal(r.lines.filter((l) => /^PASS C04 \[replay\] G2 escape sent before/.test(l)).length, 0);
  // The later run's record is held to the same: its early escape is INFO, and what was not fetched says SKIP.
  assert.ok(r.lines.some((l) => /^INFO C04 \[live-mutinynet, recorded on the final build, \d{4}-\d\d-\d\d\] Final build \(v1\.s\.undo-btc\.testnet\) escape sent before the coin was CSV old/.test(l)), r.out);
  assert.ok(r.lines.some((l) => l.startsWith(`SKIP C12 [replay] proofs/g2-v1.json execute ${v1.execute}: SKIP (network)`)), r.out);
  assert.ok(r.lines.some((l) => l.startsWith(`SKIP C03 [replay] Mutinynet coin ${s2v1.funding_coin.mutinynet_txid}: SKIP (network)`)), r.out);
  // The take of the live pages is held to the same: nothing of it was fetched, so nothing of it passes.
  assert.ok(r.lines.some((l) => l.startsWith(`SKIP C17 [replay] proofs/chrome-take.json proposal ${take.thief.propose_tx}: SKIP (network)`)), r.out);
  assert.ok(r.lines.some((l) => l.startsWith('SKIP C17 [replay] 3 more NEAR testnet lines of the live take: SKIP (network)')), r.out);
  assert.ok(r.lines.some((l) => l.startsWith(`SKIP C17 [replay] Mutinynet coin ${take.coin.mutinynet_txid}:${take.coin.vout}: SKIP (network)`)), r.out);
  // And the real phone's run: it has no execute after the wait, so two lines are left after the first, not three.
  const phoneSection = phoneLines(r);
  assert.ok(phoneSection.some((l) => l.startsWith(`SKIP C17 [replay] proofs/phone-take.json proposal ${phone.thief.propose_tx}: SKIP (network)`)), r.out);
  assert.ok(phoneSection.includes('SKIP C17 [replay] 2 more NEAR testnet lines of the live take: SKIP (network), the archival RPC did not answer'), r.out);
  assert.ok(phoneSection.some((l) => l.startsWith(`SKIP C17 [replay] Mutinynet coin ${phone.coin.mutinynet_txid}:${phone.coin.vout}: SKIP (network)`)), r.out);
  assert.equal(phoneSection.length, 3, r.out);
  // The film's take, with no execute either, the same.
  const filmSection = filmLines(r);
  assert.ok(filmSection.some((l) => l.startsWith(`SKIP C17 [replay] proofs/film-take.json proposal ${filmTake.thief.propose_tx}: SKIP (network)`)), r.out);
  assert.ok(filmSection.includes('SKIP C17 [replay] 2 more NEAR testnet lines of the live take: SKIP (network), the archival RPC did not answer'), r.out);
  assert.equal(filmSection.length, 3, r.out);
  assert.equal(r.lines.filter((l) => /^PASS (C05|C17) /.test(l)).length, 0, r.out);
  // The consensus checks still run on the raw hex in proofs/.
  assert.ok(r.lines.some((l) => /^PASS C02 \[consensus-lib\]/.test(l)), r.out);
  assert.ok(r.lines.some((l) => /^SKIP C12 \[live-testnet\] signer arguments: SKIP \(network\)/.test(l)), r.out);
  // The agent run: nothing fetched, so nothing passes; its first line and the count of the rest say SKIP.
  assert.equal(r.lines.filter((l) => /^(PASS|FAIL) C14 /.test(l)).length, 0, r.out);
  assert.ok(r.lines.some((l) => /^SKIP C14 \[replay\] the key's AddKey \S+: SKIP \(network\)/.test(l)), r.out);
  assert.ok(r.lines.some((l) => /^SKIP C14 \[replay\] 11 more transactions of the agent run: SKIP \(network\)/.test(l)), r.out);
  // A placeholder deploy/testnet.json says so; once the deploy fills it, the dead RPC does.
  assert.ok(r.lines.some((l) => /^SKIP C06 \[live-testnet\] (the contract's status view: .* holds a placeholder|status view: SKIP \(network\))/.test(l)), r.out);
  assert.equal(r.code, 0, r.out);
  everyLineHasAClaim(r.lines);
});

test('tier A, C03: the coin\'s spender must be the cold-key return proofs/ records; another spender, or none, fails', { skip: noReferee, timeout: 300_000 }, async () => {
  const cases = [
    [{ spent: true, txid: s2.coin_return.mutinynet_txid, vin: 0 }, /^PASS C03 \[replay\] .*spent later by Mutinynet txid f0bd80ec.*the cold-key return proofs\/s2-refusal\.json records/],
    [{ spent: true, txid: 'ab'.repeat(32), vin: 0 }, /^FAIL C03 \[replay\] .*spent by Mutinynet txid abab.*not the cold-key return proofs\/s2-refusal\.json records/],
    [{ spent: false }, /^FAIL C03 \[replay\] .*the API says unspent, but proofs\/s2-refusal\.json records its cold-key return/],
    [{ spent: true, txid: s2.refused_tx.mutinynet_txid_it_would_have_had, vin: 0 }, /^FAIL C03 \[replay\] .*the refused spend is the one that spent the coin/],
  ];
  for (const [outspend, want] of cases) {
    const api = await esplora({ outspend });
    try {
      const r = await tierA({ esploraUrl: api.url, referee: REFEREE });
      assert.ok(r.lines.some((l) => want.test(l)), `${JSON.stringify(outspend)}\n${r.out}`);
      assert.equal(r.code, outspend.txid === s2.coin_return.mutinynet_txid ? 0 : 1, r.out);
      everyLineHasAClaim(r.lines);
    } finally {
      api.close();
    }
  }
});

// ---------------------------------------------------------------- tier A, C14: the agent run against a stand-in archival node

const c14 = JSON.parse(read('proofs/c14-agent.json'));
const c14Chain = JSON.parse(read('tools/test/fixtures/c14-archival.json'));

/**
 * A stand-in for the archival RPC that knows the agent run's transactions and one block, as the real one answered
 * them, after `change` has edited a copy. Anything else gets no answer, so the G1 and G2 lines say SKIP (network).
 */
function archival(change = () => {}, base = c14Chain) {
  const chain = structuredClone(base);
  change(chain);
  // A fixture's queries are kept under the words of the question: an account at a block, or a view and its arguments.
  const asked = (q = {}) => (q.request_type === 'view_account' ? `view_account ${q.account_id} @${q.block_id}`
    : q.request_type === 'call_function' ? `call_function ${q.account_id} ${q.method_name} ${Buffer.from(q.args_base64 ?? '', 'base64').toString('utf8')}` : '');
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      let call;
      try {
        call = JSON.parse(body);
      } catch {
        return req.socket.destroy();
      }
      const result = call.method === 'tx' ? chain.tx[call.params?.tx_hash] : call.method === 'block' ? chain.block[call.params?.block_id]
        : call.method === 'query' ? chain.query?.[asked(call.params)] : undefined;
      if (result === undefined) return req.socket.destroy();
      res.writeHead(200, { 'content-type': 'application/json' });
      return res.end(JSON.stringify({ jsonrpc: '2.0', id: call.id, result }));
    });
  });
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r({ url: `http://127.0.0.1:${server.address().port}`, close: () => { server.closeAllConnections(); server.close(); } })));
}

const c14Lines = (r) => r.lines.filter((l) => /^(PASS|FAIL|SKIP|INFO) C14 /.test(l));

test('tier A, C14: every recorded transaction of the agent run is fetched again and passes; what NEAR refused is INFO, never PASS', { timeout: 150_000 }, async () => {
  const node = await archival();
  try {
    const r = await tierA({ esploraUrl: `${DEAD}/api`, archivalUrl: node.url });
    const lines = c14Lines(r);
    const passed = lines.filter((l) => l.startsWith('PASS C14 [replay] NEAR testnet tx '));
    assert.equal(lines.filter((l) => !l.startsWith('PASS') && !l.startsWith('INFO')).length, 0, r.out);
    // One line for each transaction the fixture holds, and each names its hash.
    assert.equal(passed.length, Object.keys(c14Chain.tx).length, r.out);
    for (const hash of Object.keys(c14Chain.tx)) assert.equal(passed.filter((l) => l.includes(`NEAR testnet tx ${hash}:`)).length, 1, hash);
    const agentKey = c14.agent.function_call_key.public_key;
    assert.ok(passed.some((l) => l.includes(`was given ${agentKey} as a function-call key for ${c14.contract.account}, methods propose_btc and execute only`)), r.out);
    assert.ok(passed.some((l) => l.includes(`${c14.propose.tx}: propose_btc on ${c14.contract.account}, signed by that function-call key, made request 0`) && l.includes('set its unlock 5:00 after the block it ran in')), r.out);
    for (const a of c14.contract_refusals.attempts) assert.ok(passed.some((l) => l.includes(a.tx) && l.endsWith(`The contract refused it: ${a.refusal}`)), a.what);
    assert.ok(passed.some((l) => l.includes(c14.owner_cancel.tx) && l.includes('log "undo:cancelled request=0"') && l.includes('software authenticator')), r.out);
    assert.ok(passed.some((l) => l.includes(c14.rotation.after_rotation.direct_tx) && l.endsWith('Smart contract panicked: SpendKeySuspended')), r.out);
    assert.ok(passed.some((l) => l.includes(c14.rotation.after_the_new_key_lands.propose_tx) && l.endsWith('Smart contract panicked: bad K_s signature')), r.out);
    const info = lines.filter((l) => l.startsWith('INFO'));
    assert.equal(info.length, 1, r.out);
    assert.match(info[0], /^INFO C14 \[live-testnet, recorded 2026-11-11\] NEAR refused 7 calls signed by the agent's key before any contract ran.* Not fetched again: /);
    for (const call of c14.near_refusals.calls) assert.ok(r.out.includes(`    ${call.what}: ${call.words}`), call.what);
    assert.equal(lines.some((l) => /^PASS .*MethodNameMismatch/.test(l)), false, 'a refusal that left nothing on chain is not a PASS');
    everyLineHasAClaim(r.lines);
  } finally {
    node.close();
  }
});

test('tier A, C14: a wider key, another signer, a call the contract took, other words or a missing log each fail their line', { timeout: 300_000 }, async () => {
  const p = c14;
  const addKey = (chain) => chain.tx[p.agent.function_call_key.add_key_tx].transaction.actions[0].AddKey.access_key;
  const succeed = (tx) => {
    tx.status = { SuccessValue: '' };
    for (const r of tx.receipts_outcome) r.outcome.status = { SuccessValue: '' };
  };
  const otherWords = (tx) => {
    const text = JSON.stringify(tx).replaceAll('webauthn: bad signature', 'request not found').replaceAll('SpendKeySuspended', 'OutflowCap').replaceAll('bad K_s signature', 'expired');
    Object.assign(tx, JSON.parse(text));
  };
  const attempt = (what) => p.contract_refusals.attempts.find((a) => a.what.startsWith(what));
  const runs = [
    [(chain) => {
      addKey(chain).permission.FunctionCall.method_names.push('cancel');
      chain.tx[p.propose.tx].transaction.public_key = p.agent.full_access_key;
      succeed(chain.tx[attempt('cancel, with a passkey').tx]);
      chain.tx[p.owner_cancel.tx].transaction.signer_id = p.agent.account;
      otherWords(chain.tx[p.rotation.after_rotation.direct_tx]);
      succeed(chain.tx[p.rotation.after_the_new_key_lands.propose_tx]);
    }, [
      [p.agent.function_call_key.add_key_tx, /the key may also call cancel$/],
      [p.propose.tx, /signed by ed25519:\S+, not the agent's function-call key$/],
      [attempt('cancel, with a passkey').tx, /the contract did not refuse it$/],
      [p.owner_cancel.tx, new RegExp(`signed by ${p.agent.account}, not ${p.relay.account}$`)],
      [p.rotation.after_rotation.direct_tx, /refused, but not with "SpendKeySuspended": Smart contract panicked: OutflowCap$/],
      [p.rotation.after_the_new_key_lands.propose_tx, /the contract did not refuse it$/],
    ]],
    [(chain) => {
      addKey(chain).permission.FunctionCall.method_names = [];
      const block = Object.values(chain.block)[0];
      block.header.timestamp_nanosec = String(BigInt(block.header.timestamp_nanosec) - 240_000_000_000n);
      otherWords(chain.tx[attempt('set_policy').tx]);
      for (const r of chain.tx[p.owner_cancel.tx].receipts_outcome) r.outcome.logs = [];
      chain.tx[p.rotation.owner_rotate.tx].transaction.actions[0].FunctionCall.method_name = 'cancel';
      chain.tx[attempt('clear_hold').tx].transaction.receiver_id = 'g1.s.undo-btc.testnet';
    }, [
      [p.agent.function_call_key.add_key_tx, /the key lists no method, which NEAR reads as every method$/],
      [p.propose.tx, /the unlock is 540000 ms after its block, not one of the contract's new-destination waits \(300000, 600000\)$/],
      [attempt('set_policy').tx, /refused, but not with "webauthn: bad signature": Smart contract panicked: request not found$/],
      [p.owner_cancel.tx, /no log "undo:cancelled request=0" from /],
      [p.rotation.owner_rotate.tx, /not one call of cancel_all_and_rotate$/],
      [attempt('clear_hold').tx, /sent to g1\.s\.undo-btc\.testnet, not /],
    ]],
    [(chain) => {
      addKey(chain).permission = 'FullAccess';
      chain.tx[p.propose.tx].status = { SuccessValue: Buffer.from('7').toString('base64') };
      const args = { ...JSON.parse(Buffer.from(chain.tx[attempt('add_destination').tx].transaction.actions[0].FunctionCall.args, 'base64').toString('utf8')), vault: 'ab'.repeat(32) };
      chain.tx[attempt('add_destination').tx].transaction.actions[0].FunctionCall.args = Buffer.from(JSON.stringify(args)).toString('base64');
    }, [
      [p.agent.function_call_key.add_key_tx, /the key it added is not a function-call key \("FullAccess"\)$/],
      [p.propose.tx, /it did not return request 0$/],
      [attempt('add_destination').tx, /not about vault /],
    ]],
    [(chain) => {
      addKey(chain).permission.FunctionCall.receiver_id = 'g1.s.undo-btc.testnet';
      chain.tx[p.agent.function_call_key.add_key_tx].transaction.public_key = p.agent.function_call_key.public_key;
    }, [[p.agent.function_call_key.add_key_tx, /signed by the agent's own key$/]]],
    [(chain) => { addKey(chain).permission.FunctionCall.receiver_id = 'g1.s.undo-btc.testnet'; }, [[p.agent.function_call_key.add_key_tx, /the key is for g1\.s\.undo-btc\.testnet, not /]]],
  ];
  for (const [change, wants] of runs) {
    const node = await archival(change);
    try {
      const r = await tierA({ esploraUrl: `${DEAD}/api`, archivalUrl: node.url });
      const lines = c14Lines(r);
      assert.equal(r.code, 1, r.out);
      for (const [hash, want] of wants) {
        const failed = lines.filter((l) => l.startsWith(`FAIL C14 [replay] NEAR testnet tx ${hash}: `));
        assert.equal(failed.length, 1, `${hash}\n${r.out}`);
        assert.match(failed[0], want);
        assert.equal(lines.some((l) => l.startsWith('PASS') && l.includes(hash)), false, `${hash} must not also pass`);
      }
      // Only the edited transactions fail: the rest still pass.
      assert.equal(lines.filter((l) => l.startsWith('FAIL')).length, wants.length, r.out);
      assert.equal(lines.filter((l) => l.startsWith('PASS')).length, Object.keys(c14Chain.tx).length - wants.length, r.out);
      everyLineHasAClaim(r.lines);
    } finally {
      node.close();
    }
  }
});

test('tier A, C14: each of the twelve is read for the key that signed it; another key than the record says fails its line', { timeout: 300_000 }, async () => {
  const p = c14;
  const agentKey = p.agent.function_call_key.public_key;
  const relayKey = c14Chain.tx[p.owner_cancel.tx].transaction.public_key;
  const attempt = (what) => p.contract_refusals.attempts.find((a) => a.what.startsWith(what));
  // As recorded: three by the agent's function-call key, seven by the full-access key, two by a key of the relay's.
  const by = (key) => Object.values(c14Chain.tx).filter((t) => t.transaction.public_key === key).length;
  assert.deepEqual([by(agentKey), by(p.agent.full_access_key), by(relayKey)], [3, 7, 2]);
  assert.equal(new Set([agentKey, p.agent.full_access_key, relayKey]).size, 3);
  const runs = [
    // A key of the relay's, which is neither the agent's nor the full-access key, on the AddKey and on a relayed call.
    [(chain) => {
      chain.tx[p.agent.function_call_key.add_key_tx].transaction.public_key = relayKey;
      chain.tx[attempt('set_policy').tx].transaction.public_key = relayKey;
    }, [
      [p.agent.function_call_key.add_key_tx, new RegExp(`signed by ${relayKey}, not the full-access key proofs/c14-agent\\.json records$`)],
      [attempt('set_policy').tx, new RegExp(`signed by ${relayKey}, not the full-access key proofs/c14-agent\\.json records$`)],
    ]],
    // The agent's own key on what the relay sent for the owner, and on a call the full-access account relayed.
    [(chain) => {
      chain.tx[p.owner_cancel.tx].transaction.public_key = agentKey;
      chain.tx[p.rotation.owner_rotate.tx].transaction.public_key = agentKey;
      chain.tx[attempt('clear_hold').tx].transaction.public_key = agentKey;
    }, [
      [p.owner_cancel.tx, /signed by the agent's function-call key$/],
      [p.rotation.owner_rotate.tx, /signed by the agent's function-call key$/],
      [attempt('clear_hold').tx, new RegExp(`signed by ${agentKey}, not the full-access key proofs/c14-agent\\.json records$`)],
    ]],
  ];
  for (const [change, wants] of runs) {
    const node = await archival(change);
    try {
      const r = await tierA({ esploraUrl: `${DEAD}/api`, archivalUrl: node.url });
      const lines = c14Lines(r);
      assert.equal(r.code, 1, r.out);
      for (const [hash, want] of wants) {
        const failed = lines.filter((l) => l.startsWith(`FAIL C14 [replay] NEAR testnet tx ${hash}: `));
        assert.equal(failed.length, 1, `${hash}\n${r.out}`);
        assert.match(failed[0], want);
        assert.equal(lines.some((l) => l.startsWith('PASS') && l.includes(hash)), false, `${hash} must not also pass`);
      }
      assert.equal(lines.filter((l) => l.startsWith('FAIL')).length, wants.length, r.out);
      assert.equal(lines.filter((l) => l.startsWith('PASS')).length, Object.keys(c14Chain.tx).length - wants.length, r.out);
      everyLineHasAClaim(r.lines);
    } finally {
      node.close();
    }
  }
});

test('tier A, C14: an archival node that stops answering part way gives SKIP (network) for that line and counts the rest, never PASS or FAIL', { timeout: 150_000 }, async () => {
  const gone = c14.contract_refusals.attempts[1].tx;
  const node = await archival((chain) => { delete chain.tx[gone]; });
  try {
    const r = await tierA({ esploraUrl: `${DEAD}/api`, archivalUrl: node.url });
    const lines = c14Lines(r).filter((l) => !l.startsWith('INFO'));
    const passed = lines.filter((l) => l.startsWith('PASS')).length;
    assert.equal(lines.filter((l) => l.startsWith('FAIL')).length, 0, r.out);
    assert.equal(lines.filter((l) => l.includes(gone)).length, 1, r.out);
    assert.ok(lines.some((l) => l.startsWith(`SKIP C14 [replay] cancel ${gone}: SKIP (network)`)), r.out);
    // Three run at a time, so how many had started when the answer stopped varies. Every one is a line or is counted.
    assert.ok(passed >= 3 && passed <= 11, r.out);
    const more = lines.map((l) => /^SKIP C14 \[replay\] (\d+) more transactions of the agent run: SKIP \(network\)/.exec(l)).find(Boolean);
    assert.equal(passed + 1 + (more ? Number(more[1]) : 0), Object.keys(c14Chain.tx).length, r.out);
  } finally {
    node.close();
  }
});

// ---------------------------------------------------------------- tier A: the later run, on the final build

const v1 = {
  contract: g2v1.contract.account,
  execute: g2v1.cosigned.attempts.find((a) => a.execute_tx && a.signer_answer).execute_tx,
  propose: g2v1.cosigned.propose_tx,
  spend: g2v1.cosigned.txid,
  escape: g2v1.escape.txid,
  tag: `Final build (${g2v1.contract.account})`,
};
const v1Lines = (r) => r.lines.filter((l) => [v1.execute, v1.propose, v1.spend, v1.escape, v1.tag, 'at the block of that execute', 'proofs/g2-v1.json', 'proofs/s2-refusal-v1.json', s2v1.funding_coin.mutinynet_txid].some((w) => l.includes(w)));
/** The stand-ins for one run of tier A over the later run's record: Esplora, and one node for archival RPC and views. */
async function v1Run({ chain = () => {}, bitcoin = () => {}, outspendV1, referee = REFEREE } = {}) {
  const api = await esplora({ outspend: { spent: true, txid: s2.coin_return.mutinynet_txid, vin: 0 }, outspendV1, change: bitcoin });
  const node = await archival(chain, g2v1Chain);
  try {
    return await tierA({ esploraUrl: api.url, archivalUrl: node.url, rpcUrl: node.url, referee });
  } finally {
    api.close();
    node.close();
  }
}

test('proofs/g2-v1.json: a live run on the contract and the wasm deploy/testnet.json names, apart from the first run\'s record', () => {
  const config = JSON.parse(read('deploy/testnet.json'));
  assert.equal(g2v1.label, 'live-mutinynet');
  assert.equal(g2v1.contract.account, config.contract);
  assert.equal(g2v1.wasm.sha256, config.wasm_sha256);
  assert.equal(g2v1.signer.account, config.signer);
  assert.notEqual(g2v1.contract.account, g2.contract.account);
  assert.notEqual(g2v1.vault.id, g2.vault.id);
  // Nothing of the first run's is in it, and it holds no key.
  for (const id of [g2.cosigned.txid, g2.escape.txid, g2.vault.address]) assert.equal(read('proofs/g2-v1.json').includes(id), false, id);
  assert.doesNotMatch(read('proofs/g2-v1.json'), /"(seed|cold_key|private_key|secret_key|passkey)": "[0-9a-f]{64}"/);
  assert.equal(g2v1.summary.pass, true);
  assert.equal(g2v1.summary.kill_condition_met, false);
  // The spend waited out the contract's unlock, and the escape the Bitcoin timelock.
  assert.ok(g2v1.cosigned.unlocked_at_ms > g2v1.cosigned.unlock);
  assert.equal(g2v1.cosigned.unlock - g2v1.cosigned.proposed_at, g2v1.cosigned.check.delay_ms);
  assert.ok(g2v1.escape.readback.blocks_after_coin >= g2v1.csv_blocks);
  assert.equal(s2v1.vault.near_testnet_contract, g2v1.contract.account);
  assert.equal(s2v1.funding_coin.vault_address, g2v1.vault.address);
  assert.equal(s2v1.node_answer.refusal, 'script');
  assert.equal(s2v1.refused_tx.sats_moved, 0);
});

test('tier A, the final build\'s run: the execute, the code at its block, the wait and the Mutinynet transactions are fetched again and pass', { timeout: 150_000 }, async () => {
  const r = await v1Run();
  const lines = v1Lines(r);
  assert.equal(lines.filter((l) => l.startsWith('FAIL')).length, 0, r.out);
  const one = (re) => {
    const hits = lines.filter((l) => re.test(l));
    assert.equal(hits.length, 1, `${re}\n${r.out}`);
    return hits[0];
  };
  const build = `the final build ${g2v1.wasm.sha256.slice(0, 10)}…`;
  const esc = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const executed = one(new RegExp(`^PASS C12 \\[replay\\] NEAR testnet tx ${v1.execute}: an execute on ${esc(v1.contract)}, ${esc(build)}\\. `));
  assert.ok(executed.includes(`was asked for the digest of Mutinynet txid ${v1.spend}`), executed);
  assert.ok(executed.includes('is the K_m signature in that transaction\'s witness'), executed);
  const code = one(/^PASS C12 \[replay\] NEAR testnet account \S+ ran code hash \S+ at the block of that execute, read from archival RPC/);
  assert.ok(code.includes(`account ${v1.contract} ran code hash ${g2v1.contract.code_hash} `) && code.includes(`the sha256 ${g2v1.wasm.sha256} that proofs/g2-v1.json records`) && code.endsWith(': the final build'), code);
  const waited = one(new RegExp(`^PASS C01 \\[replay\\] NEAR testnet tx ${v1.propose}: propose_btc on ${esc(v1.contract)}, ${esc(build)}, made request ${g2v1.cosigned.request} with its unlock 10:00 after the block it ran in; the execute, tx ${v1.execute}, ran in a block \\d+ s after that unlock, not before\\.`));
  assert.ok(waited.endsWith('One request on NEAR testnet, read from archival RPC'), waited);
  one(new RegExp(`^PASS C12 \\[replay\\] Mutinynet txid ${v1.spend} \\(${esc(v1.tag)} co-signed spend: .*\\): fetched again, same bytes as proofs/, mined at height ${g2v1.cosigned.mined_height}$`));
  one(new RegExp(`^PASS C04 \\[replay\\] Mutinynet txid ${v1.escape} \\(${esc(v1.tag)} escape: .*\\): fetched again, same bytes as proofs/, mined at height ${g2v1.escape.mined_height}, ${g2v1.escape.readback.blocks_after_coin} blocks after the coin it spends$`));
  // What a node refused left nothing on chain: the early escape is INFO, and it never passes as a replay.
  const early = one(new RegExp(`^INFO C04 \\[live-mutinynet, recorded on the final build, \\d{4}-\\d\\d-\\d\\d\\] ${esc(v1.tag)} escape sent before the coin was CSV old: `));
  assert.ok(early.includes(g2v1.escape.early.text) && early.includes('Not fetched again'), early);
  one(new RegExp(`^PASS C03 \\[replay\\] Mutinynet coin ${s2v1.funding_coin.mutinynet_txid}:${s2v1.funding_coin.vout}: spent later by Mutinynet txid ${s2v1.coin_return.mutinynet_txid}, the cold-key return proofs/s2-refusal-v1\\.json records, not by the refused spend$`));
  if (REFEREE) {
    one(new RegExp(`^PASS C12 \\[consensus-lib\\] Mutinynet txid ${v1.spend} .*libbitcoinconsensus accepts every input of the fetched bytes$`));
    one(new RegExp(`^PASS C04 \\[consensus-lib\\] Mutinynet txid ${v1.escape} .*libbitcoinconsensus accepts every input of the fetched bytes$`));
    assert.ok(one(new RegExp(`^PASS C02 \\[consensus-lib\\] ${esc(v1.tag)} control: the same spend with no spend-key signature`)).includes(g2v1.cosigned.ku_control.text));
    assert.ok(one(new RegExp(`^PASS C04 \\[consensus-lib\\] ${esc(v1.tag)} control: the escape signed one block below CSV`)).includes(g2v1.escape.csv_control.text));
    assert.ok(one(new RegExp(`^PASS C03 \\[consensus-lib\\] ${esc(v1.tag)} spend key alone, sent to Mutinynet `)).includes(s2v1.node_answer.text_verbatim.trim().slice(0, 60)));
    assert.equal(r.code, 0, r.out);
  }
  everyLineHasAClaim(r.lines);
});

test('tier A, the final build\'s run: another signature, another key, other code, a shorter wait, an early execute or other bytes each fail their line', { timeout: 600_000 }, async () => {
  const execute = (chain) => chain.tx[v1.execute];
  const answerOf = (chain) => execute(chain).receipts_outcome.find((x) => x.outcome.executor_id === g2v1.signer.account && x.outcome.status?.SuccessValue && Buffer.from(x.outcome.status.SuccessValue, 'base64').toString('utf8').includes('big_r'));
  const blockOf = (chain, hash, shiftMs) => {
    const header = chain.block[hash].header;
    header.timestamp_nanosec = String(BigInt(header.timestamp_nanosec) + BigInt(shiftMs) * 1_000_000n);
  };
  const proposedIn = (chain) => chain.tx[v1.propose].receipts_outcome.find((x) => x.outcome.logs.some((l) => l.startsWith('undo:proposed '))).block_hash;
  const ranIn = (chain) => execute(chain).receipts_outcome.find((x) => x.outcome.logs.some((l) => l.startsWith('undo:executing '))).block_hash;
  const viewKey = Object.keys(g2v1Chain.query).find((k) => k.startsWith('call_function '));
  const accountKey = Object.keys(g2v1Chain.query).find((k) => k.startsWith('view_account '));
  const runs = [
    // The signer's answer with one bit of S turned: it no longer verifies under the derived key.
    [{ chain: (chain) => {
      const receipt = answerOf(chain);
      const answer = JSON.parse(Buffer.from(receipt.outcome.status.SuccessValue, 'base64').toString('utf8'));
      answer.s.scalar = (BigInt(`0x${answer.s.scalar}`) ^ 1n).toString(16).padStart(64, '0');
      receipt.outcome.status.SuccessValue = Buffer.from(JSON.stringify(answer)).toString('base64');
    } }, new RegExp(`^FAIL C12 \\[replay\\] proofs/g2-v1\\.json execute ${v1.execute}: NEAR testnet tx ${v1.execute}: a returned signature does not verify under the derived key$`)],
    // The signer derives another key for this vault: the same x with the other y.
    [{ chain: (chain) => {
      const xy = base58Decode(JSON.parse(Buffer.from(chain.query[viewKey].result).toString('utf8')).slice('secp256k1:'.length));
      xy[63] ^= 1;
      chain.query[viewKey].result = [...Buffer.from(JSON.stringify(`secp256k1:${base58Encode(xy)}`))];
    } }, new RegExp(`^FAIL C12 \\[replay\\] proofs/g2-v1\\.json execute ${v1.execute}: NEAR testnet tx ${v1.execute}: a returned signature does not verify under the derived key$`)],
    // The contract ran other code at that block: the first run's build.
    [{ chain: (chain) => { chain.query[accountKey].code_hash = g2.contract.code_hash; } }, new RegExp(`^FAIL C12 \\[replay\\] .*${v1.contract} ran code ${g2.contract.code_hash} at the block of NEAR testnet tx ${v1.execute}; proofs/g2-v1\\.json names ${g2v1.contract.code_hash}`)],
    // The block the proposal ran in was four minutes later than it says: the wait was 6:00, not the 10:00 on record.
    [{ chain: (chain) => blockOf(chain, proposedIn(chain), 240_000) }, new RegExp(`^FAIL C01 \\[replay\\] .*NEAR testnet tx ${v1.propose}: the unlock is 360000 ms after its block, and proofs/g2-v1\\.json records a wait of 600000 ms$`)],
    // The execute's block is put a second before the unlock.
    [{ chain: (chain) => {
      const at = BigInt(chain.block[ranIn(chain)].header.timestamp_nanosec) / 1_000_000n;
      blockOf(chain, ranIn(chain), Number(BigInt(g2v1.cosigned.unlock) - 1000n - at));
    } }, new RegExp(`^FAIL C01 \\[replay\\] .*NEAR testnet tx ${v1.execute}: the contract asked the signer \\d+ ms before request ${g2v1.cosigned.request}'s unlock$`)],
    // The proposal went to another contract.
    [{ chain: (chain) => { chain.tx[v1.propose].transaction.receiver_id = g2.contract.account; } }, new RegExp(`^FAIL C01 \\[replay\\] .*NEAR testnet tx ${v1.propose}: not one propose_btc on ${v1.contract} for vault `)],
    // The node holds other bytes under the spend's txid, and another height for the escape.
    [{ bitcoin: (known) => { known.get(v1.spend).hex = g2v1.cosigned.ku_control.raw; } }, new RegExp(`^FAIL C12 \\[replay\\] Mutinynet txid ${v1.spend} \\(.*\\): the API's bytes differ from proofs/$`)],
    [{ bitcoin: (known) => { known.get(v1.escape).height += 1; } }, new RegExp(`^FAIL C04 \\[replay\\] Mutinynet txid ${v1.escape}: mined at ${g2v1.escape.mined_height + 1}, proofs/ say ${g2v1.escape.mined_height}$`)],
    // The key-alone coin was spent by the refused spend itself, or by something the record does not name.
    [{ outspendV1: { spent: true, txid: s2v1.refused_tx.mutinynet_txid_it_would_have_had, vin: 0 } }, new RegExp(`^FAIL C03 \\[replay\\] Mutinynet coin ${s2v1.funding_coin.mutinynet_txid}:\\d+: the refused spend is the one that spent the coin$`)],
    [{ outspendV1: { spent: true, txid: 'cd'.repeat(32), vin: 0 } }, new RegExp(`^FAIL C03 \\[replay\\] Mutinynet coin ${s2v1.funding_coin.mutinynet_txid}:\\d+: spent by Mutinynet txid cdcd.*not the cold-key return proofs/s2-refusal-v1\\.json records`)],
  ];
  for (const [how, want] of runs) {
    const r = await v1Run({ ...how, referee: null });
    const failed = r.lines.filter((l) => l.startsWith('FAIL'));
    assert.equal(failed.length, 1, `${want}\n${r.out}`);
    assert.match(failed[0], want);
    assert.equal(r.code, 1, r.out);
    everyLineHasAClaim(r.lines);
  }
});

test('tier A, the final build\'s run: with no archival answer its NEAR lines say SKIP (network), and none passes', { timeout: 150_000 }, async () => {
  const r = await v1Run({ chain: (chain) => { delete chain.tx[v1.execute]; }, referee: null });
  const lines = v1Lines(r);
  assert.ok(lines.some((l) => l.startsWith(`SKIP C12 [replay] proofs/g2-v1.json execute ${v1.execute}: SKIP (network)`)), r.out);
  assert.ok(lines.some((l) => l.startsWith(`SKIP C12 [replay] ${v1.contract}'s code at the block of that execute, and the wait before it: not read`)), r.out);
  assert.equal(lines.filter((l) => /^PASS (C12|C01) \[replay\] NEAR testnet /.test(l)).length, 0, r.out);
  assert.equal(lines.filter((l) => l.startsWith('FAIL')).length, 0, r.out);
  everyLineHasAClaim(r.lines);
});

// ---------------------------------------------------------------- tier A: the take of the live pages, the phone page's Cancel

const tk = {
  contract: take.contract,
  create: take.vault.create_tx,
  propose: take.thief.propose_tx,
  cancel: take.cancel.tx,
  execute: take.after.execute_after_the_wait_tx,
  coin: `${take.coin.mutinynet_txid}:${take.coin.vout}`,
};
/** The result lines tier A printed under one heading: each take record has its own, so its lines are its own. */
function sectionLines(r, heading) {
  const part = r.out.split('\n== tier A: ').find((s) => s.startsWith(heading));
  return part ? part.split('\n').filter((l) => /^(PASS|FAIL|SKIP|INFO) /.test(l)) : [];
}
function takeLines(r) {
  return sectionLines(r, 'replay of the live take in proofs/chrome-take.json: ');
}
function phoneLines(r) {
  return sectionLines(r, 'replay of the live take in proofs/phone-take.json: ');
}
function filmLines(r) {
  return sectionLines(r, 'replay of the live take in proofs/film-take.json: ');
}
/** The three takes' answers in one fixture, as one archival node would hold them. */
const bothTakes = {
  tx: { ...takeChain.tx, ...phoneChain.tx, ...filmChain.tx },
  block: { ...takeChain.block, ...phoneChain.block, ...filmChain.block },
  query: { ...takeChain.query, ...phoneChain.query, ...filmChain.query },
};
/**
 * The stand-ins for one run of tier A over the takes: Esplora, and one node for archival RPC that knows the two takes
 * alone. `repo` runs a copy of this tree that holds other records.
 */
async function takeRun({ chain = () => {}, bitcoin = () => {}, outspendTake, outspendPhone, outspendFilm, repo } = {}) {
  const api = await esplora({ outspend: { spent: true, txid: s2.coin_return.mutinynet_txid, vin: 0 }, outspendTake, outspendPhone, outspendFilm, change: bitcoin });
  const node = await archival(chain, bothTakes);
  try {
    return await tierA({ esploraUrl: api.url, archivalUrl: node.url, referee: null, repo });
  } finally {
    api.close();
    node.close();
  }
}
const esc = (text) => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

test('proofs/chrome-take.json and its fixture: the take is on the contract deploy/testnet.json names, and the fixture holds its four transactions and no transaction signature', () => {
  const config = JSON.parse(read('deploy/testnet.json'));
  assert.equal(take.contract, config.contract);
  assert.equal(take.origin, config.site_origin);
  assert.deepEqual(Object.keys(takeChain.tx).sort(), [tk.create, tk.propose, tk.cancel, tk.execute].sort());
  assert.equal(Object.keys(takeChain.block).length, 3);
  for (const tx of Object.values(takeChain.tx)) assert.equal('signature' in tx.transaction, false);
  assert.deepEqual(Object.keys(takeChain.bitcoin), [take.coin.mutinynet_txid]);
  // The record's own numbers agree with each other, and the cancel is the method the phone page's Cancel sends.
  assert.equal(take.thief.unlock_ms - take.thief.proposed_at_ms, take.thief.wait_ms);
  assert.equal(take.cancel.method, 'cancel_all_and_rotate');
  assert.equal(take.after.execute_refusal, 'RequestNotFound');
});

test('tier A, the live take: the proposal and its wait, the cancel between the proposal and the unlock with its passkey assertion verified here, the code at its block, the refused execute and the coin are fetched again and pass', { timeout: 150_000 }, async () => {
  const r = await takeRun();
  const lines = takeLines(r);
  assert.equal(lines.filter((l) => !l.startsWith('PASS')).length, 0, r.out);
  assert.equal(lines.length, 5, r.out);
  assert.ok(r.out.includes('\n== tier A: replay of the live take in proofs/chrome-take.json: the phone page\'s Cancel, fetched again from archival RPC\n'), r.out);
  const one = (re) => {
    const hits = lines.filter((l) => re.test(l));
    assert.equal(hits.length, 1, `${re}\n${r.out}`);
    return hits[0];
  };
  one(new RegExp(`^PASS C17 \\[replay\\] NEAR testnet tx ${tk.propose}: propose_btc on ${esc(tk.contract)} made request 0 of vault ${take.vault.id.slice(0, 10)}…, a spend of Mutinynet coin ${take.coin.mutinynet_txid.slice(0, 10)}…:0 to ${take.thief.sent_to}, with its unlock 5:00 after the block it ran in$`));
  const cancelled = one(new RegExp(`^PASS C05 \\[replay\\] NEAR testnet tx ${tk.cancel}: cancel_all_and_rotate on ${esc(tk.contract)} for vault ${take.vault.id.slice(0, 10)}…, sent by \\S+, the relay's account, which made the vault and is the guard it names, in a block \\d+ s after the proposal's and \\d+ s before request 0's unlock, log "undo:rotating grant=0"\\. `));
  // The times are the chain's: the block the cancel ran in, against the proposal's block and the unlock in its log.
  assert.ok(cancelled.includes(' in a block 27 s after the proposal\'s and 272 s before request 0\'s unlock'), cancelled);
  assert.ok(cancelled.includes(`Its WebAuthn assertion passes here the checks the contract makes: the origin is ${take.origin}, the challenge is the digest of this call's own arguments, user present and verified, and the P-256 signature verifies under the passkey in that vault's create_vault, tx ${tk.create}, whose keys hash to the vault id.`), cancelled);
  // No chain says which authenticator it was. The line says where that comes from, and never says a phone.
  assert.ok(cancelled.endsWith('As proofs/chrome-take.json records, the passkey was Chrome\'s virtual authenticator, not a phone\'s'), cancelled);
  const config = JSON.parse(read('deploy/testnet.json'));
  const code = one(/^PASS C05 \[replay\] NEAR testnet account \S+ ran code hash \S+ at the block of that cancel, read from archival RPC: /);
  // The config here is a copy with stand-in endpoints, so the line names it as the config it was given.
  assert.ok(code.includes(`account ${tk.contract} ran code hash ${g2v1.contract.code_hash} `) && code.includes(`: the sha256 ${config.wasm_sha256} that `) && code.endsWith(' names: the final build'), code);
  const refused = one(new RegExp(`^PASS C17 \\[replay\\] NEAR testnet tx ${tk.execute}: an execute of request 0 of that vault, sent by \\S+ in a block \\d+ s after its unlock\\. The contract refused it: Smart contract panicked: RequestNotFound\\. No receipt of it went to the signer ${esc(config.signer)}$`));
  assert.ok(refused.includes(' in a block 291 s after its unlock'), refused);
  one(new RegExp(`^PASS C17 \\[replay\\] Mutinynet coin ${tk.coin}: 2,000 sats at ${take.vault.address}, the take's vault, mined at height ${take.coin.height}\\. Still unspent, read now: the cancelled request moved nothing$`));
  everyLineHasAClaim(r.lines);
});

/** Edits the JSON arguments of a transaction's one function call, in a fixture copy. */
const editArgs = (tx, change, action = 0) => {
  const call = tx.transaction.actions[action].FunctionCall;
  const args = JSON.parse(Buffer.from(call.args, 'base64').toString('utf8'));
  change(args);
  call.args = Buffer.from(JSON.stringify(args)).toString('base64');
};
const shiftBlock = (chain, hash, shiftMs) => {
  const header = chain.block[hash].header;
  header.timestamp_nanosec = String(BigInt(header.timestamp_nanosec) + BigInt(shiftMs) * 1_000_000n);
};
const blockOfLog = (chain, hash, test) => chain.tx[hash].receipts_outcome.find((x) => x.outcome.executor_id === tk.contract && test(x.outcome)).block_hash;

test('tier A, the live take: another signature, origin, call or passkey, a late cancel, another sender, a shorter wait, an execute that ran, ran early or reached the signer, or other code each fail their line', { timeout: 600_000 }, async () => {
  const cancelIn = (chain) => blockOfLog(chain, tk.cancel, (o) => o.logs.includes(take.cancel.log));
  const proposedIn = (chain) => blockOfLog(chain, tk.propose, (o) => o.logs.some((l) => l.startsWith('undo:proposed ')));
  const refusedIn = (chain) => blockOfLog(chain, tk.execute, (o) => Boolean(o.status?.Failure));
  const accountKey = Object.keys(takeChain.query).find((k) => k.startsWith('view_account '));
  const failsHere = `^FAIL C05 \\[replay\\] NEAR testnet tx ${tk.cancel}: its WebAuthn assertion does not pass here the checks the contract makes: `;
  const runs = [
    // One bit of the assertion's signature turned.
    [(chain) => editArgs(chain.tx[tk.cancel], (a) => { a.assertion.signature = `${a.assertion.signature.slice(0, -1)}${a.assertion.signature.endsWith('8') ? '9' : '8'}`; }), new RegExp(`${failsHere}webauthn: bad signature$`)],
    // The same assertion, said to come from another site.
    [(chain) => editArgs(chain.tx[tk.cancel], (a) => {
      const client = JSON.parse(Buffer.from(a.assertion.client_data_json, 'hex').toString('utf8'));
      client.origin = 'https://undo-btc.pages.dev.example';
      a.assertion.client_data_json = Buffer.from(JSON.stringify(client)).toString('hex');
    }), new RegExp(`${failsHere}webauthn: origin not allowed$`)],
    // The assertion carried by a call that installs another key: it was made for this call's arguments and no other's.
    [(chain) => editArgs(chain.tx[tk.cancel], (a) => { a.new_k_s = 'ab'.repeat(32); }), new RegExp(`${failsHere}webauthn: wrong challenge$`)],
    // A user-verified flag cleared in the authenticator data.
    [(chain) => editArgs(chain.tx[tk.cancel], (a) => { a.assertion.authenticator_data = `${a.assertion.authenticator_data.slice(0, 64)}01${a.assertion.authenticator_data.slice(66)}`; }), new RegExp(`${failsHere}webauthn: user not verified$`)],
    // The vault made with another passkey: its keys no longer hash to the vault id.
    [(chain) => editArgs(chain.tx[tk.create], (a) => { a.args.passkey.pubkey = a.args.k_u; }), new RegExp(`^FAIL C05 \\[replay\\] NEAR testnet tx ${tk.create}: the keys in its arguments hash to vault [0-9a-f]{10}…, not ${take.vault.id.slice(0, 10)}…$`)],
    // The cancel's block put a second after the unlock.
    [(chain) => shiftBlock(chain, cancelIn(chain), 273_967), new RegExp(`^FAIL C05 \\[replay\\] NEAR testnet tx ${tk.cancel}: it ran 1000 ms after request 0's unlock, not before it$`)],
    // The cancel sent by another account than the one that made the vault.
    [(chain) => { chain.tx[tk.cancel].transaction.signer_id = 'someone.testnet'; }, new RegExp(`^FAIL C05 \\[replay\\] NEAR testnet tx ${tk.cancel}: sent by someone\\.testnet, not by \\S+, the relay's account, which made the vault$`)],
    // The cancel went to another contract.
    [(chain) => { chain.tx[tk.cancel].transaction.receiver_id = g2.contract.account; }, new RegExp(`^FAIL C05 \\[replay\\] NEAR testnet tx ${tk.cancel}: sent to ${esc(g2.contract.account)}, not ${esc(tk.contract)}$`)],
    // The proposal's block a minute later than it says: the wait was 4:00, not the 5:00 on record.
    [(chain) => shiftBlock(chain, proposedIn(chain), 60_000), new RegExp(`^FAIL C17 \\[replay\\] NEAR testnet tx ${tk.propose}: the unlock is 240000 ms after its block, and proofs/chrome-take\\.json records a wait of 300000 ms$`)],
    // The proposal asks for another coin.
    [(chain) => editArgs(chain.tx[tk.propose], (a) => { a.inputs[0].vout = 1; }), new RegExp(`^FAIL C17 \\[replay\\] NEAR testnet tx ${tk.propose}: it does not ask to spend the take's coin ${tk.coin} and nothing else$`)],
    // The execute went through.
    [(chain) => {
      const tx = chain.tx[tk.execute];
      tx.status = { SuccessValue: '' };
      for (const x of tx.receipts_outcome) x.outcome.status = { SuccessValue: '' };
    }, new RegExp(`^FAIL C17 \\[replay\\] NEAR testnet tx ${tk.execute}: the contract did not refuse it$`)],
    // The execute was refused for being early, which says nothing of a cancel.
    [(chain) => { chain.tx[tk.execute] = JSON.parse(JSON.stringify(chain.tx[tk.execute]).replaceAll('RequestNotFound', 'TooEarly')); }, new RegExp(`^FAIL C17 \\[replay\\] NEAR testnet tx ${tk.execute}: refused, but not with "RequestNotFound": Smart contract panicked: TooEarly$`)],
    // The execute's block put a second before the unlock.
    [(chain) => shiftBlock(chain, refusedIn(chain), -292_206), new RegExp(`^FAIL C17 \\[replay\\] NEAR testnet tx ${tk.execute}: it ran 1000 ms before request 0's unlock, so it does not show a refusal after the wait$`)],
    // A receipt of the execute at the signer.
    [(chain) => { chain.tx[tk.execute].receipts_outcome.push({ block_hash: refusedIn(chain), id: 'x', outcome: { executor_id: 'v1.signer-prod.testnet', gas_burnt: 0, logs: [], receipt_ids: [], status: { SuccessValue: '' }, tokens_burnt: '0' } }); }, new RegExp(`^FAIL C17 \\[replay\\] NEAR testnet tx ${tk.execute}: a receipt of it went to the signer v1\\.signer-prod\\.testnet$`)],
    // The contract ran other code at the block of the cancel: the first run's build.
    [(chain) => { chain.query[accountKey].code_hash = g2.contract.code_hash; }, new RegExp(`^FAIL C05 \\[replay\\] ${esc(tk.contract)} ran code ${g2.contract.code_hash} at the block of NEAR testnet tx ${tk.cancel}, not ${g2v1.contract.code_hash}, `)],
  ];
  for (const [chain, want] of runs) {
    const r = await takeRun({ chain });
    const failed = r.lines.filter((l) => l.startsWith('FAIL'));
    assert.equal(failed.length, 1, `${want}\n${r.out}`);
    assert.match(failed[0], want);
    assert.equal(r.code, 1, r.out);
    // A cancel that did not pass leaves the code at its block unread, and says so: never a PASS for it.
    if (failed[0].includes(tk.cancel) && !failed[0].includes('ran code')) assert.ok(r.lines.some((l) => l === `SKIP C05 [replay] ${tk.contract}'s code at the block of that cancel: not read, since the cancel did not pass`), r.out);
    if (failed[0].includes(tk.create)) assert.equal(takeLines(r).filter((l) => l.startsWith('PASS C05')).length, 0, r.out);
    assertRestsOn(r, failed[0]);
    everyLineHasAClaim(r.lines);
  }
});

/**
 * What rests on a line that failed is not a pass, and says so. The cancel, the refused execute and the coin's tie to a
 * cancelled request rest on the proposal; the code at the cancel's block and the coin's tie rest on the cancel.
 */
function assertRestsOn(r, failed) {
  const lines = takeLines(r);
  const coinSkip = `SKIP C17 [replay] Mutinynet coin ${tk.coin}: not a pass, since the cancel above did not pass, and this line rests on it. Read from the Mutinynet API: 2,000 sats at ${take.vault.address}, the take's vault, mined at height ${take.coin.height}, still unspent, read now`;
  // The transaction a FAIL line is about is the one it starts with.
  const about = (hash) => new RegExp(`^FAIL \\S+ \\[replay\\] (NEAR testnet tx|proofs/chrome-take\\.json \\w+) ${hash}:`).test(failed);
  if (about(tk.propose)) {
    assert.deepEqual(lines.filter((l) => l.startsWith('PASS')), [], r.out);
    assert.ok(lines.includes(`SKIP C05 [replay] proofs/chrome-take.json cancel ${tk.cancel}: not checked, since the proposal above did not pass, and this line rests on it: the request it cancels, made before it, and that request's unlock, after it`), r.out);
    assert.ok(lines.includes(`SKIP C17 [replay] proofs/chrome-take.json execute ${tk.execute}: not checked, since the proposal above did not pass, and this line rests on it: the request this execute names, and its unlock`), r.out);
    assert.ok(lines.includes(`SKIP C05 [replay] ${tk.contract}'s code at the block of that cancel: not read, since the cancel did not pass`), r.out);
    assert.ok(lines.includes(coinSkip), r.out);
  }
  if (about(tk.cancel) || about(tk.create)) {
    assert.ok(lines.includes(coinSkip), r.out);
    assert.equal(lines.filter((l) => l.startsWith(`PASS C17 [replay] Mutinynet coin `)).length, 0, r.out);
  }
}

test('tier A, the live take: a proposal, a cancel or a create_vault that failed after its log, a proposal that returned another request, a cancel before the proposal, and a vault passkey for another site each fail their line, and what rests on them is not a pass', { timeout: 600_000 }, async () => {
  const cancelIn = (chain) => blockOfLog(chain, tk.cancel, (o) => o.logs.includes(take.cancel.log));
  const proposedIn = (chain) => blockOfLog(chain, tk.propose, (o) => o.logs.some((l) => l.startsWith('undo:proposed ')));
  /** The transaction failed in the contract's receipt, after the log it wrote there: NEAR keeps the logs of a failed receipt. */
  const failedAfterItsLog = (hash, words) => (chain) => {
    const tx = chain.tx[hash];
    tx.status = { Failure: { ActionError: { index: 0, kind: { FunctionCallError: { ExecutionError: words } } } } };
    const receipt = tx.receipts_outcome.find((x) => x.outcome.executor_id === tk.contract);
    assert.ok(receipt.outcome.logs.length > 0, 'the log stays');
    receipt.outcome.status = tx.status;
  };
  const blockAt = (chain, hash, ms) => { chain.block[hash].header.timestamp_nanosec = String(BigInt(ms) * 1_000_000n); };
  const unlock = take.thief.unlock_ms;
  const runs = [
    // propose_btc logs, then the state is written on exit: a failure there (gas, storage) rolls the request back and
    // keeps the log. The line reads the outcome, not the log alone.
    [failedAfterItsLog(tk.propose, 'Exceeded the prepaid gas.'), new RegExp(`^FAIL C17 \\[replay\\] NEAR testnet tx ${tk.propose}: it did not succeed: Exceeded the prepaid gas\\.$`)],
    // It succeeded, but the request it made is another one than the record's.
    [(chain) => {
      const tx = chain.tx[tk.propose];
      tx.status = { SuccessValue: Buffer.from('1').toString('base64') };
      tx.receipts_outcome.find((x) => x.outcome.executor_id === tk.contract).outcome.status = tx.status;
    }, new RegExp(`^FAIL C17 \\[replay\\] NEAR testnet tx ${tk.propose}: it returned 1, not request 0$`)],
    // The cancel failed after it logged: it killed nothing.
    [failedAfterItsLog(tk.cancel, 'Smart contract panicked: x'), new RegExp(`^FAIL C05 \\[replay\\] NEAR testnet tx ${tk.cancel}: it did not succeed: Smart contract panicked: x$`)],
    // The vault's create_vault failed after it logged: the line's "which made the vault" would not hold.
    [failedAfterItsLog(tk.create, 'Smart contract panicked: x'), new RegExp(`^FAIL C05 \\[replay\\] NEAR testnet tx ${tk.create}: it did not succeed: Smart contract panicked: x$`)],
    // The cancel's block put 100 s before the proposal's, so before the request it is said to have cancelled existed.
    [(chain) => blockAt(chain, cancelIn(chain), unlock - 400_000), new RegExp(`^FAIL C05 \\[replay\\] NEAR testnet tx ${tk.cancel}: it ran 100000 ms before the proposal of request 0, tx ${tk.propose}, not after it$`)],
    // In a block at the proposal's own time: not after it.
    [(chain) => blockAt(chain, cancelIn(chain), Number(BigInt(chain.block[proposedIn(chain)].header.timestamp_nanosec) / 1_000_000n)), new RegExp(`^FAIL C05 \\[replay\\] NEAR testnet tx ${tk.cancel}: it ran 0 ms before the proposal of request 0, tx ${tk.propose}, not after it$`)],
    // The vault's passkey is for another site. Its id does not cover the site, so this line is the one that says so.
    [(chain) => editArgs(chain.tx[tk.create], (a) => { a.args.passkey.rp_id_hash = toHex(sha256(utf8('undo-btc.pages.dev.example'))); }), new RegExp(`^FAIL C05 \\[replay\\] NEAR testnet tx ${tk.create}: the vault's passkey is for another site than ${esc(take.origin)}$`)],
  ];
  for (const [chain, want] of runs) {
    const r = await takeRun({ chain });
    const failed = r.lines.filter((l) => l.startsWith('FAIL'));
    assert.equal(failed.length, 1, `${want}\n${r.out}`);
    assert.match(failed[0], want);
    assert.equal(r.code, 1, r.out);
    assertRestsOn(r, failed[0]);
    everyLineHasAClaim(r.lines);
  }
});

test('tier A, the live take\'s coin: unspent passes; spent by the cold key\'s branch says so and passes; spent by a co-signed spend to the thief\'s address, other bytes or another height fail', { timeout: 600_000 }, async () => {
  const coin = { txid: take.coin.mutinynet_txid, vout: take.coin.vout };
  const thief = addressToSpk('mutinynet', take.thief.sent_to);
  const elsewhere = addressToSpk('mutinynet', take.vault.address);
  const script = new Uint8Array(111).fill(7);
  const sig = new Uint8Array(72).fill(9);
  /** A spend of the take's coin with this witness, paying this script: only its shape is read, so its signatures are filler. */
  const spend = (witness, to, sequence = 0xfffffffd) => {
    const tx = makeTx([coin], sequence, [{ value: 1702, spk: to }]);
    tx.inputs[0].witness = witness;
    return { txid: bitcoinTxid(tx), hex: toHex(serialize(tx)) };
  };
  const thiefSpend = spend([sig, sig, Uint8Array.of(1), script], thief);
  const coldSpend = spend([sig, new Uint8Array(0), script], elsewhere, 6);
  const otherSpend = spend([sig, sig, Uint8Array.of(1), script], elsewhere);
  const oddSpend = spend([sig, script], elsewhere);
  const held = `Mutinynet coin ${tk.coin}: 2,000 sats at ${take.vault.address}, the take's vault, mined at height ${take.coin.height}\\. `;
  const knows = (s) => (known) => known.set(s.txid, { hex: s.hex, height: take.coin.height + 10 });
  const cases = [
    [{ outspendTake: { spent: true, txid: thiefSpend.txid, vin: 0 }, bitcoin: knows(thiefSpend) }, new RegExp(`^FAIL C17 \\[replay\\] ${held}Spent by Mutinynet txid ${thiefSpend.txid}, a co-signed spend that pays ${take.thief.sent_to}, the address of the cancelled request$`), 1],
    [{ outspendTake: { spent: true, txid: coldSpend.txid, vin: 0 }, bitcoin: knows(coldSpend) }, new RegExp(`^PASS C17 \\[replay\\] ${held}Spent since by Mutinynet txid ${coldSpend.txid} through the script's cold-key branch, with one signature and none from MPC: not by the cancelled request$`), 0],
    [{ outspendTake: { spent: true, txid: otherSpend.txid, vin: 0 }, bitcoin: knows(otherSpend) }, new RegExp(`^PASS C17 \\[replay\\] ${held}Spent since by Mutinynet txid ${otherSpend.txid}, a co-signed spend that does not pay ${take.thief.sent_to}: not the cancelled request's spend$`), 0],
    [{ outspendTake: { spent: true, txid: oddSpend.txid, vin: 0 }, bitcoin: knows(oddSpend) }, new RegExp(`^FAIL C17 \\[replay\\] ${held}Spent by Mutinynet txid ${oddSpend.txid}, with a witness of neither branch of the vault's script$`), 1],
    // The API names a spender whose bytes spend another coin.
    [{ outspendTake: { spent: true, txid: g2v1.escape.txid, vin: 0 } }, new RegExp(`^FAIL C17 \\[replay\\] Mutinynet coin ${tk.coin}: the API names Mutinynet txid ${g2v1.escape.txid} as its spender, and the bytes it gives do not spend this coin$`), 1],
    // The API gives another transaction's bytes for the coin, or another height.
    [{ bitcoin: (known) => { known.get(take.coin.mutinynet_txid).hex = g2v1.cosigned.raw; } }, new RegExp(`^FAIL C17 \\[replay\\] Mutinynet coin ${tk.coin}: the API's bytes are another transaction's$`), 1],
    [{ bitcoin: (known) => { known.get(take.coin.mutinynet_txid).height += 1; } }, new RegExp(`^FAIL C17 \\[replay\\] Mutinynet coin ${tk.coin}: mined at ${take.coin.height + 1}, proofs/chrome-take\\.json says ${take.coin.height}$`), 1],
  ];
  for (const [how, want, code] of cases) {
    const r = await takeRun(how);
    const lines = r.lines.filter((l) => l.includes(`Mutinynet coin ${tk.coin}`));
    assert.equal(lines.length, 1, `${want}\n${r.out}`);
    assert.match(lines[0], want);
    assert.equal(r.lines.filter((l) => l.startsWith('FAIL')).length, code, r.out);
    assert.equal(r.code, code, r.out);
    everyLineHasAClaim(r.lines);
  }
});

test('tier A, the live take: with no archival answer its NEAR lines say SKIP (network) and are counted, none passes, and the coin is read but not passed, since it rests on them; a spend to the thief still fails', { timeout: 300_000 }, async () => {
  const none = await takeRun({ chain: (chain) => { delete chain.tx[tk.propose]; } });
  let lines = takeLines(none);
  assert.ok(lines.some((l) => l.startsWith(`SKIP C17 [replay] proofs/chrome-take.json proposal ${tk.propose}: SKIP (network)`)), none.out);
  assert.ok(lines.some((l) => l.startsWith('SKIP C17 [replay] 3 more NEAR testnet lines of the live take: SKIP (network), the archival RPC did not answer')), none.out);
  // The coin's line says what the API answered, and not that a cancelled request moved nothing: nothing checked a cancel.
  const facts = `2,000 sats at ${take.vault.address}, the take's vault, mined at height ${take.coin.height}`;
  const untied = `SKIP C17 [replay] Mutinynet coin ${tk.coin}: SKIP (network): the archival RPC did not answer, so the proposal and the cancel this line rests on were not checked. Read from the Mutinynet API: ${facts}`;
  assert.ok(lines.includes(`${untied}, still unspent, read now`), none.out);
  assert.deepEqual(lines.filter((l) => l.startsWith('PASS')), [], none.out);
  assert.equal(lines.filter((l) => l.includes('cancelled request')).length, 0, none.out);
  assert.equal(none.lines.filter((l) => l.startsWith('FAIL')).length, 0, none.out);
  // The same with the coin spent: by the cold key's branch it is what was read, not a pass; to the thief's address by a
  // co-signed spend it fails, with or without a cancel to tie it to.
  const sig = new Uint8Array(72).fill(9);
  const script = new Uint8Array(111).fill(7);
  const spend = (witness, to, sequence) => {
    const tx = makeTx([{ txid: take.coin.mutinynet_txid, vout: take.coin.vout }], sequence, [{ value: 1702, spk: to }]);
    tx.inputs[0].witness = witness;
    return { txid: bitcoinTxid(tx), hex: toHex(serialize(tx)) };
  };
  const cold = spend([sig, new Uint8Array(0), script], addressToSpk('mutinynet', take.vault.address), 6);
  const thief = spend([sig, sig, Uint8Array.of(1), script], addressToSpk('mutinynet', take.thief.sent_to), 0xfffffffd);
  const silent = (chain) => { delete chain.tx[tk.propose]; };
  const knows = (s) => (known) => known.set(s.txid, { hex: s.hex, height: take.coin.height + 10 });
  const coldRun = await takeRun({ chain: silent, outspendTake: { spent: true, txid: cold.txid, vin: 0 }, bitcoin: knows(cold) });
  assert.ok(takeLines(coldRun).includes(`${untied}, spent since by Mutinynet txid ${cold.txid} through the script's cold-key branch, with one signature and none from MPC`), coldRun.out);
  assert.deepEqual(takeLines(coldRun).filter((l) => l.startsWith('PASS') || l.startsWith('FAIL')), [], coldRun.out);
  const thiefRun = await takeRun({ chain: silent, outspendTake: { spent: true, txid: thief.txid, vin: 0 }, bitcoin: knows(thief) });
  assert.deepEqual(thiefRun.lines.filter((l) => l.startsWith('FAIL')), [`FAIL C17 [replay] Mutinynet coin ${tk.coin}: ${facts}. Spent by Mutinynet txid ${thief.txid}, a co-signed spend that pays ${take.thief.sent_to}, the address of the thief tab's request in proofs/chrome-take.json`], thiefRun.out);
  assert.equal(thiefRun.code, 1, thiefRun.out);
  everyLineHasAClaim(coldRun.lines);
  everyLineHasAClaim(thiefRun.lines);
  // The vault's create_vault unanswered: the cancel cannot be checked, so it does not pass, and neither does what follows.
  const part = await takeRun({ chain: (chain) => { delete chain.tx[tk.create]; } });
  lines = takeLines(part);
  assert.equal(lines.filter((l) => l.startsWith('PASS C17 [replay] NEAR testnet tx ')).length, 1, part.out);
  assert.ok(lines.some((l) => l.startsWith(`SKIP C05 [replay] proofs/chrome-take.json cancel ${tk.cancel}: SKIP (network)`)), part.out);
  assert.ok(lines.some((l) => l.startsWith('SKIP C17 [replay] 2 more NEAR testnet lines of the live take: SKIP (network)')), part.out);
  assert.equal(lines.filter((l) => l.startsWith('PASS C05')).length, 0, part.out);
  // The proposal passed here, so the line names only the cancel it could not check.
  const untiedCancel = untied.replace('so the proposal and the cancel this line rests on were not checked', 'so the cancel this line rests on was not checked');
  assert.notEqual(untiedCancel, untied);
  assert.ok(lines.includes(`${untiedCancel}, still unspent, read now`), part.out);
  assert.ok(!lines.includes(`${untied}, still unspent, read now`), part.out);
  assert.equal(lines.filter((l) => l.startsWith('PASS C17 [replay] Mutinynet coin ')).length, 0, part.out);
  assert.equal(part.lines.filter((l) => l.startsWith('FAIL')).length, 0, part.out);
  everyLineHasAClaim(none.lines);
  everyLineHasAClaim(part.lines);
});

// ---------------------------------------------------------------- tier A: the real phone's run, a take with no execute after its wait

const pk = {
  contract: phone.contract,
  create: phone.vault.create_tx,
  propose: phone.thief.propose_tx,
  cancel: phone.cancel.tx,
  coin: `${phone.coin.mutinynet_txid}:${phone.coin.vout}`,
};
/** The flags and the count in a WebAuthn assertion's authenticator data, read here apart from tier A's own reading. */
const flagsOf = (hex) => {
  const ad = Buffer.from(hex, 'hex');
  return { authenticator_data_bytes: ad.length, user_present: Boolean(ad[32] & 1), user_verified: Boolean(ad[32] & 4), backup_eligible: Boolean(ad[32] & 8), backed_up: Boolean(ad[32] & 16), sign_count: ad.readUInt32BE(33) };
};
const phoneCancelArgs = () => JSON.parse(Buffer.from(phoneChain.tx[pk.cancel].transaction.actions[0].FunctionCall.args, 'base64').toString('utf8'));
const phoneBlockMs = (hash, test) => Number(BigInt(phoneChain.block[phoneChain.tx[hash].receipts_outcome.find((x) => x.outcome.executor_id === phone.contract && test(x.outcome)).block_hash].header.timestamp_nanosec) / 1_000_000n);
const PHONE_WHO = 'Which authenticator held the passkey, no chain says: proofs/phone-take.json reports a real device, iPhone 13 Pro Max on iOS 27.2.1 in Safari, as its author reported it, not as any chain shows it. Its authenticator data, as read here: user present, user verified, backup eligible, backed up, sign count 0. A backed-up passkey can be synced to other devices, so these flags do not name one device either';

/** A copy of what tier A reads from this tree, with one record in proofs/ changed. */
function treeWith(file, change) {
  const copy = mkdtempSync(join(work, 'tree-'));
  for (const dir of ['tools/verify', 'tools/lib', 'tools/vendor', 'site/lib', 'contracts/undo/src', 'proofs']) cpSync(join(REPO, dir), join(copy, dir), { recursive: true });
  const path = join(copy, 'proofs', file);
  const record = JSON.parse(readFileSync(path, 'utf8'));
  change(record);
  writeFileSync(path, JSON.stringify(record, null, 2));
  return copy;
}

test('proofs/phone-take.json and its fixture: a real device\'s take on the contract deploy/testnet.json names, with no execute after its wait, the assertion\'s flags as the chain has them, and no key', () => {
  const config = JSON.parse(read('deploy/testnet.json'));
  assert.equal(phone.schema, 'undo-phone-take-v1');
  assert.equal(phone.contract, config.contract);
  assert.equal(phone.origin, config.site_origin);
  assert.deepEqual(phone.labels, ['live-testnet', 'live-mutinynet', 'real device']);
  assert.notEqual(phone.vault.id, take.vault.id, 'another vault than the film\'s take');
  // No execute after the wait: none was sent in this run, so the record names none.
  assert.equal(phone.after, undefined);
  assert.equal(JSON.stringify(phone).includes('execute_after_the_wait_tx'), false);
  // The fixture: the three transactions, the two blocks tier A reads, the account at the cancel, the coin; no signature.
  assert.deepEqual(Object.keys(phoneChain.tx).sort(), [pk.create, pk.propose, pk.cancel].sort());
  assert.equal(Object.keys(phoneChain.block).length, 2);
  for (const tx of Object.values(phoneChain.tx)) assert.equal('signature' in tx.transaction, false);
  assert.deepEqual(Object.keys(phoneChain.bitcoin), [phone.coin.mutinynet_txid]);
  assert.equal(phoneChain.bitcoin[phone.coin.mutinynet_txid].status.block_height, phone.coin.height);
  // The record's numbers are the chain's: the wait, and the cancel's block against the proposal's and the unlock.
  assert.equal(phone.thief.unlock_ms - phone.thief.proposed_at_ms, phone.thief.wait_ms);
  const proposed = phoneBlockMs(pk.propose, (o) => o.logs.some((l) => l.startsWith('undo:proposed ')));
  const cancelled = phoneBlockMs(pk.cancel, (o) => o.logs.includes(phone.cancel.log));
  assert.equal(proposed, phone.thief.proposed_at_ms);
  assert.equal(cancelled - proposed, phone.cancel.block_after_the_proposal_ms);
  assert.equal(phone.thief.unlock_ms - cancelled, phone.cancel.block_before_the_unlock_ms);
  assert.equal(phone.cancel.method, 'cancel_all_and_rotate');
  // The flags the record says were read are the ones in the cancel's own authenticator data.
  const args = phoneCancelArgs();
  const flags = flagsOf(args.assertion.authenticator_data);
  for (const [k, v] of Object.entries(flags)) assert.equal(phone.assertion_as_read[k], v, k);
  const client = JSON.parse(Buffer.from(args.assertion.client_data_json, 'hex').toString('utf8'));
  assert.deepEqual([client.type, client.origin, client.crossOrigin], [phone.assertion_as_read.type, phone.assertion_as_read.origin, phone.assertion_as_read.cross_origin]);
  // What no chain holds is the author's report, and the record says so: the device, and the browser, as reported.
  for (const k of ['device', 'os', 'by', 'browser', 'browser_by', 'tabs']) assert.equal(typeof phone.device_as_reported[k], 'string', k);
  // How the phone verified its user, the record names no way: the assertion's flags say only that the authenticator did
  // (user verified), not how, and the record adds no way of its own.
  assert.equal('user_verification' in phone.device_as_reported, false);
  assert.doesNotMatch(JSON.stringify(phone), /Face ID|face_id|Touch ID/);
  assert.match(phone.device_as_reported.what_the_chain_says_of_it, /user verified says the authenticator verified the user, not how/);
  assert.match(phone.what, /device_as_reported is the author's report, not the chain's/);
  assert.match(phone.what, /The passkey's credential id is left out: no chain holds it\./);
  // The browser is the author's report too: Safari, with the phone page and the thief tab as two tabs on the one iPhone,
  // the README's one-device path. No chain says which browser it was, and the record names no other.
  assert.equal(phone.device_as_reported.browser, 'Safari');
  assert.match(phone.device_as_reported.browser_by, /^the author, in chat on 2026-11-12, /);
  assert.match(phone.device_as_reported.tabs, /^the phone page \/p\/ and the thief tab \/t\/ both ran on that one iPhone, as two Safari tabs, not on a Mac: the README's "On one device" path$/);
  assert.match(phone.what, /Which device and browser held the passkey, and where the thief tab ran, no chain shows: device_as_reported is the author's report, not the chain's: one iPhone, with the phone page and the thief tab as two Safari tabs on it\./);
  assert.doesNotMatch(JSON.stringify(phone.device_as_reported), /Chrome/);
  assert.doesNotMatch(JSON.stringify(phone.device_as_reported), /not recorded/);
  // No key: every long hex string in the record is the vault id or the coin's txid.
  const long = [...JSON.stringify(phone).matchAll(/[0-9a-f]{40,}/g)].map((m) => m[0]);
  assert.deepEqual([...new Set(long)].sort(), [phone.vault.id, phone.coin.mutinynet_txid].sort());
});

test('tier A, the real phone\'s run: the proposal and its wait, the cancel with its passkey assertion verified here and its flags as read, the code at its block and the coin pass; there is no execute line, and the film\'s take is unchanged', { timeout: 150_000 }, async () => {
  const r = await takeRun();
  const lines = phoneLines(r);
  assert.equal(lines.filter((l) => !l.startsWith('PASS')).length, 0, r.out);
  assert.equal(lines.length, 4, r.out);
  assert.ok(r.out.includes('\n== tier A: replay of the live take in proofs/phone-take.json: the phone page\'s Cancel, fetched again from archival RPC\n'), r.out);
  assert.ok(r.out.indexOf('proofs/film-take.json: the phone page') < r.out.indexOf('proofs/chrome-take.json: the phone page'), 'the film\'s take first');
  assert.ok(r.out.indexOf('proofs/chrome-take.json: the phone page') < r.out.indexOf('proofs/phone-take.json: the phone page'), 'then the others, by name');
  const one = (re) => {
    const hits = lines.filter((l) => re.test(l));
    assert.equal(hits.length, 1, `${re}\n${r.out}`);
    return hits[0];
  };
  one(new RegExp(`^PASS C17 \\[replay\\] NEAR testnet tx ${pk.propose}: propose_btc on ${esc(pk.contract)} made request 0 of vault ${phone.vault.id.slice(0, 10)}…, a spend of Mutinynet coin ${phone.coin.mutinynet_txid.slice(0, 10)}…:0 to ${phone.thief.sent_to}, with its unlock 5:00 after the block it ran in$`));
  const cancelled = one(new RegExp(`^PASS C05 \\[replay\\] NEAR testnet tx ${pk.cancel}: cancel_all_and_rotate on ${esc(pk.contract)} for vault ${phone.vault.id.slice(0, 10)}…, sent by \\S+, the relay's account, which made the vault and is the guard it names, in a block \\d+ s after the proposal's and \\d+ s before request 0's unlock, log "undo:rotating grant=0"\\. `));
  assert.ok(cancelled.includes(' in a block 20 s after the proposal\'s and 279 s before request 0\'s unlock'), cancelled);
  assert.ok(cancelled.includes(`Its WebAuthn assertion passes here the checks the contract makes: the origin is ${phone.origin}, the challenge is the digest of this call's own arguments, user present and verified, and the P-256 signature verifies under the passkey in that vault's create_vault, tx ${pk.create}, whose keys hash to the vault id.`), cancelled);
  // Which device it was is the record's report, said as such; the flags are the chain's, read here.
  assert.ok(cancelled.endsWith(` ${PHONE_WHO}`), cancelled);
  assert.doesNotMatch(cancelled, /virtual authenticator/);
  one(new RegExp(`^PASS C05 \\[replay\\] NEAR testnet account ${esc(pk.contract)} ran code hash ${g2v1.contract.code_hash} at the block of that cancel, read from archival RPC: `));
  one(new RegExp(`^PASS C17 \\[replay\\] Mutinynet coin ${pk.coin}: 2,000 sats at ${phone.vault.address}, the take's vault, mined at height ${phone.coin.height}\\. Still unspent, read now: the cancelled request moved nothing$`));
  // No execute after the wait in this record, so no line about one.
  assert.equal(lines.filter((l) => /execute/i.test(l)).length, 0, r.out);
  // The earlier film's take prints what it printed before, five lines, all PASS, and its cancel line ends as before.
  const film = takeLines(r);
  assert.equal(film.length, 5, r.out);
  assert.equal(film.filter((l) => !l.startsWith('PASS')).length, 0, r.out);
  assert.ok(film.some((l) => l.endsWith('As proofs/chrome-take.json records, the passkey was Chrome\'s virtual authenticator, not a phone\'s')), r.out);
  assert.equal(r.lines.filter((l) => l.startsWith('FAIL')).length, 0, r.out);
  everyLineHasAClaim(r.lines);
});

// ---------------------------------------------------------------- tier A: the take the film is cut from, a real phone and a second device

const fk = {
  contract: filmTake.contract,
  create: filmTake.vault.create_tx,
  propose: filmTake.thief.propose_tx,
  cancel: filmTake.cancel.tx,
  coin: `${filmTake.coin.mutinynet_txid}:${filmTake.coin.vout}`,
};
const filmBlockMs = (hash, test) => Number(BigInt(filmChain.block[filmChain.tx[hash].receipts_outcome.find((x) => x.outcome.executor_id === filmTake.contract && test(x.outcome)).block_hash].header.timestamp_nanosec) / 1_000_000n);
const FILM_WHO = 'Which authenticator held the passkey, no chain says: proofs/film-take.json reports a real device, an iPhone on iOS in Safari, as its author reported it, not as any chain shows it. Its authenticator data, as read here: user present, user verified, backup eligible, backed up, sign count 0. A backed-up passkey can be synced to other devices, so these flags do not name one device either';

test('proofs/film-take.json and its fixture: the film\'s take is a real device\'s on the contract deploy/testnet.json names, the thief tab on a second device, no execute after its wait, the assertion\'s flags and the times as the chain has them, the film\'s own bytes, and no key', () => {
  const config = JSON.parse(read('deploy/testnet.json'));
  assert.equal(filmTake.schema, 'undo-film-take-v2');
  assert.equal(filmTake.contract, config.contract);
  assert.equal(filmTake.origin, config.site_origin);
  assert.ok(filmTake.labels.includes('real device') && !filmTake.labels.includes('virtual authenticator'));
  assert.ok(![take.vault.id, phone.vault.id].includes(filmTake.vault.id), 'another vault than the other takes');
  // No execute after the wait: none is recorded, so tier A has no line for one.
  assert.equal(JSON.stringify(filmTake).includes('execute_after_the_wait_tx'), false);
  assert.equal('execute_refusal' in filmTake.after, false);
  // The fixture: the three transactions, the two blocks tier A reads, the account at the cancel, the coin; no signature.
  assert.deepEqual(Object.keys(filmChain.tx).sort(), [fk.create, fk.propose, fk.cancel].sort());
  assert.equal(Object.keys(filmChain.block).length, 2);
  for (const tx of Object.values(filmChain.tx)) assert.equal('signature' in tx.transaction, false);
  assert.deepEqual(Object.keys(filmChain.bitcoin), [filmTake.coin.mutinynet_txid]);
  assert.equal(filmChain.bitcoin[filmTake.coin.mutinynet_txid].status.block_height, filmTake.coin.height);
  // The record's numbers are the chain's: the wait, and the cancel's block against the proposal's and the unlock.
  assert.equal(filmTake.thief.unlock_ms - filmTake.thief.proposed_at_ms, filmTake.thief.wait_ms);
  const proposed = filmBlockMs(fk.propose, (o) => o.logs.some((l) => l.startsWith('undo:proposed ')));
  const cancelled = filmBlockMs(fk.cancel, (o) => o.logs.includes(filmTake.cancel.log));
  assert.equal(proposed, filmTake.thief.proposed_at_ms);
  assert.equal(cancelled - proposed, filmTake.cancel.block_after_the_proposal_ms);
  assert.equal(filmTake.thief.unlock_ms - cancelled, filmTake.cancel.block_before_the_unlock_ms);
  assert.equal(Math.floor(filmTake.cancel.block_before_the_unlock_ms / 1000), 271);
  assert.equal(filmTake.cancel.method, 'cancel_all_and_rotate');
  // The flags the record says were read are the ones in the cancel's own authenticator data: 0x1d, user verified.
  const args = JSON.parse(Buffer.from(filmChain.tx[fk.cancel].transaction.actions[0].FunctionCall.args, 'base64').toString('utf8'));
  const flags = flagsOf(args.assertion.authenticator_data);
  for (const [k, v] of Object.entries(flags)) assert.equal(filmTake.assertion_as_read[k], v, k);
  assert.equal(Buffer.from(args.assertion.authenticator_data, 'hex')[32], 0x1d);
  assert.equal(filmTake.assertion_as_read.flags_byte, '0x1d');
  const client = JSON.parse(Buffer.from(args.assertion.client_data_json, 'hex').toString('utf8'));
  assert.deepEqual([client.type, client.origin, client.crossOrigin], [filmTake.assertion_as_read.type, filmTake.assertion_as_read.origin, filmTake.assertion_as_read.cross_origin]);
  // What no chain holds is the author's report, and the record says so: the device, the browser and how it verified
  // its user. The chain says user verified, not how.
  for (const k of ['device', 'os', 'by', 'browser', 'tabs', 'user_verification', 'what_the_chain_says_of_it']) assert.equal(typeof filmTake.device_as_reported[k], 'string', k);
  assert.match(filmTake.device_as_reported.by, /^the author, /);
  assert.deepEqual([filmTake.device_as_reported.device, filmTake.device_as_reported.browser, filmTake.device_as_reported.user_verification], ['an iPhone', 'Safari', 'Face ID']);
  assert.match(filmTake.device_as_reported.what_the_chain_says_of_it, /user verified says the authenticator verified the user, not how/);
  assert.match(filmTake.what, /device_as_reported is the author's report, not the chain's: an iPhone, in Safari, with Face ID\./);
  // The thief tab ran on a second device: headless Chrome on a Mac, and the record says so in its own words.
  assert.match(filmTake.device_as_reported.tabs, /the thief tab \/t\/ ran in headless Chrome on a Mac, a second device/);
  assert.equal(filmTake.thief_cam.method, 'headless Chrome on a Mac, clicked by the capture script');
  // The film is this tree's file, and its corner clock is said with the chain's earlier block beside it.
  assert.equal(filmTake.film.file, 'site/pages/film/undo-for-bitcoin.mp4');
  assert.equal(toHex(sha256(readFileSync(join(REPO, filmTake.film.file)))), filmTake.film.sha256);
  assert.match(filmTake.film.chip, /freezes on "Cancelled at 0:41" \(41\.209 s, the phone page's first CANCELLED frame; the cancel's block came earlier, at T 35\.35 s\)/);
  // No key, no draft and no private path: every long hex string is the vault id, the coin, a recording's or the film's
  // hash, or a txid in the node's own words.
  const long = [...JSON.stringify(filmTake).matchAll(/[0-9a-f]{40,}/g)].map((m) => m[0]);
  const named = [filmTake.vault.id, filmTake.coin.mutinynet_txid, filmTake.film.sha256, filmTake.thief_cam.video.sha256, filmTake.phone_recording.sha256_ingested, ...filmTake.thief.node_answer_verbatim.match(/[0-9a-f]{64}/g)];
  for (const h of new Set(long)) assert.ok(named.includes(h), h.slice(0, 8));
  assert.doesNotMatch(JSON.stringify(filmTake), /DRAFT|draft|\/Users\/|private\/|p[0-9]\/|FILM-SPEC|"[^"]*(seed|secret|spend_key)[^"]*":/);
});

test('tier A, the film\'s take: the proposal and its wait, the cancel with its passkey assertion verified here and its flags as read, the code at its block and the coin pass; there is no execute line, and the device is the record\'s report', { timeout: 150_000 }, async () => {
  const r = await takeRun();
  const lines = filmLines(r);
  assert.equal(lines.filter((l) => !l.startsWith('PASS')).length, 0, r.out);
  assert.equal(lines.length, 4, r.out);
  assert.ok(r.out.includes('\n== tier A: replay of the live take in proofs/film-take.json: the phone page\'s Cancel, fetched again from archival RPC\n'), r.out);
  const one = (re) => {
    const hits = lines.filter((l) => re.test(l));
    assert.equal(hits.length, 1, `${re}\n${r.out}`);
    return hits[0];
  };
  one(new RegExp(`^PASS C17 \\[replay\\] NEAR testnet tx ${fk.propose}: propose_btc on ${esc(fk.contract)} made request 0 of vault ${filmTake.vault.id.slice(0, 10)}…, a spend of Mutinynet coin ${filmTake.coin.mutinynet_txid.slice(0, 10)}…:0 to ${filmTake.thief.sent_to}, with its unlock 5:00 after the block it ran in$`));
  const cancelled = one(new RegExp(`^PASS C05 \\[replay\\] NEAR testnet tx ${fk.cancel}: cancel_all_and_rotate on ${esc(fk.contract)} for vault ${filmTake.vault.id.slice(0, 10)}…, sent by \\S+, the relay's account, which made the vault and is the guard it names, in a block \\d+ s after the proposal's and \\d+ s before request 0's unlock, log "undo:rotating grant=0"\\. `));
  assert.ok(cancelled.includes(' in a block 28 s after the proposal\'s and 271 s before request 0\'s unlock'), cancelled);
  assert.ok(cancelled.includes(`Its WebAuthn assertion passes here the checks the contract makes: the origin is ${filmTake.origin}, the challenge is the digest of this call's own arguments, user present and verified, and the P-256 signature verifies under the passkey in that vault's create_vault, tx ${fk.create}, whose keys hash to the vault id.`), cancelled);
  assert.ok(cancelled.endsWith(` ${FILM_WHO}`), cancelled);
  assert.doesNotMatch(cancelled, /virtual authenticator|Face ID/);
  one(new RegExp(`^PASS C05 \\[replay\\] NEAR testnet account ${esc(fk.contract)} ran code hash ${g2v1.contract.code_hash} at the block of that cancel, read from archival RPC: `));
  one(new RegExp(`^PASS C17 \\[replay\\] Mutinynet coin ${fk.coin}: 2,000 sats at ${filmTake.vault.address}, the take's vault, mined at height ${filmTake.coin.height}\\. Still unspent, read now: the cancelled request moved nothing$`));
  assert.equal(lines.filter((l) => /execute/i.test(l)).length, 0, r.out);
  assert.equal(r.lines.filter((l) => l.startsWith('FAIL')).length, 0, r.out);
  everyLineHasAClaim(r.lines);
});

test('tier A, the film\'s take: another signature, a cancel after the unlock, other code or a co-signed spend to the request\'s address each fail their line, and the other takes still pass', { timeout: 300_000 }, async () => {
  const cancelIn = (chain) => chain.tx[fk.cancel].receipts_outcome.find((x) => x.outcome.executor_id === fk.contract && x.outcome.logs.includes(filmTake.cancel.log)).block_hash;
  const accountKey = Object.keys(filmChain.query).find((k) => k.startsWith('view_account '));
  const runs = [
    [{ chain: (chain) => editArgs(chain.tx[fk.cancel], (a) => { a.assertion.signature = `${a.assertion.signature.slice(0, -1)}${a.assertion.signature.endsWith('8') ? '9' : '8'}`; }) }, new RegExp(`^FAIL C05 \\[replay\\] NEAR testnet tx ${fk.cancel}: its WebAuthn assertion does not pass here the checks the contract makes: webauthn: bad signature$`)],
    [{ chain: (chain) => shiftBlock(chain, cancelIn(chain), filmTake.cancel.block_before_the_unlock_ms + 1000) }, new RegExp(`^FAIL C05 \\[replay\\] NEAR testnet tx ${fk.cancel}: it ran 1000 ms after request 0's unlock, not before it$`)],
    [{ chain: (chain) => { chain.query[accountKey].code_hash = g2.contract.code_hash; } }, new RegExp(`^FAIL C05 \\[replay\\] ${esc(fk.contract)} ran code ${g2.contract.code_hash} at the block of NEAR testnet tx ${fk.cancel}, not ${g2v1.contract.code_hash}, `)],
  ];
  const tx = makeTx([{ txid: filmTake.coin.mutinynet_txid, vout: filmTake.coin.vout }], 0xfffffffd, [{ value: 1702, spk: addressToSpk('mutinynet', filmTake.thief.sent_to) }]);
  tx.inputs[0].witness = [new Uint8Array(72).fill(9), new Uint8Array(72).fill(9), Uint8Array.of(1), new Uint8Array(111).fill(7)];
  const thief = { txid: bitcoinTxid(tx), hex: toHex(serialize(tx)) };
  runs.push([{ outspendFilm: { spent: true, txid: thief.txid, vin: 0 }, bitcoin: (known) => known.set(thief.txid, { hex: thief.hex, height: filmTake.coin.height + 10 }) }, new RegExp(`^FAIL C17 \\[replay\\] Mutinynet coin ${fk.coin}: 2,000 sats at ${filmTake.vault.address}, the take's vault, mined at height ${filmTake.coin.height}\\. Spent by Mutinynet txid ${thief.txid}, a co-signed spend that pays ${filmTake.thief.sent_to}, the address of the cancelled request$`)]);
  for (const [how, want] of runs) {
    const r = await takeRun(how);
    const failed = r.lines.filter((l) => l.startsWith('FAIL'));
    assert.equal(failed.length, 1, `${want}\n${r.out}`);
    assert.match(failed[0], want);
    assert.ok(filmLines(r).includes(failed[0]), 'the line is in the film\'s take\'s section');
    assert.equal(r.code, 1, r.out);
    for (const other of [takeLines(r), phoneLines(r)]) assert.equal(other.filter((l) => !l.startsWith('PASS')).length, 0, r.out);
    everyLineHasAClaim(r.lines);
  }
});

test('tier A, the real phone\'s run: another signature, a cancel after the unlock, other code or a co-signed spend to the request\'s address each fail their line', { timeout: 300_000 }, async () => {
  const cancelIn = (chain) => chain.tx[pk.cancel].receipts_outcome.find((x) => x.outcome.executor_id === pk.contract && x.outcome.logs.includes(phone.cancel.log)).block_hash;
  const accountKey = Object.keys(phoneChain.query).find((k) => k.startsWith('view_account '));
  const runs = [
    [{ chain: (chain) => editArgs(chain.tx[pk.cancel], (a) => { a.assertion.signature = `${a.assertion.signature.slice(0, -1)}${a.assertion.signature.endsWith('8') ? '9' : '8'}`; }) }, new RegExp(`^FAIL C05 \\[replay\\] NEAR testnet tx ${pk.cancel}: its WebAuthn assertion does not pass here the checks the contract makes: webauthn: bad signature$`)],
    [{ chain: (chain) => shiftBlock(chain, cancelIn(chain), phone.cancel.block_before_the_unlock_ms + 1000) }, new RegExp(`^FAIL C05 \\[replay\\] NEAR testnet tx ${pk.cancel}: it ran 1000 ms after request 0's unlock, not before it$`)],
    [{ chain: (chain) => { chain.query[accountKey].code_hash = g2.contract.code_hash; } }, new RegExp(`^FAIL C05 \\[replay\\] ${esc(pk.contract)} ran code ${g2.contract.code_hash} at the block of NEAR testnet tx ${pk.cancel}, not ${g2v1.contract.code_hash}, `)],
  ];
  // A spend of the coin to the request's address, with a co-signed witness: only its shape is read, so its signatures are filler.
  const tx = makeTx([{ txid: phone.coin.mutinynet_txid, vout: phone.coin.vout }], 0xfffffffd, [{ value: 1702, spk: addressToSpk('mutinynet', phone.thief.sent_to) }]);
  tx.inputs[0].witness = [new Uint8Array(72).fill(9), new Uint8Array(72).fill(9), Uint8Array.of(1), new Uint8Array(111).fill(7)];
  const thief = { txid: bitcoinTxid(tx), hex: toHex(serialize(tx)) };
  runs.push([{ outspendPhone: { spent: true, txid: thief.txid, vin: 0 }, bitcoin: (known) => known.set(thief.txid, { hex: thief.hex, height: phone.coin.height + 10 }) }, new RegExp(`^FAIL C17 \\[replay\\] Mutinynet coin ${pk.coin}: 2,000 sats at ${phone.vault.address}, the take's vault, mined at height ${phone.coin.height}\\. Spent by Mutinynet txid ${thief.txid}, a co-signed spend that pays ${phone.thief.sent_to}, the address of the cancelled request$`)]);
  for (const [how, want] of runs) {
    const r = await takeRun(how);
    const failed = r.lines.filter((l) => l.startsWith('FAIL'));
    assert.equal(failed.length, 1, `${want}\n${r.out}`);
    assert.match(failed[0], want);
    assert.ok(phoneLines(r).includes(failed[0]), 'the line is in the real phone\'s section');
    assert.equal(r.code, 1, r.out);
    assert.equal(takeLines(r).filter((l) => !l.startsWith('PASS')).length, 0, 'the film\'s take still passes');
    everyLineHasAClaim(r.lines);
  }
});

test('tier A, a broken take record fails, never passes: the real phone\'s record with another schema, no device, a virtual authenticator too, half an execute, another unlock, wait, cancel, address or height, other flags, or an execute that is not one; the earlier film\'s record with no execute; the film\'s record with another schema, no device or flags, a virtual authenticator, no real device, other flags, wait or height', { timeout: 1_500_000 }, async () => {
  const notARecord = (name) => new RegExp(`^FAIL C17 \\[replay\\] ${esc(name)} is not the record of a take of the live pages$`);
  const unlock = phone.thief.unlock_ms;
  const cases = [
    ['phone-take.json', (p) => { p.schema = 'undo-phone-take-v2'; }, notARecord('proofs/phone-take.json')],
    ['phone-take.json', (p) => { delete p.device_as_reported; }, notARecord('proofs/phone-take.json')],
    ['phone-take.json', (p) => { delete p.assertion_as_read; }, notARecord('proofs/phone-take.json')],
    ['phone-take.json', (p) => { p.labels.push('virtual authenticator'); }, notARecord('proofs/phone-take.json')],
    ['phone-take.json', (p) => { p.labels = p.labels.filter((l) => l !== 'real device'); }, notARecord('proofs/phone-take.json')],
    ['phone-take.json', (p) => { p.after = { execute_refusal: 'RequestNotFound' }; }, notARecord('proofs/phone-take.json')],
    ['phone-take.json', (p) => { p.after = 'none'; }, notARecord('proofs/phone-take.json')],
    ['phone-take.json', (p) => { p.thief.unlock_ms = unlock + 1000; }, new RegExp(`^FAIL C17 \\[replay\\] NEAR testnet tx ${pk.propose}: no log "undo:proposed request=0 unlock=${unlock + 1000}" from ${esc(pk.contract)}$`)],
    ['phone-take.json', (p) => { p.thief.wait_ms = 240_000; }, new RegExp(`^FAIL C17 \\[replay\\] NEAR testnet tx ${pk.propose}: the unlock is 300000 ms after its block, and proofs/phone-take\\.json records a wait of 240000 ms$`)],
    ['phone-take.json', (p) => { p.cancel.tx = tk.cancel; }, new RegExp(`^FAIL C05 \\[replay\\] NEAR testnet tx ${tk.cancel}: not one cancel_all_and_rotate for vault ${phone.vault.id.slice(0, 10)}…$`)],
    // Another address fails twice: the vault's keys do not make it, and the coin is not at it.
    ['phone-take.json', (p) => { p.vault.address = take.vault.address; }, new RegExp(`^FAIL C05 \\[replay\\] NEAR testnet tx ${pk.create}: the script of its keys is not the address ${take.vault.address} that proofs/phone-take\\.json records$`),
      `FAIL C17 [replay] Mutinynet coin ${pk.coin}: it is not 2000 sats at ${take.vault.address}, the take's vault`],
    ['phone-take.json', (p) => { p.coin.height += 1; }, new RegExp(`^FAIL C17 \\[replay\\] Mutinynet coin ${pk.coin}: mined at ${phone.coin.height}, proofs/phone-take\\.json says ${phone.coin.height + 1}$`)],
    ['phone-take.json', (p) => { p.assertion_as_read.backed_up = false; }, new RegExp(`^FAIL C05 \\[replay\\] NEAR testnet tx ${pk.cancel}: its authenticator data reads backed_up true, and proofs/phone-take\\.json records backed_up false$`)],
    ['phone-take.json', (p) => { p.assertion_as_read.sign_count = 1; }, new RegExp(`^FAIL C05 \\[replay\\] NEAR testnet tx ${pk.cancel}: its authenticator data reads sign_count 0, and proofs/phone-take\\.json records sign_count 1$`)],
    // An execute the record names is checked like the film's: the cancel is not an execute.
    ['phone-take.json', (p) => { p.after = { execute_after_the_wait_tx: pk.cancel, execute_refusal: 'RequestNotFound' }; }, new RegExp(`^FAIL C17 \\[replay\\] NEAR testnet tx ${pk.cancel}: not one execute of request 0 of vault ${phone.vault.id.slice(0, 10)}…$`)],
    // The earlier film's take must hold its execute after the wait: without one it is not that record.
    ['chrome-take.json', (p) => { delete p.after; }, notARecord('proofs/chrome-take.json')],
    // The film's take is a real device's: it names what its author reported and the flags as read, and no virtual
    // authenticator; its flags and its numbers are held to the chain's.
    ['film-take.json', (p) => { p.schema = 'undo-film-take-v3'; }, notARecord('proofs/film-take.json')],
    ['film-take.json', (p) => { delete p.device_as_reported; }, notARecord('proofs/film-take.json')],
    ['film-take.json', (p) => { delete p.assertion_as_read; }, notARecord('proofs/film-take.json')],
    ['film-take.json', (p) => { p.labels.push('virtual authenticator'); }, notARecord('proofs/film-take.json')],
    ['film-take.json', (p) => { p.labels = p.labels.filter((l) => l !== 'real device'); }, notARecord('proofs/film-take.json')],
    ['film-take.json', (p) => { p.assertion_as_read.user_verified = false; }, new RegExp(`^FAIL C05 \\[replay\\] NEAR testnet tx ${filmTake.cancel.tx}: its authenticator data reads user_verified true, and proofs/film-take\\.json records user_verified false$`)],
    ['film-take.json', (p) => { p.thief.wait_ms = 240_000; }, new RegExp(`^FAIL C17 \\[replay\\] NEAR testnet tx ${filmTake.thief.propose_tx}: the unlock is 300000 ms after its block, and proofs/film-take\\.json records a wait of 240000 ms$`)],
    ['film-take.json', (p) => { p.coin.height += 1; }, new RegExp(`^FAIL C17 \\[replay\\] Mutinynet coin ${filmTake.coin.mutinynet_txid}:0: mined at ${filmTake.coin.height}, proofs/film-take\\.json says ${filmTake.coin.height + 1}$`)],
  ];
  for (const [file, change, want, also] of cases) {
    const r = await takeRun({ repo: treeWith(file, change) });
    const failed = r.lines.filter((l) => l.startsWith('FAIL'));
    assert.deepEqual(failed.slice(1), also ? [also] : [], `${want}\n${r.out}`);
    assert.match(failed[0], want);
    assert.equal(r.code, 1, r.out);
    const sections = { 'chrome-take.json': takeLines(r), 'phone-take.json': phoneLines(r), 'film-take.json': filmLines(r) };
    const own = sections[file];
    assert.ok(own.includes(failed[0]), `the line is in ${file}'s section\n${r.out}`);
    // The other records still pass whole.
    for (const [name, other] of Object.entries(sections).filter(([name]) => name !== file)) {
      assert.ok(other.length > 0, `${name}'s section is there\n${r.out}`);
      assert.equal(other.filter((l) => !l.startsWith('PASS')).length, 0, `${name}\n${r.out}`);
    }
    // A cancel or a proposal that did not pass leaves the coin's tie to a cancelled request unpassed.
    if (/NEAR testnet tx \S+: (no log|the unlock is|not one cancel|the script of its keys|its authenticator data)/.test(failed[0])) {
      assert.equal(own.filter((l) => l.startsWith('PASS C17 [replay] Mutinynet coin ')).length, 0, r.out);
    }
    everyLineHasAClaim(r.lines);
  }
});

test('the outward gate reads a named run\'s record too: a verdict past its contents in proofs/g2-NAME.json stops it', { timeout: 120_000 }, () => {
  // A throwaway git folder with this repo's scripts and the proof checker, as the G2 rehearsal makes one. The blocked
  // list is a made-up word: the gate fails closed without one, and this test is about the proofs, not the names.
  const copy = join(work, 'outward');
  mkdirSync(join(copy, 'tools', 'test'), { recursive: true });
  mkdirSync(join(copy, 'proofs'));
  cpSync(join(REPO, 'scripts'), join(copy, 'scripts'), { recursive: true });
  cpSync(join(REPO, 'tools/test/check-g2-proof.mjs'), join(copy, 'tools', 'test', 'check-g2-proof.mjs'));
  // The list sits outside the folder it guards, as the real one does, or it would be its own first hit.
  const blocked = join(work, 'outward-blocked.txt');
  writeFileSync(blocked, 'undo-test-only-blocked-word\n');
  // Not a contract: the gate reads a wasm's strings, and wants more of them than an empty file has.
  writeFileSync(join(copy, 'some.wasm'), Array.from({ length: 60 }, (_, i) => `a printable run, number ${i}`).join('\n'));
  const git = (...args) => spawnSync('git', args, { cwd: copy, encoding: 'utf8' });
  git('init', '-q');
  git('add', '-A');
  const env = { PATH: process.env.PATH, HOME: copy, TMPDIR: work, UNDO_BLOCKED_WORDS: blocked };
  const outward = () => spawnSync('bash', [join(copy, 'scripts', 'outward-check.sh'), '--wasm', join(copy, 'some.wasm')], { encoding: 'utf8', env });
  const empty = outward();
  assert.equal(empty.status, 0, `${empty.stdout}${empty.stderr}`);
  // The recorded run passes it. Its label, chain and genesis are a live run's; only the verdict is edited below.
  cpSync(join(REPO, 'proofs/g2-v1.json'), join(copy, 'proofs', 'g2-v1.json'));
  const real = outward();
  assert.equal(real.status, 0, `${real.stdout}${real.stderr}`);
  assert.match(real.stdout, /G2 PROOF OK: chain lines pass/);
  const past = structuredClone(g2v1);
  delete past.cosigned.readback;
  writeFileSync(join(copy, 'proofs', 'g2-v1.json'), JSON.stringify(past));
  const planted = outward();
  assert.notEqual(planted.status, 0, planted.stdout);
  assert.match(planted.stdout, /G2 PROOF FAIL: pass without a co-signed spend read back/);
  assert.match(planted.stdout, /OUTWARD FAIL/);
  // And a rehearsal's label under a run's name is refused as it is at proofs/g2.json.
  writeFileSync(join(copy, 'proofs', 'g2-v1.json'), JSON.stringify({ ...g2v1, label: 'rehearsal-regtest-mock-signer' }));
  const rehearsal = outward();
  assert.notEqual(rehearsal.status, 0, rehearsal.stdout);
  assert.match(rehearsal.stdout, /G2 PROOF FAIL: its label is rehearsal-regtest-mock-signer, not a live run/);
});

test('proofs/c14-agent.json: nothing NEAR refused is recorded as on chain, the key is the narrow one, and it holds no secret', () => {
  const text = read('proofs/c14-agent.json');
  assert.equal(c14.schema, 'undo-c14-agent-v1');
  assert.deepEqual(c14.agent.function_call_key.permission.FunctionCall.method_names, ['propose_btc', 'execute']);
  assert.equal(c14.agent.function_call_key.permission.FunctionCall.receiver_id, c14.contract.account);
  assert.notEqual(c14.agent.function_call_key.public_key, c14.agent.full_access_key);
  assert.equal(c14.near_refusals.calls.length, 7);
  for (const call of c14.near_refusals.calls) {
    assert.equal(call.chain_knows_it, false, call.what);
    assert.equal(call.error.cause.name, 'INVALID_TRANSACTION', call.what);
    assert.ok(call.error.data.TxExecutionError.InvalidTxError.InvalidAccessKeyError, call.what);
    assert.equal('tx' in call, false, 'a refused call has a signed hash, not a transaction');
  }
  assert.deepEqual(c14.near_refusals.calls.slice(0, 5).map((c) => c.method), ['cancel', 'cancel_all_and_rotate', 'set_policy', 'clear_hold', 'add_destination']);
  for (const call of c14.near_refusals.calls.slice(0, 5)) assert.deepEqual(call.error.data.TxExecutionError.InvalidTxError.InvalidAccessKeyError, { MethodNameMismatch: { method_name: call.method } });
  assert.equal(c14.near_refusals.key_nonce_before, c14.near_refusals.key_nonce_after);
  assert.equal(c14.near_refusals.key_allowance_before, c14.near_refusals.key_allowance_after);
  assert.equal(c14.propose.wait_ms, c14.contract.policy.t_new_ms);
  assert.ok(c14.owner_cancel.ms_before_unlock > 0, 'the owner cancelled before the wait ended');
  assert.equal(c14.contract_refusals.after.request_unlock, c14.propose.unlock);
  assert.equal(c14.coin_after.spent, false);
  // The agent file's fields are named; its seed and key are not here, and no field holds 64 hex but public ids.
  assert.doesNotMatch(text, /"(seed|private_key|secret_key|cold|passkey_secret)": "/);
  assert.doesNotMatch(text, /ed25519:[1-9A-HJ-NP-Za-km-z]{60,}/);
});

// ---------------------------------------------------------------- tier B: totals are INFO, claims need their tests

test('tier B with a cargo that runs no named test: every claim line FAILs, suite totals are INFO, and no line passes', { timeout: 60_000 }, () => {
  const bin = join(work, 'fake-cargo');
  mkdirSync(bin, { recursive: true });
  writeFileSync(join(bin, 'cargo'), '#!/bin/sh\necho "     Running tests/elsewhere.rs (target/debug/deps/elsewhere)"\necho "test result: ok. 3 passed; 0 failed; 0 ignored"\n');
  chmodSync(join(bin, 'cargo'), 0o755);
  const out = spawnSync('bash', [join(REPO, 'tools/verify/tier-b.sh')], { encoding: 'utf8', env: { PATH: `${bin}:/usr/bin:/bin`, HOME: work, TMPDIR: work } });
  const lines = out.stdout.split('\n').filter((l) => /^(PASS|FAIL|SKIP|INFO) /.test(l));
  assert.equal(out.status, 1, out.stdout);
  assert.equal(lines.filter((l) => l.startsWith('PASS')).length, 0);
  assert.equal(lines.filter((l) => l.startsWith('INFO tier-B ')).length, 2, out.stdout);
  const claims = lines.filter((l) => !l.startsWith('INFO'));
  assert.ok(claims.length >= 13);
  for (const l of claims) assert.match(l, /^FAIL C\d\d \[(unit|consensus-lib)\] .*: did not run and pass: /);
  everyLineHasAClaim(claims);
});

// ---------------------------------------------------------------- build.sh and the deployed hash

test('wasm-vs-config: a placeholder has nothing to compare, the same bytes pass, other bytes fail and say so', () => {
  const wasm = join(work, 'undo_vault.wasm');
  writeFileSync(wasm, 'not really a wasm');
  const digest = toHex(sha256(readFileSync(wasm)));
  const config = (over) => {
    const p = join(work, `config-${Math.random().toString(36).slice(2)}.json`);
    writeFileSync(p, JSON.stringify({ ...JSON.parse(read('deploy/testnet.json')), ...over }));
    return p;
  };
  const run = (cfg) => spawnSync(process.execPath, [join(REPO, 'scripts/wasm-vs-config.mjs'), wasm, cfg], { encoding: 'utf8' });
  // Not the repo's own file as it stands: the deploy fills that one in.
  const none = run(config({ placeholder: true, contract: 'not-deployed-yet', wasm_sha256: null }));
  assert.equal(none.status, 0);
  assert.match(none.stdout, /records no deployed wasm yet/);
  const same = run(config({ placeholder: false, contract: 'v1.s.undo-btc.testnet', wasm_sha256: digest }));
  assert.equal(same.status, 0);
  assert.match(same.stdout, /the same bytes as the wasm .* records for v1\.s\.undo-btc\.testnet on NEAR testnet/);
  const other = run(config({ placeholder: false, contract: 'v1.s.undo-btc.testnet', wasm_sha256: 'ab'.repeat(32) }));
  assert.equal(other.status, 1);
  assert.match(other.stdout, /NOT the wasm/);
  assert.equal(`${none.stdout}${same.stdout}${other.stdout}`.includes(work), false, 'it prints no folder');
  assert.match(read('scripts/build.sh'), /wasm-vs-config\.mjs" "\$out\/undo_vault\.wasm"/, 'build.sh runs it on every build');
});

// ---------------------------------------------------------------- setup-repo.sh sets nobody's identity unasked

test('setup-repo.sh changes nothing unasked; --hooks sets the hooks alone; only --author sets the author\'s identity', () => {
  const clone = join(work, 'clone');
  mkdirSync(join(clone, 'scripts'), { recursive: true });
  cpSync(join(REPO, 'scripts/setup-repo.sh'), join(clone, 'scripts/setup-repo.sh'));
  const git = (...args) => spawnSync('git', args, { cwd: clone, encoding: 'utf8', env: { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1' } });
  git('init', '-q');
  const local = (key) => git('config', '--local', '--get', key).stdout.trim();
  const run = (...args) => spawnSync('bash', [join(clone, 'scripts/setup-repo.sh'), ...args], { cwd: clone, encoding: 'utf8' });
  const bare = run();
  assert.equal(bare.status, 2);
  assert.match(bare.stderr, /nothing changed/);
  assert.deepEqual([local('core.hooksPath'), local('user.name'), local('user.email')], ['', '', '']);
  assert.equal(run('--hooks').status, 0);
  assert.deepEqual([local('core.hooksPath'), local('user.name')], ['.githooks', '']);
  assert.equal(run('--author').status, 0);
  const author = /git config user\.name "([^"]+)"/.exec(read('scripts/setup-repo.sh'))[1];
  assert.equal(local('user.name'), author);
  assert.doesNotMatch(read('README.md'), /`scripts\/setup-repo\.sh` once per clone/);
});

// ---------------------------------------------------------------- proofs/ say when a field disagrees with another

test('proofs/s2-refusal.json: a tip read below the coin\'s own height carries a note saying the API lagged', () => {
  // The 11/01 capture read a lagging tip, and its note was added by hand. A fresh capture need not lag.
  if (s2.after.tip < s2.funding_coin.height) {
    assert.match(s2.after.tip_note ?? '', /lagged a block/);
    assert.ok(s2.after.tip_note.includes(String(s2.funding_coin.height)));
  }
  assert.equal(s2.coin_return.mutinynet_txid, s2.coin_return.coin_spent_by, 'the return is what spent the coin');
});

// ---------------------------------------------------------------- the watcher: the chain's clock decides

const VAULT = toHex(sha256(utf8('undo-test-only:judge-floor-vault')));
const localRaw = () => ({
  format: CONFIG_FORMAT, network: 'local', contract: 'undo.test.near', vault: VAULT, rpc: ['http://127.0.0.1:1'], page_origin: 'http://localhost:8788',
  ntfy_server: 'http://127.0.0.1:2', ntfy_topic: makeTopic(), priority: 5, poll_ms: 200,
});

/** One request proposed 10 s ago on the chain, 5:00 wait, 30 min expiry, read by a machine whose clock is `skewMs` ahead. */
async function alertWithSkew(skewMs) {
  const chainNow = 1_010_000;
  const request = {
    id: 0, kind: 'Normal', status: 'Pending', epoch: 0, inputs: [{ txid: 'aa'.repeat(32), vout: 0, value: 2000 }], to: `0014${'11'.repeat(20)}`, amount: 1600, change: null,
    tier: 'New', fee: 400, proposed_at: 1_000_000, base_unlock: 1_300_000, unlock: 1_300_000, expires_at: 2_800_000,
  };
  const reads = {
    vault: async () => ({ value: { id: VAULT, pending: [0], spend_epoch: 0, script_pubkey: `0020${'22'.repeat(32)}` }, height: 10 }),
    request: async () => ({ value: request, height: 10 }),
    clock: async () => ({ blockMs: chainNow, height: 10, heardAt: chainNow + skewMs }),
  };
  const sent = [];
  const logs = [];
  const w = new Watcher({
    config: checkWatchConfig(localRaw()), vault: VAULT, reads, nowFn: () => chainNow + skewMs, log: (l) => logs.push(l), sleep: async () => {},
    push: async (alert) => { sent.push(alert); return { id: 'm1', serverTime: null }; },
    state: new StateStore(join(work, `state-${skewMs}.json`), { contract: 'undo.test.near', vault: VAULT, network: 'local' }),
  });
  const { events } = await w.pollOnce();
  return { events, sent, logs };
}

test('watcher: a machine clock 6 or 70 minutes fast still alerts, counting down from the chain\'s clock; a few seconds is the safe side', async () => {
  for (const skew of [0, 6 * 60_000, 70 * 60_000]) {
    const { events, sent, logs } = await alertWithSkew(skew);
    assert.equal(events[0].kind, 'pushed', `skew ${skew}: ${JSON.stringify(events)}`);
    assert.equal(sent.length, 1);
    assert.match(sent[0].message, /unlocks in 4:50/, `skew ${skew}`);
    assert.equal(logs.some((l) => /^CLOCK .* ahead of the chain's/.test(l)), skew > 0, `skew ${skew}: ${logs.join(' | ')}`);
  }
  const lag = await alertWithSkew(5_000);
  assert.match(lag.sent[0].message, /unlocks in 4:45/, 'within the tolerance the later clock wins: a node a block behind');
});

// ---------------------------------------------------------------- the watcher prints file names, not folders

test('watcher: init, a loose config and a second init print the file name, never the folder or the home path', () => {
  const dir = join(work, 'watch-config-folder');
  const cfg = join(dir, 'config.json');
  const watch = (...args) => {
    const out = spawnSync(process.execPath, [join(REPO, 'tools/watch.mjs'), ...args], { encoding: 'utf8', env: { ...process.env, NODE_USE_SYSTEM_CA: '' } });
    return { code: out.status, text: `${out.stdout}${out.stderr}` };
  };
  const init = ['init', '--network', 'local', '--contract', 'undo.test.near', '--rpc', 'http://127.0.0.1:1', '--page-origin', 'http://localhost:8788', '--ntfy-server', 'http://127.0.0.1:2', '--config', cfg];
  const first = watch(...init);
  assert.equal(first.code, 0, first.text);
  assert.match(first.text, /^Wrote config\.json \(mode 600\)/m);
  const again = watch(...init);
  assert.notEqual(again.code, 0);
  assert.match(again.text, /config\.json exists/);
  chmodSync(cfg, 0o644);
  const loose = watch('run', '--once', '--vault', VAULT, '--config', cfg);
  assert.notEqual(loose.code, 0);
  assert.match(loose.text, /config\.json can be read by other users/);
  for (const r of [first, again, loose]) {
    assert.equal(r.text.includes(dir), false, r.text);
    assert.equal(r.text.includes(homedir()), false, r.text);
  }
});

// ---------------------------------------------------------------- what the README and CLAIMS.md say

test('README and CLAIMS: no TODO, the agent and watcher are reachable, every hash C14 cites is in proofs/c14-agent.json, C13 claims only the hash', () => {
  const readme = read('README.md');
  const claims = read('CLAIMS.md');
  assert.doesNotMatch(readme, /TODO/);
  assert.match(readme, /\[agent\/README\.md\]\(agent\/README\.md\)/);
  assert.match(readme, /\[docs\/watch\.md\]\(docs\/watch\.md\)/);
  assert.match(readme, /written in the window, except the vendored libraries/);
  const row = (id) => claims.split('\n').find((l) => l.startsWith(`| ${id} |`)).split(' | ');
  const c14Row = row('C14');
  assert.equal(c14Row[4], '`[mock-signer]`; `[live-testnet]`, re-fetched `[replay]`', 'C14 ran on a local sandbox and once on NEAR testnet');
  assert.match(c14Row[2], /agent\/test\/run-sandbox\.sh 86 88/);
  assert.match(c14Row[2], /agent\/test\/testnet-c14\.mjs --live/);
  // What the testnet run rests on is its record. A hash in the row, in the paragraph on that run or in the agent's
  // README that the record does not hold would be a claim with nothing under it.
  const record = read('proofs/c14-agent.json');
  const live = claims.split('\n').find((l) => l.startsWith('The agent CLI, live, '));
  assert.ok(live, 'CLAIMS.md has a paragraph on the live agent run');
  const agentReadme = read('agent/README.md');
  const onTestnet = agentReadme.slice(agentReadme.indexOf('**On NEAR testnet.**'), agentReadme.indexOf('**If a command hangs'));
  for (const [where, text] of [['the C14 row', c14Row.join(' | ')], ['the live paragraph', live], ['agent/README.md', onTestnet]]) {
    const hashes = [...text.matchAll(/`([1-9A-HJ-NP-Za-km-z]{43,44}|[0-9a-f]{64})`/g)].map((m) => m[1]);
    assert.ok(hashes.length >= 7, `${where} names its transactions`);
    for (const h of hashes) assert.ok(record.includes(`"${h}"`), `${where} cites ${h}, which proofs/c14-agent.json does not hold`);
  }
  // What NEAR refused never landed, and neither text may say a phone's passkey or the near-cli command ran there.
  assert.match(c14Row[6], /with no transaction, because NEAR does not broadcast one it refuses/);
  assert.match(c14Row[6], /With a phone's passkey as the owner: \*\*not yet run\*\*/);
  assert.match(c14Row[6], /The near-cli command `undo keys` prints, on testnet: \*\*not yet run\*\*/);
  assert.match(onTestnet, /with a phone's passkey this has \*\*not yet run\*\*/);
  assert.match(onTestnet, /that near-cli command itself has \*\*not yet run\*\* on testnet/);
  assert.doesNotMatch(agentReadme, /None of it has run against testnet/);
  assert.match(row('C13')[1], /The deployed code hash equals the wasm the operator's machine built/);
  // The label is printed on whoever's machine runs the check, so it names the machine that built, and says this run built nothing.
  assert.match(row('C13')[2], /Label when it runs: "the operator's machine built this hash", since CI does not build the wasm; the run itself rebuilds nothing/);
  assert.match(read('tools/verify/tier-a.mjs'), /'the operator\\'s machine built this hash \(scripts\/build\.sh; CI does not build the wasm, and this run rebuilds nothing\)'/);
  assert.doesNotMatch(`${read('tools/verify/tier-a.mjs')}${claims}${read('README.md')}`, /this machine built/);
  assert.doesNotMatch(claims, /current build/, 'every build is named by what it was built from');
  for (const f of ['agent/README.md', 'docs/watch.md']) assert.ok(existsSync(join(REPO, f)), f);
});

test('README and CLAIMS: what they say of the final build\'s co-signed spend and escape is in its records, and says what did not run', () => {
  const readme = read('README.md');
  const claims = read('CLAIMS.md');
  const records = `${read('proofs/g2-v1.json')}\n${read('proofs/s2-refusal-v1.json')}`;
  const everyProof = ['g1.json', 'g2.json', 'g2-v1.json', 's2-refusal.json', 's2-refusal-v1.json'].map((f) => read(`proofs/${f}`)).join('\n');
  const hashesIn = (text) => [...text.matchAll(/`([1-9A-HJ-NP-Za-km-z]{43,44}|[0-9a-f]{64})(?::\d+)?`/g)].map((m) => m[1]);
  // The paragraph on the run cites nothing its two records do not hold.
  const live = claims.split('\n').find((l) => l.startsWith('The co-signed spend and the escape, on the final build, '));
  assert.ok(live, 'CLAIMS.md has a paragraph on the final build\'s live run');
  const cited = hashesIn(live);
  assert.ok(cited.length >= 11, 'the paragraph names its transactions');
  for (const h of cited) assert.ok(records.includes(h), `the paragraph cites ${h}, which neither record holds`);
  // Each row it touched cites only what some proof holds, and names the final build's hash for its claim.
  const row = (id) => claims.split('\n').find((l) => l.startsWith(`| ${id} |`));
  const execute = g2v1.cosigned.attempts.find((a) => a.signer_answer).execute_tx;
  const wants = {
    C01: [g2v1.cosigned.propose_tx, execute],
    C02: [g2v1.cosigned.txid, g2.cosigned.txid],
    C03: [s2v1.refused_tx.mutinynet_txid_it_would_have_had, s2v1.funding_coin.mutinynet_txid, s2v1.coin_return.mutinynet_txid, s2.refused_tx.mutinynet_txid_it_would_have_had],
    C04: [g2v1.escape.txid, g2.escape.txid],
    C12: [execute, g2v1.cosigned.txid, g2v1.contract.code_hash],
    C18: [g2v1.escape.txid, g2.escape.txid],
  };
  for (const [id, hashes] of Object.entries(wants)) {
    for (const h of hashesIn(row(id))) assert.ok(everyProof.includes(h), `${id} cites ${h}, which no proof holds`);
    for (const h of hashes) assert.ok(row(id).includes(h), `${id} does not name ${h}`);
  }
  assert.match(row('C12'), new RegExp(`height ${g2v1.cosigned.mined_height}\\b`));
  assert.match(row('C04'), new RegExp(`height ${g2v1.escape.mined_height}, ${g2v1.escape.readback.blocks_after_coin} blocks after its coin`));
  // C01's live part is one request that waited, and the row says no early execute was tried there.
  assert.match(row('C01'), /one request that waited, not a test of the rule: no early execute was tried on testnet/);
  // The README's row for the contract no longer says it did not run, and names both transactions.
  assert.doesNotMatch(readme, /cold-key escape, on the final build: \*\*not yet run\*\*/);
  const contractRow = readme.split('\n').find((l) => l.startsWith('| `contracts/undo` |'));
  assert.ok(contractRow.includes(g2v1.cosigned.txid) && contractRow.includes(g2v1.escape.txid), 'the README names the spend and the escape');
  for (const h of hashesIn(contractRow)) assert.ok(records.includes(h), `the README cites ${h}, which neither record holds`);
  // What the record does not hold is said: no browser POST in this run, so the gate reads incomplete.
  assert.equal(g2v1.summary.gate_complete, Boolean(g2v1.browser?.real_post));
  if (!g2v1.summary.gate_complete) {
    assert.match(live, /a browser's POST to the Mutinynet API, .* is \*\*not yet run\*\* for this one, so `proofs\/g2-v1\.json` reads `gate_complete: false`/);
    assert.doesNotMatch(contractRow, /gate G2|G2 passed|gate complete/i);
  }
  assert.match(live, /the vault's passkey was a software key and no cancel was made/);
});

// ---------------------------------------------------------------- the README's first screens

/** The README between two of its lines, each matched whole. */
function readmeBetween(from, to) {
  const lines = read('README.md').split('\n');
  const a = lines.indexOf(from);
  const b = lines.indexOf(to);
  assert.ok(a >= 0 && b > a, `the README has "${from}" and then "${to}"`);
  return lines.slice(a + 1, b).join('\n');
}

test('README: the lead says what only this entry has, with the contract as the one that waits and "alone" beside what NEAR cannot do; then the film, the problem, and how NEAR fits', () => {
  const lines = read('README.md').split('\n');
  assert.equal(lines[0], '# Undo for Bitcoin');
  const lead = lines[2];
  for (const phrase of [
    'native Bitcoin', 'on test networks', 'Bitcoin itself refuses a stolen spend key alone', 'NEAR Chain Signatures gives the second signature when a public NEAR contract asks',
    'the contract asks only after a public wait', 'passkey can cancel', 'NEAR alone cannot take the coins', 'after a Bitcoin timelock',
  ]) assert.ok(lead.includes(phrase), `the lead says: ${phrase}`);
  assert.ok(lead.split(/\s+/).length <= 66, `the lead is ${lead.split(/\s+/).length} words`);
  assert.ok(lead.split(/[.](?:\s|$)/).filter(Boolean).length <= 2, 'one or two sentences');
  // Never the signers as the ones who wait, never "cannot take" without "alone", never a first or an always.
  assert.doesNotMatch(lead, /Chain Signatures (signs|waits|gives[^,]*) only/);
  assert.doesNotMatch(lead, /(?<!alone )cannot take|can't take/);
  assert.doesNotMatch(lead, /\b(first|always|every|never)\b/i);
  // The film: its poster, small, linked to the page that plays it, and a caption that says what it is.
  const film = readmeBetween(lead, '## Problem');
  assert.match(film, /^\n\[<img src="site\/pages\/film\/poster\.png" width="200" alt="The film's opening frame, large type on black: Your Bitcoin key was just stolen\. Under it, the thief tab, its stolen-key field blurred, set to send everything, 2,000 sats\.">\]\(https:\/\/undo-btc\.pages\.dev\/\)\n\n\[The film\]\(https:\/\/undo-btc\.pages\.dev\/\): about a minute, cut from one take on test networks: the phone page in Safari on the author's iPhone, from that iPhone's own screen recording, with Face ID, as the author reported it, and the thief tab in headless Chrome on a Mac, a second device\. The narration is a synthetic voice\.\n$/);
  // That is the film's own record: a real device's take, Face ID the author's report, the thief tab on a second device.
  assert.equal(filmTake.device_as_reported.user_verification, 'Face ID');
  assert.match(filmTake.device_as_reported.tabs, /headless Chrome on a Mac, a second device/);
  assert.match(filmTake.film.narration, /synthetic voice/);
  assert.ok(existsSync(join(REPO, 'site/pages/film/poster.png')));
  assert.match(read('site/pages/index.html'), /<video id="film"[^>]*poster="\/film\/poster\.png"/, 'the page the poster links to plays the film');
  // The problem, in three sentences, and each NEAR feature under its own name with its claim rows.
  const problem = readmeBetween('## Problem', '## How NEAR fits (tracks: open, security, defi)').trim();
  assert.equal(problem, 'A stolen Bitcoin spend key means stolen coins, at once and for good. Multisig stops that only if a second key signs every spend. Undo keeps one-key spending and adds a public wait and a cancel.');
  const fits = readmeBetween('## How NEAR fits (tracks: open, security, defi)', '## Not done yet');
  const bullets = fits.split('\n').filter((l) => l.startsWith('- '));
  assert.deepEqual(bullets.map((b) => /^- \*\*([^*]+)\*\*/.exec(b)[1]), ['Chain Signatures.', 'A public contract as referee.', 'Function-call keys.', 'NEAR alone can refuse, not take.', 'Not used:']);
  const rows = new Set(read('CLAIMS.md').split('\n').map((l) => /^\| (C\d\d) \|/.exec(l)?.[1]).filter(Boolean));
  const cited = bullets.map((b) => [...b.matchAll(/\bC\d\d\b/g)].map((m) => m[0]));
  assert.deepEqual(cited, [['C01', 'C12'], ['C05', 'C17'], ['C14'], ['C02', 'C04', 'C18'], ['C08']]);
  for (const id of cited.flat()) assert.ok(rows.has(id), `${id} is a row of CLAIMS.md`);
  // The count of signing transactions is the records' own: every execute in the three proofs tier A replays.
  const executes = (o, acc = []) => {
    if (Array.isArray(o)) o.forEach((v) => executes(v, acc));
    else if (o && typeof o === 'object') for (const [k, v] of Object.entries(o)) (k === 'execute_tx' && typeof v === 'string' ? acc.push(v) : executes(v, acc));
    return acc;
  };
  const earlier = new Set([...executes(JSON.parse(read('proofs/g1.json'))), ...executes(g2)]).size;
  const final = new Set(executes(g2v1)).size;
  assert.ok(bullets[0].includes(`fetches ${earlier + final} recorded signing transactions again and verifies the signer's signatures in them here: ${earlier} on an earlier build of the contract, ${final} on the final build (C12)`), `${earlier} + ${final} executes are recorded`);
  assert.match(read('CLAIMS.md'), new RegExp(`\\(${earlier + final} of ${earlier + final} executes\\)`), 'and C12 says the same number');
  assert.match(bullets[0], /The contract asks them to sign only after a request's public wait has run out \(C01\)/);
  // What has not run is said where the feature is claimed.
  assert.match(bullets[1], /That ran with software passkeys and Chrome's virtual authenticator, on NEAR testnet with one request pending and on a local node with several; and twice from a real phone on the live pages, each a cancel from an iPhone in Safari, as the author reported it \(no chain says which device held a passkey, and each assertion reads user verified, not how\), and each checked again by `\.\/verify\.sh A`: /);
  // The two runs from a real phone, the same two that Not done yet and Try it list: each device is the author's report,
  // said as such, and each hash and block time is its record's, both of which tier A checks again.
  assert.deepEqual([phone.device_as_reported.browser, filmTake.device_as_reported.browser], ['Safari', 'Safari']);
  assert.match(filmTake.device_as_reported.tabs, /the thief tab \/t\/ ran in headless Chrome on a Mac, a second device/);
  assert.equal(phone.vault_made_block_utc.slice(0, 10), '2026-11-12');
  assert.equal(filmTake.started_utc.slice(0, 10), '2026-11-13');
  assert.ok(bullets[1].endsWith(`: ${phone.vault_made_block_utc.slice(0, 10)}, an ${phone.device_as_reported.device} on ${phone.device_as_reported.os}, with the thief tab a second Safari tab on the same phone, NEAR testnet tx \`${phone.cancel.tx}\`, in a block ${(phone.cancel.block_after_the_proposal_ms / 1000).toFixed(1)} s after the proposal's; and ${filmTake.started_utc.slice(0, 10)}, the take the film is cut from, with the thief tab in headless Chrome on a Mac, a second device, NEAR testnet tx \`${filmTake.cancel.tx}\`, in a block ${(filmTake.cancel.block_after_the_proposal_ms / 1000).toFixed(1)} s after the proposal's.`), bullets[1]);
  // Never the film's chip as the cancel's time: the bullet gives the chain's block time only.
  assert.doesNotMatch(bullets[1], /0:41|41 s/);
  assert.match(read('CLAIMS.md'), /Several pending requests killed by one call, on testnet: \*\*not yet run\*\*/, 'C17 says the same of testnet');
  assert.match(bullets[2], /`propose_btc` and `execute` only/);
  // The agent is a command-line tool, and a script drove the recorded run: no model is in this repository.
  assert.match(bullets[2], /The agent here is a CLI with `--json` output for a model to call; a test script drove the recorded run, not a model\./);
  assert.match(read('agent/undo.mjs'), /const wantsJson = process\.argv\.includes\('--json'\);/);
  assert.ok(existsSync(join(REPO, 'agent/test/testnet-c14.mjs')), 'the script that drove the recorded run');
  assert.match(bullets[3], /All three ran on the final build with Mutinynet test coins, 2026-11-11\./);
  assert.equal(g2v1.cosigned.attempts.at(-1).contract_logs.length > 0 && g2v1.coins[0].recorded_at.slice(0, 10), '2026-11-11');
  assert.equal(bullets[4], '- **Not used:** NEAR Intents, TEE attestation. A NEAR AI model signature checked on testnet is **not yet run** (C08).');
  assert.match(fits, /Track hints this leans on: chain abstraction \(open\), function-call keys and agent security \(security\), Chain Signatures \(defi\)\./);
  assert.match(fits, /^\nEach claim number below is a row of \[CLAIMS\.md\]\(CLAIMS\.md\), with its command, its date and the hash it rests on\.\n/);
  // The earlier build's executes are on another contract account than the final build's, as the bullet says.
  assert.notEqual(g2.contract.account, g2v1.contract.account);
  // What is not done, in one list right after it, so a reader does not collect it from five places. Each line is
  // said again where it belongs, in the same words where a test already holds them.
  const notDone = readmeBetween('## Not done yet', '## Run it').split('\n').filter((l) => l.startsWith('- '));
  assert.deepEqual(notDone, [
    '- A Cancel from a real phone has run twice, each from an iPhone in Safari, as the author reported it: with the thief tab as a second Safari tab on that iPhone, 2026-11-12, and with the thief tab in headless Chrome on a Mac, a second device, 2026-11-13, the take the film is cut from (C05). From any other phone, and from a laptop or desktop with its own passkey: **not yet run**.',
    '- The lock: the deploy\'s full-access key is still on the test contract, so its holder could replace the code at once, and C11 fails in `./verify.sh A`.',
    '- Mainnet: not deployed and not run (C19). Test networks only.',
    '- An audit: the code is unaudited.',
    '- A NEAR AI model signature for the guard\'s hold, checked on testnet: **not yet run** (C08).',
  ]);
  const claimsText = read('CLAIMS.md');
  assert.match(claimsText, /\| C11 \|.*`\.\/verify\.sh A` prints FAIL on `v1\.s\.undo-btc\.testnet`, the instance of the final build, which keeps its deployer's full-access key/);
  assert.match(claimsText, /\| C19 \| On mainnet: .*\*\*not run\*\*: this build has no mainnet deploy/);
  assert.match(claimsText, /\| C08 \|.*A real NEAR AI signature checked on testnet: \*\*not yet run\*\*/);
  // C05 names the real phone's cancel, its flags as read, and the device as the author's report, not the chain's.
  assert.match(claimsText, new RegExp(`\\| C05 \\|.*From a real phone: tx \`${phone.cancel.tx}\`, 2026-11-12, .*its authenticator data reads user present, user verified, backup eligible and backed up, sign count 0\\. The device, an iPhone 13 Pro Max on iOS 27\\.2\\.1 in Safari, with the thief tab a second Safari tab on it, is the author's report: no chain says which device held a passkey, and user verified does not say how \\(Real phone below\\) \\|`));
  // C17 names the real phone's request and its cancel, and says in the same cell that the phone is the author's report.
  assert.match(claimsText, new RegExp(`\\| C17 \\|.*From a real phone, an iPhone as the author reported it \\(no chain says which device\\): tx \`${phone.thief.propose_tx}\` made request 0 with a 5:00 wait, and tx \`${phone.cancel.tx}\` cancelled it 279 s before its unlock; its coin read unspent after the unlock \\(Real phone below\\)\\.`));
  assert.doesNotMatch(claimsText, /From a real phone: \*\*not yet run\*\*/);
  assert.doesNotMatch(read('README.md'), /real phone[^.]*\*\*not yet run\*\* end to end|from a real phone: \*\*not yet run\*\*/i);
  assert.equal(claimsText.split('\n').filter((l) => l.startsWith('**Real phone.** The pages, live, 2026-11-12, ')).length, 1);
  assert.equal(claimsText.match(/\(Real phone below\)/g).length, 3, 'C05, C17 and the live take point to it');
  assert.match(read('README.md'), /Nothing here runs on NEAR mainnet or holds real bitcoin\. The code is unaudited\./);
  assert.match(read('tools/verify/tier-a.mjs'), /Its owner could replace the code at once, without the upgrade wait/, 'C11\'s own words when it fails');
});

test('the real phone\'s device and browser: every sentence that names them says they are the author\'s report, and none names a way the phone verified its user', () => {
  // No chain names a device or a browser, so a sentence that does says whose report it is. The one exception is how-to:
  // the step that tells a reader which browser to open the page in.
  const names = /iPhone|Safari|iOS \d|13 Pro Max/;
  const label = /as the author reported it|the author's report|what the author reported/i;
  const howTo = /^(1\. )?On the phone, open https:\/\/undo-btc\.pages\.dev\/p\/ in Safari or Chrome itself, not inside X or Telegram, /;
  const sentences = (text) => text.split(/\n+| \| |(?<=\.)\s+(?=[A-Z*(`[])/).map((s) => s.trim()).filter(Boolean);
  const hits = [];
  for (const f of ['README.md', 'CLAIMS.md', 'tests/REGRESSION-MAP.md']) {
    for (const s of sentences(read(f))) {
      if (!names.test(s) || howTo.test(s)) continue;
      hits.push(s);
      assert.match(s, label, `${f}: a sentence names the device or browser without saying it is the author's report: ${s}`);
    }
  }
  assert.ok(hits.length >= 8, `the sentences that name it were found: ${hits.length}`);
  // The regression map's WebAuthn row no longer lists a real phone's assertion as not covered: it names the record's cancel.
  const row17 = read('tests/REGRESSION-MAP.md').split('\n').find((l) => l.startsWith('| 17 |'));
  assert.ok(row17.includes(`one real phone's assertion, from its NEAR testnet cancel \`${phone.cancel.tx}\` (\`proofs/phone-take.json\`; which phone it was is the author's report)`), row17);
  assert.ok(row17.endsWith('| Assertions from other phones and authenticators. The sandbox tests here use a software authenticator only. |'), row17);
  // The one-device run's record names no way the phone verified its user; the assertion says only that it did (user
  // verified). The film's take names Face ID as its author's report: the README and CLAIMS may say so only in a
  // sentence that says whose report it is, never of the one-device run, and the pages and tier A's lines do not say it.
  for (const f of ['proofs/phone-take.json', 'site/pages/index.html', 'site/pages/replay/run.json']) assert.doesNotMatch(read(f), /Face ID|Touch ID/, f);
  const faceId = [];
  for (const f of ['README.md', 'CLAIMS.md', 'tests/REGRESSION-MAP.md']) {
    assert.doesNotMatch(read(f), /Touch ID/, f);
    for (const s of sentences(read(f)).filter((x) => /Face ID/.test(x))) {
      faceId.push(s);
      assert.match(s, label, `${f}: a sentence names Face ID without saying it is the author's report: ${s}`);
      assert.doesNotMatch(s, /2026-11-12|13 Pro Max|HHzwhu5f|two Safari tabs/, `${f}: Face ID is the film's take's report, not the one-device run's: ${s}`);
    }
  }
  assert.ok(faceId.length >= 4, `the sentences that name Face ID were found: ${faceId.length}`);
  assert.doesNotMatch(PHONE_WHO, /Face ID/);
  assert.doesNotMatch(FILM_WHO, /Face ID/);
});

test('README, See it on chain: seven links, each to a hash its record holds, each saying its build and what signed, and all seven fetched again by ./verify.sh A', () => {
  const section = readmeBetween('### See it on chain', '## Try it');
  const execute = g2v1.cosigned.attempts.find((a) => a.signer_answer).execute_tx;
  const links = [...section.matchAll(/\[`([^`]+)`\]\((https:\/\/[^)]+)\)/g)].map((m) => [m[1], m[2]]);
  assert.deepEqual(links, [
    [g2v1.cosigned.txid, `https://mutinynet.com/tx/${g2v1.cosigned.txid}`],
    [execute, `https://testnet.near.rocks/tx/${execute}`],
    [g2v1.escape.txid, `https://mutinynet.com/tx/${g2v1.escape.txid}`],
    [filmTake.cancel.tx, `https://testnet.near.rocks/tx/${filmTake.cancel.tx}`],
    [take.cancel.tx, `https://testnet.near.rocks/tx/${take.cancel.tx}`],
    [take.after.execute_after_the_wait_tx, `https://testnet.near.rocks/tx/${take.after.execute_after_the_wait_tx}`],
    [phone.cancel.tx, `https://testnet.near.rocks/tx/${phone.cancel.tx}`],
  ]);
  // The site links NEAR transactions on the same explorer the README does.
  assert.equal(JSON.parse(read('site/config/testnet.json')).nearTxUrl, 'https://testnet.near.rocks/tx/{}');
  assert.match(read('site/pages/replay/replay.mjs'), /'NEAR testnet': \{ tx: 'https:\/\/testnet\.near\.rocks\/tx\/\{\}' \}/);
  for (const f of ['README.md', 'site/config/testnet.json', 'site/pages/index.html', 'site/pages/replay/replay.mjs']) assert.doesNotMatch(read(f), /nearblocks/, `${f} names one NEAR explorer`);
  // No other hash in the section, and none cut short.
  const long = [...section.matchAll(/\b(?:[0-9a-f]{64}|[1-9A-HJ-NP-Za-km-z]{43,44})\b/g)].map((m) => m[0]);
  assert.deepEqual([...new Set(long)], links.map((l) => l[0]));
  assert.doesNotMatch(section.replace('`358c63bf…`', ''), /…/);
  const items = section.split('\n').filter((l) => l.startsWith('- '));
  assert.equal(items.length, 7);
  // The film's take, from a real phone with the thief tab on a second device: the chain's time, and the device, the
  // browser and Face ID as the author's report. Then the earlier film's take and the one-device run, as before.
  const filmItem = items.splice(3, 1)[0];
  assert.ok(filmItem.startsWith(`- A passkey Cancel from a real phone with the thief tab on a second device, \`${filmTake.cancel.method}\`, on the live pages, ${filmTake.started_utc.slice(0, 10)}, the take the film is cut from, another vault of the same contract, in a block ${Math.floor(filmTake.cancel.block_before_the_unlock_ms / 1000)} s before the thief's request would have unlocked. `), filmItem);
  assert.ok(filmItem.includes('As the author reported it, the passkey was an iPhone\'s, in Safari, with Face ID, and the thief tab ran in headless Chrome on a Mac. No chain says which device held a passkey, and its assertion reads user verified, not how.'), filmItem);
  assert.ok(filmItem.includes('The relay\'s NEAR account sent it; `./verify.sh A` verifies its WebAuthn signature again, under the passkey that vault was made with: '), filmItem);
  assert.equal(filmTake.assertion_as_read.user_verified, true);
  // Its build, from the records: the wasm, the contract, the day.
  assert.ok(g2v1.wasm.sha256.startsWith('358c63bf'));
  assert.ok(section.includes(`Seven transactions of the final build (wasm \`358c63bf…\`, contract \`${g2v1.contract.account}\`), ${take.started_utc.slice(0, 10)} to ${filmTake.started_utc.slice(0, 10)}`));
  assert.equal(filmTake.contract, g2v1.contract.account);
  assert.equal(take.contract, g2v1.contract.account);
  assert.equal(phone.contract, g2v1.contract.account);
  assert.equal(g2v1.cosigned.attempts.find((a) => a.signer_answer).tx_status, 'success');
  // What signed each one.
  assert.ok(items[0].includes(`mined on Mutinynet at height ${g2v1.cosigned.mined_height} with two signatures, the spend key's and the one Chain Signatures gave`));
  assert.deepEqual(g2v1.cosigned.readback.signatures.map((x) => [x.key, x.verified]), [['K_m', true], ['K_u', true]]);
  assert.ok(items[1].includes(`asking \`${g2v1.signer.account}\` to sign`) && items[1].includes('with no page and no relay'));
  assert.equal(Math.round((g2v1.cosigned.unlock - g2v1.cosigned.proposed_at) / 60000), 10, 'a 10:00 wait');
  assert.match(items[1], /11 s after the request's 10:00 unlock/);
  assert.match(read('CLAIMS.md'), new RegExp(`tx \`${execute}\`: its execute, in a block 11 s after that unlock`), 'the 11 s is C01\'s, read from chain by tier A');
  assert.ok(items[2].includes(`mined on Mutinynet at height ${g2v1.escape.mined_height}, ${g2v1.escape.readback.blocks_after_coin} blocks after its coin, with one signature, the cold key's from the recovery file, and no NEAR call`));
  assert.deepEqual(g2v1.escape.readback.signatures.map((x) => [x.key, x.verified]), [['K_e', true]]);
  assert.ok(items[3].includes(`\`${take.cancel.method}\``) && items[3].includes('The passkey was Chrome\'s virtual authenticator, not a phone\'s'));
  assert.ok(items[3].includes('the earlier film\'s take (film v2), 2026-11-11, '), items[3]);
  assert.ok(take.labels.includes('virtual authenticator'));
  // The two times of the take are the chain's: the blocks the cancel and the refused execute ran in, against the unlock.
  const blockMsOf = (hash, test) => Number(BigInt(takeChain.block[takeChain.tx[hash].receipts_outcome.find((x) => x.outcome.executor_id === take.contract && test(x.outcome)).block_hash].header.timestamp_nanosec) / 1_000_000n);
  const before = Math.floor((take.thief.unlock_ms - blockMsOf(take.cancel.tx, (o) => o.logs.includes(take.cancel.log))) / 1000);
  const after = Math.floor((blockMsOf(take.after.execute_after_the_wait_tx, (o) => Boolean(o.status?.Failure)) - take.thief.unlock_ms) / 1000);
  assert.ok(items[3].includes(`in a block ${before} s before the thief's request would have unlocked`), `${before} s`);
  assert.ok(items[3].includes('`./verify.sh A` verifies its WebAuthn signature again, under the passkey the vault was made with'));
  assert.ok(items[4].includes(`in a block ${after} s after its 5:00 wait had run out. The contract refused it, \`${take.after.execute_refusal}\`, and asked the signer for nothing`), `${after} s`);
  assert.equal(take.thief.wait_ms, 300_000);
  assert.match(items[4], /the vault's coin read unspent again on \d{4}-\d\d-\d\d: /);
  // The real phone's cancel: the chain's numbers, the device and browser as the author's report, and no claim that a
  // chain names the device. The code at its block is the final build's: tier A reads it there (C05).
  const phoneBefore = Math.floor(phone.cancel.block_before_the_unlock_ms / 1000);
  assert.equal(phoneBefore, 279);
  assert.ok(items[5].startsWith(`- A passkey Cancel from a real phone, \`${phone.cancel.method}\`, on the live pages, ${phone.vault_made_block_utc.slice(0, 10)}, another vault of the same contract, in a block ${phoneBefore} s before the thief's request would have unlocked. `), items[5]);
  assert.ok(items[5].includes('As the author reported it, the passkey was an iPhone\'s, in Safari, and the thief tab was a second Safari tab on that iPhone; no chain says which device held a passkey, and its assertion reads user verified, not how.'), items[5]);
  assert.ok(items[5].includes('The relay\'s NEAR account sent it; `./verify.sh A` verifies its WebAuthn signature again, under the passkey that vault was made with: '), items[5]);
  assert.equal(phone.device_as_reported.browser, 'Safari');
  assert.equal(phone.assertion_as_read.user_verified, true);
  assert.ok(phone.labels.includes('real device') && !phone.labels.includes('virtual authenticator'));
  assert.notEqual(phone.vault.id, take.vault.id);
  assert.match(phone.read_again, /the contract's code hash at the cancel's block 4c2mcuJj2EA4vZ6v9tNPaoRvvzN4YNRinqj31voAm2P1/);
  assert.equal(g2v1.contract.code_hash, '4c2mcuJj2EA4vZ6v9tNPaoRvvzN4YNRinqj31voAm2P1');
  // All six are fetched again, and the section says where each record is.
  assert.match(section, /`\.\/verify\.sh A` fetches all seven again: the first three are in `proofs\/g2-v1\.json`, the fourth in `proofs\/film-take\.json`, the next two in `proofs\/chrome-take\.json`, the last in `proofs\/phone-take\.json`\./);
  const tierA = read('tools/verify/tier-a.mjs');
  for (const field of ['take.cancel.tx', 'take.vault.create_tx', 't.propose_tx']) assert.ok(tierA.includes(`fetchTx(${field})`), `tier A fetches ${field}`);
  assert.ok(tierA.includes('const hash = take.after.execute_after_the_wait_tx;\n      const tx = await fetchTx(hash);'), 'and the refused execute');
});

test('README: the commands are listed once, with what a SKIP means beside them; the relay\'s accounting, the dated tests and the mainnet numbers each rest on a file', () => {
  const readme = read('README.md');
  // Run it holds the three commands; Try it opens with the site and the cancel steps, and repeats none of them.
  const run = readmeBetween('## Run it', '### See it on chain');
  assert.deepEqual(run.split('\n').filter((l) => l.startsWith('| `')).map((l) => /^\| (`[^`]+`)/.exec(l)[1]), ['`./verify.sh A`', '`./demo.sh`', '`./verify.sh B`']);
  for (const phrase of [
    '`SKIP` means the check did not run, and the line says why.', 'those replay lines then print `SKIP (network)`', 'the run prints `SKIP demo (relay)` and points to `./verify.sh A` and `B`',
    'a throwaway vault with a software passkey, a proposal to a new address, a passkey cancel, and a send back to the vault\'s own address that the live signer signs after its 1:00 wait',
    'No coin moves, but its NEAR calls are real NEAR testnet transactions',
  ]) assert.ok(run.includes(phrase), `beside the Run it table: ${phrase}`);
  // The words quoted are the words printed: demo.sh's skip line starts `SKIP demo`, and its other lines carry a step.
  assert.match(read('tools/demo/demo.mjs'), /console\.log\(`SKIP demo \$\{why\}`\);/);
  assert.match(read('tools/demo/demo.mjs'), /skip\(`\(relay\) no answer from the relay/);
  assert.ok(read('docs/relay.md').includes('`./demo.sh` prints `SKIP demo (relay)` and points to `./verify.sh A` and `B`'));
  for (const f of ['README.md', 'docs/relay.md']) assert.doesNotMatch(read(f), /`SKIP \(relay\)`/, `${f} quotes the line as it is printed`);
  // A claim number is on ./verify.sh's lines; a ./demo.sh line carries its step there, and the paragraph says which is which.
  const reading = run.split('\n').find((l) => l.startsWith('**Reading the lines.**'));
  assert.match(reading, /^\*\*Reading the lines\.\*\* Each `\.\/verify\.sh` line is `PASS`, `SKIP` or `FAIL`, a claim number from \[CLAIMS\.md\]\(CLAIMS\.md\), and a label for where it ran; /);
  assert.ok(reading.includes('A `./demo.sh` line carries its step, `demo-1` to `demo-5`, where the claim number goes.'));
  for (let i = 1; i <= 5; i += 1) assert.ok(read('tools/demo/demo.mjs').includes(`'demo-${i}'`), `demo-${i} is a line demo.sh prints`);
  // The first command's row says what to expect, and that its one FAIL is this entry's own report about itself.
  const rowA = run.split('\n').find((l) => l.startsWith('| `./verify.sh A` |'));
  assert.match(rowA, /^\| `\.\/verify\.sh A` \| 1 to 3 min, [^|]+ \| Expected today: `TIER A: \d+ PASS, 0 SKIP, 1 FAIL, \d+ INFO`, exit 1\. The one FAIL is C11, which this entry reports about itself: /);
  assert.ok(rowA.includes('fetch the live phone page\'s Cancel again and verify its passkey signature here'));
  // The same total is the last one in the row of what was built, so the two cannot drift apart.
  const total = /Expected today: `TIER A: (\d+) PASS/.exec(rowA)[1];
  const builtRow = readme.split('\n').find((l) => l.startsWith('| `verify.sh`, `demo.sh`, `CLAIMS.md` |'));
  assert.ok(builtRow.endsWith(`with the lines for the film's take, from a real phone with the thief tab on a second device (an iPhone, as the author reported it), ${total} PASS and the same FAIL |`), `the last run named there has ${total} PASS`);
  assert.ok(rowA.includes('for the film\'s take and for the one-device run, both from a real phone (an iPhone, as the author reported it), and for the earlier film\'s take in headless Chrome'), 'the three takes are fetched again');
  const tryIt = readmeBetween('## Try it', '### Try a cancel yourself');
  const doCells = tryIt.split('\n').filter((l) => l.startsWith('| ') && !l.startsWith('| Do |')).map((l) => /^\| ([^|]+) \|/.exec(l)[1]);
  assert.equal(doCells[0], 'Open https://undo-btc.pages.dev', 'the site comes first');
  // Each row says what you will see: the film, the replay's six steps, and your own cancel, which a real phone has run twice.
  const seeCells = Object.fromEntries(tryIt.split('\n').filter((l) => l.startsWith('| ') && !l.startsWith('| Do |')).map((l) => l.split(' | ')).map((c) => [c[0].slice(2), c.slice(1).join(' | ')]));
  assert.deepEqual(doCells.slice(0, 3), ['Open https://undo-btc.pages.dev', 'Press **Watch a recorded run** (`/replay/`)', 'Open `/p/` in a browser that has a passkey, then follow the four steps below']);
  assert.match(seeCells['Open https://undo-btc.pages.dev'], /^The film, about a minute, muted until you unmute it: /);
  assert.match(read('site/pages/index.html'), /<video id="film" class="film-video" muted playsinline autoplay loop controls /);
  assert.match(read('site/pages/index.html'), /<a id="replay-link" class="go" href="\/replay\/">Watch a recorded run<\/a>/);
  const replayRow = seeCells['Press **Watch a recorded run** (`/replay/`)'];
  const replay = JSON.parse(read('site/pages/replay/run.json'));
  assert.match(replayRow, /^Six steps from the final build's recorded runs, each with its real hashes from `proofs\/`: /);
  assert.equal(replay.steps.length, 6);
  assert.ok(replayRow.includes('the phone page\'s Cancel (from the film\'s take, another vault of the same contract)') && replay.steps[3].run === 'take');
  assert.ok(replayRow.includes('a request made to wait 10:00') && replayRow.endsWith('Nothing on that page is live |'));
  assert.doesNotMatch(tryIt, /\bG2\b/, 'no term before Terms');
  assert.match(seeCells['Open `/p/` in a browser that has a passkey, then follow the four steps below'], /From a real phone this ran twice, from an iPhone in Safari each time, as the author reported it: with both pages on that iPhone, 2026-11-12, and with the thief tab in headless Chrome on a Mac, 2026-11-13 \(below\) \|$/);
  assert.match(seeCells['Open https://undo-btc.pages.dev'], /Under it, that take's four hashes and three from the final build's run, each linked to an explorer \|$/);
  assert.equal(replay.film.hashes.length, 4);
  // The steps' paragraph says what ran from a real phone, with the chain's hashes and the device as the author's report.
  const steps = readmeBetween('### Try a cancel yourself', '1. On the phone, open https://undo-btc.pages.dev/p/ in Safari or Chrome itself, not inside X or Telegram, and tap **Make a test vault**, then **Confirm with your passkey**: two passkey prompts. This makes a passkey for undo-btc.pages.dev and a vault on NEAR testnet.');
  for (const h of [phone.vault.create_tx, phone.thief.propose_tx, phone.cancel.tx]) assert.ok(steps.includes(`\`${h}\``), h);
  assert.ok(steps.includes('From a real phone this has run twice, on these live pages. First, 2026-11-12, on one device: one iPhone, with the phone page and the thief tab as two Safari tabs on it, as the author reported it (iPhone 13 Pro Max, iOS 27.2.1, Safari; see "On one device" below). What the chains show, which `./verify.sh A` reads again (`proofs/phone-take.json`'), steps);
  assert.ok(steps.includes('Which device held the passkey, no chain says.'), steps);
  // The four steps' path, a phone and the thief tab on a second device, ran from a real phone in the film's take: the
  // phone and Face ID are the author's report, the thief tab was headless Chrome on a Mac pressed by a script, and the
  // hashes are the record's, which tier A reads again.
  assert.ok(steps.includes('Which device held the passkey, no chain says. Then, 2026-11-13, with the thief tab on a second device, the take the film is cut from: the phone page in Safari on an iPhone, with Face ID, as the author reported it, and the thief tab in headless Chrome on a Mac, opened from the thief link the phone page copied, its **Send everything** pressed by a script.'), steps);
  for (const h of [filmTake.vault.create_tx, filmTake.thief.propose_tx, filmTake.cancel.tx]) assert.ok(steps.includes(`\`${h}\``), h);
  assert.ok(steps.includes(`(\`${filmTake.thief.propose_tx}\`), and the phone page's Cancel, \`cancel_all_and_rotate\`, in a block ${Math.floor(filmTake.cancel.block_before_the_unlock_ms / 1000)} s before that unlock (\`${filmTake.cancel.tx}\`)`), steps);
  assert.doesNotMatch(steps, /second device[^.]*\*\*not yet run\*\*/);
  assert.doesNotMatch(read('README.md') + read('CLAIMS.md'), /[Cc]ancell?ed in 41 s|41 s to cancel|in 41 seconds/);
  // The one-device path ran from a real phone: one iPhone, two Safari tabs, the author's report, and the chain's cancel.
  // From a laptop or desktop with its own passkey it still has not.
  const oneDevice = readme.split('\n').find((l) => l.startsWith('**On one device.** '));
  assert.ok(oneDevice.includes(`It ran this way from a real phone, 2026-11-12: one iPhone, with the two pages as two Safari tabs, as the author reported it; the Cancel is NEAR testnet tx \`${phone.cancel.tx}\`, and no chain says which device held its passkey.`), oneDevice);
  assert.ok(oneDevice.includes('It also ran in one headless Chrome with two windows and Chrome\'s virtual authenticator, 2026-11-11 (NEAR testnet tx `GAMM2dVDA7aqiqer2utr1LXoYZEm9ccM8vbHYzZpovPk`, the Cancel).'), oneDevice);
  assert.ok(oneDevice.endsWith('From a laptop or desktop with its own passkey it has **not yet run**.'), oneDevice);
  assert.doesNotMatch(readme, /with a device's own passkey it has \*\*not yet run\*\*/);
  assert.equal(phone.device_as_reported.browser, 'Safari');
  for (const cell of doCells) assert.doesNotMatch(cell, /^`\.\/(verify|demo)\.sh/, 'a command of the Run it table is not listed a second time');
  assert.match(readme, /\n- The agent on a local node: `agent\/test\/run-sandbox\.sh 86 88` /, 'the agent\'s sandbox run is under More');
  // The relay: the paragraph before the steps stops at "So it can be full." and the rest is in the doc it links.
  const before = readmeBetween('### Try a cancel yourself', '1. On the phone, open https://undo-btc.pages.dev/p/ in Safari or Chrome itself, not inside X or Telegram, and tap **Make a test vault**, then **Confirm with your passkey**: two passkey prompts. This makes a passkey for undo-btc.pages.dev and a vault on NEAR testnet.');
  assert.match(before, /So it can be full\. \[docs\/relay\.md\]\(docs\/relay\.md\) has the rest of the relay's accounting\.\n/);
  // Where to open it, and on what: an app's own browser may give no passkey sheet, and the thief tab is laid out for a laptop.
  assert.match(readme, /\n1\. On the phone, open https:\/\/undo-btc\.pages\.dev\/p\/ in Safari or Chrome itself, not inside X or Telegram, and tap /);
  assert.match(readme, /\n\*\*On one device\.\*\* One browser with a passkey is enough, on a phone, a laptop or a desktop: /);
  assert.match(readme, /Copy it before you leave or reload the page: the page holds the spend key only while it is open\./, 'still true: the page stores neither key');
  const relay = read('docs/relay.md');
  for (const moved of ['The coin count can run one over for each relay fault of one kind:', 'a request that stalls for over two minutes before its coin goes out can also end with two coins', 'counts on the earlier day, the day it was charged.']) {
    assert.ok(relay.includes(moved), `docs/relay.md holds: ${moved}`);
    assert.equal(readme.includes(moved), false, 'and the README no longer does');
  }
  // The relay's numbers are in the doc alone now: the README says the limits are shared and points there.
  for (const kept of ['at most 13 new vaults and 20 test coins a day in all', '`CEILING_GENERAL_MICRO=1500000`, `CEILING_FUNDS_SATS=100000`', 'at most 32 new vaults and 50 test coins a day in all', '3 vaults and 2 test coins an hour']) {
    assert.ok(relay.includes(kept), `docs/relay.md says: ${kept}`);
    assert.equal(readme.includes(kept), false, `the README leaves it to docs/relay.md: ${kept}`);
  }
  assert.match(before, /^\nYou need a phone that can make passkeys, and a laptop; or one browser with a passkey and two tabs, on a phone, a laptop or a desktop \(see "On one device" below\)\. The relay pays the NEAR gas, and its daily limits are shared by everyone who tries this, `\.\/demo\.sh` runs included\. So it can be full\. /);
  // The cold key, said without "always": what it needs, and when it can move a coin.
  assert.ok(readme.includes('The cold key in the recovery file needs no relay and, for its exit, no NEAR: it moves a coin only once the coin is older than the timelock.'));
  assert.doesNotMatch(readme, /always works/);
  // The dated tests: the numbers are the measurements file's, with its date and its label.
  const tests = run.split('\n').find((l) => l.startsWith('**Tests behind these.**'));
  const measured = read('docs/measurements.md');
  assert.match(measured, /## Last full run\n\n2026-11-07 UTC, on the wasm below, sandbox with the mock signer/);
  assert.match(measured, /\| `scripts\/protocol-check\.sh` \| 151 passed, 0 failed, on each of protocols 86 and 88/);
  assert.match(measured, /\| `crates\/undo-core\/props\/mutation-check\.py` \| 187 of 187 killed, control green \|/);
  assert.match(measured, /\| `scripts\/shell-mutants\.py`, protocol 88 \| 200 of 200 killed/);
  assert.equal(tests, '**Tests behind these.** Last full local run, 2026-11-07, with a mock signer in place of Chain Signatures ([docs/measurements.md](docs/measurements.md)): 151 sandbox tests passed on each of NEAR protocols 86 and 88, and mutation testing with hand-written one-rule mutants killed 187 of 187 in the core and 200 of 200 in the contract shell. They are not part of `./verify.sh`; see Build under More.');
  assert.doesNotMatch(read('verify.sh'), /protocol-check|mutation-check|shell-mutants/, 'and verify.sh runs none of them');
  // The waits: the test preset's, and the mainnet preset's as the code has them.
  const policy = read('crates/undo-core/src/policy.rs');
  const body = (name) => policy.slice(policy.indexOf(`pub fn ${name}(`), policy.indexOf('\n    }\n', policy.indexOf(`pub fn ${name}(`)));
  assert.match(body('test_coin'), /t_known_ms: MINUTE,\s+t_new_ms: 5 \* MINUTE,\s+t_new_unguarded_ms: 10 \* MINUTE,/);
  assert.match(body('mainnet_proof'), /t_new_ms: 10 \* MINUTE,\s+t_new_unguarded_ms: 20 \* MINUTE,/);
  assert.match(body('mainnet'), /min: Policy \{ fee_cap_tx: 500, fee_budget_24h: 1_000, outflow_cap_24h: 0, \.\.deployed \},\s+max: Policy \{\s+t_known_ms: HOUR,\s+t_new_ms: 24 \* HOUR,\s+t_new_unguarded_ms: 48 \* HOUR,/);
  const preset = readme.split('\n').find((l) => l.startsWith('**5:00 is the test preset.**'));
  for (const phrase of [
    '1:00 to an address the vault knows, 5:00 to a new one and 10:00 with the guard offline, are the test-coin preset\'s',
    'The contract\'s mainnet preset is in the code, not deployed and not run (C19)', 'waits at least 10 minutes, 20 with the guard offline, and a vault can set those as long as 24 and 48 hours',
    'The outflow cap is not a loss limit: over it a known address waits like a new one, nothing is refused, and a send to a new address is never capped.',
  ]) assert.ok(preset.includes(phrase), `the preset paragraph says: ${phrase}`);
  assert.match(read('CLAIMS.md'), /\| C19 \| On mainnet: a co-signed spend, a cancel, a cold-key exit \| — \| — \| — \| \*\*not run\*\*: this build has no mainnet deploy \| — \|/);
});

test('README: the party table is headed as the failure cases it holds, and says what the test page does with the keys; CLAIMS names its live take', () => {
  const readme = read('README.md');
  assert.equal(readme.split('\n').filter((l) => /^## Who can do what/.test(l)).join('|'), '## Who can do what, and what happens if each is gone');
  for (const f of ['README.md', 'CLAIMS.md', 'agent/README.md', 'docs/watch.md', 'docs/relay.md', 'tools/README.md', 'site/pages/index.html']) {
    assert.doesNotMatch(read(f).replaceAll('Who can do what, and what happens if each is gone', ''), /Who can do what/, `${f} names the heading as it is`);
  }
  const table = readmeBetween('## Who can do what, and what happens if each is gone', '**Why not 2-of-3?** If one key is stolen and nobody is watching, 2-of-3 is safer: that thief gets nothing, and Undo\'s thief gets the coins after the wait. Undo makes a different trade. Spending needs no second device or hardware, so it can be used for everyday spending; a public contract controls the second signature, not a company; a phone can cancel during the wait; a cold key leaves alone if NEAR is gone. If you can keep two keys in reach for every spend, use 2-of-3.');
  const row = (start) => table.split('\n').find((l) => l.startsWith(`| ${start}`));
  assert.equal(table.split('\n')[1], '| Party | Alone it can | Alone it cannot | If it is gone |', 'the last column is what happens if each is gone');
  assert.ok(row('Owner\'s phone').includes('On a vault the page made, that means the cold key: the page\'s Cancel swaps in a `K_s` whose secret it does not keep, so save the recovery file first.'));
  assert.ok(row('Cold key (the recovery file; offline once you have saved it and closed the page) |'));
  assert.ok(row('Operator').includes('A changed page could lie, or take the spend key and the cold key: the test page makes both in one tab and holds them while it is open |'));
  assert.doesNotMatch(table, /offline recovery file|take a spend key it holds in your browser/);
  // The same three facts, in the page's code and on the page.
  assert.match(read('site/lib/intents.mjs'), /newVaultKeys\(\{ seed = randomBytes\(32\), cold = randomBytes\(32\) \} = \{\}\)/);
  assert.match(read('site/pages/p/phone.mjs'), /const newKs = spendKeys\(randomBytes\(32\)\)\.ks\.pub;/);
  assert.match(read('site/pages/p/phone.mjs'), /'Save it before your first Cancel'/);
  // The paragraph two rows and the README point to has a name a reader can search for, and is there once.
  const claims = read('CLAIMS.md');
  assert.equal(claims.split('\n').filter((l) => l.startsWith('**Live take.** The pages, live, 2026-11-11, ')).length, 1);
  assert.equal(claims.match(/\(Live take below\)/g).length, 2, 'C05 and C17 point to it');
  assert.match(readme, /the live take in \[CLAIMS\.md\]\(CLAIMS\.md\)/);
  // Another entry shares the name: said once, plainly, with no other product named.
  assert.equal(readme.split('\n').filter((l) => l === '- Name: another entry in this hackathon is also named Undo. It is a different project by a different team.').length, 1);
});

test('the README status line prints the RPC\'s refusal instead of a traceback', () => {
  const code = /python3 -c '([^']+)'/.exec(read('README.md'))[1];
  const decode = (answer) => spawnSync('python3', ['-c', code], { input: JSON.stringify(answer), encoding: 'utf8' });
  const words = Buffer.from('{"ok":true,"lines":[]}');
  assert.equal(decode({ result: { result: [...words] } }).stdout.trim(), words.toString());
  for (const answer of [{ error: { name: 'HANDLER_ERROR', cause: { name: 'UNKNOWN_ACCOUNT' } } }, { result: { error: 'MethodResolveError(MethodNotFound)' } }]) {
    const r = decode(answer);
    assert.equal(r.status, 0, r.stderr);
    assert.equal(r.stderr, '');
    assert.match(r.stdout, /^RPC refused: /);
  }
});
