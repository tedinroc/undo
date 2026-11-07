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
import { toHex, utf8 } from '../lib/bytes.mjs';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const read = (p) => readFileSync(join(REPO, p), 'utf8');
const g2 = JSON.parse(read('proofs/g2.json'));
const s2 = JSON.parse(read('proofs/s2-refusal.json'));
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
  for (const [checker, file, want] of [['check-g2-proof.mjs', 'g2.json', /G2 PROOF OK: chain lines pass, gate_complete true, consensus agrees/], ['check-g1-proof.mjs', 'g1.json', /^PASS \[consensus-lib\] \d+ final transactions accepted/m]]) {
    const r = spawnSync(process.execPath, [join(REPO, 'tools/test', checker), join(REPO, 'proofs', file)], { encoding: 'utf8', env: { ...process.env, UNDO_TOOLS_CHECK_BIN: REFEREE } });
    assert.equal(r.status, 0, r.stdout);
    assert.match(r.stdout, want);
  }
});

// ---------------------------------------------------------------- tier A against a stand-in Esplora

const DEAD = 'http://127.0.0.1:9';

/** A stand-in for mutinynet.com/api that knows the G2 transactions, with the S2 coin's spender chosen per test. */
function esplora({ outspend }) {
  const known = new Map([
    [g2.cosigned.txid, { hex: g2.cosigned.raw, height: g2.cosigned.mined_height }],
    [g2.escape.txid, { hex: g2.escape.raw, height: g2.escape.mined_height }],
    [g2.escape.coin.split(':')[0], { hex: null, height: g2.escape.coin_height }],
  ]);
  const server = createServer((req, res) => {
    const m = /^\/api\/tx\/([0-9a-f]{64})\/(hex|status|outspend\/\d+)$/.exec(req.url);
    const send = (status, body) => {
      res.writeHead(status, { 'content-type': typeof body === 'string' ? 'text/plain' : 'application/json' });
      res.end(typeof body === 'string' ? body : JSON.stringify(body));
    };
    if (!m) return send(404, 'not found');
    const [, txid, what] = m;
    if (what.startsWith('outspend')) return txid === s2.funding_coin.mutinynet_txid ? send(200, outspend) : send(404, 'not found');
    const tx = known.get(txid);
    if (!tx) return send(404, 'Transaction not found');
    if (what === 'hex') return tx.hex ? send(200, tx.hex) : send(404, 'no hex here');
    return send(200, { confirmed: true, block_height: tx.height });
  });
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r({ url: `http://127.0.0.1:${server.address().port}/api`, close: () => server.close() })));
}

/** tier-a.mjs with no cargo on PATH, NEAR at a dead port, and Esplora at `esploraUrl`. Async: the stand-in answers from here. */
function tierA({ esploraUrl, referee }) {
  const config = JSON.parse(read('deploy/testnet.json'));
  config.rpc = [DEAD];
  config.replay = { ...config.replay, near_rpc: [DEAD], near_archival_rpc: [DEAD], mutinynet_esplora: esploraUrl };
  const path = join(work, `tier-a-${Math.random().toString(36).slice(2)}.json`);
  writeFileSync(path, JSON.stringify(config));
  const env = { PATH: `${dirname(process.execPath)}:/usr/bin:/bin`, HOME: work, TMPDIR: work };
  if (referee) env.UNDO_TOOLS_CHECK_BIN = referee;
  return new Promise((done) => {
    const child = spawn(process.execPath, [join(REPO, 'tools/verify/tier-a.mjs'), '--config', path], { env });
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
  // The consensus checks still run on the raw hex in proofs/.
  assert.ok(r.lines.some((l) => /^PASS C02 \[consensus-lib\]/.test(l)), r.out);
  assert.ok(r.lines.some((l) => /^SKIP C12 \[live-testnet\] signer arguments: SKIP \(network\)/.test(l)), r.out);
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

test('README and CLAIMS: no TODO, the agent and watcher are reachable, C14 claims no testnet run, C13 claims only the hash', () => {
  const readme = read('README.md');
  const claims = read('CLAIMS.md');
  assert.doesNotMatch(readme, /TODO/);
  assert.match(readme, /\[agent\/README\.md\]\(agent\/README\.md\)/);
  assert.match(readme, /\[docs\/watch\.md\]\(docs\/watch\.md\)/);
  assert.match(readme, /written in the window, except the vendored libraries/);
  const row = (id) => claims.split('\n').find((l) => l.startsWith(`| ${id} |`)).split(' | ');
  assert.equal(row('C14')[4], '`[mock-signer]`', 'C14 ran on a local sandbox only');
  assert.match(row('C14')[2], /agent\/test\/run-sandbox\.sh 86 88/);
  assert.match(row('C13')[1], /The deployed code hash equals the wasm this machine built/);
  assert.doesNotMatch(claims, /current build/, 'every build is named by what it was built from');
  for (const f of ['agent/README.md', 'docs/watch.md']) assert.ok(existsSync(join(REPO, f)), f);
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
