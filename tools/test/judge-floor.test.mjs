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
import { base58Decode, base58Encode, toHex, utf8 } from '../lib/bytes.mjs';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const read = (p) => readFileSync(join(REPO, p), 'utf8');
const g2 = JSON.parse(read('proofs/g2.json'));
const s2 = JSON.parse(read('proofs/s2-refusal.json'));
// The later run, on the final build: its record, the spend key alone on its vault, and what the chain answered.
const g2v1 = JSON.parse(read('proofs/g2-v1.json'));
const s2v1 = JSON.parse(read('proofs/s2-refusal-v1.json'));
const g2v1Chain = JSON.parse(read('tools/test/fixtures/g2-v1-archival.json'));
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
 * A stand-in for mutinynet.com/api that knows both runs' transactions, with the S2 coin's spender chosen per test.
 * `outspendV1` is the same for the later run's key-alone coin: as recorded unless a test says otherwise. `change`
 * edits what it knows.
 */
function esplora({ outspend, outspendV1 = { spent: true, txid: s2v1.coin_return.mutinynet_txid, vin: 0 }, change = () => {} }) {
  const known = new Map([g2, g2v1].flatMap((p) => [
    [p.cosigned.txid, { hex: p.cosigned.raw, height: p.cosigned.mined_height }],
    [p.escape.txid, { hex: p.escape.raw, height: p.escape.mined_height }],
    [p.escape.coin.split(':')[0], { hex: null, height: p.escape.coin_height }],
  ]));
  change(known);
  const server = createServer((req, res) => {
    const m = /^\/api\/tx\/([0-9a-f]{64})\/(hex|status|outspend\/\d+)$/.exec(req.url);
    const send = (status, body) => {
      res.writeHead(status, { 'content-type': typeof body === 'string' ? 'text/plain' : 'application/json' });
      res.end(typeof body === 'string' ? body : JSON.stringify(body));
    };
    if (!m) return send(404, 'not found');
    const [, txid, what] = m;
    if (what.startsWith('outspend')) return txid === s2.funding_coin.mutinynet_txid ? send(200, outspend) : txid === s2v1.funding_coin.mutinynet_txid ? send(200, outspendV1) : send(404, 'not found');
    const tx = known.get(txid);
    if (!tx) return send(404, 'Transaction not found');
    if (what === 'hex') return tx.hex ? send(200, tx.hex) : send(404, 'no hex here');
    return send(200, { confirmed: true, block_height: tx.height });
  });
  return new Promise((r) => server.listen(0, '127.0.0.1', () => r({ url: `http://127.0.0.1:${server.address().port}/api`, close: () => server.close() })));
}

/**
 * tier-a.mjs with no cargo on PATH, NEAR at a dead port, and Esplora at `esploraUrl`. `archivalUrl` puts a stand-in
 * where the archival RPC is, and `rpcUrl` one where the replay's views go. Async: the stand-ins answer from here.
 */
function tierA({ esploraUrl, referee, archivalUrl = DEAD, rpcUrl = DEAD }) {
  const config = JSON.parse(read('deploy/testnet.json'));
  config.rpc = [DEAD];
  config.replay = { ...config.replay, near_rpc: [rpcUrl], near_archival_rpc: [archivalUrl], mutinynet_esplora: esploraUrl };
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
  // The later run's record is held to the same: its early escape is INFO, and what was not fetched says SKIP.
  assert.ok(r.lines.some((l) => /^INFO C04 \[live-mutinynet, recorded on the final build, \d{4}-\d\d-\d\d\] Final build \(v1\.s\.undo-btc\.testnet\) escape sent before the coin was CSV old/.test(l)), r.out);
  assert.ok(r.lines.some((l) => l.startsWith(`SKIP C12 [replay] proofs/g2-v1.json execute ${v1.execute}: SKIP (network)`)), r.out);
  assert.ok(r.lines.some((l) => l.startsWith(`SKIP C03 [replay] Mutinynet coin ${s2v1.funding_coin.mutinynet_txid}: SKIP (network)`)), r.out);
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
  assert.match(row('C13')[1], /The deployed code hash equals the wasm this machine built/);
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
  assert.match(film, /^\n\[<img src="site\/pages\/film\/poster\.png" width="200" alt="[^"]+">\]\(https:\/\/undo-btc\.pages\.dev\/\)\n\n\[The film\]\(https:\/\/undo-btc\.pages\.dev\/\): one-minute screen recording, on test networks, with a test passkey\.\n$/);
  assert.ok(existsSync(join(REPO, 'site/pages/film/poster.png')));
  assert.match(read('site/pages/index.html'), /<video id="film"[^>]*poster="\/film\/poster\.png"/, 'the page the poster links to plays the film');
  // The problem, in three sentences, and each NEAR feature under its own name with its claim rows.
  const problem = readmeBetween('## Problem', '## How NEAR fits (tracks: open, security, defi)').trim();
  assert.equal(problem, 'A stolen Bitcoin spend key means stolen coins, at once and for good. Multisig stops that only if a second key signs every spend. Undo keeps one-key spending and adds a public wait and a cancel.');
  const fits = readmeBetween('## How NEAR fits (tracks: open, security, defi)', '## Run it');
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
  assert.match(bullets[1], /That ran with software passkeys and Chrome's virtual authenticator, on NEAR testnet with one request pending and on a local node with several; from a real phone: \*\*not yet run\*\*\./);
  assert.match(read('CLAIMS.md'), /Several pending requests killed by one call, on testnet: \*\*not yet run\*\*/, 'C17 says the same of testnet');
  assert.match(bullets[2], /`propose_btc` and `execute` only/);
  assert.match(bullets[3], /All three ran on the final build with Mutinynet test coins, 2026-11-11\./);
  assert.equal(g2v1.cosigned.attempts.at(-1).contract_logs.length > 0 && g2v1.coins[0].recorded_at.slice(0, 10), '2026-11-11');
  assert.equal(bullets[4], '- **Not used:** NEAR Intents, TEE attestation. A NEAR AI model signature checked on testnet is **not yet run** (C08).');
  assert.match(fits, /Track hints this leans on: chain abstraction \(open\), function-call keys and agent security \(security\), Chain Signatures \(defi\)\./);
  assert.match(fits, /^\nEach claim number below is a row of \[CLAIMS\.md\]\(CLAIMS\.md\), with its command, its date and the hash it rests on\.\n/);
  // The earlier build's executes are on another contract account than the final build's, as the bullet says.
  assert.notEqual(g2.contract.account, g2v1.contract.account);
});

test('README, See it on chain: four links, each to a hash its record holds, each saying its build and what signed', () => {
  const take = JSON.parse(read('proofs/film-take.json'));
  const section = readmeBetween('### See it on chain', '## Try it');
  const execute = g2v1.cosigned.attempts.find((a) => a.signer_answer).execute_tx;
  const links = [...section.matchAll(/\[`([^`]+)`\]\((https:\/\/[^)]+)\)/g)].map((m) => [m[1], m[2]]);
  assert.deepEqual(links, [
    [g2v1.cosigned.txid, `https://mutinynet.com/tx/${g2v1.cosigned.txid}`],
    [execute, `https://testnet.near.rocks/tx/${execute}`],
    [g2v1.escape.txid, `https://mutinynet.com/tx/${g2v1.escape.txid}`],
    [take.cancel.tx, `https://testnet.near.rocks/tx/${take.cancel.tx}`],
  ]);
  // No other hash in the section, and none cut short.
  const long = [...section.matchAll(/\b(?:[0-9a-f]{64}|[1-9A-HJ-NP-Za-km-z]{43,44})\b/g)].map((m) => m[0]);
  assert.deepEqual([...new Set(long)], links.map((l) => l[0]));
  assert.doesNotMatch(section.replace('`358c63bf…`', ''), /…/);
  const items = section.split('\n').filter((l) => l.startsWith('- '));
  assert.equal(items.length, 4);
  // Its build, from the records: the wasm, the contract, the day.
  assert.ok(g2v1.wasm.sha256.startsWith('358c63bf'));
  assert.ok(section.includes(`Four transactions of the final build (wasm \`358c63bf…\`, contract \`${g2v1.contract.account}\`), ${take.started_utc.slice(0, 10)}`));
  assert.equal(take.contract, g2v1.contract.account);
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
  assert.ok(take.labels.includes('virtual authenticator'));
  assert.match(section, /`\.\/verify\.sh A` fetches the first three again \(`proofs\/g2-v1\.json`\); the fourth is recorded in `proofs\/film-take\.json`\./);
});

test('README: the commands are listed once, with what a SKIP means beside them; the relay\'s accounting, the dated tests and the mainnet numbers each rest on a file', () => {
  const readme = read('README.md');
  // Run it holds the three commands; Try it opens with the site and the cancel steps, and repeats none of them.
  const run = readmeBetween('## Run it', '### See it on chain');
  assert.deepEqual(run.split('\n').filter((l) => l.startsWith('| `')).map((l) => /^\| (`[^`]+`)/.exec(l)[1]), ['`./verify.sh A`', '`./demo.sh`', '`./verify.sh B`']);
  for (const phrase of [
    '`SKIP` means the check did not run, and the line says why.', 'those replay lines then print `SKIP (network)`', 'the run prints `SKIP (relay)` and points to `./verify.sh A` and `B`',
    'a throwaway vault with a software passkey, a proposal to a new address, a passkey cancel, and a send back to the vault\'s own address that the live signer signs after its 1:00 wait',
    'No coin moves, but its NEAR calls are real NEAR testnet transactions',
  ]) assert.ok(run.includes(phrase), `beside the Run it table: ${phrase}`);
  const tryIt = readmeBetween('## Try it', '### Try a cancel yourself');
  const doCells = tryIt.split('\n').filter((l) => l.startsWith('| ') && !l.startsWith('| Do |')).map((l) => /^\| ([^|]+) \|/.exec(l)[1]);
  assert.equal(doCells[0], 'Open https://undo-btc.pages.dev', 'the site comes first');
  for (const cell of doCells) assert.doesNotMatch(cell, /^`\.\/(verify|demo)\.sh/, 'a command of the Run it table is not listed a second time');
  assert.match(readme, /\n- The agent on a local node: `agent\/test\/run-sandbox\.sh 86 88` /, 'the agent\'s sandbox run is under More');
  // The relay: the paragraph before the steps stops at "So it can be full." and the rest is in the doc it links.
  const before = readmeBetween('### Try a cancel yourself', '1. On the phone, open https://undo-btc.pages.dev/p/ and tap **Make a test vault**, then **Confirm with your passkey**: two passkey prompts. This makes a passkey for undo-btc.pages.dev and a vault on NEAR testnet.');
  assert.match(before, /So it can be full\. \[docs\/relay\.md\]\(docs\/relay\.md\) has the rest of the relay's accounting\.\n/);
  const relay = read('docs/relay.md');
  for (const moved of ['The coin count can run one over for each relay fault of one kind:', 'a request that stalls for over two minutes before its coin goes out can also end with two coins', 'counts on the earlier day, the day it was charged.']) {
    assert.ok(relay.includes(moved), `docs/relay.md holds: ${moved}`);
    assert.equal(readme.includes(moved), false, 'and the README no longer does');
  }
  for (const kept of ['at most 13 new vaults and 20 test coins a day in all', '`CEILING_GENERAL_MICRO=1500000`, `CEILING_FUNDS_SATS=100000`', 'at most 32 new vaults and 50 test coins a day in all', '3 vaults and 2 test coins an hour']) {
    assert.ok(relay.includes(kept) && readme.includes(kept), `both say: ${kept}`);
  }
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
