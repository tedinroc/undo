#!/usr/bin/env node
// Runs tools/g2.mjs against the rig and breaks one thing at a time, then checks the verdict and its
// reason. Real bitcoind with standard relay policy, the real wasm on a local NEAR node, a mock signer.
// Nothing here touches a public network, and nothing here is a G2 result.
//
//   UNDO_TOOLS_CHECK_BIN=... NEAR_SANDBOX_BIN_PATH=... node tools/test/g2-rehearsal.mjs [name filter]
import { spawn, spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { randomBytes, secp256k1 } from '../lib/crypto.mjs';
import { buildFunding, parseDispenser } from '../lib/dispenser.mjs';
import { parseRecovery, buildRecovery } from '../lib/recovery.mjs';
import { addressToSpk, makeTx, p2wshAddress, SEQUENCE_COSIGNED, sighash, witnessScript } from '../lib/btc.mjs';
import { concat, fromHex, toHex } from '../lib/bytes.mjs';
import { publicSecp, spendKeys } from '../lib/keys.mjs';
import { startRig, tamperFinalTx } from './g2-rig.mjs';

const TOOLS = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const REPO = resolve(TOOLS, '..');
const ROOT = join(REPO, 'target', 'g2-rehearsal');
const REAL_PROOF = join(REPO, 'proofs', 'g2.json');
const only = process.argv[2];

let failed = 0;
const table = [];
const check = (name, ok, detail = '') => {
  console.log(`  ${ok ? 'ok  ' : 'BAD '} ${name}${ok ? '' : ` ${detail}`}`);
  if (!ok) failed += 1;
};

// Blocks keep coming while any run is alive: the first of two runs to exit must not stop the other's.
let runsAlive = 0;

function node(args, { rig, env = {}, quiet = true } = {}) {
  return new Promise((res) => {
    const child = spawn(process.execPath, [join(TOOLS, 'g2.mjs'), ...args], { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    child.stdout.on('data', (d) => { out += d; if (!quiet) process.stdout.write(d); });
    child.stderr.on('data', (d) => { out += d; if (!quiet) process.stdout.write(d); });
    child.on('exit', (code) => {
      runsAlive -= 1;
      if (rig && runsAlive === 0) rig.pauseMiner();
      res({ code, out });
    });
    runsAlive += 1;
    if (rig) rig.startMiner();
  });
}

async function main() {
  const rig = await startRig({ log: console.log });
  rmSync(ROOT, { recursive: true, force: true });
  mkdirSync(ROOT, { recursive: true });
  const mainDispenser = parseDispenser(readFileSync(rig.info.dispenser, 'utf8'), 'regtest');

  const paths = (name) => ({
    stateDir: join(ROOT, name),
    proof: join(ROOT, `${name}.json`),
    state: join(ROOT, name, 'state.json'),
    recovery: join(ROOT, name, 'vault-recovery.json'),
    keys: join(ROOT, name, 'vault-keys.json'),
  });
  const driver = (name, flags = []) => {
    const p = paths(name);
    return node(['--regtest', '--rig', rig.infoFile, '--state-dir', p.stateDir, '--out', p.proof, '--mine-timeout-sec', '120', '--sign-timeout-sec', '60', ...flags], { rig });
  };
  const readProof = (name) => JSON.parse(readFileSync(paths(name).proof, 'utf8'));
  const readState = (name) => JSON.parse(readFileSync(paths(name).state, 'utf8'));

  /** Nothing the run must keep private is in anything it writes or prints. */
  const checkSecrets = (name, out) => {
    const p = paths(name);
    const secrets = [mainDispenser.secret && Buffer.from(mainDispenser.secret).toString('hex')];
    if (existsSync(p.keys)) {
      const keys = JSON.parse(readFileSync(p.keys, 'utf8'));
      secrets.push(keys.seed, keys.passkey);
      if ((statSync(p.keys).mode & 0o077) !== 0) check('key file is private', false, name);
    }
    if (existsSync(p.recovery)) {
      try {
        secrets.push(JSON.parse(readFileSync(p.recovery, 'utf8')).cold_key);
      } catch {
        // A scenario damaged it on purpose.
      }
    }
    const texts = [out];
    for (const f of [p.state, p.proof]) if (existsSync(f)) texts.push(readFileSync(f, 'utf8'));
    return secrets.filter(Boolean).every((s) => texts.every((t) => !t.includes(s)));
  };

  const scenario = async (name, fn) => {
    if (only && !name.includes(only)) return;
    console.log(`\n== ${name}`);
    rig.setFault(null);
    rig.setRule(null);
    await rig.mine(1);
    const before = failed;
    await fn();
    table.push({ name, ok: failed === before });
  };
  const verdictOf = (name) => {
    const proof = readProof(name);
    return { pass: proof.summary.pass, reason: proof.summary.failure?.reason ?? null, kill: proof.summary.kill_condition_met };
  };
  const show = (name, r) => {
    let verdict = 'none written';
    if (existsSync(paths(name).proof)) {
      const v = verdictOf(name);
      verdict = v.pass ? 'PASS' : `FAIL ${v.reason ?? 'unfinished'}`;
    }
    console.log(`  verdict ${verdict}, exit ${r.code}`);
  };
  const posts = (kind) => rig.posts.filter((x) => x.kind === kind);
  const CSV = 6;
  const isCosignedPost = (x) => x.method === 'POST' && x.kind === 'cosigned';
  const isEscapePost = (x) => x.method === 'POST' && x.kind === 'escape';
  const isKuControl = (x) => isCosignedPost(x) && x.parsed.inputs[0].witness[1].length === 0;
  const isCsvControl = (x) => isEscapePost(x) && x.parsed.inputs[0].sequence === CSV - 1;
  const isRealCosigned = (x) => isCosignedPost(x) && !isKuControl(x);
  const isRealEscape = (x) => isEscapePost(x) && !isCsvControl(x);
  const refusal = (message) => ({ status: 400, body: `sendrawtransaction RPC error: {"code":-26,"message":"${message}"}` });
  const vaultCoins = async (address) => (await fetch(`${rig.info.esplora}/address/${address}/utxo`)).json();
  const toolsCheck = (file) => spawnSync(process.execPath, [join(TOOLS, 'test', 'check-g2-proof.mjs'), file], { encoding: 'utf8' });

  // ------------------------------------------------------------ the clean run
  await scenario('clean run', async () => {
    const r = await driver('clean');
    show('clean', r);
    const proof = readProof('clean');
    check('exit 0', r.code === 0, r.out);
    check('labelled a rehearsal, not a gate', proof.label === 'rehearsal-regtest-mock-signer' && proof.gate.startsWith('not a gate'));
    check('verdict PASS', proof.summary.pass === true);
    check('co-signed spend read back mined', proof.cosigned.readback?.height > 0);
    check('both signatures strict DER and low S', proof.cosigned.readback?.signatures.length === 2 && proof.cosigned.readback.signatures.every((s) => s.strict_der && s.low_s));
    check('refused by bitcoind itself, non-BIP68-final', proof.escape.early?.refusal === 'bip68' && /non-BIP68-final/.test(proof.escape.early.text), proof.escape.early?.text);
    check('the node, not the stand-in, said it', posts('escape').some((x) => x.node === 400 && /non-BIP68-final/.test(x.text)));
    check('mined at or after maturity', proof.escape.readback?.blocks_after_coin >= proof.csv_blocks);
    check('the same bytes were sent twice', proof.escape.rebuilt_identical === true);
    check('nothing left in the vault', proof.leftovers?.left_sats === 0);
    check('browser: says no real POST was made', proof.browser?.real_browser_post_made === false);
    check('without K_u\'s signature, the node refused it in the script', proof.cosigned.ku_control?.refusal === 'script' && /OP_CHECKSIGVERIFY/.test(proof.cosigned.ku_control.text), proof.cosigned.ku_control?.text);
    check('one block short on a mature coin, the node refused it in the script', proof.escape.csv_control?.refusal === 'script' && /Locktime requirement not satisfied/.test(proof.escape.csv_control.text), proof.escape.csv_control?.text);
    check('both controls came from bitcoind, and both name the check they hit', posts('cosigned').some((x) => x.node === 400 && /OP_CHECKSIGVERIFY/.test(x.text)) && posts('escape').some((x) => x.node === 400 && /Locktime requirement/.test(x.text)) && proof.cosigned.ku_control.names_the_check && proof.escape.csv_control.names_the_check);
    check('the control shares the real spend\'s txid, and the mined bytes are the real ones', proof.cosigned.ku_control.txid === proof.cosigned.txid && proof.cosigned.ku_control.raw !== proof.cosigned.raw);
    check('finished, but the gate is not complete', proof.summary.finished === true && proof.summary.gate_complete === false && proof.summary.gate_missing.join() === 'a browser POST');
    check('the run says so out loud', /G2 IS NOT COMPLETE/.test(r.out), r.out);
    check('no secret in state, proof or output', checkSecrets('clean', r.out));
    check('proofs/g2.json was not written', !existsSync(REAL_PROOF));
    for (const script of ['check-identity.sh', 'secret-scan.sh']) {
      const scan = spawnSync(join(REPO, 'scripts', script), ['--files', paths('clean').proof, paths('clean').state], { encoding: 'utf8' });
      check(`${script} passes on the proof and the state file`, scan.status === 0, scan.stdout);
    }
    const again = await driver('clean');
    check('a re-run of a finished run sends nothing and still says PASS', again.code === 0 && /already finished/.test(again.out));

    // The browser clause, and what can and cannot be recorded for it. Nothing here sends anything.
    const record = (file) => node(['--regtest', '--state-dir', paths('clean').stateDir, '--out', paths('clean').proof, '--record-browser', file]);
    const line = { http_status: 400, text: 'sendrawtransaction RPC error: {"code":-27,"message":"Transaction outputs already in utxo set"}', txid: proof.escape.txid, origin: 'null', at: new Date().toISOString() };
    const answerFile = join(ROOT, 'browser-line.json');
    writeFileSync(answerFile, JSON.stringify({ ...line, txid: '00'.repeat(32) }));
    const stale = await record(answerFile);
    check('a POST for another transaction is refused', stale.code === 3 && readProof('clean').summary.gate_complete === false, stale.out);
    writeFileSync(answerFile, 'not one line of JSON');
    const junk = await record(answerFile);
    check('a file that is not the printed line is refused', junk.code === 3 && readProof('clean').summary.gate_complete === false, junk.out);
    writeFileSync(answerFile, JSON.stringify(line));
    const recorded = await record(answerFile);
    const after = readProof('clean');
    check('a real answer makes the gate complete', recorded.code === 0 && after.summary.gate_complete === true && after.summary.gate_missing.length === 0 && after.browser.real_browser_post_made === true && /a node answered/.test(after.browser.real_post.outcome), recorded.out);
    const keeps = await driver('clean');
    check('and a re-run keeps it', keeps.code === 0 && readProof('clean').summary.gate_complete === true && !/NOT COMPLETE/.test(keeps.out), keeps.out);

    // The proof checker, on this real proof and on edited copies of it.
    const refused = toolsCheck(paths('clean').proof);
    check('the checker refuses a rehearsal\'s proof', refused.status === 1 && /not a live run/.test(refused.stdout), refused.stdout);
    const asLive = { ...after, label: 'live-mutinynet', gate: 'G2', chain_id: 'testnet', bitcoin: { ...after.bitcoin, network: 'mutinynet', genesis: '00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6' } };
    const edited = join(ROOT, 'edited.json');
    const checkEdited = (value) => {
      writeFileSync(edited, JSON.stringify(value));
      return toolsCheck(edited);
    };
    const taken = checkEdited(asLive);
    check('control: the same proof labelled live passes, consensus included', taken.status === 0 && /consensus agrees/.test(taken.stdout), taken.stdout);
    check('a pass with no K_u control is refused', checkEdited({ ...asLive, cosigned: { ...asLive.cosigned, ku_control: undefined } }).status === 1);
    check('a pass with no CSV control is refused', checkEdited({ ...asLive, escape: { ...asLive.escape, csv_control: undefined } }).status === 1);
    check('a complete gate with no browser POST is refused', checkEdited({ ...asLive, browser: { ...asLive.browser, real_post: undefined } }).status === 1);
    check('a control consensus would take is refused', checkEdited({ ...asLive, cosigned: { ...asLive.cosigned, ku_control: { ...asLive.cosigned.ku_control, raw: asLive.cosigned.raw } } }).status === 1);
  });

  // ------------------------------------------------------------ the controls
  await scenario('a script that lets the controls through', async () => {
    // A relay answering for the node stands in for a script without the check. Run against the real wasm,
    // so these show the driver's verdict, and the clean run shows the real node's refusals.
    rig.setRule(async (x) => (isKuControl(x) ? { status: 200, body: x.id } : null));
    const ku = await driver('ku-taken');
    show('ku-taken', ku);
    const kuProof = readProof('ku-taken');
    check('exit 1, reason ku_control_accepted, not the kill line', ku.code === 1 && verdictOf('ku-taken').reason === 'ku_control_accepted' && verdictOf('ku-taken').kill === false, ku.out);
    check('the real spend was never sent', !kuProof.cosigned.broadcast && !rig.posts.some((x) => x.txid === kuProof.cosigned.txid && x.node === 200));
    rig.setRule(async (x) => (isCsvControl(x) ? { status: 200, body: x.id } : null));
    const csv = await driver('csv-taken');
    show('csv-taken', csv);
    const csvProof = readProof('csv-taken');
    check('exit 1, reason csv_control_accepted', csv.code === 1 && verdictOf('csv-taken').reason === 'csv_control_accepted', csv.out);
    check('the real escape was not sent at maturity', !csvProof.escape.broadcast && !rig.posts.some((x) => x.txid === csvProof.escape.txid && x.node === 200));
    rig.setRule(null);
    const again = await driver('csv-taken');
    check('a re-run does not try again', again.code === 1 && /already failed/.test(again.out), again.out);
  });

  await scenario('a control refused for some other reason proves nothing', async () => {
    rig.setRule(async (x) => (isKuControl(x) ? refusal('min relay fee not met, 100 < 121') : null));
    const r = await driver('unclear');
    show('unclear', r);
    const first = readProof('unclear');
    check('exit 1, reason ku_control_unclear, can resume', r.code === 1 && verdictOf('unclear').reason === 'ku_control_unclear' && first.summary.failure.resumable === true, r.out);
    check('not recorded as a refusal', !first.cosigned.ku_control);
    rig.setRule(async (x) => (isCsvControl(x) ? refusal('min relay fee not met, 100 < 121') : null));
    const r2 = await driver('unclear');
    show('unclear', r2);
    const second = readProof('unclear');
    check('then csv_control_unclear', r2.code === 1 && verdictOf('unclear').reason === 'csv_control_unclear' && second.summary.failure.resumable === true && !second.escape.csv_control, r2.out);
    rig.setRule(null);
    const fixed = await driver('unclear');
    show('unclear', fixed);
    const last = readProof('unclear');
    check('resumes and passes, with both real refusals', fixed.code === 0 && last.cosigned.ku_control.refusal === 'script' && last.escape.csv_control.refusal === 'script', fixed.out);
  });

  // ------------------------------------------------------------ stop and resume everywhere
  await scenario('stop and resume at every step', async () => {
    const stops = JSON.parse((await node(['--list-stops'])).out).clean_run;
    let allStopped = true;
    let secretsClean = true;
    for (const stop of stops) {
      const r = await driver('resume', ['--test-stop-at', stop]);
      if (r.code !== 5) {
        allStopped = false;
        console.log(`  did not stop at ${stop}: exit ${r.code}\n${r.out}`);
      }
      secretsClean = secretsClean && checkSecrets('resume', r.out);
    }
    check(`stopped at each of ${stops.length} points, one run per point`, allStopped);
    check('no secret written at any stop', secretsClean);
    const r = await driver('resume');
    show('resume', r);
    const proof = readProof('resume');
    check('the last run finishes with PASS', r.code === 0 && proof.summary.pass === true, r.out);
    check('one vault and two coins, nothing repeated', proof.coins.length === 2);
    const counts = rig.posts.filter((x) => x.txid === proof.cosigned.txid && x.node === 200).length;
    check('the co-signed spend went out once', counts === 1, String(counts));
    check('no secret at the end', checkSecrets('resume', r.out));
  });

  await scenario('killed right after each send, before writing it down', async () => {
    const { crash } = JSON.parse((await node(['--list-stops'])).out);
    let allStopped = true;
    for (const stop of crash) {
      const r = await driver('crash', ['--test-stop-at', stop]);
      if (r.code !== 5) {
        allStopped = false;
        console.log(`  did not stop at ${stop}: exit ${r.code}\n${r.out}`);
      }
    }
    check(`stopped at each of ${crash.length} points`, allStopped);
    const r = await driver('crash');
    show('crash', r);
    const proof = readProof('crash');
    check('the last run finishes with PASS', r.code === 0 && proof.summary.pass === true, r.out);
    check('nothing was done twice: two coins, one request', proof.coins.length === 2 && proof.cosigned.request === 0);
    check('and no stray coin had to be swept up afterwards', proof.leftovers.returned.length === 0);
    check('no earlier stop on the record: each resume found what the chain already had', !proof.summary.earlier_stops, JSON.stringify(proof.summary.earlier_stops));
    const accepted = (id) => rig.posts.filter((x) => x.txid === id && x.node === 200).length;
    check('each transaction reached the node once', accepted(proof.cosigned.txid) === 1 && accepted(proof.escape.txid) === 1);
  });

  // ------------------------------------------------------------ the signer
  await scenario('bad signature from the signer: not a signature at all', async () => {
    rig.setFault('signer-garbage');
    const r = await driver('sig-garbage');
    show('sig-garbage', r);
    const proof = readProof('sig-garbage');
    check('exit 1, reason signer_no_signature', r.code === 1 && verdictOf('sig-garbage').reason === 'signer_no_signature', r.out);
    check('both attempts recorded as a callback without a signature', proof.cosigned.attempts?.length === 2 && proof.cosigned.attempts.every((a) => a.outcome === 'callback_without_signature'));
    check('transaction status said success, and that did not pass it', proof.cosigned.attempts?.every((a) => a.tx_status === 'success'));
    check('nothing was broadcast for it', !proof.cosigned.raw);
    rig.setFault(null);
    const fixed = await driver('sig-garbage');
    show('sig-garbage', fixed);
    check('once the signer is honest, a re-run passes', fixed.code === 0, fixed.out);
    check('the failed attempts stay on the record', readProof('sig-garbage').summary.earlier_stops?.some((s) => s.reason === 'signer_no_signature'));
  });

  await scenario('bad signature from the signer: another key', async () => {
    rig.setFault('signer-wrong-key');
    const r = await driver('sig-wrong');
    show('sig-wrong', r);
    check('exit 1, reason signer_no_signature', r.code === 1 && verdictOf('sig-wrong').reason === 'signer_no_signature', r.out);
    rig.setFault(null);
    const back = await driver('sig-wrong', ['--return-coins']);
    const proof = readProof('sig-wrong');
    check('--return-coins empties the vault by the escape', back.code === 0 && proof.leftovers?.left_sats === 0 && proof.leftovers.returned.length === 1, back.out);
    check('and the verdict stays FAIL', proof.summary.pass === false);
    const again = await driver('sig-wrong');
    check('that run cannot carry on after its coins went home', again.code === 1 && /--new-run/.test(again.out), again.out);
  });

  await scenario('high-S from the signer', async () => {
    rig.setFault('signer-high-s');
    const r = await driver('sig-high');
    show('sig-high', r);
    const proof = readProof('sig-high');
    check('the contract turned it low, so it passes', r.code === 0 && proof.summary.pass === true, r.out);
    check('the record says the signer sent high S', proof.cosigned.signer_s_was_high === true);
    check('low S as mined', proof.cosigned.readback?.signatures.every((s) => s.low_s));
  });

  await scenario('high-S in the final transaction', async () => {
    const r = await driver('final-high', ['--test-fault', 'tamper-final-high-s']);
    show('final-high', r);
    check('exit 1, reason high_s', r.code === 1 && verdictOf('final-high').reason === 'high_s', r.out);
    check('never broadcast', !readProof('final-high').cosigned.raw);
  });

  await scenario('bad signature in the final transaction', async () => {
    const r = await driver('final-bad', ['--test-fault', 'tamper-final-bad-sig']);
    show('final-bad', r);
    check('exit 1, reason bad_signature', r.code === 1 && verdictOf('final-bad').reason === 'bad_signature', r.out);
    check('never broadcast', !readProof('final-bad').cosigned.raw);
  });

  await scenario('the contract and this tool build different bytes', async () => {
    // Both are valid signatures by the right keys, so only the comparison of the bytes can notice.
    const name = 'mismatch';
    const stop = await driver(name, ['--test-stop-at', 'cosign:proposed']);
    check('stopped after proposing', stop.code === 5, stop.out);
    const state = readState(name);
    const c = state.cosigned;
    const [txid, vout] = c.coin.split(':');
    const coin = { txid, vout: Number(vout), value: state.coin_sats };
    const tx = makeTx([coin], SEQUENCE_COSIGNED, [{ value: c.amount, spk: fromHex(c.to) }]);
    const digest = sighash(tx, 0, fromHex(state.vault.script), coin.value);
    const { ku } = spendKeys(fromHex(JSON.parse(readFileSync(paths(name).keys, 'utf8')).seed));
    const other = secp256k1.sign(digest, ku.secret, { lowS: true, prehash: false, extraEntropy: true });
    c.half_sig = toHex(concat(other.toCompactRawBytes(), Uint8Array.of(other.recovery)));
    writeFileSync(paths(name).state, JSON.stringify(state));
    const r = await driver(name);
    show(name, r);
    check('exit 1, reason final_tx_mismatch', r.code === 1 && verdictOf(name).reason === 'final_tx_mismatch', r.out);
    check('never broadcast', !readProof(name).cosigned.raw);
  });

  await scenario('signer silent', async () => {
    rig.setFault('signer-silent');
    const r = await driver('sig-silent', ['--sign-timeout-sec', '4']);
    show('sig-silent', r);
    check('exit 1, reason signer_timeout', r.code === 1 && verdictOf('sig-silent').reason === 'signer_timeout', r.out);
    rig.setFault(null);
    const resumed = await driver('sig-silent');
    show('sig-silent', resumed);
    check('picks up the same request and passes', resumed.code === 0, resumed.out);
    check('one execute was enough', readProof('sig-silent').cosigned.attempts.length === 1);
  });

  await scenario('node rejects a correctly built co-signed spend', async () => {
    rig.setFault('node-rejects-cosigned');
    const r = await driver('kill-line');
    show('kill-line', r);
    const v = verdictOf('kill-line');
    check('exit 1, reason cosigned_rejected_by_node', r.code === 1 && v.reason === 'cosigned_rejected_by_node', r.out);
    check('it reads as G2\'s kill line', v.kill === true);
    const back = await driver('kill-line', ['--return-coins']);
    check('--return-coins gets the coin home', back.code === 0 && readProof('kill-line').leftovers.left_sats === 0, back.out);
  });

  await scenario('relay and node noise on the co-signed spend is not the kill line', async () => {
    const name = 'noise';
    const answers = [
      [{ status: 400, body: 'sendrawtransaction RPC error: {"code":-28,"message":"Loading block index..."}' }, 'relay_unavailable'],
      [{ status: 400, body: 'sendrawtransaction RPC error: {"code":-32603,"message":"Work queue depth exceeded"}' }, 'relay_unavailable'],
      [{ status: 404, body: 'Not Found' }, 'relay_unavailable'],
      [{ status: 413, body: 'Payload Too Large' }, 'relay_unavailable'],
      [refusal('too-long-mempool-chain'), 'cosigned_refused_not_script'],
      [refusal('min relay fee not met, 100 < 121'), 'fee_refused_by_node'],
    ];
    for (const [answer, reason] of answers) {
      rig.setRule(async (x) => (isRealCosigned(x) ? answer : null));
      const r = await driver(name);
      const v = verdictOf(name);
      check(`${answer.status} ${answer.body.slice(-44)}: ${reason}, no kill, can resume`, r.code === 1 && v.reason === reason && v.kill === false && readProof(name).summary.failure.resumable === true, `${v.reason} ${v.kill} ${r.out.slice(-300)}`);
    }
    rig.setRule(null);
    const fixed = await driver(name);
    show(name, fixed);
    check('the same spend passes once the noise stops', fixed.code === 0 && readProof(name).summary.pass === true, fixed.out);
  });

  await scenario('a spend already mined, with the index behind, is not the kill line', async () => {
    const name = 'lagging';
    const stop = await driver(name, ['--test-stop-at', 'crash:cosigned-sent']);
    check('stopped right after sending', stop.code === 5, stop.out);
    const id = readState(name).cosigned.txid;
    await rig.mine(1);
    const until = Date.now() + 6000;
    rig.setRule(async (x) => {
      if (x.method !== 'GET' || Date.now() > until || !x.path.startsWith(`/tx/${id}`)) return null;
      return x.path.endsWith('/status') ? { status: 200, body: '{"confirmed":false}' } : { status: 404, body: 'Transaction not found' };
    });
    const before = rig.posts.length;
    const r = await driver(name);
    show(name, r);
    const v = verdictOf(name);
    check('passes: "already" counted as sent, and waiting decided', r.code === 0 && v.pass === true && v.kill === false, r.out);
    check('the node really did say it already had it', rig.posts.slice(before).some((x) => x.txid === id && x.node === 400 && /already in utxo/i.test(x.text)));
  });

  await scenario('a transaction a relay took and then lost is sent again', async () => {
    const name = 'lost-tx';
    const lied = new Set();
    const once = (kind, x) => {
      if (lied.has(kind)) return null;
      lied.add(kind);
      return { status: 200, body: x.id };
    };
    rig.setRule(async (x) => {
      if (x.method !== 'POST') return null;
      if (x.kind === 'funding') return once('funding', x);
      if (isRealCosigned(x)) return once('cosigned', x);
      // The first escape POST is the early one, which a node has to answer.
      if (isRealEscape(x) && readState(name).escape.csv_control) return once('escape', x);
      return null;
    });
    const r = await driver(name);
    show(name, r);
    const proof = readProof(name);
    check('passes, all three lost once', r.code === 0 && proof.summary.pass === true && lied.size === 3, `${[...lied]} ${r.out}`);
    check('and the record says they went out again', proof.summary.transactions_sent_again_after_being_lost >= 3);
    const nodeTook = (id) => rig.posts.filter((x) => x.txid === id && x.node === 200).length;
    check('each reached the node once', nodeTook(proof.cosigned.txid) === 1 && nodeTook(proof.escape.txid) === 1);
  });

  await scenario('one bad answer from a relay does not end a run', async () => {
    const name = 'one-bad';
    const seen = new Set();
    const first = (key, answer) => {
      if (seen.has(key)) return null;
      seen.add(key);
      return answer;
    };
    rig.setRule(async (x) => {
      if (x.method === 'POST' && x.kind === 'funding') return first('funding post', { status: 404, body: 'Not Found' });
      if (isEscapePost(x) && !isCsvControl(x)) return first('early', { status: 400, body: 'sendrawtransaction RPC error: {"code":-32603,"message":"Work queue depth exceeded"}' });
      if (x.method === 'GET' && /^\/tx\/[0-9a-f]{64}\/hex$/.test(x.path)) return first('hex 404', { status: 404, body: 'Not Found' }) ?? first('hex junk', { status: 200, body: 'not hex at all' });
      if (x.method === 'GET' && /\/outspend\/0$/.test(x.path)) return first('outspend', { status: 200, body: '{"spent":false}' });
      if (x.method === 'GET' && x.path === '/blocks/tip/height') return first('tip 404', { status: 404, body: 'Not Found' }) ?? first('tip empty', { status: 200, body: '' });
      return null;
    });
    const r = await driver(name);
    show(name, r);
    const proof = readProof(name);
    check('passes, with no stop on the record', r.code === 0 && proof.summary.pass === true && !proof.summary.earlier_stops, `${JSON.stringify(proof.summary.earlier_stops)} ${r.out}`);
    check('every bad answer happened', seen.size === 7, [...seen].join());
  });

  // ------------------------------------------------------------ the cold key
  await scenario('a state file gone does not cost the cold key', async () => {
    const name = 'state-gone';
    const stop = await driver(name, ['--test-stop-at', 'fund-cosign:confirmed']);
    check('stopped with a coin in the vault', stop.code === 5, stop.out);
    const { address } = readState(name).vault;
    const coldBefore = readFileSync(paths(name).recovery, 'utf8');
    const keysBefore = readFileSync(paths(name).keys, 'utf8');
    unlinkSync(paths(name).state);
    const r = await driver(name);
    check('exit 3, says why', r.code === 3 && /stray_keys/.test(r.out), r.out);
    check('neither file was written over', readFileSync(paths(name).recovery, 'utf8') === coldBefore && readFileSync(paths(name).keys, 'utf8') === keysBefore);
    check('and no state file came back in its place', !existsSync(paths(name).state));
    await rig.mine(7);
    const back = await driver(name, ['--return-coins']);
    check('--return-coins works from the recovery file alone', back.code === 0 && JSON.parse(readFileSync(join(paths(name).stateDir, 'proof-after-return.json'), 'utf8')).leftovers.left_sats === 0, back.out);
    check('and it did not write over the run\'s own proof', readProof(name).summary.earlier_stops === undefined && !readProof(name).leftovers);
    check('the vault is empty on the node', (await vaultCoins(address)).length === 0);
    const fresh = await driver(name, ['--new-run', '--test-stop-at', 'vault:recorded']);
    check('--new-run moves it aside and starts over', fresh.code === 5, fresh.out);
    const moved = readdirSync(ROOT).filter((f) => f.startsWith(`${name}-`));
    check('with the old cold key kept beside it', moved.length === 1 && readFileSync(join(ROOT, moved[0], 'vault-recovery.json'), 'utf8') === coldBefore);
    check('and a new one in use', readFileSync(paths(name).recovery, 'utf8') !== coldBefore);
  });

  await scenario('a recovery file with no vault named in the state file is left alone', async () => {
    const name = 'half-written';
    await driver(name, ['--test-stop-at', 'vault:recorded']);
    const cold = readFileSync(paths(name).recovery, 'utf8');
    const state = readState(name);
    state.vault = null;
    writeFileSync(paths(name).state, JSON.stringify(state));
    const r = await driver(name);
    check('exit 3, and the file is the same', r.code === 3 && /stray_keys/.test(r.out) && readFileSync(paths(name).recovery, 'utf8') === cold, r.out);
  });

  // ------------------------------------------------------------ --return-coins
  await scenario('--return-coins needs only the recovery file', async () => {
    const name = 'bare';
    const stop = await driver(name, ['--test-stop-at', 'fund-cosign:confirmed']);
    check('stopped with a coin in the vault', stop.code === 5, stop.out);
    const { address } = readState(name).vault;
    await rig.mine(7);
    unlinkSync(paths(name).keys);
    const dead = join(ROOT, 'rig-dead.json');
    writeFileSync(dead, JSON.stringify({ ...rig.info, rpc: 'http://127.0.0.1:9' }));
    const wrongWasm = join(dirname(rig.info.wasm), 'mock_signer.wasm');
    const started = Date.now();
    const look = await node(['--regtest', '--rig', dead, '--state-dir', paths(name).stateDir, '--out', paths(name).proof, '--return-coins'], { rig });
    show(name, look);
    check('with no NEAR RPC and no key file: exit 0, and quickly', look.code === 0 && Date.now() - started < 60_000, look.out);
    check('the vault is empty on the node', (await vaultCoins(address)).length === 0);
    check('the proof says it went home', readProof(name).leftovers.left_sats === 0 && readProof(name).leftovers.returned.length === 1);
    check('a wrong wasm stops nothing either', (await node(['--regtest', '--rig', dead, '--state-dir', paths(name).stateDir, '--out', paths(name).proof, '--return-coins', '--wasm', wrongWasm], { rig })).code === 0);
    const plain = await node(['--regtest', '--rig', dead, '--state-dir', paths(name).stateDir, '--out', paths(name).proof, '--return-coins'], { rig });
    check('and a second try finds nothing and is fine', plain.code === 0, plain.out);
  });

  await scenario('--return-coins handles the runs moved aside too', async () => {
    const name = 'two-runs';
    await driver(name, ['--test-stop-at', 'fund-cosign:confirmed']);
    const first = readState(name).vault.address;
    const second = await driver(name, ['--new-run', '--test-stop-at', 'fund-cosign:confirmed']);
    check('a second run funded its own vault', second.code === 5 && readState(name).vault.address !== first, second.out);
    const secondAddress = readState(name).vault.address;
    await rig.mine(7);
    const r = await driver(name, ['--return-coins']);
    show(name, r);
    check('exit 0', r.code === 0, r.out);
    check('both vaults are empty on the node', (await vaultCoins(first)).length === 0 && (await vaultCoins(secondAddress)).length === 0);
    const moved = readdirSync(ROOT).filter((f) => f.startsWith(`${name}-`));
    check('the moved run has its own record', moved.length === 1 && JSON.parse(readFileSync(join(ROOT, moved[0], 'proof-after-return.json'), 'utf8')).leftovers.left_sats === 0);
  });

  await scenario('a built return whose coin went elsewhere does not block', async () => {
    const name = 'stuck';
    await driver(name, ['--test-stop-at', 'fund-cosign:confirmed']);
    await rig.mine(7);
    const built = await driver(name, ['--return-coins', '--test-stop-at', 'leftovers:built']);
    check('stopped with a return built', built.code === 5, built.out);
    const coin = readState(name).coins[0];
    const list = join(ROOT, 'stuck-list.json');
    writeFileSync(list, JSON.stringify([{ txid: coin.txid, vout: coin.vout, value: coin.value }]));
    const tool = spawnSync(process.execPath, [join(TOOLS, 'escape.mjs'), '--recovery', paths(name).recovery, '--utxos', list, '--to', mainDispenser.address, '--fee', '444'], { encoding: 'utf8' });
    await rig.rpc('sendrawtransaction', [tool.stdout.match(/^hex\s+([0-9a-f]+)$/m)[1]]);
    await rig.mine(1);
    const r = await driver(name, ['--return-coins']);
    show(name, r);
    const { leftovers } = readProof(name);
    check('exit 0, nothing left, and it says what happened', r.code === 0 && leftovers.left_sats === 0 && !leftovers.pending && /spent some other way/.test(leftovers.note), r.out);
  });

  await scenario('two runs on one folder', async () => {
    const name = 'twice';
    await driver(name, ['--test-stop-at', 'vault:active']);
    const [a, b] = await Promise.all([driver(name), driver(name)]);
    const codes = [a.code, b.code].sort().join();
    check('one goes on, the other is refused and says why', codes === '0,3' && /another run is working/.test(`${a.out}${b.out}`), `${codes} ${a.out.slice(-200)} ${b.out.slice(-200)}`);
    check('one coin of each kind', readProof(name).coins.map((c) => c.role).join() === 'cosign,escape');
    check('and the lock is gone', !existsSync(join(paths(name).stateDir, 'lock')));
    writeFileSync(join(paths(name).stateDir, 'lock'), '999999');
    const again = await driver(name);
    check('a dead run\'s lock does not stop a re-run', again.code === 0, again.out);
  });

  await scenario('a 404 on the vault\'s list is not an empty vault', async () => {
    const name = 'utxo-404';
    await driver(name, ['--test-stop-at', 'fund-cosign:confirmed']);
    const { address } = readState(name).vault;
    await rig.mine(7);
    rig.setRule(async (x) => (x.method === 'GET' && x.path === `/address/${address}/utxo` ? { status: 404, body: 'Not Found' } : null));
    const r = await driver(name, ['--return-coins']);
    show(name, r);
    const proof = readProof(name);
    check('exit 1, reason relay_unavailable', r.code === 1 && proof.summary.return_failure?.reason === 'relay_unavailable', r.out);
    check('no claim of 0 sats left', proof.leftovers === null || proof.leftovers?.left_sats === undefined);
    rig.setRule(null);
    check('the coin is still there', (await vaultCoins(address)).length === 1);
    const fixed = await driver(name, ['--return-coins']);
    check('it goes home once the relay answers', fixed.code === 0 && readProof(name).leftovers.left_sats === 0, fixed.out);
  });

  await scenario('a relay error during a return leaves a passing run\'s verdict alone', async () => {
    const name = 'keeps-verdict';
    const r = await driver(name);
    check('passes', r.code === 0, r.out);
    const { address } = readState(name).vault;
    const utxos = await vaultCoins(mainDispenser.address);
    const extra = buildFunding({ dispenser: mainDispenser, utxos, payTo: addressToSpk('regtest', address), value: 20_000, feeRate: 2 });
    await rig.rpc('sendrawtransaction', [extra.raw]);
    await rig.mine(7);
    rig.setRule(async (x) => (x.method === 'GET' && x.path === `/address/${address}/utxo` ? { status: 404, body: 'Not Found' } : null));
    const back = await driver(name, ['--return-coins']);
    const proof = readProof(name);
    check('the return failed, and the run still passes', back.code === 1 && proof.summary.pass === true && !proof.summary.failure && proof.summary.return_failure?.reason === 'relay_unavailable', back.out);
    rig.setRule(null);
    const again = await driver(name, ['--return-coins']);
    const last = readProof(name);
    check('it goes home on the next try, and the failure clears', again.code === 0 && last.leftovers.left_sats === 0 && !last.summary.return_failure && last.summary.pass === true, again.out);
  });

  // ------------------------------------------------------------ the recovery file
  await scenario('wrong recovery file: a good file for another vault', async () => {
    const name = 'recovery-other';
    const stop = await driver(name, ['--test-stop-at', 'fund-escape:confirmed']);
    check('stopped with a fresh coin', stop.code === 5, stop.out);
    const good = readFileSync(paths(name).recovery, 'utf8');
    const state = readState(name);
    const cold = randomBytes(32);
    const script = witnessScript(publicSecp(randomBytes(32)), publicSecp(randomBytes(32)), publicSecp(cold), state.csv);
    writeFileSync(paths(name).recovery, buildRecovery({ network: 'regtest', vaultId: 'another-vault', script, cold }));
    const before = posts('escape').length;
    const r = await driver(name);
    show(name, r);
    check('exit 1, reason wrong_recovery_file', r.code === 1 && verdictOf(name).reason === 'wrong_recovery_file', r.out);
    check('no escape was sent', posts('escape').length === before);
    writeFileSync(paths(name).recovery, good);
    const fixed = await driver(name);
    show(name, fixed);
    check('with the right file back, it resumes and passes', fixed.code === 0, fixed.out);
  });

  await scenario('wrong recovery file: the tool is allowed to try', async () => {
    const name = 'recovery-tool';
    await driver(name, ['--test-stop-at', 'fund-escape:confirmed']);
    const state = readState(name);
    const cold = randomBytes(32);
    const script = witnessScript(publicSecp(randomBytes(32)), publicSecp(randomBytes(32)), publicSecp(cold), state.csv);
    writeFileSync(paths(name).recovery, buildRecovery({ network: 'regtest', vaultId: 'another-vault', script, cold }));
    const before = posts('escape').length;
    const r = await driver(name, ['--test-fault', 'skip-recovery-check']);
    show(name, r);
    check('exit 1, the transaction does not carry the vault script', r.code === 1 && verdictOf(name).reason === 'wrong_witness_script', r.out);
    check('sent nothing to the node', posts('escape').length === before);
  });

  await scenario('wrong recovery file: damaged', async () => {
    const name = 'recovery-damaged';
    await driver(name, ['--test-stop-at', 'fund-escape:confirmed']);
    const damaged = JSON.parse(readFileSync(paths(name).recovery, 'utf8'));
    damaged.vault_id = 'edited-by-hand';
    writeFileSync(paths(name).recovery, JSON.stringify(damaged));
    const r = await driver(name);
    show(name, r);
    check('exit 1, reason recovery_file_refused', r.code === 1 && verdictOf(name).reason === 'recovery_file_refused', r.out);
    check('names the checksum', /Checksum/.test(verdictOf(name).reason + readProof(name).summary.failure.detail));
  });

  await scenario('a damaged key file is not quoted', async () => {
    const name = 'damaged-keys';
    await driver(name, ['--test-stop-at', 'vault:recorded']);
    const good = readFileSync(paths(name).keys, 'utf8');
    const { seed } = JSON.parse(good);
    const canary = `abcdef${seed.slice(6)}`;
    writeFileSync(paths(name).keys, good.replace(`"seed": "${seed}"`, `"seed": ${canary}`));
    const r = await driver(name);
    check('exit 3, says which file', r.code === 3 && /key file is damaged/.test(r.out), r.out);
    check('no part of the seed printed', !r.out.includes(canary.slice(0, 8)) && !r.out.includes(canary.slice(6, 14)), r.out);
  });

  // ------------------------------------------------------------ the early refusal
  await scenario('wrong refusal text on the early escape', async () => {
    rig.setFault('refusal-wrong-text');
    const r = await driver('wrong-text');
    show('wrong-text', r);
    check('exit 1, reason early_refusal_wrong_text', r.code === 1 && verdictOf('wrong-text').reason === 'early_refusal_wrong_text', r.out);
    check('the escape line did not pass', readProof('wrong-text').summary.lines.find((l) => l.name === 'escape_refused_before_maturity').pass === false);
    rig.setFault(null);
    const again = await driver('wrong-text');
    check('a re-run does not try again: it proved something, and it stays failed', again.code === 1 && /already failed/.test(again.out));
    const back = await driver('wrong-text', ['--return-coins']);
    check('--return-coins still gets the coin home', back.code === 0 && readProof('wrong-text').leftovers.left_sats === 0, back.out);
  });

  await scenario('early escape accepted', async () => {
    rig.setFault('early-accepted');
    const r = await driver('early-ok');
    show('early-ok', r);
    check('exit 1, reason early_escape_accepted', r.code === 1 && verdictOf('early-ok').reason === 'early_escape_accepted', r.out);
  });

  await scenario('coin matured before the early try', async () => {
    const name = 'aged';
    const stop = await driver(name, ['--test-stop-at', 'fund-escape:confirmed']);
    check('stopped with a fresh coin', stop.code === 5, stop.out);
    await rig.mine(10);
    const r1 = await driver(name, ['--test-stop-at', 'leftovers:built']);
    check('funds a new coin, proves the refusal on it, stops before returning the old one', r1.code === 5, r1.out);
    rig.setFault('refusal-wrong-text');
    const refused = await driver(name);
    check('a node refusing the return is a failure with its own reason', refused.code === 1 && verdictOf(name).reason === 'return_rejected', refused.out);
    rig.setFault(null);
    const r2 = await driver(name, ['--test-stop-at', 'leftovers:broadcast']);
    check('stops after sending it', r2.code === 5, r2.out);
    const r = await driver(name);
    show(name, r);
    const proof = readProof(name);
    check('passes', r.code === 0 && proof.summary.pass === true, r.out);
    check('the old coin is marked aged', proof.coins.some((c) => c.role === 'aged'));
    check('and it went home by the escape', proof.leftovers.returned.length === 1 && proof.leftovers.left_sats === 0);
  });

  // ------------------------------------------------------------ the relay
  await scenario('relay errors on every broadcast: 503, 429, dropped, HTML', async () => {
    rig.setFault('relay-flaky');
    const r = await driver('flaky');
    show('flaky', r);
    const proof = readProof('flaky');
    check('passes: none of them counted as a rejection', r.code === 0 && proof.summary.pass === true, r.out);
    check('the refusal is still the node\'s own', /non-BIP68-final/.test(proof.escape.early?.text ?? ''));
    check('the answers with no information are counted', proof.summary.relay_answers_with_no_information > 0);
    check('every fault happened', ['503', '429', 'dropped', '502'].every((k) => rig.posts.some((x) => String(x.relay) === k)));
  });

  await scenario('5xx for a POST that landed', async () => {
    rig.setFault('relay-landed-5xx');
    const r = await driver('landed');
    show('landed', r);
    check('passes: it looked before sending again', r.code === 0, r.out);
  });

  await scenario('relay down during the early escape', async () => {
    rig.setFault('relay-down-escape');
    const r = await driver('down-escape');
    show('down-escape', r);
    const proof = readProof('down-escape');
    check('exit 1, reason relay_unavailable', r.code === 1 && verdictOf('down-escape').reason === 'relay_unavailable', r.out);
    check('not recorded as a refusal', !proof.escape.early);
    rig.setFault(null);
    const fixed = await driver('down-escape');
    show('down-escape', fixed);
    check('resumes and passes', fixed.code === 0, fixed.out);
  });

  await scenario('relay down during the co-signed spend', async () => {
    rig.setFault('relay-down-cosigned');
    const r = await driver('down-cosign');
    show('down-cosign', r);
    const v = verdictOf('down-cosign');
    check('exit 1, reason relay_unavailable, not the kill line', r.code === 1 && v.reason === 'relay_unavailable' && !v.kill, r.out);
    rig.setFault(null);
    const fixed = await driver('down-cosign');
    show('down-cosign', fixed);
    check('resumes and passes', fixed.code === 0, fixed.out);
  });

  // ------------------------------------------------------------ refusals before acting
  await scenario('fee over a ceiling', async () => {
    const postsBefore = rig.posts.length;
    const high = await driver('fee-rate', ['--fee-rate', '50']);
    show('fee-rate', high);
    check('--fee-rate 50: exit 3, says why', high.code === 3 && /fee_over_ceiling/.test(high.out), high.out);
    const low = await driver('fee-cap', ['--fee-ceiling', '100']);
    check('--fee-ceiling 100: exit 3, says why', low.code === 3 && /fee_over_ceiling/.test(low.out), low.out);
    check('nothing sent and no state', rig.posts.length === postsBefore && !existsSync(paths('fee-rate').state) && !existsSync(paths('fee-cap').state));
  });

  await scenario('insufficient funds', async () => {
    const postsBefore = rig.posts.length;
    const poor = rig.poorDispenser();
    const empty = await driver('poor-sats', ['--dispenser', poor.path]);
    show('poor-sats', empty);
    check('an empty dispenser: exit 3, says why', empty.code === 3 && /insufficient_sats/.test(empty.out), empty.out);
    const utxos = await (await fetch(`${rig.info.esplora}/address/${mainDispenser.address}/utxo`)).json();
    const built = buildFunding({ dispenser: mainDispenser, utxos, payTo: addressToSpk('regtest', poor.address), value: 5000, feeRate: 2 });
    await rig.rpc('sendrawtransaction', [built.raw]);
    await rig.mine(1);
    const small = await driver('poor-sats', ['--dispenser', poor.path]);
    check('5,000 sats against a 20,000 coin: exit 3', small.code === 3 && /insufficient_sats/.test(small.out), small.out);
    const near = await driver('poor-near', ['--payer', rig.info.poor]);
    show('poor-near', near);
    check('a payer short of NEAR: exit 3, says why', near.code === 3 && /insufficient_near/.test(near.out), near.out);
    check('nothing sent and no state', rig.posts.length === postsBefore && !existsSync(paths('poor-sats').state) && !existsSync(paths('poor-near').state));
  });

  await scenario('refusals on the command line', async () => {
    const writes = await driver('never', ['--out', REAL_PROOF]);
    check('a rehearsal aimed at proofs/g2.json: exit 2', writes.code === 2, writes.out);
    const inside = await driver('never', ['--out', join(REPO, 'proofs', 'history', 'x.json')]);
    check('or anywhere under proofs/: exit 2', inside.code === 2, inside.out);
    check('proofs/g2.json does not exist', !existsSync(REAL_PROOF));
    // These never pass --live: an allow-list refusal has to come before any request, and plan mode writes nothing either way.
    const esplora = await node(['--esplora', 'https://blockstream.info/api']);
    check('plan with an Esplora off the list: exit 3', esplora.code === 3 && /allow list/.test(esplora.out), esplora.out);
    const rpc = await node(['--rpc', 'https://rpc.mainnet.near.org']);
    check('plan with a mainnet RPC: exit 3', rpc.code === 3 && /allow list/.test(rpc.out), rpc.out);
    const both = await node(['--live', '--regtest']);
    check('--live with --regtest: exit 2', both.code === 2, both.out);
    const fault = await node(['--test-fault', 'relay-flaky']);
    check('a test fault outside a rehearsal: exit 2', fault.code === 2, fault.out);
    const stop = await node(['--test-stop-at', 'vault:recorded']);
    check('a test stop outside a rehearsal: exit 2', stop.code === 2, stop.out);
    const rig2 = await node(['--rig', rig.infoFile]);
    check('a rig outside a rehearsal: exit 2', rig2.code === 2, rig2.out);

    // Other ways to reach proofs/. If one of these ever gets through, it is proofs/g2.json that says so below.
    const upper = await driver('never', ['--out', join(REPO, 'PROOFS', 'g2.json')]);
    check('proofs/ in another case on this disk: exit 2', upper.code === 2, upper.out);
    const link = join(ROOT, 'link-to-proofs');
    symlinkSync(join(REPO, 'proofs'), link);
    const linked = await driver('never', ['--out', join(link, 'g2.json')]);
    check('through a link: exit 2', linked.code === 2, linked.out);
    const linkedNew = await driver('never', ['--out', join(link, 'newdir', 'g2.json')]);
    check('through a link and a new folder: exit 2', linkedNew.code === 2, linkedNew.out);
    check('no such file or folder appeared', !existsSync(REAL_PROOF) && !existsSync(join(REPO, 'proofs', 'newdir')));

    // A rehearsal's state folder. Names that do not exist, so a slip here could delete nothing that matters.
    const inProofs = await node(['--regtest', '--state-dir', join(REPO, 'proofs', 'never-here')]);
    check('state under proofs/: exit 2', inProofs.code === 2, inProofs.out);
    const inPrivate = await driver('never', ['--state-dir', join(REPO, 'private', 'never-here')]);
    check('state under private/: exit 2', inPrivate.code === 2, inPrivate.out);
    const canary = join(REPO, 'target', 'g2-canary');
    rmSync(canary, { recursive: true, force: true });
    mkdirSync(canary, { recursive: true });
    writeFileSync(join(canary, 'keep.txt'), 'kept');
    const wiped = await node(['--regtest', '--state-dir', canary]);
    check('a new rig and a folder that is not a rehearsal\'s: exit 2, and it survives', wiped.code === 2 && readFileSync(join(canary, 'keep.txt'), 'utf8') === 'kept', wiped.out);
    writeFileSync(join(canary, 'vault-recovery.json'), '{}');
    const stray = await driver('never', ['--state-dir', canary]);
    check('a rig given, and a folder holding a recovery file: exit 3, and it survives', stray.code === 3 && readFileSync(join(canary, 'vault-recovery.json'), 'utf8') === '{}', stray.out);
    rmSync(canary, { recursive: true, force: true });

    // Flags that would change what a run measures, or could only fail it later.
    const csvOne = await driver('never', ['--csv', '1']);
    check('--csv 1: exit 2, the coin would mature before the early try', csvOne.code === 2, csvOne.out);
    const conf = await driver('never', ['--confirmations', '6']);
    check('--confirmations at the CSV: exit 2', conf.code === 2, conf.out);
    const small = await driver('never', ['--coin-sats', '3000']);
    check('a coin too small to escape: exit 3', small.code === 3 && /coin_too_small/.test(small.out), small.out);
    await driver('flags', ['--test-stop-at', 'vault:recorded']);
    const changed = await driver('flags', ['--fee-rate', '5']);
    check('another fee rate on a resume: exit 2', changed.code === 2, changed.out);

    // The outward gate itself, in a throwaway git folder, since it is what stands before any push.
    const copy = join(ROOT, 'outward');
    mkdirSync(join(copy, 'tools', 'test'), { recursive: true });
    mkdirSync(join(copy, 'proofs'));
    cpSync(join(REPO, 'scripts'), join(copy, 'scripts'), { recursive: true });
    cpSync(join(TOOLS, 'test', 'check-g2-proof.mjs'), join(copy, 'tools', 'test', 'check-g2-proof.mjs'));
    spawnSync('git', ['init', '-q'], { cwd: copy });
    spawnSync('git', ['add', '-A'], { cwd: copy });
    const outward = () => spawnSync(join(copy, 'scripts', 'outward-check.sh'), ['--wasm', rig.info.wasm], { encoding: 'utf8', env: { ...process.env, UNDO_BLOCKED_WORDS: resolve(REPO, '../plan/blocked-words.txt') } });
    const empty = outward();
    check('control: the gate passes with no G2 proof', empty.status === 0, `${empty.stdout}${empty.stderr}`);
    const rehearsalProof = { schema: 'undo-g2-v1', label: 'rehearsal-regtest-mock-signer', gate: 'not a gate result', summary: { pass: true, gate_complete: false } };
    writeFileSync(join(copy, 'proofs', 'g2.json'), JSON.stringify(rehearsalProof));
    const planted = outward();
    check('the gate refuses a rehearsal\'s proof at proofs/g2.json', planted.status !== 0 && /not a live run/.test(planted.stdout), planted.stdout);
    unlinkSync(join(copy, 'proofs', 'g2.json'));
    mkdirSync(join(copy, 'proofs', 'newdir'));
    writeFileSync(join(copy, 'proofs', 'newdir', 'copy.json'), JSON.stringify(rehearsalProof));
    const nested = outward();
    check('and under any other name there', nested.status !== 0 && /a rehearsal's proof is in proofs/.test(nested.stdout), nested.stdout);
  });

  // ------------------------------------------------------------ the node, directly
  await scenario('the node really refuses what the local checks refuse', async () => {
    // Without this, a local check could be stricter or looser than relay policy and nothing would show.
    const name = 'node-control';
    await driver(name, ['--test-stop-at', 'vault:active']);
    const file = parseRecovery(readFileSync(paths(name).recovery, 'utf8'));
    const utxos = await (await fetch(`${rig.info.esplora}/address/${mainDispenser.address}/utxo`)).json();
    const built = buildFunding({ dispenser: mainDispenser, utxos, payTo: addressToSpk('regtest', file.address), value: 20_000, feeRate: 2 });
    await rig.rpc('sendrawtransaction', [built.raw]);
    await rig.mine(7);
    const list = join(paths(name).stateDir, 'list.json');
    writeFileSync(list, JSON.stringify([{ txid: built.txid, vout: 0, value: 20_000 }]));
    const tool = await new Promise((res) => {
      const child = spawn(process.execPath, [join(TOOLS, 'escape.mjs'), '--recovery', paths(name).recovery, '--utxos', list, '--to', mainDispenser.address, '--fee', '300'], { stdio: ['ignore', 'pipe', 'ignore'] });
      let out = '';
      child.stdout.on('data', (d) => { out += d; });
      child.on('exit', () => res(out));
    });
    const raw = tool.match(/^hex\s+([0-9a-f]+)$/m)[1];
    const accept = async (hex) => (await rig.rpc('testmempoolaccept', [[hex]]))[0];
    const high = await accept(tamperFinalTx(raw, 'high-s'));
    check(`bitcoind refuses high S (${high['reject-reason']})`, high.allowed === false && /S value is unnecessarily high/i.test(high['reject-reason']), JSON.stringify(high));
    const bad = await accept(tamperFinalTx(raw, 'bad-sig'));
    check(`bitcoind refuses a bad signature (${bad['reject-reason']})`, bad.allowed === false, JSON.stringify(bad));
    const good = await accept(raw);
    check('control: the untouched transaction is allowed under standard policy', good.allowed === true, JSON.stringify(good));
    check('standard policy is on', (await rig.rpc('getnetworkinfo')).version >= 320000 && p2wshAddress('regtest', file.script) === file.address);
  });

  await rig.stop();
  console.log('\nScenario table:');
  for (const row of table) console.log(`  ${row.ok ? 'PASS' : 'FAIL'} ${row.name}`);
  if (failed) {
    console.log(`\nREHEARSAL FAILED: ${failed} checks`);
    process.exit(1);
  }
  console.log(`\nREHEARSAL OK: ${table.length} scenarios [regtest, mock signer. Not a G2 result]`);
}

main().catch((err) => {
  console.error(`rehearsal stopped: ${err.stack}`);
  process.exit(1);
});
