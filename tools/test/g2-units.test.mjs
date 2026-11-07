// Offline tests of what G2 decides with. Run with: node --test tools/test/g2-units.test.mjs
// Needs UNDO_TOOLS_CHECK_BIN. Test keys come from public labels or are thrown away here.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { makeTx, p2wpkhAddress, p2wshSpk, parseTx, SEQUENCE_COSIGNED, serialize, sighash, witnessScript, derSig, txid } from '../lib/btc.mjs';
import { fromHex, toHex, utf8 } from '../lib/bytes.mjs';
import { secp256k1, sha256 } from '../lib/crypto.mjs';
import { buildFunding, parseDispenser, selectCoins } from '../lib/dispenser.mjs';
import { checkEndpoints, classifyBroadcast, EndpointRefused, Esplora, RelayError, refusalKind } from '../lib/esplora.mjs';
import { assembleCosigned, checkCosigned, checkEscape, checkReadback, checkSig, cosignedVsize, escapeOneShort, escapeVsize, isHighS, matureTip, strictDerProblem, withoutKmSig, withoutKuSig, witnessHexOf } from '../lib/g2-check.mjs';
import { keyAloneHalfSig } from '../lib/spend.mjs';
import { publicSecp, spendKeys } from '../lib/keys.mjs';
import { loadKeyFile, Near } from '../lib/near.mjs';
import { tamperFinalTx } from './g2-rig.mjs';

const BIN = process.env.UNDO_TOOLS_CHECK_BIN;
assert.ok(BIN, 'set UNDO_TOOLS_CHECK_BIN');
const secret = (label) => sha256(utf8(`undo-test-only:g2-units:${label}`));
const sign = (digest, key) => derSig(secp256k1.sign(digest, key, { lowS: true, prehash: false }).toCompactRawBytes());
const rs = (digest, key) => secp256k1.sign(digest, key, { lowS: true, prehash: false }).toCompactRawBytes();
const verify = (hex, spk, value) => spawnSync(BIN, ['verify', hex, spk, String(value)], { encoding: 'utf8' }).status;

const ku = secret('k_u');
const km = secret('k_m');
const ke = secret('k_e');
const CSV = 6;
const script = witnessScript(publicSecp(ku), publicSecp(km), publicSecp(ke), CSV);
const spk = p2wshSpk(script);
const to = fromHex(`0014${toHex(sha256(utf8('dest'))).slice(0, 40)}`);
const coin = { txid: 'ab'.repeat(32), vout: 1, value: 20_000 };
const amount = 19_700;

function cosigned() {
  const tx = makeTx([coin], SEQUENCE_COSIGNED, [{ value: amount, spk: to }]);
  const digest = sighash(tx, 0, script, coin.value);
  const mpcRs = rs(digest, km);
  const halfRs = rs(digest, ku);
  return { hex: assembleCosigned({ coin, to, amount, mpcRs, halfRs, script }), digest, mpcRs, halfRs };
}
function escape() {
  const tx = makeTx([coin], CSV, [{ value: amount, spk: to }]);
  tx.inputs[0].witness = [sign(sighash(tx, 0, script, coin.value), ke), new Uint8Array(0), script];
  return toHex(serialize(tx));
}
const checkOf = (hex) => checkCosigned({ rawHex: hex, coin, to, amount, script, km: publicSecp(km), ku: publicSecp(ku) });
const escapeOf = (hex) => checkEscape({ rawHex: hex, coin, to, amount, script, csv: CSV, ke: publicSecp(ke) });

// ---------------------------------------------------------------- the refusal decides the gate

test('only a node\'s non-BIP68-final counts as the right refusal', () => {
  assert.equal(refusalKind('sendrawtransaction RPC error: {"code":-26,"message":"non-BIP68-final"}'), 'bip68');
  assert.equal(refusalKind('non-BIP68-final (code 64)'), 'bip68');
  assert.equal(refusalKind('sequence locks not met'), 'bip68');
  assert.notEqual(refusalKind('mandatory-script-verify-flag-failed (Locktime requirement not satisfied)'), 'bip68');
  assert.notEqual(refusalKind('min relay fee not met, 100 < 121'), 'bip68');
  assert.notEqual(refusalKind('bad-txns-inputs-missingorspent'), 'bip68');
  assert.notEqual(refusalKind(''), 'bip68');
  assert.equal(refusalKind('txn-already-in-mempool'), 'already');
  assert.equal(refusalKind('bad-txns-inputs-missingorspent'), 'inputs_gone');
  assert.equal(refusalKind('mandatory-script-verify-flag-failed (x)'), 'script');
  assert.equal(refusalKind('anything else'), 'other');
  assert.equal(refusalKind('Transaction outputs already in utxo set'), 'already');
  assert.equal(refusalKind('txn-same-nonwitness-data-in-mempool'), 'already');
  assert.equal(refusalKind('mempool-script-verify-flag-failed (Locktime requirement not satisfied), input 0'), 'script');
  assert.equal(refusalKind('mempool-script-verify-flag-failed (Script failed an OP_CHECKSIGVERIFY operation), input 0'), 'script');
  assert.equal(refusalKind('too-long-mempool-chain'), 'other');
});

test('a 5xx, a 429, a block page or a redirect is no answer about the transaction', () => {
  const id = 'cd'.repeat(32);
  for (const [status, body] of [[500, ''], [502, 'non-BIP68-final'], [503, 'Service Unavailable'], [504, ''], [429, 'Too Many'], [408, ''], [403, 'blocked'], [302, ''], [400, '<html>Bad Request</html>'], [404, 'Not Found'], [413, 'Payload Too Large'], [401, 'no'], [404, 'non-BIP68-final'],
    [400, 'sendrawtransaction RPC error: {"code":-28,"message":"Loading block index..."}'], [400, 'sendrawtransaction RPC error: {"code":-32603,"message":"Work queue depth exceeded"}']]) {
    assert.equal(classifyBroadcast(status, body, id).kind, 'transient', `HTTP ${status}`);
  }
  assert.equal(classifyBroadcast(200, 'not a txid', id).kind, 'transient');
  assert.equal(classifyBroadcast(200, 'ef'.repeat(32), id).kind, 'transient', 'a 2xx naming another transaction');
  assert.equal(classifyBroadcast(200, `${id}\n`, id).kind, 'accepted');
  const refused = classifyBroadcast(400, 'sendrawtransaction RPC error: {"code":-26,"message":"non-BIP68-final"}', id);
  assert.equal(refused.kind, 'rejected');
  assert.equal(refused.refusal, 'bip68');
  assert.equal(classifyBroadcast(400, 'min relay fee not met', id).refusal, 'other');
  assert.equal(classifyBroadcast(400, 'sendrawtransaction RPC error: {"code":-26,"message":"too-long-mempool-chain"}', id).kind, 'rejected');
});

// A relay that does what it is told, for the retry path.
let server;
let base;
let answers = [];
let found = null;
let reads = [];
before(async () => {
  server = createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      if (reads.length > 0) {
        const next = reads.shift();
        res.writeHead(next.status);
        res.end(next.body);
        return;
      }
      if (req.url.startsWith('/tx/') && req.method === 'GET') {
        res.writeHead(found ? 200 : 404);
        res.end(found ? JSON.stringify(found) : 'none');
        return;
      }
      const next = answers.shift();
      if (next === 'drop') {
        req.socket.destroy();
        return;
      }
      res.writeHead(next?.status ?? 503);
      res.end(next?.body ?? 'no');
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

test('broadcast retries a 5xx and a 429 and a dropped connection, then returns the node\'s answer', async () => {
  const id = '11'.repeat(32);
  answers = [{ status: 503, body: 'non-BIP68-final' }, { status: 429 }, 'drop', { status: 400, body: '{"code":-26,"message":"non-BIP68-final"}' }];
  const e = new Esplora(base, { backoffMs: 1, attempts: 8 });
  const answer = await e.broadcast('00', id);
  assert.equal(answer.kind, 'rejected');
  assert.equal(answer.refusal, 'bip68');
  assert.equal(e.transient, 3);
});

test('broadcast gives up with RelayError, never a rejection, when no node ever answers', async () => {
  answers = Array.from({ length: 8 }, () => ({ status: 503, body: 'non-BIP68-final' }));
  const e = new Esplora(base, { backoffMs: 1, attempts: 3 });
  await assert.rejects(e.broadcast('00', '22'.repeat(32)), RelayError);
});

test('broadcast treats already-in-mempool as accepted only if the transaction can be read', async () => {
  const id = '33'.repeat(32);
  const e = new Esplora(base, { backoffMs: 1, attempts: 3 });
  answers = [{ status: 400, body: 'txn-already-in-mempool' }];
  assert.equal((await e.broadcast('00', id)).kind, 'rejected', 'nothing to read here, so it is not taken on faith');
  answers = [{ status: 400, body: 'txn-already-in-mempool' }];
  found = { txid: id };
  assert.equal((await e.broadcast('00', id)).kind, 'accepted');
  found = null;
});

test('a 5xx for a POST that landed is found by looking, not by sending again', async () => {
  const id = '55'.repeat(32);
  const e = new Esplora(base, { backoffMs: 1, attempts: 3 });
  answers = [{ status: 502 }];
  found = { txid: id };
  const answer = await e.broadcast('00', id);
  found = null;
  assert.equal(answer.kind, 'accepted');
  assert.equal(answer.landed_despite, true);
  assert.equal(answers.length, 0);
});

test('a 404 or an empty answer is the relay\'s gap, never a height of 0 or an empty vault', async () => {
  const e = new Esplora(base, { backoffMs: 1, attempts: 2 });
  const bad = (body, status = 200) => ({ status, body });
  for (const answers2 of [[bad('', 404), bad('', 404)], [bad(''), bad('')], [bad('  \n'), bad('not a height')]]) {
    reads = answers2;
    await assert.rejects(e.tip(), RelayError);
  }
  reads = [bad('', 404), bad('812\n')];
  assert.equal(await e.tip(), 812);
  assert.equal(e.transient > 0, true);
  for (const answers2 of [[bad('', 404), bad('', 404)], [bad('{"a":1}'), bad('null')], [bad('not json'), bad('')]]) {
    reads = answers2;
    await assert.rejects(e.utxos('x'), RelayError);
  }
  reads = [bad('[]')];
  assert.deepEqual(await e.utxos('x'), [], 'a real empty list stays one');
  reads = [bad('', 404)];
  assert.equal(await e.txHex('x'), null);
  reads = [bad('not hex at all')];
  assert.equal(await e.txHex('x'), null);
  reads = [bad('ABCD\n')];
  assert.equal(await e.txHex('x'), 'abcd');
  reads = [];
});

test('a redirect is not followed: raw bytes stay on the allow-listed host', async () => {
  const hits = [];
  const other = createServer((req, res) => { hits.push(req.url); res.end('x'); });
  await new Promise((r) => other.listen(0, '127.0.0.1', r));
  const redirector = createServer((req, res) => {
    res.writeHead(307, { location: `http://127.0.0.1:${other.address().port}/tx` });
    res.end();
  });
  await new Promise((r) => redirector.listen(0, '127.0.0.1', r));
  const e = new Esplora(`http://127.0.0.1:${redirector.address().port}`, { backoffMs: 1, attempts: 2 });
  // Closed either way: a server left open would hang the runner, and the failure would read as a timeout.
  try {
    await assert.rejects(e.broadcast('00', '44'.repeat(32)), RelayError);
    assert.equal(hits.length, 0);
  } finally {
    redirector.close();
    other.close();
  }
});

test('NEAR calls do not follow a redirect either', async () => {
  const hits = [];
  const other = createServer((req, res) => { hits.push(req.url); res.end('{}'); });
  await new Promise((r) => other.listen(0, '127.0.0.1', r));
  const redirector = createServer((req, res) => {
    res.writeHead(307, { location: `http://127.0.0.1:${other.address().port}/` });
    res.end();
  });
  await new Promise((r) => redirector.listen(0, '127.0.0.1', r));
  try {
    await assert.rejects(new Near(`http://127.0.0.1:${redirector.address().port}`).rpcOnce(`http://127.0.0.1:${redirector.address().port}`, 'status', []));
    assert.equal(hits.length, 0);
  } finally {
    redirector.close();
    other.close();
  }
});

test('a damaged NEAR key file is not quoted back', () => {
  const dir = mkdtempSync(join(tmpdir(), 'undo-g2-units-'));
  const path = join(dir, 'k.json');
  writeFileSync(path, '{"account_id":"a","private_key":ed25519:SECRETWORDS}');
  try {
    assert.throws(() => loadKeyFile(path), (err) => !err.message.includes('SECRETWORDS') && !err.message.includes('ed25519'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- allow lists

test('live takes exact names from the allow lists, a rehearsal only this machine', () => {
  const good = { regtest: false, esplora: 'https://mutinynet.com/api', rpc: ['https://test.rpc.fastnear.com', 'https://rpc.testnet.near.org'] };
  assert.doesNotThrow(() => checkEndpoints(good));
  for (const esplora of ['https://blockstream.info/api', 'https://mempool.space/api', 'https://mutinynet.com/api/', 'http://mutinynet.com/api', 'https://mutinynet.com.evil.example/api', 'not a url']) {
    assert.throws(() => checkEndpoints({ ...good, esplora }), EndpointRefused, esplora);
  }
  for (const url of ['https://rpc.mainnet.near.org', 'https://free.rpc.fastnear.com', 'http://127.0.0.1:3030']) {
    assert.throws(() => checkEndpoints({ ...good, rpc: [url] }), EndpointRefused, url);
  }
  const local = { regtest: true, esplora: 'http://127.0.0.1:9', rpc: ['http://127.0.0.1:3030'] };
  assert.doesNotThrow(() => checkEndpoints(local));
  assert.throws(() => checkEndpoints({ ...local, esplora: 'https://mutinynet.com/api' }), EndpointRefused);
  assert.throws(() => checkEndpoints({ ...local, rpc: ['https://test.rpc.fastnear.com'] }), EndpointRefused);
});

// ---------------------------------------------------------------- signatures

test('strict DER matches what consensus refuses', () => {
  const { hex } = cosigned();
  assert.equal(checkOf(hex).problem, undefined);
  assert.equal(verify(hex, toHex(spk), coin.value), 0);
  const tx = parseTx(fromHex(hex));
  const sig = tx.inputs[0].witness[0];
  const edit = (fn) => {
    const copy = Uint8Array.from(sig);
    return fn(copy) ?? copy;
  };
  const cases = {
    'no sequence tag': edit((c) => { c[0] = 0x31; }),
    'sequence length': edit((c) => { c[1] += 1; }),
    'r tag': edit((c) => { c[2] = 3; }),
    'negative r': edit((c) => { c[4] = 0x80; }),
    's tag': edit((c) => { c[c[3] + 4] = 3; }),
    'total length': sig.slice(0, -2),
    length: new Uint8Array(5),
  };
  for (const [name, bad] of Object.entries(cases)) assert.ok(strictDerProblem(bad), name);
  assert.equal(strictDerProblem(sig), null);
  const paddedR = Uint8Array.of(0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01, 0x01);
  assert.equal(strictDerProblem(paddedR), 'padded r');
  const paddedS = Uint8Array.of(0x30, 0x07, 0x02, 0x01, 0x01, 0x02, 0x02, 0x00, 0x01, 0x01);
  assert.equal(strictDerProblem(paddedS), 'padded s');
});

test('high S, a bad signature and a wrong hash type each have their own reason', () => {
  const { hex, digest } = cosigned();
  assert.equal(checkOf(tamperFinalTx(hex, 'high-s')).problem.reason, 'high_s');
  assert.equal(checkOf(tamperFinalTx(hex, 'bad-sig')).problem.reason, 'bad_signature');
  const sig = sign(digest, km);
  const anyone = Uint8Array.from(sig);
  anyone[anyone.length - 1] = 0x81;
  assert.equal(checkSig(anyone, digest, publicSecp(km), 'K_m').reason, 'bad_sighash_type');
  assert.equal(checkSig(sig, digest, publicSecp(ku), 'K_m').reason, 'bad_signature');
  assert.equal(checkSig(sig, digest, publicSecp(km), 'K_m'), null);
  assert.equal(verify(tamperFinalTx(hex, 'bad-sig'), toHex(spk), coin.value), 1, 'consensus agrees');
});

test('a co-signed spend is checked against what was asked for, not against itself', () => {
  const { hex, mpcRs, halfRs } = cosigned();
  const tx = parseTx(fromHex(hex));
  const swapped = parseTx(fromHex(hex));
  [swapped.inputs[0].witness[0], swapped.inputs[0].witness[1]] = [swapped.inputs[0].witness[1], swapped.inputs[0].witness[0]];
  assert.equal(checkOf(toHex(serialize(swapped))).problem.reason, 'bad_signature', 'signatures in the wrong order');
  const stranger = parseTx(fromHex(hex));
  stranger.inputs[0].witness[1] = sign(sighash(makeTx([coin], SEQUENCE_COSIGNED, [{ value: amount, spk: to }]), 0, script, coin.value), secret('stranger'));
  assert.deepEqual(checkOf(toHex(serialize(stranger))).problem, { reason: 'bad_signature', detail: 'K_u' }, 'K_m good, K_u from someone else');
  assert.equal(checkCosigned({ rawHex: hex, coin, to, amount: amount - 1, script, km: publicSecp(km), ku: publicSecp(ku) }).problem.reason, 'wrong_amount');
  assert.equal(checkCosigned({ rawHex: hex, coin: { ...coin, vout: 0 }, to, amount, script, km: publicSecp(km), ku: publicSecp(ku) }).problem.reason, 'wrong_input');
  assert.equal(checkCosigned({ rawHex: hex, coin, to: spk, amount, script, km: publicSecp(km), ku: publicSecp(ku) }).problem.reason, 'wrong_output');
  assert.equal(checkCosigned({ rawHex: hex, coin: { ...coin, value: coin.value + 1 }, to, amount, script, km: publicSecp(km), ku: publicSecp(ku) }).problem.reason, 'bad_signature', 'a wrong declared value changes the digest');
  const other = witnessScript(publicSecp(ku), publicSecp(km), publicSecp(ke), CSV + 1);
  assert.equal(checkCosigned({ rawHex: hex, coin, to, amount, script: other, km: publicSecp(km), ku: publicSecp(ku) }).problem.reason, 'wrong_witness_script');
  assert.equal(checkOf('00').problem.reason, 'unparsable_tx');
  assert.equal(tx.inputs[0].sequence, SEQUENCE_COSIGNED);
  // The driver's assembly is the same bytes whichever S form the signer sends.
  const flipped = Uint8Array.from(mpcRs);
  const high = secp256k1.CURVE.n - BigInt(`0x${toHex(mpcRs.slice(32))}`);
  flipped.set(fromHex(high.toString(16).padStart(64, '0')), 32);
  assert.ok(isHighS(flipped) && !isHighS(mpcRs));
  assert.equal(assembleCosigned({ coin, to, amount, mpcRs: flipped, halfRs, script }), hex);
});

test('an escape is checked too, and consensus agrees', () => {
  const hex = escape();
  assert.equal(escapeOf(hex).problem, undefined);
  assert.equal(verify(hex, toHex(spk), coin.value), 0);
  assert.equal(checkEscape({ rawHex: hex, coin, to, amount, script, csv: CSV, ke: publicSecp(ku) }).problem.reason, 'bad_signature');
  assert.equal(checkEscape({ rawHex: hex, coin, to, amount, script, csv: CSV + 1, ke: publicSecp(ke) }).problem.reason, 'wrong_sequence');
  assert.equal(escapeOf(cosigned().hex).problem.reason, 'wrong_sequence');
  assert.equal(escapeOf(tamperFinalTx(hex, 'high-s')).problem.reason, 'high_s');
});

test('the controls: consensus refuses both, for the check each is there to test', () => {
  const { hex } = cosigned();
  const noKu = withoutKuSig(hex);
  assert.notEqual(noKu, hex);
  const [real, control] = [hex, noKu].map((h) => parseTx(fromHex(h)));
  assert.equal(txid(control), txid(real), 'same txid: only the witness changed');
  assert.deepEqual(toHex(control.inputs[0].witness[0]), toHex(real.inputs[0].witness[0]), 'K_m\'s signature stays');
  assert.equal(control.inputs[0].witness[1].length, 0);
  assert.equal(verify(hex, toHex(spk), coin.value), 0, 'control: the untouched spend is fine');
  assert.equal(verify(noKu, toHex(spk), coin.value), 1);

  const file = { csv: CSV, script };
  Object.defineProperty(file, 'cold', { value: ke, enumerable: false });
  const short = escapeOneShort({ file, coin, to, amount });
  const tx = parseTx(fromHex(short.raw));
  assert.equal(tx.inputs[0].sequence, CSV - 1);
  assert.equal(short.id, txid(tx));
  assert.notEqual(short.id, txid(parseTx(fromHex(escape()))), 'nSequence is in the txid');
  assert.equal(toHex(tx.inputs[0].witness[2]), toHex(script));
  const digest = sighash(makeTx([coin], CSV - 1, [{ value: amount, spk: to }]), 0, script, coin.value);
  assert.equal(checkSig(tx.inputs[0].witness[0], digest, publicSecp(ke), 'K_e'), null, 'an honest signature, so only OP_CSV can refuse it');
  assert.equal(verify(escape(), toHex(spk), coin.value), 0, 'control: the same escape at nSequence csv is fine');
  assert.equal(verify(short.raw, toHex(spk), coin.value), 1);
});

test('the key alone: K_u\'s real signature, nothing for K_m, and consensus refuses it', () => {
  const { hex, digest, halfRs, mpcRs } = cosigned();
  const thief = withoutKmSig({ coin, to, amount, halfRs, script });
  const tx = parseTx(fromHex(thief.raw));
  const real = parseTx(fromHex(hex));
  assert.equal(thief.id, txid(real), 'same spend as the co-signed one: only the witness differs');
  assert.equal(tx.inputs[0].sequence, SEQUENCE_COSIGNED);
  const w = tx.inputs[0].witness;
  assert.equal(w.length, 4);
  assert.equal(w[0].length, 0, 'nothing where K_m\'s signature goes');
  assert.equal(checkSig(w[1], digest, publicSecp(ku), 'K_u'), null, 'an honest K_u signature, so only K_m\'s check can refuse it');
  assert.equal(w[2][0], 1, 'the co-signed branch');
  assert.equal(toHex(w[3]), toHex(script));
  assert.equal(verify(thief.raw, toHex(spk), coin.value), 1);
  // Add K_m's signature to the same witness and it is the co-signed spend, so K_m's is all that was missing.
  w[0] = derSig(mpcRs);
  assert.equal(toHex(serialize(tx)), hex);
  assert.equal(verify(hex, toHex(spk), coin.value), 0, 'control: with K_m\'s signature it is fine');
});

test('the key alone: keyAloneHalfSig signs with K_u, derived from the seed, and nothing else', () => {
  const seed = secret('seed');
  const { ku: derived } = spendKeys(seed);
  const own = witnessScript(derived.pub, publicSecp(km), publicSecp(ke), CSV);
  const halfRs = keyAloneHalfSig({ seed, script: own, coin, to, amount });
  const digest = sighash(makeTx([coin], SEQUENCE_COSIGNED, [{ value: amount, spk: to }]), 0, own, coin.value);
  assert.equal(checkSig(derSig(halfRs.slice(0, 64)), digest, derived.pub, 'K_u'), null);
  assert.notEqual(checkSig(derSig(halfRs.slice(0, 64)), digest, publicSecp(km), 'K_m'), null);
});

test('sizes used for fees are not below the real transaction', () => {
  const { hex } = cosigned();
  const raw = fromHex(hex);
  const tx = parseTx(raw);
  const size = (t) => {
    const stripped = t.inputs.length * 41 + t.outputs.reduce((s, o) => s + 9 + o.spk.length, 0) + 10;
    return Math.ceil((stripped * 3 + raw.length) / 4);
  };
  assert.ok(cosignedVsize({ coin, to, amount, script }) >= size(tx));
  assert.ok(cosignedVsize({ coin, to, amount, script }) >= 148);
  assert.ok(escapeVsize({ coins: [coin], to, script, csv: CSV }) >= 118 && escapeVsize({ coins: [coin], to, script, csv: CSV }) < 135);
});

test('maturity: the tip at which a node takes the escape', () => {
  // A block at height h can include it when h - coin_height >= csv, and a mempool test at tip t asks about t + 1.
  assert.equal(matureTip(100, 6), 105);
  assert.equal(matureTip(100, 1), 100);
});

// ---------------------------------------------------------------- reading back

test('read-back refuses anything that differs from what was sent', () => {
  const { hex } = cosigned();
  const id = txid(parseTx(fromHex(hex)));
  const witnessHex = witnessHexOf(hex);
  const good = {
    apiTx: { txid: id, vin: [{ txid: coin.txid, vout: coin.vout, sequence: SEQUENCE_COSIGNED, witness: witnessHex }], vout: [{ scriptpubkey: toHex(to), value: amount }] },
    status: { confirmed: true, block_height: 5 },
    hexBack: hex, rawHex: hex, id, coin, toHexSpk: toHex(to), amount, sequence: SEQUENCE_COSIGNED, witnessHex,
  };
  assert.equal(checkReadback(good), null);
  const reason = (edit) => checkReadback({ ...good, ...edit }).reason;
  assert.equal(reason({ apiTx: null }), 'readback_missing');
  assert.equal(reason({ apiTx: { ...good.apiTx, txid: '00'.repeat(32) } }), 'readback_txid');
  assert.equal(reason({ hexBack: `${hex}00` }), 'readback_bytes');
  assert.equal(reason({ status: { confirmed: false } }), 'readback_not_mined');
  assert.equal(reason({ status: null }), 'readback_not_mined');
  assert.equal(reason({ apiTx: { ...good.apiTx, vin: [{ ...good.apiTx.vin[0], vout: 9 }] } }), 'readback_input');
  assert.equal(reason({ apiTx: { ...good.apiTx, vin: [{ ...good.apiTx.vin[0], sequence: 6 }] } }), 'readback_sequence');
  assert.equal(reason({ apiTx: { ...good.apiTx, vin: [{ ...good.apiTx.vin[0], witness: [] }] } }), 'readback_witness');
  assert.equal(reason({ apiTx: { ...good.apiTx, vout: [{ scriptpubkey: 'aa', value: amount }] } }), 'readback_output');
  assert.equal(reason({ apiTx: { ...good.apiTx, vout: [{ scriptpubkey: toHex(to), value: 1 }] } }), 'readback_amount');
});

// ---------------------------------------------------------------- the dispenser

const dispenserKey = secret('dispenser');
const dispenserFile = () => {
  const address = p2wpkhAddress('regtest', publicSecp(dispenserKey));
  return { format: 'undo-dispenser-v1', network: 'regtest', secret: toHex(dispenserKey), address };
};

test('a dispenser file is refused for the wrong network, the wrong address, or no key, and no error quotes it', () => {
  const good = dispenserFile();
  const d = parseDispenser(JSON.stringify(good), 'regtest');
  assert.equal(d.address, good.address);
  assert.ok(!Object.keys(d).includes('secret') && d.secret.length === 32, 'the secret is there and not enumerable');
  assert.throws(() => parseDispenser(JSON.stringify(good), 'mutinynet'), /not for mutinynet/);
  const messages = [
    () => parseDispenser(JSON.stringify(good), 'mutinynet'),
    () => parseDispenser(JSON.stringify({ ...good, address: p2wpkhAddress('regtest', publicSecp(secret('other'))) }), 'regtest'),
    () => parseDispenser(JSON.stringify({ ...good, secret: 'zz' }), 'regtest'),
    () => parseDispenser(JSON.stringify({ ...good, format: 'other' }), 'regtest'),
    () => parseDispenser('not json', 'regtest'),
  ];
  for (const bad of messages) {
    assert.throws(bad, (err) => !err.message.includes(good.secret));
  }
});

test('coin selection uses confirmed coins only', () => {
  const c = (value, confirmed = true) => ({ txid: 'aa'.repeat(32), vout: value, value, status: { confirmed } });
  assert.deepEqual(selectCoins([c(100), c(500), c(900)], 400).map((u) => u.value), [500]);
  assert.deepEqual(selectCoins([c(100), c(300)], 350).map((u) => u.value), [300, 100]);
  assert.equal(selectCoins([c(100), c(900, false)], 400), null);
  assert.equal(selectCoins([], 1), null);
});

test('a funding transaction verifies under consensus, pays the vault at vout 0, and keeps the fee honest', () => {
  const d = parseDispenser(JSON.stringify(dispenserFile()), 'regtest');
  const utxos = [{ txid: 'cd'.repeat(32), vout: 0, value: 500_000, status: { confirmed: true } }];
  const built = buildFunding({ dispenser: d, utxos, payTo: spk, value: 20_000, feeRate: 2 });
  assert.equal(verify(built.raw, toHex(d.spk), 500_000), 0);
  assert.equal(verify(built.raw, toHex(d.spk), 500_001), 1);
  const tx = parseTx(fromHex(built.raw));
  assert.equal(toHex(tx.outputs[0].spk), toHex(spk));
  assert.equal(Number(tx.outputs[0].value), 20_000);
  assert.equal(built.vout, 0);
  assert.equal(Number(tx.outputs[1].value), 500_000 - 20_000 - built.fee);
  assert.ok(built.fee >= 2 * built.vsize && built.fee <= 2 * built.vsize + 4, `${built.fee} at ${built.vsize} vB`);
  assert.equal(buildFunding({ dispenser: d, utxos, payTo: spk, value: 600_000, feeRate: 2 }).short, true);
  const tight = [{ txid: 'cd'.repeat(32), vout: 0, value: 20_500, status: { confirmed: true } }];
  const noChange = buildFunding({ dispenser: d, utxos: tight, payTo: spk, value: 20_000, feeRate: 2 });
  assert.equal(parseTx(fromHex(noChange.raw)).outputs.length, 1, 'change under dust goes to the fee');
  assert.equal(noChange.fee, 500);
});

// ---------------------------------------------------------------- the proof checker

test('the proof checker refuses a label that is not a live run, and a verdict past its contents', () => {
  const checker = resolve(dirname(fileURLToPath(import.meta.url)), 'check-g2-proof.mjs');
  const dir = mkdtempSync(join(tmpdir(), 'undo-g2-units-'));
  const run = (value) => {
    const path = join(dir, 'p.json');
    writeFileSync(path, typeof value === 'string' ? value : JSON.stringify(value));
    return spawnSync(process.execPath, [checker, path], { encoding: 'utf8', env: { PATH: process.env.PATH } });
  };
  const live = { schema: 'undo-g2-v1', label: 'live-mutinynet', gate: 'G2', chain_id: 'testnet', bitcoin: { network: 'mutinynet', genesis: '00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6' }, summary: { pass: false, gate_complete: false } };
  try {
    assert.equal(run(live).status, 0, 'a failed live run is still a true proof');
    assert.equal(run({ ...live, label: 'rehearsal-regtest-mock-signer' }).status, 1);
    assert.equal(run({ ...live, gate: 'not a gate result' }).status, 1);
    assert.equal(run({ ...live, chain_id: 'sandbox' }).status, 1);
    assert.equal(run({ ...live, bitcoin: { network: 'regtest', genesis: '00' } }).status, 1);
    assert.equal(run({ ...live, summary: { pass: true, gate_complete: false } }).status, 1, 'a pass with nothing behind it');
    assert.equal(run({ ...live, summary: { pass: false, gate_complete: true } }).status, 1, 'a complete gate on a failed run');
    assert.equal(run({ ...live, summary: { pass: false } }).status, 1, 'says nothing about the gate');
    assert.equal(run('not json').status, 1);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
