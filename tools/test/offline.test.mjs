// Offline tests of the tools. Run with: node --test tools/test/offline.test.mjs
// Needs UNDO_TOOLS_CHECK_BIN, the binary from tools/rust-check, which recomputes everything with other
// code. Test keys come from public labels, or are throwaways generated here. Nothing is committed.
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, existsSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { addressToSpk, derSig, makeTx, p2wshAddress, parseDer, parseTx, parseWitnessScript, SEQUENCE_COSIGNED, serialize, sighash, witnessScript } from '../lib/btc.mjs';
import { base58Decode, base58Encode, fromHex, toHex, utf8 } from '../lib/bytes.mjs';
import { randomBytes, secp256k1, sha256 } from '../lib/crypto.mjs';
import { signColdIntent } from '../lib/cold-intent.mjs';
import { leafPopDigest } from '../lib/intent.mjs';
import { coldKeys, spendKeys } from '../lib/keys.mjs';
import { answer } from './mock-node.mjs';
import { action, keyFromSecret, loadCredentials, signTransaction } from '../lib/near.mjs';
import { buildRecovery, parseRecovery, parseUtxos, RecoveryError } from '../lib/recovery.mjs';

const TOOLS = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = process.env.UNDO_TOOLS_CHECK_BIN;
assert.ok(BIN, 'set UNDO_TOOLS_CHECK_BIN');
let work;
before(() => { work = mkdtempSync(join(tmpdir(), 'undo-tools-')); });
after(() => rmSync(work, { recursive: true, force: true }));

const rust = (...args) => spawnSync(BIN, args, { encoding: 'utf8' });
const rustOk = (...args) => {
  const r = rust(...args);
  assert.equal(r.status, 0, `${args[0]}: ${r.stdout}${r.stderr}`);
  return r.stdout.trim();
};
const tool = (name, args, input) => spawnSync('node', [join(TOOLS, name), ...args], { encoding: 'utf8', input });
const file = (name, text) => {
  const path = join(work, name);
  writeFileSync(path, text);
  return path;
};
const makeRecovery = (network, label, csv, id = `vault-${label}`) => rustOk('make-recovery', network, label, String(csv), id);
const coinsOf = (n, seed = 'c', value = 100_000) => Array.from({ length: n }, (_, i) => ({ txid: toHex(sha256(utf8(`${seed}:${i}`))), vout: i, value }));
const fix = (w) => ({ ...w, checksum: toHex(sha256(utf8(`undo-recovery-v1\n${w.network}\n${w.vault_id}\n${w.csv}\n${w.witness_script}\n${w.address}\n${w.cold_key}\n`))) });

// ---------------------------------------------------------------- addresses

test('address vectors from BIP-173 and BIP-350', () => {
  const hex = (network, address) => toHex(addressToSpk(network, address));
  assert.equal(hex('mainnet', 'BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4'), '0014751e76e8199196d454941c45d1b3a323f1433bd6');
  assert.equal(hex('testnet4', 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7'), '00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262');
  assert.equal(hex('mainnet', 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0'), '512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
  assert.equal(hex('mainnet', '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'), '76a91477bff20c60e522dfaa3350c39b030a5d004e839a88ac');
  assert.match(hex('mainnet', '3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy'), /^a914[0-9a-f]{40}87$/);
});

test('addresses refused: wrong network, wrong checksum type, mixed case, bad checksum', () => {
  const refused = (network, address) => assert.throws(() => addressToSpk(network, address), undefined, address);
  refused('mainnet', 'tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7');
  refused('mutinynet', 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4');
  refused('mainnet', 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh');
  refused('mainnet', 'bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd');
  refused('mainnet', 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5');
  refused('mainnet', 'Bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4');
  refused('mainnet', '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN3');
  refused('mutinynet', '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2');
});

test('base58 round-trips, with leading zeros', () => {
  for (const hex of ['', '00', '0000ff', '61', '626262', 'ff'.repeat(32), `0000${'ab'.repeat(40)}`]) {
    assert.equal(toHex(base58Decode(base58Encode(fromHex(hex)))), hex);
  }
  assert.equal(base58Encode(utf8('Hello World!')), '2NEpo7TZRRrLZSi2U');
});

// ---------------------------------------------------------------- script and DER

test('script bytes and addresses agree with undo-btc across the CSV encodings', () => {
  for (const [network, csv] of [['mutinynet', 1], ['mutinynet', 6], ['mainnet', 16], ['signet', 17], ['testnet4', 127], ['regtest', 128], ['mainnet', 255], ['mainnet', 256], ['regtest', 32767], ['regtest', 32768], ['mainnet', 65535]]) {
    const text = makeRecovery(network, `s${csv}`, csv);
    const parsed = parseRecovery(text);
    assert.equal(parsed.csv, csv);
    const rebuilt = witnessScript(parsed.ku, parsed.km, parsed.ke, csv);
    assert.equal(toHex(rebuilt), JSON.parse(text).witness_script);
    assert.equal(p2wshAddress(network, rebuilt), JSON.parse(text).address);
    assert.deepEqual(JSON.parse(buildRecovery({ network, vaultId: `vault-s${csv}`, script: rebuilt, cold: parsed.cold })), JSON.parse(text));
    assert.equal(parsed.cold.length, 32);
    assert.equal(Object.keys(parsed).includes('cold'), false, 'a stray log or JSON.stringify must not reach the secret');
  }
});

test('a recovery file written here passes undo-btc\'s own dry run', () => {
  const seed = (n) => sha256(utf8(`writer:${n}`));
  const pub = (s) => secp256k1.getPublicKey(s, true);
  for (const csv of [1, 6, 300]) {
    const script = witnessScript(pub(seed(1)), pub(seed(2)), pub(seed(3)), csv);
    const path = file(`writer-${csv}.json`, buildRecovery({ network: 'mutinynet', vaultId: 'vault-writer', script, cold: seed(3) }));
    assert.match(rustOk('dry-run', path), /^ok mutinynet/);
  }
});

test('script parser refuses anything that does not rebuild to itself', () => {
  const k = (n) => secp256k1.getPublicKey(sha256(utf8(`k${n}`)), true);
  const good = witnessScript(k(1), k(2), k(3), 6);
  assert.equal(parseWitnessScript(good).csv, 6);
  const bad = Uint8Array.from(good);
  bad[72] = 1; // A push of one byte, where OP_6 must be: a non-minimal form of the same number.
  assert.throws(() => parseWitnessScript(bad));
  assert.throws(() => witnessScript(k(1), k(1), k(3), 6), /differ/);
  for (const csv of [0, 65536, -1, 1.5]) assert.throws(() => witnessScript(k(1), k(2), k(3), csv), /csv/);
});

test('DER: leading zeros, high bits, low S, and range', () => {
  const be = (hex) => fromHex(hex.padStart(64, '0'));
  const rs = (r, s) => Uint8Array.from([...be(r), ...be(s)]);
  assert.equal(toHex(derSig(rs('1', '1'))), '300602010102010101');
  assert.equal(toHex(derSig(rs('80', '7f'))), '3007020200800201' + '7f01');
  // A high S flips to its low form.
  const n = secp256k1.CURVE.n;
  assert.equal(toHex(derSig(rs((n - 1n).toString(16), '1'))).slice(0, 6), '302602');
  assert.equal(toHex(derSig(rs('1', (n - 1n).toString(16)))), '300602010102010101');
  for (const [r, s] of [['0', '1'], ['1', '0'], [n.toString(16), '1'], ['1', n.toString(16)]]) assert.throws(() => derSig(rs(r, s)), /range/);
  for (let i = 0; i < 200; i += 1) {
    const sig = secp256k1.sign(sha256(utf8(`d${i}`)), sha256(utf8(`k${i}`)), { lowS: true, prehash: false });
    const compact = sig.toCompactRawBytes();
    const der = derSig(compact);
    assert.equal(toHex(der.slice(0, -1)), sig.toDERHex());
    assert.equal(toHex(parseDer(der)), toHex(compact));
  }
});

// ---------------------------------------------------------------- escape

test('escape.mjs builds byte-identical transactions to undo-btc, and consensus accepts them', () => {
  for (const [network, csv, n, dest] of [
    ['regtest', 6, 1, 'bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080'],
    ['mutinynet', 6, 3, 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx'],
    ['mainnet', 150, 5, 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'],
    ['mainnet', 65535, 2, '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'],
  ]) {
    const rec = file(`r-${csv}.json`, makeRecovery(network, `e${csv}`, csv));
    const coins = coinsOf(n, `e${csv}`);
    const utxos = file(`u-${csv}.json`, JSON.stringify(coins));
    const out = join(work, `tx-${csv}.hex`);
    const res = tool('escape.mjs', ['--recovery', rec, '--utxos', utxos, '--to', dest, '--fee', '2000', '--out', out]);
    assert.equal(res.status, 0, res.stderr);
    const hex = readFileSync(out, 'utf8').trim();
    const spk = toHex(addressToSpk(network, dest));
    assert.equal(hex, rustOk('escape', rec, utxos, spk, '2000'), 'byte-identical to undo-btc');

    const parsed = parseRecovery(readFileSync(rec, 'utf8'));
    const vaultSpk = `0020${toHex(sha256(parsed.script))}`;
    const values = coins.map((c) => c.value);
    rustOk('verify', hex, vaultSpk, values.join(','));

    // Controls: the referee must be able to say no.
    assert.equal(rust('verify', hex, vaultSpk, [values[0] + 1, ...values.slice(1)].join(',')).status, 1, 'a wrong value must be refused');
    const tampered = parseTx(fromHex(hex));
    tampered.outputs[0].value -= 1n;
    assert.equal(rust('verify', toHex(serialize(tampered)), vaultSpk, values.join(',')).status, 1, 'a changed output must be refused');
    const early = parseTx(fromHex(hex));
    if (csv > 1) {
      early.inputs[0].sequence = csv - 1;
      assert.equal(rust('verify', toHex(serialize(early)), vaultSpk, values.join(',')).status, 1, 'one block below CSV must be refused');
    }
  }
});

test('escape output carries no secret, and every refusal is clean', () => {
  const text = makeRecovery('mutinynet', 'clean', 6);
  const secret = JSON.parse(text).cold_key;
  const rec = file('clean.json', text);
  const utxos = file('clean-u.json', JSON.stringify(coinsOf(2, 'clean')));
  const dest = 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx';
  const ok = tool('escape.mjs', ['--recovery', rec, '--utxos', utxos, '--to', dest, '--fee', '1000']);
  assert.equal(ok.status, 0, ok.stderr);
  assert.match(ok.stdout, /not checked/);
  assert.ok(!(ok.stdout + ok.stderr).includes(secret));

  const refuse = (args, why, code = 1) => {
    const r = tool('escape.mjs', args);
    assert.equal(r.status, code, `${why}: ${r.stdout}${r.stderr}`);
    assert.ok(!(r.stdout + r.stderr).includes(secret), `${why} leaked`);
  };
  refuse(['--recovery', rec, '--utxos', utxos, '--to', 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4', '--fee', '1000'], 'mainnet address on a test file');
  refuse(['--recovery', rec, '--utxos', utxos, '--to', dest, '--fee', '50000'], 'fee above 5 percent');
  const race = tool('escape.mjs', ['--recovery', rec, '--utxos', utxos, '--to', dest, '--fee', '1000']);
  assert.match(race.stdout, /must pay more in absolute fee than that link, summed over every link stacked on it in the mempool/);
  // A small coin must be able to out-pay a held link without asking for an override.
  const small = file('small.json', JSON.stringify([{ ...coinsOf(1)[0], value: 6_000 }]));
  for (const [fee, ok] of [[1_200, true], [5_000, true]]) {
    assert.equal(tool('escape.mjs', ['--recovery', rec, '--utxos', small, '--to', dest, '--fee', String(fee)]).status, ok ? 0 : 1, `small coin, fee ${fee}`);
  }
  // Above the floor the percentage still asks, and under the percentage nothing does.
  const mid = file('mid.json', JSON.stringify([{ ...coinsOf(1)[0], value: 100_000 }]));
  refuse(['--recovery', rec, '--utxos', mid, '--to', dest, '--fee', '5001'], 'over both limits');
  const big100 = file('big.json', JSON.stringify([{ ...coinsOf(1)[0], value: 1_000_000 }]));
  assert.equal(tool('escape.mjs', ['--recovery', rec, '--utxos', big100, '--to', dest, '--fee', '50000']).status, 0, 'exactly 5 percent of a large coin');
  refuse(['--recovery', rec, '--utxos', utxos, '--to', dest, '--fee', '199999', '--allow-high-fee'], 'dust');
  refuse(['--recovery', rec, '--utxos', utxos, '--to-script', '6a0100', '--fee', '1000'], 'OP_RETURN');
  refuse(['--recovery', rec, '--utxos', utxos, '--to', dest, '--fee', '1000', '--oops'], 'unknown flag', 2);
  refuse(['--recovery', rec, '--utxos', utxos, '--to', dest], 'no fee', 2);
  refuse(['--recovery', rec, '--utxos', file('dup.json', JSON.stringify([...coinsOf(1, 'd'), ...coinsOf(1, 'd')])), '--to', dest, '--fee', '1000'], 'duplicate coin');
  refuse(['--recovery', rec, '--utxos', file('empty.json', '[]'), '--to', dest, '--fee', '1000'], 'no coins');
  const big = tool('escape.mjs', ['--recovery', rec, '--utxos', utxos, '--to', dest, '--fee', '50000', '--allow-high-fee']);
  assert.equal(big.status, 0, 'a large fee works once asked for');
  const young = file('young.json', JSON.stringify([{ ...coinsOf(1, 'y')[0], confirmations: 2 }]));
  assert.match(tool('escape.mjs', ['--recovery', rec, '--utxos', young, '--to', dest, '--fee', '1000']).stdout, /too young/);
});

test('recovery refusals match undo-btc, code for code, and quote nothing from the file', () => {
  const good = JSON.parse(makeRecovery('mutinynet', 'parity', 6));
  const cases = {
    Malformed: ['not json', JSON.stringify({ ...good, extra: 1 }), JSON.stringify({ ...good, csv: '6' })],
    UnknownFormat: [JSON.stringify({ ...good, format: 'undo-recovery-v2' })],
    Checksum: [JSON.stringify({ ...good, vault_id: 'other' }), JSON.stringify({ ...good, checksum: '00'.repeat(32) })],
    Network: [JSON.stringify(fix({ ...good, network: 'nope' }))],
    VaultId: [JSON.stringify(fix({ ...good, vault_id: 'bad id' })), JSON.stringify(fix({ ...good, vault_id: '' }))],
    Script: [JSON.stringify(fix({ ...good, witness_script: '00' })), JSON.stringify(fix({ ...good, witness_script: 'zz' }))],
    CsvMismatch: [JSON.stringify(fix({ ...good, csv: 7 }))],
    AddressMismatch: [JSON.stringify(fix({ ...good, address: 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx' }))],
    ColdKey: [JSON.stringify(fix({ ...good, cold_key: '00'.repeat(32) })), JSON.stringify(fix({ ...good, cold_key: 'ab' }))],
    ColdKeyMismatch: [JSON.stringify(fix({ ...good, cold_key: toHex(sha256(utf8('someone else'))) }))],
  };
  for (const [code, texts] of Object.entries(cases)) {
    texts.forEach((text, i) => {
      assert.throws(() => parseRecovery(text), (err) => err instanceof RecoveryError && err.code === code, `${code} ${i}`);
      const path = file(`bad-${code}-${i}.json`, text);
      const r = rust('dry-run', path);
      assert.notEqual(r.status, 0);
      assert.match(r.stdout, new RegExp(`refused ${code}`), `undo-btc on ${code} ${i}: ${r.stdout}`);
      const cli = tool('escape.mjs', ['--recovery', path, '--utxos', file('u.json', JSON.stringify(coinsOf(1))), '--to-script', '0014' + '00'.repeat(20), '--fee', '500']);
      assert.equal(cli.status, 1);
      assert.ok(!(cli.stdout + cli.stderr).includes(good.cold_key));
    });
  }
});

test('UTXO lists: an esplora answer works, junk does not', () => {
  const esplora = [{ txid: 'ab'.repeat(32), vout: 1, status: { confirmed: true, block_height: 5 }, value: 5000 }];
  assert.deepEqual(parseUtxos(JSON.stringify(esplora))[0].value, 5000);
  for (const junk of ['nope', '{}', '[{"txid":"AB","vout":0,"value":1}]', `[{"txid":"${'ab'.repeat(32)}","vout":-1,"value":1}]`, `[{"txid":"${'ab'.repeat(32)}","vout":0,"value":0}]`, `[{"txid":"${'ab'.repeat(32)}","vout":0,"value":1.5}]`]) {
    assert.throws(() => parseUtxos(junk), undefined, junk);
  }
});

// ---------------------------------------------------------------- cold intents

const VAULT = 'cd'.repeat(32);
const CONTRACT = 'g1.undo-btc.testnet';

test('cold digests agree with an independent borsh encoder, signed by the derived key and never the leaf', () => {
  const cold = sha256(utf8('undo-test-only:freeze-fixture'));
  const coldHex = toHex(cold);
  const pinned = rustOk('intent-key', coldHex);
  assert.equal(toHex(coldKeys(cold).intent.pub), pinned, 'HKDF derivation matches the hkdf crate');
  const cases = [
    ['freeze', { until: 1_900_000_000_000 }, '1900000000000', 3],
    ['unfreeze', {}, '0', 4],
    ['veto_grant', { grant: 7 }, '7', 5],
    ['cancel', { request: 12 }, '12', null],
  ];
  for (const [method, fields, arg, nonce] of cases) {
    const expiresAt = 1_900_000_600_000;
    const signed = signColdIntent({ cold, contract: CONTRACT, vault: VAULT, method, fields, expiresAt, nonce });
    assert.equal(signed.digest, rustOk('cold-digest', CONTRACT, VAULT, method, arg, String(expiresAt), nonce === null ? 'none' : String(nonce)), method);
    assert.equal(rustOk('cold-check', signed.digest, signed.signature, coldHex), 'signed by intent key', method);
    assert.equal(signed.k_e_intent, pinned);
    // Control: the referee must spot the leaf key and any other key.
    const leafSig = secp256k1.sign(fromHex(signed.digest), cold, { lowS: true, prehash: false });
    const rsv = `${toHex(leafSig.toCompactRawBytes())}0${leafSig.recovery}`;
    const r = rust('cold-check', signed.digest, rsv, coldHex);
    assert.equal(r.status, 1);
    assert.match(r.stdout, /LEAF/);
  }
});

test('the leaf proof digest agrees with an independent encoder and is not a plain create digest', () => {
  const digest = sha256(utf8('undo-test-only:create-digest'));
  const tagged = toHex(leafPopDigest(digest));
  assert.equal(tagged, rustOk('leaf-pop-digest', toHex(digest)));
  assert.notEqual(tagged, toHex(digest));
});

test('every field is load-bearing in a cold digest', () => {
  const cold = sha256(utf8('undo-test-only:freeze-fields'));
  const base = { cold, contract: CONTRACT, vault: VAULT, method: 'freeze', fields: { until: 1000 }, expiresAt: 2000, nonce: 1 };
  const digest = (over) => signColdIntent({ ...base, ...over }).digest;
  const first = digest({});
  for (const over of [{ contract: 'other.testnet' }, { vault: 'ce'.repeat(32) }, { method: 'veto_grant', fields: { grant: 1000 } }, { fields: { until: 1001 } }, { expiresAt: 2001 }, { nonce: 2 }]) {
    assert.notEqual(digest(over), first, JSON.stringify(Object.keys(over)));
  }
  assert.throws(() => signColdIntent({ ...base, method: 'propose_btc' }), /signs no/);
  assert.throws(() => signColdIntent({ ...base, nonce: undefined }), /nonce/);
});

test('freeze.mjs: signs from fields, refuses digests, asks first, leaks nothing', () => {
  const text = makeRecovery('mutinynet', 'fz', 6, VAULT);
  const secret = JSON.parse(text).cold_key;
  const rec = file('fz.json', text);
  const out = join(work, 'fz-out.json');
  const now = 1_900_000_000_000;
  const base = ['--recovery', rec, '--contract', CONTRACT, '--method', 'freeze', '--nonce', '0', '--now-ms', String(now), '--out', out];
  const clean = (r) => assert.ok(!(r.stdout + r.stderr).includes(secret));

  let r = tool('freeze.mjs', [...base, '--digest', 'ab'.repeat(32), '--yes']);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /never signs a digest/);
  assert.ok(!existsSync(out));

  r = tool('freeze.mjs', base, 'no\n');
  assert.equal(r.status, 1);
  assert.match(r.stdout, /Nothing signed/);
  assert.ok(!existsSync(out), 'answering no writes nothing');
  clean(r);

  r = tool('freeze.mjs', [...base, '--minutes', '4'], 'yes\n');
  assert.equal(r.status, 1, 'six 30-second blocks is 3 minutes, so 4 is too long');
  assert.match(r.stderr, /at most the CSV period/);
  assert.ok(!existsSync(out));

  r = tool('freeze.mjs', base, 'yes\n');
  assert.equal(r.status, 0, r.stderr);
  clean(r);
  const written = readFileSync(out, 'utf8');
  assert.ok(!written.includes(secret), 'the intent file holds no secret');
  const intent = JSON.parse(written);
  assert.equal(intent.args.until, intent.args.expires_at + 6 * 30_000, 'the default asks for past its expiry, and the contract cuts it to the whole CSV period');
  assert.equal(intent.args.vault, VAULT);
  assert.equal(intent.digest, rustOk('cold-digest', CONTRACT, VAULT, 'freeze', String(intent.args.until), String(intent.args.expires_at), '0'));
  assert.equal(rustOk('cold-check', intent.digest, intent.args.signature, secret), 'signed by intent key');

  r = tool('freeze.mjs', ['--recovery', rec, '--contract', CONTRACT, '--method', 'freeze', '--out', out, '--yes']);
  assert.equal(r.status, 2, 'freeze without a nonce is a usage error');
  r = tool('freeze.mjs', ['--recovery', rec, '--contract', CONTRACT, '--method', 'cancel', '--request', '1', '--nonce', '0', '--out', out, '--yes']);
  assert.equal(r.status, 2, 'cancel takes no nonce');
  r = tool('freeze.mjs', ['--recovery', rec, '--contract', CONTRACT, '--method', 'propose_btc', '--out', out, '--yes']);
  assert.equal(r.status, 2);
  r = tool('freeze.mjs', ['--recovery', rec, '--contract', CONTRACT, '--vault', 'ee'.repeat(32), '--method', 'cancel', '--request', '1', '--out', out, '--yes']);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /not the vault/);
  r = tool('freeze.mjs', ['--recovery', rec, '--contract', CONTRACT, '--method', 'cancel', '--request', '1', '--out', rec, '--yes']);
  assert.equal(r.status, 1);
  assert.match(r.stderr, /overwrite the recovery file/);
  assert.equal(readFileSync(rec, 'utf8'), text);
});

// ---------------------------------------------------------------- keys and mock node

test('seed derivation is stable, and the keys differ', () => {
  const seed = fromHex('11'.repeat(32));
  const a = spendKeys(seed);
  const b = spendKeys(seed);
  assert.equal(toHex(a.ks.pub), toHex(b.ks.pub));
  assert.equal(toHex(a.ku.pub), toHex(b.ku.pub));
  assert.notEqual(toHex(a.ks.secret), toHex(a.ku.secret));
  const c = spendKeys(fromHex('12'.repeat(32)));
  assert.notEqual(toHex(c.ku.pub), toHex(a.ku.pub));
});

test('the mock node\'s answers recover to the derived key', () => {
  const secret = sha256(utf8('root'));
  const tweak = sha256(utf8('tweak'));
  const payload = sha256(utf8('payload'));
  const res = answer({ secret, tweakHex: toHex(tweak), payloadHex: toHex(payload) });
  const n = secp256k1.CURVE.n;
  const big = (b) => BigInt(`0x${toHex(b)}`);
  const key = fromHex(((big(secret) + big(tweak) % n) % n).toString(16).padStart(64, '0'));
  const sig = new secp256k1.Signature(BigInt(`0x${res.big_r.affine_point.slice(2)}`), BigInt(`0x${res.s.scalar}`)).addRecoveryBit(res.recovery_id);
  assert.equal(sig.recoverPublicKey(payload).toHex(true), toHex(secp256k1.getPublicKey(key, true)));
});

// ---------------------------------------------------------------- transactions and BIP-143

test('a co-signed spend built here passes consensus: script, sighash and witness order', () => {
  const s = (n) => sha256(utf8(`cosign:${n}`));
  const pub = (k) => secp256k1.getPublicKey(k, true);
  const script = witnessScript(pub(s('u')), pub(s('m')), pub(s('e')), 6);
  const spk = fromHex(`0020${toHex(sha256(script))}`);
  const coins = coinsOf(3, 'cosign');
  const tx = makeTx(coins, SEQUENCE_COSIGNED, [{ value: 299_000, spk }]);
  tx.inputs.forEach((input, i) => {
    const digest = sighash(tx, i, script, coins[i].value);
    const sign = (k) => derSig(secp256k1.sign(digest, k, { lowS: true, prehash: false }).toCompactRawBytes());
    input.witness = [sign(s('m')), sign(s('u')), Uint8Array.of(1), script];
  });
  const hex = toHex(serialize(tx));
  const values = coins.map((c) => c.value).join(',');
  rustOk('verify', hex, toHex(spk), values);
  // Controls: swapped signatures, and K_u alone with K_m's slot filled by K_u.
  const swapped = parseTx(fromHex(hex));
  swapped.inputs[0].witness = [swapped.inputs[0].witness[1], swapped.inputs[0].witness[0], Uint8Array.of(1), script];
  assert.equal(rust('verify', toHex(serialize(swapped)), toHex(spk), values).status, 1);
  const parsed = parseTx(fromHex(hex));
  assert.equal(toHex(serialize(parsed)), hex, 'parseTx round-trips');
});

test('reads near-cli\'s legacy key file, and the secret does not serialize into errors', () => {
  const dir = join(work, 'creds');
  mkdirSync(join(dir, 'testnet'), { recursive: true });
  const secret = sha256(utf8('undo-test-only:legacy-file'));
  const key = keyFromSecret(secret);
  const full = Uint8Array.from([...secret, ...key.pub]);
  writeFileSync(join(dir, 'testnet', 'a.testnet.json'), JSON.stringify({ account_id: 'a.testnet', public_key: key.publicKey, private_key: `ed25519:${base58Encode(full)}` }), { mode: 0o600 });
  process.env.NEAR_CREDENTIALS_DIR = dir;
  try {
    const loaded = loadCredentials('testnet', 'a.testnet');
    assert.equal(loaded.publicKey, key.publicKey);
    assert.equal(loaded.accountId, 'a.testnet');
    writeFileSync(join(dir, 'testnet', 'b.testnet.json'), JSON.stringify({ private_key: 'ml-dsa-65:abc' }));
    assert.throws(() => loadCredentials('testnet', 'b.testnet'), /only ed25519/);
  } finally {
    delete process.env.NEAR_CREDENTIALS_DIR;
  }
});

test('NEAR transactions sign deterministically and encode the expected enum tags', () => {
  const key = { ...keyFromSecret(sha256(utf8('near-key'))), accountId: 'a.testnet' };
  const blockHash = new Uint8Array(32).fill(9);
  const one = signTransaction({ signerId: 'a.testnet', key, nonce: 5n, receiverId: 'b.testnet', blockHash, actions: [action.call('m', { x: 1 }, 30_000_000_000_000n, 1n)] });
  const two = signTransaction({ signerId: 'a.testnet', key, nonce: 5n, receiverId: 'b.testnet', blockHash, actions: [action.call('m', { x: 1 }, 30_000_000_000_000n, 1n)] });
  assert.equal(one.hash, two.hash);
  assert.equal(action.createAccount()[0], 0);
  assert.equal(action.deploy(new Uint8Array(1))[0], 1);
  assert.equal(action.transfer(1n)[0], 3);
  assert.equal(action.addFullKey(key.pub)[0], 5);
  assert.equal(action.deleteKey(key.pub)[0], 6);
});

// ---------------------------------------------------------------- cancel.mjs: a signed cancel, from your own account

/** A JSON-RPC stand-in for a NEAR node, answering what cancel.mjs asks. `views` maps a view name to its answer. */
async function fakeNode({ chainId = 'testnet', nowMs = 1_900_000_000_000, views = {} } = {}) {
  const { createServer } = await import('node:http');
  const asked = [];
  const server = createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      const { id, method, params } = JSON.parse(body);
      const name = params?.method_name ?? params?.request_type ?? null;
      asked.push(name ? `${method}:${name}` : method);
      const reply = (result) => res.end(JSON.stringify({ jsonrpc: '2.0', id, result }));
      if (method === 'status') return reply({ chain_id: chainId });
      if (method === 'block') return reply({ header: { hash: base58Encode(sha256(utf8('block'))), timestamp_nanosec: `${nowMs}000000` } });
      if (method === 'query' && params.request_type === 'call_function') return reply({ result: [...utf8(JSON.stringify(views[params.method_name] ?? null))], logs: [] });
      return res.end(JSON.stringify({ jsonrpc: '2.0', id, error: { name: 'HANDLER_ERROR', cause: { name: 'NOT_IN_THIS_FAKE' } } }));
    });
  });
  await new Promise((r) => { server.listen(0, '127.0.0.1', r); });
  return { url: `http://127.0.0.1:${server.address().port}`, asked, close: () => new Promise((r) => { server.close(r); }) };
}

const toolAsync = (name, args, input = '') => new Promise((resolveRun) => {
  // No key folder of this machine's: a key, if one is looked for, is looked for here, and there is none.
  const env = { ...process.env, NEAR_CREDENTIALS_DIR: join(work, 'no-credentials') };
  const child = spawn('node', [join(TOOLS, name), ...args], { stdio: ['pipe', 'pipe', 'pipe'], env });
  let stdout = '';
  let stderr = '';
  child.stdout.on('data', (c) => { stdout += c; });
  child.stderr.on('data', (c) => { stderr += c; });
  child.on('close', (status) => resolveRun({ status, stdout, stderr }));
  child.stdin.end(input);
});

test('cancel.mjs: only a signed cancel, in the shape the contract takes, and never on mainnet or past its time', async () => {
  const now = 1_900_000_000_000;
  const webauthn = { authenticator_data: '00'.repeat(37), client_data_json: '7b7d', signature: '00'.repeat(64) };
  const rotate = { vault: VAULT, new_k_s: 'aa'.repeat(32), nonce: 3, expires_at: now + 600_000, assertion: webauthn };
  const owner = (over = {}) => file(`call-${Math.random().toString(16).slice(2)}.json`, JSON.stringify({ format: 'undo-owner-call-v1', contract: CONTRACT, method: 'cancel_all_and_rotate', args: rotate, ...over }));
  const signed = signColdIntent({ cold: sha256(utf8('cancel-tool-cold')), contract: CONTRACT, vault: VAULT, method: 'cancel', fields: { request: 7 }, expiresAt: now + 600_000 });
  const cold = { vault: VAULT, request: 7, expires_at: now + 600_000, auth: { Cold: signed.signature } };
  const coldFile = (over = {}) => file(`cold-${Math.random().toString(16).slice(2)}.json`, JSON.stringify({ format: 'undo-cold-intent-v1', contract: CONTRACT, method: 'cancel', args: cold, digest: signed.digest, k_e_intent: signed.k_e_intent, ...over }));
  const node = await fakeNode({ nowMs: now, views: { vault: { passkey_nonce: 3 }, request: { status: 'Pending' } } });
  const run = (path, extra = [], input = 'no\n', rpc = node.url) => toolAsync('cancel.mjs', ['--file', path, '--account', 'me.testnet', '--rpc', rpc, ...extra], input);
  try {
    assert.equal((await toolAsync('cancel.mjs', [])).status, 2);
    assert.equal((await toolAsync('cancel.mjs', ['--file', owner(), '--account', 'Not An Account'])).status, 2);
    assert.equal((await toolAsync('cancel.mjs', ['--file', owner(), '--account', 'me.testnet', '--digest', 'ab'])).status, 2, 'an unknown flag');
    const refusedBeforeReading = [
      [file('nope.json', 'not json'), /not JSON/],
      [file('rec.json', JSON.stringify({ format: 'undo-recovery-v1' })), /not a signed cancel/],
      [owner({ method: 'set_policy' }), /only cancel or cancel_all_and_rotate/],
      [coldFile({ method: 'freeze' }), /only cancel from a file/],
      [owner({ contract: 'Not A Contract' }), /names no contract/],
      [owner({ args: { ...rotate, assertion: { ...webauthn, user_handle: '00' } } }), /not the shape/],
      [coldFile({ args: { ...cold, auth: { Passkey: webauthn, Cold: signed.signature } } }), /not the shape/],
      [owner({ args: { ...rotate, receiver_id: 'someone.testnet' } }), /not the shape/],
    ];
    for (const [path, words] of refusedBeforeReading) {
      const r = await run(path);
      assert.equal(r.status, 1, r.stdout + r.stderr);
      assert.match(r.stderr, words);
    }
    assert.deepEqual(node.asked, [], 'none of those asked the chain anything');

    const main = await fakeNode({ chainId: 'mainnet', nowMs: now, views: { vault: { passkey_nonce: 3 } } });
    try {
      const r = await run(owner(), ['--yes'], '', main.url);
      assert.equal(r.status, 1);
      assert.match(r.stderr, /mainnet/);
      assert.deepEqual(main.asked, ['status'], 'it read the network and stopped');
    } finally {
      await main.close();
    }

    const late = await run(owner({ args: { ...rotate, expires_at: now - 1 } }));
    assert.match(late.stderr, /expired/);
    const used = await run(owner({ args: { ...rotate, nonce: 2 } }));
    assert.match(used.stderr, /was used already/);
    const gone = await fakeNode({ nowMs: now, views: { vault: { passkey_nonce: 3 }, request: null } });
    try {
      assert.match((await run(coldFile(), [], 'no\n', gone.url)).stderr, /is gone/);
    } finally {
      await gone.close();
    }
    const none = await fakeNode({ nowMs: now, views: { vault: null } });
    try {
      assert.match((await run(owner(), [], 'no\n', none.url)).stderr, /holds no vault/);
    } finally {
      await none.close();
    }

    node.asked.length = 0;
    const no = await run(coldFile());
    assert.equal(no.status, 1);
    assert.match(no.stdout, /signed by\s+the cold key/);
    assert.match(no.stdout, /Nothing sent/);
    assert.ok(!node.asked.some((a) => a.startsWith('send_tx') || a.includes('view_access_key')), 'answering no sends nothing and reads no key');
    const shown = await run(owner());
    assert.match(shown.stdout, /method\s+cancel_all_and_rotate/);
    assert.match(shown.stdout, /passkey nonce\s+3 \(the vault reads 3\)/);
    const noKey = await run(owner(), ['--yes', '--key-file', join(work, 'no-such-key.json')]);
    assert.equal(noKey.status, 1);
    assert.match(noKey.stderr, /no key for me\.testnet/);
    const noFile = await run(owner(), ['--yes']);
    assert.match(noFile.stderr, /no key for me\.testnet: ENOENT/, 'near-cli\'s file, under the folder this test names');
  } finally {
    await node.close();
  }
});
