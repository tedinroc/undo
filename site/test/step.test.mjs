// The browser library and tools/ stay one thing. Where a page can run a tools/ file, it runs that file, and
// the build ships those bytes. Where it cannot, because the file reads the disk at import, these tests pin
// the two to the same output.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { p2wshAddress, p2wshSpk, parseWitnessScript, witnessScript } from '../../tools/lib/btc.mjs';
import { base58Encode, fromHex, toHex } from '../../tools/lib/bytes.mjs';
import { ed25519, sha256 } from '../../tools/lib/crypto.mjs';
import { withoutKmSig } from '../../tools/lib/g2-check.mjs';
import { argBytes, intentDigest, PASSKEY_TAG } from '../../tools/lib/intent.mjs';
import { action, keyFromSecret, signTransaction } from '../../tools/lib/near.mjs';
import { keyAloneHalfSig, signSpend } from '../../tools/lib/spend.mjs';
import { parseSignerKey as toolsParseSignerKey } from '../../tools/lib/vault-client.mjs';
import { build, BuildRefused, headersFor, importGraph } from '../build.mjs';
import { cosignedVsizeOf, keyAloneSpend, sendEverything, spkToAddress } from '../lib/bitcoin.mjs';
import { checkConfig } from '../lib/config.mjs';
import { buildPropose, cancelDigest, newVaultKeys, rotateDigest, seedMatchesVault } from '../lib/intents.mjs';
import { callAction, milliNear, signedTransaction } from '../lib/near-tx.mjs';
import { failureOf as siteFailureOf, returnValue as siteReturnValue } from '../lib/near-read.mjs';
import { failureOf as toolsFailureOf, returnValue as toolsReturnValue } from '../../tools/lib/near.mjs';
import { parseSignerKey } from '../lib/views.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const SITE = resolve(HERE, '..');
const REPO = resolve(SITE, '..');
const label = (text) => sha256(new TextEncoder().encode(`undo-test-only:web:${text}`));

// ---------------------------------------------------------------- the digest a phone signs

const ROTATE = {
  contract: 'undo.example.testnet',
  vaultHex: toHex(label('rotate-vault')),
  newKs: ed25519.getPublicKey(label('rotate-new-ks')),
  nonce: 3,
  expiresAt: 1_730_000_123_456,
};

/** The same bytes by hand, from auth.rs's IntentBytes, with no code shared with tools/ or site/. */
function handRotateDigest({ contract, vaultHex, newKs, nonce, expiresAt }) {
  const u32 = (n) => {
    const out = Buffer.alloc(4);
    out.writeUInt32LE(n);
    return out;
  };
  const u64 = (n) => {
    const out = Buffer.alloc(8);
    out.writeBigUInt64LE(BigInt(n));
    return out;
  };
  const str = (s) => Buffer.concat([u32(Buffer.byteLength(s)), Buffer.from(s)]);
  const sha = (b) => createHash('sha256').update(b).digest();
  return sha(Buffer.concat([
    str('undo-passkey-v1'),
    str(contract),
    Buffer.from(vaultHex, 'hex'),
    str('cancel_all_and_rotate'),
    sha(Buffer.from(newKs)), // A fixed array carries no length in Borsh.
    u64(expiresAt),
    Buffer.from([1]),
    u64(nonce),
  ])).toString('hex');
}

test('cancel_all_and_rotate digest: the page, tools/lib/intent.mjs and a by-hand encoding of auth.rs agree', () => {
  const page = toHex(rotateDigest(ROTATE));
  const tools = toHex(intentDigest({ tag: PASSKEY_TAG, contract: ROTATE.contract, vault: fromHex(ROTATE.vaultHex), method: 'cancel_all_and_rotate', args: argBytes.cancel_all_and_rotate({ newKs: ROTATE.newKs }), expiresAt: ROTATE.expiresAt, nonce: ROTATE.nonce }));
  assert.equal(page, tools);
  assert.equal(page, handRotateDigest(ROTATE));
});

test('cancel_all_and_rotate digest: every field it should bind, binds', () => {
  const base = toHex(rotateDigest(ROTATE));
  const changes = [
    { contract: 'other.example.testnet' }, { vaultHex: toHex(label('other')) }, { newKs: ed25519.getPublicKey(label('other')) }, { nonce: 4 }, { expiresAt: ROTATE.expiresAt + 1 },
  ];
  for (const change of changes) assert.notEqual(toHex(rotateDigest({ ...ROTATE, ...change })), base, Object.keys(change)[0]);
});

test('cancel digest: no nonce, and not interchangeable with a rotation', () => {
  const digest = cancelDigest({ contract: ROTATE.contract, vaultHex: ROTATE.vaultHex, request: 3, expiresAt: ROTATE.expiresAt });
  const tools = intentDigest({ tag: PASSKEY_TAG, contract: ROTATE.contract, vault: fromHex(ROTATE.vaultHex), method: 'cancel', args: argBytes.cancel({ request: 3 }), expiresAt: ROTATE.expiresAt, nonce: null });
  assert.equal(toHex(digest), toHex(tools));
  assert.notEqual(toHex(digest), toHex(rotateDigest(ROTATE)));
});

// ---------------------------------------------------------------- the thief's two spends

const fixture = () => {
  const keys = newVaultKeys({ seed: label('seed'), cold: label('cold') });
  const km = fromHex('02'.concat(toHex(label('km-x'))));
  const script = witnessScript(keys.ku.pub, km, keys.leaf.pub, 6);
  const vaultId = label('vault-id');
  const vault = { id: toHex(vaultId), k_s: toHex(keys.ks.pub), k_u: toHex(keys.ku.pub), script_pubkey: toHex(p2wshSpk(script)) };
  const coin = { txid: toHex(label('coin')), vout: 1, value: 2000 };
  return { keys, script, vault, coin, to: fromHex(`0014${toHex(label('dest')).slice(0, 40)}`) };
};

test('keyAloneSpend, one coin: byte for byte what tools/lib/g2-check.mjs and spend.mjs send in S2', () => {
  const { keys, script, coin, to } = fixture();
  const page = keyAloneSpend({ seed: keys.seed, script, coins: [coin], to, amount: 1700 });
  const halfRs = keyAloneHalfSig({ seed: keys.seed, script, coin, to, amount: 1700 });
  const tools = withoutKmSig({ coin, to, amount: 1700, halfRs, script });
  assert.equal(page.raw, tools.raw);
  assert.equal(page.txid, tools.id);
});

test('buildPropose: exactly signSpend.propose, and refuses a seed that is not the vault\'s', () => {
  const { keys, script, vault, coin, to } = fixture();
  const common = { contract: ROTATE.contract, script, inputs: [coin], to, amount: 1700, nonce: 0, expiresAt: ROTATE.expiresAt };
  const page = buildPropose({ ...common, vault, seed: keys.seed });
  const { args } = signSpend.propose({ ...common, seed: keys.seed, vault: fromHex(vault.id), spk: fromHex(vault.script_pubkey), change: null });
  assert.deepEqual(page, args);
  assert.throws(() => buildPropose({ ...common, vault, seed: label('someone-else') }), /spend key/);
});

test('seedMatchesVault: compares what a pasted seed derives with what the contract stores', () => {
  const { keys, vault } = fixture();
  assert.deepEqual(seedMatchesVault(keys.seed, vault), { ks: true, ku: true });
  assert.deepEqual(seedMatchesVault(label('wrong'), vault), { ks: false, ku: false });
});

test('sendEverything: all of it minus a fee over the contract\'s floor, or says it is short', () => {
  const { script, coin, to } = fixture();
  const spend = sendEverything({ coins: [coin], to, script, feeRate: 2 });
  assert.equal(spend.amount + spend.fee, 2000);
  assert.equal(spend.fee, Math.ceil(cosignedVsizeOf({ coins: [coin], to, script }) * 2));
  assert.equal(sendEverything({ coins: [], to, script, feeRate: 2 }).short, true);
  assert.equal(sendEverything({ coins: [{ ...coin, value: 100 }], to, script, feeRate: 2 }).short, true);
});

// ---------------------------------------------------------------- real values from the G2 run

const G2 = JSON.parse(readFileSync(join(REPO, 'proofs/g2.json'), 'utf8'));

test('real fixture: G2\'s vault on Mutinynet gives its real address and script', () => {
  const { vault } = G2;
  const script = witnessScript(fromHex(vault.k_u), fromHex(vault.k_m), fromHex(vault.k_e_leaf), vault.csv);
  assert.equal(toHex(script), vault.script);
  assert.equal(toHex(p2wshSpk(script)), vault.spk);
  assert.equal(p2wshAddress('mutinynet', script), vault.address);
  assert.equal(spkToAddress('mutinynet', vault.spk), vault.address);
  assert.deepEqual(parseWitnessScript(script).csv, vault.csv);
});

test('real fixture: G2\'s destination, and Taproot and foreign templates', () => {
  assert.match(spkToAddress('mutinynet', G2.cosigned.to), /^tb1q/);
  assert.match(spkToAddress('mutinynet', `5120${'11'.repeat(32)}`), /^tb1p/);
  assert.equal(spkToAddress('mutinynet', '6a0411223344'), null);
  assert.equal(spkToAddress('mutinynet', `76a914${'11'.repeat(20)}88ac`), null);
});

test('real fixture: the fee G2 planned for a co-signed spend, at its rate', () => {
  const { vault, cosigned } = G2;
  const coin = { txid: cosigned.coin.split(':')[0], vout: Number(cosigned.coin.split(':')[1]), value: cosigned.amount + cosigned.fee };
  const spend = sendEverything({ coins: [coin], to: fromHex(cosigned.to), script: fromHex(vault.script), feeRate: G2.fee_rate_sat_vb });
  assert.ok(spend.fee >= cosigned.fee, `${spend.fee} is worst-case and should not undershoot the ${cosigned.fee} G2 paid`);
  assert.ok(spend.fee - cosigned.fee <= 4);
});

// ---------------------------------------------------------------- what a Worker has to reimplement

test('near-tx: the same transaction bytes as tools/lib/near.mjs, for a function call with and without deposit', async () => {
  const key = { ...keyFromSecret(label('near-key')), accountId: 'relay.example.testnet' };
  const fields = { nonce: 12345n, blockHash: label('block'), receiverId: 'undo.example.testnet' };
  for (const [method, args, gas, deposit] of [['heartbeat', { vault: 'aa' }, 10n, 0n], ['create_vault', { args: { x: 1 } }, 120n, milliNear(50)]]) {
    const tools = signTransaction({ ...fields, signerId: key.accountId, key, actions: [action.call(method, args, gas * 1_000_000_000_000n, deposit)] });
    const page = await signedTransaction({ ...fields, signerId: key.accountId, publicKey: key.pub, actions: [callAction(method, args, gas, deposit)] }, async (hash) => ed25519.sign(hash, key.secret));
    assert.equal(page.base64, tools.base64);
    assert.equal(page.hash, tools.hash);
  }
});

test('near-tx: WebCrypto Ed25519 signs what noble signs, so a Worker can use it', async () => {
  const secret = label('webcrypto');
  // PKCS#8 for a raw Ed25519 seed. This is how a Worker imports its env binding.
  const pkcs8 = Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.from(secret)]);
  const key = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
  const message = label('message');
  const signature = new Uint8Array(await crypto.subtle.sign('Ed25519', key, message));
  assert.equal(toHex(signature), toHex(ed25519.sign(message, secret)));
});

test('views.parseSignerKey equals vault-client\'s', () => {
  const xy = new Uint8Array(64).fill(7);
  xy[63] = 9;
  const text = `secp256k1:${base58Encode(xy)}`;
  assert.equal(toHex(parseSignerKey(text)), toHex(toolsParseSignerKey(text)));
  xy[63] = 8;
  assert.equal(toHex(parseSignerKey(`secp256k1:${base58Encode(xy)}`)), toHex(toolsParseSignerKey(`secp256k1:${base58Encode(xy)}`)));
});

test('failureOf and returnValue equal the tools\' on real result shapes', () => {
  const ok = { status: { SuccessValue: Buffer.from('42').toString('base64') }, receipts_outcome: [] };
  const nested = { status: { SuccessValue: '' }, receipts_outcome: [{ outcome: { status: { Failure: { ActionError: { index: 0 } } } } }] };
  const top = { status: { Failure: { InvalidTxError: { InvalidNonce: { ak_nonce: 3, tx_nonce: 2 } } } }, receipts_outcome: [] };
  for (const r of [ok, nested, top, null]) {
    assert.equal(siteFailureOf(r), toolsFailureOf(r));
    assert.deepEqual(siteReturnValue(r), toolsReturnValue(r));
  }
});

// ---------------------------------------------------------------- the build

const LOCAL_CONFIG = {
  mode: 'local', contract: 'film.test.near', rpc: ['http://127.0.0.1:3030'], esplora: 'http://127.0.0.1:3002', relay: '/api/relay', funds: '/api/funds',
  btcTxUrl: null, btcAddressUrl: null, nearTxUrl: null, rpId: 'localhost', softPasskey: true,
};

const walk = (dir) => readdirSync(dir).flatMap((name) => {
  const path = join(dir, name);
  return statSync(path).isDirectory() ? walk(path) : [path];
});

function buildInto(config) {
  const out = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'undo-build-test-'));
  const result = build({ configObject: config, out, allowUnfilled: true });
  return { out, result, files: walk(out), done: () => rmSync(out, { recursive: true, force: true }) };
}

test('build: the tools files in a build are the tools files, byte for byte', () => {
  const b = buildInto(LOCAL_CONFIG);
  try {
    const shipped = b.files.filter((f) => f.includes(`${join(b.out, 'tools')}/`));
    assert.ok(shipped.length > 10);
    for (const f of shipped) assert.deepEqual(readFileSync(f), readFileSync(join(REPO, f.slice(b.out.length + 1))), f);
    for (const must of ['tools/lib/intent.mjs', 'tools/lib/spend.mjs', 'tools/lib/keys.mjs', 'tools/lib/esplora.mjs', 'tools/lib/btc.mjs', 'tools/vendor/noble/curves/nist.js']) {
      assert.ok(shipped.includes(join(b.out, must)), must);
    }
  } finally {
    b.done();
  }
});

test('build: nothing with a Node import, a test, a driver or a source map reaches the output', () => {
  const b = buildInto(LOCAL_CONFIG);
  try {
    for (const f of b.files) {
      assert.ok(!f.endsWith('.map'), f);
      if (!/\.m?js$/.test(f)) continue;
      const text = readFileSync(f, 'utf8');
      assert.ok(!/from\s+['"]node:/.test(text), `${f} imports node:`);
      assert.ok(!text.includes('sourceMappingURL'), f);
    }
    const names = b.files.map((f) => f.slice(b.out.length + 1));
    for (const never of ['tools/lib/near.mjs', 'tools/lib/vault-client.mjs', 'tools/lib/dispenser.mjs', 'tools/g2.mjs', 'site/test/stage.mjs', 'site/build.mjs', 'site/lib/near-tx.mjs']) {
      assert.ok(!names.includes(never), never);
    }
  } finally {
    b.done();
  }
});

test('build: the importable library holds no Buffer or process on a path a page calls', async () => {
  // Buffer appears in exactly two tools functions: bytes.mjs base64, which pages get from site/lib/base64.mjs
  // instead, and intent.mjs softAssertion, which only the tools' tests call. Pin that, so a third is noticed.
  const b = buildInto(LOCAL_CONFIG);
  try {
    const uses = [];
    for (const f of b.files.filter((x) => /\.m?js$/.test(x))) {
      readFileSync(f, 'utf8').split('\n').forEach((line, i) => {
        if (/\b(Buffer|process)\.[a-z]/.test(line) && !/^\s*(\/\/|\*)/.test(line)) uses.push(`${f.slice(b.out.length + 1)}:${i + 1}`);
      });
    }
    assert.deepEqual(uses.map((u) => u.split(':')[0]).sort(), ['tools/lib/bytes.mjs', 'tools/lib/bytes.mjs', 'tools/lib/intent.mjs']);
  } finally {
    b.done();
  }
});

test('build: the software authenticator ships only if the config asks', () => {
  const on = buildInto(LOCAL_CONFIG);
  const off = buildInto({ ...LOCAL_CONFIG, softPasskey: false });
  try {
    assert.ok(on.files.some((f) => f.endsWith('soft-authenticator.mjs')));
    assert.ok(!off.files.some((f) => f.endsWith('soft-authenticator.mjs')));
  } finally {
    on.done();
    off.done();
  }
});

test('build: refuses a bad config, a Node import and an unfilled contract', () => {
  assert.throws(() => build({ configObject: { ...LOCAL_CONFIG, esplora: 'https://mutinynet.example/api' }, out: join(tmpdir(), 'undo-never') }), /leaves this machine/);
  const dir = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'undo-graph-test-'));
  try {
    const bad = join(dir, 'bad.mjs');
    writeFileSync(bad, "import { readFileSync } from 'node:fs';\n");
    assert.throws(() => importGraph([bad], null), BuildRefused);
    const bare = join(dir, 'bare.mjs');
    writeFileSync(bare, "import x from 'left-pad';\n");
    assert.throws(() => importGraph([bare], null), BuildRefused);
    const outside = join(dir, 'outside.mjs');
    writeFileSync(outside, `import '${join(REPO, 'tools/g2.mjs')}';\n`);
    assert.throws(() => importGraph([outside], null), BuildRefused);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  // The repo's testnet config names a contract once it is deployed, so build the unfilled case from it.
  const testnet = JSON.parse(readFileSync(join(SITE, 'config/testnet.json'), 'utf8'));
  const unfilled = { ...testnet, contract: 'FILL-AT-DEPLOY.testnet' };
  assert.throws(() => build({ configObject: unfilled, out: join(tmpdir(), 'undo-never') }), /not filled in/);
});

test('build: a page can only reach the hosts its config names', () => {
  const headers = headersFor(checkConfig(LOCAL_CONFIG));
  assert.match(headers, /connect-src 'self' http:\/\/127\.0\.0\.1:3030 http:\/\/127\.0\.0\.1:3002;/);
  assert.match(headers, /script-src 'self'/);
  assert.match(headers, /frame-ancestors 'none'/);
  assert.ok(!headers.includes('unsafe'));
});

test('no production endpoint is written anywhere in site/lib, so test mode has nothing to fall back to', () => {
  for (const f of walk(join(SITE, 'lib'))) {
    const text = readFileSync(f, 'utf8');
    assert.ok(!/mutinynet\.com|fastnear|near\.org|near\.rocks|drpc|nearblocks|pages\.dev|signer-prod/.test(text), f);
  }
});

test('site/config/testnet.json is a valid live config apart from the contract the lead fills in', () => {
  const config = checkConfig(JSON.parse(readFileSync(join(SITE, 'config/testnet.json'), 'utf8')));
  assert.equal(config.softPasskey, false);
  assert.equal(config.labels.chip, 'signet test coins');
});
