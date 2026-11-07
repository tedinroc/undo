#!/usr/bin/env node
// Breaks the tools one line at a time, in a scratch copy, and checks that the offline tests notice.
// A survivor means a test is not testing what it says. Sandbox-only behaviour is not covered here.
//
//   UNDO_TOOLS_CHECK_BIN=... node tools/test/mutants.mjs
import { spawnSync } from 'node:child_process';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const TOOLS = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const REPO = resolve(TOOLS, '..');
const MUTANTS = [
  ['btc: no low-S', 'lib/btc.mjs', 's > HALF_ORDER ? ORDER - s : s', 's'],
  ['btc: CSV 128 pushed as one byte', 'lib/btc.mjs', 'if (v <= 127) return', 'if (v <= 128) return'],
  ['btc: CSV 32768 without the sign byte', 'lib/btc.mjs', 'return Uint8Array.of(3, v & 0xff, v >> 8, 0);', 'return Uint8Array.of(2, v & 0xff, v >> 8);'],
  ['btc: script operand order', 'lib/btc.mjs', 'Uint8Array.of(0x63, 0x21), ku, Uint8Array.of(0xad, 0x21), km,', 'Uint8Array.of(0x63, 0x21), km, Uint8Array.of(0xad, 0x21), ku,'],
  ['btc: sighash skips the value', 'lib/btc.mjs', 'compactSize(script.length), script, u64le(value), u32le(input.sequence),', 'compactSize(script.length), script, u64le(0), u32le(input.sequence),'],
  ['btc: address checksum ignored', 'lib/btc.mjs', "if (check !== (version === 0 ? BECH32 : BECH32M)) throw new Error('bad checksum');", ''],
  ['btc: base58 checksum ignored', 'lib/btc.mjs', "if (!equal(check, raw.slice(21))) throw new Error('bad checksum');", ''],
  ['recovery: checksum ignored', 'lib/recovery.mjs', "if (toHex(sha256(utf8(checksumText(w)))) !== w.checksum) fail('Checksum', 'checksum does not match, the file is damaged');", ''],
  ['recovery: address ignored', 'lib/recovery.mjs', "if (p2wshAddress(w.network, script) !== w.address) fail('AddressMismatch', 'address does not match the script and network');", ''],
  ['recovery: cold key not matched to script', 'lib/recovery.mjs', "if (!equal(coldPub, parts.ke)) fail('ColdKeyMismatch', 'cold key is not the one in the script');", ''],
  ['recovery: unknown fields allowed', 'lib/recovery.mjs', 'keys.length !== FIELDS.length || ', ''],
  ['recovery: dust allowed', 'lib/recovery.mjs', 'send < DUST_LIMIT', 'send < 0'],
  ['recovery: burn allowed', 'lib/recovery.mjs', "if (destination.length === 0 || destination[0] === 0x6a) fail('Destination', 'destination would burn the coins');", ''],
  ['recovery: wrong nSequence on escape', 'lib/recovery.mjs', 'makeTx(coins, file.csv,', 'makeTx(coins, file.csv - 1,'],
  ['recovery: secret enumerable', 'lib/recovery.mjs', "{ value: cold, enumerable: false }", '{ value: cold, enumerable: true }'],
  ['escape: high-fee guard gone', 'escape.mjs', "if (a.fee > HIGH_FEE_FLOOR_SATS && a.fee * 100 > total * HIGH_FEE_PERCENT && !a['allow-high-fee']) {", 'if (false) {'],
  ['escape: high-fee guard has no floor', 'escape.mjs', "if (a.fee > HIGH_FEE_FLOOR_SATS && a.fee * 100", 'if (a.fee * 100'],
  ['escape: high-fee guard has no percentage', 'escape.mjs', "a.fee > HIGH_FEE_FLOOR_SATS && a.fee * 100 > total * HIGH_FEE_PERCENT &&", 'a.fee > HIGH_FEE_FLOOR_SATS &&'],
  ['escape: the fee race goes unsaid', 'escape.mjs', "console.log('fee race ", "void ('fee race "],
  ['keys: intent key label changed', 'lib/keys.mjs', "'undo-k_e-intent-secp256k1-v1'", "'undo-k_e-intent-v2'"],
  ['cold: leaf key signs', 'lib/cold-intent.mjs', 'signSecp(digest, keys.intent.secret)', 'signSecp(digest, keys.leaf.secret)'],
  ['cold: tag changed', 'lib/intent.mjs', "export const COLD_TAG = 'undo-cold-v1';", "export const COLD_TAG = 'undo-cold-v2';"],
  ['cold: nonce not bound', 'lib/intent.mjs', 'b.option(nonce, b.u64),\n  ));\n}\n\n/** `txid`', 'b.option(null, b.u64),\n  ));\n}\n\n/** `txid`'],
  ['cold: expiry not bound', 'lib/intent.mjs', 'b.raw(sha256(args)),\n    b.u64(expiresAt),', 'b.raw(sha256(args)),\n    b.u64(0),'],
  ['cold: args not hashed in', 'lib/intent.mjs', 'b.raw(sha256(args)),', 'b.raw(sha256(new Uint8Array(0))),'],
  ['leaf proof: tag dropped', 'lib/intent.mjs', 'return sha256(concat(utf8(LEAF_POP_TAG), createDigestBytes));', 'return createDigestBytes;'],
  ['freeze: too-long freeze allowed', 'freeze.mjs', 'if (named !== undefined && fields.until > max) throw', 'if (false) throw'],
  ['freeze: the default stops at this clock plus the period', 'freeze.mjs', 'fields.until = named ?? expiresAt + period;', 'fields.until = named ?? max;'],
  ['freeze: digest flag ignored', 'freeze.mjs', "if (raw.includes('--digest')) throw new Error('this tool never signs a digest handed to it. Give it the fields');", "if (raw.includes('--digest')) raw.splice(raw.indexOf('--digest'), 2);"],
  ['freeze: signs without asking', 'freeze.mjs', "if (!a.yes && !(await askYes('Type yes to sign:'))) {", 'if (false) {'],
  ['freeze: wrong vault allowed', 'freeze.mjs', "if (a.vault && /^[0-9a-f]{64}$/.test(file.vaultId) && a.vault !== file.vaultId) {", 'if (false) {'],
  ['freeze: may overwrite the recovery file', 'freeze.mjs', "if (existsSync(a.out) && realpathSync(a.out) === realpathSync(a.recovery)) throw new Error('--out would overwrite the recovery file');", ''],
  ['human-key: key may live in the repo', 'human-key.mjs', "throw new Error('keys never live inside the repo');", 'return;'],
  ['human-key: dispenser overwrites', 'human-key.mjs', "if (existsSync(path)) {\n    const data", "if (false) {\n    const data"],
  ['human-key: address before read-back', 'human-key.mjs', "if (!back || addressOf('mainnet', fixedHex(back, 32, 'keychain item')) !== address) throw new Error('the Keychain did not keep the key. Nothing to fund');", ''],
  ['human-key: secret on the command line', 'human-key.mjs', "spawnSync('security', ['-i'], {", "spawnSync('security', ['-i', toHex(secret)], {"],
  ['g2: any status counts as a refusal', 'lib/esplora.mjs', "if (status !== 400) return { kind: 'transient', status, text };", ''],
  ['g2: a busy node counts as a refusal', 'lib/esplora.mjs', "if (NODE_BUSY.test(text)) return { kind: 'transient', status, text };", ''],
  ['g2: tip takes an empty answer', 'lib/esplora.mjs', "return trimmed !== '' && Number.isSafeInteger(height) && height >= 0 ? height : undefined;", 'return height;'],
  ['g2: a 404 reads as no answer needed', 'lib/esplora.mjs', 'const value = text === null ? undefined : parse(text);', "const value = text === null ? [] : parse(text);"],
  ['g2: anything reads as a coin list', 'lib/esplora.mjs', 'return Array.isArray(list) ? list : undefined;', 'return list ?? undefined;'],
  ['g2: non-hex reads as bytes', 'lib/esplora.mjs', "return text && /^[0-9a-f]+$/i.test(text) ? text.toLowerCase() : null;", 'return text ?? null;'],
  ['g2: utxo set answer is not already', 'lib/esplora.mjs', '|already-in-utxo|already in utxo/i', '/i'],
  ['g2: NEAR follows redirects', 'lib/near.mjs', "      redirect: 'error',\n", ''],
  ['g2: NEAR key file quoted', 'lib/near.mjs', "throw new Error(err.code ? `key file: ${err.code}` : 'key file is not JSON');", 'throw err;'],
  ['g2: K_u control keeps the signature', 'lib/g2-check.mjs', 'tx.inputs[0].witness[1] = new Uint8Array(0);', ''],
  ['g2: CSV control at nSequence csv', 'lib/g2-check.mjs', 'makeTx([coin], file.csv - 1,', 'makeTx([coin], file.csv,'],
  ['g2: checker takes any label', 'test/check-g2-proof.mjs', "need(p.label === 'live-mutinynet', `its label is ${p.label}, not a live run`);", ''],
  ['g2: any refusal proves the CSV', 'lib/esplora.mjs', "if (/non-BIP68-final|sequence[- ]locks? (not|on)/i.test(text)) return 'bip68';", "return 'bip68';"],
  ['g2: a web page counts as a node', 'lib/esplora.mjs', "if (/<html/i.test(text)) return { kind: 'transient', status, text: 'a web page, not a node' };", ''],
  ['g2: any 2xx counts as accepted', 'lib/esplora.mjs', "return text.toLowerCase() === txid ? { kind: 'accepted', status, text } : { kind: 'transient', status, text: 'a 2xx that does not name this transaction' };", "return { kind: 'accepted', status, text };"],
  ['g2: redirects followed', 'lib/esplora.mjs', "redirect: 'error', ", ''],
  ['g2: no look after a 5xx', 'lib/esplora.mjs', "if (seen?.txid === txid) return { kind: 'accepted', status: answer.status, text: answer.text, landed_despite: true };", ''],
  ['g2: already taken on faith', 'lib/esplora.mjs', "if (seen?.txid === txid) return { kind: 'accepted', status: answer.status, text: answer.text, already: true };", "return { kind: 'accepted', status: answer.status, text: answer.text, already: true };"],
  ['g2: Esplora allow list ignored', 'lib/esplora.mjs', "if (regtest ? !isLocal(esplora) : !ESPLORA_ALLOW.includes(esplora)) throw new EndpointRefused('that Esplora is not on the allow list');", ''],
  ['g2: RPC allow list ignored', 'lib/esplora.mjs', "if (regtest ? !isLocal(url) : !NEAR_RPC_ALLOW.includes(url)) throw new EndpointRefused('that NEAR RPC is not on the allow list');", ''],
  ['g2: rehearsal may use any host', 'lib/esplora.mjs', "u.protocol === 'http:' && LOCAL_HOSTS.has(u.hostname)", 'true'],
  ['g2: high S not checked', 'lib/g2-check.mjs', "if (toBig(s) > HALF_ORDER) return { reason: 'high_s', detail: name };", ''],
  ['g2: signature not verified', 'lib/g2-check.mjs', "if (!verifies(r, s, digest, pub)) return { reason: 'bad_signature', detail: name };", ''],
  ['g2: hash type not checked', 'lib/g2-check.mjs', "if (sig[sig.length - 1] !== 1) return { reason: 'bad_sighash_type', detail: name };", ''],
  ['g2: padded r allowed', 'lib/g2-check.mjs', "if (lenR > 1 && sig[4] === 0 && !(sig[5] & 0x80)) return 'padded r';", ''],
  ['g2: padded s allowed', 'lib/g2-check.mjs', "if (lenS > 1 && sig[lenR + 6] === 0 && !(sig[lenR + 7] & 0x80)) return 'padded s';", ''],
  ['g2: signatures may swap', 'lib/g2-check.mjs', "checkSig(w[0], digest, km, 'K_m') ?? checkSig(w[1], digest, ku, 'K_u')", "checkSig(w[1], digest, ku, 'K_u')"],
  ['g2: K_u not checked', 'lib/g2-check.mjs', "checkSig(w[0], digest, km, 'K_m') ?? checkSig(w[1], digest, ku, 'K_u')", "checkSig(w[0], digest, km, 'K_m')"],
  ['g2: amount not compared', 'lib/g2-check.mjs', "if (Number(output.value) !== amount) return { reason: 'wrong_amount', detail: String(output.value) };", ''],
  ['g2: output not compared', 'lib/g2-check.mjs', "if (!equal(output.spk, to)) return { reason: 'wrong_output', detail: toHex(output.spk) };", ''],
  ['g2: input not compared', 'lib/g2-check.mjs', "if (input.coin.txid !== coin.txid || input.coin.vout !== coin.vout) return { reason: 'wrong_input', detail: `${input.coin.txid}:${input.coin.vout}` };", ''],
  ['g2: sequence not compared', 'lib/g2-check.mjs', "if (input.sequence !== sequence) return { reason: 'wrong_sequence', detail: String(input.sequence) };", ''],
  ['g2: script not compared', 'lib/g2-check.mjs', "if (!equal(input.witness[witnessItems - 1], script)) return { reason: 'wrong_witness_script', detail: 'not the vault script' };", ''],
  ['g2: read-back skips the bytes', 'lib/g2-check.mjs', "if (hexBack !== rawHex) return { reason: 'readback_bytes', detail: 'the mined bytes differ from the bytes sent' };", ''],
  ['g2: read-back takes unconfirmed', 'lib/g2-check.mjs', "if (!status?.confirmed || !Number.isInteger(status.block_height)) return { reason: 'readback_not_mined', detail: 'not confirmed' };", ''],
  ['g2: read-back skips the witness', 'lib/g2-check.mjs', "if (items(vin.witness) !== items(witnessHex)) return { reason: 'readback_witness', detail: 'witness differs' };", ''],
  ['g2: maturity one block late', 'lib/g2-check.mjs', 'coinHeight + csv - 1', 'coinHeight + csv'],
  ['g2: dispenser network ignored', 'lib/dispenser.mjs', "if (w.network !== network) throw new Error(`dispenser file is not for ${network}`);", ''],
  ['g2: dispenser address unchecked', 'lib/dispenser.mjs', "if (p2wpkhAddress(network, pub) !== w.address) throw new Error('dispenser address is not the key\\'s address');", ''],
  ['g2: unconfirmed coins spent', 'lib/dispenser.mjs', 'utxos.filter((u) => u.status?.confirmed)', 'utxos'],
  ['g2: dispenser secret enumerable', 'lib/dispenser.mjs', "{ value: secret, enumerable: false }", '{ value: secret, enumerable: true }'],
  ['human 01: no yes needed', '../scripts/human/01-testnet-accounts.sh', 'if [ "$answer" != "yes" ]; then', 'if false; then'],
  ['human 02: no yes needed', '../scripts/human/02-dispenser-address.sh', 'if [ "$answer" != "yes" ]; then', 'if false; then'],
  ['human 03: no yes needed', '../scripts/human/03-funding-key.sh', 'if [ "$answer" != "yes" ]; then', 'if false; then'],
  ['human 01: no private folder', '../scripts/human/01-testnet-accounts.sh', '"$HERE/00-private-setup.sh"\n', ''],
  ['human 00: the folder is left open', '../scripts/human/00-private-setup.sh', 'chmod 700 "$DIR"', ':'],
  ['human 00: the handoff has no wrangler environment', '../scripts/human/00-private-setup.sh', 'XDG_CONFIG_HOME=$prefs', 'XDG_CONFIG_HOME=<fill in>'],
  ['human 01: key files left readable', '../scripts/human/01-testnet-accounts.sh', 'chmod -R go-rwx "$HOME/.near-credentials"', ':'],
  ['human 03: key file left readable', '../scripts/human/03-funding-key.sh', 'chmod 600 "${files[0]}"', ':'],
  ['human 03: no directory lock', '../scripts/human/03-funding-key.sh', 'chmod 700 "$DEPLOYER_DIR"', ':'],
  ['install: checksum ignored', '../scripts/human/install-near-cli.sh', 'if [ -z "$want" ] || [ "$want" != "$got" ]; then', 'if false; then'],
];

// A run that timed out, or stopped with no test failing, says nothing about the mutant, so it is no kill.
const judge = (r) => {
  if (r.status === 0) return 'SURVIVED';
  if (r.status === null || r.error) return 'NOT JUDGED';
  return /^(?:# fail|ℹ fail) [1-9]/m.test(r.stdout ?? '') ? 'killed' : 'NOT JUDGED';
};

if (process.argv[2] === '--self-test') {
  const cases = [
    [{ status: 0, stdout: 'ℹ fail 0' }, 'SURVIVED'],
    [{ status: 1, stdout: 'ℹ pass 3\nℹ fail 1\n' }, 'killed'],
    [{ status: 1, stdout: '# pass 3\n# fail 2\n' }, 'killed'],
    [{ status: null, stdout: 'ℹ fail 1', error: { code: 'ETIMEDOUT' } }, 'NOT JUDGED'],
    [{ status: 1, stdout: 'ℹ pass 3\nℹ fail 0\n' }, 'NOT JUDGED'],
    [{ status: 1, stdout: '' }, 'NOT JUDGED'],
  ];
  const wrong = cases.filter(([run, want]) => judge(run) !== want);
  console.log(`self-test: ${cases.length - wrong.length} of ${cases.length}`);
  process.exit(wrong.length ? 1 : 0);
}

const only = process.argv[2];
let survived = 0;
let notApplied = 0;
let notJudged = 0;
const base = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'undo-mutants-'));
const freshCopy = () => {
  const repo = join(base, 'repo');
  rmSync(repo, { recursive: true, force: true });
  mkdirSync(join(repo, 'proofs'), { recursive: true });
  cpSync(TOOLS, join(repo, 'tools'), { recursive: true, filter: (p) => !p.includes('rust-check') });
  cpSync(join(REPO, 'scripts'), join(repo, 'scripts'), { recursive: true });
  return repo;
};
const runTests = (repo) => spawnSync('node', ['--test', join(repo, 'tools/test/offline.test.mjs'), join(repo, 'tools/test/g2-units.test.mjs'), join(repo, 'tools/test/human-scripts.test.mjs')], {
  encoding: 'utf8', env: { ...process.env, UNDO_BLOCKED_WORDS: resolve(REPO, '../plan/blocked-words.txt') }, timeout: 180_000,
});
try {
  // The control. If the tests fail on an unbroken copy, every mutant below would read as killed.
  const control = runTests(freshCopy());
  if (control.status !== 0) {
    console.log(`CONTROL FAILED: the tests do not pass on an unbroken copy, so no score means anything.\n${control.stdout.split('\n').filter((l) => l.startsWith('not ok')).join('\n')}`);
    process.exit(2);
  }
  console.log('control passed: the tests pass on an unbroken copy');
  for (const [name, file, from, to] of MUTANTS) {
    if (only && !name.includes(only)) continue;
    const repo = freshCopy();
    const path = resolve(repo, 'tools', file);
    const text = readFileSync(path, 'utf8');
    if (!text.includes(from)) {
      console.log(`NOT APPLIED ${name}`);
      notApplied += 1;
      continue;
    }
    writeFileSync(path, text.replace(from, to));
    const verdict = judge(runTests(repo));
    console.log(`${verdict} ${name}`);
    if (verdict === 'SURVIVED') survived += 1;
    if (verdict === 'NOT JUDGED') notJudged += 1;
  }
} finally {
  rmSync(base, { recursive: true, force: true });
}
console.log(`${MUTANTS.length} mutants, survived ${survived}, not applied ${notApplied}, not judged ${notJudged}`);
process.exit(survived || notApplied || notJudged ? 1 : 0);
