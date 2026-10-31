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
  ['escape: high-fee guard gone', 'escape.mjs', "if (a.fee * 100 > total * HIGH_FEE_PERCENT && !a['allow-high-fee']) {", 'if (false) {'],
  ['keys: intent key label changed', 'lib/keys.mjs', "'undo-k_e-intent-secp256k1-v1'", "'undo-k_e-intent-v2'"],
  ['cold: leaf key signs', 'lib/cold-intent.mjs', 'signSecp(digest, keys.intent.secret)', 'signSecp(digest, keys.leaf.secret)'],
  ['cold: tag changed', 'lib/intent.mjs', "export const COLD_TAG = 'undo-cold-v1';", "export const COLD_TAG = 'undo-cold-v2';"],
  ['cold: nonce not bound', 'lib/intent.mjs', 'b.option(nonce, b.u64),\n  ));\n}\n\n/** `txid`', 'b.option(null, b.u64),\n  ));\n}\n\n/** `txid`'],
  ['cold: expiry not bound', 'lib/intent.mjs', 'b.raw(sha256(args)),\n    b.u64(expiresAt),', 'b.raw(sha256(args)),\n    b.u64(0),'],
  ['cold: args not hashed in', 'lib/intent.mjs', 'b.raw(sha256(args)),', 'b.raw(sha256(new Uint8Array(0))),'],
  ['leaf proof: tag dropped', 'lib/intent.mjs', 'return sha256(concat(utf8(LEAF_POP_TAG), createDigestBytes));', 'return createDigestBytes;'],
  ['freeze: too-long freeze allowed', 'freeze.mjs', 'if (fields.until > max) throw', 'if (false) throw'],
  ['freeze: digest flag ignored', 'freeze.mjs', "if (raw.includes('--digest')) throw new Error('this tool never signs a digest handed to it. Give it the fields');", "if (raw.includes('--digest')) raw.splice(raw.indexOf('--digest'), 2);"],
  ['freeze: signs without asking', 'freeze.mjs', "if (!a.yes && !(await askYes('Type yes to sign:'))) {", 'if (false) {'],
  ['freeze: wrong vault allowed', 'freeze.mjs', "if (a.vault && /^[0-9a-f]{64}$/.test(file.vaultId) && a.vault !== file.vaultId) {", 'if (false) {'],
  ['freeze: may overwrite the recovery file', 'freeze.mjs', "if (existsSync(a.out) && realpathSync(a.out) === realpathSync(a.recovery)) throw new Error('--out would overwrite the recovery file');", ''],
  ['human-key: key may live in the repo', 'human-key.mjs', "throw new Error('keys never live inside the repo');", 'return;'],
  ['human-key: dispenser overwrites', 'human-key.mjs', "if (existsSync(path)) {\n    const data", "if (false) {\n    const data"],
  ['human-key: address before read-back', 'human-key.mjs', "if (!back || addressOf('mainnet', fixedHex(back, 32, 'keychain item')) !== address) throw new Error('the Keychain did not keep the key. Nothing to fund');", ''],
  ['human-key: secret on the command line', 'human-key.mjs', "spawnSync('security', ['-i'], {", "spawnSync('security', ['-i', toHex(secret)], {"],
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

const only = process.argv[2];
let survived = 0;
let notApplied = 0;
const base = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'undo-mutants-'));
try {
  for (const [name, file, from, to] of MUTANTS) {
    if (only && !name.includes(only)) continue;
    const repo = join(base, 'repo');
    rmSync(repo, { recursive: true, force: true });
    mkdirSync(repo, { recursive: true });
    cpSync(TOOLS, join(repo, 'tools'), { recursive: true, filter: (p) => !p.includes('rust-check') });
    cpSync(join(REPO, 'scripts'), join(repo, 'scripts'), { recursive: true });
    const path = resolve(repo, 'tools', file);
    const text = readFileSync(path, 'utf8');
    if (!text.includes(from)) {
      console.log(`NOT APPLIED ${name}`);
      notApplied += 1;
      continue;
    }
    writeFileSync(path, text.replace(from, to));
    const env = { ...process.env, UNDO_BLOCKED_WORDS: resolve(REPO, '../plan/blocked-words.txt') };
    const r = spawnSync('node', ['--test', join(repo, 'tools/test/offline.test.mjs'), join(repo, 'tools/test/human-scripts.test.mjs')], { encoding: 'utf8', env, timeout: 180_000 });
    if (r.status === 0) {
      console.log(`SURVIVED ${name}`);
      survived += 1;
    } else {
      console.log(`killed ${name}`);
    }
  }
} finally {
  rmSync(base, { recursive: true, force: true });
}
console.log(`${MUTANTS.length} mutants, survived ${survived}, not applied ${notApplied}`);
process.exit(survived || notApplied ? 1 : 0);
