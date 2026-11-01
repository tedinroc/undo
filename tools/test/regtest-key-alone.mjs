#!/usr/bin/env node
// A thief with the spend key alone, against a real node: bitcoind on regtest, local, with no peers, no
// wallet and standard relay policy on. The real script holds the coin. K_u's real signature goes in and
// nothing goes where K_m's belongs. It must be refused, and for K_m's check rather than K_u's: the same
// spend with K_u's taken out instead fails somewhere else, and with both signatures it is mined.
//
// UNDO_BITCOIN_BIN names the folder holding bitcoind and bitcoin-cli. Keys come from public labels.
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { makeTx, p2wpkhAddress, p2wpkhSpk, p2wshAddress, SEQUENCE_COSIGNED, sighash, witnessScript } from '../lib/btc.mjs';
import { utf8 } from '../lib/bytes.mjs';
import { secp256k1, sha256 } from '../lib/crypto.mjs';
import { assembleCosigned, cosignedVsize, withoutKmSig, withoutKuSig } from '../lib/g2-check.mjs';
import { publicSecp, spendKeys } from '../lib/keys.mjs';
import { keyAloneHalfSig } from '../lib/spend.mjs';

const TOOLS = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = process.env.UNDO_BITCOIN_BIN ?? resolve(TOOLS, '..', 'crates/undo-btc/.tools/bitcoin-32.1/bin');
const secret = (label) => sha256(utf8(`undo-test-only:regtest-key-alone:${label}`));
const work = mkdtempSync(join(tmpdir(), 'undo-regtest-'));
let failures = 0;
const report = (ok, name, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'} [regtest] ${name}${ok ? '' : ` ${detail}`}`);
  if (!ok) failures += 1;
};

const freePort = () => new Promise((res) => {
  const s = createServer().listen(0, '127.0.0.1', () => {
    const { port } = s.address();
    s.close(() => res(port));
  });
});

async function main() {
  const rpcPort = await freePort();
  const datadir = join(work, 'node');
  spawnSync('mkdir', ['-p', datadir]);
  const node = spawn(join(BIN, 'bitcoind'), ['-regtest', '-server=1', '-listen=0', '-dnsseed=0', '-fixedseeds=0', '-discover=0', '-disablewallet=1', '-acceptnonstdtxn=0', '-printtoconsole=0', '-dbcache=8', '-par=1', `-datadir=${datadir}`, `-rpcport=${rpcPort}`], { stdio: 'ignore' });
  const run = (...args) => spawnSync(join(BIN, 'bitcoin-cli'), ['-regtest', `-datadir=${datadir}`, `-rpcport=${rpcPort}`, ...args], { encoding: 'utf8' });
  const cli = (...args) => {
    const r = run(...args);
    if (r.status !== 0) throw new Error(`${args[0]}: ${r.stderr.trim()}`);
    return r.stdout.trim();
  };
  try {
    cli('-rpcwait', '-rpcwaittimeout=60', 'getblockcount');

    const seed = secret('seed');
    const { ku } = spendKeys(seed);
    const km = secret('k_m');
    const script = witnessScript(ku.pub, publicSecp(km), publicSecp(secret('k_e')), 6);
    const address = p2wshAddress('regtest', script);
    const dest = secp256k1.getPublicKey(secret('dest'), true);
    const to = p2wpkhSpk(dest);
    const other = p2wpkhAddress('regtest', dest);

    // The vault's coin is a coinbase, which needs 100 confirmations before anything can spend it.
    const [first] = JSON.parse(cli('generatetoaddress', '1', address));
    const tx0 = JSON.parse(cli('getblock', first, '2')).tx[0];
    const vout = tx0.vout.findIndex((o) => o.scriptPubKey.address === address);
    const coin = { txid: tx0.txid, vout, value: Math.round(tx0.vout[vout].value * 1e8) };
    cli('generatetoaddress', '101', other);

    const amount = coin.value - cosignedVsize({ coin, to, amount: 1, script }) * 2;
    const halfRs = keyAloneHalfSig({ seed, script, coin, to, amount });
    const thief = withoutKmSig({ coin, to, amount, halfRs, script });

    const accept = (raw) => JSON.parse(cli('testmempoolaccept', JSON.stringify([raw])))[0];
    const send = (raw) => run('sendrawtransaction', raw);

    const alone = accept(thief.raw);
    report(alone.allowed === false, `the key alone is refused (${alone['reject-reason']}): ${alone['reject-details'] ?? ''}`, JSON.stringify(alone));
    const answer = send(thief.raw);
    report(answer.status !== 0, `sendrawtransaction answers: ${answer.stderr.trim()}`, answer.stdout);
    report(/false\/empty top stack/i.test(answer.stderr), 'it got past K_u\'s check and failed at K_m\'s: the script ran to its end and left false', answer.stderr);
    report(!/CHECKSIGVERIFY/i.test(answer.stderr), 'and it is not the OP_CHECKSIGVERIFY answer', answer.stderr);
    report(cli('gettxout', coin.txid, String(coin.vout)) !== '', 'the coin is still unspent');

    const digest = sighash(makeTx([coin], SEQUENCE_COSIGNED, [{ value: amount, spk: to }]), 0, script, coin.value);
    const mpcRs = secp256k1.sign(digest, km, { lowS: true, prehash: false }).toCompactRawBytes();
    const both = assembleCosigned({ coin, to, amount, mpcRs, halfRs, script });

    const noKu = send(withoutKuSig(both));
    report(noKu.status !== 0 && /CHECKSIGVERIFY/i.test(noKu.stderr), 'control: without K_u\'s signature the answer names OP_CHECKSIGVERIFY, so the two refusals differ', noKu.stderr);

    report(accept(both).allowed === true, 'control: with K_m\'s signature too, the same spend is allowed');
    const sentId = cli('sendrawtransaction', both);
    report(sentId === thief.id, 'and it has the same txid as what the thief sent');
    const [mined] = JSON.parse(cli('generatetoaddress', '1', other));
    report(JSON.parse(cli('getblock', mined, '1')).tx.includes(sentId), 'and it is mined');
    report(cli('gettxout', coin.txid, String(coin.vout)) === '', 'the coin is spent now');
  } finally {
    try {
      cli('stop');
    } catch {
      node.kill();
    }
    await new Promise((r) => { node.on('exit', r); setTimeout(r, 15000); });
    rmSync(work, { recursive: true, force: true });
  }
  if (failures) process.exit(1);
  console.log('REGTEST OK');
}

main().catch((err) => {
  console.error(`regtest stopped: ${err.message}`);
  process.exit(1);
});
