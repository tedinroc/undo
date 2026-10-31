#!/usr/bin/env node
// escape.mjs against a real node: bitcoind on regtest, local, with no peers, no wallet and standard
// relay policy on. Refused one block before the CSV matures, mined at it. Reads only a recovery file
// and a UTXO list, as the tool promises.
//
// UNDO_BITCOIN_BIN names the folder holding bitcoind and bitcoin-cli. UNDO_TOOLS_CHECK_BIN makes the
// recovery file. CSV is 150 because regtest coins come from coinbases, which need 100 confirmations
// first, so a smaller CSV would have matured before the coin could be spent at all.
import { spawn, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { p2wpkhAddress } from '../lib/btc.mjs';
import { toHex, utf8 } from '../lib/bytes.mjs';
import { secp256k1, sha256 } from '../lib/crypto.mjs';

const TOOLS = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const BIN = process.env.UNDO_BITCOIN_BIN ?? resolve(TOOLS, '..', 'crates/undo-btc/.tools/bitcoin-32.1/bin');
const CHECK = process.env.UNDO_TOOLS_CHECK_BIN;
const CSV = 150;
const FEE = 2000;
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
  const cli = (...args) => {
    const r = spawnSync(join(BIN, 'bitcoin-cli'), ['-regtest', `-datadir=${datadir}`, `-rpcport=${rpcPort}`, ...args], { encoding: 'utf8' });
    if (r.status !== 0) throw new Error(`${args[0]}: ${r.stderr.trim()}`);
    return r.stdout.trim();
  };
  try {
    cli('-rpcwait', '-rpcwaittimeout=60', 'getblockcount');
    report(JSON.parse(cli('getnetworkinfo')).version >= 320000, 'node is up');

    const recovery = join(work, 'cold-file.json');
    const made = spawnSync(CHECK, ['make-recovery', 'regtest', 'regtest-escape', String(CSV), 'vault-regtest'], { encoding: 'utf8' });
    writeFileSync(recovery, made.stdout, { mode: 0o600 });
    const { address, cold_key: secret } = JSON.parse(readFileSync(recovery, 'utf8'));

    // The vault's coins: two coinbases at heights 1 and 2. Then bury them just short of the CSV.
    const hashes = JSON.parse(cli('generatetoaddress', '2', address));
    const coins = hashes.map((h) => {
      const tx = JSON.parse(cli('getblock', h, '2')).tx[0];
      const vout = tx.vout.findIndex((o) => o.scriptPubKey.address === address);
      return { txid: tx.txid, vout, value: Math.round(tx.vout[vout].value * 1e8) };
    });
    const other = p2wpkhAddress('regtest', secp256k1.getPublicKey(sha256(utf8('undo-test-only:regtest-miner')), true));
    const youngest = () => 2; // Height of the younger coin.
    const utxos = join(work, 'utxos.json');
    writeFileSync(utxos, JSON.stringify(coins));
    const dest = p2wpkhAddress('regtest', secp256k1.getPublicKey(sha256(utf8('undo-test-only:regtest-dest')), true));

    const out = spawnSync('node', [join(TOOLS, 'escape.mjs'), '--recovery', recovery, '--utxos', utxos, '--to', dest, '--fee', String(FEE)], { encoding: 'utf8' });
    report(out.status === 0, 'escape.mjs built a transaction from the file and the list alone', out.stderr);
    const raw = out.stdout.match(/^hex\s+([0-9a-f]+)$/m)?.[1];
    report(Boolean(raw) && !out.stdout.includes(secret), 'it printed hex and no secret');

    const accept = () => JSON.parse(cli('testmempoolaccept', JSON.stringify([raw])))[0];

    // A block at height h can include the spend when h - coin_height >= csv, so a mempool test at
    // tip t asks about h = t + 1.
    const tipFor = (height) => {
      const tip = Number(cli('getblockcount'));
      if (height > tip) cli('generatetoaddress', String(height - tip), other);
    };
    tipFor(youngest() + CSV - 2);
    const early = accept();
    report(early.allowed === false && early['reject-reason'] === 'non-BIP68-final', `refused one block before maturity (${early['reject-reason']})`, JSON.stringify(early));

    tipFor(youngest() + CSV - 1);
    const ripe = accept();
    report(ripe.allowed === true, 'allowed at maturity, under standard relay policy', JSON.stringify(ripe));
    const sentId = cli('sendrawtransaction', raw);
    const [mined] = JSON.parse(cli('generatetoaddress', '1', other));
    const block = JSON.parse(cli('getblock', mined, '1'));
    report(block.tx.includes(sentId), `mined at height ${block.height}, ${CSV} blocks after the younger coin`);
    const gone = coins.every((c) => cli('gettxout', c.txid, String(c.vout)) === '');
    report(gone, 'both coins are spent');
    const size = JSON.parse(cli('getrawtransaction', sentId, 'true', mined));
    const paid = size.vout[0].value;
    report(Math.round(paid * 1e8) === coins.reduce((s, c) => s + c.value, 0) - FEE, 'the destination got everything but the fee');
    console.log(`measured: ${coins.length} inputs, ${size.vsize} vB, ${(FEE / size.vsize).toFixed(2)} sat/vB, script ${toHex(new Uint8Array(0)).length + JSON.parse(readFileSync(recovery, 'utf8')).witness_script.length / 2} bytes`);
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
