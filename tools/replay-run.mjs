#!/usr/bin/env node
// Builds site/pages/replay/run.json, the replay page's only data, from the two real records in proofs/: the G2 run on
// Mutinynet and NEAR testnet (proofs/g2.json) and the refused key-alone spend on the same test vault
// (proofs/s2-refusal.json). Nothing here is typed by hand: every hash, time, amount and node answer is copied from
// those files, so the page cannot show a hash that did not happen. site/test/landing.test.mjs rebuilds it and
// compares, so the file cannot drift from its sources.
//
//   node tools/replay-run.mjs            writes site/pages/replay/run.json
//   node tools/replay-run.mjs --check    exits 1 if the file is not what the proofs make
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const RUN_JSON = join(REPO, 'site', 'pages', 'replay', 'run.json');

const read = (name) => JSON.parse(readFileSync(join(REPO, 'proofs', name), 'utf8'));
const NEAR = 'NEAR testnet';
const BTC = 'Mutinynet';
const dateOf = (iso) => iso.slice(0, 10);
const isoOf = (ms) => new Date(ms).toISOString();
const mmss = (ms) => `${Math.floor(ms / 60000)}:${String(Math.floor((ms % 60000) / 1000)).padStart(2, '0')}`;

const nearTx = (hash, what) => ({ kind: 'hash', chain: NEAR, type: 'tx', hash, what });
const btcTx = (hash, what) => ({ kind: 'hash', chain: BTC, type: 'txid', hash, what });
const btcAddress = (hash, what) => ({ kind: 'hash', chain: BTC, type: 'address', hash, what });
const node = (text) => ({ kind: 'node', chain: BTC, text });
const say = (text) => ({ kind: 'text', text });

export function buildRun({ g2 = read('g2.json'), s2 = read('s2-refusal.json') } = {}) {
  if (g2.label !== 'live-mutinynet' || g2.gate !== 'G2' || g2.chain_id !== 'testnet') throw new Error('proofs/g2.json is not the live G2 record');
  if (s2.schema !== 'undo-s2-refusal-v1' || s2.node_answer.kind !== 'rejected' || s2.node_answer.refusal !== 'script') throw new Error('proofs/s2-refusal.json is not a script refusal');
  if (s2.vault.id !== g2.vault.id || s2.funding_coin.vault_address !== g2.vault.address) throw new Error('the two records are not the same test vault');
  const c = g2.cosigned;
  const e = g2.escape;
  const g2Date = dateOf(g2.coins[0].recorded_at);
  const s2Date = dateOf(s2.node_answer.at_utc);
  const executed = c.attempts.find((x) => x.outcome === 'signed');
  return {
    schema: 'undo-replay-v1',
    label: 'replay',
    title: 'Replay of earlier runs',
    note: 'Real hashes from two earlier runs on one test vault, shown in story order. Nothing on this page is happening now, and no clock here is running.',
    chip: s2.chip,
    vault: { id: g2.vault.id, address: g2.vault.address, contract: g2.contract.account, code_hash: g2.contract.code_hash, signer: g2.signer.account, csv_blocks: g2.vault.csv },
    runs: {
      s2: { date: s2Date, what: 'the spend key alone, sent straight to Bitcoin', near: s2.near_chain, bitcoin: s2.bitcoin_chain },
      g2: { date: g2Date, what: 'G2: the wait, the contract\'s signature, and the cold-key exit', near: NEAR, bitcoin: `${BTC} (a signet)` },
    },
    steps: [
      {
        id: 'coin', run: 's2', at: null,
        title: 'A coin sits in the test vault.',
        lines: [
          btcAddress(s2.funding_coin.vault_address, 'the test vault'),
          btcTx(s2.funding_coin.mutinynet_txid, `the coin: ${s2.funding_coin.value_sats.toLocaleString('en-US')} sats, block ${s2.funding_coin.height}`),
        ],
      },
      {
        id: 'refused', run: 's2', at: s2.node_answer.at_utc,
        title: 'Sent with the spend key alone, the way a thief would. Bitcoin refuses.',
        lines: [
          say('A spend signed by the spend key only, with nothing where the second signature goes, posted straight to a Mutinynet node.'),
          node(s2.node_answer.text_verbatim),
          say(`Read again at ${s2.after.read_at_utc.slice(11, 19)} UTC: the coin is still unspent. The thief's spend moved nothing.`),
          btcTx(s2.coin_return.mutinynet_txid, `later, the owner's cold key took the coin back, block ${s2.coin_return.height}`),
        ],
        film: true,
      },
      {
        id: 'wait', run: 'g2', at: isoOf(c.proposed_at),
        // Another run on the same vault, a day earlier: the owner's own test spend, not the thief's.
        title: `Another request on this vault, ${g2Date}: the owner's own test spend. It needs a second signature, and a public NEAR contract makes it wait.`,
        lines: [
          nearTx(c.propose_tx, 'the request'),
          say(`The contract set its unlock ${mmss(c.unlock - c.proposed_at)} later: requested ${isoOf(c.proposed_at).slice(11, 19)} UTC, unlocks ${isoOf(c.unlock).slice(11, 19)} UTC. ${c.check.unguarded ? 'A new destination, and no guard was running.' : ''}`.trim()),
        ],
      },
      {
        id: 'cancel', run: null, at: null, recorded: false,
        title: 'Your phone cancels first.',
        lines: [say('Not in this recording yet: no cancel on NEAR testnet is recorded here. This step stays empty until one is.')],
      },
      {
        id: 'signed', run: 'g2', at: isoOf(c.unlocked_at_ms),
        title: `That same request, ${g2Date}, the owner's own test spend: nobody cancelled it. At the unlock, the contract asked for Bitcoin's second signature.`,
        lines: [
          nearTx(executed.execute_tx, 'the contract asks the signer'),
          btcTx(c.txid, `paid ${c.amount.toLocaleString('en-US')} sats out, block ${c.mined_height}`),
        ],
      },
      {
        id: 'exit', run: 'g2', at: null,
        title: `If NEAR goes away, the cold key gets the coin out after a timelock: ${g2.vault.csv} blocks here.`,
        lines: [
          say('Too early, the node refuses it:'),
          node(e.early.text),
          say(`After ${e.readback.blocks_after_coin} blocks, with no NEAR at all:`),
          btcTx(e.txid, `${e.amount.toLocaleString('en-US')} sats out by the cold key, block ${e.mined_height}`),
        ],
        film: true,
      },
    ],
    // What the landing page links "From earlier runs:", and what else it lists from the same vault. When the film
    // ships, its own capture record supplies a "From the film:" list instead.
    earlier: [
      btcAddress(g2.vault.address, 'the test vault'),
      btcTx(s2.funding_coin.mutinynet_txid, 'the coin the spend key alone could not move'),
      btcTx(e.txid, 'the cold key\'s exit after the timelock'),
    ],
    same_vault: [
      nearTx(c.propose_tx, 'a request the contract made wait'),
      nearTx(executed.execute_tx, 'the contract asking for the second signature'),
      btcTx(c.txid, 'the spend it co-signed after the wait'),
    ],
  };
}

export const runText = (run = buildRun()) => `${JSON.stringify(run, null, 2)}\n`;

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const text = runText();
  if (process.argv.includes('--check')) {
    const now = readFileSync(RUN_JSON, 'utf8');
    if (now !== text) {
      console.error('site/pages/replay/run.json is not what proofs/ make. Run node tools/replay-run.mjs');
      process.exit(1);
    }
    console.log('run.json matches proofs/');
  } else {
    writeFileSync(RUN_JSON, text);
    console.log(`wrote site/pages/replay/run.json: ${buildRun().steps.length} steps`);
  }
}
