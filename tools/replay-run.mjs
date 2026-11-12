#!/usr/bin/env node
// Builds site/pages/replay/run.json, the replay page's only data, from the real records in proofs/: the final build's
// live run on Mutinynet and NEAR testnet (proofs/g2-v1.json), the refused key-alone spend on the same test vault
// (proofs/s2-refusal-v1.json), and, for the cancel, the take of the live pages the film is cut from
// (proofs/film-take.json), which is another vault of the same contract and says so on its step; that step also says,
// from proofs/phone-take.json, that a Cancel from a real phone has since run, with the device as its author reported it.
// Nothing here is typed by hand: every hash, time, amount and node answer is copied from those files, so the page
// cannot show a hash that did not happen. site/test/landing.test.mjs rebuilds it and compares, so the file cannot drift from its sources. The
// landing page's three lists come from here too: "From the film:" (the take), "From the final build's run" and, from
// the earlier build's record (proofs/g2.json), "From an earlier build".
//
//   node tools/replay-run.mjs            writes site/pages/replay/run.json
//   node tools/replay-run.mjs --check    exits 1 if the file is not what the proofs make
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const RUN_JSON = join(REPO, 'site', 'pages', 'replay', 'run.json');

const json = (...path) => JSON.parse(readFileSync(join(REPO, ...path), 'utf8'));
const read = (name) => json('proofs', name);
const NEAR = 'NEAR testnet';
const BTC = 'Mutinynet';
const dateOf = (iso) => iso.slice(0, 10);
const isoOf = (ms) => new Date(ms).toISOString();
const clockOf = (iso) => iso.slice(11, 19);
const mmss = (ms) => `${Math.floor(ms / 60000)}:${String(Math.floor((ms % 60000) / 1000)).padStart(2, '0')}`;
const sats = (n) => `${n.toLocaleString('en-US')} sats`;

const nearTx = (hash, what) => ({ kind: 'hash', chain: NEAR, type: 'tx', hash, what });
const btcTx = (hash, what) => ({ kind: 'hash', chain: BTC, type: 'txid', hash, what });
const btcAddress = (hash, what) => ({ kind: 'hash', chain: BTC, type: 'address', hash, what });
const node = (text) => ({ kind: 'node', chain: BTC, text });
const say = (text) => ({ kind: 'text', text });

/** A record of one live run with a mined co-signed spend and a mined escape, or an error that names the file. */
function liveRun(p, name) {
  if (p.label !== 'live-mutinynet' || p.gate !== 'G2' || p.chain_id !== 'testnet') throw new Error(`proofs/${name} is not the record of a live run`);
  const executed = p.cosigned?.attempts?.find((x) => x.outcome === 'signed');
  if (!executed || !p.cosigned.readback || !p.escape?.readback) throw new Error(`proofs/${name} holds no mined co-signed spend and escape`);
  return executed;
}

/**
 * `g2` and `s2` are the final build's run and the key-alone refusal on its vault; `take` is the live pages' take;
 * `phone` is the run of the same pages from a real phone, another vault again; `earlier` is the earlier build's run;
 * `deploy` and `site` are deploy/testnet.json and site/config/testnet.json, which say what "the final build" and "the
 * contract this site uses" are.
 */
export function buildRun({
  g2 = read('g2-v1.json'), s2 = read('s2-refusal-v1.json'), take = read('film-take.json'), phone = read('phone-take.json'), earlier = read('g2.json'),
  deploy = json('deploy', 'testnet.json'), site = json('site', 'config', 'testnet.json'),
} = {}) {
  if (take.schema !== 'undo-film-take-v1' || take.cancel.method !== 'cancel_all_and_rotate' || take.after.execute_refusal !== 'RequestNotFound') throw new Error('proofs/film-take.json is not the film\'s take');
  const executed = liveRun(g2, 'g2-v1.json');
  if (g2.wasm.sha256 !== deploy.wasm_sha256 || g2.contract.account !== deploy.contract) throw new Error('proofs/g2-v1.json is not a run of the final build, the wasm and contract deploy/testnet.json names');
  if (g2.contract.account !== site.contract) throw new Error('proofs/g2-v1.json is not a run on the contract this site\'s config names');
  if (s2.schema !== 'undo-s2-refusal-v1' || s2.node_answer.kind !== 'rejected' || s2.node_answer.refusal !== 'script') throw new Error('proofs/s2-refusal-v1.json is not a script refusal');
  if (s2.vault.id !== g2.vault.id || s2.funding_coin.vault_address !== g2.vault.address) throw new Error('the two records are not the same test vault');
  if (take.contract !== g2.contract.account || take.vault.id === g2.vault.id) throw new Error('proofs/film-take.json is not another vault of the same contract');
  // The real phone's run: a take of its own, on yet another vault of the same contract. Which device and browser it
  // was is its author's report, and the record keeps it apart from what the chains show.
  const reported = phone.device_as_reported ?? {};
  if (phone.schema !== 'undo-phone-take-v1' || !phone.labels?.includes('real device') || phone.labels.includes('virtual authenticator') || phone.cancel?.method !== 'cancel_all_and_rotate') throw new Error('proofs/phone-take.json is not a real device\'s take');
  if (phone.contract !== g2.contract.account || [g2.vault.id, take.vault.id].includes(phone.vault.id)) throw new Error('proofs/phone-take.json is not another vault of the same contract');
  if (typeof reported.device !== 'string' || typeof reported.browser !== 'string' || !/^the author, /.test(reported.by ?? '')) throw new Error('proofs/phone-take.json does not say what its author reported');
  const phoneDate = dateOf(phone.vault_made_block_utc);
  const earlierExecuted = liveRun(earlier, 'g2.json');
  if (earlier.contract.account === g2.contract.account || earlier.wasm.sha256 === g2.wasm.sha256) throw new Error('proofs/g2.json is not an earlier build\'s run');
  const c = g2.cosigned;
  const e = g2.escape;
  const t = take.thief;
  const g2Date = dateOf(g2.coins[0].recorded_at);
  const s2Date = dateOf(s2.node_answer.at_utc);
  const takeDate = dateOf(take.started_utc);
  const earlierDate = dateOf(earlier.coins[0].recorded_at);
  const proposed = isoOf(c.proposed_at);
  // The request of steps 3 and 5, named the same way both times so a reader can tell it from the take's.
  const request = `${g2Date} at ${proposed.slice(11, 16)} UTC`;
  const signedBy = c.readback.signatures.filter((s) => s.verified).map((s) => s.key).sort().join(' ');
  if (signedBy !== 'K_m K_u') throw new Error('proofs/g2-v1.json does not record both signatures of the mined spend as verified');
  return {
    schema: 'undo-replay-v1',
    label: 'replay',
    title: 'Replay of the final build\'s runs',
    note: `Real hashes from two runs on one test vault of the contract this site uses, ${g2Date === s2Date ? g2Date : `${g2Date} and ${s2Date}`}, shown in story order; the cancel in step 4 is from another vault of that contract and says so. Nothing on this page is happening now, and no clock here is running.`,
    chip: s2.chip,
    vault: { id: g2.vault.id, address: g2.vault.address, contract: g2.contract.account, code_hash: g2.contract.code_hash, wasm_sha256: g2.wasm.sha256, signer: g2.signer.account, csv_blocks: g2.vault.csv },
    runs: {
      s2: { date: s2Date, label: 'final build', what: 'the spend key alone, sent straight to Bitcoin', near: s2.near_chain, bitcoin: s2.bitcoin_chain },
      g2: { date: g2Date, label: 'final build', what: 'the wait, the contract\'s signature, and the cold-key exit', near: NEAR, bitcoin: `${BTC} (a signet)` },
      take: { date: takeDate, label: 'the live pages, another vault', what: 'the take of the live phone page and thief tab that the film is cut from', near: take.near_chain, bitcoin: take.bitcoin_chain },
    },
    steps: [
      {
        id: 'coin', run: 's2', at: null,
        title: 'A coin sits in the test vault.',
        lines: [
          btcAddress(s2.funding_coin.vault_address, 'the test vault'),
          btcTx(s2.funding_coin.mutinynet_txid, `the coin: ${sats(s2.funding_coin.value_sats)}, block ${s2.funding_coin.height}`),
        ],
      },
      {
        id: 'refused', run: 's2', at: s2.node_answer.at_utc,
        title: 'Sent with the spend key alone, the way a thief would. Bitcoin refuses.',
        lines: [
          say('A spend signed by the spend key only, with nothing where the second signature goes, posted straight to a Mutinynet node.'),
          node(s2.node_answer.text_verbatim),
          say(`Read again at ${clockOf(s2.after.read_at_utc)} UTC: the coin is still unspent. The thief's spend moved nothing.`),
          btcTx(s2.coin_return.mutinynet_txid, `later, the owner's cold key took the coin back, block ${s2.coin_return.height}`),
        ],
      },
      {
        id: 'wait', run: 'g2', at: proposed,
        // Another run on the same vault: the owner's own test spend, not the thief's.
        title: `Another request on this vault, ${request}: the owner's own test spend. It needs a second signature, and a public NEAR contract makes it wait.`,
        lines: [
          nearTx(c.propose_tx, 'the request'),
          say(`The contract set its unlock ${mmss(c.unlock - c.proposed_at)} later: requested ${clockOf(proposed)} UTC, unlocks ${clockOf(isoOf(c.unlock))} UTC.${c.check.unguarded ? ' A new destination, with no guard online.' : ''}`),
        ],
      },
      {
        // The two runs replayed here hold no cancel. The take of the live pages does, on another vault of the same
        // contract: the step is that take's, with its own hashes, and its title and its lines say whose it is.
        id: 'cancel', run: 'take', at: isoOf(t.proposed_at_ms),
        title: `The phone page's Cancel stops a thief's request. Another test vault of the same contract, ${takeDate === g2Date ? 'the same day' : takeDate}.`,
        lines: [
          say(`From the live pages, in the take the film is cut from: the thief tab asked to send that vault's coin away, and the phone page cancelled.`),
          nearTx(t.propose_tx, `the thief tab's request, made to wait ${mmss(t.wait_ms)}`),
          nearTx(take.cancel.tx, `the phone page's Cancel (${take.cancel.method})`),
          nearTx(take.after.execute_after_the_wait_tx, `after the wait, an execute of that request: refused by the contract (${take.after.execute_refusal})`),
          btcTx(take.coin.mutinynet_txid, `that vault's coin: ${sats(take.coin.value_sats)}, unspent when read again on ${dateOf(take.after.coin_unspent_read_utc)}`),
          say(`Chrome's virtual authenticator stood in for a phone's passkey. A Cancel from a real phone ran once, ${phoneDate === takeDate ? 'the same day' : phoneDate}, on another vault of the same contract: one ${reported.device}, with the phone page and the thief tab as two ${reported.browser} tabs on it, as the author reported it.`),
        ],
      },
      {
        id: 'signed', run: 'g2', at: isoOf(c.unlocked_at_ms),
        title: `Back on the first vault, the request of ${request}, the owner's own test spend: nobody cancelled it. Once it unlocked, the contract asked for Bitcoin's second signature.`,
        lines: [
          nearTx(executed.execute_tx, 'the contract asks the signer'),
          btcTx(c.txid, `paid ${sats(c.amount)} out, block ${c.mined_height}`),
          say('Mined with two signatures: the spend key\'s, and the one NEAR Chain Signatures gave.'),
        ],
      },
      {
        id: 'exit', run: 'g2', at: null,
        title: `If NEAR goes away, the cold key gets the coin out after a timelock: ${g2.vault.csv} blocks here.`,
        lines: [
          say('Too early, the node refuses it:'),
          node(e.early.text),
          say(`After ${e.readback.blocks_after_coin} blocks, with no NEAR at all:`),
          btcTx(e.txid, `${sats(e.amount)} out by the cold key, block ${e.mined_height}`),
        ],
      },
    ],
    // What the landing page links "From the film:": the film's own take, from its capture record. Another vault than
    // the final build's run below, so it is a list of its own.
    film: {
      date: takeDate,
      note: 'Chrome\'s virtual authenticator stood in for a phone\'s passkey',
      hashes: [
        btcAddress(take.vault.address, 'the film\'s test vault'),
        btcTx(take.coin.mutinynet_txid, `its coin: ${sats(take.coin.value_sats)}, unspent when read again on ${dateOf(take.after.coin_unspent_read_utc)}`),
        nearTx(t.propose_tx, `the thief's request, made to wait ${mmss(t.wait_ms)}`),
        nearTx(take.cancel.tx, 'the phone page\'s cancel'),
        nearTx(take.after.execute_after_the_wait_tx, 'after the wait, an execute of that request: refused by the contract'),
      ],
    },
    // What the landing page links "From the final build's run": the spend the contract co-signed and the cold key's exit.
    final: {
      date: g2Date,
      contract: g2.contract.account,
      hashes: [
        btcTx(c.txid, `the spend it co-signed after a ${mmss(c.check.delay_ms)} wait`),
        nearTx(executed.execute_tx, 'the contract asking for the second signature'),
        btcTx(e.txid, 'the cold key\'s exit after the timelock, with no NEAR'),
      ],
    },
    // And "From an earlier build": the same three of the first live run, on the earlier build's contract.
    earlier: {
      date: earlierDate,
      contract: earlier.contract.account,
      hashes: [
        btcTx(earlier.cosigned.txid, 'the spend it co-signed after the wait'),
        nearTx(earlierExecuted.execute_tx, 'the contract asking for the second signature'),
        btcTx(earlier.escape.txid, 'the cold key\'s exit after the timelock'),
      ],
    },
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
