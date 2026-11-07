#!/usr/bin/env node
// verify.sh tier A: read-only. Needs no key and no account, signs nothing and sends nothing.
//
//   node tools/verify/tier-a.mjs [--config deploy/testnet.json]
//
// 1. The deployed contract named in the config: its code hash against the wasm hash the config
//    records, no full-access key on it, its `status` view. A placeholder config says so and skips these.
// 2. The live signer still parses the contract's exact `sign` arguments, by calling `sign` as a view:
//    a view cannot sign, so a well-formed request stops at ProhibitedInView and a malformed one at
//    the JSON parser. Nothing is signed.
// 3. Replay: every real NEAR testnet hash in proofs/g1.json and proofs/g2.json is fetched again from
//    archival RPC, and each signature the signer returned is verified again, here, under the key the
//    live signer derives for that vault. Every Mutinynet txid is fetched again and compared byte for
//    byte with proofs/, and judged by libbitcoinconsensus. With no network, the raw hex in proofs/ is
//    judged instead, and the fetch line says SKIP (network).
// 4. A recovery file built the way the page builds it, then the crate's dry-run escape over it.
// 5. Static: the contract calls nothing outside itself but the signer's `sign` and
//    `derived_public_key`, so it never reads Bitcoin through MPC.
//
// A network failure is SKIP (network), never PASS and never FAIL. A line about something this run did not fetch or
// judge, only read from proofs/, is INFO. Exit 0 with no FAIL, 1 with any.
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseTx, parseWitnessScript, witnessScript } from '../lib/btc.mjs';
import { base58Encode, fromBase64, fromHex, toHex } from '../lib/bytes.mjs';
import { randomBytes, secp256k1 } from '../lib/crypto.mjs';
import { coldKeys, publicSecp, spendKeys } from '../lib/keys.mjs';
import { buildRecovery } from '../lib/recovery.mjs';
import { parseSignerKey } from '../lib/vault-client.mjs';
import { buildBin, cargoAvailable, consensusJudge } from './rust.mjs';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const argv = process.argv.slice(2);
const flag = argv.indexOf('--config');
const configPath = resolve(flag >= 0 && argv[flag + 1] ? argv[flag + 1] : process.env.UNDO_CONFIG ?? join(REPO, 'deploy/testnet.json'));
const shown = (p) => (p.startsWith(REPO) ? relative(REPO, p) : 'the config named by UNDO_CONFIG');

const tally = { PASS: 0, FAIL: 0, SKIP: 0, INFO: 0 };
const line = (status, id, label, text) => {
  tally[status] += 1;
  console.log(`${status} ${id} [${label}] ${text}`);
};
const short = (h) => `${h.slice(0, 10)}…`;

// ------------------------------------------------------------------ network, read-only

class NetworkDown extends Error {}
class ChainAnswer extends Error {
  constructor(message, data) {
    super(message);
    this.data = data;
  }
}

const sleep = (ms) => new Promise((r) => { setTimeout(r, ms); });

/** JSON-RPC over a list of URLs. A refusal by a node is a ChainAnswer; no answer from any is NetworkDown. */
async function rpc(urls, method, params, { timeoutMs = 15_000 } = {}) {
  let last = 'no URL';
  for (let round = 0; round < 2; round += 1) {
    for (const url of urls) {
      try {
        const res = await fetch(url, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', id: 'verify', method, params }),
          redirect: 'error',
          signal: AbortSignal.timeout(timeoutMs),
        });
        const text = await res.text();
        let data;
        try {
          data = JSON.parse(text);
        } catch {
          last = `HTTP ${res.status} with no JSON`;
          continue;
        }
        if (data.error) {
          if (/rate limit|too many/i.test(JSON.stringify(data.error)) || res.status === 429) {
            last = 'rate limited';
            await sleep(1500);
            continue;
          }
          throw new ChainAnswer(data.error.cause?.name ?? data.error.name ?? data.error.message ?? 'error', data.error);
        }
        return data.result;
      } catch (err) {
        if (err instanceof ChainAnswer) throw err;
        last = err.name === 'TimeoutError' ? 'timeout' : err.message;
      }
    }
  }
  throw new NetworkDown(last);
}

/** A view call. Returns { value } or { error } with the contract's own words. */
async function view(urls, account, method, args, finality = 'final') {
  const result = await rpc(urls, 'query', {
    request_type: 'call_function', account_id: account, method_name: method, finality,
    args_base64: Buffer.from(JSON.stringify(args)).toString('base64'),
  });
  if (result.error) return { error: result.error };
  return { value: JSON.parse(Buffer.from(result.result).toString('utf8')) };
}

async function getText(url, { timeoutMs = 15_000 } = {}) {
  for (let i = 0; i < 2; i += 1) {
    try {
      const res = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(timeoutMs) });
      if (res.status === 404) return { status: 404, text: await res.text() };
      if (res.ok) return { status: res.status, text: await res.text() };
    } catch {
      // Tried again once, then reported as no answer.
    }
    await sleep(800);
  }
  throw new NetworkDown(`no answer from ${new URL(url).host}`);
}

/** Runs fn and turns a dead network into one SKIP line. */
async function guarded(id, label, what, fn) {
  try {
    await fn();
  } catch (err) {
    if (err instanceof NetworkDown) line('SKIP', id, label, `${what}: SKIP (network): ${err.message}`);
    else line('FAIL', id, label, `${what}: ${err instanceof ChainAnswer ? `the node answered ${err.message}` : err.message}`);
  }
}

// ------------------------------------------------------------------ Rust referees, built on demand

const cargo = cargoAvailable();
const consensusAccepts = (raw, spk, values) => consensusJudge(REPO, raw, spk, values);

// ------------------------------------------------------------------ the signer's answers

/** The payloads the signer logged and the signatures it returned, in one transaction's receipts. */
function signerReceipts(tx, signer) {
  const payloads = [];
  const signatures = [];
  for (const r of tx.receipts_outcome) {
    if (r.outcome.executor_id !== signer) continue;
    for (const log of r.outcome.logs) {
      const m = /path: "([^"]+)", payload: Ecdsa\(BoundedVec \{ inner: \[([0-9, ]+)\]/.exec(log);
      if (m) payloads.push({ path: m[1], payload: toHex(Uint8Array.from(m[2].split(',').map((n) => Number(n.trim())))) });
    }
    const value = r.outcome.status?.SuccessValue;
    if (value) {
      try {
        const answer = JSON.parse(Buffer.from(fromBase64(value)).toString('utf8'));
        if (answer?.big_r?.affine_point && answer?.s?.scalar) signatures.push(answer);
      } catch {
        // A signer receipt that returned something else, like a receipt id.
      }
    }
  }
  return { payloads, signatures };
}

const verifiesUnder = (answer, payloadHex, pubkey) => {
  const r = BigInt(`0x${answer.big_r.affine_point.slice(2)}`);
  const s = BigInt(`0x${answer.s.scalar}`);
  return secp256k1.verify(new secp256k1.Signature(r, s).toCompactRawBytes(), fromHex(payloadHex), pubkey, { prehash: false, lowS: false });
};

const derivedCache = new Map();
async function derivedKey(urls, signer, predecessor, path) {
  const key = `${predecessor}|${path}`;
  if (!derivedCache.has(key)) {
    const out = await view(urls, signer, 'derived_public_key', { path, predecessor, domain_id: 0 });
    if (out.error) throw new ChainAnswer(`derived_public_key refused: ${out.error}`);
    derivedCache.set(key, parseSignerKey(out.value));
  }
  return derivedCache.get(key);
}

/** One G1 or G2 execute: fetch it again, find the signer's answer, verify it here. */
async function replayExecute({ proofName, run, contract, signer, archival, rpcUrls }) {
  const tx = await rpc(archival, 'tx', { tx_hash: run.execute_tx, sender_account_id: contract, wait_until: 'NONE' });
  if (tx.transaction?.receiver_id !== contract) throw new Error(`NEAR testnet tx ${run.execute_tx} is not a call to ${contract}`);
  const { payloads, signatures } = signerReceipts(tx, signer);
  const path = `undo/${run.vault}`;
  if (payloads.length === 0 || signatures.length === 0) throw new Error(`NEAR testnet tx ${run.execute_tx}: no sign request and answer from ${signer} in its receipts`);
  if (!payloads.every((p) => p.path === path)) throw new Error(`NEAR testnet tx ${run.execute_tx}: a sign request for another path`);
  const km = await derivedKey(rpcUrls, signer, contract, path);
  for (const answer of signatures) {
    if (!payloads.some((p) => verifiesUnder(answer, p.payload, km))) throw new Error(`NEAR testnet tx ${run.execute_tx}: a returned signature does not verify under the derived key`);
  }
  const recorded = run.signer_answer ?? run.attempts?.find((a) => a.signer_answer)?.signer_answer;
  const sameAsProof = recorded && signatures.some((a) => a.big_r.affine_point === recorded.big_r.affine_point && a.s.scalar === recorded.s.scalar);
  if (!sameAsProof) throw new Error(`NEAR testnet tx ${run.execute_tx}: the chain's signature is not the one ${proofName} records`);
  const payloadsInProof = run.payloads ?? null;
  if (payloadsInProof && !payloadsInProof.every((p) => payloads.some((q) => q.payload === p))) throw new Error(`NEAR testnet tx ${run.execute_tx}: payloads differ from ${proofName}`);
  const raw = run.final_tx ?? run.raw;
  if (raw) {
    const script = parseTx(fromHex(raw)).inputs[0].witness.at(-1);
    if (toHex(parseWitnessScript(script).km) !== toHex(km)) throw new Error(`NEAR testnet tx ${run.execute_tx}: the Bitcoin script names another K_m`);
  }
  return { signatures: signatures.length, km, block: tx.transaction_outcome?.block_hash };
}

// ------------------------------------------------------------------ 1. the deployed contract

async function deployed(config) {
  const net = config.label;
  console.log(`== tier A: the deployed contract, ${shown(configPath)} (${config.network}, read-only)`);
  if (config.placeholder) {
    const why = `${shown(configPath)} holds a placeholder: no contract is deployed yet`;
    line('SKIP', 'C13', net, `deployed code hash against the built wasm hash: ${why}`);
    line('SKIP', 'C11', net, `no full-access key on the contract: ${why}`);
    line('SKIP', 'C06', net, `the contract's status view: ${why}`);
    return;
  }
  const urls = config.rpc;
  const built = config.wasm_built_by === 'ci' ? 'CI built this hash' : 'this machine built this hash (the operator\'s machine, scripts/build.sh; CI does not build the wasm, and this run rebuilds nothing)';
  await guarded('C13', net, 'deployed code hash', async () => {
    const account = await rpc(urls, 'query', { request_type: 'view_account', account_id: config.contract, finality: 'final' });
    if (!config.wasm_sha256) throw new Error(`${shown(configPath)} records no wasm_sha256 to compare with`);
    const want = base58Encode(fromHex(config.wasm_sha256));
    if (account.code_hash !== want) throw new Error(`${config.contract} runs code ${account.code_hash}, not the wasm ${config.wasm_sha256} (${want}) the config records`);
    line('PASS', 'C13', net, `${config.contract} runs code hash ${account.code_hash}, the sha256 ${config.wasm_sha256} of the wasm in ${shown(configPath)}. Label: ${built}. It proves which bytes run, not that this source rebuilds them`);
  });
  await guarded('C11', net, 'access keys', async () => {
    const list = await rpc(urls, 'query', { request_type: 'view_access_key_list', account_id: config.contract, finality: 'final' });
    const full = list.keys.filter((k) => k.access_key.permission === 'FullAccess');
    if (full.length > 0) throw new Error(`${config.contract} has ${full.length} full-access key(s): ${full.map((k) => k.public_key).join(', ')}. Its owner could replace the code at once, without the upgrade wait`);
    line('PASS', 'C11', net, `${config.contract} has no full-access key (${list.keys.length ? `${list.keys.length} function-call key(s)` : 'no access key at all'}): code changes only through upgrade_propose and its public wait`);
  });
  await guarded('C06', net, 'status view', async () => {
    const out = await view(urls, config.contract, 'status', {});
    if (out.error) throw new Error(`status refused: ${out.error}`);
    if (typeof out.value?.ok !== 'boolean' || !Array.isArray(out.value.lines)) throw new Error('status is not { ok, lines }');
    line('PASS', 'C06', net, `${config.contract} status answers ok=${out.value.ok}, verbatim:`);
    for (const l of out.value.lines) console.log(`    ${l}`);
  });
}


async function signerArgs(config) {
  // The live signer is the one that matters. A local stage's mock signer checks its deposit first, so a
  // stage config asks the live testnet signer instead, over public RPC.
  const live = config.label === 'live-testnet' || config.label === 'live-mainnet';
  const net = live ? config.label : 'live-testnet';
  const urls = live ? config.rpc : config.replay.near_rpc;
  const signer = live ? config.signer : config.replay.signer ?? 'v1.signer-prod.testnet';
  console.log(`\n== tier A: the signer ${signer} still parses the contract's sign arguments (read-only)`);
  await guarded('C12', net, 'signer arguments', async () => {
    const good = await rpc(urls, 'query', {
      request_type: 'call_function', account_id: signer, method_name: 'sign', finality: 'final',
      args_base64: Buffer.from(JSON.stringify({ request: { path: 'undo/verify', payload_v2: { Ecdsa: '00'.repeat(31) + '01' }, domain_id: 0 } })).toString('base64'),
    });
    const control = await rpc(urls, 'query', {
      request_type: 'call_function', account_id: signer, method_name: 'sign', finality: 'final',
      args_base64: Buffer.from(JSON.stringify({ request: { path: 'undo/verify', payload_vX: { Ecdsa: '00'.repeat(31) + '01' }, domain_id: 0 } })).toString('base64'),
    });
    const parsed = /ProhibitedInView/.test(good.error ?? '');
    const controlRefused = /payload_v2|deserial/i.test(control.error ?? '');
    if (!parsed || !controlRefused) throw new Error(`the signer's answers changed: request "${good.error ?? 'no error'}", control "${control.error ?? 'no error'}"`);
    line('PASS', 'C12', net, `${signer} parses the contract's exact sign arguments (a view stops at ProhibitedInView), and a control with a wrong field fails to parse. Nothing was signed`);
  });
}

// ------------------------------------------------------------------ 3. replay of real hashes

function proof(name) {
  const path = join(REPO, 'proofs', name);
  return existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : null;
}

function g1Runs(p) {
  const runs = [];
  const walk = (node) => {
    if (Array.isArray(node)) node.forEach(walk);
    else if (node && typeof node === 'object') {
      if (node.execute_tx && node.signer_answer && node.vault) runs.push(node);
      else Object.values(node).forEach(walk);
    }
  };
  walk(p.stages);
  return runs;
}

async function replayNear(config) {
  const g1 = proof('g1.json');
  const g2 = proof('g2.json');
  const archival = config.replay.near_archival_rpc;
  const rpcUrls = config.replay.near_rpc;
  console.log('\n== tier A: replay of real NEAR testnet hashes in proofs/, fetched again from archival RPC');
  if (!g1) {
    line('SKIP', 'C12', 'replay', 'proofs/g1.json is not in this tree');
  } else {
    const contract = g1.contract.account;
    const signer = g1.signer.account;
    await guarded('C12', 'replay', 'G1 contract code', async () => {
      const account = await rpc(rpcUrls, 'query', { request_type: 'view_account', account_id: contract, finality: 'final' });
      const want = base58Encode(fromHex(g1.wasm.sha256));
      if (account.code_hash !== g1.contract.code_hash || account.code_hash !== want) throw new Error(`${contract} now runs ${account.code_hash}; proofs/g1.json names ${g1.contract.code_hash}, the hash of wasm ${g1.wasm.sha256}`);
      line('PASS', 'C12', 'replay', `NEAR testnet account ${contract} still runs code hash ${account.code_hash}, the sha256 of the G1 wasm (${short(g1.wasm.sha256)}). That is an earlier build than this tree's, kept as the proof's subject`);
    });
    const runs = g1Runs(g1);
    let ok = 0;
    let skipped = false;
    for (const [i, run] of runs.entries()) {
      if (skipped) {
        line('SKIP', 'C12', 'replay', `${runs.length - i} more G1 execute transactions: SKIP (network), the archival RPC did not answer`);
        break;
      }
      try {
        const out = await replayExecute({ proofName: 'proofs/g1.json', run, contract, signer, archival, rpcUrls });
        ok += 1;
        line('PASS', 'C12', 'replay', `NEAR testnet tx ${run.execute_tx}: ${signer} returned ${out.signatures} signature(s) that verify here under the K_m it derives for undo/${short(run.vault)}, and match proofs/g1.json and the key in that run's Bitcoin script`);
      } catch (err) {
        if (err instanceof NetworkDown) {
          skipped = true;
          line('SKIP', 'C12', 'replay', `NEAR testnet tx ${run.execute_tx}: SKIP (network): ${err.message}`);
        } else line('FAIL', 'C12', 'replay', err instanceof ChainAnswer ? `NEAR testnet tx ${run.execute_tx}: the node answered ${err.message}` : err.message);
      }
    }
    if (!skipped) console.log(`    ${ok} of ${runs.length} G1 execute transactions re-verified`);

    const act = g1.stages?.activation;
    if (act?.good_vault?.tx && act?.bad_vault?.tx) {
      await guarded('C15', 'replay', 'G1 activation', async () => {
        const logsOf = async (hash) => (await rpc(archival, 'tx', { tx_hash: hash, sender_account_id: contract, wait_until: 'NONE' })).receipts_outcome.flatMap((r) => r.outcome.logs);
        const good = await logsOf(act.good_vault.tx);
        const bad = await logsOf(act.bad_vault.tx);
        if (!good.includes(`undo:active vault=${act.good_vault.vault}`)) throw new Error(`NEAR testnet tx ${act.good_vault.tx}: no undo:active log for its vault`);
        if (!bad.some((l) => l.startsWith(`undo:refused vault=${act.bad_vault.vault}`))) throw new Error(`NEAR testnet tx ${act.bad_vault.tx}: no undo:refused log for its vault`);
        line('PASS', 'C15', 'replay', `NEAR testnet tx ${act.bad_vault.tx}: a vault created with a K_m the signer does not derive was refused when the signer answered (undo:refused, deposit refunded); tx ${act.good_vault.tx}: the matching one read active`);
      });
    }
  }
  if (g2?.cosigned?.attempts?.length) {
    const contract = g2.contract.account;
    const signer = g2.signer.account;
    for (const attempt of g2.cosigned.attempts.filter((a) => a.execute_tx && a.signer_answer)) {
      await guarded('C12', 'replay', `G2 execute ${attempt.execute_tx}`, async () => {
        const out = await replayExecute({ proofName: 'proofs/g2.json', run: { ...attempt, vault: g2.vault.id, raw: g2.cosigned.raw, payloads: null }, contract, signer, archival, rpcUrls });
        line('PASS', 'C12', 'replay', `NEAR testnet tx ${attempt.execute_tx}: the signature for G2's co-signed Bitcoin spend verifies here under the K_m ${signer} derives for undo/${short(g2.vault.id)}`);
        return out;
      });
    }
  }
}

/** One Mutinynet transaction: fetched and compared with proofs/, or the raw hex from proofs/ on its own. */
async function replayBitcoin({ id, what, txid, raw, spk, values, esplora, expectHeight, coin }) {
  let fetched = false;
  try {
    const hex = await getText(`${esplora}/tx/${txid}/hex`);
    if (hex.status === 404) throw new Error(`Mutinynet txid ${txid} (${what}): the API does not know it`);
    if (hex.text.trim() !== raw) throw new Error(`Mutinynet txid ${txid} (${what}): the API's bytes differ from proofs/`);
    const status = JSON.parse((await getText(`${esplora}/tx/${txid}/status`)).text);
    if (!status.confirmed) throw new Error(`Mutinynet txid ${txid} (${what}): not confirmed`);
    if (expectHeight && status.block_height !== expectHeight) throw new Error(`Mutinynet txid ${txid}: mined at ${status.block_height}, proofs/ say ${expectHeight}`);
    let age = '';
    if (coin) {
      const parent = JSON.parse((await getText(`${esplora}/tx/${coin.txid}/status`)).text);
      age = `, ${status.block_height - parent.block_height} blocks after the coin it spends`;
    }
    fetched = true;
    line('PASS', id, 'replay', `Mutinynet txid ${txid} (${what}): fetched again, same bytes as proofs/, mined at height ${status.block_height}${age}`);
  } catch (err) {
    if (err instanceof NetworkDown) line('SKIP', id, 'replay', `Mutinynet txid ${txid} (${what}): SKIP (network): ${err.message}; judging the raw hex in proofs/ instead`);
    else line('FAIL', id, 'replay', err.message);
  }
  const { verdict: accepted, why, crashed } = consensusAccepts(raw, spk, values);
  if (crashed) line('FAIL', id, 'consensus-lib', `Mutinynet txid ${txid} (${what}): no verdict: ${why}`);
  else if (accepted === null) line('SKIP', id, 'consensus-lib', `Mutinynet txid ${txid}: libbitcoinconsensus not run: ${why}`);
  else if (accepted) line('PASS', id, 'consensus-lib', `Mutinynet txid ${txid} (${what}): libbitcoinconsensus accepts every input of the ${fetched ? 'fetched' : 'recorded'} bytes`);
  else line('FAIL', id, 'consensus-lib', `Mutinynet txid ${txid} (${what}): libbitcoinconsensus refuses it`);
}

function refusedControl({ id, what, raw, spk, values, nodeText }) {
  const { verdict: accepted, why, crashed } = consensusAccepts(raw, spk, values);
  // A crash is no refusal: a control passes only on the referee's own "refused" answer.
  if (crashed) return line('FAIL', id, 'consensus-lib', `${what}: no verdict: ${why}`);
  if (accepted === null) return line('SKIP', id, 'consensus-lib', `${what}: not judged: ${why}`);
  if (accepted) return line('FAIL', id, 'consensus-lib', `${what}: libbitcoinconsensus accepts it, and it must not`);
  return line('PASS', id, 'consensus-lib', `${what}: libbitcoinconsensus refuses it here too. The Mutinynet node's answer when it was sent, recorded in proofs/: ${nodeText}`);
}

async function replayMutinynet(config) {
  const esplora = config.replay.mutinynet_esplora;
  const g2 = proof('g2.json');
  console.log('\n== tier A: replay of real Mutinynet transactions in proofs/ (Bitcoin signet test coins)');
  if (g2) {
    const spk = g2.vault.spk;
    const valueOf = (role) => g2.coins.find((c) => c.role === role)?.value;
    const cosignValue = valueOf('cosign');
    const escapeValue = valueOf('escape');
    await replayBitcoin({ id: 'C12', what: 'G2 co-signed spend: the spend key and the contract-requested MPC signature', txid: g2.cosigned.txid, raw: g2.cosigned.raw, spk, values: [cosignValue], esplora, expectHeight: g2.cosigned.mined_height });
    refusedControl({ id: 'C02', what: 'G2 control: the same spend with no spend-key signature, the MPC one alone', raw: g2.cosigned.ku_control.raw, spk, values: [cosignValue], nodeText: g2.cosigned.ku_control.text });
    await replayBitcoin({ id: 'C04', what: 'G2 escape: the cold key alone, from the recovery file, once the coin was CSV old', txid: g2.escape.txid, raw: g2.escape.raw, spk, values: [escapeValue], esplora, expectHeight: g2.escape.mined_height, coin: { txid: g2.escape.coin.split(':')[0] } });
    // Read from proofs/ only: nothing here fetches or judges it again, so it is INFO, not PASS.
    line('INFO', 'C04', 'live-mutinynet, recorded in G2, 2026-10-31', `G2 escape sent before the coin was CSV old: the Mutinynet node refused it at tip ${g2.escape.early.tip_before}, coin height ${g2.escape.early.coin_height}: ${g2.escape.early.text}. Not fetched again: a refused transaction leaves nothing on chain to fetch`);
    refusedControl({ id: 'C04', what: 'G2 control: the escape signed one block below CSV', raw: g2.escape.csv_control.raw, spk, values: [escapeValue], nodeText: g2.escape.csv_control.text });
  } else line('SKIP', 'C12', 'replay', 'proofs/g2.json is not in this tree');

  const s2 = proof('s2-refusal.json');
  if (s2) {
    const spk = g2?.vault?.address === s2.funding_coin.vault_address ? g2.vault.spk : null;
    if (!spk) line('FAIL', 'C03', 'replay', 'proofs/s2-refusal.json names a vault this tree has no script for');
    else {
      refusedControl({ id: 'C03', what: `spend key alone, sent to Mutinynet ${s2.node_answer.at_utc}: would have been txid ${s2.refused_tx.mutinynet_txid_it_would_have_had}`, raw: s2.refused_tx.raw_hex, spk, values: [s2.funding_coin.value_sats], nodeText: s2.node_answer.text_verbatim });
      try {
        const out = JSON.parse((await getText(`${esplora}/tx/${s2.funding_coin.mutinynet_txid}/outspend/${s2.funding_coin.vout}`)).text);
        const coin = `Mutinynet coin ${s2.funding_coin.mutinynet_txid}:${s2.funding_coin.vout}`;
        const back = s2.coin_return?.mutinynet_txid ?? null;
        if (out.spent && out.txid === s2.refused_tx.mutinynet_txid_it_would_have_had) line('FAIL', 'C03', 'replay', `${coin}: the refused spend is the one that spent the coin`);
        else if (out.spent && back && out.txid === back) line('PASS', 'C03', 'replay', `${coin}: spent later by Mutinynet txid ${out.txid}, the cold-key return proofs/s2-refusal.json records, not by the refused spend`);
        else if (out.spent) line('FAIL', 'C03', 'replay', `${coin}: spent by Mutinynet txid ${out.txid}, which is ${back ? `not the cold-key return proofs/s2-refusal.json records (${back})` : 'not in proofs/s2-refusal.json'}`);
        else if (back) line('FAIL', 'C03', 'replay', `${coin}: the API says unspent, but proofs/s2-refusal.json records its cold-key return ${back}`);
        else line('PASS', 'C03', 'replay', `${coin}: still unspent`);
      } catch (err) {
        if (err instanceof NetworkDown) line('SKIP', 'C03', 'replay', `Mutinynet coin ${s2.funding_coin.mutinynet_txid}: SKIP (network): ${err.message}`);
        else line('FAIL', 'C03', 'replay', err.message);
      }
    }
  }
}

// ------------------------------------------------------------------ 4. recovery file, 5. static

function recoveryDryRun() {
  console.log('\n== tier A: recovery file dry run (C18), on throwaway keys made here and thrown away');
  if (!cargo) return line('SKIP', 'C18', 'consensus-lib', 'recovery dry run: cargo is not installed');
  const built = buildBin({ cwd: REPO, args: ['-p', 'undo-btc', '--features', 'tools', '--bin', 'recovery-dry-run'], bin: 'recovery-dry-run' });
  if (!built.bin) return line('SKIP', 'C18', 'consensus-lib', `recovery dry run: ${built.why}`);
  // The file as the page makes it: tools/lib/recovery.mjs, the module the page imports.
  const { ku } = spendKeys(randomBytes(32));
  const cold = randomBytes(32);
  const km = publicSecp(randomBytes(32));
  const script = witnessScript(ku.pub, km, coldKeys(cold).leaf.pub, 6);
  const dir = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'undo-verify-'));
  try {
    const file = join(dir, 'throwaway.json');
    writeFileSync(file, buildRecovery({ network: 'mutinynet', vaultId: toHex(randomBytes(32)), script, cold }), { mode: 0o600 });
    chmodSync(file, 0o600);
    const out = spawnSync(built.bin, [file], { encoding: 'utf8' });
    for (const l of out.stdout.trim().split('\n')) {
      const m = /^(PASS|FAIL) (\S+) \[([^\]]+)\] (.*)$/.exec(l);
      if (m) line(m[1], m[2], m[3], `${m[4]} (file built by tools/lib/recovery.mjs, as the page builds it)`);
      else console.log(`    ${l}`);
    }
    if (out.status !== 0 && !/FAIL/.test(out.stdout)) line('FAIL', 'C18', 'consensus-lib', `recovery-dry-run exit ${out.status}`);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function staticChecks() {
  console.log('\n== tier A: static');
  const dir = join(REPO, 'contracts/undo/src');
  const src = readdirSync(dir).filter((f) => f.endsWith('.rs')).map((f) => readFileSync(join(dir, f), 'utf8')).join('\n');
  const creates = [...src.matchAll(/env::promise_create\(\s*([^,]+?),\s*"([a-z_]+)"/g)].map((m) => ({ target: m[1].trim(), method: m[2] }));
  const thens = [...src.matchAll(/env::promise_then\(\s*[a-z_]+,\s*([^,]+?),\s*"([a-z_]+)"/g)].map((m) => ({ target: m[1].trim(), method: m[2] }));
  // A batch is its create line and the action lines right after it. Only a transfer may go to another account.
  const lines = src.split('\n');
  const batches = [];
  lines.forEach((l, i) => {
    const m = /promise_batch_create\((.+)\);/.exec(l);
    if (!m) return;
    const actions = [];
    for (let j = i + 1; j < lines.length && /promise_batch_action_/.test(lines[j]); j += 1) actions.push(/promise_batch_action_([a-z_]+)/.exec(lines[j])[1]);
    batches.push({ target: m[1].trim(), actions });
  });
  const calls = (src.match(/promise_batch_action_function_call/g) ?? []).length;
  const listed = batches.reduce((n, b) => n + b.actions.filter((a) => a === 'function_call').length, 0);
  const outside = creates.filter((c) => c.target !== 'cfg.signer.clone()' || !['sign', 'derived_public_key'].includes(c.method));
  const callbacks = thens.filter((t) => t.target !== 'env::current_account_id()');
  const otherBatches = batches.filter((b) => b.target !== '&env::current_account_id()' && b.actions.some((a) => a !== 'transfer'));
  if (creates.length === 0 || batches.length === 0) return line('FAIL', 'C16', 'static', 'found no promise_create or promise_batch_create in contracts/undo/src: the check reads the wrong files');
  if (calls !== listed) return line('FAIL', 'C16', 'static', 'a function call in a batch this check cannot place');
  if (outside.length || callbacks.length || otherBatches.length) return line('FAIL', 'C16', 'static', `contracts/undo calls out to something else: ${JSON.stringify({ outside, callbacks, otherBatches })}`);
  line('PASS', 'C16', 'static', `contracts/undo/src has ${creates.length} call sites that leave the contract, both to the configured signer, only ${[...new Set(creates.map((c) => c.method))].join(' and ')}; every callback is to itself, and the only batch to another account is a refund transfer. No Bitcoin data is read through MPC`);
}

// ------------------------------------------------------------------ main

let config;
try {
  config = JSON.parse(readFileSync(configPath, 'utf8'));
} catch (err) {
  console.log(`FAIL config [static] cannot read ${shown(configPath)}: ${err.message}`);
  process.exit(1);
}
const started = Date.now();
await deployed(config);
await signerArgs(config);
await replayNear(config);
await replayMutinynet(config);
recoveryDryRun();
staticChecks();
console.log(`\nTIER A: ${tally.PASS} PASS, ${tally.SKIP} SKIP, ${tally.FAIL} FAIL${tally.INFO ? `, ${tally.INFO} INFO` : ''} in ${Math.round((Date.now() - started) / 1000)} s${config.placeholder ? '. The deployed-contract lines are SKIP because the config is a placeholder' : ''}`);
process.exit(tally.FAIL ? 1 : 0);
