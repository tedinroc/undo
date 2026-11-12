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
//    Then the same for each later live run, proofs/g2-NAME.json, on the contract and build that record names:
//    the contract's code hash at the block of the execute, the proposal's unlock and the execute's block against
//    it, the signer's signature against the digest of the mined Bitcoin transaction and against its witness, and
//    the Mutinynet transactions. With proofs/s2-refusal-NAME.json, the spend key alone on that run's vault.
//    Then the take of the live pages in proofs/film-take.json: the thief tab's proposal and its wait, the phone
//    page's cancel_all_and_rotate before that unlock, with its WebAuthn assertion checked again here under the
//    passkey the vault was made with, the execute the contract refused after the unlock, and the coin, read now.
// 4. The agent run in proofs/c14-agent.json: the transaction that gave the agent its function-call key,
//    its proposal, the calls the contract refused, the owner's cancel and rotation, each fetched again
//    from archival RPC. What NEAR itself refused was never on chain, so that part is INFO.
// 5. A recovery file built the way the page builds it, then the crate's dry-run escape over it.
// 6. Static: the contract calls nothing outside itself but the signer's `sign` and
//    `derived_public_key`, so it never reads Bitcoin through MPC.
//
// A network failure is SKIP (network), never PASS and never FAIL. A line about something this run did not fetch or
// judge, only read from proofs/, is INFO. Exit 0 with no FAIL, 1 with any.
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { addressToSpk, derSig, makeTx, p2wshAddress, parseTx, parseWitnessScript, SEQUENCE_COSIGNED, sighash, txid as txidOf, witnessScript } from '../lib/btc.mjs';
import { base58Encode, fromBase64, fromHex, toHex, utf8 } from '../lib/bytes.mjs';
import { randomBytes, secp256k1, sha256 } from '../lib/crypto.mjs';
import { checkCosigned, checkEscape } from '../lib/g2-check.mjs';
import { argBytes, intentDigest, PASSKEY_TAG, vaultId } from '../lib/intent.mjs';
import { coldKeys, publicSecp, spendKeys } from '../lib/keys.mjs';
import { buildRecovery } from '../lib/recovery.mjs';
import { parseSignerKey } from '../lib/vault-client.mjs';
import { refusalOf } from '../../site/lib/webauthn.mjs';
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
  return { signatures: signatures.length, km, block: tx.transaction_outcome?.block_hash, tx, payloads, answers: signatures };
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
  const built = config.wasm_built_by === 'ci' ? 'CI built this hash' : 'the operator\'s machine built this hash (scripts/build.sh; CI does not build the wasm, and this run rebuilds nothing)';
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

// ------------------------------------------------------------------ 4. the agent run (C14)

/** The methods an agent's NEAR key may call. A key with any other, or with none listed (which means all), fails. */
const AGENT_KEY_METHODS = ['propose_btc', 'execute'];

/** The one function call a transaction makes, with its JSON arguments, or null if it is anything else. */
function onlyCall(tx) {
  const actions = tx.transaction?.actions ?? [];
  const call = actions.length === 1 ? actions[0].FunctionCall : null;
  if (!call) return null;
  let args = null;
  try {
    args = JSON.parse(Buffer.from(fromBase64(call.args)).toString('utf8'));
  } catch {
    // Arguments that are not JSON: the caller's checks on them fail.
  }
  return { method: call.method_name, deposit: call.deposit, args };
}

/** How a transaction ended. ok: it succeeded, with the value it returned. Else the first failure in it, as JSON text, or null if it has no end yet. */
function outcomeOf(tx) {
  const failures = [tx.status?.Failure, ...(tx.receipts_outcome ?? []).map((r) => r.outcome.status?.Failure)].filter(Boolean);
  if (failures.length) return { ok: false, failure: JSON.stringify(failures[0]) };
  if (typeof tx.status?.SuccessValue !== 'string') return { ok: false, failure: null };
  let value = null;
  try {
    value = tx.status.SuccessValue === '' ? null : JSON.parse(Buffer.from(fromBase64(tx.status.SuccessValue)).toString('utf8'));
  } catch {
    // A return value that is not JSON stays null.
  }
  return { ok: true, value, failure: null };
}

const logsIn = (tx, executor) => (tx.receipts_outcome ?? []).filter((r) => r.outcome.executor_id === executor).flatMap((r) => r.outcome.logs);

/**
 * proofs/c14-agent.json against the chain. Every line fetches one recorded transaction again and reads
 * what the chain says of it: who signed, with which key, which method, and how it ended. The key is the
 * agent's function-call key on the agent's three, the full-access key the record names on the AddKey and on
 * the six calls relayed for the agent, and on the relay's two any key but the agent's.
 */
async function replayAgent(config) {
  const c14 = proof('c14-agent.json');
  console.log('\n== tier A: replay of the agent run in proofs/c14-agent.json, fetched again from archival RPC');
  if (!c14) return line('SKIP', 'C14', 'replay', 'proofs/c14-agent.json is not in this tree');
  const archival = config.replay.near_archival_rpc;
  const contract = c14.contract.account;
  const agent = c14.agent.account;
  const key = c14.agent.function_call_key.public_key;
  const fullKey = c14.agent.full_access_key;
  const vault = c14.vault.id;
  const relay = c14.relay.account;
  const fetchTx = (hash, sender) => rpc(archival, 'tx', { tx_hash: hash, sender_account_id: sender, wait_until: 'NONE' });
  const said = (text) => {
    try {
      return JSON.parse(text)?.ActionError?.kind?.FunctionCallError?.ExecutionError ?? text;
    } catch {
      return text;
    }
  };
  /** A call to the contract about this run's vault, by this signer and method. Returns the call and how it ended. */
  const callTo = async (hash, signer, method) => {
    const tx = await fetchTx(hash, signer);
    const t = tx.transaction ?? {};
    if (t.hash !== hash) throw new Error(`NEAR testnet tx ${hash}: the node answered about another transaction`);
    if (t.signer_id !== signer) throw new Error(`NEAR testnet tx ${hash}: signed by ${t.signer_id}, not ${signer}`);
    if (t.receiver_id !== contract) throw new Error(`NEAR testnet tx ${hash}: sent to ${t.receiver_id}, not ${contract}`);
    const call = onlyCall(tx);
    if (!call || call.method !== method) throw new Error(`NEAR testnet tx ${hash}: not one call of ${method}`);
    if (call.args?.vault !== vault) throw new Error(`NEAR testnet tx ${hash}: not about vault ${short(vault)}`);
    return { tx, call, signedBy: t.public_key, ...outcomeOf(tx) };
  };
  const refusedWith = (out, hash, needle) => {
    if (!out.failure) throw new Error(`NEAR testnet tx ${hash}: the contract did not refuse it`);
    if (!out.failure.includes(needle)) throw new Error(`NEAR testnet tx ${hash}: refused, but not with "${needle}": ${said(out.failure)}`);
    return said(out.failure);
  };
  /** The full-access key the record names: it added the agent's key, and it sent what the agent could only sign. */
  const byFullKey = (signedBy, hash) => {
    if (signedBy !== fullKey) throw new Error(`NEAR testnet tx ${hash}: signed by ${signedBy}, not the full-access key proofs/c14-agent.json records`);
  };
  /** What the relay sent for the owner: the relay's key is not in the record, so the check is that it is not the agent's. */
  const notByAgentKey = (signedBy, hash) => {
    if (signedBy === key) throw new Error(`NEAR testnet tx ${hash}: signed by the agent's function-call key`);
  };

  const add = c14.agent.function_call_key.add_key_tx;
  const propose = c14.propose;
  const cancel = c14.owner_cancel;
  const rot = c14.rotation;
  const checks = [
    [`the key's AddKey ${add}`, async () => {
      const tx = await fetchTx(add, agent);
      const t = tx.transaction ?? {};
      const added = (t.actions ?? []).length === 1 ? t.actions[0].AddKey : null;
      if (t.hash !== add || t.signer_id !== agent || t.receiver_id !== agent || !added) throw new Error(`NEAR testnet tx ${add}: not one AddKey on ${agent}`);
      if (!outcomeOf(tx).ok) throw new Error(`NEAR testnet tx ${add}: it did not succeed`);
      if (added.public_key !== key) throw new Error(`NEAR testnet tx ${add}: it added ${added.public_key}, not the agent's key ${key}`);
      if (t.public_key === key) throw new Error(`NEAR testnet tx ${add}: signed by the agent's own key`);
      byFullKey(t.public_key, add);
      const perm = added.access_key?.permission?.FunctionCall;
      if (!perm) throw new Error(`NEAR testnet tx ${add}: the key it added is not a function-call key (${JSON.stringify(added.access_key?.permission)})`);
      const methods = perm.method_names ?? [];
      if (perm.receiver_id !== contract) throw new Error(`NEAR testnet tx ${add}: the key is for ${perm.receiver_id}, not ${contract}`);
      if (methods.length === 0) throw new Error(`NEAR testnet tx ${add}: the key lists no method, which NEAR reads as every method`);
      const extra = methods.filter((m) => !AGENT_KEY_METHODS.includes(m));
      if (extra.length) throw new Error(`NEAR testnet tx ${add}: the key may also call ${extra.join(', ')}`);
      return `NEAR testnet tx ${add}: ${agent} was given ${key} as a function-call key for ${contract}, methods ${methods.join(' and ')} only, signed by the full-access key the record names. NEAR refuses a transaction the agent's key signs for any other method or account, or with a deposit, before a contract runs`;
    }],
    [`the agent's propose_btc ${propose.tx}`, async () => {
      const out = await callTo(propose.tx, agent, 'propose_btc');
      if (out.signedBy !== key) throw new Error(`NEAR testnet tx ${propose.tx}: signed by ${out.signedBy}, not the agent's function-call key`);
      if (!out.ok || out.value !== propose.request) throw new Error(`NEAR testnet tx ${propose.tx}: it did not return request ${propose.request}`);
      const want = `undo:proposed request=${propose.request} unlock=${propose.unlock}`;
      const receipt = (out.tx.receipts_outcome ?? []).find((r) => r.outcome.executor_id === contract && r.outcome.logs.includes(want));
      if (!receipt) throw new Error(`NEAR testnet tx ${propose.tx}: no log "${want}" from ${contract}`);
      // The contract's clock is the block the call ran in. The wait is its unlock less that block's time.
      const block = await rpc(archival, 'block', { block_id: receipt.block_hash });
      const wait = propose.unlock - Number(BigInt(block.header.timestamp_nanosec) / 1_000_000n);
      const waits = [c14.contract.policy.t_new_ms, c14.contract.policy.t_new_unguarded_ms];
      if (!waits.includes(wait)) throw new Error(`NEAR testnet tx ${propose.tx}: the unlock is ${wait} ms after its block, not one of the contract's new-destination waits (${waits.join(', ')})`);
      return `NEAR testnet tx ${propose.tx}: propose_btc on ${contract}, signed by that function-call key, made request ${propose.request} of vault ${short(vault)}, and the contract set its unlock ${wait / 60_000}:00 after the block it ran in`;
    }],
    ...c14.contract_refusals.attempts.map((r) => [`${r.method} ${r.tx}`, async () => {
      const out = await callTo(r.tx, r.sent_by, r.method);
      byFullKey(out.signedBy, r.tx);
      const words = refusedWith(out, r.tx, r.needle);
      return `NEAR testnet tx ${r.tx}: ${r.what}, sent by the full-access account ${r.sent_by} with the full-access key the record names. The contract refused it: ${words}`;
    }]),
    [`the owner's cancel ${cancel.tx}`, async () => {
      const out = await callTo(cancel.tx, relay, 'cancel');
      notByAgentKey(out.signedBy, cancel.tx);
      if (out.call.args.request !== propose.request || !out.call.args.auth?.Passkey) throw new Error(`NEAR testnet tx ${cancel.tx}: not a passkey cancel of request ${propose.request}`);
      const want = `undo:cancelled request=${propose.request}`;
      if (!out.ok || !logsIn(out.tx, contract).includes(want)) throw new Error(`NEAR testnet tx ${cancel.tx}: no log "${want}" from ${contract}`);
      return `NEAR testnet tx ${cancel.tx}: the owner's passkey cancel of request ${propose.request}, sent by the relay ${relay} with a key that is not the agent's, log "${want}". The passkey was a software authenticator`;
    }],
    [`the owner's rotation ${rot.owner_rotate.tx}`, async () => {
      const out = await callTo(rot.owner_rotate.tx, relay, 'cancel_all_and_rotate');
      notByAgentKey(out.signedBy, rot.owner_rotate.tx);
      const want = `undo:rotating grant=${rot.owner_rotate.grant}`;
      if (!out.ok || !logsIn(out.tx, contract).includes(want)) throw new Error(`NEAR testnet tx ${rot.owner_rotate.tx}: no log "${want}" from ${contract}`);
      return `NEAR testnet tx ${rot.owner_rotate.tx}: the owner's passkey cancel_all_and_rotate, sent by the relay ${relay} with a key that is not the agent's, log "${want}". The passkey was a software authenticator`;
    }],
    [`the agent's propose_btc after the rotation ${rot.after_rotation.direct_tx}`, async () => {
      const out = await callTo(rot.after_rotation.direct_tx, agent, 'propose_btc');
      if (out.signedBy !== key) throw new Error(`NEAR testnet tx ${rot.after_rotation.direct_tx}: signed by ${out.signedBy}, not the agent's function-call key`);
      const words = refusedWith(out, rot.after_rotation.direct_tx, 'SpendKeySuspended');
      return `NEAR testnet tx ${rot.after_rotation.direct_tx}: propose_btc signed by the agent's function-call key after the rotation. The contract refused it: ${words}`;
    }],
    [`the agent's propose_btc after the new key landed ${rot.after_the_new_key_lands.propose_tx}`, async () => {
      const out = await callTo(rot.after_the_new_key_lands.propose_tx, agent, 'propose_btc');
      if (out.signedBy !== key) throw new Error(`NEAR testnet tx ${rot.after_the_new_key_lands.propose_tx}: signed by ${out.signedBy}, not the agent's function-call key`);
      const words = refusedWith(out, rot.after_the_new_key_lands.propose_tx, 'bad K_s signature');
      return `NEAR testnet tx ${rot.after_the_new_key_lands.propose_tx}: the agent CLI's propose once the owner's new spend key had landed. The contract refused it: ${words}`;
    }],
  ];
  const settle = async ([what, check]) => {
    try {
      return { status: 'PASS', text: await check() };
    } catch (err) {
      if (err instanceof NetworkDown) return { status: 'SKIP', text: `${what}: SKIP (network): ${err.message}`, down: true };
      return { status: 'FAIL', text: err instanceof ChainAnswer ? `${what}: the node answered ${err.message}` : err.message };
    }
  };
  // The first alone: with no archival RPC it says so once, and the rest are counted, not waited for. Then three at
  // a time, printed in the order above. A check that finds the network gone stops new ones from starting.
  const results = [await settle(checks[0])];
  let down = results[0].down === true;
  let next = 1;
  await Promise.all(Array.from({ length: 3 }, async () => {
    while (!down && next < checks.length) {
      const i = next;
      next += 1;
      results[i] = await settle(checks[i]);
      if (results[i].down) down = true;
    }
  }));
  for (const r of results) if (r) line(r.status, 'C14', 'replay', r.text);
  const unasked = checks.length - results.filter(Boolean).length;
  if (unasked > 0) line('SKIP', 'C14', 'replay', `${unasked} more transactions of the agent run: SKIP (network), the archival RPC did not answer`);
  // Read from proofs/ only. NEAR never broadcasts a transaction it refuses for its access key.
  const refused = c14.near_refusals.calls.map((r) => `${r.what}: ${r.words}`);
  line('INFO', 'C14', `live-testnet, recorded ${c14.near_refusals.at_utc.slice(0, 10)}`, `NEAR refused ${refused.length} calls signed by the agent's key before any contract ran, and the key's nonce did not move (${c14.near_refusals.key_nonce_before} before and after). Not fetched again: a transaction NEAR refuses for its access key is never broadcast, so nothing is on chain to fetch. As recorded:`);
  for (const l of refused) console.log(`    ${l}`);
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

/**
 * The Mutinynet half of one G2-shaped record: the co-signed spend, the escape and the refusals a sound script gives.
 * `tag` starts each line, and `where` is the INFO line's label for what is read from the record and not fetched.
 */
async function replayRunBitcoin({ p, esplora, tag, where }) {
  const spk = p.vault.spk;
  const valueOf = (role) => p.coins.find((c) => c.role === role)?.value;
  const cosignValue = valueOf('cosign');
  const escapeValue = valueOf('escape');
  await replayBitcoin({ id: 'C12', what: `${tag} co-signed spend: the spend key and the contract-requested MPC signature`, txid: p.cosigned.txid, raw: p.cosigned.raw, spk, values: [cosignValue], esplora, expectHeight: p.cosigned.mined_height });
  refusedControl({ id: 'C02', what: `${tag} control: the same spend with no spend-key signature, the MPC one alone`, raw: p.cosigned.ku_control.raw, spk, values: [cosignValue], nodeText: p.cosigned.ku_control.text });
  await replayBitcoin({ id: 'C04', what: `${tag} escape: the cold key alone, from the recovery file, once the coin was CSV old`, txid: p.escape.txid, raw: p.escape.raw, spk, values: [escapeValue], esplora, expectHeight: p.escape.mined_height, coin: { txid: p.escape.coin.split(':')[0] } });
  // Read from proofs/ only: nothing here fetches or judges it again, so it is INFO, not PASS.
  line('INFO', 'C04', where, `${tag} escape sent before the coin was CSV old: the Mutinynet node refused it at tip ${p.escape.early.tip_before}, coin height ${p.escape.early.coin_height}: ${p.escape.early.text}. Not fetched again: a refused transaction leaves nothing on chain to fetch`);
  refusedControl({ id: 'C04', what: `${tag} control: the escape signed one block below CSV`, raw: p.escape.csv_control.raw, spk, values: [escapeValue], nodeText: p.escape.csv_control.text });
}

/** The spend key alone, as one s2-refusal record holds it: judged here again, and its coin's spender read again. */
async function replayKeyAlone({ s2, name, spk, esplora, tag = '' }) {
  refusedControl({ id: 'C03', what: `${tag}spend key alone, sent to Mutinynet ${s2.node_answer.at_utc}: would have been txid ${s2.refused_tx.mutinynet_txid_it_would_have_had}`, raw: s2.refused_tx.raw_hex, spk, values: [s2.funding_coin.value_sats], nodeText: s2.node_answer.text_verbatim });
  try {
    const out = JSON.parse((await getText(`${esplora}/tx/${s2.funding_coin.mutinynet_txid}/outspend/${s2.funding_coin.vout}`)).text);
    const coin = `Mutinynet coin ${s2.funding_coin.mutinynet_txid}:${s2.funding_coin.vout}`;
    const back = s2.coin_return?.mutinynet_txid ?? null;
    if (out.spent && out.txid === s2.refused_tx.mutinynet_txid_it_would_have_had) line('FAIL', 'C03', 'replay', `${coin}: the refused spend is the one that spent the coin`);
    else if (out.spent && back && out.txid === back) line('PASS', 'C03', 'replay', `${coin}: spent later by Mutinynet txid ${out.txid}, the cold-key return ${name} records, not by the refused spend`);
    else if (out.spent) line('FAIL', 'C03', 'replay', `${coin}: spent by Mutinynet txid ${out.txid}, which is ${back ? `not the cold-key return ${name} records (${back})` : `not in ${name}`}`);
    else if (back) line('FAIL', 'C03', 'replay', `${coin}: the API says unspent, but ${name} records its cold-key return ${back}`);
    else line('PASS', 'C03', 'replay', `${coin}: still unspent`);
  } catch (err) {
    if (err instanceof NetworkDown) line('SKIP', 'C03', 'replay', `Mutinynet coin ${s2.funding_coin.mutinynet_txid}: SKIP (network): ${err.message}`);
    else line('FAIL', 'C03', 'replay', err.message);
  }
}

async function replayMutinynet(config) {
  const esplora = config.replay.mutinynet_esplora;
  const g2 = proof('g2.json');
  console.log('\n== tier A: replay of real Mutinynet transactions in proofs/ (Bitcoin signet test coins)');
  if (g2) await replayRunBitcoin({ p: g2, esplora, tag: 'G2', where: 'live-mutinynet, recorded in G2, 2026-10-31' });
  else line('SKIP', 'C12', 'replay', 'proofs/g2.json is not in this tree');

  const s2 = proof('s2-refusal.json');
  if (s2) {
    const spk = g2?.vault?.address === s2.funding_coin.vault_address ? g2.vault.spk : null;
    if (!spk) line('FAIL', 'C03', 'replay', 'proofs/s2-refusal.json names a vault this tree has no script for');
    else await replayKeyAlone({ s2, name: 'proofs/s2-refusal.json', spk, esplora });
  }
}

// ------------------------------------------------------------------ 3b. later live runs, each on the build it names

/** proofs/g2-NAME.json, with proofs/s2-refusal-NAME.json beside it if there is one. */
function laterRuns() {
  const dir = join(REPO, 'proofs');
  if (!existsSync(dir)) return [];
  return readdirSync(dir).filter((f) => /^g2-[a-z][a-z0-9]{0,15}\.json$/.test(f)).sort().map((f) => {
    const s2File = f.replace(/^g2-/, 's2-refusal-');
    return { name: `proofs/${f}`, p: proof(f), s2: proof(s2File), s2Name: `proofs/${s2File}` };
  });
}

const clock = (ms) => `${Math.floor(ms / 60_000)}:${String(Math.round((ms % 60_000) / 1000)).padStart(2, '0')}`;
const blockMs = async (archival, hash) => Number(BigInt((await rpc(archival, 'block', { block_id: hash })).header.timestamp_nanosec) / 1_000_000n);

/**
 * One later run. The NEAR half: which code the contract ran at the block of the execute, the proposal's unlock
 * against the block it ran in and the execute's block against that unlock, and the signer's answer against the
 * digest and the witness of the Bitcoin transaction the record says was mined. Then the Mutinynet half.
 */
async function replayLaterRun(config, { name, p, s2, s2Name }) {
  const archival = config.replay.near_archival_rpc;
  const rpcUrls = config.replay.near_rpc;
  const esplora = config.replay.mutinynet_esplora;
  const contract = p.contract?.account;
  const signer = p.signer?.account;
  const sha = p.wasm?.sha256 ?? '';
  // CLAIMS.md calls the wasm deploy/testnet.json records the final build.
  const isFinal = sha !== '' && sha === config.wasm_sha256;
  const build = isFinal ? `the final build ${short(sha)}` : `the build ${short(sha)}`;
  const tag = isFinal ? `Final build (${contract})` : `Build ${short(sha)} (${contract})`;
  const day = (p.coins?.[0]?.recorded_at ?? '').slice(0, 10) || 'no date';
  console.log(`\n== tier A: replay of the live run in ${name}: ${contract}, ${build}, with Mutinynet test coins`);
  if (p.schema !== 'undo-g2-v1' || p.label !== 'live-mutinynet' || p.chain_id !== 'testnet' || !contract || !signer || !p.vault?.id) {
    return line('FAIL', 'C12', 'replay', `${name} is not the record of a live run on NEAR testnet and Mutinynet`);
  }
  const c = p.cosigned ?? {};
  const e = p.escape ?? {};
  if (!c.readback || !e.readback) {
    // What a record does not hold did not run. It is said once, and no line passes for it.
    line('INFO', 'C12', `live-mutinynet, recorded ${day}`, `${name} holds ${c.readback ? 'a mined co-signed spend' : 'no mined co-signed spend'} and ${e.readback ? 'a mined escape' : 'no mined escape'}: the rest of that run is not yet run, and nothing here is replayed from it`);
    return undefined;
  }

  const vault = p.vault.id;
  const coinOf = (role) => p.coins.find((x) => x.role === role);
  const cosignCoin = { txid: c.coin.split(':')[0], vout: Number(c.coin.split(':')[1]), value: coinOf('cosign')?.value };
  const attempt = (c.attempts ?? []).find((a) => a.execute_tx && a.signer_answer);
  let executed = null;
  if (!attempt) line('FAIL', 'C12', 'replay', `${name} records a mined co-signed spend and no execute with a signer's answer`);
  else {
    await guarded('C12', 'replay', `${name} execute ${attempt.execute_tx}`, async () => {
      const out = await replayExecute({ proofName: name, run: { ...attempt, vault, raw: c.raw, payloads: null }, contract, signer, archival, rpcUrls });
      // The digest the signer was asked for is the one Bitcoin checks for the recorded transaction, and the
      // signature in that transaction's witness is the signer's answer, with S on the low side as Bitcoin wants it.
      const script = fromHex(p.vault.script);
      const digest = toHex(sighash(makeTx([cosignCoin], SEQUENCE_COSIGNED, [{ value: c.amount, spk: fromHex(c.to) }]), 0, script, cosignCoin.value));
      if (!out.payloads.some((q) => q.payload === digest)) throw new Error(`NEAR testnet tx ${attempt.execute_tx}: the signer was asked for another digest than Mutinynet txid ${c.txid}'s`);
      const checked = checkCosigned({ rawHex: c.raw, coin: cosignCoin, to: fromHex(c.to), amount: c.amount, script, km: out.km, ku: fromHex(p.vault.k_u) });
      if (checked.problem) throw new Error(`Mutinynet txid ${c.txid}: ${checked.problem.reason}: ${checked.problem.detail}`);
      if (checked.facts.txid !== c.txid) throw new Error(`${name}: the recorded bytes are txid ${checked.facts.txid}, not ${c.txid}`);
      // derSig writes r and s as Bitcoin takes them: strict DER, S on the low side, SIGHASH_ALL.
      const inWitness = toHex(parseTx(fromHex(c.raw)).inputs[0].witness[0]);
      const same = out.answers.some((a) => toHex(derSig(fromHex(`${a.big_r.affine_point.slice(2)}${a.s.scalar}`))) === inWitness);
      if (!same) throw new Error(`Mutinynet txid ${c.txid}: the K_m signature in its witness is not the one the signer returned in NEAR testnet tx ${attempt.execute_tx}`);
      executed = out;
      line('PASS', 'C12', 'replay', `NEAR testnet tx ${attempt.execute_tx}: an execute on ${contract}, ${build}. ${signer} was asked for the digest of Mutinynet txid ${c.txid}, and its answer verifies here under the K_m it derives for undo/${short(vault)}, matches ${name}, and is the K_m signature in that transaction's witness, beside the spend key's, which verifies here too`);
    });
  }
  if (attempt && !executed) line('SKIP', 'C12', 'replay', `${contract}'s code at the block of that execute, and the wait before it: not read, since the execute was not`);
  else if (executed) {
    await guarded('C12', 'replay', `${contract} code at the execute`, async () => {
      const account = await rpc(archival, 'query', { request_type: 'view_account', account_id: contract, block_id: executed.block });
      const want = base58Encode(fromHex(sha));
      if (account.code_hash !== want || p.contract.code_hash !== want) throw new Error(`${contract} ran code ${account.code_hash} at the block of NEAR testnet tx ${attempt.execute_tx}; ${name} names ${p.contract.code_hash}, and its wasm ${sha} hashes to ${want}`);
      line('PASS', 'C12', 'replay', `NEAR testnet account ${contract} ran code hash ${account.code_hash} at the block of that execute, read from archival RPC: the sha256 ${sha} that ${name} records${isFinal ? `, and that ${shown(configPath)} names: the final build` : ''}`);
    });
    await guarded('C01', 'replay', `${name} proposal ${c.propose_tx}`, async () => {
      const tx = await rpc(archival, 'tx', { tx_hash: c.propose_tx, sender_account_id: contract, wait_until: 'NONE' });
      const call = onlyCall(tx);
      if (tx.transaction?.receiver_id !== contract || call?.method !== 'propose_btc' || call.args?.vault !== vault) throw new Error(`NEAR testnet tx ${c.propose_tx}: not one propose_btc on ${contract} for vault ${short(vault)}`);
      const said = `undo:proposed request=${c.request} unlock=${c.unlock}`;
      const receipt = (tx.receipts_outcome ?? []).find((r) => r.outcome.executor_id === contract && r.outcome.logs.includes(said));
      if (!receipt) throw new Error(`NEAR testnet tx ${c.propose_tx}: no log "${said}" from ${contract}`);
      const wait = c.unlock - (await blockMs(archival, receipt.block_hash));
      if (wait !== c.check?.delay_ms) throw new Error(`NEAR testnet tx ${c.propose_tx}: the unlock is ${wait} ms after its block, and ${name} records a wait of ${c.check?.delay_ms} ms`);
      const began = `undo:executing request=${c.request} `;
      const ran = (executed.tx.receipts_outcome ?? []).find((r) => r.outcome.executor_id === contract && r.outcome.logs.some((l) => l.startsWith(began)));
      if (!ran) throw new Error(`NEAR testnet tx ${attempt.execute_tx}: no log "${began.trim()}" from ${contract}`);
      const after = (await blockMs(archival, ran.block_hash)) - c.unlock;
      if (after < 0) throw new Error(`NEAR testnet tx ${attempt.execute_tx}: the contract asked the signer ${-after} ms before request ${c.request}'s unlock`);
      line('PASS', 'C01', 'replay', `NEAR testnet tx ${c.propose_tx}: propose_btc on ${contract}, ${build}, made request ${c.request} with its unlock ${clock(wait)} after the block it ran in; the execute, tx ${attempt.execute_tx}, ran in a block ${Math.floor(after / 1000)} s after that unlock, not before. One request on NEAR testnet, read from archival RPC`);
    });
  }

  // The escape is the cold key's alone: no NEAR transaction to fetch. Its signature is checked here, then the node's copy.
  const escapeCoin = { txid: e.coin.split(':')[0], vout: Number(e.coin.split(':')[1]), value: coinOf('escape')?.value };
  const escaped = checkEscape({ rawHex: e.raw, coin: escapeCoin, to: parseTx(fromHex(e.raw)).outputs[0].spk, amount: e.amount, script: fromHex(p.vault.script), csv: p.vault.csv, ke: fromHex(p.vault.k_e_leaf) });
  if (escaped.problem) line('FAIL', 'C04', 'replay', `${name}: the recorded escape is not a cold-key spend of ${e.coin} at nSequence ${p.vault.csv}: ${escaped.problem.reason}: ${escaped.problem.detail}`);
  await replayRunBitcoin({ p, esplora, tag, where: `live-mutinynet, recorded on ${isFinal ? 'the final build' : build}, ${day}` });

  if (s2) {
    if (s2.funding_coin?.vault_address !== p.vault.address) line('FAIL', 'C03', 'replay', `${s2Name} names another vault than ${name}'s`);
    else await replayKeyAlone({ s2, name: s2Name, spk: p.vault.spk, esplora, tag: `${tag} ` });
  }
  return undefined;
}

async function replayLaterRuns(config) {
  for (const run of laterRuns()) await replayLaterRun(config, run);
}

// ------------------------------------------------------------------ 3c. the take of the live pages: the phone page's Cancel

/** The function call of `method` among a transaction's actions, with its JSON arguments, or null. */
function callNamed(tx, method) {
  const call = (tx.transaction?.actions ?? []).map((a) => a.FunctionCall).find((c) => c?.method_name === method);
  if (!call) return null;
  try {
    return JSON.parse(Buffer.from(fromBase64(call.args)).toString('utf8'));
  } catch {
    return null;
  }
}

/** The contract's own words in a failed call, or the failure as it came. */
const refusalWords = (failure) => {
  try {
    return JSON.parse(failure)?.ActionError?.kind?.FunctionCallError?.ExecutionError ?? failure;
  } catch {
    return failure;
  }
};

/**
 * proofs/film-take.json against the chains: the one take of the live phone page and thief tab that the film is cut
 * from. Its NEAR testnet transactions are fetched again from archival RPC, and the cancel's WebAuthn assertion is
 * checked again here, the way contracts/undo/src/auth.rs checks it, under the passkey in the vault's own create_vault.
 * The coin is read from the Mutinynet API as it is now. What no chain can say, which authenticator held the passkey,
 * is read from the record, and the line says so.
 */
async function replayTake(config) {
  const name = 'proofs/film-take.json';
  const take = proof('film-take.json');
  console.log(`\n== tier A: replay of the live take in ${name}: the phone page's Cancel, fetched again from archival RPC`);
  if (!take) return line('SKIP', 'C17', 'replay', `${name} is not in this tree`);
  const t = take.thief ?? {};
  const contract = take.contract;
  const vault = take.vault?.id ?? '';
  const sound = take.schema === 'undo-film-take-v1' && typeof contract === 'string' && /^[0-9a-f]{64}$/.test(vault) && take.vault.create_tx && take.vault.address
    && t.propose_tx && Number.isSafeInteger(t.request_id) && Number.isSafeInteger(t.unlock_ms) && Number.isSafeInteger(t.wait_ms) && t.sent_to && take.cancel?.tx && take.cancel.method === 'cancel_all_and_rotate'
    && take.after?.execute_after_the_wait_tx && take.after.execute_refusal && /^[0-9a-f]{64}$/.test(take.coin?.mutinynet_txid ?? '') && typeof take.origin === 'string';
  if (!sound) return line('FAIL', 'C17', 'replay', `${name} is not the record of a take of the live pages`);
  const archival = config.replay.near_archival_rpc;
  const esplora = config.replay.mutinynet_esplora;
  const signer = config.replay.signer ?? config.signer;
  const coinId = `${take.coin.mutinynet_txid}:${take.coin.vout}`;
  const virtual = (take.labels ?? []).includes('virtual authenticator');
  const fetchTx = async (hash) => {
    const tx = await rpc(archival, 'tx', { tx_hash: hash, sender_account_id: contract, wait_until: 'NONE' });
    if (tx.transaction?.hash !== hash) throw new Error(`NEAR testnet tx ${hash}: the node answered about another transaction`);
    if (tx.transaction.receiver_id !== contract) throw new Error(`NEAR testnet tx ${hash}: sent to ${tx.transaction.receiver_id}, not ${contract}`);
    return tx;
  };
  const receiptOf = (tx, test) => (tx.receipts_outcome ?? []).find((r) => r.outcome.executor_id === contract && test(r.outcome));
  // The wasm this contract account is recorded to run: the config's, or a later run's record of the same account.
  const sha = contract === config.contract ? config.wasm_sha256 : laterRuns().map((r) => r.p).find((p) => p?.contract?.account === contract)?.wasm?.sha256;
  // What a later line rests on, set only when the line that checks it passes: the proposal's block time (the request
  // exists, with its unlock), and the cancel's block (it ran after that proposal and before the unlock). A line that
  // rests on one of them is not checked without it, and says so.
  let proposedMs = null;
  let cancelBlock = null;
  let archivalDown = false;
  const restsOnProposal = (what, on) => ({ status: 'SKIP', text: `${what}: not checked, since the proposal above did not pass, and this line rests on it: ${on}` });

  const checks = [
    ['C17', `${name} proposal ${t.propose_tx}`, async () => {
      const tx = await fetchTx(t.propose_tx);
      const call = onlyCall(tx);
      if (call?.method !== 'propose_btc' || call.args?.vault !== vault) throw new Error(`NEAR testnet tx ${t.propose_tx}: not one propose_btc for vault ${short(vault)}`);
      const spends = (call.args.inputs ?? []).map((c) => `${c.txid}:${c.vout}`);
      if (spends.length !== 1 || spends[0] !== coinId) throw new Error(`NEAR testnet tx ${t.propose_tx}: it does not ask to spend the take's coin ${coinId} and nothing else`);
      if (call.args.to !== toHex(addressToSpk('mutinynet', t.sent_to))) throw new Error(`NEAR testnet tx ${t.propose_tx}: it pays another address than ${t.sent_to}, the one ${name} records`);
      // propose_btc logs as its last statement, before the state is written on exit: a failure after the log rolls the
      // request back and keeps the log. So the request exists only if the call succeeded and returned its id.
      const ended = outcomeOf(tx);
      if (!ended.ok) throw new Error(`NEAR testnet tx ${t.propose_tx}: it did not succeed: ${ended.failure ? refusalWords(ended.failure) : 'no outcome yet'}`);
      if (ended.value !== t.request_id) throw new Error(`NEAR testnet tx ${t.propose_tx}: it returned ${JSON.stringify(ended.value)}, not request ${t.request_id}`);
      const said = `undo:proposed request=${t.request_id} unlock=${t.unlock_ms}`;
      const receipt = receiptOf(tx, (o) => o.logs.includes(said));
      if (!receipt) throw new Error(`NEAR testnet tx ${t.propose_tx}: no log "${said}" from ${contract}`);
      const proposedAt = await blockMs(archival, receipt.block_hash);
      const wait = t.unlock_ms - proposedAt;
      if (wait !== t.wait_ms) throw new Error(`NEAR testnet tx ${t.propose_tx}: the unlock is ${wait} ms after its block, and ${name} records a wait of ${t.wait_ms} ms`);
      proposedMs = proposedAt;
      return `NEAR testnet tx ${t.propose_tx}: propose_btc on ${contract} made request ${t.request_id} of vault ${short(vault)}, a spend of Mutinynet coin ${short(take.coin.mutinynet_txid)}:${take.coin.vout} to ${t.sent_to}, with its unlock ${clock(wait)} after the block it ran in`;
    }],
    ['C05', `${name} cancel ${take.cancel.tx}`, async () => {
      if (proposedMs === null) return restsOnProposal(`${name} cancel ${take.cancel.tx}`, `the request it cancels, made before it, and that request's unlock, after it`);
      // The vault's own create_vault: the passkey it was made with, bound to the vault id by the id's hash.
      const made = await fetchTx(take.vault.create_tx);
      const a = callNamed(made, 'create_vault')?.args;
      if (!a?.passkey?.pubkey || !logsIn(made, contract).includes(`undo:created vault=${vault}`)) throw new Error(`NEAR testnet tx ${take.vault.create_tx}: not the create_vault of vault ${short(vault)}`);
      // The line says the relay's account made the vault: its create_vault, logged, must also have succeeded.
      if (!outcomeOf(made).ok) throw new Error(`NEAR testnet tx ${take.vault.create_tx}: it did not succeed: ${outcomeOf(made).failure ? refusalWords(outcomeOf(made).failure) : 'no outcome yet'}`);
      const kp = fromHex(a.passkey.pubkey);
      const id = toHex(vaultId({ contract, ks: fromHex(a.k_s), ku: fromHex(a.k_u), keLeaf: fromHex(a.k_e_leaf), keIntent: fromHex(a.k_e_intent), kp, csv: a.csv }));
      if (id !== vault) throw new Error(`NEAR testnet tx ${take.vault.create_tx}: the keys in its arguments hash to vault ${short(id)}, not ${short(vault)}`);
      if (p2wshAddress('mutinynet', witnessScript(fromHex(a.k_u), fromHex(a.k_m), fromHex(a.k_e_leaf), a.csv)) !== take.vault.address) throw new Error(`NEAR testnet tx ${take.vault.create_tx}: the script of its keys is not the address ${take.vault.address} that ${name} records`);
      if (a.passkey.rp_id_hash !== toHex(sha256(utf8(new URL(take.origin).hostname)))) throw new Error(`NEAR testnet tx ${take.vault.create_tx}: the vault's passkey is for another site than ${take.origin}`);

      const tx = await fetchTx(take.cancel.tx);
      const call = onlyCall(tx);
      if (call?.method !== take.cancel.method || call.args?.vault !== vault) throw new Error(`NEAR testnet tx ${take.cancel.tx}: not one ${take.cancel.method} for vault ${short(vault)}`);
      const sender = tx.transaction.signer_id;
      if (sender !== made.transaction.signer_id || sender !== a.guard) throw new Error(`NEAR testnet tx ${take.cancel.tx}: sent by ${sender}, not by ${made.transaction.signer_id}, the relay's account, which made the vault`);
      const receipt = receiptOf(tx, (o) => o.logs.includes(take.cancel.log));
      if (!outcomeOf(tx).ok || !receipt) throw new Error(`NEAR testnet tx ${take.cancel.tx}: ${outcomeOf(tx).ok ? `no log "${take.cancel.log}" from ${contract}` : `it did not succeed: ${outcomeOf(tx).failure ? refusalWords(outcomeOf(tx).failure) : 'no outcome yet'}`}`);
      const ranAt = await blockMs(archival, receipt.block_hash);
      const before = t.unlock_ms - ranAt;
      if (before <= 0) throw new Error(`NEAR testnet tx ${take.cancel.tx}: it ran ${-before} ms after request ${t.request_id}'s unlock, not before it`);
      // A cancel kills the requests pending when it runs: one that ran before the proposal says nothing of that request.
      const since = ranAt - proposedMs;
      if (since <= 0) throw new Error(`NEAR testnet tx ${take.cancel.tx}: it ran ${-since} ms before the proposal of request ${t.request_id}, tx ${t.propose_tx}, not after it`);
      // The challenge a passkey signs is the digest of the call's own arguments, so an assertion made for one call fits no other.
      const digest = intentDigest({ tag: PASSKEY_TAG, contract, vault: fromHex(vault), method: call.method, args: argBytes.cancel_all_and_rotate({ newKs: fromHex(call.args.new_k_s) }), expiresAt: call.args.expires_at, nonce: call.args.nonce });
      const refusal = refusalOf({ assertion: call.args.assertion, digest, pubkey: kp, rpIdHash: fromHex(a.passkey.rp_id_hash), origins: [take.origin] });
      if (refusal) throw new Error(`NEAR testnet tx ${take.cancel.tx}: its WebAuthn assertion does not pass here the checks the contract makes: ${refusal}`);
      cancelBlock = receipt.block_hash;
      return `NEAR testnet tx ${take.cancel.tx}: ${call.method} on ${contract} for vault ${short(vault)}, sent by ${sender}, the relay's account, which made the vault and is the guard it names, in a block ${Math.floor(since / 1000)} s after the proposal's and ${Math.floor(before / 1000)} s before request ${t.request_id}'s unlock, log "${take.cancel.log}". Its WebAuthn assertion passes here the checks the contract makes: the origin is ${take.origin}, the challenge is the digest of this call's own arguments, user present and verified, and the P-256 signature verifies under the passkey in that vault's create_vault, tx ${take.vault.create_tx}, whose keys hash to the vault id. ${virtual ? `As ${name} records, the passkey was Chrome's virtual authenticator, not a phone's` : `Which authenticator held the passkey, no chain says: see ${name}`}`;
    }],
    ['C05', `${contract} code at the cancel`, async () => {
      if (!cancelBlock) return { status: 'SKIP', text: `${contract}'s code at the block of that cancel: not read, since the cancel did not pass` };
      if (!sha) return { status: 'SKIP', text: `${contract}'s code at the block of that cancel: not read, since no record in this tree names the wasm ${contract} runs` };
      const account = await rpc(archival, 'query', { request_type: 'view_account', account_id: contract, block_id: cancelBlock });
      const want = base58Encode(fromHex(sha));
      if (account.code_hash !== want) throw new Error(`${contract} ran code ${account.code_hash} at the block of NEAR testnet tx ${take.cancel.tx}, not ${want}, the hash of the wasm ${sha}`);
      return `NEAR testnet account ${contract} ran code hash ${account.code_hash} at the block of that cancel, read from archival RPC: the sha256 ${sha}${sha === config.wasm_sha256 ? ` that ${shown(configPath)} names: the final build` : ''}`;
    }],
    ['C17', `${name} execute ${take.after.execute_after_the_wait_tx}`, async () => {
      if (proposedMs === null) return restsOnProposal(`${name} execute ${take.after.execute_after_the_wait_tx}`, 'the request this execute names, and its unlock');
      const hash = take.after.execute_after_the_wait_tx;
      const tx = await fetchTx(hash);
      const call = onlyCall(tx);
      if (call?.method !== 'execute' || call.args?.vault !== vault || call.args.request !== t.request_id) throw new Error(`NEAR testnet tx ${hash}: not one execute of request ${t.request_id} of vault ${short(vault)}`);
      const out = outcomeOf(tx);
      const receipt = receiptOf(tx, (o) => Boolean(o.status?.Failure));
      if (out.ok || !out.failure || !receipt) throw new Error(`NEAR testnet tx ${hash}: the contract did not refuse it`);
      if (!out.failure.includes(take.after.execute_refusal)) throw new Error(`NEAR testnet tx ${hash}: refused, but not with "${take.after.execute_refusal}": ${refusalWords(out.failure)}`);
      const after = (await blockMs(archival, receipt.block_hash)) - t.unlock_ms;
      if (after <= 0) throw new Error(`NEAR testnet tx ${hash}: it ran ${-after} ms before request ${t.request_id}'s unlock, so it does not show a refusal after the wait`);
      if ((tx.receipts_outcome ?? []).some((r) => r.outcome.executor_id === signer)) throw new Error(`NEAR testnet tx ${hash}: a receipt of it went to the signer ${signer}`);
      return `NEAR testnet tx ${hash}: an execute of request ${t.request_id} of that vault, sent by ${tx.transaction.signer_id} in a block ${Math.floor(after / 1000)} s after its unlock. The contract refused it: ${refusalWords(out.failure)}. No receipt of it went to the signer ${signer}`;
    }],
  ];
  // One at a time, in story order. When the archival RPC stops answering it says so once, and the rest are counted.
  for (const [i, [id, what, check]] of checks.entries()) {
    try {
      const out = await check();
      if (typeof out === 'string') line('PASS', id, 'replay', out);
      else line(out.status, id, 'replay', out.text);
    } catch (err) {
      if (err instanceof NetworkDown) {
        archivalDown = true;
        line('SKIP', id, 'replay', `${what}: SKIP (network): ${err.message}`);
        const left = checks.length - i - 1;
        if (left > 0) line('SKIP', 'C17', 'replay', `${left} more NEAR testnet lines of the live take: SKIP (network), the archival RPC did not answer`);
        break;
      }
      line('FAIL', id, 'replay', err instanceof ChainAnswer ? `${what}: the node answered ${err.message}` : err.message);
    }
  }

  // The coin, as the Mutinynet API has it now. The cancelled request's own spend would be a co-signed spend to the thief's address.
  // That this coin was a cancelled request's rests on the proposal and the cancel above: the cancel passes only after
  // the proposal did. Without it the line is not a pass, says why, and says only what the API answered; a spend to
  // the thief's address still fails it.
  const coin = `Mutinynet coin ${coinId}`;
  const cancelled = cancelBlock !== null;
  const notTied = archivalDown ? `SKIP (network): the archival RPC did not answer, so ${proposedMs === null ? 'the proposal and the cancel' : 'the cancel'} this line rests on ${proposedMs === null ? 'were' : 'was'} not checked`
    : 'not a pass, since the cancel above did not pass, and this line rests on it';
  try {
    const hex = await getText(`${esplora}/tx/${take.coin.mutinynet_txid}/hex`);
    if (hex.status === 404) throw new Error(`${coin}: the API does not know its transaction`);
    const funding = parseTx(fromHex(hex.text.trim()));
    if (txidOf(funding) !== take.coin.mutinynet_txid) throw new Error(`${coin}: the API's bytes are another transaction's`);
    const output = funding.outputs[take.coin.vout];
    if (!output || Number(output.value) !== take.coin.value_sats || toHex(output.spk) !== toHex(addressToSpk('mutinynet', take.vault.address))) throw new Error(`${coin}: it is not ${take.coin.value_sats} sats at ${take.vault.address}, the take's vault`);
    const status = JSON.parse((await getText(`${esplora}/tx/${take.coin.mutinynet_txid}/status`)).text);
    if (!status.confirmed || status.block_height !== take.coin.height) throw new Error(`${coin}: mined at ${status.confirmed ? status.block_height : 'no height'}, ${name} says ${take.coin.height}`);
    const facts = `${take.coin.value_sats.toLocaleString('en-US')} sats at ${take.vault.address}, the take's vault, mined at height ${status.block_height}`;
    const held = `${coin}: ${facts}`;
    /** A coin the cancelled request did not move: a pass with the clause that says so, or, untied to a cancel, what was read. */
    const kept = (read, clause) => (cancelled ? line('PASS', 'C17', 'replay', `${held}. ${read[0].toUpperCase()}${read.slice(1)}${clause}`)
      : line('SKIP', 'C17', 'replay', `${coin}: ${notTied}. Read from the Mutinynet API: ${facts}, ${read}`));
    const out = JSON.parse((await getText(`${esplora}/tx/${take.coin.mutinynet_txid}/outspend/${take.coin.vout}`)).text);
    if (!out.spent) kept('still unspent, read now', ': the cancelled request moved nothing');
    else {
      const spent = await getText(`${esplora}/tx/${out.txid}/hex`);
      if (spent.status === 404) throw new Error(`${coin}: the API names Mutinynet txid ${out.txid} as its spender and does not know that transaction`);
      const spender = parseTx(fromHex(spent.text.trim()));
      const input = spender.inputs.find((x) => x.coin.txid === take.coin.mutinynet_txid && x.coin.vout === take.coin.vout);
      if (txidOf(spender) !== out.txid || !input) throw new Error(`${coin}: the API names Mutinynet txid ${out.txid} as its spender, and the bytes it gives do not spend this coin`);
      // The script's two branches leave different witnesses: [K_m sig, K_u sig, 01, script] and [K_e sig, empty, script].
      const w = input.witness;
      const cosigned = w.length === 4 && w[2].length === 1 && w[2][0] === 1;
      const cold = w.length === 3 && w[1].length === 0;
      const thief = toHex(addressToSpk('mutinynet', t.sent_to));
      if (cosigned && spender.outputs.some((o) => toHex(o.spk) === thief)) line('FAIL', 'C17', 'replay', `${held}. Spent by Mutinynet txid ${out.txid}, a co-signed spend that pays ${t.sent_to}, ${cancelled ? 'the address of the cancelled request' : `the address of the thief tab's request in ${name}`}`);
      else if (cold) kept(`spent since by Mutinynet txid ${out.txid} through the script's cold-key branch, with one signature and none from MPC`, ': not by the cancelled request');
      else if (cosigned) kept(`spent since by Mutinynet txid ${out.txid}, a co-signed spend that does not pay ${t.sent_to}`, ': not the cancelled request\'s spend');
      else line('FAIL', 'C17', 'replay', `${held}. Spent by Mutinynet txid ${out.txid}, with a witness of neither branch of the vault's script`);
    }
  } catch (err) {
    if (err instanceof NetworkDown) line('SKIP', 'C17', 'replay', `${coin}: SKIP (network): ${err.message}`);
    else line('FAIL', 'C17', 'replay', err.message.startsWith(coin) ? err.message : `${coin}: ${err.message}`);
  }
  return undefined;
}

// ------------------------------------------------------------------ 5. recovery file, 6. static

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
    let verdicts = 0;
    for (const l of out.stdout.trim().split('\n')) {
      const m = /^(PASS|FAIL) (\S+) \[([^\]]+)\] (.*)$/.exec(l);
      if (m) {
        verdicts += 1;
        line(m[1], m[2], m[3], `${m[4]} (file built by tools/lib/recovery.mjs, as the page builds it)`);
      } else console.log(`    ${l}`);
    }
    // No verdict line is no pass: a dry run that printed nothing must not leave C18 out of the run.
    if (verdicts === 0) line('FAIL', 'C18', 'consensus-lib', `recovery-dry-run exit ${out.status}, and no PASS or FAIL line`);
    else if (out.status !== 0 && !/FAIL/.test(out.stdout)) line('FAIL', 'C18', 'consensus-lib', `recovery-dry-run exit ${out.status}`);
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
await replayAgent(config);
await replayMutinynet(config);
await replayLaterRuns(config);
await replayTake(config);
recoveryDryRun();
staticChecks();
console.log(`\nTIER A: ${tally.PASS} PASS, ${tally.SKIP} SKIP, ${tally.FAIL} FAIL${tally.INFO ? `, ${tally.INFO} INFO` : ''} in ${Math.round((Date.now() - started) / 1000)} s${config.placeholder ? '. The deployed-contract lines are SKIP because the config is a placeholder' : ''}`);
process.exit(tally.FAIL ? 1 : 0);
