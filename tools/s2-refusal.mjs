#!/usr/bin/env node
// The film's S2: a thief with the spend key alone tries a straight Bitcoin spend, and a Bitcoin node
// answers. Real coin in a real vault on Mutinynet, one real POST, and the node's words kept as they came.
//
//   node tools/s2-refusal.mjs --vault-dir DIR --capture FILE          plan only: reads public state, sends nothing
//   node tools/s2-refusal.mjs --vault-dir DIR --capture FILE --live   runs it, or picks it up from where it stopped
//
// --vault-dir is a finished G2 run's folder (private/g2, or private/g2-NAME for a run made with --run NAME), read
// and never written, and --capture is the record to write: the first run's is proofs/s2-refusal.json, so a later
// run's takes another name, proofs/s2-refusal-NAME.json, which ./verify.sh A reads beside proofs/g2-NAME.json.
// A capture file that already records another vault is never written over. No NEAR write: the vault already
// exists, and NEAR is only read, to show it is the vault the contract knows. The Mutinynet transactions:
// funding from the dispenser, the refused POST (pays nothing), and the escape that sends the coin back
// once it matures. State goes in the gitignored private/s2, and it holds no secret.
//
// Only a node's answer about this transaction is a refusal. A 5xx or a 429 says nothing, so those bytes
// go out again, and each answer is on record. A refusal that is on record is never sent a second time.
//
// Exit 0: refused by the script, coin read as unspent, coin back. 1: anything else. 2: bad usage.
// 3: refused before any write. 4: plan only, something is missing.
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, hostname, userInfo } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs, UsageError } from './lib/args.mjs';
import { makeTx, p2wshAddress, p2wshSpk, parseTx, SEQUENCE_COSIGNED, sighash, witnessScript } from './lib/btc.mjs';
import { fromHex, toHex, utf8 } from './lib/bytes.mjs';
import { sha256 } from './lib/crypto.mjs';
import { buildFunding, loadDispenser } from './lib/dispenser.mjs';
import { checkEndpoints, classifyBroadcast, Esplora, ESPLORA_ALLOW, NEAR_RPC_ALLOW } from './lib/esplora.mjs';
import { checkEscape, checkSig, cosignedVsize, escapeVsize, matureTip, withoutKmSig } from './lib/g2-check.mjs';
import { spendKeys } from './lib/keys.mjs';
import { Near } from './lib/near.mjs';
import { parseRecovery } from './lib/recovery.mjs';
import { keyAloneHalfSig } from './lib/spend.mjs';
import { VaultClient } from './lib/vault-client.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '..');
const STATE_DIR = join(REPO, 'private', 's2');
const GENESIS = '00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6';
const NETWORK = 'mutinynet';
const COIN_SATS = 10_000;
const FEE_RATE = 2;
const FEE_CEILING = 1000;
const POLL_MS = 5000;
const MINE_TIMEOUT_MS = 30 * 60_000;
const POST_TRIES = 6;
const USAGE = 'usage: s2-refusal.mjs --vault-dir DIR --capture FILE [--live] [--dispenser FILE] [--coin-sats N]';

const log = (...parts) => console.log(...parts);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
class Refused extends Error {}
class Stop extends Error {}

const SCRUB = [[REPO, '<repo>'], [homedir(), '<home>'], [userInfo().username, '<user>'], [hostname(), '<host>'], [hostname().split('.')[0], '<host>']]
  .filter(([value]) => value && value.length >= 3 && !/^[0-9a-f]+$/i.test(value));
const scrub = (text) => SCRUB.reduce((out, [value, mark]) => out.split(value).join(mark), text);

function writeJson(path, value, secrets, mode) {
  const text = scrub(`${JSON.stringify(value, null, 2)}\n`);
  for (const secret of secrets) {
    if (text.includes(secret)) throw new Error('a secret reached a file meant to hold none. Nothing was written');
  }
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(`${path}.tmp`, text, mode ? { mode } : undefined);
  renameSync(`${path}.tmp`, path);
}

/** Everything about the vault that must agree before a sat moves. Reads only. */
async function readVault({ dir, near, secrets }) {
  const g2 = JSON.parse(readFileSync(join(dir, 'state.json'), 'utf8'));
  if (g2.regtest) throw new Refused('that folder is a rehearsal');
  if (g2.network !== NETWORK) throw new Refused(`that folder is for ${g2.network}`);
  const v = g2.vault;
  if (!v?.active) throw new Refused('that folder names no active vault');

  const recoveryPath = join(dir, 'vault-recovery.json');
  const file = parseRecovery(readFileSync(recoveryPath, 'utf8'));
  secrets.push(toHex(file.cold));
  let seed;
  try {
    const held = JSON.parse(readFileSync(join(dir, 'vault-keys.json'), 'utf8'));
    seed = fromHex(held.seed);
    secrets.push(held.seed, held.passkey);
  } catch {
    // Node quotes the text around a parse error, and here that text is the seed.
    throw new Refused('the vault key file is damaged');
  }

  const script = fromHex(v.script);
  const ku = spendKeys(seed).ku.pub;
  if (toHex(ku) !== v.k_u) throw new Refused('the seed does not give this vault\'s K_u');
  if (toHex(witnessScript(ku, fromHex(v.k_m), fromHex(v.k_e_leaf), v.csv)) !== v.script) throw new Refused('the keys do not give this vault\'s script');
  if (p2wshAddress(NETWORK, script) !== v.address || file.address !== v.address) throw new Refused('the script, the recovery file and the address disagree');

  // K_m is the signer's, and the contract's row names it too. A coin here is in a vault the contract knows.
  const instance = await near.view(g2.contract, 'instance');
  if (instance.network !== NETWORK) throw new Refused(`the contract is for ${instance.network}`);
  const client = new VaultClient({ near, contract: g2.contract, signer: g2.signer, instance, origin: 'https://undo-btc.pages.dev', rpId: 'undo-btc.pages.dev' });
  const id = fromHex(v.id);
  const row = await client.viewVault(id);
  if (!row?.active) throw new Refused('the contract has no active row for this vault');
  if (row.address !== v.address || row.k_m !== v.k_m) throw new Refused('the contract\'s row disagrees with the folder');
  const signerKm = toHex(await client.derivedKey(id));
  if (signerKm !== v.k_m) throw new Refused('the signer derives another K_m for this vault');
  const code = (await near.account(g2.contract))?.code_hash ?? null;
  return { g2, v, seed, script, recoveryPath, file, contract: g2.contract, signer: g2.signer, code };
}

async function waitMined(esplora, id, resend) {
  const deadline = Date.now() + MINE_TIMEOUT_MS;
  let polls = 0;
  while (Date.now() < deadline) {
    const status = await esplora.txStatus(id);
    if (status?.confirmed) return status;
    polls += 1;
    if (resend && polls % 6 === 0 && !(await esplora.tx(id))) {
      log(`  ${id} is not known to the relay any more, sending the same bytes again`);
      await resend();
    }
    await sleep(POLL_MS);
  }
  throw new Stop(`${id} was not mined in time. Run again to resume`);
}

/** The coin, recorded before it is broadcast, so a stop at any point loses nothing. */
async function fundCoin({ state, save, esplora, dispenser, v, coinSats }) {
  if (!state.coin) {
    const utxos = await esplora.utxos(dispenser.address);
    const built = buildFunding({ dispenser, utxos, payTo: fromHex(v.spk), value: coinSats, feeRate: FEE_RATE });
    if (built.short) throw new Stop('the dispenser cannot cover the coin and the fee right now');
    if (built.fee > FEE_CEILING) throw new Stop(`funding would pay ${built.fee} sats, over ${FEE_CEILING}`);
    state.coin = { ...built, recorded_at: new Date().toISOString() };
    save();
  }
  const c = state.coin;
  if (c.height !== undefined) return c;
  if (!(await esplora.tx(c.txid))) {
    const answer = await esplora.broadcast(c.raw, c.txid);
    if (answer.kind !== 'accepted' && answer.refusal !== 'already') throw new Stop(`funding refused: ${answer.text}`);
  }
  log(`Funding coin ${c.txid}:${c.vout} on Mutinynet, ${c.value} sats, fee ${c.fee}. Waiting for a block`);
  const status = await waitMined(esplora, c.txid, () => esplora.broadcast(c.raw, c.txid));
  c.height = status.block_height;
  c.block = status.block_hash;
  save();
  log(`  mined at ${c.height}`);
  return c;
}

/** The thief's transaction, and every check that it is what it claims, before it goes anywhere. */
function buildThief({ checkBin, seed, script, spk, coin, toSpk, ku }) {
  const value = { txid: coin.txid, vout: coin.vout, value: coin.value };
  const fee = cosignedVsize({ coin: value, to: toSpk, amount: 1, script }) * FEE_RATE;
  if (fee > FEE_CEILING) throw new Stop(`it would pay ${fee} sats, over ${FEE_CEILING}`);
  const amount = coin.value - fee;
  const halfRs = keyAloneHalfSig({ seed, script, coin: value, to: toSpk, amount });
  const built = withoutKmSig({ coin: value, to: toSpk, amount, halfRs, script });
  const tx = parseTx(fromHex(built.raw));
  const w = tx.inputs[0].witness;
  const digest = sighash(makeTx([value], SEQUENCE_COSIGNED, [{ value: amount, spk: toSpk }]), 0, script, coin.value);
  const bad = checkSig(w[1], digest, ku, 'K_u');
  if (bad) throw new Stop(`K_u's signature is not honest, so a refusal would prove nothing: ${bad.reason}`);
  if (w[0].length !== 0) throw new Stop('something sits where K_m\'s signature goes');
  const local = spawnSync(checkBin, ['verify', built.raw, toHex(spk), String(coin.value)], { encoding: 'utf8' });
  if (local.status === 0) throw new Stop('libbitcoinconsensus accepts the key alone. Nothing was sent. The script is not what this project claims');
  // Exit 1 is the referee's refusal. A crash is none, and the record would then claim a refusal that never happened.
  if (local.status !== 1) throw new Stop(`the consensus check gave no verdict (exit ${local.status}). Nothing was sent`);
  return { ...built, fee, amount, consensus: 'libbitcoinconsensus refused it before the POST', k_u_signature_verified: true };
}

/** A control for that last check: a dead checker refuses everything, so it must accept G2's mined spend. */
function checkerControl({ checkBin, g2, spk }) {
  const raw = g2.cosigned?.raw;
  const value = g2.coins?.find((c) => c.role === 'cosign')?.value;
  if (!raw || !value) throw new Refused('that run has no co-signed spend to use as the consensus control');
  if (spawnSync(checkBin, ['verify', raw, toHex(spk), String(value)], { encoding: 'utf8' }).status !== 0) {
    throw new Refused('the consensus check refuses a spend that was mined, so its refusals mean nothing');
  }
}

/** One POST, and the body exactly as it came. Esplora.broadcast cuts the text, so it does not do this one. */
async function postOnce(esplora, raw, id) {
  const at = new Date().toISOString();
  let res;
  try {
    res = await esplora.request('/tx', { method: 'POST', headers: { 'content-type': 'text/plain' }, body: raw });
  } catch (err) {
    return { at_utc: at, http_status: null, text_verbatim: null, kind: 'transient', note: err.message };
  }
  const body = await res.text();
  const sorted = classifyBroadcast(res.status, body, id);
  return { at_utc: at, http_status: res.status, text_verbatim: body, kind: sorted.kind, refusal: sorted.refusal ?? null };
}

function captureOf({ state, vault, cfg, thief }) {
  const c = state.coin;
  const p = state.post;
  const last = p.answers[p.answers.length - 1];
  const rawBytes = fromHex(thief.raw);
  return {
    schema: 'undo-s2-refusal-v1',
    chip: 'signet test coins',
    bitcoin_chain: 'Mutinynet (a signet)',
    near_chain: 'NEAR testnet, read only',
    attempt: 'A straight Bitcoin spend of the whole coin with the spend key alone: K_u\'s real signature, and nothing where K_m\'s goes.',
    node_answer: {
      endpoint: `POST ${cfg.esplora}/tx`,
      http_status: last.http_status,
      text_verbatim: last.text_verbatim,
      at_utc: last.at_utc,
      origin: 'No browser and no page. A Node script sent it, and set no Origin header',
      kind: last.kind,
      refusal: last.refusal,
      false_top_stack: /false\/empty top stack/i.test(last.text_verbatim ?? ''),
      names_op_checksigverify: /CHECKSIGVERIFY/i.test(last.text_verbatim ?? ''),
      names_this_tx: (last.text_verbatim ?? '').includes(thief.id),
      names_this_coin: (last.text_verbatim ?? '').includes(`${c.txid}:${c.vout}`),
      answers_with_no_information_before_it: p.answers.length - 1,
    },
    funding_coin: {
      mutinynet_txid: c.txid, vout: c.vout, value_sats: c.value, height: c.height, block: c.block, fee_paid_sats: c.fee,
      vault_address: vault.v.address,
    },
    refused_tx: {
      mutinynet_txid_it_would_have_had: thief.id,
      sha256_of_raw_bytes: toHex(sha256(rawBytes)),
      sha256_of_raw_hex_text: toHex(sha256(utf8(thief.raw))),
      raw_hex: thief.raw,
      pays_to: state.to_address,
      amount_sats: thief.amount,
      fee_it_offered_sats: thief.fee,
      witness: ['empty, where K_m goes', 'K_u, verified here before the POST', '01, the co-signed branch', 'the vault script'],
      consensus_before_post: thief.consensus,
      sats_moved: 0,
    },
    vault: { near_testnet_contract: vault.contract, near_testnet_code_hash: vault.code, id: vault.v.id, csv_blocks: vault.v.csv, k_m: vault.v.k_m, k_u: vault.v.k_u, signer: vault.signer, note: `The vault of the tools/g2.mjs run on ${vault.contract}. The contract row and the signer's derived key were read before funding and both matched` },
    after: state.after ?? null,
    coin_return: state.returned ?? null,
  };
}

async function returnCoin({ state, save, esplora, vault, dispenser, cfg }) {
  if (state.returned?.height !== undefined) return;
  const c = state.coin;
  const v = vault.v;
  const value = { txid: c.txid, vout: c.vout, value: c.value };
  if (!state.returned) {
    const mature = matureTip(c.height, v.csv);
    log(`Sending the coin back by the escape, once the tip reaches ${mature}`);
    const deadline = Date.now() + MINE_TIMEOUT_MS;
    while ((await esplora.tip()) < mature) {
      if (Date.now() > deadline) throw new Stop('the coin did not mature in time. Run again to resume');
      await sleep(POLL_MS);
    }
    const fee = escapeVsize({ coins: [value], to: dispenser.spk, script: vault.script, csv: v.csv }) * FEE_RATE;
    const workDir = join(STATE_DIR, 'work');
    mkdirSync(workDir, { recursive: true, mode: 0o700 });
    const listPath = join(workDir, 'utxos.json');
    writeFileSync(listPath, JSON.stringify([value]));
    const r = spawnSync(process.execPath, [join(HERE, 'escape.mjs'), '--recovery', vault.recoveryPath, '--utxos', listPath, '--to', dispenser.address, '--fee', String(fee)], { encoding: 'utf8', cwd: workDir, env: { PATH: process.env.PATH ?? '' } });
    if (r.status !== 0) throw new Stop(`escape.mjs refused: ${r.stderr.trim()}`);
    const raw = r.stdout.match(/^hex\s+([0-9a-f]+)$/m)?.[1];
    const id = r.stdout.match(/^txid\s+([0-9a-f]{64})$/m)?.[1];
    if (!raw || !id) throw new Stop('escape.mjs printed no transaction');
    const amount = c.value - fee;
    const checked = checkEscape({ rawHex: raw, coin: value, to: dispenser.spk, amount, script: vault.script, csv: v.csv, ke: fromHex(v.k_e_leaf) });
    if (checked.problem) throw new Stop(`the escape is not what was asked for: ${checked.problem.reason}`);
    if (spawnSync(cfg.checkBin, ['verify', raw, v.spk, String(c.value)], { encoding: 'utf8' }).status !== 0) throw new Stop('consensus refuses the escape');
    state.returned = { path: 'escape, signed by the cold key', mutinynet_txid: id, raw, fee_sats: fee, amount_sats: amount, to: dispenser.address };
    save();
  }
  const ret = state.returned;
  if (!(await esplora.tx(ret.mutinynet_txid))) {
    const answer = await esplora.broadcast(ret.raw, ret.mutinynet_txid);
    if (answer.kind !== 'accepted' && answer.refusal !== 'already' && answer.refusal !== 'bip68') throw new Stop(`the escape was refused: ${answer.text}`);
    // A relay can lag its own tip by a block. waitMined sends the same bytes again.
    if (answer.refusal === 'bip68') log('  the relay is a block behind, trying again next block');
  }
  log(`  escape ${ret.mutinynet_txid}, waiting for a block`);
  const status = await waitMined(esplora, ret.mutinynet_txid, () => esplora.broadcast(ret.raw, ret.mutinynet_txid));
  ret.height = status.block_height;
  ret.block = status.block_hash;
  const spend = await esplora.outspend(c.txid, c.vout);
  if (spend?.txid !== ret.mutinynet_txid) throw new Stop(`the coin reads as spent by ${spend?.txid}`);
  ret.coin_spent_by = spend.txid;
  ret.left_at_address_sats = (await esplora.utxos(v.address)).reduce((s, u) => s + u.value, 0);
  delete ret.raw;
  save();
  log(`  mined at ${ret.height}. ${ret.amount_sats} sats back at the dispenser, ${ret.fee_sats} paid in fee`);
}

async function main() {
  const a = parseArgs(process.argv.slice(2), { live: 'flag', 'vault-dir': 'text', capture: 'text', dispenser: 'text', 'coin-sats': 'int' });
  if (!a['vault-dir'] || !a.capture) throw new UsageError(USAGE);
  const coinSats = a['coin-sats'] ?? COIN_SATS;
  if (coinSats < 6000) throw new UsageError('--coin-sats must be at least 6000, or escape.mjs asks about its fee');
  // A record already there is some vault's only copy. A run adds to its own, and never writes over another's:
  // read from the two files alone, before any request.
  const capturePath = resolve(a.capture);
  if (existsSync(capturePath)) {
    const vaultOf = (path) => {
      try {
        return JSON.parse(readFileSync(path, 'utf8'))?.vault?.id ?? null;
      } catch {
        return null;
      }
    };
    const mine = vaultOf(join(resolve(a['vault-dir']), 'state.json'));
    if (!mine || vaultOf(capturePath) !== mine) throw new Refused('--capture names a file that records another vault, or that this tool did not write. Nothing was sent. Give this run a file of its own');
  }
  const checkBin = process.env.UNDO_TOOLS_CHECK_BIN;
  if (!checkBin || !existsSync(checkBin)) throw new Refused('set UNDO_TOOLS_CHECK_BIN');

  const cfg = { esplora: ESPLORA_ALLOW[0], rpc: NEAR_RPC_ALLOW, checkBin };
  checkEndpoints({ regtest: false, esplora: cfg.esplora, rpc: cfg.rpc });
  const esplora = new Esplora(cfg.esplora);
  if ((await esplora.genesis())?.trim() !== GENESIS) throw new Refused('that Esplora is on another Bitcoin chain');
  const near = new Near(cfg.rpc);
  const nearStatus = await near.status();
  if (nearStatus.chain_id !== 'testnet') throw new Refused(`expected NEAR testnet, the RPC says ${nearStatus.chain_id}`);

  const secrets = [];
  const dispenser = loadDispenser(a.dispenser ?? join(homedir(), '.config', 'undo', 'dispenser-mutinynet.json'), NETWORK);
  secrets.push(toHex(dispenser.secret));
  const vault = await readVault({ dir: resolve(a['vault-dir']), near, secrets });
  const spk = fromHex(vault.v.spk);
  if (toHex(p2wshSpk(vault.script)) !== vault.v.spk) throw new Refused('the script does not give this vault\'s output script');
  checkerControl({ checkBin, g2: vault.g2, spk });

  const statePath = join(STATE_DIR, 'state.json');
  const ignored = spawnSync('git', ['-C', REPO, 'check-ignore', '-q', statePath]).status === 0;
  if (!ignored) throw new Refused('the state folder is not gitignored');
  const state = existsSync(statePath) ? JSON.parse(readFileSync(statePath, 'utf8')) : { schema: 'undo-s2-state-v1', started_at: new Date().toISOString() };
  const utxos = await esplora.utxos(dispenser.address);
  const atVault = await esplora.utxos(vault.v.address);
  const tip = await esplora.tip();

  if (!a.live) {
    log('PLAN ONLY. Nothing was sent. Add --live to run it.');
    log(`  Bitcoin    Mutinynet at ${cfg.esplora}, tip ${tip}`);
    log(`  vault      ${vault.v.address}, CSV ${vault.v.csv}, ${atVault.length} coins there now. Contract row and signer's K_m both agree with the folder`);
    log(`  contract   ${vault.contract} on NEAR testnet, code hash ${vault.code}. Read only`);
    log(`  dispenser  ${dispenser.address}, ${utxos.filter((u) => u.status?.confirmed).reduce((s, u) => s + u.value, 0)} confirmed sats`);
    log(`  control    the consensus check accepts G2's mined spend`);
    log(`  state      ${state.coin ? `exists, coin ${state.coin.txid}${state.post ? ', POST on record' : ''}` : 'none: would start fresh'}`);
    log(`Would do: fund ${coinSats} sats, POST K_u's signature alone once, re-read the coin, send it back by the escape after ${vault.v.csv} blocks.`);
    return 0;
  }

  mkdirSync(STATE_DIR, { recursive: true, mode: 0o700 });
  const lockPath = join(STATE_DIR, 'lock');
  try {
    writeFileSync(lockPath, String(process.pid), { flag: 'wx', mode: 0o600 });
  } catch {
    throw new Refused('another run is working here. If it is not, delete its lock file');
  }
  process.on('exit', () => rmSync(lockPath, { force: true }));
  const save = () => writeJson(statePath, state, secrets, 0o600);
  state.to_address = dispenser.address;
  save();

  const coin = await fundCoin({ state, save, esplora, dispenser, v: vault.v, coinSats });
  const ku = fromHex(vault.v.k_u);
  const thief = buildThief({ checkBin, seed: vault.seed, script: vault.script, spk, coin, toSpk: dispenser.spk, ku });

  // ------------------------------------------------------------ the POST
  state.post ??= { answers: [] };
  const landed = () => state.post.answers.some((x) => x.kind !== 'transient');
  if (!landed()) {
    const before = await esplora.outspend(coin.txid, coin.vout);
    if (before?.spent) throw new Stop(`the coin is already spent, by ${before.txid}`);
    for (let i = 0; i < POST_TRIES && !landed(); i += 1) {
      const answer = await postOnce(esplora, thief.raw, thief.id);
      state.post.answers.push(answer);
      save();
      log(`POST /tx: HTTP ${answer.http_status}: ${answer.text_verbatim ?? answer.note}`);
      if (answer.kind === 'transient') await sleep(POLL_MS * (i + 1));
    }
  }
  const last = state.post.answers[state.post.answers.length - 1];
  if (last.kind === 'transient') throw new Stop('no node answered about this transaction. Run again: nothing is known yet');
  if (last.kind === 'accepted') {
    console.error('A NODE TOOK THE SPEND KEY ALONE. The script on chain is not what this project claims. Stopped.');
    return 1;
  }

  // ------------------------------------------------------------ the coin afterwards
  if (!state.after) {
    const spend = await esplora.outspend(coin.txid, coin.vout);
    const list = await esplora.utxos(vault.v.address);
    const known = await esplora.tx(thief.id);
    state.after = {
      read_at_utc: new Date().toISOString(),
      tip: await esplora.tip(),
      outspend_answer: spend,
      in_address_utxo_list: list.some((u) => u.txid === coin.txid && u.vout === coin.vout),
      refused_tx_known_to_the_api: Boolean(known),
      coin_still_unspent: spend?.spent === false,
    };
    save();
  }
  const capture = () => writeJson(capturePath, captureOf({ state, vault, cfg, thief }), secrets);
  capture();
  log(`Capture written. Coin still unspent: ${state.after.coin_still_unspent}. Refusal kind: ${last.refusal}`);
  if (!state.after.coin_still_unspent) throw new Stop('the coin does not read as unspent');
  if (last.refusal !== 'script') throw new Stop(`refused, but not by the script: ${last.text_verbatim}`);

  await returnCoin({ state, save, esplora, vault, dispenser, cfg });
  capture();
  log('Done. Capture updated with the coin\'s return.');
  return 0;
}

main().then((code) => process.exit(code ?? 0)).catch((err) => {
  if (err instanceof UsageError) {
    console.error(err.message);
    process.exit(2);
  }
  if (err instanceof Refused) {
    console.error(`Refused: ${scrub(err.message)}`);
    process.exit(3);
  }
  console.error(`s2 stopped: ${scrub(err.message)}`);
  process.exit(1);
});
