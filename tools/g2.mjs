#!/usr/bin/env node
// G2 driver: does the two-branch script hold on a real Bitcoin network? Real coins on Mutinynet and
// real signatures from the testnet signer.
//
//   node tools/g2.mjs                  plan only: reads public state, sends nothing, says if it would go
//   node tools/g2.mjs --live           runs it, or picks it up from where it stopped
//   node tools/g2.mjs --live --return-coins   sends what is left in every run's vault back, by the
//                                      escape. Needs only the recovery files, Esplora and the dispenser
//   node tools/g2.mjs --record-browser FILE   writes a browser POST's result into the proof. No network
//   node tools/g2.mjs --regtest        rehearses on bitcoind, a local NEAR node and a mock signer
//
// A co-signed spend is proposed, waits out the unlock, is signed by the signer, read back mined. Then
// the escape: built only from the recovery file and an Esplora UTXO list by tools/escape.mjs, sent
// while the coin is young and refused, sent again unchanged once it matures, read back mined.
//
// A young coin's refusal says nothing about the witness, since a node checks BIP-68 before the script.
// So two transactions a sound script must refuse go out too, and they pay nothing when refused: the
// co-signed spend with K_u's signature taken out, and on a mature coin the escape signed for nSequence
// csv-1. A script without K_u's check or without OP_CSV takes them, and the run fails.
//
// Secrets live in the recovery file and vault-keys.json, under a gitignored folder. The state file
// beside them holds none. A coin goes into the state file before its transaction is broadcast, so a
// stop at any point loses nothing, and a re-run asks the chain what happened before doing anything.
//
// Read request state, not transaction status: status says success even when a callback failed.
// Only a node's answer about the transaction counts as a refusal. A 5xx or a 429 is no answer. Only a
// script refusal of a correctly built co-signed spend is the kill line.
//
// Exit 0: passed, or plan ready. 1: failed, each failure with its own reason. 2: bad usage.
// 3: refused before any write. 4: plan only, something is missing. 5: rehearsal stopped on request.
import { spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, readdirSync, readFileSync, realpathSync, renameSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, hostname, userInfo } from 'node:os';
import { basename, dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs, UsageError } from './lib/args.mjs';
import { p2wshAddress, p2wshSpk, parseTx, witnessScript } from './lib/btc.mjs';
import { base58Encode, fromHex, toHex } from './lib/bytes.mjs';
import { randomBytes, sha256 } from './lib/crypto.mjs';
import { buildFunding, fundingVsize, loadDispenser } from './lib/dispenser.mjs';
import { checkEndpoints, classifyBroadcast, EndpointRefused, Esplora, ESPLORA_ALLOW, NEAR_RPC_ALLOW, RelayError } from './lib/esplora.mjs';
import { assembleCosigned, checkCosigned, checkEscape, checkReadback, cosignedVsize, escapeOneShort, escapeVsize, isHighS, matureTip, withoutKuSig, witnessHexOf } from './lib/g2-check.mjs';
import { spendKeys } from './lib/keys.mjs';
import { action, credentialsPath, failureOf, loadCredentials, logsOf, Near, RpcError, TGAS } from './lib/near.mjs';
import { buildRecovery, parseRecovery, RecoveryError } from './lib/recovery.mjs';
import { newOwnerKeys, VaultClient } from './lib/vault-client.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(HERE, '..');
const PROOFS = join(REPO, 'proofs');
const PRIVATE = join(REPO, 'private');
const REHEARSAL_ROOT = join(REPO, 'target', 'g2-rehearsal');

const USAGE = `usage: g2.mjs [--live | --regtest] [--return-coins] [--new-run] [--list-stops] [--record-browser FILE]
  [--coin-sats N] [--csv N] [--fee-rate N] [--fee-ceiling N] [--confirmations N] [--sign-timeout-sec N] [--mine-timeout-sec N]
  [--dispenser FILE] [--payer ACCOUNT] [--relay ACCOUNT] [--contract ACCOUNT] [--esplora URL] [--rpc URL] [--wasm FILE]
  rehearsal only: --rig FILE --state-dir DIR --out FILE --test-stop-at NAME --test-fault NAME --poll-ms N`;

const LIVE = {
  chain: 'testnet',
  network: 'mutinynet',
  rpc: NEAR_RPC_ALLOW,
  esplora: ESPLORA_ALLOW[0],
  // Every signet shares this genesis, and mainnet does not. The allow list names the signet itself.
  genesis: '00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6',
  signer: 'v1.signer-prod.testnet',
  payer: 's.undo-btc.testnet',
  relay: 's.undo-relay.testnet',
  contract: 'g1.s.undo-btc.testnet',
  credNetwork: 'testnet',
  stateDir: join(REPO, 'private', 'g2'),
  out: join(PROOFS, 'g2.json'),
  label: 'live-mutinynet',
  gate: 'G2',
};
const REGTEST_GENESIS = '0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206';
const REGTEST_LABEL = 'rehearsal-regtest-mock-signer';

const CSV = 6;
const COIN_SATS = 20_000;
const FEE_RATE = 2;
// Per transaction. The contract refuses a co-signed spend above 1,000 sats on this preset anyway.
const FEE_CEILING = 1000;
const DEPOSIT_MILLI = 50;
const SIGN_TGAS = 30;
const CALLBACK_TGAS = 10;
const OWN_WORK_TGAS = 30;
const SIGN_ATTEMPTS = 2;
const FRESH_COIN_TRIES = 3;
const MATURE_RETRIES = 5;
// While waiting for a transaction nobody knows of any more, how many polls between sends of the same bytes.
const RESEND_EVERY = 6;
const READBACK_TRIES = 12;
// escape.mjs asks for a flag above this share of the coins, and this driver does not pass one.
const ESCAPE_FEE_PERCENT = 5;
const ORIGIN = 'https://undo-btc.pages.dev';
const RP_ID = 'undo-btc.pages.dev';

// The stop points of a clean run, in order. The rehearsal stops at each one and resumes.
const STOPS = [
  'vault:recorded', 'vault:active',
  'fund-cosign:recorded', 'fund-cosign:broadcast', 'fund-cosign:confirmed',
  'cosign:signed-intent', 'cosign:proposed', 'cosign:unlocked', 'cosign:executing', 'cosign:signed', 'cosign:assembled', 'cosign:ku-control', 'cosign:broadcast', 'cosign:mined',
  'fund-escape:recorded', 'fund-escape:broadcast', 'fund-escape:confirmed',
  'escape:built', 'escape:refused', 'escape:matured', 'escape:csv-control', 'escape:broadcast', 'escape:mined',
  'browser:measured', 'leftovers:listed',
];
// Only reached when a coin is left over.
const LEFTOVER_STOPS = ['leftovers:built', 'leftovers:broadcast'];
// Right after a send and before writing it down, where the chain knows more than the state file.
const CRASH_STOPS = ['crash:create-sent', 'crash:fund-cosign-sent', 'crash:propose-sent', 'crash:execute-sent', 'crash:ku-control-sent', 'crash:cosigned-sent', 'crash:fund-escape-sent', 'crash:csv-control-sent', 'crash:escape-sent'];

const log = (...parts) => console.log(...parts);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** A failure with its own reason. Resumable ones say nothing against the script or the keys. */
class Fail extends Error {
  constructor(step, reason, detail, { resumable = false, kill = false } = {}) {
    super(`${reason}: ${detail}`);
    Object.assign(this, { step, reason, detail, resumable, kill });
  }
}
class Refused extends Error {}
class CoinAged extends Error {}

// ---------------------------------------------------------------- what goes on disk

const SCRUB = [[REPO, '<repo>'], [homedir(), '<home>'], [userInfo().username, '<user>'], [hostname(), '<host>'], [hostname().split('.')[0], '<host>']]
  // A bare hex word could also occur inside a txid, and replacing it there would corrupt the record.
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

/** The path as it really is on disk, through links and in the disk's own case, even if not all of it exists yet. */
function realOf(path) {
  const rest = [];
  let at = resolve(path);
  while (!existsSync(at) && dirname(at) !== at) {
    rest.unshift(basename(at));
    at = dirname(at);
  }
  return join(realpathSync.native(at), ...rest);
}

function isInside(path, folder) {
  const rel = relative(realOf(folder), realOf(path));
  return rel === '' || (rel !== '..' && !rel.startsWith('../') && !rel.startsWith('/'));
}

/** One run at a time on a folder: a second would spend what the first is about to. A dead run's lock is taken over. */
function takeLock(dir) {
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const path = join(dir, 'lock');
  for (;;) {
    try {
      writeFileSync(path, String(process.pid), { flag: 'wx', mode: 0o600 });
      process.on('exit', () => rmSync(path, { force: true }));
      return;
    } catch (err) {
      if (err.code !== 'EEXIST') throw err;
    }
    try {
      process.kill(Number(readFileSync(path, 'utf8')), 0);
    } catch (err) {
      if (err.code === 'ESRCH') {
        rmSync(path, { force: true });
        continue;
      }
    }
    throw new Refused('another run is working in this folder. If it is not, delete its lock file');
  }
}

const insideProofs = (path) => isInside(path, PROOFS);
const holdsSecrets = (dir) => existsSync(join(dir, 'vault-recovery.json')) || existsSync(join(dir, 'vault-keys.json'));

function isGitignored(path) {
  return spawnSync('git', ['-C', REPO, 'check-ignore', '-q', path], { encoding: 'utf8' }).status === 0;
}

function toolsCheckBin() {
  const candidates = [process.env.UNDO_TOOLS_CHECK_BIN, join(REPO, 'target/fix2-tools/debug/undo-tools-check'), join(HERE, 'rust-check/target/debug/undo-tools-check')];
  return candidates.find((p) => p && existsSync(p)) ?? null;
}

function outwardCheck(wasm) {
  const result = spawnSync(join(REPO, 'scripts', 'outward-check.sh'), ['--wasm', wasm], { encoding: 'utf8' });
  process.stdout.write(result.stdout ?? '');
  process.stderr.write(result.stderr ?? '');
  return result.status === 0;
}

// ---------------------------------------------------------------- money

function plannedFees(cfg, dispenser) {
  const dummyCoin = { txid: '00'.repeat(32), vout: 0, value: cfg.coinSats };
  const script = new Uint8Array(111);
  const vaultSpk = new Uint8Array(34);
  const sizes = {
    funding: fundingVsize([dummyCoin], vaultSpk, dispenser.spk),
    cosigned: cosignedVsize({ coin: dummyCoin, to: dispenser.spk, amount: 1, script }),
    escape: escapeVsize({ coins: [dummyCoin], to: dispenser.spk, script, csv: 6 }),
  };
  const fees = Object.fromEntries(Object.entries(sizes).map(([k, v]) => [k, v * cfg.feeRate]));
  return { sizes, fees };
}

/** What is still to be spent, given what the state file says already went out. */
function budget(cfg, state, fees) {
  const has = (role) => state?.coins.some((c) => c.role === role);
  const cosignDone = Boolean(state?.cosigned?.readback);
  const coinsLeft = (has('cosign') || cosignDone ? 0 : 1) + (has('escape') ? 0 : 1);
  const hasVault = Boolean(state?.vault?.active);
  return {
    coinsLeft,
    sats: coinsLeft * (cfg.coinSats + fees.funding) + fees.funding,
    // Prepaid gas is held until its refund lands, so these carry a float.
    payerNear: hasVault ? 0 : (DEPOSIT_MILLI + 20 + 100) / 1000,
    relayNear: cosignDone ? 0 : 0.06,
  };
}

function refuseFees(cfg, plan) {
  for (const [name, fee] of Object.entries(plan.fees)) {
    if (fee > cfg.feeCeiling) throw new Refused(`fee_over_ceiling: the ${name} transaction would pay ${fee} sats at ${cfg.feeRate} sat/vB, over the ceiling of ${cfg.feeCeiling}`);
  }
  if (plan.fees.escape * 100 > cfg.coinSats * ESCAPE_FEE_PERCENT) throw new Refused(`coin_too_small: an escape fee of ${plan.fees.escape} sats is above ${ESCAPE_FEE_PERCENT}% of a ${cfg.coinSats} sat coin, and escape.mjs would refuse it`);
}

// ---------------------------------------------------------------- the run

class Driver {
  constructor(ctx) {
    Object.assign(this, ctx);
    this.secrets = [];
    this.statePath = join(this.cfg.stateDir, 'state.json');
    this.keysPath = join(this.cfg.stateDir, 'vault-keys.json');
    this.recoveryPath = join(this.cfg.stateDir, 'vault-recovery.json');
    this.workDir = join(this.cfg.stateDir, 'work');
    if (this.dispenser) this.secrets.push(toHex(this.dispenser.secret));
  }

  stop(name) {
    if (this.cfg.stopAt === name) {
      log(`Stopped on request at ${name}. Run again to resume.`);
      process.exit(5);
    }
  }

  save() {
    writeJson(this.statePath, this.state, this.secrets, 0o600);
  }

  writeProof() {
    if (this.cfg.regtest && insideProofs(this.cfg.out)) throw new Error('a rehearsal never writes into proofs/');
    writeJson(this.cfg.out, this.proofOf(), this.secrets);
  }

  // -------------------------------------------------------------- vault

  loadSecretsIfAny() {
    if (existsSync(this.recoveryPath)) {
      try {
        this.secrets.push(JSON.parse(readFileSync(this.recoveryPath, 'utf8')).cold_key);
      } catch {
        // A damaged file is the escape stage's to report.
      }
    }
    if (existsSync(this.keysPath)) {
      try {
        const keys = JSON.parse(readFileSync(this.keysPath, 'utf8'));
        this.seed = fromHex(keys.seed);
        this.passkey = fromHex(keys.passkey);
        this.secrets.push(keys.seed, keys.passkey);
      } catch {
        // Node quotes the text around a parse error, and here that text is the seed. The way out needs only the recovery file.
        if (!this.cfg.returnCoins) throw new Refused('the vault key file is damaged');
      }
    }
    this.secrets = this.secrets.filter((s) => typeof s === 'string' && s.length > 0);
  }

  async stageVault() {
    const { client, cfg, state } = this;
    if (!state.vault) {
      if (holdsSecrets(cfg.stateDir)) throw new Refused('stray_keys: this folder holds a recovery or key file that no state file names');
      const cold = randomBytes(32);
      const seed = randomBytes(32);
      const passkey = randomBytes(32);
      const keys = newOwnerKeys({ seed, cold, passkey });
      const id = client.idFor(keys, state.csv);
      const km = await client.derivedKey(id);
      const script = witnessScript(keys.ku.pub, km, keys.leaf.pub, state.csv);
      mkdirSync(cfg.stateDir, { recursive: true, mode: 0o700 });
      chmodSync(cfg.stateDir, 0o700);
      // Secrets reach the disk before any transaction exists that would need them.
      // wx: a cold key already here may be the only way to coins. It is never written over.
      writeFileSync(this.recoveryPath, `${buildRecovery({ network: state.network, vaultId: toHex(id), script, cold })}\n`, { mode: 0o600, flag: 'wx' });
      writeFileSync(this.keysPath, `${JSON.stringify({ format: 'undo-g2-vault-keys-v1', seed: toHex(seed), passkey: toHex(passkey) }, null, 2)}\n`, { mode: 0o600, flag: 'wx' });
      this.loadSecretsIfAny();
      const dry = spawnSync(cfg.checkBin, ['dry-run', this.recoveryPath], { encoding: 'utf8' });
      if (dry.status !== 0) throw new Fail('vault', 'recovery_file_refused', `the Rust referee refused a new recovery file: ${dry.stdout.trim()}`);
      state.vault = {
        id: toHex(id),
        csv: state.csv,
        k_m: toHex(km),
        k_u: toHex(keys.ku.pub),
        k_e_leaf: toHex(keys.leaf.pub),
        script: toHex(script),
        spk: toHex(p2wshSpk(script)),
        address: p2wshAddress(state.network, script),
        recovery_file: 'written to a gitignored local path, never in this file',
        recovery_dry_run: dry.stdout.trim(),
        deposit_milli_near: DEPOSIT_MILLI,
        active: false,
      };
      this.save();
      log(`Vault ${state.vault.id}, address ${state.vault.address}, CSV ${state.csv} blocks`);
    }
    this.stop('vault:recorded');
    if (state.vault.active) return;

    const vaultId = fromHex(state.vault.id);
    let view = await client.viewVault(vaultId);
    if (!view) {
      const file = parseRecovery(readFileSync(this.recoveryPath, 'utf8'));
      const keys = newOwnerKeys({ seed: this.seed, cold: file.cold, passkey: this.passkey });
      const created = await client.create(this.payer, keys, { csv: state.csv, depositMilli: DEPOSIT_MILLI });
      this.stop('crash:create-sent');
      state.vault.create_tx = created.tx;
      view = created.view;
      const failure = failureOf(created.result);
      if (!view && failure) throw new Fail('vault', 'vault_not_created', failure, { resumable: true });
      this.save();
    }
    if (view && !view.active) {
      // The first callback was lost. The contract keeps the row and lets anyone ask again.
      await this.near.sendAndWait(this.payer, cfg.contract, [action.call('activate', { vault: state.vault.id }, 100n * TGAS, 0n)]);
      view = await client.viewVault(vaultId);
    }
    if (!view?.active) throw new Fail('vault', 'vault_not_active', view ? 'the signer did not confirm K_m' : 'the row is gone: the contract refused K_m', { resumable: true });
    if (view.address !== state.vault.address) throw new Fail('vault', 'vault_address_mismatch', `the contract says ${view.address}`);
    if (view.k_m !== state.vault.k_m) throw new Fail('vault', 'vault_key_mismatch', 'the contract holds another K_m');
    if (view.csv !== state.csv) throw new Fail('vault', 'vault_csv_mismatch', String(view.csv));
    state.vault.active = true;
    state.vault.spend_nonce_at_create = view.spend_nonce;
    this.save();
    log('Vault active');
    this.stop('vault:active');
  }

  // -------------------------------------------------------------- coins

  /** A coin on the vault's address, recorded before it is broadcast and read back when it confirms. */
  async ensureCoin(role) {
    const { esplora, state, cfg } = this;
    for (let tries = 0; tries < FRESH_COIN_TRIES; tries += 1) {
      let coin = state.coins.find((c) => c.role === role);
      if (coin?.height !== undefined) return coin;
      if (!coin) coin = await this.recordFunding(role);
      this.stop(`fund-${role}:recorded`);
      const seen = await esplora.tx(coin.txid);
      if (!seen) {
        const answer = await esplora.broadcast(coin.raw, coin.txid);
        this.stop(`crash:fund-${role}-sent`);
        if (answer.kind !== 'accepted' && answer.refusal !== 'already') {
          if (answer.refusal === 'inputs_gone') {
            // Something else spent the dispenser coin first. Nothing of ours went out, so pick again.
            log(`  the dispenser coin was already spent elsewhere, choosing another`);
            coin.role = 'never_broadcast';
            coin.dropped_because = answer.text;
            this.save();
            continue;
          }
          // It says nothing about the script, and sending the same bytes again costs nothing.
          throw new Fail(`fund-${role}`, 'funding_rejected', answer.text, { resumable: true });
        }
      }
      coin.broadcast = true;
      this.save();
      log(`  funding ${role}: ${coin.txid} sent`);
      this.stop(`fund-${role}:broadcast`);
      const status = await this.waitMined(`fund-${role}`, coin.txid, { confirmations: cfg.confirmations, resend: () => esplora.broadcast(coin.raw, coin.txid) });
      coin.height = status.block_height;
      coin.block_hash = status.block_hash;
      coin.confirmations_when_recorded = (await esplora.tip()) - coin.height + 1;
      this.save();
      log(`  funding ${role}: mined at ${coin.height}, ${coin.confirmations_when_recorded} confirmations`);
      this.stop(`fund-${role}:confirmed`);
      return coin;
    }
    throw new Fail(`fund-${role}`, 'dispenser_coins_taken', 'the dispenser coins kept being spent by something else', { resumable: true });
  }

  async recordFunding(role) {
    const { cfg, state, esplora, dispenser } = this;
    const deadline = Date.now() + cfg.mineTimeoutSec * 1000;
    let built;
    for (;;) {
      const utxos = await esplora.utxos(dispenser.address);
      built = buildFunding({ dispenser, utxos, payTo: fromHex(state.vault.spk), value: state.coin_sats, feeRate: cfg.feeRate });
      if (!built.short) break;
      // Only confirmed coins get spent, and the dispenser's own change may still be on its way.
      const total = utxos.reduce((s, u) => s + u.value, 0);
      if (total <= state.coin_sats || Date.now() > deadline) throw new Fail(`fund-${role}`, 'insufficient_sats', `the dispenser cannot cover ${state.coin_sats} sats and the fee`, { resumable: true });
      await sleep(cfg.pollMs);
    }
    if (built.fee > cfg.feeCeiling) throw new Fail(`fund-${role}`, 'fee_over_ceiling', `funding would pay ${built.fee} sats, over ${cfg.feeCeiling}`);
    const coin = { role, ...built, broadcast: false, recorded_at: new Date().toISOString() };
    state.coins.push(coin);
    this.save();
    return coin;
  }

  /** A relay that took a transaction can lose it: a restart, an eviction. Then `resend` sends the same bytes. */
  async waitMined(step, id, { confirmations = 1, resend = null } = {}) {
    const { esplora, cfg, state } = this;
    const deadline = Date.now() + cfg.mineTimeoutSec * 1000;
    let polls = 0;
    while (Date.now() < deadline) {
      const status = await esplora.txStatus(id);
      if (status?.confirmed) {
        const tip = await esplora.tip();
        if (tip - status.block_height + 1 >= confirmations) return status;
      } else if (resend && (polls += 1) % RESEND_EVERY === 0 && !(await esplora.tx(id))) {
        log(`  ${id} is not known to the relay any more, sending the same bytes again`);
        state.resent = (state.resent ?? 0) + 1;
        await resend();
      }
      await sleep(cfg.pollMs);
    }
    throw new Fail(step, 'not_mined_in_time', `${id} after ${cfg.mineTimeoutSec} s`, { resumable: true });
  }

  async waitNextBlock(step) {
    const { esplora, cfg } = this;
    const was = await esplora.tip();
    const deadline = Date.now() + cfg.mineTimeoutSec * 1000;
    while ((await esplora.tip()) === was) {
      if (Date.now() > deadline) throw new Fail(step, 'not_mined_in_time', `the tip stayed at ${was}`, { resumable: true });
      await sleep(cfg.pollMs);
    }
  }

  /** Esplora's view of a mined transaction. A missing or unusable answer is the relay's gap, so it asks again. */
  async readMined(step, id, coin) {
    const { esplora, cfg } = this;
    let got;
    for (let i = 0; i < READBACK_TRIES; i += 1) {
      got = { apiTx: await esplora.tx(id), hexBack: await esplora.txHex(id), fresh: await esplora.txStatus(id), spend: await esplora.outspend(coin.txid, coin.vout) };
      if (got.apiTx && got.hexBack && got.fresh?.confirmed && got.spend?.txid) return got;
      await sleep(cfg.pollMs);
    }
    throw new Fail(step, 'readback_incomplete', `no full answer about ${id} in ${READBACK_TRIES} tries`, { resumable: true });
  }

  /**
   * Bytes a sound script must refuse. A script refusal is the only good answer, and it pays nothing.
   * Being taken means the script on chain is not the one this project claims.
   */
  async control(step, name, stopName, raw, id, expected) {
    const answer = await this.esplora.broadcast(raw, id);
    this.stop(stopName);
    const taken = answer.kind === 'accepted' || answer.refusal === 'already';
    if (taken) throw new Fail(step, `${name}_accepted`, `the node took it: ${answer.text}`);
    if (answer.refusal !== 'script') throw new Fail(step, `${name}_unclear`, `refused, but not by the script: ${answer.text}`, { resumable: true });
    return { txid: id, raw, http_status: answer.status, text: answer.text, refusal: answer.refusal, names_the_check: expected.test(answer.text) };
  }

  /** libbitcoinconsensus on every input, and a wrong value that must fail, so a dead checker cannot pass. */
  consensus(step, rawHex, spkHex, values) {
    const { checkBin } = this.cfg;
    const ok = spawnSync(checkBin, ['verify', rawHex, spkHex, values.join(',')], { encoding: 'utf8' });
    if (ok.status !== 0) throw new Fail(step, 'consensus_refused', ok.stdout.trim() || ok.stderr.trim());
    const wrong = [...values];
    wrong[0] += 1;
    const control = spawnSync(checkBin, ['verify', rawHex, spkHex, wrong.join(',')], { encoding: 'utf8' });
    if (control.status === 0) throw new Fail(step, 'consensus_control_passed', 'a wrong value was accepted, so this check proves nothing');
    // Exit 1 is the referee's refusal; a crash is not one, and would make this control prove nothing.
    if (control.status !== 1) throw new Fail(step, 'consensus_control_not_judged', `the referee gave no verdict on the wrong value (exit ${control.status})`);
    return { accepted: 'libbitcoinconsensus, every input', wrong_value_control: 'refused' };
  }

  // -------------------------------------------------------------- co-signed spend

  vaultObject() {
    const v = this.state.vault;
    const { ks, ku } = spendKeys(this.seed);
    return {
      id: fromHex(v.id), hex: v.id, keys: { seed: this.seed, ks, ku }, km: fromHex(v.k_m), csv: v.csv,
      script: fromHex(v.script), spk: fromHex(v.spk), spendNonce: 0, passkeyNonce: 0,
    };
  }

  async stageCosigned() {
    const { state, client } = this;
    const c = state.cosigned;
    if (c.readback) return;
    const coin = await this.ensureCoin('cosign');
    if (!c.raw) {
      const vault = this.vaultObject();
      const request = await this.proposeOnce(vault, coin);
      await client.waitUntil(request.unlock + 1, { fastForward: this.cfg.regtest, log, pollMs: this.cfg.regtest ? this.cfg.pollMs : 2000 });
      c.unlocked_at_ms = await this.near.nowMs();
      this.save();
      this.stop('cosign:unlocked');
      const signed = await this.signOnce(vault);
      this.stop('cosign:signed');
      await this.assemble(signed, coin);
      this.stop('cosign:assembled');
    }
    if (!c.ku_control) {
      c.ku_control = await this.control('cosign', 'ku_control', 'crash:ku-control-sent', withoutKuSig(c.raw), c.txid, /CHECKSIGVERIFY/i);
      this.save();
      log(`  without K_u's signature, refused: ${c.ku_control.text}`);
    }
    this.stop('cosign:ku-control');
    await this.broadcastCosigned(coin);
  }

  async proposeOnce(vault, coin) {
    const { state, client, near, cfg } = this;
    const c = state.cosigned;
    const to = this.dispenser.spk;
    const value = { txid: coin.txid, vout: coin.vout, value: coin.value };
    const size = cosignedVsize({ coin: value, to, amount: 1, script: vault.script });
    // The contract's floor is 149 vB at 1 sat/vB, from counts, a little over the real size.
    const fee = Math.max(size * cfg.feeRate, 149);
    if (fee > cfg.feeCeiling) throw new Fail('cosign', 'fee_over_ceiling', `would pay ${fee} sats, over ${cfg.feeCeiling}`);
    const amount = coin.value - fee;
    const point = await near.view(cfg.contract, 'outpoint', { vault: vault.hex, txid: coin.txid, vout: coin.vout });
    if (point.state === 'Free') {
      const view = await client.viewVault(vault.id);
      vault.spendNonce = view.spend_nonce;
      const inputs = [value];
      c.check = await near.view(cfg.contract, 'check_propose', { vault: vault.hex, inputs, to: toHex(to), amount, change: null });
      const args = await client.proposeArgs(vault, { coins: inputs, to, amount, change: null });
      Object.assign(c, { to: toHex(to), amount, fee, planned_vsize: size, half_sig: args.half_sigs[0], coin: `${coin.txid}:${coin.vout}`, coin_confirmations_at_propose: (await this.esplora.tip()) - coin.height + 1 });
      this.save();
      this.stop('cosign:signed-intent');
      const proposed = await client.propose(this.relay, vault, args, 41n).catch((err) => {
        throw new Fail('cosign', 'propose_refused', err.message, { resumable: true });
      });
      this.stop('crash:propose-sent');
      c.propose_tx = proposed.tx;
      c.request = proposed.request;
    } else {
      // A run stopped after the transaction went out. The ledger knows which request holds the coin.
      c.request = point.request ?? c.request;
      if (c.request === undefined || c.request === null) throw new Fail('cosign', 'coin_busy', `coin is ${point.state} under no request`);
      if (c.half_sig === undefined) throw new Fail('cosign', 'lost_half_signature', 'a request exists but this run did not record its half-signature');
    }
    const request = await client.viewRequest(vault, c.request);
    if (!request) throw new Fail('cosign', 'request_gone', `request ${c.request}`, { resumable: true });
    Object.assign(c, { tier: request.tier, unlock: request.unlock, expires_at: request.expires_at, proposed_at: request.proposed_at });
    this.save();
    log(`  proposed request ${c.request}, tier ${request.tier}, ${Math.round((request.unlock - request.proposed_at) / 1000)} s to unlock`);
    this.stop('cosign:proposed');
    return request;
  }

  /** Sends execute at inclusion, then watches contract state. Never trusts the transaction's status. */
  async signOnce(vault) {
    const { state, client, near, cfg } = this;
    const c = state.cosigned;
    c.attempts ??= [];
    const prepaid = BigInt(SIGN_TGAS + CALLBACK_TGAS + OWN_WORK_TGAS);
    // A run that stopped right after sending leaves a transaction the state may not show yet.
    await sleep(cfg.regtest ? 2500 : 5000);
    for (let tries = 0; tries < SIGN_ATTEMPTS; tries += 1) {
      let view = await client.viewRequest(vault, c.request);
      if (!view) throw new Fail('cosign', 'request_gone', `request ${c.request}`, { resumable: true });
      let attempt = c.attempts[c.attempts.length - 1];
      if (view.status === 'Signed') {
        if (attempt && !attempt.outcome) {
          attempt.outcome = 'signed';
          delete attempt.started_at;
          Object.assign(attempt, await this.receiptFacts(attempt.execute_tx));
          this.save();
        }
        return view;
      }
      // An attempt with no outcome was included when it was sent, even if the state does not show it
      // yet. Sending again would race it, so watch it first.
      const unresolved = attempt && !attempt.outcome;
      const canSend = !unresolved && (view.status === 'Pending' || (view.status === 'Signing' && view.in_flight === 0));
      if (canSend) {
        const sent = await near.send(this.relay, cfg.contract, [action.call('execute', { vault: vault.hex, request: c.request, sign_tgas: SIGN_TGAS }, prepaid * TGAS, 0n)]);
        this.stop('crash:execute-sent');
        attempt = { execute_tx: sent.hash, attach_tgas: SIGN_TGAS, prepaid_tgas: Number(prepaid), started_at: Date.now() };
        c.attempts.push(attempt);
        this.save();
        this.stop('cosign:executing');
      } else if (attempt) {
        // Picked up mid-signing. The clock restarts, since the first run's clock is gone.
        attempt.started_at = Date.now();
      }
      const deadline = Date.now() + cfg.signTimeoutSec * 1000;
      let outcome = 'timeout';
      let polls = 0;
      while (Date.now() < deadline) {
        await sleep(cfg.regtest ? 200 : 1000);
        polls += 1;
        view = await client.viewRequest(vault, c.request).catch(() => view);
        if (!view) break;
        if (view.status === 'Signed') {
          outcome = 'signed';
          break;
        }
        if (view.status === 'Signing' && view.in_flight === 0) {
          outcome = 'callback_without_signature';
          break;
        }
        if (view.status === 'Pending' && polls % 5 === 0 && attempt) {
          const status = await near.txStatus(attempt.execute_tx, this.relay.accountId).catch(() => null);
          const failure = failureOf(status);
          if (failure) {
            outcome = 'execute_refused';
            attempt.failure = failure;
            break;
          }
        }
      }
      if (attempt) {
        attempt.outcome = outcome;
        attempt.ms = Date.now() - attempt.started_at;
        delete attempt.started_at;
        // Reading receipts waits for the whole tree, so not while the signer is still silent.
        if (outcome !== 'timeout') Object.assign(attempt, await this.receiptFacts(attempt.execute_tx));
        this.save();
      }
      log(`  signer: ${outcome}${attempt?.ms !== undefined ? ` after ${attempt.ms} ms` : ''}`);
      if (outcome === 'signed') return view;
      if (outcome === 'timeout') throw new Fail('cosign', 'signer_timeout', `no answer in ${cfg.signTimeoutSec} s`, { resumable: true });
      if (outcome === 'execute_refused') throw new Fail('cosign', 'execute_refused', attempt.failure, { resumable: true });
    }
    // Status says success here, and that is exactly why status is not what gets read.
    const last = c.attempts[c.attempts.length - 1];
    throw new Fail('cosign', 'signer_no_signature', `the contract stored no signature in ${c.attempts.length} attempts, transaction status: ${last?.tx_status ?? 'unknown'}`, { resumable: true });
  }

  async receiptFacts(hash) {
    const { near, cfg } = this;
    try {
      const status = await near.txStatus(hash, this.relay.accountId, 'EXECUTED_OPTIMISTIC');
      const answers = status.receipts_outcome
        .filter((r) => r.outcome.executor_id === cfg.signer && r.outcome.status?.SuccessValue)
        .map((r) => {
          try {
            return JSON.parse(Buffer.from(r.outcome.status.SuccessValue, 'base64').toString('utf8'));
          } catch {
            return null;
          }
        })
        .filter((v) => v && typeof v === 'object');
      return {
        tx_status: failureOf(status) ? 'failure' : 'success',
        contract_logs: logsOf(status).filter((l) => l.startsWith('undo:')),
        signer_answer: answers[0] ?? null,
      };
    } catch (err) {
      return { receipt_note: `could not read receipts: ${err.message}` };
    }
  }

  /** The contract's transaction and one built here from the raw signatures must be the same bytes. */
  async assemble(view, coin) {
    const { state } = this;
    const c = state.cosigned;
    const v = state.vault;
    const script = fromHex(v.script);
    const fromContract = await this.near.view(this.cfg.contract, 'final_tx', { vault: v.id, request: c.request });
    if (!fromContract) throw new Fail('cosign', 'final_tx_missing', 'a Signed request has no final transaction');
    const mpcRs = fromHex(view.sigs[0]);
    const value = { txid: coin.txid, vout: coin.vout, value: coin.value };
    const contractHex = this.cfg.tamperFinalTx ? this.cfg.tamperFinalTx(fromContract) : fromContract;
    const checked = checkCosigned({ rawHex: contractHex, coin: value, to: fromHex(c.to), amount: c.amount, script, km: fromHex(v.k_m), ku: fromHex(v.k_u) });
    if (checked.problem) throw new Fail('cosign', checked.problem.reason, `contract's final_tx: ${checked.problem.detail}`);
    const built = assembleCosigned({ coin: value, to: fromHex(c.to), amount: c.amount, mpcRs, halfRs: fromHex(c.half_sig), script });
    if (built !== contractHex) throw new Fail('cosign', 'final_tx_mismatch', 'the contract and this tool built different bytes');
    c.signer_s_was_high = isHighS(mpcRs);
    c.local_checks = checked.facts;
    c.consensus = this.consensus('cosign', built, v.spk, [coin.value]);
    c.raw = built;
    c.txid = checked.facts.txid;
    this.save();
    log(`  assembled ${c.txid}, ${checked.facts.vsize} vB, strict DER and low S on both signatures, consensus accepts it`);
  }

  /** Sends the spend and reads the answer. "Already" counts as sent: waitMined and the read-back decide. */
  async sendCosigned() {
    const { esplora, state } = this;
    const c = state.cosigned;
    const answer = await esplora.broadcast(c.raw, c.txid);
    this.stop('crash:cosigned-sent');
    c.broadcast_answer = { http_status: answer.status, text: answer.text };
    if (answer.kind === 'accepted' || answer.refusal === 'already') return;
    this.save();
    // DER and low S passed, consensus passed, and a node's script check still says no. That is the kill line.
    if (answer.refusal === 'script') throw new Fail('cosign', 'cosigned_rejected_by_node', answer.text, { kill: true });
    // A coin gone or a fee too low says nothing about how the spend was built, and neither does the rest.
    if (answer.refusal === 'inputs_gone') throw new Fail('cosign', 'coin_spent_elsewhere', answer.text, { resumable: true });
    if (/fee/i.test(answer.text)) throw new Fail('cosign', 'fee_refused_by_node', answer.text, { resumable: true });
    throw new Fail('cosign', 'cosigned_refused_not_script', answer.text, { resumable: true });
  }

  async broadcastCosigned(coin) {
    const { esplora, state } = this;
    const c = state.cosigned;
    if (!c.broadcast) {
      if (!(await esplora.tx(c.txid))) await this.sendCosigned();
      c.broadcast = true;
      this.save();
      log(`  co-signed spend ${c.txid} sent`);
    }
    this.stop('cosign:broadcast');
    const status = await this.waitMined('cosign', c.txid, { resend: () => this.sendCosigned() });
    c.mined_height = status.block_height;
    c.mined_block = status.block_hash;
    this.save();
    this.stop('cosign:mined');

    const { apiTx, hexBack, fresh, spend } = await this.readMined('cosign', c.txid, coin);
    const value = { txid: coin.txid, vout: coin.vout, value: coin.value };
    const witnessHex = witnessHexOf(c.raw);
    const bad = checkReadback({ apiTx, status: fresh, hexBack, rawHex: c.raw, id: c.txid, coin: value, toHexSpk: c.to, amount: c.amount, sequence: 0xfffffffd, witnessHex });
    if (bad) throw new Fail('cosign', bad.reason, bad.detail);
    const back = checkCosigned({ rawHex: hexBack, coin: value, to: fromHex(c.to), amount: c.amount, script: fromHex(state.vault.script), km: fromHex(state.vault.k_m), ku: fromHex(state.vault.k_u) });
    if (back.problem) throw new Fail('cosign', back.problem.reason, `as mined: ${back.problem.detail}`);
    c.readback = {
      txid: apiTx.txid, height: fresh.block_height, block: fresh.block_hash, input: `${value.txid}:${value.vout}`, sequence: apiTx.vin[0].sequence,
      output_script: apiTx.vout[0].scriptpubkey, output_value: apiTx.vout[0].value, fee: coin.value - apiTx.vout[0].value, api_fee: apiTx.fee ?? null,
      signatures: back.facts.signatures, vsize: back.facts.vsize, coin_spent_by: spend.txid,
      confirmations_at_readback: (await esplora.tip()) - fresh.block_height + 1,
    };
    if (spend.txid !== c.txid) throw new Fail('cosign', 'readback_outspend', `the coin reads as spent by ${spend.txid}`);
    this.save();
    log(`  mined at ${fresh.block_height}, read back: txid, input, output, DER and low S on both signatures`);
  }

  // -------------------------------------------------------------- escape

  /** The public half of the recovery file, and a refusal with its own reason if it is not this vault's. */
  readRecovery(step) {
    let file;
    try {
      file = parseRecovery(readFileSync(this.recoveryPath, 'utf8'));
    } catch (err) {
      const code = err instanceof RecoveryError ? err.code : 'unreadable';
      throw new Fail(step, 'recovery_file_refused', `${code}: ${err.message}`, { resumable: true });
    }
    if (file.address !== this.state.vault.address && !this.cfg.skipRecoveryCheck) {
      throw new Fail(step, 'wrong_recovery_file', 'this file is for another vault', { resumable: true });
    }
    this.secrets.push(toHex(file.cold));
    return file;
  }

  /** The same tool a user would run, as a subprocess, with nothing but the file and the list. */
  runEscapeTool(step, coins, fee) {
    const { workDir, state } = this;
    mkdirSync(workDir, { recursive: true });
    const listPath = join(workDir, `utxos-${coins[0].txid.slice(0, 8)}.json`);
    writeFileSync(listPath, JSON.stringify(coins));
    const r = spawnSync(process.execPath, [join(HERE, 'escape.mjs'), '--recovery', this.recoveryPath, '--utxos', listPath, '--to', this.dispenser.address, '--fee', String(fee)], {
      encoding: 'utf8', cwd: workDir, env: { PATH: process.env.PATH ?? '' },
    });
    const out = `${r.stdout ?? ''}${r.stderr ?? ''}`;
    for (const secret of this.secrets) {
      if (out.includes(secret)) throw new Fail(step, 'escape_tool_printed_a_secret', 'the tool wrote a secret to its output');
    }
    if (r.status !== 0) throw new Fail(step, 'escape_tool_refused', out.trim(), { resumable: true });
    const raw = r.stdout.match(/^hex\s+([0-9a-f]+)$/m)?.[1];
    const id = r.stdout.match(/^txid\s+([0-9a-f]{64})$/m)?.[1];
    if (!raw || !id) throw new Fail(step, 'escape_tool_refused', 'no transaction in its output');
    return { raw, txid: id, argv: ['--recovery FILE', '--utxos FILE', `--to ${this.dispenser.address}`, `--fee ${fee}`], network: state.network };
  }

  checkEscapeTx(step, raw, coin, amount) {
    const v = this.state.vault;
    const value = { txid: coin.txid, vout: coin.vout, value: coin.value };
    const checked = checkEscape({ rawHex: raw, coin: value, to: this.dispenser.spk, amount, script: fromHex(v.script), csv: v.csv, ke: fromHex(v.k_e_leaf) });
    if (checked.problem) throw new Fail(step, checked.problem.reason, checked.problem.detail);
    return { facts: checked.facts, consensus: this.consensus(step, raw, v.spk, [coin.value]) };
  }

  async stageEscape() {
    const e = this.state.escape;
    if (e.readback) return;
    if (!e.early) await this.earlyRefusal();
    await this.matureEscape();
  }

  async earlyRefusal() {
    const { esplora, state, cfg } = this;
    const e = state.escape;
    const v = state.vault;
    for (let tries = 0; tries < FRESH_COIN_TRIES; tries += 1) {
      const coin = await this.ensureCoin('escape');
      const mature = matureTip(coin.height, v.csv);
      const file = this.readRecovery('escape');
      const list = await esplora.utxos(file.address);
      const entry = list.find((u) => u.txid === coin.txid && u.vout === coin.vout);
      if (!entry && !cfg.skipRecoveryCheck) throw new Fail('escape', 'escape_coin_missing', 'the coin is not in the Esplora list for this address', { resumable: true });
      if (!e.raw) {
        const fee = escapeVsize({ coins: [coin], to: this.dispenser.spk, script: fromHex(v.script), csv: v.csv }) * cfg.feeRate;
        if (fee > cfg.feeCeiling) throw new Fail('escape', 'fee_over_ceiling', `would pay ${fee} sats, over ${cfg.feeCeiling}`);
        const listed = entry ?? { txid: coin.txid, vout: coin.vout, value: coin.value };
        const tool = this.runEscapeTool('escape', [listed], fee);
        const amount = coin.value - fee;
        const { facts, consensus } = this.checkEscapeTx('escape', tool.raw, coin, amount);
        Object.assign(e, { raw: tool.raw, txid: tool.txid, coin: `${coin.txid}:${coin.vout}`, coin_height: coin.height, fee, amount, local_checks: facts, consensus, tool: tool.argv, utxo_list_entries: 1 });
        this.save();
        log(`  escape.mjs built ${tool.txid} from the recovery file and the list`);
      }
      this.stop('escape:built');

      const tipBefore = await esplora.tip();
      const aged = async () => {
        if ((await esplora.tip()) >= mature) throw new CoinAged();
      };
      let answer;
      try {
        await aged();
        answer = await esplora.broadcast(e.raw, e.txid, { guard: aged });
      } catch (err) {
        if (!(err instanceof CoinAged)) throw err;
        // Too old to prove anything. It stays in the vault for the last step, and a new coin takes over.
        log(`  coin ${coin.txid} matured before the early try, funding a fresh one`);
        coin.role = 'aged';
        for (const key of ['raw', 'txid', 'coin', 'coin_height', 'fee', 'amount', 'local_checks', 'consensus', 'tool', 'utxo_list_entries']) delete e[key];
        this.save();
        continue;
      }
      const tipAfter = await esplora.tip();
      e.early = {
        http_status: answer.status, text: answer.text, refusal: answer.kind === 'accepted' ? 'none: accepted' : answer.refusal,
        tip_before: tipBefore, tip_after: tipAfter, coin_height: coin.height, coin_confirmations: tipBefore - coin.height + 1, csv: v.csv, mature_at_tip: mature,
      };
      this.save();
      if (answer.kind === 'accepted') throw new Fail('escape', 'early_escape_accepted', `accepted ${mature - tipBefore} blocks before maturity`);
      if (answer.refusal !== 'bip68') throw new Fail('escape', 'early_refusal_wrong_text', answer.text);
      log(`  refused early, at ${e.early.coin_confirmations} of ${v.csv} confirmations: ${answer.text}`);
      this.stop('escape:refused');
      return;
    }
    throw new Fail('escape', 'no_young_coin', `each of ${FRESH_COIN_TRIES} coins matured before the early try`, { resumable: true });
  }

  async matureEscape() {
    const { esplora, state, cfg } = this;
    const e = state.escape;
    const v = state.vault;
    const coin = state.coins.find((c) => c.role === 'escape');
    const mature = matureTip(coin.height, v.csv);
    if (!e.broadcast) {
      let tip = await esplora.tip();
      if (tip < mature) log(`  waiting for tip ${mature}, now ${tip}`);
      const deadline = Date.now() + cfg.mineTimeoutSec * 1000;
      while (tip < mature) {
        if (Date.now() > deadline) throw new Fail('escape', 'not_mined_in_time', `the tip did not reach ${mature}`, { resumable: true });
        await sleep(cfg.pollMs);
        tip = await esplora.tip();
      }
      this.stop('escape:matured');

      const seen = await esplora.tx(e.txid);
      if (!seen) {
        // Same inputs give the same signature, so a rebuild must give the same bytes. Sent as recorded.
        const file = this.readRecovery('escape');
        if (!e.csv_control) {
          const short = escapeOneShort({ file, coin: { txid: coin.txid, vout: coin.vout, value: coin.value }, to: this.dispenser.spk, amount: e.amount });
          e.csv_control = await this.control('escape', 'csv_control', 'crash:csv-control-sent', short.raw, short.id, /Locktime requirement/i);
          e.csv_control.sequence = v.csv - 1;
          e.csv_control.tip = tip;
          this.save();
          log(`  on the mature coin, signed for nSequence ${v.csv - 1}, refused: ${e.csv_control.text}`);
        }
        this.stop('escape:csv-control');
        const list = await esplora.utxos(file.address);
        const entry = list.find((u) => u.txid === coin.txid && u.vout === coin.vout);
        if (!entry) throw new Fail('escape', 'escape_coin_gone', 'the coin is not in the UTXO list and the escape was not found', { resumable: true });
        const again = this.runEscapeTool('escape', [entry], e.fee);
        e.rebuilt_identical = again.raw === e.raw;
        if (!e.rebuilt_identical) throw new Fail('escape', 'escape_not_identical', 'the tool built different bytes from the same file and list');
        e.tip_at_broadcast = tip;
        for (let tries = 0; ; tries += 1) {
          const answer = await esplora.broadcast(e.raw, e.txid);
          this.stop('crash:escape-sent');
          e.mature_answer = { http_status: answer.status, text: answer.text };
          if (answer.kind === 'accepted' || answer.refusal === 'already') break;
          // Only a script refusal says the escape itself is wrong.
          if (answer.refusal === 'script') throw new Fail('escape', 'escape_rejected', answer.text);
          if (answer.refusal !== 'bip68') throw new Fail('escape', 'escape_refused_not_script', answer.text, { resumable: true });
          // A relay can lag its own tip by a block. Past a few blocks that is no longer the reason.
          if (tries >= MATURE_RETRIES) throw new Fail('escape', 'escape_refused_after_maturity', `still ${answer.text} ${tries} blocks past maturity`);
          await this.waitNextBlock('escape');
        }
      }
      e.broadcast = true;
      this.save();
      log(`  escape ${e.txid} sent`);
    }
    this.stop('escape:broadcast');
    const status = await this.waitMined('escape', e.txid, {
      resend: async () => {
        const answer = await esplora.broadcast(e.raw, e.txid);
        if (answer.refusal === 'script') throw new Fail('escape', 'escape_rejected', answer.text);
      },
    });
    e.mined_height = status.block_height;
    e.mined_block = status.block_hash;
    this.save();
    this.stop('escape:mined');

    const { apiTx, hexBack, fresh, spend } = await this.readMined('escape', e.txid, coin);
    const value = { txid: coin.txid, vout: coin.vout, value: coin.value };
    const bad = checkReadback({ apiTx, status: fresh, hexBack, rawHex: e.raw, id: e.txid, coin: value, toHexSpk: toHex(this.dispenser.spk), amount: e.amount, sequence: v.csv, witnessHex: witnessHexOf(e.raw) });
    if (bad) throw new Fail('escape', bad.reason, bad.detail);
    const age = fresh.block_height - coin.height;
    if (age < v.csv) throw new Fail('escape', 'csv_not_enforced', `mined ${age} blocks after the coin, under a CSV of ${v.csv}`);
    const back = checkEscape({ rawHex: hexBack, coin: value, to: this.dispenser.spk, amount: e.amount, script: fromHex(v.script), csv: v.csv, ke: fromHex(v.k_e_leaf) });
    if (back.problem) throw new Fail('escape', back.problem.reason, `as mined: ${back.problem.detail}`);
    if (spend.txid !== e.txid) throw new Fail('escape', 'readback_outspend', `the coin reads as spent by ${spend.txid}`);
    e.readback = {
      txid: apiTx.txid, height: fresh.block_height, block: fresh.block_hash, input: `${value.txid}:${value.vout}`, sequence: apiTx.vin[0].sequence,
      output_script: apiTx.vout[0].scriptpubkey, output_value: apiTx.vout[0].value, fee: coin.value - apiTx.vout[0].value, api_fee: apiTx.fee ?? null,
      blocks_after_coin: age, signatures: back.facts.signatures, vsize: back.facts.vsize, coin_spent_by: spend.txid,
      confirmations_at_readback: (await esplora.tip()) - fresh.block_height + 1,
    };
    this.save();
    log(`  mined at ${fresh.block_height}, ${age} blocks after the coin, read back`);
  }

  // -------------------------------------------------------------- browser

  async stageBrowser() {
    const { state, esplora } = this;
    if (state.browser) return;
    let measured;
    try {
      measured = await esplora.preflight(ORIGIN);
    } catch (err) {
      measured = { origin: ORIGIN, error: err.message, preflight_allows_post: null };
    }
    state.browser = {
      ...measured,
      method: this.cfg.regtest ? 'OPTIONS from this script, against the local stand-in: says nothing about a real relay' : 'OPTIONS from this script, with an Origin header',
      real_browser_post_made: false,
      statement: 'No browser made a real POST during this run. The headers say a browser would be let through, and only a real browser POST can show that it works. The gate stays incomplete until one is recorded.',
    };
    this.save();
    log(`  CORS preflight: allow-origin ${measured.allow_origin ?? 'none'}, allow-methods ${measured.allow_methods ?? 'none'}. No real browser POST was made.`);
    this.stop('browser:measured');
  }

  /** The last clause of the gate is a person's. The mined escape is safe to POST: it can pay nothing again. */
  printBrowserStep() {
    const { state, cfg } = this;
    if (state.browser?.real_post || !state.escape.readback) return;
    const path = join(cfg.stateDir, 'browser-step.txt');
    const js = `fetch(${JSON.stringify(`${cfg.esplora}/tx`)},{method:'POST',headers:{'content-type':'text/plain'},body:${JSON.stringify(state.escape.raw)}})`
      + '.then(async(r)=>({http_status:r.status,text:await r.text()})).catch((e)=>({error:String(e)}))'
      + `.then((o)=>console.log(JSON.stringify({...o,txid:${JSON.stringify(state.escape.txid)},origin:location.origin,at:new Date().toISOString()})))`;
    writeFileSync(path, [
      'G2 is not complete until a browser has tried the POST. This sends the escape that is already mined, so it can pay nothing again.',
      '1. Paste this into a browser console, on any page whose rules let a page fetch other hosts:',
      '',
      js,
      '',
      '2. Save the one line it prints to a file, and run: node tools/g2.mjs --record-browser FILE',
      '',
    ].join('\n'), { mode: 0o600 });
    log(`G2 IS NOT COMPLETE: no browser POST is on record. The steps are in ${scrub(path)}`);
  }

  // -------------------------------------------------------------- what is left

  async stageLeftovers() {
    const { esplora, state, cfg } = this;
    const v = state.vault;
    state.leftovers ??= { returned: [] };
    const l = state.leftovers;
    const list = await esplora.utxos(v.address);
    l.listed_at_start ??= list.map((u) => ({ coin: `${u.txid}:${u.vout}`, value: u.value, height: u.status?.block_height ?? null }));
    this.save();
    this.stop('leftovers:listed');

    if (l.pending) await this.finishReturn();
    let coins = await esplora.utxos(v.address);
    if (coins.length > 0) {
      log(`  ${coins.length} coin(s) left in the vault, ${coins.reduce((s, c) => s + c.value, 0)} sats. Returning them by the escape`);
      // Wait for a coin still in flight, then for the youngest to mature.
      const deadline = Date.now() + cfg.mineTimeoutSec * 1000;
      for (;;) {
        coins = await esplora.utxos(v.address);
        const tip = await esplora.tip();
        if (coins.every((c) => c.status?.confirmed && tip >= matureTip(c.status.block_height, v.csv))) break;
        if (Date.now() > deadline) throw new Fail('leftovers', 'not_mined_in_time', 'coins did not mature', { resumable: true });
        await sleep(cfg.pollMs);
      }
      const fee = coins.length ? escapeVsize({ coins, to: this.dispenser.spk, script: fromHex(v.script), csv: v.csv }) * cfg.feeRate : 0;
      const total = coins.reduce((s, c) => s + c.value, 0);
      if (coins.length === 0) {
        l.note = 'the coins were spent while waiting';
      } else if (total - fee < 546) {
        l.note = `${total} sats left, too little to pay the fee and clear dust`;
      } else {
        this.readRecovery('leftovers');
        const tool = this.runEscapeTool('leftovers', coins, fee);
        const spk = toHex(this.dispenser.spk);
        const parsed = parseTx(fromHex(tool.raw));
        if (parsed.outputs.length !== 1 || toHex(parsed.outputs[0].spk) !== spk || Number(parsed.outputs[0].value) !== total - fee) throw new Fail('leftovers', 'wrong_output', 'the tool built something else');
        l.pending = { raw: tool.raw, txid: tool.txid, coins: coins.map((c) => `${c.txid}:${c.vout}`), value: total, fee };
        this.consensus('leftovers', tool.raw, v.spk, coins.map((c) => c.value));
        this.save();
        this.stop('leftovers:built');
        await this.finishReturn();
      }
    }
    const after = await esplora.utxos(v.address);
    l.left_sats = after.reduce((s, c) => s + c.value, 0);
    l.left_coins = after.map((c) => `${c.txid}:${c.vout}`);
    for (const coin of state.coins.filter((c) => c.broadcast)) {
      const spend = await esplora.outspend(coin.txid, coin.vout);
      coin.spent_by = spend?.txid ?? null;
    }
    this.save();
  }

  async finishReturn() {
    const { esplora, state, cfg } = this;
    const l = state.leftovers;
    const p = l.pending;
    if (!(await esplora.tx(p.txid))) {
      const answer = await esplora.broadcast(p.raw, p.txid);
      if (answer.kind !== 'accepted' && answer.refusal !== 'already') {
        // Its coins went some other way. Holding on to it would block every later try.
        const list = await esplora.utxos(state.vault.address);
        if (!p.coins.every((name) => list.some((u) => `${u.txid}:${u.vout}` === name))) {
          l.note = `a built return was dropped: its coins were spent some other way (${answer.text})`;
          delete l.pending;
          this.save();
          return;
        }
        throw new Fail('leftovers', 'return_rejected', answer.text, { resumable: true });
      }
    }
    if (cfg.returnCoins && !state.done) state.coins_returned_early = true;
    this.save();
    this.stop('leftovers:broadcast');
    const status = await this.waitMined('leftovers', p.txid, { resend: () => esplora.broadcast(p.raw, p.txid) });
    l.returned.push({ txid: p.txid, coins: p.coins, sats: p.value, fee: p.fee, height: status.block_height, path: 'escape' });
    delete l.pending;
    this.save();
    log(`  returned ${p.value - p.fee} sats to the dispenser in ${p.txid}`);
  }

  // -------------------------------------------------------------- report

  lines() {
    const { state } = this;
    const c = state.cosigned;
    const e = state.escape;
    return [
      { name: 'cosigned_mined_and_read_back', pass: Boolean(c.readback) },
      { name: 'cosigned_without_ku_refused_by_script', pass: c.ku_control?.refusal === 'script' },
      { name: 'escape_refused_before_maturity', pass: e.early?.refusal === 'bip68' },
      { name: 'escape_one_short_refused_by_script_after_maturity', pass: e.csv_control?.refusal === 'script' },
      { name: 'escape_mined_after_maturity_and_read_back', pass: Boolean(e.readback) },
      { name: 'browser_post', pass: null, note: !state.browser ? 'not measured' : state.browser.real_post ? `tried, ${state.browser.real_post.outcome}` : `allow-origin ${state.browser.allow_origin ?? 'none'}. No real browser POST on record, so the gate is not complete.` },
      { name: 'coins_returned', pass: null, note: state.leftovers ? `${state.leftovers.left_sats ?? 'unknown'} sats left in the vault` : 'not reached' },
    ];
  }

  proofOf() {
    const { state, cfg, facts } = this;
    const lines = this.lines();
    const passed = lines.every((l) => l.pass !== false) && !state.failed;
    const missing = [
      ...(passed && state.done ? [] : ['the on-chain lines']),
      ...(state.browser?.real_post ? [] : ['a browser POST']),
    ];
    return {
      schema: 'undo-g2-v1',
      label: cfg.label,
      gate: cfg.regtest ? 'not a gate result: regtest, a local NEAR node and a mock signer' : 'G2',
      ...(facts ?? state.facts),
      csv_blocks: state.csv,
      fee_rate_sat_vb: state.fee_rate,
      passkey: '[software authenticator]: a real phone is G3',
      vault: state.vault && Object.fromEntries(Object.entries(state.vault).filter(([k]) => k !== 'active')),
      coins: state.coins.map(({ raw, ...coin }) => ({ ...coin, raw_bytes: raw.length / 2, funding_tx_hex: raw })),
      cosigned: state.cosigned,
      escape: state.escape,
      browser: state.browser,
      leftovers: state.leftovers,
      summary: {
        lines,
        // The chain's part only. gate_complete says whether the whole gate is done.
        pass: passed,
        finished: Boolean(state.done),
        gate_complete: missing.length === 0,
        gate_missing: missing,
        failure: state.failed,
        return_failure: state.return_failure,
        kill_condition_met: Boolean(state.failed?.kill),
        earlier_stops: state.earlier_failures,
        relay_answers_with_no_information: state.relay_transient,
        transactions_sent_again_after_being_lost: state.resent,
      },
    };
  }

  printCoins() {
    const { state } = this;
    log('Coins:');
    for (const c of state.coins) {
      log(`  ${c.role.padEnd(16)} ${c.txid}:${c.vout} ${c.value} sats, height ${c.height ?? 'unconfirmed'}, ${c.spent_by ? `spent by ${c.spent_by}` : 'not read as spent'}`);
    }
    const l = state.leftovers;
    if (l) log(`  left in the vault: ${l.left_sats ?? 'unknown'} sats. Returned by the escape: ${l.returned.length}${l.note ? `. ${l.note}` : ''}`);
    else if (state.vault) log(`  the vault was not read for what is left. Return coins with: node tools/g2.mjs --live --return-coins`);
  }

  recordFailure(err) {
    const { state, cfg } = this;
    const failure = { step: err.step, reason: err.reason, detail: err.detail, resumable: err.resumable, kill: err.kill, at: new Date().toISOString() };
    // A return that hit a relay error says nothing about the gate, so it leaves the run's verdict alone.
    if (cfg.returnCoins) state.return_failure = failure;
    else state.failed = failure;
    state.earlier_failures ??= [];
    state.earlier_failures.push({ step: err.step, reason: err.reason, detail: err.detail, at: failure.at });
    state.relay_transient = (state.relay_transient ?? 0) + this.esplora.transient;
    this.esplora.transient = 0;
    this.save();
    this.writeProof();
    log(`FAIL ${err.reason} at ${err.step}: ${err.detail}`);
    if (err.kill) log('This is G2\'s kill line: a correctly built co-signed spend, after DER and low-S checks, was not accepted.');
    log(err.resumable ? 'Fix the cause and run again: it resumes from here.' : 'Not resumable: this says something about the transaction, the keys or the node.');
  }

  /** Runs every stage in order, each one safe to repeat. */
  async run() {
    const { state, cfg } = this;
    const stages = cfg.returnCoins
      ? [['leftovers', () => this.stageLeftovers()]]
      : [
          ['vault', () => this.stageVault()],
          ['cosign', () => this.stageCosigned()],
          ['escape', () => this.stageEscape()],
          ['browser', () => this.stageBrowser()],
          ['leftovers', () => this.stageLeftovers()],
        ];
    if (state.failed && !state.failed.resumable && !cfg.returnCoins) {
      log(`This run already failed: ${state.failed.reason} at ${state.failed.step}: ${state.failed.detail}`);
      this.writeProof();
      this.printCoins();
      return 1;
    }
    // The coins this run was going to use have gone home, so it cannot carry on from here.
    if (state.coins_returned_early && !cfg.returnCoins) {
      log('This run\'s coins were returned with --return-coins. Use --new-run to start another.');
      this.writeProof();
      this.printCoins();
      return 1;
    }
    if (!cfg.returnCoins) state.failed = null;
    this.save();
    try {
      for (const [name, stage] of stages) {
        log(`Stage ${name}`);
        try {
          await stage();
        } catch (err) {
          if (err instanceof Fail) throw err;
          if (err instanceof RelayError) throw new Fail(name, 'relay_unavailable', err.message, { resumable: true });
          if (err instanceof RpcError) throw new Fail(name, 'near_rpc_error', err.message, { resumable: true });
          throw new Fail(name, 'stopped_on_error', err.message, { resumable: true });
        }
        this.writeProof();
      }
    } catch (err) {
      this.recordFailure(err);
      this.printCoins();
      return 1;
    }
    state.relay_transient = (state.relay_transient ?? 0) + this.esplora.transient;
    this.esplora.transient = 0;
    if (!cfg.returnCoins) state.done = true;
    delete state.return_failure;
    this.save();
    this.writeProof();
    this.printCoins();
    const lines = this.lines();
    for (const l of lines) log(`${l.pass === null ? 'MEASURED' : l.pass ? 'PASS' : 'FAIL'} ${l.name}${l.note ? `: ${l.note}` : ''} [${cfg.label}]`);
    if (cfg.returnCoins) return state.leftovers.left_sats === 0 ? 0 : 1;
    for (const c of [state.cosigned.ku_control, state.escape.csv_control]) {
      if (!c?.names_the_check) log(`NOTE a control was refused by the script in words this driver does not know, so read them: ${c?.text}`);
    }
    this.printBrowserStep();
    return lines.every((l) => l.pass !== false) ? 0 : 1;
  }
}

// ---------------------------------------------------------------- plan

async function printPlan({ cfg, facts, instance, dispenser, dispenserProblem, near, state, strayKeys, payerProblem, relayProblem, signerOk, codeOk, instanceProblem, plan, need, utxos, estimates, preflight }) {
  const balance = async (name) => Number((await near.account(name))?.amount ?? 0) / 1e24;
  const payerNear = await balance(cfg.payer);
  const relayNear = await balance(cfg.relay);
  const confirmed = (utxos ?? []).filter((u) => u.status?.confirmed).reduce((s, u) => s + u.value, 0);
  const allSats = (utxos ?? []).reduce((s, u) => s + u.value, 0);
  const lost = cfg.feeRate * (plan.sizes.funding * 2 + plan.sizes.cosigned + plan.sizes.escape);
  const unlockMin = instance ? Math.round(instance.policy.t_new_unguarded_ms / 60_000) : '?';
  log('');
  log('PLAN ONLY. Nothing was sent. Add --live to run it.');
  log(`  NEAR             ${facts.chain_id}, protocol ${facts.protocol_version}, signer ${cfg.signer} ${facts.signer.version ?? ''}, K_m view ${signerOk ? 'answered' : 'DID NOT ANSWER'}`);
  log(`  contract         ${cfg.contract} ${codeOk ? '(this wasm\'s code)' : '(OTHER CODE OR NONE)'}${instanceProblem ? `, ${instanceProblem}` : ''}`);
  log(`  Bitcoin          ${cfg.network} at ${cfg.esplora}, tip ${facts.bitcoin.tip_at_start}, next-block fee ${estimates?.['1'] ?? 'unknown'} sat/vB, this run pays ${cfg.feeRate}`);
  log(`  dispenser        ${dispenser ? `${dispenser.address}, ${confirmed} confirmed sats in ${(utxos ?? []).length} coins` : `NOT READY: ${dispenserProblem}`}`);
  log(`  payer            ${cfg.payer}: ${payerNear.toFixed(3)} NEAR, ${payerProblem ?? 'ed25519 key file present'}`);
  log(`  relay            ${cfg.relay}: ${relayNear.toFixed(3)} NEAR, ${relayProblem ?? 'ed25519 key file present'}`);
  log(`  consensus check  ${cfg.checkBin ? 'undo-tools-check found' : 'MISSING: set UNDO_TOOLS_CHECK_BIN'}`);
  log(`  CORS preflight   allow-origin ${preflight?.allow_origin ?? 'unknown'}, allow-methods ${preflight?.allow_methods ?? 'unknown'}. This was a read, not a browser POST`);
  log(`  state            ${strayKeys ? 'STRAY KEYS: a recovery or key file that no state file names. Use --return-coins, then --new-run' : state ? `exists: would resume${state.failed ? `, last stop ${state.failed.reason}` : ''}${state.done ? ', and it already finished' : ''}` : 'none: would start fresh'}`);
  log('');
  log('Would do, in order:');
  log(`  1. create and activate one vault on ${cfg.contract}: CSV ${state?.csv ?? cfg.csv} blocks, ${DEPOSIT_MILLI} milliNEAR credit, recovery file under the gitignored private/g2`);
  log(`  2. send ${cfg.coinSats} sats from the dispenser to the vault's P2WSH, about ${plan.fees.funding} sats fee, and wait for a confirmation`);
  log(`  3. propose from ${cfg.relay}, wait out the unlock (${unlockMin} min here: an address the vault does not know, no guard), execute at ${SIGN_TGAS} Tgas, wait for the real signature`);
  log('     assemble the witness here, compare with the contract\'s bytes, check strict DER, low S and consensus');
  log('     broadcast it with K_u\'s signature taken out: must be refused by the script, and pays nothing. Then broadcast the real one');
  log(`     to the dispenser, about ${plan.fees.cosigned} sats fee. Wait until mined, read back, check txid, input, output and both signatures`);
  log(`  4. send a second ${cfg.coinSats} sats to the vault, about ${plan.fees.funding} sats fee, wait for one confirmation`);
  log('     run tools/escape.mjs as a subprocess from the recovery file and an Esplora list. Broadcast while young: must be refused non-BIP68-final');
  log(`     wait ${state?.csv ?? cfg.csv} blocks. Broadcast an escape signed for nSequence ${(state?.csv ?? cfg.csv) - 1}: must be refused by the script, and pays nothing`);
  log(`     broadcast the same bytes as before, about ${plan.fees.escape} sats fee, wait until mined, read back`);
  log(`  5. CORS preflight with Origin ${ORIGIN}. The real browser POST is a separate step afterwards: until then the proof says gate_complete false`);
  log('  6. list what is left in the vault and send it back by the escape');
  log('');
  log(`Needs about ${need.sats} sats on hand (${lost} lost to fees, the rest comes back), ${need.payerNear.toFixed(3)} NEAR from the payer and ${need.relayNear.toFixed(3)} from the relay. Credit stays in the vault row.`);
  log(`About 20 minutes, most of it the unlock. Proof goes to proofs/g2.json.`);
  const short = [];
  if (!dispenser) short.push('dispenser');
  if (dispenser && allSats < need.sats) short.push(`sats: ${allSats} of ${need.sats}`);
  if (payerProblem || payerNear < need.payerNear) short.push('payer');
  if (relayProblem || relayNear < need.relayNear) short.push('relay');
  if (!signerOk) short.push('signer view');
  if (!codeOk) short.push('contract code');
  if (instanceProblem) short.push(instanceProblem);
  if (!cfg.checkBin) short.push('undo-tools-check');
  if (strayKeys) short.push('stray keys');
  log(short.length ? `NOT READY: ${short.join(', ')}.` : 'READY. It would go.');
  return short.length ? 4 : 0;
}

// ---------------------------------------------------------------- main

function credProblem(cfg, name) {
  if (!existsSync(credentialsPath(cfg.credNetwork, name))) return 'key file MISSING';
  try {
    loadCredentials(cfg.credNetwork, name);
    return null;
  } catch (err) {
    return `key file refused: ${err.message}`;
  }
}

function freshState(cfg) {
  return {
    schema: 'undo-g2-state-v1', regtest: cfg.regtest, label: cfg.label, network: cfg.network, contract: cfg.contract, signer: cfg.signer,
    csv: cfg.csv, coin_sats: cfg.coinSats, fee_rate: cfg.feeRate, started_at: new Date().toISOString(),
    vault: null, coins: [], cosigned: {}, escape: {}, browser: null, leftovers: null, failed: null, done: false,
  };
}

function loadState(dir) {
  const path = join(dir, 'state.json');
  return existsSync(path) ? JSON.parse(readFileSync(path, 'utf8')) : null;
}

/** This run's folder and each one --new-run moved aside, if they hold a recovery file. */
function runFolders(stateDir) {
  const parent = dirname(stateDir);
  const moved = !existsSync(parent) ? [] : readdirSync(parent)
    .filter((name) => name.startsWith(`${basename(stateDir)}-`) && /-[0-9]+$/.test(name))
    .sort()
    .map((name) => join(parent, name));
  return [stateDir, ...moved].filter((dir) => existsSync(join(dir, 'vault-recovery.json')));
}

/**
 * The way out needs what escape.mjs needs: a recovery file, a UTXO list, somewhere to send. So no NEAR
 * RPC, no wasm and no key file here, and no state file either if that went missing too.
 */
async function returnCoins({ cfg, base, esplora, dispenserPath, feeRateGiven }) {
  const genesis = (await esplora.genesis())?.trim();
  if (genesis !== base.genesis) throw new Refused('that Esplora is on another Bitcoin chain');
  let dispenser;
  try {
    dispenser = loadDispenser(dispenserPath, cfg.network);
  } catch (err) {
    throw new Refused(`dispenser: ${err.code === 'ENOENT' ? 'no dispenser file' : err.message}`);
  }
  const folders = runFolders(cfg.stateDir);
  if (folders.length === 0) throw new Refused('there is no recovery file in this run or an earlier one, so nothing to return');
  let worst = 0;
  for (const dir of folders) {
    let state = loadState(dir);
    if (state && state.regtest !== cfg.regtest) throw new Refused('that state file belongs to the other mode');
    let file;
    try {
      file = parseRecovery(readFileSync(join(dir, 'vault-recovery.json'), 'utf8'));
    } catch (err) {
      log(`FAIL a recovery file was refused, so its coins stay: ${err instanceof RecoveryError ? err.code : 'unreadable'}`);
      worst = 1;
      continue;
    }
    const current = dir === cfg.stateDir;
    log(`Run ${current ? 'in use' : `moved aside, ${basename(dir)}`}: vault ${file.address}`);
    if (!cfg.live) {
      const coins = await esplora.utxos(file.address);
      log(`  ${coins.reduce((sum, c) => sum + c.value, 0)} sats in ${coins.length} coins. Add --live to send them back`);
      continue;
    }
    // With no state file there is no run to report on, so the proof it would overwrite is left alone.
    const ownProof = current && state;
    state ??= { ...freshState(cfg), csv: file.csv };
    state.vault ??= { id: file.vaultId, csv: file.csv, script: toHex(file.script), spk: toHex(p2wshSpk(file.script)), address: file.address, active: false };
    const sub = { ...cfg, stateDir: dir, out: ownProof ? cfg.out : join(dir, 'proof-after-return.json'), feeRate: feeRateGiven ? cfg.feeRate : (state.fee_rate ?? cfg.feeRate) };
    const driver = new Driver({ cfg: sub, state, esplora, dispenser, facts: state.facts ?? { bitcoin: { network: cfg.network, genesis }, facts_note: 'this state file had no facts: read by a run that needs no NEAR RPC' } });
    driver.loadSecretsIfAny();
    takeLock(dir);
    worst = Math.max(worst, await driver.run());
  }
  return worst;
}

/** The gate's last clause. Reads a file, rewrites the proof, sends nothing. */
function recordBrowser({ file, stateDir, out, regtest, label }) {
  const state = loadState(stateDir);
  if (!state?.done) throw new Refused('this run has not finished, so there is nothing to add a browser POST to');
  if (state.regtest !== regtest) throw new Refused('that state file belongs to the other mode');
  let got;
  try {
    got = JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    throw new Refused('that file is not the one line the browser printed');
  }
  if (got?.txid !== state.escape.txid) throw new Refused('that POST was for another transaction');
  if (typeof got.at !== 'string' || typeof got.origin !== 'string') throw new Refused('that file is not the one line the browser printed');
  const blocked = typeof got.error === 'string';
  if (!blocked && (!Number.isInteger(got.http_status) || typeof got.text !== 'string')) throw new Refused('that file has neither an answer nor an error');
  const answered = blocked ? null : classifyBroadcast(got.http_status, got.text, got.txid);
  const outcome = blocked ? 'the browser could not make the request' : answered.kind === 'transient' ? 'the relay answered, not a node' : 'a node answered';
  state.browser ??= {};
  state.browser.real_browser_post_made = !blocked;
  state.browser.real_post = {
    outcome, origin: got.origin.slice(0, 200), at: got.at.slice(0, 40), sent: 'the escape already mined, which can pay nothing again', txid: got.txid,
    ...(blocked ? { error: got.error.slice(0, 200) } : { http_status: got.http_status, text: answered.text }),
    recorded_from: 'a browser console, by hand',
  };
  state.browser.statement = 'A browser tried the POST. The result is in real_post, as printed by that browser.';
  const driver = new Driver({ cfg: { stateDir, out, regtest, label }, state, facts: state.facts });
  driver.loadSecretsIfAny();
  driver.save();
  driver.writeProof();
  log(`Recorded: ${outcome}. The proof now says gate_complete ${driver.proofOf().summary.gate_complete}.`);
  return 0;
}

let ownRig = null;

async function main() {
  const a = parseArgs(process.argv.slice(2), {
    live: 'flag', regtest: 'flag', 'return-coins': 'flag', 'new-run': 'flag', 'list-stops': 'flag', 'record-browser': 'text',
    'coin-sats': 'int', csv: 'int', 'fee-rate': 'int', 'fee-ceiling': 'int', confirmations: 'int', 'sign-timeout-sec': 'int', 'mine-timeout-sec': 'int',
    dispenser: 'text', payer: 'text', relay: 'text', contract: 'text', esplora: 'text', rpc: 'text', wasm: 'text',
    rig: 'text', 'state-dir': 'text', out: 'text', 'test-stop-at': 'text', 'test-fault': 'text', 'poll-ms': 'int',
  });
  if (a['list-stops']) {
    log(JSON.stringify({ clean_run: STOPS, leftovers_only: LEFTOVER_STOPS, crash: CRASH_STOPS }));
    return 0;
  }
  if (a.live && a.regtest) throw new UsageError('--live and --regtest are opposites');
  const rehearsalFlags = ['rig', 'state-dir', 'out', 'test-stop-at', 'test-fault', 'poll-ms'];
  if (!a.regtest) {
    const used = rehearsalFlags.filter((f) => a[f] !== undefined);
    if (used.length) throw new UsageError(`--${used[0]} is for --regtest only`);
  }
  const stopAt = a['test-stop-at'];
  if (stopAt && ![...STOPS, ...LEFTOVER_STOPS, ...CRASH_STOPS].includes(stopAt)) throw new UsageError('no such stop point. See --list-stops');
  if (a.csv !== undefined && (a.csv < 1 || a.csv > 65535)) throw new UsageError('--csv must be 1 to 65535');
  // A coin this old when it is first read has matured already, so it could not show the refusal.
  if ((a.confirmations ?? 1) >= (a.csv ?? CSV)) throw new UsageError('--confirmations must be under --csv');
  const coinSats = a['coin-sats'] ?? COIN_SATS;
  if (coinSats < 2000) throw new UsageError('--coin-sats must be at least 2000');
  if (a['return-coins'] && a['new-run']) throw new UsageError('--return-coins handles every run already, so --new-run has no place beside it');
  if (a.regtest && a['return-coins'] && !a.rig) throw new UsageError('--return-coins in a rehearsal needs --rig: a new rig has no coins');

  const stateArg = a['state-dir'] && resolve(a['state-dir']);
  if (stateArg) {
    // Live state is never a rehearsal's to touch, and the proofs folder holds no state at all.
    if (isInside(stateArg, PRIVATE)) throw new UsageError('a rehearsal never keeps state under private/');
    if (isInside(stateArg, PROOFS)) throw new UsageError('a rehearsal never keeps state under proofs/');
    // A rig started here has a new chain and wipes the folder, so only a folder that is surely a rehearsal's.
    const wipeable = isInside(stateArg, REHEARSAL_ROOT) && realOf(stateArg) !== realOf(REHEARSAL_ROOT);
    if (!a.rig && existsSync(stateArg) && !wipeable) throw new UsageError('a rig started here needs a new --state-dir, or one under target/g2-rehearsal. Nothing was deleted');
  }

  if (a['record-browser']) {
    return recordBrowser({
      file: a['record-browser'],
      stateDir: stateArg ?? (a.regtest ? join(REHEARSAL_ROOT, 'state') : LIVE.stateDir),
      out: resolve(a.out ?? (a.regtest ? join(REHEARSAL_ROOT, 'g2-rehearsal.json') : LIVE.out)),
      regtest: Boolean(a.regtest),
      label: a.regtest ? REGTEST_LABEL : LIVE.label,
    });
  }

  let rigInfo = null;
  if (a.regtest) {
    if (a.rig) {
      rigInfo = JSON.parse(readFileSync(a.rig, 'utf8'));
    } else {
      const { startRig, RIG_FAULTS } = await import('./test/g2-rig.mjs');
      ownRig = await startRig({ log });
      rigInfo = ownRig.info;
      ownRig.startMiner();
      if (a['test-fault'] && RIG_FAULTS.includes(a['test-fault'])) ownRig.setFault(a['test-fault']);
    }
    process.env.NEAR_CREDENTIALS_DIR = rigInfo.creds;
  }
  const base = a.regtest
    ? {
        chain: null, network: 'regtest', rpc: [rigInfo.rpc], esplora: rigInfo.esplora, genesis: REGTEST_GENESIS, signer: rigInfo.signer, payer: rigInfo.payer, relay: rigInfo.relay,
        contract: rigInfo.contract, credNetwork: 'sandbox', stateDir: join(REHEARSAL_ROOT, 'state'), out: join(REHEARSAL_ROOT, 'g2-rehearsal.json'), label: REGTEST_LABEL,
      }
    : LIVE;

  const cfg = {
    regtest: Boolean(a.regtest),
    live: Boolean(a.live) || Boolean(a.regtest),
    returnCoins: Boolean(a['return-coins']),
    label: base.label,
    network: base.network,
    credNetwork: base.credNetwork,
    signer: base.signer,
    payer: a.payer ?? base.payer,
    relay: a.relay ?? base.relay,
    contract: a.contract ?? base.contract,
    esplora: a.esplora ?? base.esplora,
    rpc: a.rpc ? [a.rpc] : base.rpc,
    coinSats,
    csv: a.csv ?? CSV,
    feeRate: a['fee-rate'] ?? FEE_RATE,
    feeCeiling: a['fee-ceiling'] ?? FEE_CEILING,
    confirmations: a.confirmations ?? 1,
    signTimeoutSec: a['sign-timeout-sec'] ?? 300,
    mineTimeoutSec: a['mine-timeout-sec'] ?? 1800,
    pollMs: a['poll-ms'] ?? (a.regtest ? 200 : 5000),
    stateDir: resolve(a['state-dir'] ?? base.stateDir),
    out: resolve(a.out ?? base.out),
    stopAt,
    checkBin: toolsCheckBin(),
  };
  if (cfg.regtest && insideProofs(cfg.out)) throw new UsageError('a rehearsal never writes into proofs/');

  // ------------------------------------------------------------ refusals before any request
  checkEndpoints({ regtest: cfg.regtest, esplora: cfg.esplora, rpc: cfg.rpc });
  if (cfg.feeRate < 1) throw new Refused('fee_over_ceiling: a fee rate under 1 sat/vB would not relay');

  const fault = a['test-fault'];
  if (fault) {
    const { tamperFinalTx, RIG_FAULTS } = await import('./test/g2-rig.mjs');
    if (fault === 'tamper-final-high-s') cfg.tamperFinalTx = (hex) => tamperFinalTx(hex, 'high-s');
    else if (fault === 'tamper-final-bad-sig') cfg.tamperFinalTx = (hex) => tamperFinalTx(hex, 'bad-sig');
    else if (fault === 'skip-recovery-check') cfg.skipRecoveryCheck = true;
    else if (!RIG_FAULTS.includes(fault)) throw new UsageError('no such test fault');
  }

  const wasmPath = resolve(a.wasm ?? (cfg.regtest ? rigInfo.wasm : null) ?? join(process.env.CARGO_TARGET_DIR ?? join(REPO, 'target'), 'near', 'undo_vault.wasm'));
  const dispenserPath = a.dispenser ?? (cfg.regtest ? rigInfo.dispenser : join(homedir(), '.config', 'undo', 'dispenser-mutinynet.json'));

  if (cfg.returnCoins) {
    const esplora = new Esplora(cfg.esplora, cfg.regtest ? { backoffMs: 60, attempts: 8 } : {});
    const code = await returnCoins({ cfg, base, esplora, dispenserPath, feeRateGiven: a['fee-rate'] !== undefined });
    // An escape to the dispenser carries no name. The proof it rewrites gets the check, if there is a wasm to give it.
    if (!cfg.regtest && cfg.live && existsSync(wasmPath) && !outwardCheck(wasmPath)) {
      console.error('The proof does not pass the outward check. Do not push it.');
      return 1;
    }
    return code;
  }

  if (!existsSync(wasmPath)) throw new Refused('no wasm to compare with. Run scripts/build.sh first');
  const wasmBytes = readFileSync(wasmPath);
  const wasmHash = sha256(wasmBytes);
  const codeHash = base58Encode(wasmHash);

  const near = new Near(cfg.rpc);
  const esplora = new Esplora(cfg.esplora, cfg.regtest ? { backoffMs: 60, attempts: 8 } : {});

  // ------------------------------------------------------------ which chains
  const status = await near.status();
  if (status.chain_id === 'mainnet') throw new Refused('this driver never runs on mainnet');
  if (!cfg.regtest && status.chain_id !== base.chain) throw new Refused(`expected ${base.chain}, the RPC says ${status.chain_id}`);
  if (cfg.regtest && status.chain_id === 'testnet') throw new Refused('--regtest pointed at testnet');
  const genesis = (await esplora.genesis())?.trim();
  if (genesis !== base.genesis) throw new Refused('that Esplora is on another Bitcoin chain');

  const statePath = join(cfg.stateDir, 'state.json');
  if (!cfg.regtest && !isGitignored(join(cfg.stateDir, 'state.json'))) throw new Refused('the state folder is not gitignored');
  if (a['new-run'] && (existsSync(statePath) || holdsSecrets(cfg.stateDir))) {
    if (!cfg.live) throw new UsageError('--new-run needs --live or --regtest');
    takeLock(cfg.stateDir);
    const moved = `${cfg.stateDir}-${Date.now()}`;
    renameSync(cfg.stateDir, moved);
    log('Moved the earlier run aside, recovery file and all. Its coins are still its own.');
  }
  // A rig started here has a new chain, so an earlier state folder describes nothing on it.
  if (ownRig && existsSync(cfg.stateDir)) rmSync(cfg.stateDir, { recursive: true, force: true });
  const state = existsSync(statePath) ? JSON.parse(readFileSync(statePath, 'utf8')) : null;
  if (state && state.regtest !== cfg.regtest) throw new Refused('that state file belongs to the other mode');
  if (state && state.contract !== cfg.contract) throw new Refused('that state file is for another contract');
  // The cold key here may be the only way to coins, and starting fresh would need a new one.
  const strayKeys = !state?.vault && holdsSecrets(cfg.stateDir);
  if (strayKeys && cfg.live) throw new Refused('stray_keys: this folder holds a recovery or key file that no state file names, and coins may sit under it. Nothing was replaced. Use --return-coins, then --new-run');
  if (state?.vault && !existsSync(join(cfg.stateDir, 'vault-recovery.json'))) throw new Refused('the state file names a vault, and its recovery file is gone');
  // A flag that changes what this run measures cannot change halfway through it.
  if (state) {
    const differs = [['csv', a.csv, state.csv], ['coin-sats', a['coin-sats'], state.coin_sats], ['fee-rate', a['fee-rate'], state.fee_rate]].find(([, given, kept]) => given !== undefined && given !== kept);
    if (differs) throw new UsageError(`--${differs[0]} differs from this run's ${differs[2]}. Use --new-run for another value`);
    Object.assign(cfg, { csv: state.csv, coinSats: state.coin_sats, feeRate: state.fee_rate });
  }

  // ------------------------------------------------------------ what can be read before going
  const signerVersion = await near.view(cfg.signer, 'version').catch(() => null);
  const account = await near.account(cfg.contract);
  const codeOk = account?.code_hash === codeHash;
  const instance = codeOk ? await near.view(cfg.contract, 'instance') : null;
  const instanceProblem = !instance ? 'no instance'
    : instance.signer !== cfg.signer ? `this contract's signer is ${instance.signer}`
      : instance.network !== cfg.network ? `this contract is for ${instance.network}`
        : instance.preset !== 'TestCoin' ? `this contract's preset is ${instance.preset}` : null;
  const samplePath = `undo/${'0'.repeat(64)}`;
  const signerOk = await near.view(cfg.signer, 'derived_public_key', { path: samplePath, predecessor: cfg.contract, domain_id: 0 }).then(() => true).catch(() => false);

  let dispenser = null;
  let dispenserProblem = null;
  try {
    dispenser = loadDispenser(dispenserPath, cfg.network);
  } catch (err) {
    dispenserProblem = err.code === 'ENOENT' ? 'no dispenser file' : err.message;
  }
  const tip = await esplora.tip();
  const utxos = dispenser ? await esplora.utxos(dispenser.address) : null;
  const estimates = await esplora.feeEstimates().catch(() => null);

  const facts = {
    chain_id: status.chain_id,
    protocol_version: status.protocol_version,
    node_version: status.version?.version,
    wasm: { sha256: toHex(wasmHash), bytes: wasmBytes.length },
    contract: { account: cfg.contract, code_hash: account?.code_hash ?? null },
    signer: { account: cfg.signer, version: signerVersion },
    instance: instance && { preset: instance.preset, network: instance.network, sign_tgas_floor: instance.sign_tgas, callback_tgas: instance.callback_tgas, block_ms: instance.block_ms },
    bitcoin: { network: cfg.network, esplora: cfg.regtest ? 'a local stand-in over a real bitcoind' : cfg.esplora, genesis, tip_at_start: tip },
    outward_check: 'not run: a local node is not outward',
  };

  // ------------------------------------------------------------ outward check
  if (!cfg.regtest) {
    log('Outward check:');
    if (!outwardCheck(wasmPath)) {
      console.error('Refused: the outward check failed, so nothing was sent.');
      return 3;
    }
    facts.outward_check = 'passed before any write';
  }

  // ------------------------------------------------------------ money
  const planDispenser = dispenser ?? { spk: new Uint8Array(22) };
  const plan = plannedFees(cfg, planDispenser);
  const need = budget(cfg, state, plan.fees);
  refuseFees(cfg, plan);

  if (!cfg.live) {
    const preflight = await esplora.preflight(ORIGIN).catch(() => null);
    return printPlan({
      cfg, facts, instance, dispenser, dispenserProblem, near, state, strayKeys, plan, need, utxos, estimates, preflight, signerOk, codeOk, instanceProblem,
      payerProblem: credProblem(cfg, cfg.payer), relayProblem: credProblem(cfg, cfg.relay),
    });
  }

  if (!codeOk) throw new Refused('the contract holds other code than this wasm, or none');
  if (instanceProblem) throw new Refused(instanceProblem);
  if (!signerOk) throw new Refused('the signer does not answer derived_public_key');
  if (!dispenser) throw new Refused(`dispenser: ${dispenserProblem}`);
  if (!cfg.checkBin) throw new Refused('no undo-tools-check. Set UNDO_TOOLS_CHECK_BIN');

  const payer = loadCredentials(cfg.credNetwork, cfg.payer);
  const relay = loadCredentials(cfg.credNetwork, cfg.relay);
  // Unconfirmed counts here: after a stop the dispenser's change can still be on its way.
  const heldSats = (utxos ?? []).reduce((s, u) => s + u.value, 0);
  log(`Needs about ${need.sats} sats on hand, ${need.payerNear.toFixed(3)} NEAR from the payer, ${need.relayNear.toFixed(3)} NEAR from the relay.`);
  if (heldSats < need.sats) throw new Refused(`insufficient_sats: the dispenser holds ${heldSats} sats, this run needs about ${need.sats}. Nothing was sent.`);
  const held = async (name) => Number((await near.account(name))?.amount ?? 0) / 1e24;
  if ((await held(cfg.payer)) < need.payerNear) throw new Refused(`insufficient_near: ${cfg.payer} is short of ${need.payerNear.toFixed(3)} NEAR. Nothing was sent.`);
  if ((await held(cfg.relay)) < need.relayNear) throw new Refused(`insufficient_near: ${cfg.relay} is short of ${need.relayNear.toFixed(3)} NEAR. Nothing was sent.`);

  // ------------------------------------------------------------ run
  takeLock(cfg.stateDir);
  const client = new VaultClient({ near, contract: cfg.contract, signer: cfg.signer, instance, origin: ORIGIN, rpId: RP_ID });
  const driver = new Driver({ cfg, state: state ?? freshState(cfg), near, client, esplora, payer, relay, dispenser, facts });
  driver.loadSecretsIfAny();
  driver.state.facts = facts;
  if (driver.state.vault && !driver.seed) throw new Refused('the state file names a vault, and its key file is gone');
  if (driver.state.done) {
    log('This run already finished. Use --new-run to start another.');
    driver.writeProof();
    driver.printCoins();
    const lines = driver.lines();
    for (const l of lines) log(`${l.pass === null ? 'MEASURED' : l.pass ? 'PASS' : 'FAIL'} ${l.name} [${cfg.label}]`);
    driver.printBrowserStep();
    return lines.every((l) => l.pass !== false) ? 0 : 1;
  }
  log(`${cfg.regtest ? 'Rehearsal' : 'Live'}: contract ${cfg.contract}, signer ${cfg.signer}, ${cfg.network}, label ${cfg.label}`);
  let code = await driver.run();
  if (!cfg.regtest) {
    log('Outward check on the proof just written:');
    if (!outwardCheck(wasmPath)) {
      console.error('The proof does not pass the outward check. Do not push it. Nothing else was sent.');
      code = 1;
    }
  }
  log(cfg.regtest ? `Proof written to the rehearsal folder. Label: ${cfg.label}. This is a local rehearsal, not a G2 result.` : `Proof written to proofs/g2.json. Label: ${cfg.label}.`);
  return code;
}

main().finally(() => ownRig?.stop()).then((code) => process.exit(code ?? 0)).catch((err) => {
  if (err instanceof UsageError) {
    console.error(err.message);
    process.exit(2);
  }
  if (err instanceof Refused || err instanceof EndpointRefused) {
    console.error(`Refused: ${scrub(err.message)}`);
    process.exit(3);
  }
  console.error(`g2 stopped: ${scrub(err.message)}`);
  process.exit(1);
});

