#!/usr/bin/env node
// demo.sh: a self-test on a vault you just created, with no browser and no key of your own.
//
//   node tools/demo/demo.mjs [--config deploy/testnet.json]
//
// It walks the page's path through the relay the config names, with the page's own code from
// site/lib: a throwaway vault whose passkey is a software P-256 authenticator, run through the same
// WebAuthn parser the phone page uses; a proposal to a new address; a passkey cancel; then a send
// to a known address (the vault's own), executed after its wait, so the signer signs it. No coin
// moves and none is needed: the contract does not read Bitcoin, so the coins here are made up, and
// the signed transaction is judged by libbitcoinconsensus against that made-up coin.
//
// The relay pays the NEAR. If the relay is down, at its daily limit, or the config is a
// placeholder, this prints SKIP and points to the replay in ./verify.sh A and to tier B.
// Exit 0 when every line passed, 1 on any FAIL, 3 on SKIP.
import { existsSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { fromHex, toHex } from '../lib/bytes.mjs';
import { randomBytes, secp256k1 } from '../lib/crypto.mjs';
import { p2wpkhSpk } from '../lib/btc.mjs';
import { consensusVerdict, toolsCheck } from '../verify/rust.mjs';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const argv = process.argv.slice(2);
const flag = argv.indexOf('--config');
const configPath = resolve(flag >= 0 && argv[flag + 1] ? argv[flag + 1] : process.env.UNDO_CONFIG ?? join(REPO, 'deploy/testnet.json'));
const shown = configPath.startsWith(REPO) ? relative(REPO, configPath) : 'the config named by UNDO_CONFIG';
const POINTERS = 'Without the relay: ./verify.sh A replays the real testnet and Mutinynet hashes, ./verify.sh B runs the state machine and the Bitcoin consensus tests offline';

const started = Date.now();
const seconds = () => `${Math.round((Date.now() - started) / 1000)} s`;
let fails = 0;
const say = (status, id, label, text) => {
  if (status === 'FAIL') fails += 1;
  console.log(`${status} ${id} [${label}] ${text}`);
};
const skip = (why) => {
  console.log(`SKIP demo ${why}`);
  console.log(`     ${POINTERS}`);
  process.exit(3);
};
const sleep = (ms) => new Promise((r) => { setTimeout(r, ms); });
const mmss = (ms) => `${Math.floor(ms / 60_000)}:${String(Math.round((ms % 60_000) / 1000)).padStart(2, '0')}`;

let config;
try {
  config = JSON.parse(readFileSync(configPath, 'utf8'));
} catch (err) {
  console.log(`FAIL demo [static] cannot read ${shown}: ${err.message}`);
  process.exit(1);
}
if (config.placeholder) skip(`(not deployed) ${shown} holds a placeholder: there is no testnet contract or relay for this build yet, so nothing was sent`);

// The page's own library. It lives in site/lib, beside the pages that import it.
const lib = async (name) => import(pathToFileURL(join(REPO, 'site/lib', name)).href);
if (!existsSync(join(REPO, 'site/lib/webauthn.mjs'))) skip('(tree) site/lib is not in this tree, so the page\'s code cannot be run');
const { RelayClient } = await lib('relay-client.mjs');
const { NearReader } = await lib('near-read.mjs');
const { contractViews, derivedKey } = await lib('views.mjs');
const { softCredentials } = await lib('soft-authenticator.mjs');
const { createPasskey, getAssertion } = await lib('webauthn.mjs');
const { buildCreateArgs, buildPropose, cancelArgs, cancelDigest, newVaultKeys, rpIdHashOf, vaultIdOf } = await lib('intents.mjs');
const { solvePow } = await lib('pow.mjs');
const { sendEverything } = await lib('bitcoin.mjs');

const net = config.label;
const CSV = 6;

// ------------------------------------------------------------------ the relay first, and nothing sent if it is not there

const relay = new RelayClient({ relay: config.relay, funds: config.relay.replace(/\/relay$/, '/funds') });
const status = await relay.status();
if (!status.reachable) skip(`(relay) no answer from the relay in ${shown}: ${status.why}`);
if (!status.general?.up) skip(`(relay) the relay's general key is not taking new vaults now: ${status.general?.why}${status.general?.resets_at ? `, resets ${new Date(status.general.resets_at).toISOString()}` : ''}`);
if (!status.owner?.up) skip(`(relay) the relay's cancel key is not up now: ${status.owner?.why}`);

const reader = new NearReader({ urls: config.rpc, timeoutMs: 15_000 });
const views = contractViews(reader, config.contract);
let instance;
try {
  instance = await views.instance();
} catch (err) {
  skip(`(rpc) could not read ${config.contract}'s instance view: ${err.message}`);
}
if (!instance.origins.includes(config.site_origin)) {
  say('FAIL', 'demo', net, `${config.contract} does not list ${config.site_origin} among its origins (${instance.origins.join(', ')}): ${shown} is for another instance`);
  process.exit(1);
}
const chainNow = async () => (await reader.blockTime()).blockMs;

/** The relay answers once the transaction is included. The contract's state is what says what it did. */
async function until(what, fn, { timeoutMs = 60_000, everyMs = 700 } = {}) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    let out = null;
    try {
      out = await fn();
    } catch {
      // A lagging node. The deadline ends this.
    }
    if (out) return out;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await sleep(everyMs);
  }
}

async function main() {
  console.log(`== demo.sh: self-test on a vault you just created. NEAR ${config.network} contract ${config.contract}, relay ${config.relay}`);
  console.log(`   Passkey: [software authenticator] in this process, through site/lib/webauthn.mjs. Coins: made up, none moves. NEAR fees: the relay's.`);

  // 1. A throwaway vault, as the phone makes it.
  const soft = softCredentials({ secret: randomBytes(32), origin: config.site_origin, rpId: config.rp_id });
  const made = await createPasskey({ credentials: soft, rpId: config.rp_id, label: 'demo.sh throwaway' });
  const keys = newVaultKeys();
  const vaultHex = toHex(vaultIdOf({ contract: config.contract, keys, passkeyPub: made.pubkey, csv: CSV }));
  const km = await derivedKey(reader, { signer: instance.signer, domainId: instance.domain_id, contract: config.contract, vaultHex });
  const built = await buildCreateArgs({
    contract: config.contract, keys, passkeyPub: made.pubkey, rpIdHash: rpIdHashOf(config.rp_id), km, guard: status.relayAccount,
    policy: instance.policy, csv: CSV, expiresAt: (await chainNow()) + 30 * 60_000,
    assert: async (digest) => (await getAssertion({ credentials: soft, digest, rpId: config.rp_id, credentialId: made.credentialId })).args,
  });
  const pow = await solvePow(vaultHex, status.powBits);
  const created = await relay.call('create_vault', built.args, { pow });
  const vault = await until('the vault to read active', async () => {
    const v = await views.vault(vaultHex);
    return v?.active ? v : null;
  }, { timeoutMs: 45_000 });
  if (vault.k_m !== toHex(km)) throw new Error('the vault stores another K_m than the signer derives');
  say('PASS', 'demo-1', net, `vault ${vaultHex} created and active, NEAR ${config.network} tx ${created.hash}. Its K_m is the key ${instance.signer} derives for it; its Bitcoin address is ${vault.address}`);

  // 2. The stolen-key move: everything to a new address. It must wait, and the wait is the contract's.
  const script = fromHex(await views.script(vaultHex));
  const madeUpCoin = () => ({ txid: toHex(randomBytes(32)), vout: 0, value: 10_000 });
  const stranger = p2wpkhSpk(secp256k1.getPublicKey(randomBytes(32), true));
  const theft = sendEverything({ coins: [madeUpCoin()], to: stranger, script, feeRate: 2 });
  const theftCheck = await views.checkPropose(vaultHex, { inputs: theft.inputs, to: toHex(stranger), amount: theft.amount });
  const theftArgs = buildPropose({ contract: config.contract, vault, script, seed: keys.seed, inputs: theft.inputs, to: stranger, amount: theft.amount, nonce: vault.spend_nonce, expiresAt: (await chainNow()) + 30 * 60_000 });
  const proposed = await relay.call('propose_btc', theftArgs);
  const pending = await until('the proposal to show', async () => {
    const v = await views.vault(vaultHex);
    return v.pending.length ? { id: v.pending.at(-1), v } : null;
  });
  const request = await views.request(vaultHex, pending.id);
  if (request.status !== 'Pending') throw new Error(`the proposal reads ${request.status}, not Pending`);
  say('PASS', 'demo-2', net, `the spend key proposed all ${theft.amount} sat to a new address: request ${pending.id}, tier ${request.tier}, it waits ${mmss(request.unlock - request.proposed_at)} on the contract's clock (check_propose said ${mmss(theftCheck.delay_ms)}). NEAR ${config.network} tx ${proposed.hash}`);

  // 3. The owner's phone cancels it.
  const cancelExpires = (await chainNow()) + 10 * 60_000;
  const digest = cancelDigest({ contract: config.contract, vaultHex, request: pending.id, expiresAt: cancelExpires });
  const { args: assertion, highS } = await getAssertion({ credentials: soft, digest, rpId: config.rp_id, credentialId: made.credentialId });
  const cancelled = await relay.call('cancel', cancelArgs({ vaultHex, request: pending.id, expiresAt: cancelExpires, assertion }));
  await until('the request to be gone', async () => ((await views.request(vaultHex, pending.id)) === null ? true : null));
  say('PASS', 'demo-3', net, `the passkey cancelled request ${pending.id} before its wait ended: the contract checked the WebAuthn assertion (software authenticator through the page's parser; ${highS ? 'it signed high-S and the parser normalised it' : 'it signed low-S'}) and deleted the request. NEAR ${config.network} tx ${cancelled.hash}`);

  // 4. A send to a known address, the vault's own: it waits T_known, then the contract asks the signer.
  const v2 = await views.vault(vaultHex);
  const own = fromHex(v2.script_pubkey);
  const coin = madeUpCoin();
  const home = sendEverything({ coins: [coin], to: own, script, feeRate: 2 });
  const homeArgs = buildPropose({ contract: config.contract, vault: v2, script, seed: keys.seed, inputs: home.inputs, to: own, amount: home.amount, nonce: v2.spend_nonce, expiresAt: (await chainNow()) + 30 * 60_000 });
  const homeSent = await relay.call('propose_btc', homeArgs);
  const homeId = (await until('the second proposal to show', async () => {
    const v = await views.vault(vaultHex);
    return v.pending.length ? { id: v.pending.at(-1) } : null;
  })).id;
  const homeReq = await views.request(vaultHex, homeId);
  const wait = homeReq.unlock - homeReq.proposed_at;
  console.log(`     request ${homeId} to the vault's own address, tier ${homeReq.tier}, waits ${mmss(wait)} (NEAR ${config.network} tx ${homeSent.hash}). Waiting on the contract's clock...`);
  await until('the unlock', async () => ((await chainNow()) >= homeReq.unlock ? true : null), { timeoutMs: wait + 120_000, everyMs: 2000 });
  let executed = null;
  for (let i = 0; i < 10 && !executed; i += 1) {
    try {
      executed = await relay.call('execute', { vault: vaultHex, request: homeId });
    } catch (err) {
      if (!/not unlocked/.test(err.message ?? '') || i === 9) throw err;
      await sleep(Math.max(1000, (err.retryAfterS ?? 2) * 1000));
    }
  }
  const signed = await until('the signer\'s answer', async () => {
    const r = await views.request(vaultHex, homeId);
    return r?.status === 'Signed' ? r : null;
  }, { timeoutMs: 120_000, everyMs: 1000 });
  const finalTx = await views.finalTx(vaultHex, homeId);
  if (!finalTx) throw new Error('the request reads Signed but final_tx is empty');
  say('PASS', 'demo-4', net, `after ${mmss(wait)} the relay called execute (NEAR ${config.network} tx ${executed.hash}), ${instance.signer} signed, and the contract assembled the Bitcoin transaction (${signed.sigs.length} signature(s))`);

  // 5. The signed transaction, judged by the consensus library against the made-up coin.
  const verdict = consensusVerdict(REPO, finalTx, v2.script_pubkey, [coin.value]);
  const control = consensusVerdict(REPO, finalTx, v2.script_pubkey, [coin.value + 1]);
  if (verdict === null) say('SKIP', 'demo-5', 'consensus-lib', `the signed transaction was not judged: ${toolsCheck(REPO).why}`);
  else if (verdict && !control) say('PASS', 'demo-5', 'consensus-lib', `libbitcoinconsensus accepts the contract's final transaction for the made-up ${coin.value} sat coin, and refuses it for a wrong value. Nothing was broadcast`);
  else say('FAIL', 'demo-5', 'consensus-lib', `libbitcoinconsensus: real value ${verdict ? 'accepted' : 'refused'}, wrong value ${control ? 'accepted' : 'refused'}`);
}

try {
  await main();
} catch (err) {
  if (err?.code === 'relay_down') skip(`(relay) the relay stopped answering mid-run: ${err.message}`);
  if (err?.code === 'daily_ceiling' || err?.code === 'rate_limited') skip(`(relay) ${err.code}: ${err.message}`);
  say('FAIL', 'demo', net, `${err.code ? `${err.code}: ` : ''}${err.message}${err.verbatim ? ` | ${err.verbatim}` : ''}`);
}
console.log(fails ? `DEMO FAIL in ${seconds()}` : `DEMO PASS in ${seconds()}. Self-test on a vault you just created; labels say which network`);
process.exit(fails ? 1 : 0);
