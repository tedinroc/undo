// A made_vaults row is written before the relay sends a create_vault. A vault id does not cover guard, policy, K_m or
// rp_id_hash, so a create the contract refuses, or one whose vault never activates, leaves a row whose id anyone can
// then make straight on the contract, with another guard. Such a vault must get neither the owner key nor a test coin:
// the relay counts a vault as its own only once its own create_vault ran and made the vault the chain holds now.
// Real wasm, local NEAR node, regtest, mock signer. [mock-signer]
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { toHex } from '../../tools/lib/bytes.mjs';
import { ed25519, secp256k1, sha256 } from '../../tools/lib/crypto.mjs';
import { action, failureOf, TGAS } from '../../tools/lib/near.mjs';
import { buildCreateArgs, newVaultKeys, rotateArgs, rotateDigest, rpIdHashOf, vaultIdOf } from '../lib/intents.mjs';
import { NearReader } from '../lib/near-read.mjs';
import { fundsPowTarget, solvePow } from '../lib/pow.mjs';
import { RELAY_METHODS } from '../lib/relay-table.mjs';
import { softCredentials } from '../lib/soft-authenticator.mjs';
import { contractViews, derivedKey } from '../lib/views.mjs';
import { createPasskey, getAssertion } from '../lib/webauthn.mjs';
import { stageAvailable, startStage } from './stage.mjs';

const skip = stageAvailable() ? false : 'set NEAR_SANDBOX_BIN_PATH and UNDO_WASM_DIR to run this against the real wasm';
const label = (text) => sha256(new TextEncoder().encode(`undo-test-only:made-row:${text}`));
const sleep = (ms) => new Promise((r) => { setTimeout(r, ms); });

let stage;
let reader;
let views;
let instance;
let powBits;

before(async () => {
  if (skip) return;
  stage = await startStage({ miner: false, relayEnv: { STATUS_CACHE_MS: 0, CEILING_GENERAL_MICRO: 10_000_000 } });
  reader = new NearReader({ urls: stage.config.rpc, timeoutMs: 15_000 });
  views = contractViews(reader, stage.contract);
  instance = await views.instance();
  powBits = (await (await fetch(`${stage.origin}/api/relay`)).json()).pow_bits;
}, { timeout: 180_000 });

after(async () => {
  await stage?.stop();
});

async function waitFor(what, fn, timeoutMs = 30_000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    const out = await fn();
    if (out) return out;
    await sleep(200);
  }
  throw new Error(`never saw ${what}`);
}

/** create_vault arguments for the keys named `name`. `km` defaults to the key the signer derives for that vault. */
async function createArgs(name, guard, { km = null } = {}) {
  const soft = softCredentials({ secret: label(`${name}-passkey`), origin: stage.origin, rpId: stage.rpId });
  const made = await createPasskey({ credentials: soft, rpId: stage.rpId });
  const keys = newVaultKeys({ seed: label(`${name}-seed`), cold: label(`${name}-cold`) });
  const vaultHex = toHex(vaultIdOf({ contract: stage.contract, keys, passkeyPub: made.pubkey, csv: 6 }));
  const right = await derivedKey(reader, { signer: instance.signer, domainId: instance.domain_id, contract: stage.contract, vaultHex });
  const chainNow = (await reader.blockTime()).blockMs;
  const built = await buildCreateArgs({
    contract: stage.contract, keys, passkeyPub: made.pubkey, rpIdHash: rpIdHashOf(stage.rpId), km: km ?? right, guard, policy: instance.policy, csv: 6, expiresAt: chainNow + 30 * 60_000,
    assert: async (digest) => (await getAssertion({ credentials: soft, digest, rpId: stage.rpId, credentialId: made.credentialId })).args,
  });
  return { soft, made, keys, vaultHex, args: built.args };
}

async function tapCancel(v, ip = '127.0.0.1') {
  const vault = await views.vault(v.vaultHex);
  const nonce = vault?.passkey_nonce ?? 0;
  const newKs = ed25519.getPublicKey(label(`${v.vaultHex}-new-ks-${nonce}`));
  const expiresAt = (await reader.blockTime()).blockMs + 10 * 60_000;
  const digest = rotateDigest({ contract: stage.contract, vaultHex: v.vaultHex, newKs, nonce, expiresAt });
  const { args: assertion } = await getAssertion({ credentials: v.soft, digest, rpId: stage.rpId, credentialId: v.made.credentialId });
  return stage.api('/api/relay', { method: 'cancel_all_and_rotate', args: rotateArgs({ vaultHex: v.vaultHex, newKs, nonce, expiresAt, assertion }) }, { ip });
}

const askFunds = async (v, ip) => stage.api('/api/funds', { vault: v.vaultHex, pow: await solvePow(fundsPowTarget(v.vaultHex), powBits) }, { ip });

/** The payer sends it straight to the contract, free of the relay's limits. */
async function straight(v) {
  const spec = RELAY_METHODS.create_vault;
  const sent = await stage.near.sendAndWait(stage.payer, stage.contract, [
    action.call('create_vault', { args: v.args }, BigInt(spec.tgas) * TGAS, stage.milliNear(spec.depositMilli)),
  ]);
  return failureOf(sent.result);
}

const flip = (hex) => hex.slice(0, 10) + (hex[10] === '0' ? '1' : '0') + hex.slice(11);

async function settled(hash) {
  return waitFor('the create outcome', async () => {
    const o = await reader.txOutcome(hash, stage.relay.accountId, { wait: 'FINAL' });
    return o.settled ? o : null;
  }, 60_000);
}

async function activeVault(vaultHex) {
  return waitFor('the vault active', async () => {
    const r = await views.vault(vaultHex);
    return r?.active ? r : null;
  });
}

test('made rows: a vault made through the relay gets the owner key and a coin; one made straight gets neither [mock-signer]', { skip, timeout: 300_000 }, async (t) => {
  const own = await createArgs('own', stage.relay.accountId);
  const sent = await stage.api('/api/relay', { method: 'create_vault', args: own.args, pow: await solvePow(own.vaultHex, powBits) }, { ip: '10.9.0.1' });
  assert.equal(sent.status, 200, JSON.stringify(sent.body));
  await activeVault(own.vaultHex);
  const coin = await askFunds(own, '10.9.0.2');
  t.diagnostic(`relay-made vault, funds: ${coin.status} ${coin.body.code ?? 'ok'} value=${coin.body.value ?? '-'}`);
  assert.equal(coin.status, 200, JSON.stringify(coin.body));
  const tapped = await tapCancel(own);
  t.diagnostic(`relay-made vault, owner cancel: ${tapped.status} ${tapped.body.code ?? 'sent'} key=${tapped.body.key ?? '-'}`);
  assert.equal(tapped.status, 200, JSON.stringify(tapped.body));
  assert.equal(tapped.body.key, 'owner');

  const control = await createArgs('control', stage.payer.accountId);
  assert.equal(await straight(control), null);
  await activeVault(control.vaultHex);
  const controlTap = await tapCancel(control);
  t.diagnostic(`straight vault, owner cancel: ${controlTap.status} ${controlTap.body.code ?? 'sent'}`);
  assert.equal(controlTap.body.code, 'not_this_relays');
  const controlCoin = await askFunds(control, '10.9.0.9');
  t.diagnostic(`straight vault, funds: ${controlCoin.status} ${controlCoin.body.code ?? 'ok'}`);
  assert.equal(controlCoin.body.code, 'would_refuse');
});

test('made rows: a relay create the contract refuses (bad pop_u) leaves no vault of its own; the same id made straight with another guard gets neither [mock-signer]', { skip, timeout: 300_000 }, async (t) => {
  const viaRelay = await createArgs('bad-u', stage.relay.accountId);
  const sent = await stage.api('/api/relay', { method: 'create_vault', args: { ...viaRelay.args, pop_u: flip(viaRelay.args.pop_u) }, pow: await solvePow(viaRelay.vaultHex, powBits) }, { ip: '10.9.1.1' });
  t.diagnostic(`relay create with a bad pop_u: ${sent.status} ${sent.body.code ?? 'sent'}`);
  assert.equal(sent.status, 200, JSON.stringify(sent.body));
  const outcome = await settled(sent.body.hash);
  t.diagnostic(`chain outcome: ${outcome.failure ? outcome.failure.slice(0, 160) : null}`);
  assert.match(outcome.failure ?? '', /bad K_u signature/);
  assert.equal(await views.vault(viaRelay.vaultHex), null, 'no vault on chain');

  // The same keys, so the same vault id, straight on the contract, naming the payer as guard.
  const direct = await createArgs('bad-u', stage.payer.accountId);
  assert.equal(direct.vaultHex, viaRelay.vaultHex, 'guard is not in the vault id');
  assert.equal(await straight(direct), null);
  const row = await activeVault(direct.vaultHex);
  assert.notEqual(row.guard, stage.relay.accountId);

  const coin = await askFunds(direct, '10.9.1.2');
  t.diagnostic(`funds for the straight vault: ${coin.status} ${coin.body.code ?? 'ok'}`);
  assert.equal(coin.status, 422, JSON.stringify(coin.body));
  assert.equal(coin.body.code, 'would_refuse');
  const tapped = await tapCancel(direct);
  t.diagnostic(`owner cancel for the straight vault: ${tapped.status} ${tapped.body.code ?? 'sent'}`);
  assert.equal(tapped.status, 422, JSON.stringify(tapped.body));
  assert.equal(tapped.body.code, 'not_this_relays');
});

test('made rows, AUDIT-3 form: a refused relay create (bad pop_leaf), then the same args straight from the payer naming the relay as guard: no coin [mock-signer]', { skip, timeout: 300_000 }, async (t) => {
  const viaRelay = await createArgs('bad-leaf', stage.relay.accountId);
  const sent = await stage.api('/api/relay', { method: 'create_vault', args: { ...viaRelay.args, pop_leaf: flip(viaRelay.args.pop_leaf) }, pow: await solvePow(viaRelay.vaultHex, powBits) }, { ip: '10.9.2.1' });
  assert.equal(sent.status, 200, JSON.stringify(sent.body));
  const outcome = await settled(sent.body.hash);
  t.diagnostic(`chain outcome: ${outcome.failure ? outcome.failure.slice(0, 160) : null}`);
  assert.match(outcome.failure ?? '', /bad K_e leaf signature/);

  assert.equal(await straight(viaRelay), null);
  const row = await activeVault(viaRelay.vaultHex);
  assert.equal(row.guard, stage.relay.accountId, 'the straight vault names the relay, as in AUDIT-3');
  const coin = await askFunds(viaRelay, '10.9.2.2');
  t.diagnostic(`funds for the straight vault naming the relay: ${coin.status} ${coin.body.code ?? 'ok'}`);
  assert.equal(coin.body.code, 'would_refuse');
  const tapped = await tapCancel(viaRelay);
  t.diagnostic(`owner cancel for it: ${tapped.status} ${tapped.body.code ?? 'sent'}`);
  assert.equal(tapped.body.code, 'not_this_relays');
});

test('made rows: a relay create that runs but never activates (a wrong K_m), then the same id made straight with another guard: neither [mock-signer]', { skip, timeout: 300_000 }, async (t) => {
  // Signed over a K_m the signer does not derive: every proof checks, the create runs, and on_derived removes the vault.
  const wrongKm = secp256k1.getPublicKey(label('wrong-km'), true);
  const viaRelay = await createArgs('wrong-km', stage.relay.accountId, { km: wrongKm });
  const sent = await stage.api('/api/relay', { method: 'create_vault', args: viaRelay.args, pow: await solvePow(viaRelay.vaultHex, powBits) }, { ip: '10.9.3.1' });
  assert.equal(sent.status, 200, JSON.stringify(sent.body));
  const outcome = await settled(sent.body.hash);
  t.diagnostic(`chain outcome: failure=${outcome.failure}`);
  assert.equal(outcome.failure, null, 'the relay\'s create ran');
  await waitFor('the vault removed by on_derived', async () => (await views.vault(viaRelay.vaultHex)) === null);

  const direct = await createArgs('wrong-km', stage.payer.accountId);
  assert.equal(direct.vaultHex, viaRelay.vaultHex, 'K_m is not in the vault id');
  assert.equal(await straight(direct), null);
  await activeVault(direct.vaultHex);
  const coin = await askFunds(direct, '10.9.3.2');
  t.diagnostic(`funds for the straight vault: ${coin.status} ${coin.body.code ?? 'ok'}`);
  assert.equal(coin.body.code, 'would_refuse');
  const tapped = await tapCancel(direct);
  t.diagnostic(`owner cancel for it: ${tapped.status} ${tapped.body.code ?? 'sent'}`);
  assert.equal(tapped.body.code, 'not_this_relays');
});
