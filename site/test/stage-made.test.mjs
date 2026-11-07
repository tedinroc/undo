// The stage's relay the way phone.test.mjs now makes its vaults, with no Chrome: through the relay's own create_vault,
// each from its own address. Such a vault gets the owner key's cancel and a test coin. One made straight on the
// contract, the way phone.test.mjs used to make them, gets neither. phone.test.mjs needs Chrome; this is the part of
// its setup that runs without it. Real wasm, local NEAR node, regtest. [mock-signer]
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { toHex } from '../../tools/lib/bytes.mjs';
import { ed25519, sha256 } from '../../tools/lib/crypto.mjs';
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
const label = (text) => sha256(new TextEncoder().encode(`undo-test-only:stage-made:${text}`));
const sleep = (ms) => new Promise((r) => { setTimeout(r, ms); });

let stage;
let reader;
let views;
let instance;
let powBits;

before(async () => {
  if (skip) return;
  // As phone.test.mjs starts it: a general ceiling that holds a whole file's worth of vaults.
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

/** The create_vault arguments phone.test.mjs builds, with a soft passkey in place of Chrome's virtual one. */
async function createArgs(name, guard = stage.relay.accountId) {
  const soft = softCredentials({ secret: label(`${name}-passkey`), origin: stage.origin, rpId: stage.rpId });
  const made = await createPasskey({ credentials: soft, rpId: stage.rpId });
  const keys = newVaultKeys({ seed: label(`${name}-seed`), cold: label(`${name}-cold`) });
  const vaultHex = toHex(vaultIdOf({ contract: stage.contract, keys, passkeyPub: made.pubkey, csv: 6 }));
  const km = await derivedKey(reader, { signer: instance.signer, domainId: instance.domain_id, contract: stage.contract, vaultHex });
  const chainNow = (await reader.blockTime()).blockMs;
  const built = await buildCreateArgs({
    contract: stage.contract, keys, passkeyPub: made.pubkey, rpIdHash: rpIdHashOf(stage.rpId), km, guard, policy: instance.policy, csv: 6, expiresAt: chainNow + 30 * 60_000,
    assert: async (digest) => (await getAssertion({ credentials: soft, digest, rpId: stage.rpId, credentialId: made.credentialId })).args,
  });
  return { soft, made, keys, vaultHex, args: built.args };
}

/** phone.test.mjs's makeVault: through the relay, from the address `ip`. Returns the relay's answer too. */
async function viaRelay(name, ip) {
  const v = await createArgs(name);
  const pow = await solvePow(v.vaultHex, powBits);
  const answer = await stage.api('/api/relay', { method: 'create_vault', args: v.args, pow }, { ip });
  if (answer.status === 200) await waitFor('the vault on the chain', async () => (await views.vault(v.vaultHex)) !== null);
  return { ...v, answer };
}

/** How phone.test.mjs used to make them: straight on the contract, from the payer's own account, which guards it. */
async function straight(name) {
  const v = await createArgs(name, stage.payer.accountId);
  const spec = RELAY_METHODS.create_vault;
  const sent = await stage.near.sendAndWait(stage.payer, stage.contract, [
    action.call('create_vault', { args: v.args }, BigInt(spec.tgas) * TGAS, stage.milliNear(spec.depositMilli)),
    action.call('heartbeat', { vault: v.vaultHex }, BigInt(spec.heartbeatTgas) * TGAS, 0n),
  ]);
  assert.equal(failureOf(sent.result), null);
  return v;
}

/** The phone's Cancel: a passkey-signed cancel_all_and_rotate, sent to the relay. */
async function tapCancel(v, ip) {
  const vault = await views.vault(v.vaultHex);
  const newKs = ed25519.getPublicKey(label(`${v.vaultHex}-new-ks-${vault.passkey_nonce}`));
  const expiresAt = (await reader.blockTime()).blockMs + 10 * 60_000;
  const digest = rotateDigest({ contract: stage.contract, vaultHex: v.vaultHex, newKs, nonce: vault.passkey_nonce, expiresAt });
  const { args: assertion } = await getAssertion({ credentials: v.soft, digest, rpId: stage.rpId, credentialId: v.made.credentialId });
  return stage.api('/api/relay', { method: 'cancel_all_and_rotate', args: rotateArgs({ vaultHex: v.vaultHex, newKs, nonce: vault.passkey_nonce, expiresAt, assertion }) }, { ip });
}

const askFunds = async (v, ip) => stage.api('/api/funds', { vault: v.vaultHex, pow: await solvePow(fundsPowTarget(v.vaultHex), powBits) }, { ip });

test('phone.test.mjs\'s vaults: made through the relay, each from its own address, they get the relay\'s cancel and a test coin [mock-signer]', { skip, timeout: 240_000 }, async (t) => {
  // One address gets 3 creates an hour, which is why phone.test.mjs gives each vault its own.
  const same = [];
  for (let i = 0; i < 4; i += 1) same.push(await viaRelay(`same-${i}`, '10.9.0.1'));
  assert.deepEqual(same.map((v) => v.answer.status), [200, 200, 200, 429], JSON.stringify(same.map((v) => v.answer.body.code ?? 'sent')));
  assert.equal(same[3].answer.body.code, 'rate_limited');

  const own = [];
  for (let i = 0; i < 4; i += 1) own.push(await viaRelay(`own-${i}`, `10.9.1.${i + 1}`));
  assert.deepEqual(own.map((v) => v.answer.status), [200, 200, 200, 200], JSON.stringify(own.map((v) => v.answer.body)));

  const v = own[0];
  const vault = await views.vault(v.vaultHex);
  assert.equal(vault.guard, stage.relay.accountId);
  assert.equal(vault.active, true);
  assert.equal(vault.guard_online, true, 'the relay beat at creation');

  const coin = await askFunds(v, '10.9.2.1');
  t.diagnostic(`funds for a vault the relay made: ${coin.status} ${coin.body.code ?? 'ok'}`);
  assert.notEqual(coin.body.code, 'would_refuse', 'the made rule lets it through');
  assert.notEqual(coin.body.code, 'state_store_down');

  const tapped = await tapCancel(v, '127.0.0.1');
  assert.equal(tapped.status, 200, JSON.stringify(tapped.body));
  assert.equal(tapped.body.key, 'owner');
  await waitFor('the rotation on the chain', async () => (await views.vault(v.vaultHex)).k_s_suspended === true);
});

test('the old way: a vault made straight on the contract gets not_this_relays for its owner\'s own cancel, and no coin [mock-signer]', { skip, timeout: 120_000 }, async () => {
  const v = await straight('straight');
  const tapped = await tapCancel(v, '127.0.0.1');
  assert.equal(tapped.status, 422);
  assert.equal(tapped.body.code, 'not_this_relays');
  assert.match(tapped.body.message, /tools\/cancel\.mjs/);
  assert.equal((await views.vault(v.vaultHex)).k_s_suspended, false);
  const coin = await askFunds(v, '10.9.3.1');
  assert.equal(coin.status, 422);
  assert.equal(coin.body.code, 'would_refuse');
});
