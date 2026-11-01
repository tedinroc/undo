// The library against the real wasm on a local NEAR node, with the mock signer: the film's whole path as the
// pages will walk it, through the same functions. Labelled [mock-signer]. It says nothing about the live
// signer or a real phone. Skipped, and it says so, without NEAR_SANDBOX_BIN_PATH and UNDO_WASM_DIR.
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { fromHex, toHex } from '../../tools/lib/bytes.mjs';
import { ed25519, sha256 } from '../../tools/lib/crypto.mjs';
import { action, failureOf, returnValue, TGAS } from '../../tools/lib/near.mjs';
import { scriptMatchesVault, sendEverything, spkToAddress } from '../lib/bitcoin.mjs';
import { clock, SkewTracker } from '../lib/clock.mjs';
import { buildCreateArgs, buildPropose, cancelArgs, cancelDigest, newVaultKeys, rotateArgs, rotateDigest, rpIdHashOf, vaultIdOf } from '../lib/intents.mjs';
import { NearReader } from '../lib/near-read.mjs';
import { CREATE_DEPOSIT_MILLI, executeTgas, RELAY_METHODS, relayBodyProblem } from '../lib/relay-table.mjs';
import { advanceState, requestState } from '../lib/request-state.mjs';
import { softCredentials } from '../lib/soft-authenticator.mjs';
import { contractViews, derivedKey } from '../lib/views.mjs';
import { createPasskey, getAssertion, refusalOf } from '../lib/webauthn.mjs';
import { stageAvailable, startStage } from './stage.mjs';

const skip = stageAvailable() ? false : 'set NEAR_SANDBOX_BIN_PATH and UNDO_WASM_DIR to run this against the real wasm';
const label = (text) => sha256(new TextEncoder().encode(`undo-test-only:web:${text}`));
const FIVE_MINUTES = 300_000;

let stage;
let reader;
let views;
let instance;

before(async () => {
  if (skip) return;
  stage = await startStage({ miner: false });
  reader = new NearReader({ urls: stage.config.rpc, timeoutMs: 15_000 });
  views = contractViews(reader, stage.contract);
  instance = await views.instance();
}, { timeout: 180_000 });

after(async () => {
  await stage?.stop();
});

const relayCall = (method, args, tgas, deposit = 0n) => stage.near.sendAndWait(stage.relay, stage.contract, [action.call(method, args, BigInt(tgas) * TGAS, deposit)]);

/** A throwaway vault as the phone makes it, relayed as /api/relay will: create and heartbeat in one batch. */
async function filmVault(name, { depositMilli = CREATE_DEPOSIT_MILLI, highS = false } = {}) {
  const soft = softCredentials({ secret: label(`${name}-passkey`), origin: stage.origin, rpId: stage.rpId, highS });
  const made = await createPasskey({ credentials: soft, rpId: stage.rpId });
  const keys = newVaultKeys({ seed: label(`${name}-seed`), cold: label(`${name}-cold`) });
  const passkeyPub = made.pubkey;
  const vaultHex = toHex(vaultIdOf({ contract: stage.contract, keys, passkeyPub, csv: 6 }));
  const km = await derivedKey(reader, { signer: instance.signer, domainId: instance.domain_id, contract: stage.contract, vaultHex });
  const chainNow = (await reader.blockTime()).blockMs;
  const built = await buildCreateArgs({
    contract: stage.contract, keys, passkeyPub, rpIdHash: rpIdHashOf(stage.rpId), km, guard: stage.relay.accountId, policy: instance.policy, csv: 6, expiresAt: chainNow + 30 * 60_000,
    assert: async (digest) => (await getAssertion({ credentials: soft, digest, rpId: stage.rpId, credentialId: made.credentialId })).args,
  });
  assert.equal(built.vaultHex, vaultHex);
  assert.equal(relayBodyProblem({ method: 'create_vault', args: built.args, pow: 0 }), null, 'real arguments pass the relay\'s shape check');
  const spec = RELAY_METHODS.create_vault;
  const sent = await stage.near.sendAndWait(stage.relay, stage.contract, [
    action.call('create_vault', { args: built.args }, BigInt(spec.tgas) * TGAS, stage.milliNear(depositMilli)),
    action.call('heartbeat', { vault: vaultHex }, BigInt(spec.heartbeatTgas) * TGAS, 0n),
  ]);
  return { sent, soft, keys, made, vaultHex, passkeyPub };
}

async function propose(v, coinValue = 2000) {
  const vault = await views.vault(v.vaultHex);
  const script = fromHex(await views.script(v.vaultHex));
  const coin = { txid: toHex(label(`coin-${v.vaultHex}-${vault.spend_nonce}`)), vout: 0, value: coinValue };
  const to = fromHex(`0014${toHex(label('thief')).slice(0, 40)}`);
  const spend = sendEverything({ coins: [coin], to, script, feeRate: 2 });
  const check = await views.checkPropose(v.vaultHex, { inputs: spend.inputs, to: toHex(to), amount: spend.amount });
  const chainNow = (await reader.blockTime()).blockMs;
  const args = buildPropose({ contract: stage.contract, vault, script, seed: v.keys.seed, inputs: spend.inputs, to, amount: spend.amount, nonce: vault.spend_nonce, expiresAt: chainNow + 30 * 60_000 });
  assert.equal(relayBodyProblem({ method: 'propose_btc', args }), null);
  const sent = await relayCall('propose_btc', args, RELAY_METHODS.propose_btc.tgas);
  assert.equal(failureOf(sent.result), null);
  return { request: returnValue(sent.result), check, tx: sent.hash, to, spend };
}

async function rotateWith(v, { digestNewKs = null } = {}) {
  const vault = await views.vault(v.vaultHex);
  const newKs = ed25519.getPublicKey(label(`${v.vaultHex}-new-ks-${vault.passkey_nonce}`));
  const expiresAt = (await reader.blockTime()).blockMs + 10 * 60_000;
  const digest = rotateDigest({ contract: stage.contract, vaultHex: v.vaultHex, newKs: digestNewKs ?? newKs, nonce: vault.passkey_nonce, expiresAt });
  const { args: assertion, highS } = await getAssertion({ credentials: v.soft, digest, rpId: stage.rpId, credentialId: v.made.credentialId });
  const args = rotateArgs({ vaultHex: v.vaultHex, newKs, nonce: vault.passkey_nonce, expiresAt, assertion });
  assert.equal(relayBodyProblem({ method: 'cancel_all_and_rotate', args }), null);
  const sent = await relayCall('cancel_all_and_rotate', args, RELAY_METHODS.cancel_all_and_rotate.tgas);
  return { sent, assertion, digest, highS };
}

async function chainClock(unlock, proposedAt) {
  const tracker = new SkewTracker();
  const sample = tracker.add(await reader.blockTime());
  return clock(unlock, sample, Date.now(), proposedAt);
}

async function fastForwardTo(target) {
  for (let i = 0; i < 200; i += 1) {
    const now = (await reader.blockTime()).blockMs;
    if (now >= target) return;
    await stage.near.sandboxFastForward(Math.min(Math.ceil((target - now) / 500) + 5, 5000));
    await new Promise((r) => setTimeout(r, 300));
  }
  throw new Error('the clock never reached the target');
}

test('a vault as the phone makes it activates, reads 5:00, and the contract built the script the page checks', { skip, timeout: 60_000 }, async () => {
  const v = await filmVault('new');
  assert.equal(failureOf(v.sent.result), null);
  const vault = await views.vault(v.vaultHex);
  assert.equal(vault.active, true);
  assert.equal(vault.guard_online, true);
  assert.equal(vault.guard, stage.relay.accountId);
  assert.equal(await views.delayNow(v.vaultHex), FIVE_MINUTES);
  assert.equal(vault.address, spkToAddress('regtest', vault.script_pubkey));
  assert.ok(scriptMatchesVault(fromHex(await views.script(v.vaultHex)), vault));
  assert.equal(vault.passkey, toHex(v.passkeyPub));
  const status = await views.status(v.vaultHex);
  assert.ok(status.lines.some((line) => line.includes('guard online')), status.lines.join(' / '));
});

test('the thief\'s proposal: the clock is the contract\'s 5:00, read through the skew correction', { skip, timeout: 60_000 }, async () => {
  const v = await filmVault('clock');
  const { request, check } = await propose(v);
  assert.equal(check.tier, 'New');
  assert.equal(check.delay_ms, FIVE_MINUTES);
  const { vault, request: r } = await views.both(v.vaultHex, request);
  assert.equal(r.unlock - r.proposed_at, FIVE_MINUTES);
  assert.deepEqual(vault.pending, [request]);
  const c = await chainClock(r.unlock, r.proposed_at);
  assert.ok(c.remainingMs <= FIVE_MINUTES && c.remainingMs > FIVE_MINUTES - 15_000, `${c.remainingMs} ms left`);
  assert.ok(c.fuse > 0.9 && c.fuse <= 1);
  const s = requestState({ request: r, vault, chainNow: c.chainNow });
  assert.equal(s.kind, 'waiting');
  assert.equal(s.clockRuns, true);
});

test('the contract refuses an assertion over another digest, in the words the page predicts, and nothing changes', { skip, timeout: 60_000 }, async () => {
  const v = await filmVault('tamper');
  const { request } = await propose(v);
  const before = await views.vault(v.vaultHex);
  const out = await rotateWith(v, { digestNewKs: ed25519.getPublicKey(label('some-other-key')) });
  const failure = failureOf(out.sent.result);
  assert.ok(failure?.includes('webauthn: wrong challenge'), failure);
  const after = await views.vault(v.vaultHex);
  assert.equal(after.spend_epoch, before.spend_epoch);
  assert.equal(after.k_s_suspended, false);
  assert.equal(requestState({ request: await views.request(v.vaultHex, request), vault: after, chainNow: (await reader.blockTime()).blockMs }).kind, 'waiting');
  // The page's own check gives the same words, before any gas is spent.
  const rightDigest = rotateDigest({ contract: stage.contract, vaultHex: v.vaultHex, newKs: ed25519.getPublicKey(label(`${v.vaultHex}-new-ks-${before.passkey_nonce}`)), nonce: before.passkey_nonce, expiresAt: 1 });
  assert.equal(refusalOf({ assertion: out.assertion, digest: rightDigest, pubkey: v.passkeyPub, rpIdHash: rpIdHashOf(stage.rpId), origins: instance.origins }), 'webauthn: wrong challenge');
});

test('Cancel: a high-S authenticator, normalised by the page, is accepted; the request reads cancelled at once though its status says Pending', { skip, timeout: 60_000 }, async () => {
  const v = await filmVault('cancel', { highS: true });
  const { request } = await propose(v);
  const out = await rotateWith(v);
  assert.equal(out.highS, true);
  assert.equal(failureOf(out.sent.result), null);
  const { vault, request: r } = await views.both(v.vaultHex, request);
  assert.equal(r.status, 'Pending', 'which is why a page cannot read status alone');
  assert.equal(vault.k_s_suspended, true);
  const chainNow = (await reader.blockTime()).blockMs;
  const s = requestState({ request: r, vault, chainNow, lastKnown: r });
  assert.equal(s.kind, 'cancelled');
  assert.equal(s.reason, 'rotated');
  assert.equal(s.clockRuns, false);

  // That key cannot ask again, and the page's refusal is the contract's.
  const script = fromHex(await views.script(v.vaultHex));
  const coin = { txid: toHex(label('second-coin')), vout: 0, value: 2000 };
  const to = fromHex(`0014${toHex(label('thief')).slice(0, 40)}`);
  const spend = sendEverything({ coins: [coin], to, script, feeRate: 2 });
  const again = buildPropose({ contract: stage.contract, vault, script, seed: v.keys.seed, inputs: spend.inputs, to, amount: spend.amount, nonce: vault.spend_nonce, expiresAt: chainNow + 30 * 60_000 });
  const refused = await relayCall('propose_btc', again, 40);
  assert.ok(failureOf(refused.result)?.includes('SpendKeySuspended'), failureOf(refused.result));
});

test('Too late: a signature, then a rotation. The epoch has moved and the literal rule would say cancelled. It must not', { skip, timeout: 120_000 }, async () => {
  const v = await filmVault('late');
  const { request } = await propose(v);
  const r0 = await views.request(v.vaultHex, request);
  await fastForwardTo(r0.unlock);
  const vault0 = await views.vault(v.vaultHex);
  const chainNow0 = (await reader.blockTime()).blockMs;
  const unlocked = requestState({ request: r0, vault: vault0, chainNow: chainNow0 });
  assert.equal(unlocked.kind, 'unlocked');
  assert.equal(unlocked.cancellable, true, 'at zero the contract still takes a cancel');

  assert.equal(relayBodyProblem({ method: 'execute', args: { vault: v.vaultHex, request } }), null);
  const gas = executeTgas(r0.inputs.length, { signTgas: instance.sign_tgas, callbackTgas: instance.callback_tgas });
  const sent = await stage.near.send(stage.relay, stage.contract, [action.call('execute', { vault: v.vaultHex, request }, BigInt(gas) * TGAS, 0n)]);
  assert.ok(sent.hash);
  let r = r0;
  for (let i = 0; i < 120 && r.status !== 'Signed'; i += 1) {
    await new Promise((res) => setTimeout(res, 250));
    r = await views.request(v.vaultHex, request);
  }
  assert.equal(r.status, 'Signed');

  const out = await rotateWith(v);
  assert.equal(failureOf(out.sent.result), null, 'the phone\'s tap lands, and stops nothing');
  const { vault, request: after } = await views.both(v.vaultHex, request);
  assert.equal(after.status, 'Signed');
  assert.notEqual(after.epoch, vault.spend_epoch, 'the literal epoch rule is true here');
  const chainNow = (await reader.blockTime()).blockMs;
  const s = requestState({ request: after, vault, chainNow, lastKnown: r });
  assert.equal(s.kind, 'signed');
  assert.equal(advanceState(requestState({ request: r0, vault, chainNow: chainNow0 }), s).kind, 'signed');
  assert.ok(await views.finalTx(v.vaultHex, request), 'the transaction exists, and anyone can broadcast it');
});

test('cancel, the nonce-free call, works by the page\'s path, and a gone request reads cancelled only because it was seen', { skip, timeout: 60_000 }, async () => {
  const v = await filmVault('single');
  const { request } = await propose(v);
  const seen = await views.request(v.vaultHex, request);
  const expiresAt = (await reader.blockTime()).blockMs + 10 * 60_000;
  const digest = cancelDigest({ contract: stage.contract, vaultHex: v.vaultHex, request, expiresAt });
  const { args: assertion } = await getAssertion({ credentials: v.soft, digest, rpId: stage.rpId });
  const args = cancelArgs({ vaultHex: v.vaultHex, request, expiresAt, assertion });
  assert.equal(relayBodyProblem({ method: 'cancel', args }), null);
  const sent = await relayCall('cancel', args, RELAY_METHODS.cancel.tgas);
  assert.equal(failureOf(sent.result), null);
  const { vault, request: gone } = await views.both(v.vaultHex, request);
  assert.equal(gone, null);
  const chainNow = (await reader.blockTime()).blockMs;
  assert.equal(requestState({ request: gone, vault, chainNow, lastKnown: seen }).kind, 'cancelled');
  assert.equal(requestState({ request: gone, vault, chainNow }).kind, 'unseen');
});

const burntTgas = (result) => (result.receipts_outcome.reduce((sum, r) => sum + r.outcome.gas_burnt, result.transaction_outcome.outcome.gas_burnt) / 1e12).toFixed(2);

test('measure: gas of each relayed call, against what the relay attaches', { skip, timeout: 60_000 }, async (t) => {
  const v = await filmVault('gas');
  const p = await propose(v);
  const proposedResult = await stage.near.txStatus(p.tx, stage.relay.accountId, 'EXECUTED_OPTIMISTIC');
  const r = await rotateWith(v);
  t.diagnostic(`create_vault + heartbeat batch: ${burntTgas(v.sent.result)} Tgas burnt, attached ${RELAY_METHODS.create_vault.tgas} + ${RELAY_METHODS.create_vault.heartbeatTgas}`);
  t.diagnostic(`propose_btc, 1 input: ${burntTgas(proposedResult)} Tgas burnt, attached ${RELAY_METHODS.propose_btc.tgas}`);
  t.diagnostic(`cancel_all_and_rotate: ${burntTgas(r.sent.result)} Tgas burnt, attached ${RELAY_METHODS.cancel_all_and_rotate.tgas}`);
  assert.ok(Number(burntTgas(r.sent.result)) < RELAY_METHODS.cancel_all_and_rotate.tgas);
});

test('measure: the deposit a whole film loop needs, and what is left of it', { skip, timeout: 120_000 }, async (t) => {
  for (const depositMilli of [10, 15, 20, CREATE_DEPOSIT_MILLI]) {
    const v = await filmVault(`deposit-${depositMilli}`, { depositMilli });
    const failure = failureOf(v.sent.result);
    if (failure) {
      t.diagnostic(`deposit ${depositMilli} mN: create refused: ${failure.slice(0, 200)}`);
      continue;
    }
    const before = await views.vault(v.vaultHex);
    let outcome = 'ok';
    try {
      await propose(v);
      const out = await rotateWith(v);
      if (failureOf(out.sent.result)) outcome = `rotate refused: ${failureOf(out.sent.result).slice(0, 160)}`;
    } catch (err) {
      outcome = `refused: ${err.message.slice(0, 160)}`;
    }
    const after = await views.vault(v.vaultHex);
    if (depositMilli === CREATE_DEPOSIT_MILLI) assert.equal(outcome, 'ok', 'the deposit the relay attaches finishes a loop');
    t.diagnostic(`deposit ${depositMilli} mN: ${outcome}; credit after create ${Number(before.storage_credit / 10n ** 18n) / 1e3} mN, after loop ${Number(after.storage_credit / 10n ** 18n) / 1e3} mN`);
  }
});
