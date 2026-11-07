#!/usr/bin/env node
// Each signed encoding, on the real wasm, with a control that must be refused. A correct result here
// means the Node encoders and the contract agree byte for byte. The mock signer stands in for MPC.
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from '../lib/args.mjs';
import { p2wshAddress } from '../lib/btc.mjs';
import { base58Encode, fromHex, toHex } from '../lib/bytes.mjs';
import { randomBytes } from '../lib/crypto.mjs';
import { signSecp } from '../lib/intent.mjs';
import { action, failureOf, keyFromSecret, loadKeyFile, milliNear, NEAR, Near, returnValue, TGAS } from '../lib/near.mjs';
import { buildRecovery } from '../lib/recovery.mjs';
import { coldCancelDigest, fakeCoins, newOwnerKeys, OWNER_ATTACH_TGAS, throwawayOperatorPasskey, VaultClient } from '../lib/vault-client.mjs';
import { argBytes } from '../lib/intent.mjs';
import { startMockNode } from './mock-node.mjs';

const TOOLS = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const a = parseArgs(process.argv.slice(2), { rpc: 'text', 'root-key': 'text', 'mock-wasm': 'text', wasm: 'text' });
const near = new Near([a.rpc]);
const root = loadKeyFile(a['root-key']);
const work = mkdtempSync(join(tmpdir(), 'undo-intents-'));
let failures = 0;
const check = (name, ok, detail = '') => {
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${ok ? '' : ` ${detail}`}`);
  if (!ok) failures += 1;
};
const refused = (result, needle) => {
  const f = failureOf(result);
  return Boolean(f) && (!needle || f.includes(needle));
};

async function account(name, amount) {
  const key = keyFromSecret(randomBytes(32));
  const accountId = `${name}${toHex(randomBytes(3))}.${root.accountId}`;
  const sent = await near.sendAndWait(root, accountId, [action.createAccount(), action.transfer(BigInt(amount) * NEAR), action.addFullKey(key.pub)]);
  if (failureOf(sent.result)) throw new Error(failureOf(sent.result));
  return { ...key, accountId };
}

async function main() {
  const mock = await account('mock', 30);
  const secret = randomBytes(32);
  await near.sendAndWait(mock, mock.accountId, [action.deploy(readFileSync(a['mock-wasm'])), action.call('new', { secret_hex: toHex(secret), mode: 'Yield' }, 100n * TGAS, 0n)]);
  const undo = await account('undo', 30);
  const relay = await account('relay', 30);
  const origin = 'https://app.example';
  const rpId = 'app.example';
  await near.sendAndWait(undo, undo.accountId, [
    action.deploy(readFileSync(a.wasm)),
    action.call('new', {
      preset: 'TestCoin', operator: relay.accountId, restrict_create: false, signer: mock.accountId, domain_id: 0, sign_tgas: 30, callback_tgas: 10,
      derive_tgas: 30, network: 'regtest', origins: [origin], outflow_cap_24h: 1_000_000,
      operator_passkey: throwawayOperatorPasskey(rpId),
    }, 100n * TGAS, 0n),
  ]);
  const instance = await near.view(undo.accountId, 'instance');
  const client = new VaultClient({ near, contract: undo.accountId, signer: mock.accountId, instance, origin, rpId });
  const responder = await account('node', 30);
  const node = startMockNode({ near, mock, responder, secret });

  try {
    // ---- create_vault: vault id, create digest, all four proofs of possession
    const keys = newOwnerKeys();
    const vault = await client.create(relay, keys, { depositMilli: 100 });
    check('create_vault accepted: id, digest and four proofs agree with the contract', vault.view?.active === true, failureOf(vault.result));
    check('the contract computed the id these keys give', vault.view?.id === vault.hex);
    check('the contract built the script and address this tool builds', vault.view?.address === p2wshAddress('regtest', vault.script));
    check('derived K_m is the signer\'s', vault.view?.k_m === toHex(vault.km));

    const other = newOwnerKeys();
    const { args: goodArgs } = await client.createArgs(other, {});
    const tamperedPop = { ...goodArgs, pop_u: goodArgs.pop_e };
    const refusedPop = await near.sendAndWait(relay, undo.accountId, [action.call('create_vault', { args: tamperedPop }, 100n * TGAS, milliNear(50))]);
    check('control: a proof from the wrong key is refused', refused(refusedPop.result, 'bad K_u signature'), failureOf(refusedPop.result));
    const foreignLeaf = await near.sendAndWait(relay, undo.accountId, [action.call('create_vault', { args: { ...goodArgs, pop_leaf: goodArgs.pop_e } }, 100n * TGAS, milliNear(50))]);
    check('control: the intent key cannot prove the escape key', refused(foreignLeaf.result, 'bad K_e leaf signature'), failureOf(foreignLeaf.result));

    // ---- propose through the CLI signer, offline, then relayed
    const viewFile = join(work, 'view.json');
    const seedFile = join(work, 'seed');
    const script = await near.view(undo.accountId, 'script', { vault: vault.hex });
    writeFileSync(viewFile, JSON.stringify({ ...vault.view, script }));
    writeFileSync(seedFile, `${toHex(keys.seed)}\n`, { mode: 0o600 });
    const coins = fakeCoins(2, 200_000);
    const inputsFile = join(work, 'inputs.json');
    writeFileSync(inputsFile, JSON.stringify(coins));
    const to = fromHex(`0014${toHex(randomBytes(20))}`);
    const expires = (await near.nowMs()) + 30 * 60_000;
    const printed = execFileSync('node', [join(TOOLS, 'sign-intent.mjs'), 'propose_btc', '--contract', undo.accountId, '--vault-view', viewFile, '--seed-file', seedFile,
      '--inputs', inputsFile, '--to-script', toHex(to), '--amount', '50000', '--change', String(400_000 - 50_000 - 800), '--nonce', '0', '--expires-at', String(expires)], { encoding: 'utf8' });
    const signedOut = JSON.parse(printed);
    check('sign-intent prints no seed', !printed.includes(toHex(keys.seed)));

    const wrongNonce = await near.sendAndWait(relay, undo.accountId, [action.call('propose_btc', { ...signedOut.args, nonce: 1 }, 40n * TGAS, 0n)]);
    check('control: a changed nonce breaks the K_s signature', refused(wrongNonce.result, 'bad K_s signature'), failureOf(wrongNonce.result));
    const wrongAmount = await near.sendAndWait(relay, undo.accountId, [action.call('propose_btc', { ...signedOut.args, amount: 50_001 }, 40n * TGAS, 0n)]);
    check('control: a changed amount breaks the K_s signature', refused(wrongAmount.result, 'bad K_s signature'), failureOf(wrongAmount.result));

    const proposed = await near.sendAndWait(relay, undo.accountId, [action.call('propose_btc', signedOut.args, 40n * TGAS, 0n)]);
    check('propose_btc from sign-intent.mjs accepted: K_s digest and K_u sighash agree', !failureOf(proposed.result), failureOf(proposed.result));
    const request = returnValue(proposed.result);
    vault.spendNonce = 1;

    // ---- freeze.mjs --method cancel: the cold intent path, the derived key, the real contract
    const recovery = join(work, 'cold-file.json');
    writeFileSync(recovery, buildRecovery({ network: 'regtest', vaultId: vault.hex, script: vault.script, cold: keys.cold }), { mode: 0o600 });
    const dryRunBin = process.env.UNDO_TOOLS_CHECK_BIN;
    if (dryRunBin) {
      const res = spawnSync(dryRunBin, ['dry-run', recovery], { encoding: 'utf8' });
      check('undo-btc accepts the recovery file this vault\'s keys give', res.status === 0, res.stdout);
    }
    const outFile = join(work, 'cancel-intent.json');
    const cli = spawnSync('node', [join(TOOLS, 'freeze.mjs'), '--recovery', recovery, '--contract', undo.accountId, '--method', 'cancel', '--request', String(request), '--now-ms', String(await near.nowMs()), '--out', outFile, '--yes'], { encoding: 'utf8' });
    check('freeze.mjs --method cancel ran', cli.status === 0, cli.stderr);
    check('freeze.mjs printed no cold key', !cli.stdout.includes(toHex(keys.cold)) && !cli.stderr.includes(toHex(keys.cold)));
    const intent = JSON.parse(readFileSync(outFile, 'utf8'));
    check('the intent file holds no cold key', !JSON.stringify(intent).includes(toHex(keys.cold)));
    check('the file names the vault\'s stored intent key', intent.k_e_intent === vault.view.k_e_intent);

    const leafDigest = coldCancelDigest({ contract: undo.accountId, vault: vault.id, request, expiresAt: intent.args.expires_at });
    const leafSigned = await near.sendAndWait(relay, undo.accountId, [action.call('cancel', { ...intent.args, auth: { Cold: toHex(signSecp(leafDigest, keys.leaf.secret)) } }, 40n * TGAS, 0n)]);
    check('control: the leaf key cannot cancel', refused(leafSigned.result, 'bad K_e signature'), failureOf(leafSigned.result));

    // A stranger relays it with tools/cancel.mjs, from their own account, with no relay at all.
    const strangerKey = join(work, 'stranger-key.json');
    writeFileSync(strangerKey, JSON.stringify({ account_id: relay.accountId, private_key: `ed25519:${base58Encode(relay.secret)}` }), { mode: 0o600 });
    const { NODE_USE_SYSTEM_CA: _ca, ...toolEnv } = process.env;
    const ownCancel = (file) => spawnSync('node', [join(TOOLS, 'cancel.mjs'), '--file', file, '--account', relay.accountId, '--key-file', strangerKey, '--rpc', a.rpc, '--yes'], { encoding: 'utf8', env: toolEnv, timeout: 120_000 });
    const sentOwn = ownCancel(outFile);
    check('a cancel signed offline by freeze.mjs and sent by a stranger with tools/cancel.mjs is accepted', sentOwn.status === 0 && /The contract took it/.test(sentOwn.stdout), `${sentOwn.stdout}${sentOwn.stderr}`);
    check('cancel.mjs printed no key', !`${sentOwn.stdout}${sentOwn.stderr}`.includes(base58Encode(relay.secret)));
    const gone = await near.view(undo.accountId, 'request', { vault: vault.hex, request });
    check('the request is gone', gone === null);
    const twice = ownCancel(outFile);
    check('cancel.mjs refuses to send it again, since the request is gone', twice.status === 1 && /is gone/.test(twice.stderr), `${twice.stdout}${twice.stderr}`);

    // ---- passkey intents with a software authenticator
    const p = await client.selfSpendArgs(vault, fakeCoins(1, 100_000), 950);
    const second = await client.propose(relay, vault, p);
    const passExpires = (await near.nowMs()) + 30 * 60_000;
    const cancelArgs = client.cancelArgsPasskey(vault, second.request, passExpires);
    const wrongRequest = await near.sendAndWait(relay, undo.accountId, [action.call('cancel', { ...cancelArgs, request: second.request + 1 }, 40n * TGAS, 0n)]);
    check('control: an assertion for another request is refused', refused(wrongRequest.result, 'webauthn'), failureOf(wrongRequest.result));
    const passkeyCancel = await near.sendAndWait(relay, undo.accountId, [action.call('cancel', cancelArgs, 40n * TGAS, 0n)]);
    check('cancel by software passkey accepted', !failureOf(passkeyCancel.result), failureOf(passkeyCancel.result));

    // ---- the other three cold intents, from freeze.mjs, on the real wasm. Offline signing, stranger relays.
    const coldIntent = async (name, args, nonce) => {
      const file = join(work, `${name}-intent.json`);
      const flags = ['--recovery', recovery, '--contract', undo.accountId, '--method', name, '--now-ms', String(await near.nowMs()), '--out', file, '--yes', '--nonce', String(nonce), ...args];
      const ran = spawnSync('node', [join(TOOLS, 'freeze.mjs'), ...flags], { encoding: 'utf8' });
      check(`freeze.mjs --method ${name} ran`, ran.status === 0, ran.stderr);
      const signed = JSON.parse(readFileSync(file, 'utf8'));
      check(`the ${name} intent file holds no cold key`, !JSON.stringify(signed).includes(toHex(keys.cold)));
      return signed.args;
    };
    const relayCold = (method, args) => near.sendAndWait(relay, undo.accountId, [action.call(method, args, 60n * TGAS, 0n)]);

    // A rotation for veto_grant to stop.
    const rotateKey = randomBytes(32);
    const rotateExpires = (await near.nowMs()) + 30 * 60_000;
    const rotateAssertion = client.passkeyAssertion(vault, 'cancel_all_and_rotate', argBytes.cancel_all_and_rotate({ newKs: rotateKey }), rotateExpires, vault.passkeyNonce);
    const rotated = await near.sendAndWait(relay, undo.accountId, [action.call('cancel_all_and_rotate', { vault: vault.hex, new_k_s: toHex(rotateKey), nonce: vault.passkeyNonce, expires_at: rotateExpires, assertion: rotateAssertion }, 60n * TGAS, 0n)]);
    check('a passkey rotation is waiting', !failureOf(rotated.result), failureOf(rotated.result));
    vault.passkeyNonce += 1;
    const grant = returnValue(rotated.result);

    let coldNonce = 0;
    const vetoArgs = await coldIntent('veto_grant', ['--grant', String(grant)], coldNonce);
    const vetoOther = await relayCold('veto_grant', { ...vetoArgs, grant: grant + 1 });
    check('control: an intent for one grant does not carry another', refused(vetoOther.result, 'bad K_e signature'), failureOf(vetoOther.result));
    const vetoed = await relayCold('veto_grant', vetoArgs);
    check('veto_grant signed by freeze.mjs accepted', !failureOf(vetoed.result), failureOf(vetoed.result));
    coldNonce += 1;
    check('the grant is gone', (await near.view(undo.accountId, 'vault', { vault: vault.hex })).grants.length === 0);
    const vetoAgain = await relayCold('veto_grant', vetoArgs);
    check('control: a replayed intent is refused', refused(vetoAgain.result, 'BadNonce'), failureOf(vetoAgain.result));

    const freezeArgs = await coldIntent('freeze', ['--minutes', '2'], coldNonce);
    const freezeLeaf = await relayCold('freeze', { ...freezeArgs, until: freezeArgs.until + 1 });
    check('control: an intent for one time does not carry another', refused(freezeLeaf.result, 'bad K_e signature'), failureOf(freezeLeaf.result));
    const frozen = await relayCold('freeze', freezeArgs);
    check('freeze signed by freeze.mjs accepted', !failureOf(frozen.result), failureOf(frozen.result));
    coldNonce += 1;
    check('the vault reads frozen', (await near.view(undo.accountId, 'vault', { vault: vault.hex })).frozen_until === freezeArgs.until);

    const unfreezeArgs = await coldIntent('unfreeze', [], coldNonce);
    const unfreezeStale = await relayCold('unfreeze', { ...unfreezeArgs, nonce: coldNonce + 1 });
    check('control: a changed nonce breaks the cold signature', refused(unfreezeStale.result, 'bad K_e signature'), failureOf(unfreezeStale.result));
    const unfrozen = await relayCold('unfreeze', unfreezeArgs);
    check('unfreeze signed by freeze.mjs accepted', !failureOf(unfrozen.result), failureOf(unfrozen.result));
    check('the vault reads unfrozen', (await near.view(undo.accountId, 'vault', { vault: vault.hex })).frozen_until === null);

    // ---- the passkey methods the page will sign, through this package's own encoders
    const dest = fromHex(`0014${'ab'.repeat(20)}`);
    const FAR = (await near.nowMs()) + 30 * 60_000;
    const passkeyCall = async (method, argsBytes, call) => {
      const view = await near.view(undo.accountId, 'vault', { vault: vault.hex });
      vault.passkeyNonce = view.passkey_nonce;
      const assertion = client.passkeyAssertion(vault, method, argsBytes, FAR, view.passkey_nonce);
      return near.sendAndWait(relay, undo.accountId, [action.call(method, { vault: vault.hex, ...call, nonce: view.passkey_nonce, expires_at: FAR, assertion }, OWNER_ATTACH_TGAS * TGAS, 0n)]);
    };
    const added = await passkeyCall('add_destination', argBytes.add_destination({ script: dest }), { script: toHex(dest) });
    check('add_destination signed by this package accepted', !failureOf(added.result), failureOf(added.result));
    const removed = await passkeyCall('remove_destination', argBytes.remove_destination({ script: dest }), { script: toHex(dest) });
    check('remove_destination signed by this package accepted', !failureOf(removed.result), failureOf(removed.result));
    const current = (await near.view(undo.accountId, 'vault', { vault: vault.hex })).policy;
    const tighter = { ...current, fee_cap_tx: current.fee_cap_tx - 1 };
    const tightened = await passkeyCall('set_policy', argBytes.set_policy({ policy: tighter }), { policy: tighter });
    check('set_policy signed by this package accepted', !failureOf(tightened.result), failureOf(tightened.result));
    const guarded = await passkeyCall('set_guard', argBytes.set_guard({ guard: 'guard.test.near' }), { guard: 'guard.test.near' });
    check('set_guard signed by this package accepted', !failureOf(guarded.result), failureOf(guarded.result));
    const noHold = await passkeyCall('clear_hold', argBytes.clear_hold({ request: 999 }), { request: 999 });
    check('clear_hold signed by this package reaches the rules', refused(noHold.result, 'NotPending') || refused(noHold.result, 'RequestNotFound'), failureOf(noHold.result));
  } finally {
    await node.stop();
    rmSync(work, { recursive: true, force: true });
  }
  if (failures) process.exit(1);
  console.log('INTENTS OK [mock-signer]');
}

main().catch((err) => {
  console.error(`intents stopped: ${err.message}`);
  rmSync(work, { recursive: true, force: true });
  process.exit(1);
});
