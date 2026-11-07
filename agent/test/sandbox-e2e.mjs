#!/usr/bin/env node
// The agent CLI end to end, on the real wasm and a local NEAR node. The mock signer stands in for MPC,
// the coins are made up and served by a local Esplora stand-in, and the passkey is a software
// authenticator. Every line says so with [mock-signer]. Nothing here touches a live network.
//
//   node agent/test/sandbox-e2e.mjs --rpc URL --root-key FILE --mock-wasm FILE --wasm FILE [--out FILE]
//
// --out keeps a copy of the transcript: each CLI command and its real stdout. Temporary files go
// under $UNDO_AGENT_WORK, else <repo>/target/agent-sandbox, and are deleted at the end.
import { spawn } from 'node:child_process';
import { createServer } from 'node:http';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from '../../tools/lib/args.mjs';
import { addressToSpk, segwitAddress } from '../../tools/lib/btc.mjs';
import { base58Decode, base58Encode, fromHex, toHex } from '../../tools/lib/bytes.mjs';
import { randomBytes } from '../../tools/lib/crypto.mjs';
import { argBytes, createDigest, intentDigest, leafPopDigest, PASSKEY_TAG, signEd25519, signSecp, softAssertion } from '../../tools/lib/intent.mjs';
import { action, failureOf, keyFromSecret, loadKeyFile, milliNear, NEAR, Near, returnValue, RpcError, TGAS } from '../../tools/lib/near.mjs';
import { signSpend } from '../../tools/lib/spend.mjs';
import { coldCancelDigest, newOwnerKeys, OWNER_ATTACH_TGAS, throwawayOperatorPasskey, VaultClient } from '../../tools/lib/vault-client.mjs';
import { AGENT_METHODS } from '../lib/config.mjs';
import { contractWords, runtimeWords } from '../lib/format.mjs';

const AGENT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const REPO = resolve(AGENT, '..');
const a = parseArgs(process.argv.slice(2), { rpc: 'text', 'root-key': 'text', 'mock-wasm': 'text', wasm: 'text', out: 'text' });
for (const need of ['rpc', 'root-key', 'mock-wasm', 'wasm']) if (!a[need]) throw new Error(`needs --${need}`);
const near = new Near([a.rpc]);
const root = loadKeyFile(a['root-key']);
const base = process.env.UNDO_AGENT_WORK ?? join(REPO, 'target', 'agent-sandbox');
mkdirSync(base, { recursive: true });
const work = mkdtempSync(join(base, 'run-'));
const LABEL = '[mock-signer]';
const transcript = [];
let passed = 0;
let failed = 0;

function check(name, ok, detail = '', claim = '') {
  const tag = claim ? `${claim} ${LABEL}` : LABEL;
  console.log(`${ok ? 'PASS' : 'FAIL'} ${tag} ${name}${ok ? '' : `: ${detail}`}`);
  if (ok) passed += 1;
  else failed += 1;
}

const refusedWith = (result, needle) => {
  const f = failureOf(result);
  return Boolean(f) && f.includes(needle);
};

async function account(name, amount) {
  const key = keyFromSecret(randomBytes(32));
  const accountId = `${name}${toHex(randomBytes(3))}.${root.accountId}`;
  const sent = await near.sendAndWait(root, accountId, [action.createAccount(), action.transfer(BigInt(amount) * NEAR), action.addFullKey(key.pub)]);
  if (failureOf(sent.result)) throw new Error(failureOf(sent.result));
  return { ...key, accountId };
}

/**
 * Runs the CLI as an agent would, and keeps the command and its stdout for the transcript. Async, so
 * the Esplora stand-in in this process can answer the CLI while it runs.
 */
function undo(args, file) {
  return new Promise((done) => {
    const child = spawn(process.execPath, [join(AGENT, 'undo.mjs'), ...args, '--file', file], {
      env: { PATH: process.env.PATH, HOME: work, TMPDIR: work },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    const timer = setTimeout(() => child.kill('SIGKILL'), 120_000);
    child.on('close', (code) => {
      clearTimeout(timer);
      transcript.push(`$ undo ${args.map((t) => (/\s/.test(t) ? `"${t}"` : t)).join(' ')}`, ...out.trimEnd().split('\n'), ...(err ? [`[stderr] ${err.trimEnd()}`] : []), `[exit ${code}]`, '');
      done({ code, out, err });
    });
  });
}

/** create_vault with a guard named, so a heartbeat can bring the new-destination wait to 5:00. */
async function createGuarded(client, payer, keys, guard) {
  const csv = 6;
  const id = client.idFor(keys, csv);
  const km = await client.derivedKey(id);
  const expires = (await near.nowMs()) + 30 * 60_000;
  const digest = createDigest({ contract: client.contract, vault: id, km, rpIdHash: client.rpIdHash, guard, policy: client.instance.policy, expiresAt: expires });
  const args = {
    k_s: toHex(keys.ks.pub),
    k_u: toHex(keys.ku.pub),
    k_m: toHex(km),
    k_e_leaf: toHex(keys.leaf.pub),
    k_e_intent: toHex(keys.intent.pub),
    passkey: { pubkey: toHex(keys.kp.pub), rp_id_hash: toHex(client.rpIdHash) },
    guard,
    csv,
    policy: null,
    expires_at: expires,
    pop_s: toHex(signEd25519(digest, keys.ks.secret)),
    pop_u: toHex(signSecp(digest, keys.ku.secret)),
    pop_e: toHex(signSecp(digest, keys.intent.secret)),
    pop_leaf: toHex(signSecp(leafPopDigest(digest), keys.leaf.secret)),
    pop_p: softAssertion({ secret: keys.kp.secret, digest, origin: client.origin, rpId: client.rpId }),
  };
  const sent = await near.sendAndWait(payer, client.contract, [action.call('create_vault', { args }, 100n * TGAS, milliNear(100))]);
  if (failureOf(sent.result)) throw new Error(`create_vault: ${failureOf(sent.result)}`);
  return { id, hex: toHex(id), keys, km, csv, spendNonce: 0, passkeyNonce: 0 };
}

/** An Esplora stand-in on this machine: GET /address/<a>/utxo only. The coins are made up. */
function esploraStandIn(coinsFor) {
  const server = createServer((req, res) => {
    const m = req.method === 'GET' && req.url.match(/^\/address\/([a-z0-9]+)\/utxo$/);
    if (!m) {
      res.writeHead(404).end('not found');
      return;
    }
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(coinsFor(m[1])));
  });
  return new Promise((ok) => server.listen(0, '127.0.0.1', () => ok({
    url: `http://127.0.0.1:${server.address().port}`,
    close: () => new Promise((r) => { server.closeAllConnections(); server.close(r); }),
  })));
}

const tbAddress = () => segwitAddress('mutinynet', 0, randomBytes(20));
const requestIdFrom = (out) => Number((out.match(/^request +#(\d+)$/m) ?? [])[1]);

async function main() {
  // ---- the instance: mock signer, real wasm, Mutinynet addresses, a guard
  const mock = await account('mock', 30);
  const secret = randomBytes(32);
  await near.sendAndWait(mock, mock.accountId, [action.deploy(readFileSync(a['mock-wasm'])), action.call('new', { secret_hex: toHex(secret), mode: 'Yield' }, 100n * TGAS, 0n)]);
  const undoAcct = await account('undo', 30);
  const relay = await account('relay', 30);
  const guard = await account('guard', 10);
  const origin = 'https://app.example';
  const rpId = 'app.example';
  await near.sendAndWait(undoAcct, undoAcct.accountId, [
    action.deploy(readFileSync(a.wasm)),
    action.call('new', {
      preset: 'TestCoin', operator: relay.accountId, restrict_create: false, signer: mock.accountId, domain_id: 0, sign_tgas: 30, callback_tgas: 10,
      derive_tgas: 30, network: 'mutinynet', origins: [origin], outflow_cap_24h: 1_000_000, operator_passkey: throwawayOperatorPasskey(rpId),
    }, 100n * TGAS, 0n),
  ]);
  const contract = undoAcct.accountId;
  const instance = await near.view(contract, 'instance');
  const client = new VaultClient({ near, contract, signer: mock.accountId, instance, origin, rpId });
  const owner = newOwnerKeys();
  const vault = await createGuarded(client, relay, owner, guard.accountId);
  await near.sendAndWait(guard, contract, [action.call('heartbeat', { vault: vault.hex }, 30n * TGAS, 0n)]);
  let view = await near.view(contract, 'vault', { vault: vault.hex });
  check('setup: vault active on the real wasm, guard online, so a new destination waits the guarded 5:00', view?.active === true && view.guard_online === true);
  vault.spk = view.script_pubkey;

  const coins = [
    { txid: toHex(randomBytes(32)), vout: 0, value: 150_000, status: { confirmed: true } },
    { txid: toHex(randomBytes(32)), vout: 1, value: 60_000, status: { confirmed: true } },
    { txid: toHex(randomBytes(32)), vout: 0, value: 999, status: { confirmed: false } },
  ];
  const esplora = await esploraStandIn((addr) => (addr === view.address ? coins : []));

  try {
    // ---- init and keys: the owner hands over the spend seed, never K_p or K_e
    const agentAcct = await account('agent', 5);
    const seedFile = join(work, 'agent.seed');
    writeFileSync(seedFile, `${toHex(owner.seed)}\n`, { mode: 0o600 });
    const file = join(work, 'undo-agent.json');
    const initArgs = ['init', '--near-network', 'sandbox', '--rpc', a.rpc, '--contract', contract, '--vault', vault.hex, '--account', agentAcct.accountId, '--seed-file', seedFile, '--esplora', esplora.url];
    const wrongSeed = join(work, 'wrong.seed');
    writeFileSync(wrongSeed, `${toHex(randomBytes(32))}\n`, { mode: 0o600 });
    const badInit = await undo(initArgs.map((t) => (t === seedFile ? wrongSeed : t)), join(work, 'never.json'));
    check('control: init refuses a seed that is not the vault\'s spend key', badInit.code === 1 && /does not hold the vault's spend key/.test(badInit.out), badInit.out + badInit.err);
    const init = await undo(initArgs, file);
    check('init wrote the agent file', init.code === 0, init.out + init.err);
    const saved = JSON.parse(readFileSync(file, 'utf8'));
    check('the agent file is mode 600', (statSync(file).mode & 0o777) === 0o600);
    check('the agent file holds only the spend seed and one NEAR key: no passkey, no cold key',
      Object.keys(saved).sort().join(',') === 'account_id,contract,esplora,near_network,private_key,rpc,seed,undo_agent,vault'
      && !JSON.stringify(saved).includes(toHex(owner.cold)) && !JSON.stringify(saved).includes(toHex(owner.kp.secret)));

    const keysJson = JSON.parse((await undo(['keys', '--json'], file)).out);
    check('undo keys names the contract and only propose_btc and execute', keysJson.contract === contract && keysJson.methods.join(',') === 'propose_btc,execute');
    check('undo keys reads the key as not on chain yet', keysJson.on_chain.ok === false && /not on chain/.test(keysJson.on_chain.text));
    const keysText = (await undo(['keys'], file)).out;
    check('undo keys prints no secret', !keysText.includes(saved.private_key) && !keysText.includes(saved.seed));

    // The owner runs the printed command. Here the test adds the same key with the account's full key.
    const fcPub = keyFromSecret(fromNearSecret(saved.private_key)).pub;
    const allowance = (NEAR * 25n) / 100n;
    const added = await near.sendAndWait(agentAcct, agentAcct.accountId, [action.addCallKey(fcPub, contract, AGENT_METHODS, allowance)]);
    check('the owner added the function-call key undo keys printed', !failureOf(added.result), failureOf(added.result));
    const keysAfter = JSON.parse((await undo(['keys', '--json'], file)).out);
    check('undo keys reads it back from chain: scoped to the contract, two methods', keysAfter.on_chain.ok === true, keysAfter.on_chain.text);

    // ---- controls on the agent's own NEAR key
    const fullFile = join(work, 'full-access.json');
    writeFileSync(fullFile, JSON.stringify({ ...saved, private_key: `ed25519:${base58Full(agentAcct)}` }), { mode: 0o600 });
    const dest1 = tbAddress();
    const nonceBefore = (await near.view(contract, 'vault', { vault: vault.hex })).spend_nonce;
    const full = await undo(['propose', '--to', dest1, '--amount', '50000'], fullFile);
    check('control: propose refuses a full-access NEAR key and sends nothing', full.code === 1 && /FULL ACCESS/.test(full.out)
      && (await near.view(contract, 'vault', { vault: vault.hex })).spend_nonce === nonceBefore, full.out + full.err);
    const wide = keyFromSecret(randomBytes(32));
    await near.sendAndWait(agentAcct, agentAcct.accountId, [action.addCallKey(wide.pub, contract, [], allowance)]);
    const wideFile = join(work, 'wide.json');
    writeFileSync(wideFile, JSON.stringify({ ...saved, private_key: `ed25519:${base58Full(wide)}` }), { mode: 0o600 });
    const wideRun = await undo(['propose', '--to', dest1, '--amount', '50000'], wideFile);
    check('control: propose refuses a function-call key with an empty method list (every method)', wideRun.code === 1 && /empty method list/.test(wideRun.out), wideRun.out + wideRun.err);
    const ownerFile = join(work, 'owner-in-agent.json');
    writeFileSync(ownerFile, JSON.stringify({ ...saved, cold_key: 'x' }), { mode: 0o600 });
    const ownerRun = await undo(['status'], ownerFile);
    check('control: the CLI refuses an agent file holding an owner key field', ownerRun.code === 2 && /never holds the owner's passkey or cold key/.test(ownerRun.err), ownerRun.err);
    writeFileSync(join(work, 'loose.json'), JSON.stringify(saved), { mode: 0o644 });
    const loose = await undo(['status'], join(work, 'loose.json'));
    check('control: the CLI refuses an agent file others can read', loose.code === 2 && /chmod 600/.test(loose.err), loose.err);

    // ---- check, propose, status
    const chk = await undo(['check', '--to', dest1, '--amount', '50000'], file);
    check('undo check: free view, tier New, wait 5:00', chk.code === 0 && /^tier +New/m.test(chk.out) && /^wait +5:00 after propose/m.test(chk.out), chk.out + chk.err);
    check('undo check sent nothing', (await near.view(contract, 'vault', { vault: vault.hex })).spend_nonce === nonceBefore);
    // The whole --to is the address: a valid one with anything in front is refused in words, and nothing is sent.
    const junk = await undo(['propose', '--to', `tb1qqqqqqqqq${dest1}`, '--amount', '50000'], file);
    check('undo propose refuses a valid address with junk in front, in plain words, and sends nothing', junk.code === 1
      && /^--to is not a mutinynet address: its checksum does not match, so a character is wrong$/m.test(junk.out) && !/^\s+at /m.test(junk.out + junk.err)
      && (await near.view(contract, 'vault', { vault: vault.hex })).spend_nonce === nonceBefore, junk.out + junk.err);

    const prop = await undo(['propose', '--to', dest1, '--amount', '50000', '--memo', 'invoice 42'], file);
    const filmStdout = prop.out;
    const r1 = requestIdFrom(prop.out);
    check('undo propose exits 0 and prints a request id', prop.code === 0 && Number.isInteger(r1), prop.out + prop.err);
    if (!Number.isInteger(r1)) throw new Error('no request to test further');
    const req1 = await near.view(contract, 'request', { vault: vault.hex, request: r1 });
    const shown = prop.out.match(/^unlocks in (\d+):(\d\d)$/m);
    const now1 = await near.nowMs();
    check('the request is on chain: Pending, tier New, 50,000 sats to that address', req1?.status === 'Pending' && req1.tier === 'New' && req1.amount === 50_000 && req1.to === toHex(addressToSpk('mutinynet', dest1)));
    check('the contract set the wait to exactly 5:00, and the CLI printed it', req1.unlock - req1.proposed_at === 300_000 && /^wait +5:00, set by the contract$/m.test(prop.out));
    check('"unlocks in M:SS" matches the contract\'s unlock against block time, within the seconds that passed',
      Boolean(shown) && (Number(shown[1]) * 60 + Number(shown[2])) * 1000 >= req1.unlock - now1 && (Number(shown[1]) * 60 + Number(shown[2])) * 1000 <= 300_000, shown?.[0]);
    check('propose names the phone as the one that can cancel', /^The owner's phone can cancel it until then\. This key cannot\.$/m.test(prop.out));
    check('every hash names its chain', /^NEAR sandbox tx [1-9A-HJ-NP-Za-km-z]{43,44}$/m.test(prop.out));
    check('propose prints no seed and no key', !prop.out.includes(saved.seed) && !prop.out.includes(saved.private_key));
    check('the memo went into the signed request', req1.snapshot?.memo === 'invoice 42' || JSON.stringify(req1.snapshot).includes('invoice 42'), JSON.stringify(req1.snapshot));

    const st = await undo(['status'], file);
    check('undo status lists the request as waiting, with the contract\'s own status lines', st.code === 0 && new RegExp(`#${r1}  New  50,000 sats to ${dest1}  waiting, unlocks in \\d+:\\d\\d`).test(st.out) && /guard online/.test(st.out), st.out + st.err);

    // ---- C14, layer one: NEAR itself refuses the agent's key for anything but its two methods
    const fcKey = { ...keyFromSecret(fromNearSecret(saved.private_key)), accountId: agentAcct.accountId };
    const far = (await near.nowMs()) + 30 * 60_000;
    const fakeAssertion = { authenticator_data: '00', client_data_json: '00', signature: '00' };
    const nearRefuses = async (method, args, deposit = 0n, receiver = contract) => {
      try {
        await near.send(fcKey, receiver, [action.call(method, args, 30n * TGAS, deposit)]);
        return null;
      } catch (err) {
        return err instanceof RpcError ? runtimeWords(err) : `not an RPC refusal: ${err.message}`;
      }
    };
    for (const [method, args] of [
      ['cancel', { vault: vault.hex, request: r1, expires_at: far, auth: { Passkey: fakeAssertion } }],
      ['cancel_all_and_rotate', { vault: vault.hex, new_k_s: toHex(randomBytes(32)), nonce: 0, expires_at: far, assertion: fakeAssertion }],
      ['set_policy', { vault: vault.hex, policy: { ...view.policy, t_new_ms: 60_000 }, nonce: 0, expires_at: far, assertion: fakeAssertion }],
      ['clear_hold', { vault: vault.hex, request: r1, nonce: 0, expires_at: far, assertion: fakeAssertion }],
      ['add_destination', { vault: vault.hex, script: toHex(addressToSpk('mutinynet', dest1)), nonce: 0, expires_at: far, assertion: fakeAssertion }],
    ]) {
      const words = await nearRefuses(method, args);
      check(`agent's NEAR key refused for ${method} by NEAR, before the contract: ${words}`, Boolean(words) && words.includes('MethodNameMismatch'), words ?? 'it was accepted', 'C14');
    }
    const deposit = await nearRefuses('propose_btc', {}, 1n);
    check(`agent's NEAR key cannot attach a deposit: ${deposit}`, Boolean(deposit) && deposit.includes('DepositWithFunctionCall'), deposit ?? 'accepted', 'C14');
    const elsewhere = await nearRefuses('pending', {}, 0n, mock.accountId);
    check(`agent's NEAR key cannot call another contract: ${elsewhere}`, Boolean(elsewhere) && elsewhere.includes('ReceiverMismatch'), elsewhere ?? 'accepted', 'C14');

    // ---- C14, layer two: relayed by a full-access account, the contract refuses what the agent can sign
    const agentP256 = randomBytes(32);
    const agentAssertion = (method, argsBytes, nonce) => softAssertion({
      secret: agentP256, origin, rpId,
      digest: intentDigest({ tag: PASSKEY_TAG, contract, vault: vault.id, method, args: argsBytes, expiresAt: far, nonce }),
    });
    const relayed = (method, args) => near.sendAndWait(relay, contract, [action.call(method, args, OWNER_ATTACH_TGAS * TGAS, 0n)]);
    const pk = (await near.view(contract, 'vault', { vault: vault.hex })).passkey_nonce;
    const newKs = randomBytes(32);
    const shorter = { ...view.policy, t_known_ms: 30_000, t_new_ms: 60_000, t_new_unguarded_ms: 60_000 };
    const attempts = [
      ['cancel, with a passkey assertion from a P-256 key the agent made', 'cancel',
        { vault: vault.hex, request: r1, expires_at: far, auth: { Passkey: agentAssertion('cancel', argBytes.cancel({ request: r1 }), null) } }, 'webauthn: bad signature'],
      ['cancel, as the cold key, signed with K_u', 'cancel',
        { vault: vault.hex, request: r1, expires_at: far, auth: { Cold: toHex(signSecp(coldCancelDigest({ contract, vault: vault.id, request: r1, expiresAt: far }), owner.ku.secret)) } }, 'bad K_e signature'],
      ['cancel_all_and_rotate to a spend key the agent chose', 'cancel_all_and_rotate',
        { vault: vault.hex, new_k_s: toHex(newKs), nonce: pk, expires_at: far, assertion: agentAssertion('cancel_all_and_rotate', argBytes.cancel_all_and_rotate({ newKs }), pk) }, 'webauthn: bad signature'],
      ['set_policy to shorten every wait', 'set_policy',
        { vault: vault.hex, policy: shorter, nonce: pk, expires_at: far, assertion: agentAssertion('set_policy', argBytes.set_policy({ policy: shorter }), pk) }, 'webauthn: bad signature'],
      ['add_destination, to make its own destination fast', 'add_destination',
        { vault: vault.hex, script: toHex(addressToSpk('mutinynet', dest1)), nonce: pk, expires_at: far, assertion: agentAssertion('add_destination', argBytes.add_destination({ script: addressToSpk('mutinynet', dest1) }), pk) }, 'webauthn: bad signature'],
      ['clear_hold', 'clear_hold',
        { vault: vault.hex, request: r1, nonce: pk, expires_at: far, assertion: agentAssertion('clear_hold', argBytes.clear_hold({ request: r1 }), pk) }, 'webauthn: bad signature'],
    ];
    for (const [what, method, args, needle] of attempts) {
      const sent = await relayed(method, args);
      check(`contract refuses the agent's ${what}: ${contractWords(failureOf(sent.result) ?? 'accepted')}`, refusedWith(sent.result, needle), failureOf(sent.result) ?? 'accepted', 'C14');
    }
    const still = await near.view(contract, 'request', { vault: vault.hex, request: r1 });
    view = await near.view(contract, 'vault', { vault: vault.hex });
    check('after every attempt: the request still waits with the same unlock, the policy and key are unchanged', still?.status === 'Pending' && still.unlock === req1.unlock
      && view.policy.t_new_ms === 300_000 && view.k_s === toHex(owner.ks.pub) && !view.k_s_suspended && view.known.length === 0, '', 'C14');

    // ---- the owner's passkey cancels (software authenticator)
    const cancelArgs = client.cancelArgsPasskey({ ...vault, keys: owner }, r1, far);
    const cancelled = await relayed('cancel', cancelArgs);
    check('the owner\'s passkey cancels the agent\'s request [software authenticator]', !failureOf(cancelled.result), failureOf(cancelled.result));
    const gone = await undo(['status', '--request', String(r1)], file);
    check('undo status --request reads it gone', gone.code === 0 && new RegExp(`#${r1}  not in the queue`).test(gone.out), gone.out + gone.err);

    // ---- a second spend, then the owner rotates
    const dest2 = tbAddress();
    const all = await undo(['propose', '--to', dest2, '--amount', 'all'], file);
    const r2 = requestIdFrom(all.out);
    const req2 = Number.isInteger(r2) ? await near.view(contract, 'request', { vault: vault.hex, request: r2 }) : null;
    check('undo propose --amount all spends both free coins, no change, after the cancel freed them', all.code === 0 && req2?.inputs.length === 2 && req2.change === null && req2.amount === 210_000 - req2.fee, all.out + all.err);
    view = await near.view(contract, 'vault', { vault: vault.hex });
    const rotateTo = randomBytes(32);
    const rotateAssertion = client.passkeyAssertion({ ...vault, keys: owner }, 'cancel_all_and_rotate', argBytes.cancel_all_and_rotate({ newKs: rotateTo }), far, view.passkey_nonce);
    const rotated = await relayed('cancel_all_and_rotate', { vault: vault.hex, new_k_s: toHex(rotateTo), nonce: view.passkey_nonce, expires_at: far, assertion: rotateAssertion });
    const grant = returnValue(rotated.result);
    check('the owner\'s passkey rotates: every pending request dies, the agent\'s key is suspended [software authenticator]', !failureOf(rotated.result), failureOf(rotated.result));
    const after = await undo(['status'], file);
    const one = await undo(['status', '--request', String(r2)], file);
    check('undo status says the agent\'s key is suspended and the second request is dead',
      /^spend key: suspended by the owner's rotation/m.test(after.out) && new RegExp(`#${r2}  .*(not in the queue|dead: the owner's rotation)`).test(one.out), after.out + one.out);

    const nonceSuspended = (await near.view(contract, 'vault', { vault: vault.hex })).spend_nonce;
    const refused = await undo(['propose', '--to', dest1, '--amount', '50000'], file);
    // This wasm's check_propose already refuses a suspended key, so the CLI sends nothing. A wasm that
    // did not would get the same refusal from propose_btc, with a NEAR tx hash.
    const viaCheck = /^refused by the contract: SpendKeySuspended$/m.test(refused.out) && /^its free check_propose view said so: nothing signed, nothing sent$/m.test(refused.out);
    const viaTx = /^refused by the contract: Smart contract panicked: SpendKeySuspended$/m.test(refused.out) && /^NEAR sandbox tx /m.test(refused.out);
    check(`a propose after rotation is refused by the contract${viaCheck ? ' in check_propose, nothing sent' : ''}: ${(refused.out.match(/^refused by the contract: (.*)$/m) ?? [])[1]}`,
      refused.code === 1 && (viaCheck || viaTx) && (await near.view(contract, 'vault', { vault: vault.hex })).spend_nonce === nonceSuspended, refused.out + refused.err, 'C14');
    // An agent that skips the check and sends anyway, with its own function-call key.
    const scriptHex = await near.view(contract, 'script', { vault: vault.hex });
    const direct = signSpend.propose({
      seed: owner.seed, contract, vault: vault.id, script: fromHex(scriptHex), spk: fromHex(view.script_pubkey), inputs: [coins[0]].map(({ txid, vout, value }) => ({ txid, vout, value })),
      to: addressToSpk('mutinynet', dest1), amount: 50_000, change: 150_000 - 50_000 - 384, nonce: nonceSuspended, expiresAt: (await near.nowMs()) + 10 * 60_000, memo: null,
    });
    const skipped = await near.sendAndWait(fcKey, contract, [action.call('propose_btc', direct.args, 30n * TGAS, 0n)]);
    check(`propose_btc sent straight from the agent's key, skipping the check, is refused by the contract: ${contractWords(failureOf(skipped.result) ?? 'accepted')}`,
      refusedWith(skipped.result, 'SpendKeySuspended'), failureOf(skipped.result) ?? 'accepted', 'C14');

    // The new key lands after T_known. Then the old one is simply not the vault's key.
    const ready = (await near.view(contract, 'vault', { vault: vault.hex })).grant_list.find((g) => g.id === grant)?.ready_at;
    await client.waitUntil(ready + 1000, { fastForward: true });
    const landed = await relayed('apply_grant', { vault: vault.hex, grant });
    view = await near.view(contract, 'vault', { vault: vault.hex });
    check('the rotation lands after T_known: the vault\'s spend key is the owner\'s new one', !failureOf(landed.result) && view.k_s === toHex(rotateTo) && !view.k_s_suspended, failureOf(landed.result));
    const late = await undo(['propose', '--to', dest1, '--amount', '50000'], file);
    check(`a propose after the rotation lands is refused by the contract: ${(late.out.match(/^refused by the contract: (.*)$/m) ?? [])[1]}`,
      late.code === 1 && /^refused by the contract: Smart contract panicked: bad K_s signature$/m.test(late.out), late.out + late.err, 'C14');
    const lateStatus = await undo(['status'], file);
    check('undo status says the vault\'s key is no longer the agent\'s', /^spend key: not this agent's/m.test(lateStatus.out), lateStatus.out);

    console.log('\n---- film: real stdout of one `undo propose` [NEAR sandbox, mock signer, made-up coins]');
    process.stdout.write(filmStdout);
    console.log('---- end');
  } finally {
    await esplora.close();
    if (a.out) writeFileSync(a.out, `${transcript.join('\n')}\n`);
    rmSync(work, { recursive: true, force: true });
  }
  console.log(`${failed ? 'AGENT CLI FAILED' : 'AGENT CLI OK'} ${LABEL}: ${passed} passed, ${failed} failed`);
  if (failed) process.exit(1);
}

function fromNearSecret(text) {
  return base58Decode(text.slice('ed25519:'.length)).slice(0, 32);
}

/** near-cli's 64-byte form of a key, as an agent file holds it. */
function base58Full(key) {
  const full = new Uint8Array(64);
  full.set(key.secret, 0);
  full.set(key.pub, 32);
  return base58Encode(full);
}

main().catch((err) => {
  console.error(`agent e2e stopped: ${err.message}`);
  rmSync(work, { recursive: true, force: true });
  process.exit(1);
});

