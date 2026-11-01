// A real browser: headless Chrome, a built site, navigator.credentials on Chrome's virtual authenticator. It
// shows the library loads in a page under the CSP the build writes, that a real browser's WebAuthn output
// goes through assertionToArgs, and, with the stage up, that the real wasm accepts it. Not a phone: gate G3 is.
// One Chrome only, killed in `after`. Skipped, and it says so, if Chrome is not there.
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { fromHex, toHex } from '../../tools/lib/bytes.mjs';
import { ed25519, sha256 } from '../../tools/lib/crypto.mjs';
import { argBytes, intentDigest, PASSKEY_TAG } from '../../tools/lib/intent.mjs';
import { action, failureOf, returnValue, TGAS } from '../../tools/lib/near.mjs';
import { build } from '../build.mjs';
import { rpIdHashOf } from '../lib/intents.mjs';
import { CREATE_DEPOSIT_MILLI, RELAY_METHODS } from '../lib/relay-table.mjs';
import { isHighS, refusalOf } from '../lib/webauthn.mjs';
import { chromeAvailable, startChrome } from './chrome.mjs';
import { stageAvailable, startStage, staticServer } from './stage.mjs';

const skip = chromeAvailable() ? false : 'set CHROME_BIN to run this in a real browser';
const label = (text) => sha256(new TextEncoder().encode(`undo-test-only:web:${text}`));

let browser;
let cdp;
let plain;

const LOCAL = {
  mode: 'local', contract: 'film.test.near', rpc: ['http://127.0.0.1:9'], esplora: 'http://127.0.0.1:9', relay: '/api/relay', funds: '/api/funds',
  btcTxUrl: null, btcAddressUrl: null, nearTxUrl: null, rpId: 'localhost', softPasskey: false,
};

before(async () => {
  if (skip) return;
  browser = await startChrome();
  ({ cdp } = browser);
  await browser.addPasskeyDevice();

  const dir = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'undo-browser-dist-'));
  build({ configObject: LOCAL, out: dir });
  const server = await staticServer({ dir, port: 0, onApi: (req, res) => {
    res.writeHead(503, { 'content-type': 'application/json' });
    res.end('{"ok":false,"code":"relay_not_configured"}');
  } });
  plain = { dir, server, origin: `http://localhost:${server.address().port}` };
}, { timeout: 60_000 });

after(async () => {
  await browser?.stop();
  plain?.server.close();
  plain?.server.closeAllConnections?.();
  if (plain) rmSync(plain.dir, { recursive: true, force: true });
});

const IMPORT = "const lib = await import('/site/lib/index.mjs');";

test('Chrome: the library loads as plain modules under the build\'s CSP, with no Node in sight', { skip, timeout: 30_000 }, async () => {
  await cdp.open(`${plain.origin}/`);
  const out = await cdp.page(`${IMPORT} return { buffer: typeof Buffer, process: typeof process, config: (await lib.loadConfig()).labels.chip, secure: isSecureContext };`);
  assert.deepEqual(out, { buffer: 'undefined', process: 'undefined', config: 'local test coins, mock signer', secure: true });
});

test('Chrome: the digest a phone signs equals the one Node computes with tools/lib/intent.mjs', { skip, timeout: 30_000 }, async () => {
  const vaultHex = toHex(label('browser-vault'));
  const newKs = ed25519.getPublicKey(label('browser-new-ks'));
  const inPage = await cdp.page(`${IMPORT} const d = lib.rotateDigest({ contract: 'undo.example.testnet', vaultHex: '${vaultHex}', newKs: lib.fromBase64('${Buffer.from(newKs).toString('base64')}'), nonce: 3, expiresAt: 1730000123456 }); return Array.from(d, (x) => x.toString(16).padStart(2, '0')).join('');`);
  const tools = intentDigest({ tag: PASSKEY_TAG, contract: 'undo.example.testnet', vault: fromHex(vaultHex), method: 'cancel_all_and_rotate', args: argBytes.cancel_all_and_rotate({ newKs }), expiresAt: 1730000123456, nonce: 3 });
  assert.equal(inPage, toHex(tools));
});

test('Chrome: the relay being absent reads as a state, and a clock from real numbers', { skip, timeout: 30_000 }, async () => {
  const out = await cdp.page(`${IMPORT} const client = new lib.RelayClient({ relay: '/api/relay', funds: '/api/funds' }); const s = await client.status(); return { reachable: s.reachable, why: s.why, owner: s.owner.up, clock: lib.clock(1000300000, { blockMs: 1000000000, localMs: 0 }, 0).text };`);
  assert.deepEqual(out, { reachable: false, why: 'relay_not_configured', owner: false, clock: '5:00.0' });
});

test('Chrome: a real navigator.credentials passkey, created and asserted through the library, checks by the contract\'s rules', { skip, timeout: 60_000 }, async (t) => {
  const made = await cdp.page(`${IMPORT}
    const p = await lib.createPasskey({ credentials: navigator.credentials, rpId: 'localhost' });
    return { pub: lib.toBase64(p.pubkey), cred: lib.toBase64Url(p.credentialId), flags: p.flags };`);
  assert.ok(made.flags.up && made.flags.uv);
  const pubkey = new Uint8Array(Buffer.from(made.pub, 'base64'));
  assert.equal(pubkey.length, 33);

  let high = 0;
  const TAPS = 8;
  for (let i = 0; i < TAPS; i += 1) {
    const digest = label(`browser-digest-${i}`);
    const got = await cdp.page(`${IMPORT}
      const a = await lib.getAssertion({ credentials: navigator.credentials, digest: lib.fromBase64('${Buffer.from(digest).toString('base64')}'), rpId: 'localhost', credentialId: lib.fromBase64Url('${made.cred}') });
      return { args: a.args, highS: a.highS };`);
    if (got.highS) high += 1;
    assert.equal(isHighS(fromHex(got.args.signature)), false);
    assert.equal(refusalOf({ assertion: got.args, digest, pubkey, rpIdHash: rpIdHashOf('localhost'), origins: [plain.origin] }), null);
    assert.equal(refusalOf({ assertion: got.args, digest: label('other'), pubkey, rpIdHash: rpIdHashOf('localhost'), origins: [plain.origin] }), 'webauthn: wrong challenge');
  }
  t.diagnostic(`virtual authenticator: ${high} of ${TAPS} assertions came high-S before normalising`);
});

test('Chrome and the real wasm: a passkey vault, the thief\'s proposal, Cancel, all from page code. [mock-signer] [virtual authenticator]', { skip: skip || (stageAvailable() ? false : 'set NEAR_SANDBOX_BIN_PATH and UNDO_WASM_DIR to run this against the real wasm'), timeout: 180_000 }, async () => {
  const stage = await startStage({ miner: false, softPasskey: false });
  try {
    await cdp.open(`${stage.origin}/`);
    const relay = stage.relay.accountId;
    // Everything below up to the send runs in the page, with its CSP, against the local RPC.
    const made = await cdp.page(`${IMPORT}
      const config = await lib.loadConfig();
      const reader = new lib.NearReader({ urls: config.rpc, timeoutMs: 15000 });
      const views = lib.contractViews(reader, config.contract);
      const instance = await views.instance();
      const p = await lib.createPasskey({ credentials: navigator.credentials, rpId: config.rpId });
      const keys = lib.newVaultKeys();
      const vaultHex = lib.vaultIdOf({ contract: config.contract, keys, passkeyPub: p.pubkey, csv: 6 });
      const hex = Array.from(vaultHex, (x) => x.toString(16).padStart(2, '0')).join('');
      const km = await lib.derivedKey(reader, { signer: instance.signer, domainId: instance.domain_id, contract: config.contract, vaultHex: hex });
      const chainNow = (await reader.blockTime()).blockMs;
      const built = await lib.buildCreateArgs({
        contract: config.contract, keys, passkeyPub: p.pubkey, rpIdHash: lib.rpIdHashOf(config.rpId), km, guard: '${relay}', policy: instance.policy, csv: 6, expiresAt: chainNow + 1800000,
        assert: async (digest) => (await lib.getAssertion({ credentials: navigator.credentials, digest, rpId: config.rpId, credentialId: p.credentialId })).args,
      });
      globalThis.film = { lib, config, reader, views, instance, p, keys, hex };
      return { args: built.args, vaultHex: built.vaultHex, shape: lib.relayBodyProblem({ method: 'create_vault', args: built.args, pow: 0 }) };`);
    assert.equal(made.shape, null);
    const spec = RELAY_METHODS.create_vault;
    const created = await stage.near.sendAndWait(stage.relay, stage.contract, [
      action.call('create_vault', { args: made.args }, BigInt(spec.tgas) * TGAS, stage.milliNear(CREATE_DEPOSIT_MILLI)),
      action.call('heartbeat', { vault: made.vaultHex }, BigInt(spec.heartbeatTgas) * TGAS, 0n),
    ]);
    assert.equal(failureOf(created.result), null, 'the real wasm took a real browser\'s pop_p');

    const proposal = await cdp.page(`const { lib, config, reader, views, keys, hex } = globalThis.film;
      const vault = await views.vault(hex);
      const script = lib.fromBase64(btoa(String.fromCharCode(...(await views.script(hex)).match(/../g).map((b) => parseInt(b, 16)))));
      const to = script.slice(0, 0).constructor.from([0, 20, ...new Array(20).fill(7)]);
      const coin = { txid: 'ab'.repeat(32), vout: 0, value: 2000 };
      const spend = lib.sendEverything({ coins: [coin], to, script, feeRate: 2 });
      const chainNow = (await reader.blockTime()).blockMs;
      const args = lib.buildPropose({ contract: config.contract, vault, script, seed: keys.seed, inputs: spend.inputs, to, amount: spend.amount, nonce: vault.spend_nonce, expiresAt: chainNow + 1800000 });
      return { args, active: vault.active, online: vault.guard_online, shape: lib.relayBodyProblem({ method: 'propose_btc', args }) };`);
    assert.deepEqual([proposal.active, proposal.online, proposal.shape], [true, true, null]);
    const proposed = await stage.near.sendAndWait(stage.relay, stage.contract, [action.call('propose_btc', proposal.args, 40n * TGAS, 0n)]);
    assert.equal(failureOf(proposed.result), null);
    const request = returnValue(proposed.result);

    const waiting = await cdp.page(`const { lib, reader, views, hex } = globalThis.film;
      const { vault, request } = await views.both(hex, ${request});
      const sample = await reader.blockTime();
      const c = lib.clock(request.unlock, sample, Date.now(), request.proposed_at);
      globalThis.film.seen = request;
      return { state: lib.requestState({ request, vault, chainNow: c.chainNow }).kind, text: c.text, delay: request.unlock - request.proposed_at };`);
    assert.equal(waiting.state, 'waiting');
    assert.equal(waiting.delay, 300000);
    assert.match(waiting.text, /^[45]:\d\d\.\d$/);

    const tap = await cdp.page(`const { lib, config, reader, views, p, hex } = globalThis.film;
      const vault = await views.vault(hex);
      const newKs = lib.spendKeys(crypto.getRandomValues(new Uint8Array(32))).ks.pub;
      const expiresAt = (await reader.blockTime()).blockMs + 600000;
      const digest = lib.rotateDigest({ contract: config.contract, vaultHex: hex, newKs, nonce: vault.passkey_nonce, expiresAt });
      const a = await lib.getAssertion({ credentials: navigator.credentials, digest, rpId: config.rpId, credentialId: p.credentialId });
      const args = lib.rotateArgs({ vaultHex: hex, newKs, nonce: vault.passkey_nonce, expiresAt, assertion: a.args });
      return { args, shape: lib.relayBodyProblem({ method: 'cancel_all_and_rotate', args }) };`);
    assert.equal(tap.shape, null);
    const rotated = await stage.near.sendAndWait(stage.relay, stage.contract, [action.call('cancel_all_and_rotate', tap.args, 30n * TGAS, 0n)]);
    assert.equal(failureOf(rotated.result), null, 'the real wasm took a real browser\'s cancel');

    const frozen = await cdp.page(`const { lib, reader, views, hex, seen } = globalThis.film;
      const { vault, request } = await views.both(hex, ${request});
      const chainNow = (await reader.blockTime()).blockMs;
      return { status: request.status, state: lib.requestState({ request, vault, chainNow, lastKnown: seen }).kind, suspended: vault.k_s_suspended };`);
    assert.deepEqual(frozen, { status: 'Pending', state: 'cancelled', suspended: true });
  } finally {
    await stage.stop();
  }
});
