#!/usr/bin/env node
// Step 50. Reads back what went live, and sends nothing that can cost anything: every POST here is one the relay
// must refuse before a key signs, and the two relay keys' nonces are read before and after to prove they signed
// nothing.
//
//   node scripts/go-live/50-readback.mjs --dry-run --public-keys FILE
//   node scripts/go-live/50-readback.mjs --live    --public-keys FILE [--wasm FILE] [--operator-passkey FILE]
//   node scripts/go-live/50-readback.mjs --network sandbox --rpc URL --site http://127.0.0.1:PORT --config FILE --live …
//
// Checks: GET /api/relay and its headers; view_access_key for the three relay keys; the instance view (and code hash,
// with --wasm); /undo-config.json against the repo's config; refused POSTs, among them an owner call and a funding for
// a vault this relay did not make and the shapes the contract cannot parse; the CSP and other headers on every page,
// equal to what site/build.mjs writes for that config; no source map behind any module a page loads; the landing
// page's name and chip. A network failure reads SKIP (network), never PASS. Exit 0 only when no line is FAIL or SKIP.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs, UsageError } from '../../tools/lib/args.mjs';
import { NEAR } from '../../tools/lib/near.mjs';
import { readBack } from './checks.mjs';
import {
  accessKey, connect, CRON_ALLOWANCE_NEAR, CRON_METHODS, line, modeOf, nearOf, note, OWNER_ALLOWANCE_NEAR, OWNER_METHODS,
  permissionProblem, plan, readJson, readOperatorPasskey, Refused, REPO, SITE, wasmFacts,
} from './lib.mjs';

const USAGE = `usage: 50-readback.mjs (--dry-run | --live) --public-keys FILE [--site URL] [--config FILE] [--wasm FILE]
  [--operator-passkey FILE] [--network testnet|sandbox] [--rpc URL] [--sign-tgas N]`;

const PAGES = ['/', '/replay/', '/p/', '/t/'];
const ZERO_VAULT = '00'.repeat(32);
const TIMEOUT_MS = 20_000;
// What a 30 Tgas owner send can hold until its refund lands: below this a cancel cannot be paid for.
const KEY_FLOOR = NEAR / 20n;

class NetworkSkip extends Error {}

const results = [];
function say(verdict, label, text) {
  line(verdict, label, text);
  results.push(verdict);
}

async function http(site, path, { method = 'GET', headers = {}, body } = {}) {
  let res;
  try {
    res = await fetch(new URL(path, site), { method, headers, body, redirect: 'manual', signal: AbortSignal.timeout(TIMEOUT_MS) });
  } catch (err) {
    throw new NetworkSkip(`${method} ${path}: ${err.cause?.code ?? err.name}`);
  }
  const text = await res.text();
  let json = null;
  try {
    json = JSON.parse(text);
  } catch {
    // Not JSON: a page, a module, a refusal from a proxy.
  }
  return { status: res.status, headers: res.headers, text, json };
}

/**
 * Each refused call: what to send, and the status and codes that count as refused, and words the answer must hold.
 * `now` sets the expiry of the calls that must get past it, and `fundsPow` solves the funds proof of work for the
 * all-zero vault, so those two reach the rule they test.
 */
export function refusals({ now = Date.now(), fundsPow = 0 } = {}) {
  const relayPost = (body, extra = {}) => ({ method: 'POST', path: '/api/relay', headers: { 'content-type': 'application/json', ...extra }, body: typeof body === 'string' ? body : JSON.stringify(body) });
  const later = now + 10 * 60_000;
  const webauthn = { authenticator_data: '00'.repeat(37), client_data_json: '7b7d', signature: '00'.repeat(64) };
  return [
    { name: 'a browser Origin that is not this site', ...relayPost({ method: 'activate', args: { vault: ZERO_VAULT } }, { origin: 'https://example.com' }), status: 403, codes: ['bad_origin'] },
    { name: 'a method off the list', ...relayPost({ method: 'upgrade_apply', args: {} }), status: 400, codes: ['unknown_method'] },
    { name: 'heartbeat without the operator token', ...relayPost({ method: 'heartbeat', args: { vault: ZERO_VAULT } }), status: 400, codes: ['unknown_method'] },
    { name: 'a body that is not JSON', ...relayPost('not json'), status: 400, codes: ['bad_request'] },
    { name: 'a body over the cap', ...relayPost(JSON.stringify({ method: 'activate', args: { vault: ZERO_VAULT }, pad: 'x'.repeat(25 * 1024) })), status: 400, codes: ['bad_request'] },
    { name: 'create_vault with no arguments', ...relayPost({ method: 'create_vault', args: {} }), status: 400, codes: ['bad_request'] },
    { name: 'a cold-key cancel on a vault that does not exist', ...relayPost({ method: 'cancel', args: { vault: ZERO_VAULT, request: 0, expires_at: 0, auth: { Cold: '00'.repeat(65) } } }), status: 422, codes: ['assertion_refused', 'would_refuse'] },
    {
      name: 'an owner call for a vault this relay did not make',
      ...relayPost({ method: 'cancel', args: { vault: ZERO_VAULT, request: 0, expires_at: later, auth: { Cold: '00'.repeat(65) } } }),
      status: 422, codes: ['not_this_relays'], words: ['tools/cancel.mjs', 'tools/freeze.mjs --method cancel'],
    },
    { name: 'a WebAuthn assertion with a field the contract does not have', ...relayPost({ method: 'cancel_all_and_rotate', args: { vault: ZERO_VAULT, new_k_s: '00'.repeat(32), nonce: 0, expires_at: later, assertion: { ...webauthn, user_handle: '00' } } }), status: 400, codes: ['bad_request'] },
    { name: 'a cancel naming both the passkey and the cold key', ...relayPost({ method: 'cancel', args: { vault: ZERO_VAULT, request: 0, expires_at: later, auth: { Passkey: webauthn, Cold: '00'.repeat(65) } } }), status: 400, codes: ['bad_request'] },
    { name: 'PUT on the relay', method: 'PUT', path: '/api/relay', headers: {}, body: undefined, status: 405, codes: ['bad_request'] },
    { name: 'GET on funds', method: 'GET', path: '/api/funds', headers: {}, body: undefined, status: 405, codes: ['bad_request'] },
    { name: 'funds with no vault', method: 'POST', path: '/api/funds', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ vault: 'zz' }), status: 400, codes: ['bad_request'] },
    { name: 'funds for a vault this relay did not make', method: 'POST', path: '/api/funds', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ vault: ZERO_VAULT, pow: fundsPow }), status: 422, codes: ['would_refuse'], words: ['only funds vaults it made'] },
  ];
}

/** The funds proof of work for the all-zero vault at the relay's own bits, with the page's own solver. */
async function zeroVaultPow(bits) {
  const pow = await import(pathToFileURL(join(REPO, 'site', 'lib', 'pow.mjs')).href);
  return pow.solvePow(pow.fundsPowTarget(ZERO_VAULT), bits);
}

/** Module and stylesheet paths a page loads, from its own HTML. */
export function assetsOf(html) {
  const out = new Set();
  for (const m of html.matchAll(/<(?:script|link)\b[^>]*\b(?:src|href)="(\/[^"]+\.(?:mjs|js|css))"/g)) out.add(m[1]);
  return [...out];
}

async function main() {
  const a = parseArgs(process.argv.slice(2), {
    'dry-run': 'flag', live: 'flag', network: 'text', rpc: 'text', site: 'text', config: 'text', 'public-keys': 'text', wasm: 'text',
    'operator-passkey': 'text', 'sign-tgas': 'int',
  });
  const { network, live, defaults } = modeOf(a, USAGE);
  if (!a['public-keys']) throw new Refused(`give --public-keys FILE, the .public.json 20-relay-keys.mjs wrote\n${USAGE}`);
  const keys = readJson(a['public-keys'], 'public keys file');
  if (!keys.contract || !keys.relay_account || !keys.keys) throw new Refused('the public keys file has no contract, relay account or keys');
  if (Object.values(keys.keys).some((k) => k.secret_key)) throw new Refused('that file holds secret keys. Pass the .public.json copy');
  const site = a.site ?? SITE.origin;
  const configPath = a.config ?? join(REPO, 'site', 'config', 'testnet.json');
  const label = defaults.label;
  const { contract, relay_account: relay } = keys;

  console.log(`50-readback: ${live ? 'LIVE READS' : 'DRY RUN'} on ${network} [${label}], site ${site}`);
  note(`contract ${contract}, relay account ${relay}`);
  plan(`GET ${site}/api/relay`);
  plan(`view_access_key on ${relay} for ${Object.keys(keys.keys).join(', ')}`);
  plan(`view instance and status on ${contract}${a.wasm ? ', and its code hash against --wasm' : ''}`);
  plan(`GET ${site}/undo-config.json against ${configPath}`);
  for (const r of refusals()) plan(`${r.method} ${r.path}: ${r.name}, must answer ${r.status} ${r.codes.join(' or ')}`);
  plan(`headers on ${PAGES.join(', ')}; a .map behind every module they load`);
  if (!live) {
    console.log('DRY RUN: nothing read, nothing sent.');
    return 0;
  }

  const { near } = await connect(network, a.rpc);
  const { buildModule, config } = await loadBuild(configPath);
  let powBits = null;
  const guarded = async (name, fn) => {
    try {
      await fn();
    } catch (err) {
      if (err instanceof NetworkSkip) say('SKIP', label, `(network) ${name}: ${err.message}`);
      else say('FAIL', label, `${name}: ${err.message}`);
    }
  };

  // ---------------------------------------------------------------- the relay's own answer
  await guarded('GET /api/relay', async () => {
    const r = await http(site, '/api/relay');
    const j = r.json ?? {};
    powBits = Number.isSafeInteger(j.pow_bits) ? j.pow_bits : null;
    say(r.status === 200 && j.ok === true ? 'PASS' : 'FAIL', label, `GET /api/relay answers ${r.status} ok=${j.ok}`);
    say(j.relay_account === relay ? 'PASS' : 'FAIL', label, `relay_account is ${j.relay_account}`);
    say(j.contract === contract ? 'PASS' : 'FAIL', label, `contract is ${j.contract}`);
    for (const bucket of ['owner', 'general']) say(j[bucket]?.up === true ? 'PASS' : 'FAIL', label, `${bucket}: up=${j[bucket]?.up} why=${j[bucket]?.why ?? null}${j[bucket]?.degraded ? ' degraded' : ''}`);
    say(j.funds?.up === true ? 'PASS' : 'WARN', label, `funds: up=${j.funds?.up} why=${j.funds?.why ?? null} sats=${j.funds?.sats}`);
    say(r.headers.get('cache-control') === 'no-store' ? 'PASS' : 'FAIL', label, `/api/relay Cache-Control is ${r.headers.get('cache-control')}`);
    say(r.headers.get('access-control-allow-origin') === null ? 'PASS' : 'FAIL', label, `/api/relay sends ${r.headers.get('access-control-allow-origin') === null ? 'no' : 'a'} CORS header`);
  });

  // ---------------------------------------------------------------- keys on chain
  const want = {
    RELAY_GENERAL_KEY: { full: true },
    RELAY_OWNER_KEY: { receiver: contract, methods: [...OWNER_METHODS], allowance: nearOf(OWNER_ALLOWANCE_NEAR) },
    RELAY_CRON_KEY: { receiver: contract, methods: [...CRON_METHODS], allowance: nearOf(CRON_ALLOWANCE_NEAR) },
  };
  const nonces = {};
  for (const [name, perm] of Object.entries(want)) {
    await guarded(`${name} on chain`, async () => {
      const k = keys.keys[name];
      if (!k) throw new Error('not in the public keys file');
      const access = await accessKey(near, relay, k.public_key);
      const problem = permissionProblem(access, perm);
      say(problem ? 'FAIL' : 'PASS', label, `${name} ${k.public_key}: ${problem ?? (perm.full ? 'FullAccess' : `FunctionCall to ${perm.receiver}, [${perm.methods.join(', ')}]`)}`);
      if (access?.permission?.FunctionCall) {
        const left = BigInt(access.permission.FunctionCall.allowance);
        say(left >= KEY_FLOOR ? 'PASS' : 'FAIL', label, `${name} allowance left ${Number(left / 10n ** 21n) / 1000} NEAR`);
      }
      if (access) nonces[name] = access.nonce;
    });
  }

  // ---------------------------------------------------------------- the instance
  await guarded('instance view', async () => {
    const facts = a.wasm ? wasmFacts(a.wasm) : null;
    const operatorPasskey = a['operator-passkey'] ? readOperatorPasskey(a['operator-passkey'], SITE.rpId) : null;
    const instance = await near.view(contract, 'instance');
    const verdicts = await readBack({ near, contract, expect: { signer: defaults.signer ?? instance.signer, parent: defaults.parent ?? instance.operator, signTgas: a['sign-tgas'] ?? 30, operatorPasskey }, facts, label });
    results.push(...verdicts);
    if (network === 'sandbox') note('sandbox: the signer is whatever mock this instance names, so it is read, not compared');
  });

  // ---------------------------------------------------------------- the page's config
  await guarded('undo-config.json', async () => {
    const r = await http(site, '/undo-config.json');
    const served = r.json ?? {};
    const expected = JSON.parse(JSON.stringify({ ...config, labels: undefined }));
    say(r.status === 200 && JSON.stringify(served) === JSON.stringify(expected) ? 'PASS' : 'FAIL', label, `/undo-config.json ${r.status} ${JSON.stringify(served) === JSON.stringify(expected) ? 'equals' : 'differs from'} the repo's config`);
    say(served.contract === contract ? 'PASS' : 'FAIL', label, `the page's config names ${served.contract}`);
    if (served.h7 === true) say('WARN', label, 'the page is in test mode (h7): right for H7, wrong for the final deploy');
  });

  // ---------------------------------------------------------------- refused POSTs, and the keys signed nothing
  const sent = refusals({ now: Date.now(), fundsPow: powBits === null ? 0 : await zeroVaultPow(powBits) });
  for (const r of sent) {
    await guarded(r.name, async () => {
      const out = await http(site, r.path, { method: r.method, headers: r.headers, body: r.body });
      const code = out.json?.code ?? null;
      const missing = (r.words ?? []).filter((w) => !String(out.json?.message ?? '').includes(w));
      const ok = out.status === r.status && r.codes.includes(code) && missing.length === 0;
      const why = missing.length ? `, its message lacks "${missing.join('", "')}"` : `, expected ${r.status} ${r.codes.join(' or ')}`;
      say(ok ? 'PASS' : 'FAIL', label, `refused ${r.name}: ${out.status} ${code}${ok ? '' : why}`);
    });
  }
  for (const name of ['RELAY_GENERAL_KEY', 'RELAY_OWNER_KEY']) {
    await guarded(`${name} nonce`, async () => {
      if (nonces[name] === undefined) throw new Error('no nonce read before the POSTs');
      const after = (await accessKey(near, relay, keys.keys[name].public_key))?.nonce;
      say(after === nonces[name] ? 'PASS' : 'FAIL', label, `${name} nonce ${nonces[name]} before the refused POSTs, ${after} after${after === nonces[name] ? ': it signed nothing' : ': something was signed, or other traffic ran'}`);
    });
  }

  // ---------------------------------------------------------------- headers and source maps
  const wanted = parseHeaders(buildModule.headersFor(config));
  for (const page of PAGES) {
    await guarded(`headers on ${page}`, async () => {
      const r = await http(site, page);
      say(r.status === 200 ? 'PASS' : 'FAIL', label, `GET ${page} answers ${r.status}`);
      for (const [name, value] of Object.entries(wanted)) {
        const got = r.headers.get(name);
        say(got === value ? 'PASS' : 'FAIL', label, `${page} ${name}${got === value ? ' as built' : `: ${got === null ? 'missing' : `"${got}"`}, expected "${value}"`}`);
      }
      if (page === '/') {
        say(/<title>Undo for Bitcoin<\/title>/.test(r.text) ? 'PASS' : 'FAIL', label, 'the landing page is titled Undo for Bitcoin');
        // The HTML draws the testnet chip; a local build's script swaps in its own words after loading the config.
        const drawn = config.mode === 'testnet' ? r.text.includes(`id="chip" class="chip">${config.labels.chip}<`) : r.text.includes('id="chip" class="chip">');
        say(drawn ? 'PASS' : 'FAIL', label, `the landing page draws the chip${config.mode === 'testnet' ? ` "${config.labels.chip}"` : ''} before any script`);
      }
      for (const asset of assetsOf(r.text)) {
        const body = await http(site, asset);
        if (body.text.includes('sourceMappingURL')) say('FAIL', label, `${asset} points at a source map`);
        const map = await http(site, `${asset}.map`);
        const isMap = map.status === 200 && map.json && typeof map.json.mappings === 'string';
        say(isMap ? 'FAIL' : 'PASS', label, `${asset}.map ${isMap ? 'is served' : `is not a source map (${map.status})`}`);
      }
    });
  }

  const count = (v) => results.filter((x) => x === v).length;
  console.log(`READBACK: ${count('PASS')} PASS, ${count('FAIL')} FAIL, ${count('SKIP')} SKIP, ${count('WARN')} WARN`);
  return count('FAIL') + count('SKIP') > 0 ? 1 : 0;
}

/** site/build.mjs from the merged tree, and the config it would build with. */
async function loadBuild(configPath) {
  let buildModule;
  let configModule;
  try {
    buildModule = await import(pathToFileURL(join(REPO, 'site', 'build.mjs')).href);
    configModule = await import(pathToFileURL(join(REPO, 'site', 'lib', 'config.mjs')).href);
  } catch {
    throw new Refused('site/build.mjs is not in this tree: merge the web branch first');
  }
  const config = configModule.checkConfig(JSON.parse(readFileSync(configPath, 'utf8')));
  return { buildModule, config };
}

/** `_headers` text to {lower-case name: value}, for the /* block. */
export function parseHeaders(text) {
  const out = {};
  for (const raw of text.split('\n').slice(1)) {
    const at = raw.indexOf(':');
    if (at > 0) out[raw.slice(0, at).trim().toLowerCase()] = raw.slice(at + 1).trim();
  }
  return out;
}

if (process.argv[1]?.endsWith('50-readback.mjs')) {
  main().then((code) => process.exit(code)).catch((err) => {
    if (err instanceof UsageError) {
      console.error(`${err.message}\n${USAGE}`);
      process.exit(2);
    }
    if (err instanceof Refused) {
      console.error(`REFUSED: ${err.message}`);
      process.exit(3);
    }
    console.error(`ERROR: ${err.message}`);
    process.exit(1);
  });
}
