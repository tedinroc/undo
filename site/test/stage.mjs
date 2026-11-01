// The local stage every page and the relay run on: tools/test/g2-rig.mjs (real bitcoind with standard
// relay policy, an Esplora stand-in, a local NEAR node, a mock signer that answers with the live wire shape),
// plus the real contract deployed for this page's origin, a build of the site with a local config, and a
// static server. Nothing here can reach a live host: checkConfig refuses a local config that names one.
//
//   const stage = await startStage();     stage.pageUrl('/p/', { v: vaultHex })
//   ...
//   await stage.stop();
//
// Run as a script, it stays up and prints what to open:  node site/test/stage.mjs
// Needs NEAR_SANDBOX_BIN_PATH, UNDO_WASM_DIR and UNDO_BITCOIN_BIN, and UNDO_LIBLZMA_DIR where the sandbox
// binary links an outside liblzma.
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { createServer } from 'node:http';
import { createServer as tcpServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, extname, join, normalize, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { startRig } from '../../tools/test/g2-rig.mjs';
import { action, failureOf, keyFromSecret, loadKeyFile, milliNear, NEAR, Near, TGAS } from '../../tools/lib/near.mjs';
import { base58Encode } from '../../tools/lib/bytes.mjs';
import { randomBytes } from '../../tools/lib/crypto.mjs';
import { throwawayOperatorPasskey } from '../../tools/lib/vault-client.mjs';
import { build } from '../build.mjs';
import { buildFragment } from '../lib/fragment.mjs';
import { localStateNamespace } from './do-shim.mjs';

const SITE = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const RELAY_HANDLER = join(SITE, 'functions/_relay/handler.mjs');
const MIME = { '.html': 'text/html; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json', '.svg': 'image/svg+xml', '.png': 'image/png', '.mp4': 'video/mp4', '.webp': 'image/webp', '.woff2': 'font/woff2' };

export const stageAvailable = () => Boolean(process.env.NEAR_SANDBOX_BIN_PATH && process.env.UNDO_WASM_DIR);

const freePort = () => new Promise((res) => {
  const s = tcpServer().listen(0, '127.0.0.1', () => {
    const { port } = s.address();
    s.close(() => res(port));
  });
});

/** Serves a built site the way Pages does: `_headers` on everything, a folder's index.html, /api to the relay. */
export function staticServer({ dir, port, onApi }) {
  const headerLines = existsSync(join(dir, '_headers')) ? readFileSync(join(dir, '_headers'), 'utf8').split('\n').slice(1).filter(Boolean) : [];
  const headers = Object.fromEntries(headerLines.map((line) => {
    const at = line.indexOf(':');
    return [line.slice(0, at).trim(), line.slice(at + 1).trim()];
  }));
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, 'http://local');
    if (url.pathname.startsWith('/api/')) return onApi(req, res, url);
    let path = normalize(join(dir, decodeURIComponent(url.pathname)));
    if (!path.startsWith(dir)) {
      res.writeHead(403);
      return res.end();
    }
    if (existsSync(path) && statSync(path).isDirectory()) path = join(path, 'index.html');
    if (!existsSync(path)) {
      res.writeHead(404, headers);
      return res.end('not found');
    }
    res.writeHead(200, { ...headers, 'content-type': MIME[extname(path)] ?? 'application/octet-stream', 'cache-control': 'no-store' });
    return res.end(readFileSync(path));
  });
  return new Promise((r) => {
    server.listen(port, '127.0.0.1', () => r(server));
  });
}

const notBuilt = (res, code = 503) => {
  res.writeHead(code, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ ok: false, code: 'relay_not_configured', message: 'the local stage has no relay handler yet' }));
};

/** Bridges Node's HTTP to the handler a Pages Function calls, so the same code answers both. */
async function bridge(handler, req, res, url, origin) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  const request = new Request(`${origin}${url.pathname}${url.search}`, {
    method: req.method,
    headers: { ...req.headers, 'cf-connecting-ip': req.socket.remoteAddress ?? '127.0.0.1' },
    body: chunks.length ? Buffer.concat(chunks) : undefined,
  });
  const response = await handler(request);
  res.writeHead(response.status, Object.fromEntries(response.headers));
  res.end(Buffer.from(await response.arrayBuffer()));
}

// tools/test/g2-rig.mjs calls this without importing it. Until that file gets its import, a global keeps the
// rig running. Harmless once it does.
globalThis.throwawayOperatorPasskey ??= throwawayOperatorPasskey;

export async function startStage({ log = () => {}, protocol = 88, blockMs = 1500, port = 0, softPasskey = true, relayEnv = {}, miner = true } = {}) {
  if (!stageAvailable()) throw new Error('set NEAR_SANDBOX_BIN_PATH and UNDO_WASM_DIR');
  const rig = await startRig({ log, protocol, blockMs });
  try {
    return await stageOn(rig, { port, softPasskey, relayEnv, miner });
  } catch (err) {
    await rig.stop();
    throw err;
  }
}

async function stageOn(rig, { port, softPasskey, relayEnv, miner }) {
  const pagePort = port || (await freePort());
  const origin = `http://localhost:${pagePort}`;
  const rpId = 'localhost';
  const near = new Near([rig.info.rpc], { timeoutMs: 30_000 });
  const payer = loadKeyFile(join(rig.info.creds, 'sandbox', `${rig.info.payer}.json`));
  const relay = loadKeyFile(join(rig.info.creds, 'sandbox', `${rig.info.relay}.json`));

  // The rig's own contract allows only the public origin. Pages here need their own.
  const contractKey = { ...keyFromSecret(randomBytes(32)), accountId: `film.${rig.info.payer}` };
  const wasm = readFileSync(rig.info.wasm);
  const opened = await near.sendAndWait(payer, contractKey.accountId, [action.createAccount(), action.transfer(40n * NEAR), action.addFullKey(contractKey.pub)]);
  if (failureOf(opened.result)) throw new Error(`stage account failed: ${failureOf(opened.result)}`);
  // `new` is private, so the contract's own key deploys and calls it.
  const deployed = await near.sendAndWait(contractKey, contractKey.accountId, [
    action.deploy(wasm),
    action.call('new', {
      preset: 'TestCoin', operator: payer.accountId, restrict_create: false, signer: rig.info.signer, domain_id: 0,
      sign_tgas: 30, callback_tgas: 10, derive_tgas: 30, network: 'regtest', origins: [origin], outflow_cap_24h: 1_000_000,
      operator_passkey: throwawayOperatorPasskey(rpId),
    }, 100n * TGAS, 0n),
  ]);
  if (failureOf(deployed.result)) throw new Error(`stage deploy failed: ${failureOf(deployed.result)}`);

  const config = {
    mode: 'local',
    contract: contractKey.accountId,
    rpc: [rig.info.rpc],
    esplora: rig.info.esplora,
    relay: '/api/relay',
    funds: '/api/funds',
    btcTxUrl: null,
    btcAddressUrl: null,
    nearTxUrl: null,
    rpId,
    softPasskey,
  };
  const out = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'undo-stage-dist-'));
  build({ configObject: config, out });

  let handler = null;
  if (existsSync(RELAY_HANDLER)) {
    const { makeRelay } = await import(pathToFileURL(RELAY_HANDLER).href);
    handler = await makeRelay({
      local: true,
      CONTRACT_ID: contractKey.accountId,
      NEAR_RPC_URLS: rig.info.rpc,
      ESPLORA_URL: rig.info.esplora,
      RELAY_ACCOUNT: relay.accountId,
      RELAY_GENERAL_KEY: `ed25519:${base58Encode(relay.secret)}`,
      RELAY_OWNER_KEY: `ed25519:${base58Encode(relay.secret)}`,
      DISPENSER_SECRET: JSON.parse(readFileSync(rig.info.dispenser, 'utf8')).secret,
      DISPENSER_NETWORK: 'regtest',
      IP_SALT: 'undo-test-only:stage',
      POW_BITS: 8,
      UNDO_STATE: localStateNamespace(),
      ...relayEnv,
    });
  }
  const server = await staticServer({
    dir: out,
    port: pagePort,
    onApi: (req, res, url) => (handler ? bridge(handler, req, res, url, origin) : notBuilt(res)).catch((err) => {
      res.writeHead(500);
      res.end(err.message);
    }),
  });
  if (miner) rig.startMiner();

  return {
    origin,
    rpId,
    config,
    near,
    rig,
    payer,
    relay,
    contract: contractKey.accountId,
    signer: rig.info.signer,
    dir: out,
    milliNear,
    pageUrl: (path, fields = {}) => `${origin}${path}${buildFragment(fields)}`,
    async stop() {
      server.close();
      server.closeAllConnections?.();
      await rig.stop();
      rmSync(out, { recursive: true, force: true });
    },
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const stage = await startStage({ log: console.log, port: Number(process.env.STAGE_PORT ?? 0) });
  console.log(`Stage up. Site ${stage.origin}  NEAR ${stage.config.rpc[0]}  Esplora ${stage.config.esplora}  contract ${stage.contract}`);
  const stop = () => stage.stop().then(() => process.exit(0));
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}
