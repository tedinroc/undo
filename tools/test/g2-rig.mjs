// The local stage for a G2 rehearsal: real bitcoind on regtest with standard relay policy, an Esplora
// stand-in over it, a local NEAR node with the real wasm, and a mock signer. Test keys only, thrown
// away with the folder. The faults below break one thing at a time. Sandbox only, never live.
import { spawn } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer as httpServer } from 'node:http';
import { createServer as tcpServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { p2wpkhAddress, parseTx, serialize, txid as txidOf } from '../lib/btc.mjs';
import { base58Encode, concat, fromHex, toHex } from '../lib/bytes.mjs';
import { randomBytes, secp256k1, sha256 } from '../lib/crypto.mjs';
import { publicSecp } from '../lib/keys.mjs';
import { action, failureOf, keyFromSecret, loadKeyFile, NEAR, Near, TGAS } from '../lib/near.mjs';
import { answer, startMockNode } from './mock-node.mjs';

const TOOLS = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const REPO = resolve(TOOLS, '..');
const ORIGIN = 'https://undo-btc.pages.dev';
const N = secp256k1.CURVE.n;

export const RIG_FAULTS = [
  'signer-garbage', 'signer-wrong-key', 'signer-high-s', 'signer-silent',
  'relay-flaky', 'relay-landed-5xx', 'relay-down-escape', 'relay-down-cosigned',
  'refusal-wrong-text', 'early-accepted', 'node-rejects-cosigned',
];

const freePort = () => new Promise((res) => {
  const s = tcpServer().listen(0, '127.0.0.1', () => {
    const { port } = s.address();
    s.close(() => res(port));
  });
});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const sats = (btc) => Math.round(btc * 1e8);

// ---------------------------------------------------------------- faults in signatures

function strictDer(r, s) {
  const int = (x) => {
    let hex = x.toString(16);
    if (hex.length % 2) hex = `0${hex}`;
    let bytes = fromHex(hex);
    if (bytes[0] & 0x80) bytes = concat(Uint8Array.of(0), bytes);
    return concat(Uint8Array.of(2, bytes.length), bytes);
  };
  const body = concat(int(r), int(s));
  return concat(Uint8Array.of(0x30, body.length), body, Uint8Array.of(1));
}

/** The contract's bytes, with the signer's signature broken after the contract built them. */
export function tamperFinalTx(hex, kind) {
  const tx = parseTx(fromHex(hex));
  const w = tx.inputs[0].witness;
  const sig = w[0];
  const lenR = sig[3];
  const r = BigInt(`0x${toHex(sig.slice(4, 4 + lenR))}`);
  const s = BigInt(`0x${toHex(sig.slice(6 + lenR, sig.length - 1))}`);
  if (kind === 'high-s') w[0] = strictDer(r, N - s);
  else if (kind === 'bad-sig') w[0] = strictDer(r, s === 1n ? 2n : s - 1n);
  else throw new Error('no such tamper');
  return toHex(serialize(tx));
}

function flipS(response) {
  const s = BigInt(`0x${response.s.scalar}`);
  const recovery = response.recovery_id ^ 1;
  const r = response.big_r.affine_point.slice(2);
  return {
    ...response,
    big_r: { affine_point: `${recovery & 1 ? '03' : '02'}${r}` },
    s: { scalar: (N - s).toString(16).padStart(64, '0') },
    recovery_id: recovery,
  };
}

// ---------------------------------------------------------------- the rig

export async function startRig({ log = () => {}, protocol = 88, blockMs = 1500 } = {}) {
  const sandboxBin = process.env.NEAR_SANDBOX_BIN_PATH;
  if (!sandboxBin) throw new Error('set NEAR_SANDBOX_BIN_PATH');
  const wasmDir = process.env.UNDO_WASM_DIR ?? join(process.env.CARGO_TARGET_DIR ?? join(REPO, 'target'), 'near');
  for (const f of ['undo_vault', 'mock_signer']) {
    if (!existsSync(join(wasmDir, `${f}.wasm`))) throw new Error(`no ${f}.wasm, run scripts/build.sh`);
  }
  const binDir = process.env.UNDO_BITCOIN_BIN ?? join(REPO, 'crates/undo-btc/.tools/bitcoin-32.1/bin');
  const work = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'undo-g2-rig-'));
  const children = [];
  const killAll = () => {
    for (const c of children) {
      try {
        c.kill('SIGKILL');
      } catch {
        // Already gone.
      }
    }
  };
  process.on('exit', () => {
    killAll();
    rmSync(work, { recursive: true, force: true });
  });

  // ------------------------------------------------------------ bitcoind
  const rpcPort = await freePort();
  const datadir = join(work, 'bitcoin');
  mkdirSync(datadir);
  children.push(spawn(join(binDir, 'bitcoind'), ['-regtest', '-server=1', '-listen=0', '-dnsseed=0', '-fixedseeds=0', '-discover=0', '-disablewallet=1', '-acceptnonstdtxn=0', '-txindex=1', '-printtoconsole=0', '-dbcache=8', '-par=1', `-datadir=${datadir}`, `-rpcport=${rpcPort}`], { stdio: 'ignore' }));
  const cookiePath = join(datadir, 'regtest', '.cookie');
  const auth = () => `Basic ${Buffer.from(readFileSync(cookiePath, 'utf8').trim()).toString('base64')}`;
  let rpcId = 0;
  const rpc = async (method, params = []) => {
    const res = await fetch(`http://127.0.0.1:${rpcPort}/`, {
      method: 'POST',
      headers: { authorization: auth(), 'content-type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '1.0', id: (rpcId += 1), method, params }),
    });
    const data = await res.json();
    if (data.error) {
      const err = new Error(JSON.stringify(data.error));
      err.rpc = data.error;
      throw err;
    }
    return data.result;
  };
  for (let i = 0; ; i += 1) {
    try {
      await rpc('getblockcount');
      break;
    } catch (err) {
      if (i > 300) throw new Error(`bitcoind did not start: ${err.message}`);
      await sleep(200);
    }
  }

  const testKey = (label) => sha256(new TextEncoder().encode(`undo-test-only:g2-rig:${label}:${toHex(randomBytes(8))}`));
  const minerAddress = p2wpkhAddress('regtest', publicSecp(testKey('miner')));
  const dispenserSecret = testKey('dispenser');
  const dispenserAddress = p2wpkhAddress('regtest', publicSecp(dispenserSecret));
  const dispenserFile = join(work, 'dispenser.json');
  const writeDispenser = (path, secret, address) => {
    writeFileSync(path, JSON.stringify({ format: 'undo-dispenser-v1', network: 'regtest', secret: toHex(secret), address }), { mode: 0o600 });
  };
  writeDispenser(dispenserFile, dispenserSecret, dispenserAddress);
  // One coinbase for the dispenser, then the 100 blocks it must wait to be spendable.
  await rpc('generatetoaddress', [1, dispenserAddress]);
  await rpc('generatetoaddress', [100, minerAddress]);

  // ------------------------------------------------------------ the Esplora stand-in
  const rig = { fault: null, rule: null, posts: [], gets: 0, flakyCount: new Map() };
  const spends = new Map();
  let scanLock = Promise.resolve();
  const scan = (address) => {
    const run = scanLock.then(() => rpc('scantxoutset', ['start', [`addr(${address})`]]));
    scanLock = run.catch(() => {});
    return run;
  };

  async function utxosOf(address) {
    const scanned = await scan(address);
    const list = [];
    for (const u of scanned.unspents) {
      list.push({ txid: u.txid, vout: u.vout, value: sats(u.amount), status: { confirmed: true, block_height: u.height, block_hash: await rpc('getblockhash', [u.height]) } });
    }
    const mempool = await rpc('getrawmempool');
    const out = [];
    for (const id of mempool) {
      const tx = await rpc('getrawtransaction', [id, 1]).catch(() => null);
      if (!tx) continue;
      for (const vin of tx.vin) {
        const at = list.findIndex((c) => c.txid === vin.txid && c.vout === vin.vout);
        if (at >= 0) list.splice(at, 1);
      }
      tx.vout.forEach((o) => {
        if (o.scriptPubKey.address === address) out.push({ txid: id, vout: o.n, value: sats(o.value), status: { confirmed: false } });
      });
    }
    return [...list, ...out];
  }

  async function txJson(id) {
    let tx;
    try {
      tx = await rpc('getrawtransaction', [id, 1]);
    } catch (err) {
      if (err.rpc?.code === -5) return null;
      throw err;
    }
    let status = { confirmed: false };
    if (tx.blockhash) {
      const header = await rpc('getblockheader', [tx.blockhash]);
      status = { confirmed: true, block_height: header.height, block_hash: tx.blockhash };
    }
    return {
      hex: tx.hex,
      json: {
        txid: tx.txid,
        version: tx.version,
        locktime: tx.locktime,
        vin: tx.vin.map((v) => ({ txid: v.txid, vout: v.vout, sequence: v.sequence, witness: v.txinwitness ?? [] })),
        vout: tx.vout.map((o) => ({ scriptpubkey: o.scriptPubKey.hex, value: sats(o.value) })),
        status,
      },
    };
  }

  const kindOf = (parsed) => {
    const count = parsed.inputs[0].witness.length;
    return count === 4 ? 'cosigned' : count === 3 ? 'escape' : 'funding';
  };

  /** Returns what the relay answers for this POST, or null to pass it to the node. */
  function postFault(kind, raw, id) {
    const seen = rig.flakyCount.get(raw) ?? 0;
    rig.flakyCount.set(raw, seen + 1);
    switch (rig.fault) {
      case 'relay-flaky':
        if (seen === 0) return { status: 503, body: 'Service Unavailable' };
        if (seen === 1) return { status: 429, body: 'Too Many Requests' };
        if (seen === 2) return { drop: true };
        if (seen === 3) return { status: 502, body: '<html><body>Bad Gateway</body></html>' };
        return null;
      case 'relay-landed-5xx':
        return seen === 0 ? { status: 502, body: 'Bad Gateway', forward: true } : null;
      case 'relay-down-escape':
        return kind === 'escape' ? { status: 503, body: 'Service Unavailable' } : null;
      case 'relay-down-cosigned':
        return kind === 'cosigned' ? { status: 503, body: 'Service Unavailable' } : null;
      case 'refusal-wrong-text':
        return kind === 'escape' ? { status: 400, body: 'sendrawtransaction RPC error: {"code":-26,"message":"min relay fee not met, 100 < 121"}' } : null;
      case 'early-accepted':
        return kind === 'escape' && seen === 0 ? { status: 200, body: id } : null;
      case 'node-rejects-cosigned':
        return kind === 'cosigned' ? { status: 400, body: 'sendrawtransaction RPC error: {"code":-26,"message":"mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)"}' } : null;
      default:
        return null;
    }
  }

  async function forward(raw, id, parsed) {
    try {
      const sent = await rpc('sendrawtransaction', [raw]);
      for (const input of parsed.inputs) spends.set(`${input.coin.txid}:${input.coin.vout}`, id);
      return { status: 200, body: sent };
    } catch (err) {
      return { status: 400, body: `sendrawtransaction RPC error: ${JSON.stringify(err.rpc ?? { message: err.message })}` };
    }
  }

  async function handle(req, res) {
    const url = new URL(req.url, 'http://local');
    const parts = url.pathname.split('/').filter(Boolean);
    const send = (status, body, type = 'text/plain') => {
      res.writeHead(status, { 'content-type': type, 'access-control-allow-origin': '*', 'access-control-allow-methods': 'GET, POST, OPTIONS', 'access-control-allow-headers': 'Content-Type' });
      res.end(body);
    };
    const json = (value) => send(200, JSON.stringify(value), 'application/json');

    if (req.method === 'OPTIONS') return send(204, '');
    // A rehearsal's own relay behaviour for one scenario. Null passes the request on as usual.
    if (rig.rule && req.method === 'GET') {
      const said = await rig.rule({ method: 'GET', path: url.pathname });
      if (said) return send(said.status, said.body, 'application/json');
    }
    if (req.method === 'POST' && url.pathname === '/tx') {
      const chunks = [];
      for await (const c of req) chunks.push(c);
      const raw = Buffer.concat(chunks).toString('utf8').trim();
      let parsed;
      try {
        parsed = parseTx(fromHex(raw));
      } catch {
        return send(400, 'bad tx');
      }
      const kind = kindOf(parsed);
      const id = txidOf(parsed);
      const said = rig.rule ? await rig.rule({ method: 'POST', path: url.pathname, kind, id, parsed, raw }) : null;
      if (said) {
        rig.posts.push({ kind, txid: id, relay: said.status, text: said.body });
        return send(said.status, said.body);
      }
      const fault = postFault(kind, raw, id);
      if (fault?.drop) {
        rig.posts.push({ kind, txid: id, relay: 'dropped' });
        req.socket.destroy();
        return undefined;
      }
      if (fault && !fault.forward) {
        rig.posts.push({ kind, txid: id, relay: fault.status });
        return send(fault.status, fault.body);
      }
      const out = await forward(raw, id, parsed);
      rig.posts.push({ kind, txid: id, node: out.status, text: out.body });
      if (fault?.forward) return send(fault.status, fault.body);
      return send(out.status, out.body);
    }
    if (req.method !== 'GET') return send(405, 'no');
    rig.gets += 1;
    if (rig.fault === 'relay-flaky' && rig.gets % 7 === 0) return send(503, 'Service Unavailable');

    if (url.pathname === '/blocks/tip/height') return send(200, String(await rpc('getblockcount')));
    if (parts[0] === 'block-height') return send(200, await rpc('getblockhash', [Number(parts[1])]));
    if (url.pathname === '/fee-estimates') return json({ 1: 1.0, 6: 1.0 });
    if (parts[0] === 'address' && parts[2] === 'utxo') return json(await utxosOf(parts[1]));
    if (parts[0] === 'tx') {
      const tx = await txJson(parts[1]);
      // Measured on Mutinynet: these two answer for a transaction nobody has heard of, and the rest say 404.
      if (!tx && parts[2] === 'status') return json({ confirmed: false });
      if (!tx && parts[2] === 'outspend') return json({ spent: false });
      if (!tx) return send(404, 'Transaction not found');
      if (parts.length === 2) return json(tx.json);
      if (parts[2] === 'hex') return send(200, tx.hex);
      if (parts[2] === 'status') return json(tx.json.status);
      if (parts[2] === 'outspend') {
        const left = await rpc('gettxout', [parts[1], Number(parts[3]), true]);
        if (left) return json({ spent: false });
        const by = spends.get(`${parts[1]}:${parts[3]}`);
        return json(by ? { spent: true, txid: by } : { spent: true });
      }
    }
    return send(404, 'not found');
  }

  const server = httpServer((req, res) => {
    handle(req, res).catch((err) => {
      res.writeHead(500);
      res.end(err.message);
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const esploraUrl = `http://127.0.0.1:${server.address().port}`;

  // ------------------------------------------------------------ the miner
  let timer = null;
  let mining = false;
  const mineOne = async () => {
    if (mining) return;
    mining = true;
    try {
      await rpc('generatetoaddress', [1, minerAddress]);
    } catch {
      // bitcoind is stopping.
    } finally {
      mining = false;
    }
  };
  const startMiner = () => {
    if (!timer) timer = setInterval(mineOne, blockMs);
  };
  const pauseMiner = () => {
    clearInterval(timer);
    timer = null;
  };

  // ------------------------------------------------------------ the NEAR node
  if (process.env.UNDO_LIBLZMA_DIR) process.env.DYLD_LIBRARY_PATH = process.env.UNDO_LIBLZMA_DIR;
  const home = join(work, 'near');
  const nearRpc = await freePort();
  const nearNet = await freePort();
  await new Promise((res, rej) => {
    const init = spawn(sandboxBin, ['--home', home, 'init', '--fast'], { stdio: 'ignore' });
    init.on('exit', (code) => (code === 0 ? res() : rej(new Error('sandbox init failed'))));
    init.on('error', rej);
  });
  const genesis = JSON.parse(readFileSync(join(home, 'genesis.json'), 'utf8'));
  genesis.protocol_version = protocol;
  genesis.epoch_length = 100000;
  writeFileSync(join(home, 'genesis.json'), JSON.stringify(genesis));
  children.push(spawn(sandboxBin, ['--home', home, 'run', '--rpc-addr', `127.0.0.1:${nearRpc}`, '--network-addr', `127.0.0.1:${nearNet}`], { stdio: 'ignore' }));
  const rpcUrl = `http://127.0.0.1:${nearRpc}`;
  const near = new Near([rpcUrl], { timeoutMs: 30_000 });
  for (let i = 0; ; i += 1) {
    try {
      const status = await near.rpcOnce(rpcUrl, 'status', []);
      if (status.protocol_version === protocol && status.sync_info.latest_block_height > 2) break;
    } catch {
      // Still starting.
    }
    if (i > 300) throw new Error('the local NEAR node did not start');
    await sleep(200);
  }

  const root = loadKeyFile(join(home, 'validator_key.json'));
  const creds = join(work, 'creds');
  mkdirSync(join(creds, 'sandbox'), { recursive: true });
  const makeAccount = async (name, balanceNear) => {
    const accountId = `${name}.${root.accountId}`;
    const key = keyFromSecret(randomBytes(32));
    const sent = await near.sendAndWait(root, accountId, [action.createAccount(), action.transfer(BigInt(balanceNear * 1000) * (NEAR / 1000n)), action.addFullKey(key.pub)]);
    if (failureOf(sent.result)) throw new Error(`could not create ${accountId}: ${failureOf(sent.result)}`);
    const file = join(creds, 'sandbox', `${accountId}.json`);
    writeFileSync(file, JSON.stringify({ account_id: accountId, private_key: `ed25519:${base58Encode(key.secret)}` }), { mode: 0o600 });
    chmodSync(file, 0o600);
    return { ...key, accountId };
  };
  const mock = await makeAccount('mock', 50);
  const mockSecret = sha256(new TextEncoder().encode(`undo-test-only:g2-mock-root:${toHex(randomBytes(8))}`));
  const otherSecret = sha256(new TextEncoder().encode('undo-test-only:g2-wrong-root'));
  const deployedMock = await near.sendAndWait(mock, mock.accountId, [action.deploy(readFileSync(join(wasmDir, 'mock_signer.wasm'))), action.call('new', { secret_hex: toHex(mockSecret), mode: 'Yield' }, 100n * TGAS, 0n)]);
  if (failureOf(deployedMock.result)) throw new Error(`mock deploy failed: ${failureOf(deployedMock.result)}`);
  const payer = await makeAccount('payer', 100);
  const relay = await makeAccount('relay', 50);
  const poor = await makeAccount('poor', 0.01);
  const responder = await makeAccount('node', 50);
  const contract = await makeAccount('undo', 50);
  const deployed = await near.sendAndWait(contract, contract.accountId, [
    action.deploy(readFileSync(join(wasmDir, 'undo_vault.wasm'))),
    action.call('new', {
      preset: 'TestCoin', operator: payer.accountId, restrict_create: false, signer: mock.accountId, domain_id: 0,
      sign_tgas: 15, callback_tgas: 10, derive_tgas: 30, network: 'regtest', origins: [ORIGIN], outflow_cap_24h: 1_000_000,
      operator_passkey: throwawayOperatorPasskey(new URL(ORIGIN).hostname),
    }, 100n * TGAS, 0n),
  ]);
  if (failureOf(deployed.result)) throw new Error(`contract deploy failed: ${failureOf(deployed.result)}`);
  // The driver reads the code hash at final, which lags the deploy by a block or two.
  for (let i = 0; (await near.account(contract.accountId))?.code_hash === '11111111111111111111111111111111'; i += 1) {
    if (i > 100) throw new Error('the deploy never reached final');
    await sleep(100);
  }

  // The signer's faults. Every answer but silence goes through the real wire shape.
  const respond = (args) => {
    switch (rig.fault) {
      case 'signer-garbage':
        return { scheme: 'Secp256k1', big_r: { affine_point: `02${'00'.repeat(32)}` }, s: { scalar: '00'.repeat(32) }, recovery_id: 0 };
      case 'signer-wrong-key':
        return answer({ ...args, secret: otherSecret });
      case 'signer-high-s':
        return flipS(answer(args));
      case 'signer-silent':
        return null;
      default:
        return answer(args);
    }
  };
  const mockNode = startMockNode({ near, mock, responder, secret: mockSecret, respond, again: true });

  const info = {
    label: 'rehearsal rig: regtest, a local NEAR node, a mock signer',
    rpc: rpcUrl,
    esplora: esploraUrl,
    signer: mock.accountId,
    payer: payer.accountId,
    relay: relay.accountId,
    poor: poor.accountId,
    contract: contract.accountId,
    creds,
    dispenser: dispenserFile,
    wasm: join(wasmDir, 'undo_vault.wasm'),
  };
  const infoFile = join(work, 'rig.json');
  writeFileSync(infoFile, JSON.stringify(info), { mode: 0o600 });
  log(`Rig up: regtest at height ${await rpc('getblockcount')}, NEAR protocol ${protocol}`);

  let stopped = false;
  return {
    info,
    infoFile,
    work,
    rpc,
    posts: rig.posts,
    setFault: (name) => {
      if (name !== null && !RIG_FAULTS.includes(name)) throw new Error('no such fault');
      rig.fault = name;
      rig.flakyCount.clear();
    },
    /** `rule` gets each POST and GET and may answer it with { status, body }. */
    setRule: (rule) => {
      rig.rule = rule;
    },
    startMiner,
    pauseMiner,
    mine: (count) => rpc('generatetoaddress', [count, minerAddress]),
    /** A second dispenser file, holding nothing until someone pays it. */
    poorDispenser: () => {
      const secret = testKey('poor-dispenser');
      const address = p2wpkhAddress('regtest', publicSecp(secret));
      const path = join(work, 'dispenser-poor.json');
      writeDispenser(path, secret, address);
      return { path, address };
    },
    async stop() {
      if (stopped) return;
      stopped = true;
      pauseMiner();
      await mockNode.stop();
      server.close();
      server.closeAllConnections?.();
      try {
        await rpc('stop');
      } catch {
        // Already stopping.
      }
      await sleep(300);
      killAll();
      await sleep(200);
      rmSync(work, { recursive: true, force: true });
    },
  };
}
