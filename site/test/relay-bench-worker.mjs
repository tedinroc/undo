// What the relay does between its I/O, in a loop, with its I/O answered from memory. Run by relay-bench.mjs.
import { buildFunding, dispenserFromSecret } from '../functions/_relay/funding.mjs';
import { makeRelay } from '../functions/_relay/handler.mjs';
import { parseTx, txid } from '../../tools/lib/btc.mjs';
import { base58Encode, fromHex } from '../../tools/lib/bytes.mjs';
import { sha256 } from '../../tools/lib/crypto.mjs';
import { callAction, signedTransaction } from '../lib/near-tx.mjs';
import { relayKey } from '../functions/_relay/near-send.mjs';

const label = (t) => sha256(new TextEncoder().encode(`undo-test-only:bench:${t}`));
const SEED = `ed25519:${base58Encode(label('key'))}`;
const HASH = base58Encode(label('block'));
const respond = (result) => new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), { headers: { 'content-type': 'application/json' } });
const encoded = (value) => [...new TextEncoder().encode(JSON.stringify(value))];

function memoryNamespace() {
  let nonce = 1000;
  const answers = {
    charge: { ok: true },
    addCost: { ok: true },
    refund: { ok: true },
    lease: () => ({ nonce: (nonce += 1) }),
    status: { ok: true, spent: { general: 0, owner: 0, funds: 0 }, resets_at: 0, coins: { free_sats: 0, refreshed_at: null } },
    funded: { ok: true, already: false },
    reserveCoin: () => ({ ok: true, coins: [{ txid: 'cd'.repeat(32), vout: (nonce += 1), value: 1_000_000 }] }),
    commitCoin: { ok: true },
    fundedDone: { ok: true },
  };
  return {
    idFromName: () => 'x',
    get: () => ({
      fetch: async (url) => {
        const op = new URL(url).pathname.slice(1);
        const a = answers[op];
        return new Response(JSON.stringify(typeof a === 'function' ? a() : a));
      },
    }),
  };
}

const fakeRpc = (vaultView) => async (url, init) => {
  if (url.endsWith('/tx')) return new Response(txid(parseTx(fromHex(init.body))));
  if (url.endsWith('/utxo')) return new Response('[]');
  const body = JSON.parse(init.body);
  if (body.method === 'block') return respond({ header: { hash: HASH, height: 10, timestamp_nanosec: '1000000000000' } });
  if (body.method === 'send_tx') return respond({ final_execution_status: 'INCLUDED' });
  if (body.method === 'query') return respond({ result: encoded(vaultView), block_height: 10, logs: [] });
  throw new Error(`no fake for ${body.method}`);
};

let relayEnv = null;
let relay = null;
function relayWith(vaultView) {
  relayEnv = { BEAT_TOKEN: 'bench', CONTRACT_ID: 'c.test', RELAY_ACCOUNT: 'r.test', NEAR_RPC_URLS: 'http://rpc.fake', ESPLORA_URL: 'http://esplora.fake', DISPENSER_SECRET: DISPENSER, DISPENSER_NETWORK: 'mutinynet', RELAY_GENERAL_KEY: SEED, RELAY_OWNER_KEY: SEED, IP_SALT: 's', POW_BITS: '0', UNDO_STATE: memoryNamespace() };
  relay = makeRelay(relayEnv, { fetchFn: fakeRpc(vaultView) });
  return relay;
}

const DISPENSER = 'aa'.repeat(32);
const PAY_TO = Uint8Array.from([0, 32, ...new Array(32).fill(7)]);

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const n = Number(url.searchParams.get('n') ?? 1);
    const t0 = performance.now();
    if (url.pathname === '/null') return new Response('ok');
    if (url.pathname === '/tx') {
      const key = await relayKey(SEED, 'r.test');
      for (let i = 0; i < n; i += 1) {
        await signedTransaction({ signerId: 'r.test', publicKey: key.pub, nonce: BigInt(i + 1), receiverId: 'c.test', blockHash: HASH, actions: [callAction('heartbeat', { vault: 'ab'.repeat(32) }, 10)] }, key.sign);
      }
    } else if (url.pathname === '/funding') {
      const dispenser = dispenserFromSecret(DISPENSER, 'mutinynet');
      for (let i = 0; i < n; i += 1) {
        buildFunding({ dispenser, utxos: [{ txid: 'cd'.repeat(32), vout: i, value: 1_000_000, status: { confirmed: true } }], payTo: PAY_TO, value: 2000, feeRate: 2 });
      }
    } else if (url.pathname === '/relay' || url.pathname === '/funds') {
      const { body, view } = await request.json();
      const handler = relayWith(view);
      for (let i = 0; i < n; i += 1) {
        const res = await handler(new Request(`http://x/api${url.pathname}`, { method: 'POST', body, headers: { 'cf-connecting-ip': '1.2.3.4', 'x-undo-beat': 'bench' } }));
        const answer = await res.json();
        if (!answer.ok) return new Response(JSON.stringify(answer), { status: 500 });
      }
    } else {
      return new Response('no', { status: 404 });
    }
    return new Response(JSON.stringify({ inside_ms: performance.now() - t0 }));
  },
};
