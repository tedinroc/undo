// Plays the MPC network for the mock signer on a local node: reads queued requests and answers them
// with the live signer's arithmetic and wire shape. Sandbox only.
import { toHex, fromHex } from '../lib/bytes.mjs';
import { secp256k1 } from '../lib/crypto.mjs';
import { action, TGAS } from '../lib/near.mjs';

const ORDER = secp256k1.CURVE.n;
const big = (bytes) => BigInt(`0x${toHex(bytes)}`);

export function answer({ secret, tweakHex, payloadHex }) {
  const key = (big(secret) + big(fromHex(tweakHex)) % ORDER) % ORDER;
  const sig = secp256k1.sign(fromHex(payloadHex), fromHex(key.toString(16).padStart(64, '0')), { lowS: true, prehash: false });
  const r = sig.r.toString(16).padStart(64, '0');
  const s = sig.s.toString(16).padStart(64, '0');
  return {
    scheme: 'Secp256k1',
    big_r: { affine_point: `${(sig.recovery & 1) ? '03' : '02'}${r}` },
    s: { scalar: s },
    recovery_id: sig.recovery,
  };
}

/** `respond` may change the answer, or return null to stay silent. `again` answers a repeated request. */
export function startMockNode({ near, mock, responder, secret, pollMs = 150, respond = answer, again = false }) {
  let stopped = false;
  const answered = new Set();
  const loop = async () => {
    while (!stopped) {
      try {
        const pending = await near.view(mock.accountId, 'pending');
        for (const request of pending) {
          const id = `${request.tweak}:${request.payload.Ecdsa}`;
          if (answered.has(id)) continue;
          const response = respond({ secret, tweakHex: request.tweak, payloadHex: request.payload.Ecdsa });
          if (!response) continue;
          answered.add(id);
          await near.send(responder, mock.accountId, [action.call('respond', { request, response }, 100n * TGAS, 0n)]);
          if (again) setTimeout(() => answered.delete(id), 3000);
        }
      } catch {
        // A mock's poll failing is not news. The driver's own timeout reports what matters.
      }
      await new Promise((r) => setTimeout(r, pollMs));
    }
  };
  const done = loop();
  return { stop: () => { stopped = true; return done; } };
}
