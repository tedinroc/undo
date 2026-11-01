// The Worker that owns the state store, and one cron: a heartbeat on one canary vault, if one is set. No
// per-vault cron: a vault gets its beat at creation and before each take. It answers nothing over HTTP.
import { NearSender, relayKey } from '../../../site/functions/_relay/near-send.mjs';
import { StateClient } from '../../../site/functions/_relay/state-client.mjs';
import { callAction } from '../../../site/lib/near-tx.mjs';
import { RELAY_METHODS } from '../../../site/lib/relay-table.mjs';

export { UndoState } from './undo-state.mjs';

const urlsOf = (text) => String(text ?? '').split(',').map((u) => u.trim()).filter(Boolean);

/** One heartbeat on CANARY_VAULT. Returns its hash, or null when no canary is set. */
export async function canaryBeat(env, { fetchFn, nowFn = () => Date.now() } = {}) {
  const vault = env.CANARY_VAULT;
  if (!vault) return null;
  const missing = ['CONTRACT_ID', 'RELAY_ACCOUNT', 'RELAY_CRON_KEY', 'NEAR_RPC_URLS'].filter((name) => !env[name]);
  if (missing.length) throw new Error(`canary: not configured: ${missing.join(', ')}`);
  const key = await relayKey(env.RELAY_CRON_KEY, env.RELAY_ACCOUNT);
  const state = new StateClient(env.UNDO_STATE, env.UNDO_STATE_NAME);
  const sender = new NearSender({ urls: urlsOf(env.NEAR_RPC_URLS), signerId: env.RELAY_ACCOUNT, receiverId: env.CONTRACT_ID, nowFn, ...(fetchFn ? { fetchFn } : {}) });
  const sent = await sender.send(key, [callAction('heartbeat', { vault }, RELAY_METHODS.heartbeat.tgas)], { nonces: state });
  await state.call('heartbeatLogged', { vault, at: nowFn(), hash: sent.hash });
  return sent.hash;
}

export default {
  fetch: () => new Response('not found', { status: 404 }),
  scheduled: (event, env, ctx) => {
    ctx.waitUntil(canaryBeat(env));
  },
};
