// /api/funds: test coins from the relay's own wallet, a separate action a visitor asks for. A coin never pays out
// on vault creation. The address comes from the contract, so nobody can name a payee.
import { classifyBroadcast } from '../../../tools/lib/esplora.mjs';
import { fromHex } from '../../../tools/lib/bytes.mjs';
import { checkPow, fundsPowTarget } from '../../lib/pow.mjs';
import { hashIp, json, numberOr, readBody, Refusal } from './answer.mjs';
import { buildFunding, dispenserFromSecret } from './funding.mjs';

const DEFAULT_SATS = 2000;
const DEFAULT_CEILING = 40_000;
const DEFAULT_FEE_RATE = 2;
const EMPTY_HOLDS_MS = 10 * 60_000;
const CALL_TIMEOUT_MS = 8000;
const RESERVE_VSIZE = 180;
const INPUT_VSIZE = 68;

const settings = (relay) => ({
  sats: numberOr(relay.env.FUNDS_SATS, DEFAULT_SATS),
  ceiling: numberOr(relay.env.CEILING_FUNDS_SATS, DEFAULT_CEILING),
  feeRate: numberOr(relay.env.FUNDS_FEE_RATE, DEFAULT_FEE_RATE),
});

const fundsConfigured = (relay) => Boolean(relay.configured && relay.state && relay.env.IP_SALT && relay.env.DISPENSER_SECRET && relay.env.DISPENSER_NETWORK && relay.env.ESPLORA_URL);

/** The status line. "Empty" holds only for a while after a real look, so a refill by hand is found again. */
export function fundsStatus(relay, read) {
  const { sats, ceiling, feeRate } = settings(relay);
  const line = { up: true, why: null, sats, resets_at: null };
  if (!fundsConfigured(relay)) return { ...line, up: false, why: 'relay_not_configured' };
  if (read === null) return { ...line, up: false, why: 'state_store_down' };
  if (read.spent.funds + sats > ceiling) return { ...line, up: false, why: 'daily_ceiling', resets_at: read.resets_at };
  const lookedLately = read.coins.refreshed_at !== null && relay.nowFn() - read.coins.refreshed_at < EMPTY_HOLDS_MS;
  if (lookedLately && read.coins.free_sats < sats + feeRate * RESERVE_VSIZE) return { ...line, up: false, why: 'dispenser_empty' };
  return line;
}

const dispensers = new Map();

function dispenserOf(relay) {
  const { DISPENSER_SECRET: secret, DISPENSER_NETWORK: network } = relay.env;
  const id = `${network}\n${secret}`;
  if (!dispensers.has(id)) {
    try {
      dispensers.set(id, dispenserFromSecret(secret, network));
    } catch {
      throw new Refusal('relay_not_configured', { message: 'the dispenser key cannot be read' });
    }
  }
  return dispensers.get(id);
}

async function esplora(relay, path, init = {}) {
  let res;
  let body;
  try {
    res = await relay.fetchFn(`${relay.env.ESPLORA_URL}${path}`, { ...init, signal: AbortSignal.timeout(CALL_TIMEOUT_MS) });
    body = await res.text();
  } catch (err) {
    return { status: null, body: err.name };
  }
  return { status: res.status, body };
}

/** What Esplora lists for the dispenser, into the state store. */
async function refreshCoins(relay, dispenser) {
  const { status, body } = await esplora(relay, `/address/${dispenser.address}/utxo`);
  let listed = null;
  if (status === 200) {
    try {
      listed = JSON.parse(body);
    } catch {
      // Falls through as a dead Esplora.
    }
  }
  if (!Array.isArray(listed)) throw new Refusal('esplora_down', { message: 'could not read the dispenser\'s coins', verbatim: body.slice(0, 400) });
  await relay.state.call('addCoins', { coins: listed.map((u) => ({ txid: u.txid, vout: u.vout, value: u.value })), now: relay.nowFn() });
}

async function reserve(relay, dispenser, need, perInput) {
  const first = await relay.state.call('reserveCoin', { need, perInput, now: relay.nowFn() });
  if (first.ok) return first.coins;
  await refreshCoins(relay, dispenser);
  const second = await relay.state.call('reserveCoin', { need, perInput, now: relay.nowFn() });
  if (second.ok) return second.coins;
  // Every coin is on lease to another funding. That is busy, not empty, and the page should say so.
  if (second.busy) throw new Refusal('rate_limited', { message: 'another funding holds the coin', retryAfterS: 5 });
  throw new Refusal('dispenser_empty', { message: 'the dispenser has no coin left' });
}

/** Sends it, and asks after it if the answer was lost. Accepted, refused or unknown, in Esplora's own words. */
async function broadcast(relay, built) {
  const posted = await esplora(relay, '/tx', { method: 'POST', headers: { 'content-type': 'text/plain' }, body: built.raw });
  const said = classifyBroadcast(posted.status ?? 0, posted.body, built.txid);
  if (said.kind !== 'transient') return { said, posted };
  const seen = await esplora(relay, `/tx/${built.txid}/hex`);
  if (seen.status === 200) return { said: { kind: 'accepted' }, posted };
  return { said, posted };
}

async function fund(relay, dispenser, payTo, vault, { sats, feeRate }) {
  const need = sats + feeRate * RESERVE_VSIZE;
  for (let round = 0; ; round += 1) {
    const coins = await reserve(relay, dispenser, need, feeRate * INPUT_VSIZE);
    const built = buildFunding({
      dispenser,
      utxos: coins.map((c) => ({ ...c, status: { confirmed: true } })),
      payTo,
      value: sats,
      feeRate,
    });
    if (built.short) {
      await relay.state.call('releaseCoin', { coins });
      throw new Refusal('dispenser_empty', { message: 'the dispenser has no coin left' });
    }
    const { said, posted } = await broadcast(relay, built);
    if (said.kind === 'accepted') {
      const change = built.change ? { txid: built.txid, vout: 1, value: built.change } : null;
      await relay.state.call('commitCoin', { coins, change });
      await relay.state.call('fundedDone', { vault, txid: built.txid, now: relay.nowFn() });
      return json(200, { ok: true, txid: built.txid, vout: built.vout, value: built.value, broadcast: { status: posted.status, body: posted.body } });
    }
    if (said.kind === 'transient') {
      // It may yet land, so the coin stays leased and the claim stands until they run out.
      const keep = new Refusal('esplora_down', { message: 'the node did not answer', verbatim: posted.body.slice(0, 400), retryAfterS: 120 });
      keep.keepClaim = true;
      throw keep;
    }
    if (said.refusal === 'inputs_gone' && round === 0) {
      await relay.state.call('releaseCoin', { coins, gone: true });
      continue;
    }
    await relay.state.call('releaseCoin', { coins });
    throw new Refusal('tx_refused', { message: 'the node refused the funding', verbatim: posted.body });
  }
}

async function refuseIfItHoldsACoin(relay, row) {
  const { status, body } = await esplora(relay, `/address/${row.address}/utxo`);
  let listed = null;
  if (status === 200) {
    try {
      listed = JSON.parse(body);
    } catch {
      // Falls through as a dead Esplora.
    }
  }
  if (!Array.isArray(listed)) throw new Refusal('esplora_down', { message: 'could not read that vault\'s coins', verbatim: body.slice(0, 400) });
  if (listed.length > 0) throw new Refusal('would_refuse', { message: 'that vault already holds a coin' });
}

export async function fundsHandler(relay, request) {
  if (relay.originProblem(request)) throw new Refusal('bad_origin', { message: 'that origin may not call this' });
  const body = await readBody(request);
  const fields = body && typeof body === 'object' && !Array.isArray(body) ? Object.keys(body).sort() : [];
  if (fields.join() !== 'pow,vault' || typeof body.vault !== 'string' || !/^[0-9a-f]{64}$/.test(body.vault)) {
    throw new Refusal('bad_request', { message: 'name one vault, with its proof of work' });
  }
  if (!fundsConfigured(relay)) throw new Refusal('relay_not_configured', { message: 'the dispenser is not set' });
  const { vault } = body;
  if (!checkPow(fundsPowTarget(vault), body.pow, relay.powBits)) throw new Refusal('pow_bad', { message: 'that proof of work does not solve this vault' });
  let row;
  try {
    row = await relay.reader().view(relay.contract, 'vault', { vault });
  } catch {
    throw new Refusal('rpc_down', { message: 'could not read the vault' });
  }
  if (row === null) throw new Refusal('bad_request', { message: 'no such vault' });
  if (!row.active) throw new Refusal('bad_request', { message: 'that vault is not active' });
  // Anyone can make a vault directly, free of this relay's limits, and name whatever guard they like.
  if (row.guard !== relay.account) throw new Refusal('would_refuse', { message: 'this relay only funds vaults it guards' });

  const conf = settings(relay);
  const dispenser = dispenserOf(relay);
  const ipHash = await hashIp(relay.env.IP_SALT, request.headers.get('cf-connecting-ip'));
  let claim;
  try {
    claim = await relay.state.call('funded', { vault, ipHash, sats: conf.sats, ceiling: conf.ceiling, now: relay.nowFn() });
  } catch {
    throw new Refusal('state_store_down', { message: 'the state store is not answering' });
  }
  if (!claim.ok) {
    throw new Refusal(claim.code, {
      message: claim.code === 'daily_ceiling' ? 'the dispenser is at today\'s limit' : 'too many asks for coins',
      retryAfterS: claim.retry_after_s ?? null,
      bucket: claim.bucket ?? null,
      resetsAt: claim.resets_at ?? null,
    });
  }
  if (claim.already) return json(200, { ok: true, txid: claim.txid, vout: 0, value: conf.sats, already: true, broadcast: null });
  try {
    await refuseIfItHoldsACoin(relay, row);
    return await fund(relay, dispenser, fromHex(row.script_pubkey), vault, conf);
  } catch (err) {
    if (!err.keepClaim) await relay.state.call('fundedDrop', { vault, sats: conf.sats, now: relay.nowFn() }).catch(() => {});
    if (err instanceof Refusal) throw err;
    throw new Refusal('state_store_down', { message: 'the state store is not answering' });
  }
}
