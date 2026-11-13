// /try/'s steps with no page around them, each (ctx, ...) -> a promise, so a Node test can hold each one down with fakes.
// ctx is the page's: { config, reader, views, relay, esplora, skew }. Nothing here draws, and nothing here opens a passkey
// sheet: those are try.mjs's, inside a tap. `sleep` and `now` are passed in where a step waits, for a test's clock.
//
// The thief half (theftPrep, sendKeyAlone, proposeTheft, findRequest) holds the spend key, as the thief tab does. The owner
// half (readOwner) reads only the contract: what it says of a request comes from views.vault and views.request, never
// from what the thief half sent (R4).
import {
  keyAloneSpend, postTxOnce, readPatiently, RelayRefused, requestState, advanceState, scriptMatchesVault, sendEverything, buildPropose, spkToAddress,
} from '/site/lib/index.mjs';
import { fromHex, toHex } from '/tools/lib/bytes.mjs';
import { randomBytes } from '/tools/lib/crypto.mjs';
import { chainNowOf } from '../p/vault-make.mjs';

const realSleep = (ms) => new Promise((r) => { setTimeout(r, ms); });
// The relay answers rate_limited with a wait of 5 s when another ask for the same vault holds the coin (funds.mjs). A
// wait this short is asked again after it; a longer one is a limit, and is said, not waited out.
export const FUND_RETRY_MAX_S = 10;
export const FUND_RETRIES = 3;
const MAX_INPUTS = 16;
// A node a few blocks behind answers null for a request it has not reached. A seen request reads as gone only when it
// stays gone (phone.mjs NULL_READS_TO_BELIEVE).
export const NULL_READS_TO_BELIEVE = 3;

/**
 * Asks the relay for a test coin, only while the page is visible (R10): `whenVisible` resolves when it is, and is asked
 * again right before each ask. `pow` is the promise of the proof of work, started while the vault was being made, so
 * there is one solve however many asks. rate_limited with a wait of FUND_RETRY_MAX_S or less is asked again after that
 * wait, at most FUND_RETRIES times; nothing else is. Resolves to the relay's answer (`already: true` is a coin the relay
 * sent this vault earlier, the same as paid), or throws its RelayRefused.
 */
export async function askCoin(ctx, { vaultHex, pow, whenVisible = async () => {}, sleep = realSleep, onRetry = () => {} }) {
  for (let retries = 0; ; retries += 1) {
    const nonce = await pow;
    await whenVisible();
    try {
      return await ctx.relay.fund(vaultHex, { pow: nonce });
    } catch (err) {
      const short = err instanceof RelayRefused && err.code === 'rate_limited' && Number.isFinite(err.retryAfterS) && err.retryAfterS <= FUND_RETRY_MAX_S;
      if (!short || retries >= FUND_RETRIES) throw err;
      onRetry(retries + 1, err.retryAfterS);
      await sleep(err.retryAfterS * 1000);
    }
  }
}

/**
 * A creation the relay gave no answer for, or answered with a code it can give after sending: the chain decides (M8).
 * Reads the contract for this vault for the awake time waitActive gives it. Resolves to { vault } when the contract
 * reads it active, or { vault: null } when it does not yet, which stays true if it lands later.
 */
export async function vaultAfterNoAnswer(ctx, prepared, { waitActive, now, sleep } = {}) {
  try {
    const made = await waitActive(ctx, prepared, null, { ...(now ? { now } : {}), ...(sleep ? { sleep } : {}) });
    return { vault: made.vault };
  } catch {
    return { vault: null };
  }
}

/** The coins a node lists at an address, largest first, as the thief tab takes them (no confirmed filter). */
export const coinsOf = (utxos) => utxos.map((c) => ({ txid: c.txid, vout: c.vout, value: c.value })).sort((a, b) => b.value - a.value).slice(0, MAX_INPUTS);

/**
 * Reads the address every `everyMs` until a node lists a coin there, for at most `forMs`. Resolves to { coins } with at
 * least one, or { coins: [] } when none came in that time. A read that fails says so through `onDown(err)` and the reads
 * go on; `onUp()` when one works again. `stop()` true ends it early with { coins: [], stopped: true }.
 */
export async function waitForCoin(ctx, { address, everyMs = 1000, forMs = 60_000, sleep = realSleep, now = () => Date.now(), onDown = () => {}, onUp = () => {}, stop = () => false }) {
  const end = now() + forMs;
  for (;;) {
    if (stop()) return { coins: [], stopped: true };
    try {
      const coins = coinsOf(await ctx.esplora.utxos(address));
      onUp();
      if (coins.length) return { coins };
    } catch (err) {
      onDown(err);
    }
    if (now() >= end) return { coins: [] };
    await sleep(everyMs);
  }
}

/**
 * The thief half's checks before it sends, as the thief tab makes them: the contract's script for this vault, and that
 * it really pays the vault's address; a fee rate; and a destination nobody holds, a P2WPKH of 20 random bytes in the
 * vault's network's own form (as thiefLink builds it). Throws { code: 'script_mismatch' } for a script that does not pay
 * this vault, { code: 'near_down' } or { code: 'btc_down' } for a read that failed.
 */
export async function theftPrep(ctx, { vaultHex, vault, network }) {
  let script;
  try {
    script = fromHex(await ctx.views.script(vaultHex));
  } catch (err) {
    throw Object.assign(new Error('the script read failed'), { code: 'near_down', cause: err });
  }
  if (!scriptMatchesVault(script, vault)) throw Object.assign(new Error('the script does not pay this vault'), { code: 'script_mismatch' });
  let estimates;
  try {
    estimates = await ctx.esplora.feeEstimates();
  } catch (err) {
    throw Object.assign(new Error('the fee read failed'), { code: 'btc_down', cause: err });
  }
  const feeRate = Math.max(2, Math.ceil(estimates?.['6'] ?? 2));
  const to = Uint8Array.of(0x00, 0x14, ...randomBytes(20));
  return { script, feeRate, to, toAddress: spkToAddress(network, to) };
}

/** The contract's own opinion of the theft, before anything is signed (check_propose). Throws its ViewRefused. */
export async function checkTheft(ctx, { vaultHex, coins, to, script, feeRate }) {
  const spend = sendEverything({ coins, to, script, feeRate });
  if (spend.short) return { spend, check: null };
  const check = await ctx.views.checkPropose(vaultHex, { inputs: spend.inputs, to: toHex(to), amount: spend.amount });
  return { spend, check };
}

/**
 * The spend key alone, straight to Bitcoin: the coins a node lists now, everything to `to`, one POST. `visible()` is
 * asked right before the POST (R10), and a page that is not on screen sends nothing ({ hidden: true }). { none: true }
 * when no coin is listed. Otherwise postTxOnce's answer, with the spend it sent.
 */
export async function sendKeyAlone(ctx, { address, seed, script, to, feeRate, visible = () => true }) {
  let coins;
  try {
    coins = coinsOf(await ctx.esplora.utxos(address));
  } catch (err) {
    return { kind: 'no_answer', body: null, error: err.message, errorKind: err.errorKind ?? null };
  }
  const spend = sendEverything({ coins, to, script, feeRate });
  if (coins.length === 0 || spend.short) return { none: true };
  if (!visible()) return { hidden: true };
  const { raw, txid } = keyAloneSpend({ seed, script, coins, to, amount: spend.amount });
  const answer = await postTxOnce(ctx.config.esplora, raw, txid);
  return { ...answer, spend, coins };
}

/**
 * The thief asks the NEAR contract, as the thief tab's ask(): the vault read fresh (its pending list, so a request that
 * was already there is not taken for this one), the chain's clock, propose_btc's arguments signed with the spend key,
 * and the relay. Only from a page on screen (R10): `whenVisible` resolves when it is, and `visible()` is asked right
 * before the POST, with nothing awaited between the two. A page that went off screen during the reads sends nothing:
 * it waits until it is shown, then reads the vault and the clock again, so the proposal is built from reads made then.
 * Resolves to { hash, seenBefore }; throws the relay's RelayRefused or a read's error.
 */
export async function proposeTheft(ctx, { vaultHex, script, seed, spend, to, visible = () => true, whenVisible = async () => {} }) {
  for (;;) {
    await whenVisible();
    // Both at once, each asked again while no node answers: nothing goes to the relay until both are in.
    const [vault, block] = await Promise.all([readPatiently(() => ctx.views.vault(vaultHex)), readPatiently(() => ctx.reader.blockTime())]);
    const seenBefore = new Set(vault.pending);
    ctx.skew.add(block);
    if (!visible()) continue;
    const args = buildPropose({
      contract: ctx.config.contract, vault, script, seed, inputs: spend.inputs, to, amount: spend.amount, nonce: vault.spend_nonce, expiresAt: block.blockMs + 30 * 60_000,
    });
    const sent = await ctx.relay.call('propose_btc', args);
    return { hash: sent.hash, seenBefore };
  }
}

/**
 * The thief half looks for the request its proposal made: a pending id that was not there before. Gives up after `forMs`
 * with { code: 'no_request' }, and only when its last read got the vault: while the reads fail, or the node has no vault
 * for it, "no request appeared" would be said of a contract nobody read, so it reads on until one answers or `stop()`
 * (R3). A transaction the contract refused throws { code: 'contract_refused', verbatim }, read at 15 s and at the end
 * (the thief tab's findRequest, on a clock).
 */
export async function findRequest(ctx, { vaultHex, seenBefore, hash, relayAccount, forMs = 30_000, everyMs = 500, sleep = realSleep, now = () => Date.now(), stop = () => false }) {
  const start = now();
  let asked = 0;
  for (;;) {
    if (stop()) return null;
    const vault = await ctx.views.vault(vaultHex).catch(() => null);
    const fresh = vault?.pending.filter((id) => !seenBefore.has(id)) ?? [];
    if (fresh.length) return Math.max(...fresh);
    const spent = now() - start;
    if (hash && ((asked === 0 && spent >= forMs / 2) || (asked === 1 && spent >= forMs))) {
      asked += 1;
      const outcome = await ctx.reader.txOutcome(hash, relayAccount ?? '').catch(() => null);
      if (outcome?.failure) throw Object.assign(new Error(outcome.failure), { code: 'contract_refused', verbatim: outcome.failure });
    }
    if (spent >= forMs && vault) throw Object.assign(new Error('the transaction was sent and no new request appeared on the contract'), { code: 'no_request' });
    await sleep(everyMs);
  }
}

/**
 * The owner half: one read of what the contract holds for this vault. `items` (a Map, kept across reads) holds each
 * request seen: { id, request, current, nulls, state }. Reads the vault, then every id it lists and every id already
 * seen that has not ended, and judges each with requestState and advanceState; a null counts only once it has stayed
 * null NULL_READS_TO_BELIEVE times. Resolves to the vault (null when the node has none) and the requests' states.
 */
export async function readOwner(ctx, { vaultHex, items }) {
  const vault = await ctx.views.vault(vaultHex);
  if (!vault) return { vault: null, items };
  const ids = new Set(vault.pending);
  for (const item of items.values()) if (!item.state?.terminal) ids.add(item.id);
  const list = [...ids];
  const rows = await Promise.all(list.map((id) => ctx.views.request(vaultHex, id)));
  list.forEach((id, i) => {
    const row = rows[i];
    let item = items.get(id);
    if (!item) {
      if (!row) return;
      item = { id, request: row, current: row, nulls: 0, state: null };
      items.set(id, item);
    }
    item.current = row;
    if (row) {
      item.request = row;
      item.nulls = 0;
    } else item.nulls += 1;
  });
  const now = chainNowOf(ctx.skew) ?? Date.now();
  for (const item of items.values()) {
    const raw = requestState({ request: item.current, vault, chainNow: now, lastKnown: item.request });
    if (raw.kind === 'unseen' || raw.kind === 'no_vault') continue;
    if (!item.current && item.nulls < NULL_READS_TO_BELIEVE) continue;
    item.state = advanceState(item.state, raw);
  }
  return { vault, items };
}

/**
 * What the owner half does with what it read: the one request it handles, when exactly one is on the contract and it
 * waits or is unlocked ({ kind: 'request', item }); 'other' when a request moved on (signing, signed, expired, or
 * cancelled from somewhere else) or a second one is there, which only the phone page handles (C11); 'none' before any.
 */
export function ownerFocus(items) {
  const judged = [...items.values()].filter((item) => item.state);
  if (judged.length === 0) return { kind: 'none' };
  if (judged.length > 1) return { kind: 'other', why: 'second' };
  const [item] = judged;
  if (item.state.cancellable) return { kind: 'request', item };
  return { kind: 'other', why: item.state.kind, item };
}

/** "The coin never moved." needs both answers: a node that knows each coin, and says its output is unspent. */
export async function coinStill(ctx, inputs) {
  if (!inputs?.length) return false;
  for (const coin of inputs) {
    const [tx, out] = await Promise.all([ctx.esplora.tx(coin.txid), ctx.esplora.outspend(coin.txid, coin.vout)]);
    if (!tx || !out || out.spent !== false) return false;
  }
  return true;
}
