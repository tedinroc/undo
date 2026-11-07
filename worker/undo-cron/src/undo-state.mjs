// The relay's strongly consistent state: limits, daily ceilings, a nonce row per key, the dispenser's coins.
// A plain class with no `cloudflare:` import, so site/test can run this same class over node:sqlite. Each
// operation is one synchronous transaction, so nothing else runs between its reads and its writes. It stores
// no address and no body: an IP only as a salted hash, a vault id and that vault's two public keys, all of which the
// chain shows, and for an owner call only which call it was, so one signed body is charged once.
import { OWNER, OWNER_UNCHECKED_SHARE, RELAY_METHODS } from '../../../site/lib/relay-table.mjs';

export const FUNDS = 'funds';
export const FUNDS_PER_IP_HOUR = 2;

const HOUR = 3_600_000;
const MINUTE = 60_000;
const DAY = 86_400_000;
const PRUNE_EVERY = 10 * MINUTE;
const CLAIM_MS = 2 * MINUTE;
const LEASE_MS = MINUTE;
const MAX_INPUTS = 4;

const SCHEMA = [
  'CREATE TABLE IF NOT EXISTS ip_counter (ip_hash TEXT NOT NULL, method TEXT NOT NULL, window_start INTEGER NOT NULL, count INTEGER NOT NULL, PRIMARY KEY (ip_hash, method, window_start))',
  'CREATE TABLE IF NOT EXISTS vault_counter (vault TEXT NOT NULL, method TEXT NOT NULL, window_start INTEGER NOT NULL, count INTEGER NOT NULL, PRIMARY KEY (vault, method, window_start))',
  'CREATE TABLE IF NOT EXISTS daily_ceiling (day INTEGER NOT NULL, bucket TEXT NOT NULL, spent INTEGER NOT NULL, PRIMARY KEY (day, bucket))',
  'CREATE TABLE IF NOT EXISTS nonce_lease (key_id TEXT PRIMARY KEY, next_nonce INTEGER NOT NULL, updated_at INTEGER NOT NULL)',
  'CREATE TABLE IF NOT EXISTS dispenser_utxos (txid TEXT NOT NULL, vout INTEGER NOT NULL, value INTEGER NOT NULL, state TEXT NOT NULL, reserved_until INTEGER, PRIMARY KEY (txid, vout))',
  'CREATE TABLE IF NOT EXISTS funded_vaults (vault TEXT PRIMARY KEY, txid TEXT, at INTEGER NOT NULL)',
  'CREATE TABLE IF NOT EXISTS heartbeat_log (vault TEXT NOT NULL, at INTEGER NOT NULL, hash TEXT NOT NULL, PRIMARY KEY (vault, at))',
  'CREATE TABLE IF NOT EXISTS alert_state (class TEXT PRIMARY KEY, value TEXT, at INTEGER NOT NULL)',
  // The vaults this relay sent a create_vault for, with the passkey and cold intent key they were made with. Only these
  // get the owner key and test coins: anyone can make a vault straight on the contract, as many as they like.
  'CREATE TABLE IF NOT EXISTS made_vaults (vault TEXT PRIMARY KEY, passkey TEXT NOT NULL, k_e_intent TEXT NOT NULL, at INTEGER NOT NULL)',
  // One row per owner call sent: vault, method, signer, nonce or request, expiry. A body the contract would refuse
  // cannot be sent twice, and one it would take cannot be charged twice.
  'CREATE TABLE IF NOT EXISTS owner_sent (vault TEXT NOT NULL, call TEXT NOT NULL, at INTEGER NOT NULL, PRIMARY KEY (vault, call))',
];

export const UNCHECKED = `${OWNER}_unchecked`;

const dayOf = (now) => Math.floor(now / DAY);
const resetsAt = (now) => (dayOf(now) + 1) * DAY;
const reply = (status, value) => new Response(JSON.stringify(value), { status, headers: { 'content-type': 'application/json' } });

export class UndoState {
  constructor(ctx, env) {
    Object.assign(this, { ctx, env, sql: ctx.storage.sql, prunedAt: 0 });
    for (const statement of SCHEMA) this.sql.exec(statement);
  }

  async fetch(request) {
    const op = new URL(request.url).pathname.slice(1);
    if (!Object.hasOwn(UndoState.OPS, op)) return reply(404, { ok: false, code: 'bad_request' });
    const body = request.method === 'POST' ? await request.json() : {};
    return reply(200, this.ctx.storage.transactionSync(() => UndoState.OPS[op].call(this, body)));
  }

  first(query, ...bindings) {
    return this.sql.exec(query, ...bindings).toArray()[0] ?? null;
  }

  // ------------------------------------------------------------ limits

  spentToday(bucket, now) {
    return this.first('SELECT spent FROM daily_ceiling WHERE day = ? AND bucket = ?', dayOf(now), bucket)?.spent ?? 0;
  }

  prune(now) {
    if (now - this.prunedAt < PRUNE_EVERY) return;
    this.prunedAt = now;
    this.sql.exec('DELETE FROM ip_counter WHERE window_start < ?', now - 2 * HOUR);
    this.sql.exec("DELETE FROM vault_counter WHERE window_start < ? AND method NOT LIKE '%:day'", now - 2 * HOUR);
    this.sql.exec('DELETE FROM vault_counter WHERE window_start < ?', now - 2 * DAY);
    this.sql.exec('DELETE FROM daily_ceiling WHERE day < ?', dayOf(now) - 7);
    this.sql.exec('DELETE FROM heartbeat_log WHERE at < ?', now - DAY);
    // A day's limits outlive this, and an old body is refused on its nonce or its request once read.
    this.sql.exec('DELETE FROM owner_sent WHERE at < ?', now - 2 * DAY);
  }

  /**
   * A ceiling first, because it holds for everybody. Nothing is counted unless everything passes. Returns a ticket:
   * exactly what was counted, so a send that never reached the chain can give back each count it took. `share` is a
   * second, smaller ceiling the call also counts against. `rows` name the per-vault counters, which differ for a call
   * the relay could not check.
   */
  chargeNow({ key, method, ipHash, vault, now, ceiling, cost, perIpHour, share = null, rows = null }) {
    this.prune(now);
    const spent = this.spentToday(key, now);
    if (spent + cost > ceiling) return { ok: false, code: 'daily_ceiling', bucket: key, resets_at: resetsAt(now) };
    if (share && this.spentToday(share.bucket, now) + cost > share.ceiling) return { ok: false, code: 'rate_limited', retry_after_s: 60, unchecked: true };
    const ipWindow = Math.floor(now / HOUR) * HOUR;
    if (perIpHour) {
      const seen = this.first('SELECT count FROM ip_counter WHERE ip_hash = ? AND method = ? AND window_start = ?', ipHash, method, ipWindow)?.count ?? 0;
      if (seen >= perIpHour) return { ok: false, code: 'rate_limited', retry_after_s: Math.ceil((ipWindow + HOUR - now) / 1000) };
    }
    const counters = [];
    for (const { name, limit, span } of rows ?? []) {
      if (!limit) continue;
      const window = Math.floor(now / span) * span;
      const seen = this.first('SELECT count FROM vault_counter WHERE vault = ? AND method = ? AND window_start = ?', vault, name, window)?.count ?? 0;
      if (seen >= limit) return { ok: false, code: 'rate_limited', retry_after_s: Math.ceil((window + span - now) / 1000) };
      counters.push([vault, name, window]);
    }
    if (perIpHour) this.sql.exec('INSERT INTO ip_counter VALUES (?, ?, ?, 1) ON CONFLICT DO UPDATE SET count = count + 1', ipHash, method, ipWindow);
    for (const [v, name, window] of counters) this.sql.exec('INSERT INTO vault_counter VALUES (?, ?, ?, 1) ON CONFLICT DO UPDATE SET count = count + 1', v, name, window);
    const buckets = share ? [key, share.bucket] : [key];
    for (const bucket of buckets) this.sql.exec('INSERT INTO daily_ceiling VALUES (?, ?, ?) ON CONFLICT DO UPDATE SET spent = spent + ?', dayOf(now), bucket, cost, cost);
    return { ok: true, spent: spent + cost, ticket: { day: dayOf(now), buckets, cost, counters } };
  }

  /** Gives back a ceiling. With a ticket, on the day it was charged, and its per-vault counts too when `counters`. */
  refundNow({ bucket, cost, now, ticket = null, counters = false }) {
    if (!ticket) {
      this.sql.exec('UPDATE daily_ceiling SET spent = MAX(0, spent - ?) WHERE day = ? AND bucket = ?', cost, dayOf(now), bucket);
      return { ok: true };
    }
    const day = Number.isSafeInteger(ticket.day) ? ticket.day : dayOf(now);
    const back = Number.isFinite(cost) ? cost : ticket.cost;
    for (const b of Array.isArray(ticket.buckets) ? ticket.buckets : []) {
      if (typeof b === 'string') this.sql.exec('UPDATE daily_ceiling SET spent = MAX(0, spent - ?) WHERE day = ? AND bucket = ?', back, day, b);
    }
    if (!counters) return { ok: true };
    for (const [v, name, window] of Array.isArray(ticket.counters) ? ticket.counters : []) {
      this.sql.exec('UPDATE vault_counter SET count = MAX(0, count - 1) WHERE vault = ? AND method = ? AND window_start = ?', v, name, window);
    }
    if (Array.isArray(ticket.sent)) this.sql.exec('DELETE FROM owner_sent WHERE vault = ? AND call = ?', ticket.sent[0], ticket.sent[1]);
    if (typeof ticket.made === 'string') this.sql.exec('DELETE FROM made_vaults WHERE vault = ?', ticket.made);
    return { ok: true };
  }

  madeRow(vault) {
    return this.first('SELECT passkey, k_e_intent FROM made_vaults WHERE vault = ?', vault);
  }

  // ------------------------------------------------------------ dispenser

  freeCoins(now) {
    return this.sql.exec("SELECT txid, vout, value FROM dispenser_utxos WHERE state = 'free' OR (state = 'reserved' AND reserved_until <= ?) ORDER BY value, txid, vout", now).toArray();
  }

  heldSats(now) {
    return this.first("SELECT COALESCE(SUM(value), 0) AS sats FROM dispenser_utxos WHERE state = 'reserved' AND reserved_until > ?", now).sats;
  }

  markCoins(coins, state, reservedUntil = null) {
    for (const c of coins) this.sql.exec('UPDATE dispenser_utxos SET state = ?, reserved_until = ? WHERE txid = ? AND vout = ?', state, reservedUntil, c.txid, c.vout);
  }

  static OPS = {
    /**
     * An owner call is charged only for a vault this relay made, and only once per signed call (`call`). One the relay
     * could not check (`checked: false`) counts on its own per-vault rows and its own share of the owner ceiling.
     */
    charge({ key, method, ipHash = null, vault = null, now, ceiling, checked = true, call = null }) {
      const spec = RELAY_METHODS[method];
      if (!spec || spec.key !== key || !Number.isFinite(ceiling)) return { ok: false, code: 'bad_request' };
      const owner = key === OWNER;
      if (owner && (typeof vault !== 'string' || !this.madeRow(vault))) return { ok: false, code: 'not_this_relays' };
      if (owner && (typeof call !== 'string' || !call)) return { ok: false, code: 'bad_request' };
      if (owner && this.first('SELECT at FROM owner_sent WHERE vault = ? AND call = ?', vault, call)) return { ok: false, code: 'already_sent' };
      const unchecked = owner && checked === false;
      const rows = unchecked
        ? [{ name: `${method}:unchecked`, limit: spec.uncheckedPerVaultMinute, span: MINUTE }, { name: `${key}:unchecked:day`, limit: spec.uncheckedPerVaultDay, span: DAY }]
        : [{ name: method, limit: spec.perVaultMinute, span: MINUTE }, { name: `${key}:day`, limit: spec.perVaultDay, span: DAY }];
      const share = unchecked ? { bucket: UNCHECKED, ceiling: Math.floor(ceiling * OWNER_UNCHECKED_SHARE) } : null;
      const out = this.chargeNow({ key, method, ipHash, vault, now, ceiling, cost: spec.costMicro, perIpHour: spec.perIpHour, share, rows });
      if (out.ok && owner) {
        this.sql.exec('INSERT INTO owner_sent VALUES (?, ?, ?)', vault, call, now);
        out.ticket.sent = [vault, call];
      }
      return out;
    },

    /**
     * A create_vault this relay is about to send. `made` says whether this call wrote the row, so only it takes the row
     * back if its own send never reaches the chain. A row written in the last two minutes means another send of the same
     * create is under way: `busy`, and the handler sends nothing, so a node refusing one of two sends cannot take away
     * the row of the one that landed. An older row stays as it is, and is never this call's to take back.
     */
    made({ vault, passkey, k_e_intent: cold, now }) {
      if (![vault, passkey, cold].every((v) => typeof v === 'string' && /^[0-9a-f]+$/.test(v))) return { ok: false, code: 'bad_request' };
      const row = this.first('SELECT at FROM made_vaults WHERE vault = ?', vault);
      if (row) return { ok: true, made: false, busy: now - row.at < CLAIM_MS };
      this.sql.exec('INSERT INTO made_vaults VALUES (?, ?, ?, ?)', vault, passkey, cold, now);
      return { ok: true, made: true };
    },

    /** Null for a vault this relay did not make. */
    madeVault({ vault }) {
      return { ok: true, row: typeof vault === 'string' ? this.madeRow(vault) : null };
    },

    /** The rest of a call whose size was only known after a read, such as an execute of several inputs. */
    addCost({ key, cost, now, ceiling }) {
      const spent = this.spentToday(key, now);
      if (!Number.isFinite(cost) || cost < 0 || !Number.isFinite(ceiling)) return { ok: false, code: 'bad_request' };
      if (spent + cost > ceiling) return { ok: false, code: 'daily_ceiling', bucket: key, resets_at: resetsAt(now) };
      this.sql.exec('INSERT INTO daily_ceiling VALUES (?, ?, ?) ON CONFLICT DO UPDATE SET spent = spent + ?', dayOf(now), key, cost, cost);
      return { ok: true };
    },

    /**
     * Gives back what a call charged when its transaction never ran. With `counters`, the send itself failed before
     * the chain had it, so its per-vault counts, its owner call row and a vault row it wrote come back too. A per-IP
     * count stays, so a flood from one address reaches the chain only as often as its limit.
     */
    refund({ bucket, cost, now, ticket = null, counters = false }) {
      return this.refundNow({ bucket, cost, now, ticket, counters });
    },

    /** One row per key, so the general key's traffic can never hold up the owner key's. */
    lease({ key, now = 0 }) {
      const row = this.first('SELECT next_nonce FROM nonce_lease WHERE key_id = ?', key);
      if (!row) return { need_chain: true };
      this.sql.exec('UPDATE nonce_lease SET next_nonce = ?, updated_at = ? WHERE key_id = ?', row.next_nonce + 1, now, key);
      return { nonce: row.next_nonce };
    },

    seed({ key, chain_nonce: chain, now }) {
      const known = this.first('SELECT next_nonce FROM nonce_lease WHERE key_id = ?', key)?.next_nonce ?? 0;
      const nonce = Math.max(known, chain + 1);
      this.sql.exec('INSERT OR REPLACE INTO nonce_lease VALUES (?, ?, ?)', key, nonce + 1, now);
      return { nonce };
    },

    /** The node said what it has used. The next nonce only moves forward: a gap is allowed, a repeat is not. */
    reset({ key, ak_nonce: ak, now }) {
      return UndoState.OPS.seed.call(this, { key, chain_nonce: ak, now });
    },

    status({ now }) {
      const spent = Object.fromEntries(['general', 'owner', FUNDS].map((bucket) => [bucket, this.spentToday(bucket, now)]));
      const refreshed = this.first("SELECT at FROM alert_state WHERE class = 'dispenser_refresh'")?.at ?? null;
      return {
        ok: true,
        spent,
        resets_at: resetsAt(now),
        // Coins on lease count: they come back, or become change. Busy is not empty.
        coins: { free_sats: this.freeCoins(now).reduce((sum, c) => sum + c.value, 0) + this.heldSats(now), refreshed_at: refreshed },
      };
    },

    /** What Esplora lists. A coin already known keeps its state, so a spent one cannot come back. */
    addCoins({ coins, now }) {
      for (const c of coins) this.sql.exec("INSERT OR IGNORE INTO dispenser_utxos VALUES (?, ?, ?, 'free', NULL)", c.txid, c.vout, c.value);
      this.sql.exec("INSERT OR REPLACE INTO alert_state VALUES ('dispenser_refresh', NULL, ?)", now);
      return { ok: true };
    },

    /** Smallest single coin that covers it, else largest first. Leased, so a concurrent funding cannot pick it. */
    reserveCoin({ need, perInput = 0, now }) {
      const free = this.freeCoins(now);
      let picked = free.find((c) => c.value >= need);
      picked = picked ? [picked] : null;
      if (!picked) {
        const taken = [];
        let total = 0;
        for (const c of [...free].reverse().slice(0, MAX_INPUTS)) {
          taken.push(c);
          total += c.value;
          if (total >= need + perInput * (taken.length - 1)) {
            picked = taken;
            break;
          }
        }
      }
      if (!picked) return { ok: false, code: 'dispenser_empty', busy: this.heldSats(now) > 0 };
      this.markCoins(picked, 'reserved', now + LEASE_MS);
      return { ok: true, coins: picked };
    },

    commitCoin({ coins, change = null }) {
      this.markCoins(coins, 'spent');
      if (change) this.sql.exec("INSERT OR IGNORE INTO dispenser_utxos VALUES (?, ?, ?, 'free', NULL)", change.txid, change.vout, change.value);
      return { ok: true };
    },

    /** `gone` when a node said these inputs are spent. */
    releaseCoin({ coins, gone = false }) {
      this.markCoins(coins, gone ? 'spent' : 'free');
      return { ok: true };
    },

    /**
     * One funding per vault, claimed here before any coin moves: per-IP limit, daily ceiling and the claim are
     * one step. A vault already paid answers with its transaction, so a lost answer costs nothing to ask again.
     */
    funded({ vault, ipHash, sats, ceiling, now }) {
      const row = this.first('SELECT txid, at FROM funded_vaults WHERE vault = ?', vault);
      if (row?.txid) return { ok: true, already: true, txid: row.txid };
      if (row && now - row.at < CLAIM_MS) return { ok: false, code: 'rate_limited', retry_after_s: Math.ceil((row.at + CLAIM_MS - now) / 1000) };
      if (!row) {
        const charged = this.chargeNow({ key: FUNDS, method: FUNDS, ipHash, now, ceiling, cost: sats, perIpHour: FUNDS_PER_IP_HOUR });
        if (!charged.ok) return charged;
      }
      this.sql.exec('INSERT OR REPLACE INTO funded_vaults VALUES (?, NULL, ?)', vault, now);
      return { ok: true, already: false };
    },

    fundedDone({ vault, txid, now }) {
      this.sql.exec('INSERT OR REPLACE INTO funded_vaults VALUES (?, ?, ?)', vault, txid, now);
      return { ok: true };
    },

    /** No coin moved, so the vault may ask again and the ceiling gets its sats back. */
    fundedDrop({ vault, sats, now }) {
      this.sql.exec('DELETE FROM funded_vaults WHERE vault = ? AND txid IS NULL', vault);
      this.refundNow({ bucket: FUNDS, cost: sats, now });
      return { ok: true };
    },

    heartbeatLogged({ vault, at, hash }) {
      this.sql.exec('INSERT OR REPLACE INTO heartbeat_log VALUES (?, ?, ?)', vault, at, hash);
      return { ok: true };
    },

    heartbeats({ vault }) {
      return { ok: true, beats: this.sql.exec('SELECT at, hash FROM heartbeat_log WHERE vault = ? ORDER BY at DESC LIMIT 20', vault).toArray() };
    },
  };
}
