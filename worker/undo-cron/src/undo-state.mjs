// The relay's strongly consistent state: limits, daily ceilings, a nonce row per key, the dispenser's coins.
// A plain class with no `cloudflare:` import, so site/test can run this same class over node:sqlite. Each
// operation is one synchronous transaction, so nothing else runs between its reads and its writes. It stores
// no address and no body: an IP only as a salted hash, and a vault id, which is public.
import { RELAY_METHODS } from '../../../site/lib/relay-table.mjs';

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
];

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
    this.sql.exec('DELETE FROM vault_counter WHERE window_start < ?', now - 2 * HOUR);
    this.sql.exec('DELETE FROM daily_ceiling WHERE day < ?', dayOf(now) - 7);
    this.sql.exec('DELETE FROM heartbeat_log WHERE at < ?', now - DAY);
  }

  /** A ceiling first, because it holds for everybody. Nothing is counted unless everything passes. */
  chargeNow({ key, method, ipHash, vault, now, ceiling, cost, perIpHour, perVaultMinute }) {
    this.prune(now);
    const spent = this.spentToday(key, now);
    if (spent + cost > ceiling) return { ok: false, code: 'daily_ceiling', bucket: key, resets_at: resetsAt(now) };
    const ipWindow = Math.floor(now / HOUR) * HOUR;
    const vaultWindow = Math.floor(now / MINUTE) * MINUTE;
    if (perIpHour) {
      const seen = this.first('SELECT count FROM ip_counter WHERE ip_hash = ? AND method = ? AND window_start = ?', ipHash, method, ipWindow)?.count ?? 0;
      if (seen >= perIpHour) return { ok: false, code: 'rate_limited', retry_after_s: Math.ceil((ipWindow + HOUR - now) / 1000) };
    }
    if (perVaultMinute) {
      const seen = this.first('SELECT count FROM vault_counter WHERE vault = ? AND method = ? AND window_start = ?', vault, method, vaultWindow)?.count ?? 0;
      if (seen >= perVaultMinute) return { ok: false, code: 'rate_limited', retry_after_s: Math.ceil((vaultWindow + MINUTE - now) / 1000) };
    }
    if (perIpHour) this.sql.exec('INSERT INTO ip_counter VALUES (?, ?, ?, 1) ON CONFLICT DO UPDATE SET count = count + 1', ipHash, method, ipWindow);
    if (perVaultMinute) this.sql.exec('INSERT INTO vault_counter VALUES (?, ?, ?, 1) ON CONFLICT DO UPDATE SET count = count + 1', vault, method, vaultWindow);
    this.sql.exec('INSERT INTO daily_ceiling VALUES (?, ?, ?) ON CONFLICT DO UPDATE SET spent = spent + ?', dayOf(now), key, cost, cost);
    return { ok: true, spent: spent + cost };
  }

  refundNow({ bucket, cost, now }) {
    this.sql.exec('UPDATE daily_ceiling SET spent = MAX(0, spent - ?) WHERE day = ? AND bucket = ?', cost, dayOf(now), bucket);
    return { ok: true };
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
    charge({ key, method, ipHash = null, vault = null, now, ceiling }) {
      const spec = RELAY_METHODS[method];
      if (!spec || spec.key !== key || !Number.isFinite(ceiling)) return { ok: false, code: 'bad_request' };
      return this.chargeNow({ key, method, ipHash, vault, now, ceiling, cost: spec.costMicro, perIpHour: spec.perIpHour, perVaultMinute: spec.perVaultMinute });
    },

    /** Gives back what a call charged when its transaction never ran. A per-IP count stays. */
    refund({ bucket, cost, now }) {
      return this.refundNow({ bucket, cost, now });
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
