// The only clock a page may show. It is the contract's unlock, against the contract's own time, which is
// the block time an RPC node reported, moved forward by how long ago this machine heard it. Local time
// only measures elapsed time; its absolute value never reaches a screen. There is no clock without a
// real request: pass no unlock and you get null, not a number.

/**
 * @param unlock contract's `unlock` in ms, or null when no request exists
 * @param rpcBlockTime { blockMs, localMs } from NearReader.blockTime or SkewTracker.sample()
 * @param localNow this machine's Date.now()
 * @param proposedAt contract's `proposed_at`, for the fuse
 */
export function clock(unlock, rpcBlockTime, localNow, proposedAt = null) {
  if (unlock === null || unlock === undefined || !rpcBlockTime) return null;
  const chainNow = rpcBlockTime.blockMs + (localNow - rpcBlockTime.localMs);
  const remainingMs = Math.max(0, unlock - chainNow);
  const total = proposedAt === null ? null : unlock - proposedAt;
  return {
    chainNow,
    remainingMs,
    zero: remainingMs === 0,
    fuse: total && total > 0 ? Math.min(1, remainingMs / total) : null,
    ...digits(remainingMs),
  };
}

/** m:ss.t. Rounds up, so it reads 0:00.0 only when zero has really come, and 5:00.0 at a fresh 5:00. */
export function digits(remainingMs) {
  const tenthsLeft = Math.ceil(remainingMs / 100);
  const minutes = Math.floor(tenthsLeft / 600);
  const seconds = Math.floor((tenthsLeft % 600) / 10);
  const tenths = tenthsLeft % 10;
  const secondsText = String(seconds).padStart(2, '0');
  return { minutes, seconds, tenths, text: `${minutes}:${secondsText}.${tenths}`, short: `${minutes}:${secondsText}` };
}

/**
 * The best reading of the chain's clock from several polls. Network delay and block age only ever make a reading late,
 * so among recent samples the latest-looking one is closest, with one exception: a node can be wrong the other way, and
 * one such read must not move a clock. So a sample that stands ahead of all the others waits until a second read agrees.
 * A reading can reach the screen up to the block age behind the chain, and never ahead of what two reads reported.
 */
const AGREE_MS = 5000;

export class SkewTracker {
  constructor({ windowMs = 30_000 } = {}) {
    this.windowMs = windowMs;
    this.samples = [];
    this.best = null;
  }

  add({ blockMs, localMs }) {
    this.samples.push({ blockMs, localMs });
    this.samples = this.samples.filter((s) => localMs - s.localMs <= this.windowMs);
    const offset = (s) => s.blockMs - s.localMs;
    const ahead = [...this.samples].sort((a, b) => offset(b) - offset(a));
    // The furthest ahead that a second sample stands close behind. With no two agreeing, the most cautious one.
    this.best = ahead.find((s, i) => i + 1 < ahead.length && offset(s) - offset(ahead[i + 1]) <= AGREE_MS) ?? ahead.at(-1);
    return this.sample();
  }

  /** { blockMs, localMs } for clock(), or null before the first poll. */
  sample() {
    return this.best;
  }
}
