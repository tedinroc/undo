// What the relay answers. Every refusal has the same fields, so a page can tell a limit from a ceiling from an
// outage, and none of them ever says anything about a key, an address or a body.
import { toHex, utf8 } from '../../../tools/lib/bytes.mjs';
import { MAX_RELAY_BODY, RELAY_ERRORS } from '../../lib/relay-table.mjs';

/** A refusal with a code from RELAY_ERRORS. `verbatim` is a chain's or node's own text, untouched. */
export class Refusal extends Error {
  constructor(code, { message = code, verbatim = null, retryAfterS = null, bucket = null, resetsAt = null, status = null } = {}) {
    super(message);
    Object.assign(this, { code, verbatim, retryAfterS, bucket, resetsAt, status });
  }
}

/**
 * Fetch as a Worker must do it: workerd throws on `redirect: 'error'`, which the shared readers ask for. 'manual'
 * gives the same guarantee, since a redirect is never followed and its body is not JSON or a txid.
 */
export const workerFetch = (url, init = {}) => globalThis.fetch(url, { ...init, redirect: 'manual' });

const HEADERS = { 'content-type': 'application/json', 'cache-control': 'no-store' };

export const json = (status, value) => new Response(JSON.stringify(value), { status, headers: HEADERS });

export const refused = (err) => json(err.status ?? RELAY_ERRORS[err.code] ?? 500, {
  ok: false,
  code: err.code,
  message: err.message,
  verbatim: err.verbatim,
  retry_after_s: err.retryAfterS,
  bucket: err.bucket,
  resets_at: err.resetsAt,
});

export const numberOr = (value, fallback) => {
  const n = Number(value);
  return value !== undefined && value !== '' && Number.isFinite(n) ? n : fallback;
};

/** IPv6 hands out a /64 at a time, so a limit per address would be no limit at all. */
export function limitAddress(ip) {
  if (!ip) return 'unknown';
  if (!ip.includes(':')) return ip;
  return ip.split(':').slice(0, 4).join(':');
}

/** The only form an address is ever kept in. */
export async function hashIp(salt, ip) {
  const digest = await crypto.subtle.digest('SHA-256', utf8(`${salt}|${limitAddress(ip)}`));
  return toHex(new Uint8Array(digest));
}

/** The body as JSON, its size checked before any of it is parsed. */
export async function readBody(request) {
  const declared = Number(request.headers.get('content-length') ?? 0);
  if (declared > MAX_RELAY_BODY) throw new Refusal('bad_request', { message: 'the body is too large' });
  const buffer = await request.arrayBuffer();
  if (buffer.byteLength > MAX_RELAY_BODY) throw new Refusal('bad_request', { message: 'the body is too large' });
  try {
    return JSON.parse(new TextDecoder().decode(buffer));
  } catch {
    throw new Refusal('bad_request', { message: 'the body is not JSON' });
  }
}
