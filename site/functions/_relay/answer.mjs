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

/** Whether a 64-byte Ed25519 signature checks, with WebCrypto, because noble's JavaScript does not fit a Worker's CPU limit. */
export async function ed25519Verifies(publicKey, signature, message) {
  try {
    const key = await crypto.subtle.importKey('raw', publicKey, { name: 'Ed25519' }, false, ['verify']);
    return await crypto.subtle.verify({ name: 'Ed25519' }, key, signature, message);
  } catch {
    return false;
  }
}

export const numberOr = (value, fallback) => {
  const n = Number(value);
  return value !== undefined && value !== '' && Number.isFinite(n) ? n : fallback;
};

/** Eight numbers from any way of writing an IPv6 address, or null. `::` and a dotted tail are why text won't do. */
function hextets(text) {
  let body = text;
  const dotted = /^(.*:)(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(body);
  if (dotted) {
    const [, head, a, b, c, d] = dotted;
    body = `${head}${((Number(a) << 8) | Number(b)).toString(16)}:${((Number(c) << 8) | Number(d)).toString(16)}`;
  }
  const parts = body.split('::');
  if (parts.length > 2) return null;
  const head = parts[0] ? parts[0].split(':') : [];
  const tail = parts[1] ? parts[1].split(':') : [];
  const missing = 8 - head.length - tail.length;
  if (parts.length === 1 ? missing !== 0 : missing < 1) return null;
  const all = [...head, ...Array(Math.max(0, missing)).fill('0'), ...tail].map((h) => (/^[0-9a-f]{1,4}$/.test(h) ? Number.parseInt(h, 16) : null));
  return all.includes(null) ? null : all;
}

/**
 * IPv6 hands out a /64 at a time, so a limit per address would be no limit at all. The same /64 has many spellings
 * (`2a01:4f8::1:1`, `2a01:4f8:0:0::2:1`), so it is written out first. A /48 is often free too, and that is left to
 * the proof of work and the ceilings: a whole ISP can share one /48, and strangers should not use up each other's limit.
 */
export function limitAddress(ip) {
  if (!ip) return 'unknown';
  const text = ip.toLowerCase();
  if (!text.includes(':')) return text;
  const all = hextets(text);
  if (!all) return text;
  const mapped = all.slice(0, 5).every((h) => h === 0) && all[5] === 0xffff;
  if (mapped) return `${all[6] >> 8}.${all[6] & 255}.${all[7] >> 8}.${all[7] & 255}`;
  return all.slice(0, 4).map((h) => h.toString(16)).join(':');
}

/** The only form an address is ever kept in. */
export async function hashIp(salt, ip) {
  const digest = await crypto.subtle.digest('SHA-256', utf8(`${salt}|${limitAddress(ip)}`));
  return toHex(new Uint8Array(digest));
}

/** The body as JSON. Reading stops at the cap, because a chunked upload declares no length and could fill the isolate. */
export async function readBody(request) {
  const tooLarge = () => new Refusal('bad_request', { message: 'the body is too large' });
  if (Number(request.headers.get('content-length') ?? 0) > MAX_RELAY_BODY) throw tooLarge();
  const chunks = [];
  let size = 0;
  if (request.body) {
    const reader = request.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_RELAY_BODY) {
        await reader.cancel().catch(() => {});
        throw tooLarge();
      }
      chunks.push(value);
    }
  }
  const buffer = new Uint8Array(size);
  let at = 0;
  for (const chunk of chunks) {
    buffer.set(chunk, at);
    at += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder().decode(buffer));
  } catch {
    throw new Refusal('bad_request', { message: 'the body is not JSON' });
  }
}
