// How a page finds its vault and request: the URL fragment, which a browser never sends to a server, so
// no log anywhere holds a vault, a credential id or a key. Strict on reading, because a link can be typed.
import { toBase64Url } from './base64.mjs';

const RULES = {
  v: /^[0-9a-f]{64}$/,          // vault id
  r: /^(0|[1-9][0-9]{0,15})$/,  // request id, as text in the URL
  c: /^[A-Za-z0-9_-]{1,512}$/,  // passkey credential id, base64url. Not a secret
  to: /^[a-z0-9]{14,90}$/,      // destination address, shown and sent as given
  k: /^[0-9a-f]{64}$/,          // the thief tab's stolen seed. Throwaway test coins, and only where a page asks for it
};

// Sixteen digits reach past 2^53, where Number() rounds an id to another request's, so `r` must also read back as itself.
const fits = (name, text) => RULES[name].test(text) && (name !== 'r' || Number.isSafeInteger(Number(text)));

export function parseFragment(hash) {
  const text = String(hash ?? '').replace(/^#/, '');
  const out = {};
  const refused = [];
  for (const [name, value] of new URLSearchParams(text)) {
    if (!Object.hasOwn(RULES, name)) continue;
    if (fits(name, value)) out[name] = name === 'r' ? Number(value) : value;
    else refused.push(name);
  }
  return { ...out, refused };
}

export function buildFragment(fields) {
  const parts = [];
  for (const [name, value] of Object.entries(fields)) {
    if (value === null || value === undefined) continue;
    if (!Object.hasOwn(RULES, name)) throw new Error(`no such fragment field: ${name}`);
    const text = String(value);
    if (!fits(name, text)) throw new Error(`fragment field ${name} is malformed`);
    parts.push(`${name}=${text}`);
  }
  return `#${parts.join('&')}`;
}

/** After a page has read `k`, this takes it back out of the address bar and history entry. */
export function withoutSecret(hash) {
  const fields = parseFragment(hash);
  delete fields.k;
  delete fields.refused;
  return buildFragment(fields);
}

export const credentialToFragment = (rawId) => toBase64Url(rawId instanceof Uint8Array ? rawId : new Uint8Array(rawId));
