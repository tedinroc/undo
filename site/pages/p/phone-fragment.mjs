// What the phone page keeps across a reload: the chain, plus these. The shared fields go through site/lib's strict
// parser. These are the page's own, and they are just as strict. No field here is a key of anything that holds a coin:
// `k` is only written in the test mode, whose vault holds made-up coins.
import { parseFragment } from '/site/lib/index.mjs';

const EXTRA = {
  tx: /^[1-9A-HJ-NP-Za-km-z]{32,64}$/,      // the cancelling NEAR hash. No view names it, so the page keeps it
  f: /^\d{1,3}:\d\d\.\d$/,                  // the digits as they froze on this screen
  h7: /^1$/,                                // test mode
  op: /^(02|03)[0-9a-f]{64}$/,              // test mode: the operator passkey's public key. It cannot be asked for twice
  opc: /^[A-Za-z0-9_-]{1,512}$/,            // test mode: its credential id
  log: /^[A-Za-z0-9.~_-]{0,4000}$/,         // test mode: what each tap did
  q: /^[a-z]{0,8}\.?[a-z]{0,8}$/,           // test mode: the two answers only a person can give
  aw: /^(on|refused|none)$/,                 // test mode: whether the screen could be kept on
  pk: /^[a-z0-9.]{0,16}$/,                  // test mode: the first passkey's backup flags and the proof tap's S form
};

const ORDER = ['h7', 'v', 'r', 'c', 'k', 'to', 'tx', 'f', 'pk', 'aw', 'log', 'op', 'opc', 'q'];

export function parsePhoneFragment(hash) {
  const out = parseFragment(hash);
  for (const [name, value] of new URLSearchParams(String(hash ?? '').replace(/^#/, ''))) {
    if (!Object.hasOwn(EXTRA, name)) continue;
    if (EXTRA[name].test(value)) out[name] = value;
    else out.refused.push(name);
  }
  return out;
}

export function buildPhoneFragment(fields) {
  const parts = [];
  for (const name of ORDER) {
    const value = fields[name];
    if (value === null || value === undefined || value === '') continue;
    parts.push(`${name}=${value}`);
  }
  return parts.length ? `#${parts.join('&')}` : '';
}

/** Rewrites the address bar without a new history entry, and never a server round trip. */
export function writeFragment(fields, win = globalThis) {
  const text = buildPhoneFragment(fields);
  try {
    win.history.replaceState(null, '', text || win.location.pathname);
  } catch {
    // A browser that refuses this keeps the state in memory until the page closes.
  }
  return text;
}

const STORE_PREFIX = 'undo.passkey.';

/** localStorage holds the passkey's credential id and nothing else. It can be absent or throw on any call. */
export function rememberCredential(vaultHex, credentialB64, win = globalThis) {
  try {
    win.localStorage.setItem(STORE_PREFIX + vaultHex, credentialB64);
    return true;
  } catch {
    return false;
  }
}

export function recallCredential(vaultHex, win = globalThis) {
  try {
    const value = win.localStorage.getItem(STORE_PREFIX + vaultHex);
    return value && EXTRA.opc.test(value) ? value : null;
  } catch {
    return null;
  }
}
