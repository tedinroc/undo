// What the phone page keeps across a reload: the chain, plus these. The shared fields go through site/lib's strict
// parser. These are the page's own, and they are just as strict. No field here is a key of anything that holds a coin:
// `k` is only written in the test mode, whose vault holds made-up coins.
//
// Anyone can write a link, so nothing a screen claims about a request lives in the fragment. `r` is only a place to
// look, and what this page saw and sent stays in sessionStorage, which a link cannot write.
import { parseFragment } from '/site/lib/index.mjs';

const EXTRA = {
  h7: /^1$/,                                // test mode
  op: /^(02|03)[0-9a-f]{64}$/,              // test mode: the operator passkey's public key. It cannot be asked for twice
  opc: /^[A-Za-z0-9_-]{1,512}$/,            // test mode: its credential id
  log: /^[A-Za-z0-9.~_-]{0,4000}$/,         // test mode: what each tap did
  q: /^[a-z]{0,8}\.?[a-z]{0,8}$/,           // test mode: the two answers only a person can give
  aw: /^(on|refused|none)$/,                 // test mode: whether the screen could be kept on
  pk: /^[a-z0-9.]{0,16}$/,                  // test mode: the first passkey's backup flags and the proof tap's S form
};

const ORDER = ['h7', 'v', 'r', 'c', 'k', 'to', 'pk', 'aw', 'log', 'op', 'opc', 'q'];

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
const SEEN_PREFIX = 'undo-phone:';

/** What this tab saw of a vault's requests and sent itself: { seen, tx, frozen, ks }. Absent in a private window. */
export function recallSeen(vaultHex, win = globalThis) {
  try {
    return JSON.parse(win.sessionStorage.getItem(SEEN_PREFIX + vaultHex) ?? 'null');
  } catch {
    return null;
  }
}

export function rememberSeen(vaultHex, value, win = globalThis) {
  try {
    win.sessionStorage.setItem(SEEN_PREFIX + vaultHex, JSON.stringify(value));
    return true;
  } catch {
    return false;
  }
}

/**
 * localStorage holds the passkey's credential id and nothing else. It can be absent or throw on any call. Only an id
 * that has made an assertion goes in here, never one a link named, or one junk link would break Cancel for good.
 */
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
