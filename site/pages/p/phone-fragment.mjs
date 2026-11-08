// What the phone page keeps across a reload: the chain, plus these. The shared fields go through site/lib's strict
// parser. These are the page's own, and they are just as strict. No field here is a key of anything that holds a coin:
// `k` is only written in the test mode, whose vault holds made-up coins.
//
// Anyone can write a link, so nothing a screen claims lives in the fragment. `r` is only a place to look, and what
// this page saw and sent stays in sessionStorage, which a link cannot write. That holds for the test mode's report
// too: the tries, the passkey flags and the operator passkey it made are kept there, never in the link.
import { buildFragment, parseFragment, spkToAddress } from '/site/lib/index.mjs';

const CREDENTIAL_ID = /^[A-Za-z0-9_-]{1,512}$/;

const EXTRA = {
  h7: /^1$/,                                // test mode
  opproof: /^[0-9a-f]{64}$/,                // operator check: the deploy's fresh nonce
  opfor: /^[a-z0-9][a-z0-9._-]{1,62}[a-z0-9]$/, // operator check: the instance the deploy will create
};

const ORDER = ['h7', 'v', 'r', 'c', 'k', 'to', 'opproof', 'opfor'];

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

/**
 * The thief tab's link for the vault this tab made: its id, its spend key, and somewhere to send, since the tab keeps
 * "Send everything" off until `to` is an address of the vault's network. The destination is a P2WPKH address of 20
 * random bytes, so nobody holds it and it is never the vault's own P2WSH: the send is the stolen-key case, a new
 * destination with the longer wait. In the contract's `network`'s own form, tb1 or bcrt1, as both pages print it.
 */
export function thiefLink(origin, vaultHex, seedHex, random20, network) {
  if (!(random20 instanceof Uint8Array) || random20.length !== 20) throw new Error('thiefLink: the destination takes 20 bytes');
  const to = spkToAddress(network, Uint8Array.of(0x00, 0x14, ...random20));
  return `${origin}/t/${buildFragment({ v: vaultHex, k: seedHex, to })}`;
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
const H7_KEY = 'undo-h7';
const H7_FIELDS = {
  v: /^[0-9a-f]{64}$/,                      // the test vault this tab made
  op: /^(02|03)[0-9a-f]{64}$/,              // the operator passkey this tab made. It cannot be asked for twice
  opc: CREDENTIAL_ID,                       // its credential id
  log: /^[A-Za-z0-9.~_-]{0,4000}$/,         // what each tap did, read back from the contract
  q: /^[a-z]{0,8}\.?[a-z]{0,8}$/,           // the two answers only a person can give
  aw: /^(on|refused|none)$/,                 // whether the screen could be kept on
  pk: /^[a-z0-9.]{0,16}$/,                  // the first passkey's backup flags and the proof tap's S form
};

/** What this tab's test run made and saw. Only what this tab wrote, so a link cannot put words in the report. */
export function recallH7(win = globalThis) {
  let raw;
  try {
    raw = JSON.parse(win.sessionStorage.getItem(H7_KEY) ?? 'null');
  } catch {
    return {};
  }
  const out = {};
  for (const [name, rule] of Object.entries(H7_FIELDS)) if (typeof raw?.[name] === 'string' && rule.test(raw[name])) out[name] = raw[name];
  return out;
}

export function rememberH7(value, win = globalThis) {
  const out = {};
  for (const name of Object.keys(H7_FIELDS)) if (typeof value?.[name] === 'string' && value[name] !== '') out[name] = value[name];
  try {
    win.sessionStorage.setItem(H7_KEY, JSON.stringify(out));
    return true;
  } catch {
    return false;
  }
}

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
    return value && CREDENTIAL_ID.test(value) ? value : null;
  } catch {
    return null;
  }
}
