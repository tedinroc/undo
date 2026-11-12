// The owner half of /try/ and its Cancel (pages/try/owner.mjs), in Node: a made-up contract, relay, passkey and Esplora,
// and a clock this file moves. Section 11 T8 of the /try/ spec, every row of section 7's CANCEL (C1 to C11), null reads
// and terminal states (the v2 gate), and THE RULE for the Cancel button: every passkey call is made inside the tap, and
// nothing is awaited before it. Every host, key and hash here is made up, and nothing leaves this machine.
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign as nodeSign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { register } from 'node:module';
import { mock, test } from 'node:test';

register('./page-hooks.mjs', import.meta.url);

// ---------------------------------------------------------------- a DOM with just what owner.mjs and kit.mjs touch

class Text {
  constructor(text) { this.text = text; }

  get textContent() { return this.text; }
}

class El {
  constructor(tag) {
    Object.assign(this, { tag, attrs: {}, kids: [], className: '', hidden: false, style: {}, dataset: {}, listeners: {}, parentElement: null, clientWidth: 0 });
    const names = new Set();
    this.classList = {
      add: (c) => names.add(c),
      remove: (c) => names.delete(c),
      toggle: (c, on) => ((on ?? !names.has(c)) ? names.add(c) : names.delete(c)),
      contains: (c) => names.has(c),
    };
  }

  setAttribute(name, value) {
    if (name === 'hidden') this.hidden = true;
    else this.attrs[name] = value;
  }

  getAttribute(name) { return this.attrs[name] ?? null; }

  get id() { return this.attrs.id ?? null; }

  addEventListener(type, fn) { (this.listeners[type] ??= []).push(fn); }

  removeEventListener() {}

  append(...kids) {
    for (const kid of kids) {
      const node = typeof kid === 'string' ? new Text(kid) : kid;
      node.parentElement = this;
      this.kids.push(node);
    }
  }

  replaceChildren(...kids) {
    this.kids = [];
    this.append(...kids);
  }

  get textContent() { return this.kids.map((k) => k.textContent).join(''); }

  set textContent(value) {
    this.kids = [];
    if (value !== '') this.append(String(value));
  }

  getBoundingClientRect() { return { width: 0, height: 0, top: 0, bottom: 0, left: 0, right: 0 }; }

  /** A tap: the listeners run now, and a passkey call made before they return was made inside the tap. */
  click() {
    globalThis.inTap = true;
    try {
      return (this.listeners.click ?? []).map((fn) => fn({ type: 'click', preventDefault() {} }));
    } finally {
      globalThis.inTap = false;
    }
  }

  find(id) {
    if (this.id === id) return this;
    for (const kid of this.kids) {
      const got = kid instanceof El ? kid.find(id) : null;
      if (got) return got;
    }
    return null;
  }

  all(test, out = []) {
    for (const kid of this.kids) {
      if (!(kid instanceof El)) continue;
      if (test(kid)) out.push(kid);
      kid.all(test, out);
    }
    return out;
  }
}

// What watchSheet reads: a page that never loses focus or stops drawing, on a clock this file moves (PERF).
const PERF = { t: 0 };
const fakeDocument = { hidden: false, visibilityState: 'visible', createElement: (tag) => new El(tag), addEventListener() {}, removeEventListener() {}, body: new El('body') };
globalThis.document = fakeDocument;
globalThis.window = {
  document: fakeDocument, performance: { now: () => PERF.t }, requestAnimationFrame: () => 0, cancelAnimationFrame() {}, addEventListener() {}, removeEventListener() {}, innerHeight: 548,
};

const { CANCEL_AGAIN_MS, ownerDrawing, READING_SLOT, RECAP_AFTER_MS, RECAP_ROOM_PX, recapPlace, SEND_GIVE_UP_MS, startOwner } = await import('../pages/try/owner.mjs');
const { NEXT, nextOf, say, W } = await import('../pages/try/words.mjs');
const { digits, nearTxLabel, p256FromSpki, RelayRefused, RpcDown, spkToAddress } = await import('/site/lib/index.mjs');
const { problemWords } = await import('../pages/p/sense.mjs');

// The Next sentences nextOf gives for the owner's states, by their names in words.mjs.
const NEXTS = {
  waiting: NEXT.cancelWaiting, unlocked: NEXT.cancelNow, openPhone: NEXT.openPhone, openPhoneWhy: NEXT.openPhoneWhy, retryPasskey: NEXT.retryPasskey, hang: NEXT.cancelHang,
  waitThenCancel: NEXT.waitThenCancel, keepsReading: NEXT.keepsReading, sendingCancel: NEXT.sendingCancel, done: NEXT.done,
};

const SOURCE = readFileSync(new URL('../pages/try/owner.mjs', import.meta.url), 'utf8');

// ---------------------------------------------------------------- a made-up world

const RP = 'undo.example.test';
const ORIGIN = `https://${RP}`;
const VAULT = 'ab'.repeat(32);
const HASH = 'H'.repeat(44);
const TO = `0014${'99'.repeat(20)}`;
const CRED = new Uint8Array(20).fill(7);
const sha = (b) => new Uint8Array(createHash('sha256').update(b).digest());
const hex = (u8) => Buffer.from(u8).toString('hex');
const ab = (u8) => u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
const b64u = (u8) => Buffer.from(u8).toString('base64url');
const flush = async () => { for (let i = 0; i < 40; i += 1) await new Promise((r) => { setImmediate(r); }); };
const config = { contract: 'c.testnet', rpId: RP, labels: { near: 'NEAR testnet', bitcoin: 'Mutinynet', chip: 'signet test coins' }, nearTxUrl: null, btcTxUrl: null, btcAddressUrl: null };
const instance = { network: 'signet', origins: [ORIGIN] };
const OK_STATUS = { reachable: true, answered: true, code: null, why: null, relayAccount: 'relay.testnet', powBits: 8, owner: { up: true, why: null }, general: { up: true, why: null }, funds: { up: true, why: null } };
const passkey = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const stranger = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const PASSKEY_HEX = hex(p256FromSpki(new Uint8Array(passkey.publicKey.export({ type: 'spki', format: 'der' }))));
const notAllowed = (message) => Object.assign(new Error(message), { name: 'NotAllowedError' });

/** Every view any test saw: nextOf must word each one (T5's rules). */
const SEEN_VIEWS = [];

/** What a phone's passkey answers, signed over what getAssertion asked: by this vault's passkey, or by another one. */
function assertionFor(options, key) {
  const client = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: b64u(new Uint8Array(options.publicKey.challenge)), origin: ORIGIN }));
  const authData = new Uint8Array([...sha(Buffer.from(RP)), 0x1d, 0, 0, 0, 0]);
  const der = new Uint8Array(nodeSign('sha256', Buffer.concat([authData, sha(client)]), { key: key.privateKey, dsaEncoding: 'der' }));
  return { rawId: ab(CRED), response: { authenticatorData: ab(authData), clientDataJSON: ab(new Uint8Array(client)), signature: ab(der) } };
}

function world({ status = OK_STATUS, origin = ORIGIN } = {}) {
  const w = {
    t: 1_000_000, timers: [], seq: 0, visible: true, shows: [], awake: 0,
    vault: {
      id: VAULT, active: true, k_s: '11'.repeat(32), k_s_suspended: false, passkey: PASSKEY_HEX, rp_id_hash: hex(sha(Buffer.from(RP))), spend_epoch: 2,
      frozen_until: null, spend_nonce: 1, passkey_nonce: 0, pending: [], script_pubkey: `0020${'77'.repeat(32)}`, address: 'tb1qvaultaddress',
    },
    requests: new Map(), nulls: new Map(), readFail: 0, lagVault: null, vaultReads: 0,
    status: structuredClone(status), statusReads: 0, posts: [], cancelAnswer: 'ok', outcome: { known: true, settled: true, failure: null }, outcomeReads: 0,
    coinKnown: true, coinSpent: false, get: ['ok'], calls: [], marks: [], views: [],
  };
  w.chain = () => 1_800_000_000_000 + (w.t - 1_000_000);
  w.env = {
    now: () => w.t,
    setTimeout: (fn, ms) => {
      w.seq += 1;
      w.timers.push({ id: w.seq, at: w.t + Math.max(0, ms ?? 0), fn });
      return w.seq;
    },
    clearTimeout: (id) => { w.timers = w.timers.filter((x) => x.id !== id); },
    visible: () => w.visible,
    onShow: (fn) => { w.shows.push(fn); },
    origin,
    hostname: RP,
  };
  /** The contract's cancel_all_and_rotate, as far as a page can see it: a new epoch, K_s and passkey nonce. */
  w.rotate = (args) => {
    w.vault.spend_epoch += 1;
    w.vault.k_s = args.new_k_s;
    w.vault.passkey_nonce += 1;
    w.vault.pending = [];
  };
  w.propose = (id = 1, { unlockIn = 300_000 } = {}) => {
    const now = w.chain();
    w.requests.set(id, {
      id, kind: 'Normal', status: 'Pending', epoch: w.vault.spend_epoch, inputs: [{ txid: '88'.repeat(32), vout: 0, value: 2000 }], to: TO, amount: 1700, change: null, tier: 'New',
      fee: 300, proposed_at: now, base_unlock: now + unlockIn, unlock: now + unlockIn, expires_at: now + 30 * 60_000,
    });
    w.vault.pending.push(id);
  };
  w.ctx = {
    config, instance, sense: { secure: true, api: true, platform: true, mobile: true, inApp: null, ua: 'iPhone' }, awake: { start: () => { w.awake += 1; }, stop() {} },
    skew: { add() {}, sample: () => ({ blockMs: w.chain(), localMs: Date.now() }) },
    views: {
      vault: async () => {
        w.vaultReads += 1;
        if (w.readFail > 0) {
          w.readFail -= 1;
          throw new RpcDown('vault', []);
        }
        if (w.lagVault) {
          const lagging = w.lagVault;
          w.lagVault = null;
          return structuredClone(lagging);
        }
        return structuredClone(w.vault);
      },
      request: async (vault, id) => {
        const nulls = w.nulls.get(id) ?? 0;
        if (nulls > 0) {
          w.nulls.set(id, nulls - 1);
          return null;
        }
        return structuredClone(w.requests.get(id) ?? null);
      },
    },
    reader: {
      blockTime: async () => ({ blockMs: w.chain(), localMs: Date.now(), height: 1 }),
      txOutcome: async () => {
        w.outcomeReads += 1;
        return structuredClone(w.outcome);
      },
    },
    relay: {
      status: async () => {
        w.statusReads += 1;
        return structuredClone(w.status);
      },
      call: async (method, args) => {
        w.posts.push({ method, args });
        const how = w.cancelAnswer;
        if (how === 'never') return new Promise(() => {});
        if (how === 'down-applied') {
          w.rotate(args);
          throw new RelayRefused({ code: 'relay_down', message: 'no answer from the relay: the connection failed' });
        }
        if (typeof how === 'object') throw new RelayRefused(how);
        if (how === 'ok') w.rotate(args);
        return { ok: true, hash: HASH, method };
      },
    },
    esplora: {
      tx: async (txid) => (w.coinKnown ? { txid } : null),
      outspend: async () => ({ spent: w.coinSpent }),
    },
    credentials: {
      get(options) {
        const how = w.get[Math.min(w.calls.length, w.get.length - 1)];
        const call = { inTap: globalThis.inTap === true, challenge: b64u(new Uint8Array(options.publicKey.challenge)), allow: options.publicKey.allowCredentials.map((c) => b64u(new Uint8Array(c.id))), aborted: false, how };
        w.calls.push(call);
        return new Promise((resolve, reject) => {
          options.signal?.addEventListener('abort', () => {
            call.aborted = true;
            reject(Object.assign(new Error('The operation was aborted.'), { name: 'AbortError' }));
          });
          if (how === 'never') return;
          if (how === 'ok') resolve(assertionFor(options, passkey));
          else if (how === 'wrong') resolve(assertionFor(options, stranger));
          // A sheet a person closed: it was up for a while, so the page saw time go by.
          else if (how === 'dismiss') {
            PERF.t += 900;
            reject(notAllowed('This request has been cancelled by the user.'));
          } else if (how === 'blocked') reject(notAllowed('The document is not focused.'));
        });
      },
    },
  };
  /** Moves this world's clock by `ms`, running each timer that falls due in order, and lets the page's promises settle. */
  w.advance = async (ms) => {
    const end = w.t + ms;
    await flush();
    for (;;) {
      w.timers.sort((a, b) => a.at - b.at || a.id - b.id);
      const next = w.timers[0];
      if (!next || next.at > end) break;
      w.timers.shift();
      w.t = Math.max(w.t, next.at);
      next.fn();
      await flush();
    }
    w.t = end;
    await flush();
  };
  w.start = (more = {}) => {
    const owner = startOwner(w.ctx, {
      vaultHex: VAULT, credentialId: CRED, status: structuredClone(w.status),
      onView: (view) => { w.views.push(view); SEEN_VIEWS.push(view); },
      mark: (name) => { w.marks.push(name); },
      env: w.env,
      ...more,
    });
    w.owner = owner;
    return owner;
  };
  return w;
}

/** A tap on Cancel, as the button's listener makes it: the work runs now, inside the tap. */
function tap(fn) {
  globalThis.inTap = true;
  try {
    fn();
  } finally {
    globalThis.inTap = false;
  }
}

/** A world with a vault, the watch on it, and one request read waiting. */
async function waiting(t, opts = {}, { unlockIn = 300_000 } = {}) {
  const w = world(opts);
  const owner = w.start(opts.start);
  t.after(() => owner.stop());
  await w.advance(0);
  w.propose(1, { unlockIn });
  await w.advance(1000);
  return { w, owner };
}

const pick = (view) => ({ state: view.state, fail: view.fail, control: view.control, link: view.link, line: view.line });

// ---------------------------------------------------------------- the watch

test('the request on screen is the one the contract lists, with the contract\'s own numbers (R4)', async (t) => {
  const w = world();
  const owner = w.start();
  t.after(() => owner.stop());
  await w.advance(0);
  assert.equal(owner.view().state, 'watching');
  assert.equal(owner.view().step, null);
  assert.equal(w.calls.length, 0);
  w.propose(1);
  await w.advance(1000);
  const view = owner.view();
  assert.deepEqual(pick(view), { state: 'request', fail: null, control: 'cancel', link: null, line: null });
  assert.equal(view.step, 'cancel');
  assert.equal(view.kind, 'waiting');
  assert.equal(view.request.id, 1);
  assert.equal(view.request.total, 2000);
  assert.equal(view.request.fee, 300);
  assert.equal(view.request.destination, spkToAddress('signet', TO));
  assert.deepEqual(w.marks, ['requestSeen']);
  assert.equal(view.keyStopped, false);
  // What the contract says now is what the screen says: the controller has no other source for a request.
  w.requests.get(1).inputs = [{ txid: '88'.repeat(32), vout: 0, value: 5000 }];
  await w.advance(1000);
  assert.equal(owner.view().request.total, 5000);
  assert.equal(owner.handoffPath(), `/p/#v=${VAULT}&r=1&c=${b64u(CRED)}`);
  assert.ok(!/k=|seed|cold/.test(owner.handoffPath()), 'no key in the hand-off link');
});

test('a null read is believed only after three in a row', async (t) => {
  const { w, owner } = await waiting(t);
  w.nulls.set(1, 1);
  await w.advance(1000);
  await w.advance(1000);
  assert.equal(owner.view().state, 'request', 'two nulls: a node a block behind');
  await w.advance(1000);
  assert.equal(owner.view().kind, 'waiting', 'the row is back, and so is the count');
  w.nulls.set(1, 3);
  await w.advance(1000);
  await w.advance(1000);
  assert.equal(owner.view().kind, 'waiting');
  await w.advance(1000);
  assert.equal(owner.view().kind, 'cancelled', 'three nulls of a request this page read Pending: it is gone');
  assert.equal(owner.view().state, 'cancelled');
  assert.equal(owner.view().keyStopped, false, 'the contract still reads the same K_s: no "That key can\'t ask again."');
  assert.equal(owner.view().cancelHash, null);
  assert.equal(owner.view().cancelSent, false);
});

test('waiting, then unlocked at zero, then the cancel: CANCELLED, the key read changed, the coin unspent', async (t) => {
  const { w, owner } = await waiting(t, {}, { unlockIn: 5000 });
  assert.equal(owner.view().kind, 'waiting');
  assert.equal(nextOf(owner.view()).text, say(NEXTS.waiting));
  assert.match(owner.clock().text, /^0:0[45]\.\d$/);
  await w.advance(5000);
  assert.equal(owner.view().kind, 'unlocked');
  assert.equal(owner.view().control, 'cancel');
  assert.equal(nextOf(owner.view()).text, say(NEXTS.unlocked));
  assert.equal(owner.clock().text, '0:00.0');
  const digest = owner.prep().digest;
  tap(() => owner.cancelTap());
  assert.equal(w.calls.length, 1);
  assert.equal(w.calls[0].inTap, true, 'the sheet was asked for inside the tap');
  assert.deepEqual(w.calls[0].allow, [b64u(CRED)], 'only the passkey this page made');
  assert.equal(w.calls[0].challenge, b64u(digest), 'it signs the digest made before the tap');
  assert.equal(owner.view().state, 'tapped');
  assert.equal(owner.view().control, 'waiting');
  assert.equal(w.awake, 1, 'the screen is kept on, after the call');
  await w.advance(0);
  const sent = w.posts.filter((p) => p.method === 'cancel_all_and_rotate');
  assert.equal(sent.length, 1);
  assert.equal(sent[0].args.vault, VAULT);
  assert.equal(sent[0].args.nonce, 0);
  assert.match(sent[0].args.new_k_s, /^[0-9a-f]{64}$/);
  assert.ok(sent[0].args.assertion.signature);
  await w.advance(400);
  const view = owner.view();
  assert.equal(view.state, 'cancelled');
  assert.equal(view.step, 'cancelled');
  assert.equal(view.control, 'hash');
  assert.equal(view.cancelHash, HASH, 'the chain says this page\'s cancel ran');
  assert.equal(view.keyStopped, true);
  assert.equal(view.coinStill, true);
  assert.ok(Math.abs(view.cancelledWall - Date.now()) < 5000, 'wall time, as the run line is');
  assert.deepEqual(w.marks, ['requestSeen', 'cancelTap', 'assertion', 'cancelSent', 'cancelled', 'coinChecked']);
  assert.deepEqual(nextOf(view), { text: say(NEXTS.done), tag: 'Done' });
  // All read: the watch stops, and leaves nothing running.
  await w.advance(40_000);
  assert.equal(w.timers.length, 0);
});

test('a coin no node knows, or one that is spent, never gets "The coin never moved."', async (t) => {
  const { w, owner } = await waiting(t);
  w.coinKnown = false;
  tap(() => owner.cancelTap());
  await w.advance(1000);
  assert.equal(owner.view().state, 'cancelled');
  await w.advance(20_000);
  assert.equal(owner.view().coinStill, false);
  w.coinKnown = true;
  w.coinSpent = true;
  await w.advance(20_000);
  assert.equal(owner.view().coinStill, false);
  w.coinSpent = false;
  await w.advance(16_000);
  assert.equal(owner.view().coinStill, true);
});

test('a terminal state holds against a lagging read', async (t) => {
  const { w, owner } = await waiting(t);
  // A coin no node knows yet keeps the watch reading after CANCELLED.
  w.coinKnown = false;
  const before = structuredClone(w.vault);
  tap(() => owner.cancelTap());
  await w.advance(1000);
  assert.equal(owner.view().state, 'cancelled');
  // A node behind the one that served the cancel: the old epoch, the request still pending in it.
  w.lagVault = { ...before, pending: [1] };
  w.requests.get(1).epoch = before.spend_epoch;
  const reads = w.vaultReads;
  const seen = w.views.length;
  // After CANCELLED, with the key read changed, the watch reads every 15 s until the coin is checked.
  await w.advance(16_000);
  assert.ok(w.vaultReads > reads, 'the lagging vault was read');
  assert.deepEqual(w.views.slice(seen).map((v) => v.state).filter((s) => s !== 'cancelled'), [], 'not for one read');
  assert.equal(owner.view().state, 'cancelled');
});

test('the request moved on: signed or expired is C11, "That request is no longer waiting.", and a sheet still up ends', async (t) => {
  const { w, owner } = await waiting(t);
  w.get = ['never'];
  tap(() => owner.cancelTap());
  assert.equal(owner.view().state, 'tapped');
  w.requests.get(1).status = 'Signed';
  await w.advance(1000);
  assert.deepEqual(pick(owner.view()), { state: 'other', fail: 'C11', control: 'handoff', link: null, line: say(W.notWaiting) });
  assert.equal(w.calls[0].aborted, true, 'nothing a sheet signs can help this request now');
  assert.equal(nextOf(owner.view()).text, say(NEXTS.openPhone));

  const later = await waiting(t, {}, { unlockIn: 60_000 });
  await later.w.advance(31 * 60_000);
  assert.deepEqual(pick(later.owner.view()), { state: 'other', fail: 'C11', control: 'handoff', link: null, line: say(W.notWaiting) });
  assert.equal(later.owner.view().kind, 'expired');
  assert.equal(later.owner.clock(), null, 'no clock runs for it');
});

test('a second request on the contract is the phone page\'s (C11), and says nothing untrue of the first', async (t) => {
  const { w, owner } = await waiting(t);
  w.propose(2);
  await w.advance(1000);
  const view = owner.view();
  assert.deepEqual(pick(view), { state: 'other', fail: 'C11', control: 'handoff', link: null, line: null });
  assert.equal(view.kind, 'waiting', 'the first still waits, so "no longer waiting" would be untrue');
  assert.equal(owner.handoffPath(), `/p/#v=${VAULT}&r=1&c=${b64u(CRED)}`);
  tap(() => owner.cancelTap());
  assert.equal(w.calls.length, 0, 'no Cancel here');

  // Two in the first read: the first listed is the one the link names, and the phone page shows both.
  const both = world();
  both.propose(1);
  both.propose(2);
  const two = both.start();
  t.after(() => two.stop());
  await both.advance(0);
  assert.equal(two.view().fail, 'C11');
  assert.equal(two.handoffPath(), `/p/#v=${VAULT}&r=1&c=${b64u(CRED)}`);

  // A cancel that is out when a second request lands goes on: it cancels them all.
  const other = await waiting(t);
  tap(() => other.owner.cancelTap());
  other.w.cancelAnswer = 'never';
  other.w.propose(2);
  await other.w.advance(1000);
  assert.equal(other.owner.view().state, 'cancel_sending');
});

test('the digest is made before the tap, and made again once half its time is gone or the passkey nonce moves', async (t) => {
  const { w, owner } = await waiting(t, {}, { unlockIn: 20 * 60_000 });
  const first = owner.prep();
  assert.ok(first, 'made when Cancel was first drawn');
  assert.ok(Math.abs(first.expiresAt - (w.chain() + 10 * 60_000)) <= 2, 'ten minutes on the contract\'s clock');
  await w.advance(4 * 60_000);
  assert.equal(owner.prep(), first, 'six minutes left: the same digest');
  await w.advance(90_000);
  const second = owner.prep();
  assert.notEqual(second, first, 'under five minutes left: a new one');
  assert.ok(second.expiresAt - w.chain() > 9 * 60_000);
  w.vault.passkey_nonce = 4;
  await w.advance(1000);
  const third = owner.prep();
  assert.notEqual(third, second);
  assert.equal(third.nonce, 4);
  tap(() => owner.cancelTap());
  assert.equal(w.calls[0].challenge, b64u(third.digest));
  assert.equal(w.calls[0].inTap, true);
});

// ---------------------------------------------------------------- C1 to C10

test('C1: a sheet closed. "Not cancelled. The passkey did not sign.", Cancel stays, and the next tap asks inside it', async (t) => {
  const { w, owner } = await waiting(t);
  w.get = ['dismiss', 'ok'];
  tap(() => owner.cancelTap());
  await w.advance(0);
  assert.deepEqual(pick(owner.view()), { state: 'request', fail: 'C1', control: 'cancel', link: null, line: say(W.notCancelledNoSign) });
  assert.equal(nextOf(owner.view()).text, say(NEXTS.waiting));
  assert.equal(w.posts.length, 0);
  tap(() => owner.cancelTap());
  assert.deepEqual(w.calls.map((c) => c.inTap), [true, true]);
  assert.equal(owner.view().line, null, 'a new tap clears the old line');
  await w.advance(1000);
  assert.equal(owner.view().state, 'cancelled');
});

test('C2: no passkey came back at once. "Try the passkey again" opens no sheet and puts Cancel back', async (t) => {
  const { w, owner } = await waiting(t);
  w.get = ['blocked', 'ok'];
  tap(() => owner.cancelTap());
  await w.advance(0);
  assert.deepEqual(pick(owner.view()), { state: 'request', fail: 'C2', control: 'retry-passkey', link: null, line: problemWords('webauthn_blocked') });
  assert.equal(nextOf(owner.view()).text, say(NEXTS.retryPasskey));
  owner.retryPasskey();
  assert.equal(w.calls.length, 1, 'no sheet from that button');
  assert.equal(owner.view().control, 'cancel');
  tap(() => owner.cancelTap());
  assert.equal(w.calls[1].inTap, true);
});

test('C3: no sheet after 12 s. Cancel is back with the phone page under it, and its tap ends the stuck call and asks again inside the tap', async (t) => {
  const { w, owner } = await waiting(t);
  w.get = ['never', 'ok'];
  mock.timers.enable({ apis: ['setTimeout'] });
  t.after(() => mock.timers.reset());
  tap(() => owner.cancelTap());
  assert.equal(owner.view().control, 'waiting');
  // A second tap before the page says anything lands on nothing.
  tap(() => owner.cancelTap());
  assert.equal(w.calls.length, 1);
  mock.timers.tick(12_000);
  await flush();
  assert.deepEqual(pick(owner.view()), { state: 'tapped', fail: 'C3', control: 'cancel', link: 'handoff', line: null });
  assert.equal(nextOf(owner.view()).text, say(NEXTS.hang));
  tap(() => owner.cancelTap());
  assert.equal(w.calls.length, 2);
  assert.equal(w.calls[0].aborted, true);
  assert.equal(w.calls[1].inTap, true);
  mock.timers.reset();
  await w.advance(1000);
  assert.equal(owner.view().state, 'cancelled');
});

test('C4: a passkey answer that does not check out for this vault is not sent, and the phone page is the way on', async (t) => {
  const { w, owner } = await waiting(t);
  w.get = ['wrong'];
  tap(() => owner.cancelTap());
  await w.advance(0);
  assert.deepEqual(pick(owner.view()), { state: 'request', fail: 'C4', control: 'handoff', link: null, line: 'Not cancelled. That passkey\'s signature does not check out for this vault.' });
  assert.equal(w.posts.length, 0);
  await w.advance(10_000);
  assert.equal(owner.view().fail, 'C4', 'it stays');
  assert.equal(nextOf(owner.view()).text, say(NEXTS.openPhone));
});

test('C5: too many tries. The wait in its words, Cancel stays, and the next tap asks inside it', async (t) => {
  const { w, owner } = await waiting(t);
  w.cancelAnswer = { code: 'rate_limited', retryAfterS: 30 };
  tap(() => owner.cancelTap());
  await w.advance(0);
  assert.deepEqual(pick(owner.view()), { state: 'request', fail: 'C5', control: 'cancel', link: null, line: 'Not cancelled. Too many tries through the relay. Wait 30 s and tap again.' });
  assert.equal(nextOf(owner.view()).text, say(NEXTS.waitThenCancel));
  w.cancelAnswer = 'ok';
  tap(() => owner.cancelTap());
  assert.deepEqual(w.calls.map((c) => c.inTap), [true, true]);
  await w.advance(1000);
  assert.equal(owner.view().state, 'cancelled');
});

test('C6: refused before the relay sent anything. "Not cancelled." and the relay\'s sentence; the phone page', async (t) => {
  const { w, owner } = await waiting(t);
  w.cancelAnswer = { code: 'wrong_guard' };
  tap(() => owner.cancelTap());
  await w.advance(0);
  assert.deepEqual(pick(owner.view()), { state: 'request', fail: 'C6', control: 'handoff', link: null, line: 'Not cancelled. This vault\'s guard is not this relay.' });
  await w.advance(70_000);
  assert.equal(owner.view().fail, 'C6');
  assert.equal(nextOf(owner.view()).text, say(NEXTS.openPhoneWhy));
});

test('C7: no answer from the relay. Never "Not cancelled"; the contract decides, and reads it CANCELLED', async (t) => {
  const { w, owner } = await waiting(t);
  w.cancelAnswer = 'down-applied';
  tap(() => owner.cancelTap());
  await w.advance(0);
  assert.deepEqual(pick(owner.view()), { state: 'request', fail: 'C7', control: 'reading', link: 'handoff', line: say(W.cancelNoAnswer) });
  assert.equal(nextOf(owner.view()).text, say(NEXTS.keepsReading));
  await w.advance(1000);
  const view = owner.view();
  assert.equal(view.state, 'cancelled');
  assert.equal(view.cancelHash, null, 'this page never read its own cancel run: the recap says only what the contract reads');
  assert.equal(view.cancelSent, true);
});

test('C7: a code the relay can give after it sent: its sentence alone, and Cancel back 60 s after the send if the contract still shows the request', async (t) => {
  const { w, owner } = await waiting(t);
  w.cancelAnswer = { code: 'relay_error' };
  tap(() => owner.cancelTap());
  await w.advance(0);
  assert.deepEqual(pick(owner.view()), { state: 'request', fail: 'C7', control: 'reading', link: 'handoff', line: 'The relay hit an error.' });
  await w.advance(CANCEL_AGAIN_MS - 2000);
  assert.equal(owner.view().fail, 'C7');
  await w.advance(3000);
  assert.deepEqual(pick(owner.view()), { state: 'request', fail: null, control: 'cancel', link: null, line: 'The relay hit an error.' });
  w.cancelAnswer = 'ok';
  tap(() => owner.cancelTap());
  assert.deepEqual(w.calls.map((c) => c.inTap), [true, true]);
});

test('C7 R3: its line is what the relay said, not a read of the contract, so it stays while every read fails, and after the 60 s', async (t) => {
  for (const [answer, line] of [[{ code: 'relay_down' }, say(W.cancelNoAnswer)], [{ code: 'relay_error' }, 'The relay hit an error.']]) {
    const { w, owner } = await waiting(t);
    w.cancelAnswer = answer;
    tap(() => owner.cancelTap());
    await w.advance(0);
    assert.equal(owner.view().fail, 'C7');
    w.readFail = 1_000_000;
    await w.advance(5000);
    let view = owner.view();
    assert.equal(view.readDown, true, 'three reads in a row failed');
    assert.deepEqual(pick(view), { state: 'request', fail: 'C7', control: 'reading', link: 'handoff', line }, `${answer.code}: the line went with the reads`);
    // 60 s after the send Cancel is back, the reads still failing: the relay's words still stand.
    await w.advance(CANCEL_AGAIN_MS);
    view = owner.view();
    assert.equal(view.readDown, true);
    assert.equal(view.control, 'cancel');
    assert.equal(view.line, line, `${answer.code}: the line went with the reads after the 60 s`);
    owner.stop();
  }
});

test('C8: the contract refused the cancel. "Not cancelled." and the contract\'s reason; the phone page', async (t) => {
  const { w, owner } = await waiting(t);
  w.cancelAnswer = 'ok-unapplied';
  w.outcome = { known: true, settled: true, failure: '{"ActionError":{"kind":{"FunctionCallError":{"ExecutionError":"Smart contract panicked: BadNonce"}}}}' };
  tap(() => owner.cancelTap());
  await w.advance(1000);
  assert.deepEqual(pick(owner.view()), { state: 'request', fail: 'C8', control: 'handoff', link: null, line: 'Not cancelled. The vault changed after this was signed.' });
  assert.equal(owner.view().cancelHash, null);
  await w.advance(70_000);
  assert.equal(owner.view().fail, 'C8');
});

test('C9: sent, and nothing settled in 30 s. The tx under the line; Cancel back 60 s after the send', async (t) => {
  const { w, owner } = await waiting(t);
  w.cancelAnswer = 'ok-unapplied';
  w.outcome = { known: false, settled: false, verbatim: 'UNKNOWN_TRANSACTION' };
  tap(() => owner.cancelTap());
  await w.advance(SEND_GIVE_UP_MS - 1000);
  assert.equal(owner.view().state, 'cancel_sending');
  assert.equal(nextOf(owner.view()).text, say(NEXTS.sendingCancel));
  await w.advance(2000);
  const view = owner.view();
  assert.deepEqual(pick(view), { state: 'request', fail: 'C9', control: 'reading', link: 'handoff', line: say(W.sentNotShown) });
  assert.equal(view.words, nearTxLabel(config, HASH));
  assert.equal(view.cancelHash, null, 'no settled outcome, so no hash is this page\'s cancel');
  assert.ok(w.outcomeReads > 10, 'the outcome was read until the page gave up');
  assert.equal(nextOf(view).text, say(NEXTS.keepsReading));
  await w.advance(CANCEL_AGAIN_MS - SEND_GIVE_UP_MS);
  assert.equal(owner.view().control, 'cancel');
  assert.equal(owner.view().line, say(W.sentNotShown));
});

test('C9 R3: while every read fails, no "doesn\'t show it yet" (the read-down line says what is known), the tx stays; a read that answers brings the line back', async (t) => {
  const { w, owner } = await waiting(t);
  w.cancelAnswer = 'ok-unapplied';
  w.outcome = { known: false, settled: false, verbatim: 'UNKNOWN_TRANSACTION' };
  w.readFail = 1_000_000;
  tap(() => owner.cancelTap());
  await w.advance(SEND_GIVE_UP_MS + 1000);
  let view = owner.view();
  assert.equal(view.readDown, true);
  assert.deepEqual(pick(view), { state: 'request', fail: 'C9', control: 'reading', link: 'handoff', line: null });
  assert.equal(view.words, nearTxLabel(config, HASH), 'the relay sent it: its tx stays');
  assert.equal(nextOf(view).text, say(NEXTS.keepsReading));
  // 60 s after the send Cancel is back; the reads still fail, so still no line that only a read could give.
  await w.advance(CANCEL_AGAIN_MS - SEND_GIVE_UP_MS);
  view = owner.view();
  assert.equal(view.control, 'cancel');
  assert.equal(view.line, null);
  // A read answers, with the request still waiting: the contract does not show the cancel, and now that is said.
  w.readFail = 0;
  await w.advance(1000);
  view = owner.view();
  assert.equal(view.readDown, false);
  assert.equal(view.control, 'cancel');
  assert.equal(view.line, say(W.sentNotShown));
  // Gone again: three failed reads, and the line goes with them.
  w.readFail = 1_000_000;
  await w.advance(3000);
  assert.equal(owner.view().readDown, true);
  assert.equal(owner.view().line, null);
});

test('C9: a cancel the contract shows late still ends CANCELLED, with its hash', async (t) => {
  const { w, owner } = await waiting(t);
  w.cancelAnswer = 'ok-unapplied';
  w.outcome = { known: true, settled: true, failure: null };
  tap(() => owner.cancelTap());
  await w.advance(SEND_GIVE_UP_MS + 1000);
  assert.equal(owner.view().fail, 'C9', 'settled, and the request still reads waiting');
  w.rotate(w.posts[0].args);
  await w.advance(1000);
  assert.equal(owner.view().state, 'cancelled');
  assert.equal(owner.view().cancelHash, HASH);
});

test('C10: no Cancel where it cannot work, in /p/\'s words for four reasons and this page\'s own for the rest; back when it can', async (t) => {
  const cases = [
    [{ status: { ...OK_STATUS, owner: { up: false, why: null } } }, 'The relay says it can\'t send a cancel right now, so this page can\'t send one.'],
    [{ status: { ...OK_STATUS, owner: { up: false, why: 'daily_ceiling', resets_at: 1 } } }, 'The relay hit today\'s limit.'],
    [{ origin: 'https://elsewhere.example.test' }, 'This page isn\'t allowed to cancel for this vault.'],
    [{ status: { ...OK_STATUS, owner: { up: false, why: 'owner_key_low' } } }, say(W.cantCancel)],
    [{ status: { ...OK_STATUS, reachable: false, relayAccount: null } }, say(W.cantCancel)],
  ];
  for (const [opts, line] of cases) {
    const { w, owner } = await waiting(t, opts);
    assert.deepEqual(pick(owner.view()), { state: 'request', fail: 'C10', control: 'handoff', link: null, line }, line);
    assert.equal(nextOf(owner.view()).text, say(NEXTS.openPhoneWhy));
    tap(() => owner.cancelTap());
    assert.equal(w.calls.length, 0);
  }
  const { w, owner } = await waiting(t);
  w.vault.frozen_until = w.chain() + 3_600_000;
  await w.advance(1000);
  assert.equal(owner.view().line, 'The cold key has frozen this vault.');
  // The relay's status is read again while a request waits, so Cancel comes back when the relay can send.
  const down = await waiting(t, { status: { ...OK_STATUS, owner: { up: false, why: null } } });
  down.w.status = structuredClone(OK_STATUS);
  await down.w.advance(6000);
  assert.equal(down.owner.view().control, 'cancel');
});

// ---------------------------------------------------------------- the page

test('hidden, the watch reads nothing; shown, it reads at once (L1)', async (t) => {
  const { w, owner } = await waiting(t);
  w.visible = false;
  await w.advance(1000);
  const reads = w.vaultReads;
  await w.advance(30_000);
  assert.equal(w.vaultReads, reads, 'nothing read while hidden');
  w.requests.get(1).status = 'Signed';
  w.visible = true;
  for (const fn of w.shows) fn();
  await w.advance(0);
  assert.equal(w.vaultReads, reads + 1);
  assert.equal(owner.view().fail, 'C11', 'the screen jumps to what the chain says');
});

test('every read failing: after three, the page says so and the digits stop; back when a read answers (L3)', async (t) => {
  const { w, owner } = await waiting(t);
  w.readFail = 3;
  await w.advance(2000);
  assert.equal(owner.view().readDown, false);
  assert.ok(owner.clock());
  await w.advance(1000);
  assert.equal(owner.view().readDown, true);
  assert.equal(owner.clock(), null);
  assert.equal(owner.view().control, 'cancel', 'Cancel still works: it does not need this read');
  await w.advance(1000);
  assert.equal(owner.view().readDown, false);
  assert.ok(owner.clock());
});

test('v1: the watch alone. A request is read; no digest is made and no Cancel is offered', async (t) => {
  const { w, owner } = await waiting(t, { start: { cancelHere: false } });
  assert.equal(owner.view().state, 'request');
  assert.equal(owner.view().control, null);
  assert.equal(owner.view().here, false);
  assert.equal(owner.prep(), null);
  tap(() => owner.cancelTap());
  assert.equal(w.calls.length, 0);
  assert.equal(w.statusReads, 0, 'no status reads for a Cancel that is not here');
});

// ---------------------------------------------------------------- THE RULE

/** The text of a function declared in owner.mjs, from its name to its closing brace at the same indent. */
function body(name) {
  const start = SOURCE.search(new RegExp(`\\n( *)(async )?function ${name}\\(`));
  assert.ok(start >= 0, `owner.mjs declares ${name}`);
  const indent = /\n( *)/.exec(SOURCE.slice(start))[1];
  const end = SOURCE.indexOf(`\n${indent}}\n`, start + 1);
  return SOURCE.slice(start, end + indent.length + 2);
}
const WAITS = /\bawait\b|\.then\(|setTimeout|setInterval|queueMicrotask|\bfetch\(|requestAnimationFrame|\bsleep\(|Promise\./;

test('THE RULE in the source: cancelTap and ensurePrep are plain functions, and nothing in cancelTap waits before askAssertion', () => {
  const tapBody = body('cancelTap');
  assert.doesNotMatch(tapBody, /async function cancelTap/);
  const before = tapBody.slice(0, tapBody.indexOf('askAssertion(')).replace(/^\s*\/\/.*$/gm, '');
  assert.ok(tapBody.includes('askAssertion('), 'cancelTap asks the passkey itself');
  assert.doesNotMatch(before, WAITS);
  // Bookkeeping only before the call: the guards, the precomputed digest, the call's own abort, the old call's abort.
  const calls = [...before.matchAll(/([A-Za-z_.$]+)\(/g)].map((m) => m[1]).filter((name) => name !== 'function cancelTap' && name !== 'cancelTap');
  assert.deepEqual(calls, ['ensurePrep', 'AbortController', 'old.abort.abort']);
  const prep = body('ensurePrep');
  assert.doesNotMatch(prep, /async function ensurePrep/);
  assert.doesNotMatch(prep, WAITS);
  // The Cancel button's listener is a plain arrow that calls the handler and returns.
  assert.match(SOURCE, /id: 'cancel', type: 'button', [^\n]*onclick: \(\) => cancel\(\) \}/);
  assert.doesNotMatch(SOURCE, /onclick: async/);
});

test('one table: every sentence owner.mjs draws comes from words.mjs or site/lib, but the one slot words.mjs does not hold yet', () => {
  const code = SOURCE.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '').replace(/\s\/\/ .*$/gm, '');
  const literals = [...code.matchAll(/'((?:[^'\\\n]|\\.)*)'|`((?:[^`\\]|\\.)*)`/g)].map((m) => m[1] ?? m[2]);
  const sentences = literals.filter((s) => /^[A-Z][a-z']+ [a-z]/.test(s));
  // READING_SLOT may move into words.mjs (W.slotReading); until then it is the one literal here.
  assert.deepEqual(sentences.filter((s) => s !== READING_SLOT), []);
  assert.equal(READING_SLOT, 'Reading the contract');
});

// ---------------------------------------------------------------- the drawing (v2)

/** The two boxes try.mjs gives the drawing, and its sheet. */
function boxes() {
  return { block: new El('div'), dock: new El('div'), sheet: new El('div') };
}

function drawn(w, owner, { thief = { refused: true, nodeWords: 'mandatory-script-verify-flag-failed (Script evaluated without error but finished with a false/empty top stack element)', proposeHash: 'P'.repeat(44) } } = {}) {
  const b = boxes();
  const marks = [];
  const recaps = [];
  const drawing = ownerDrawing({
    owner, config, ...b, thief: () => thief, mark: (name) => marks.push(name), onRecap: (sheet) => recaps.push(sheet),
    onHandoff: () => marks.push('handoff'), timers: { setTimeout: w.env.setTimeout, clearTimeout: w.env.clearTimeout },
  });
  return { ...b, drawing, marks, recaps, draw: () => drawing.draw(owner.view()) };
}

const texts = (node) => node.all(() => true).filter((n) => !n.hidden && n.kids.some((k) => k instanceof Text)).map((n) => n.kids.filter((k) => k instanceof Text).map((k) => k.text).join(''));

test('drawing S4: the request block once, one control in the dock, and the Cancel button\'s tap asks inside the tap', async (t) => {
  const { w, owner } = await waiting(t, {}, { unlockIn: 300_000 });
  const d = drawn(w, owner);
  t.after(() => d.drawing.dispose());
  d.drawing.draw({ ...owner.view(), state: 'watching', request: null });
  assert.equal(d.block.kids.length, 0, 'nothing before a request');
  d.draw();
  const root = d.block.kids[0];
  assert.equal(root.id, 'owner');
  assert.deepEqual(texts(root), [say(W.owner), say(W.seenLabel), say(W.to), spkToAddress('signet', TO), '2,000 sats', '300 sats of it is the Bitcoin fee.', say(W.unlocksIn), ':', '.']);
  assert.equal(d.dock.kids.length, 1);
  const cancel = d.dock.kids[0];
  assert.equal(cancel.id, 'cancel');
  assert.equal(cancel.textContent, `${say(W.cancel)}${say(W.prompt3)}`);
  assert.deepEqual(d.marks, ['cancelShown']);
  d.drawing.frame();
  assert.match(root.find('digits').dataset.clock, /^4:5\d\.\d$/);
  const returned = cancel.click();
  assert.equal(returned.some((r) => r instanceof Promise), false, 'the listener is not async');
  assert.equal(w.calls.length, 1);
  assert.equal(w.calls[0].inTap, true);
  d.draw();
  assert.equal(d.dock.kids[0].id, 'waiting');
  assert.equal(d.dock.kids[0].textContent, say(W.waitingPasskey));
  assert.equal(d.block.kids[0], root, 'the same block: nothing is drawn again');
});

test('drawing S6 and S7: the digits stop where they were, the stamp lands, the hash fills the dock, then the recap\'s four receipts', async (t) => {
  const { w, owner } = await waiting(t);
  const d = drawn(w, owner);
  t.after(() => d.drawing.dispose());
  d.draw();
  await w.advance(2000);
  d.draw();
  d.drawing.frame();
  const digitsNode = d.block.find('digits');
  const held = digitsNode.dataset.clock;
  d.dock.kids[0].click();
  await w.advance(1000);
  d.draw();
  assert.equal(owner.view().state, 'cancelled');
  await w.advance(5000);
  d.drawing.frame();
  assert.equal(digitsNode.dataset.clock, held, 'the digits stopped where they were');
  assert.equal(d.block.find('stamp').textContent, say(W.stamp));
  assert.equal(d.block.find('wait-label').style.visibility, 'hidden', '"unlocks in" is not true of a cancelled request; its box stays');
  assert.equal(d.block.find('at-zero').hidden, true);
  assert.equal(d.block.find('key-line').textContent, say(W.keyStopped));
  assert.equal(d.block.find('coin-line').textContent, say(W.coinStill));
  // The recap rose RECAP_AFTER_MS after the stamp, which the 5 s above covered.
  assert.equal(d.recaps.length, 1);
  const recap = d.sheet.find('recap');
  assert.ok(recap);
  assert.ok(RECAP_AFTER_MS <= 5000);
  assert.equal(recap.find('row-refused').kids[0].textContent, 'Mutinynet refused the key alone.');
  assert.equal(recap.find('node-words').hidden, true);
  recap.find('node-toggle').click();
  assert.equal(recap.find('node-words').hidden, false);
  assert.equal(recap.find('row-wait').kids[0].textContent, `The NEAR contract set a ${digits(300_000).short} public wait on the request.`);
  assert.equal(recap.find('row-cancel-text').textContent, say(W.recapPasskey));
  assert.match(recap.find('cancel-tx').textContent, new RegExp(HASH));
  assert.equal(recap.find('row-key').textContent, say(W.keyStopped));
  assert.equal(recap.find('row-coin').kids[0].textContent, say(W.coinStill));
  assert.equal(d.dock.kids[0].id, 'back-start');
  assert.equal(d.dock.kids[0].attrs.href, '/');
  assert.equal(recap.find('other-device').attrs.href, '/p/');
});

test('drawing after a cancel the relay never answered: the recap says only "The contract reads this request cancelled."', async (t) => {
  const { w, owner } = await waiting(t);
  const d = drawn(w, owner, { thief: { refused: true, nodeWords: null, proposeHash: null } });
  t.after(() => d.drawing.dispose());
  d.draw();
  w.cancelAnswer = 'down-applied';
  w.coinKnown = false;
  d.dock.kids[0].click();
  await w.advance(0);
  d.draw();
  assert.equal(d.dock.kids[0].textContent, READING_SLOT);
  assert.equal(d.dock.find('open-phone-link').textContent, say(W.openPhone));
  d.dock.find('open-phone-link').click();
  assert.ok(d.marks.includes('handoff'));
  assert.equal(d.block.find('owner-line').textContent, say(W.cancelNoAnswer));
  await w.advance(1000);
  d.draw();
  assert.equal(d.block.find('owner-line').hidden, true, 'its line goes once the contract reads CANCELLED');
  await w.advance(RECAP_AFTER_MS + 1000);
  const recap = d.sheet.find('recap');
  assert.equal(recap.find('row-cancel-text').textContent, say(W.recapRead));
  assert.equal(recap.find('cancel-tx').textContent, '', 'the slot stays empty');
  assert.equal(recap.find('node-toggle'), null, 'no words to open');
  assert.equal(recap.find('row-coin'), null, 'no node has said the coin is unspent');
  assert.equal(d.block.find('coin-line').textContent, '');
  w.coinKnown = true;
  await w.advance(16_000);
  d.draw();
  assert.equal(d.block.find('coin-line').textContent, say(W.coinStill));
  assert.equal(recap.find('row-coin').kids[0].textContent, say(W.coinStill));
});

test('drawing a CANCELLED this page did not send: the stamp, an empty hash slot, and no key line while the key is the same', async (t) => {
  const { w, owner } = await waiting(t);
  const d = drawn(w, owner, { thief: { refused: false } });
  t.after(() => d.drawing.dispose());
  d.draw();
  // Another device's cancel that deleted the request and left K_s as it was (a made-up case: it shows what each line needs).
  w.nulls.set(1, 99);
  for (let i = 0; i < 3; i += 1) await w.advance(1000);
  d.draw();
  assert.equal(owner.view().state, 'cancelled');
  assert.equal(d.block.find('stamp').textContent, say(W.stamp));
  assert.equal(d.block.find('key-line').textContent, '');
  assert.deepEqual(d.dock.kids.map((k) => k.id), ['near-tx']);
  assert.equal(d.dock.kids[0].textContent, '');
  await w.advance(RECAP_AFTER_MS + 1000);
  const recap = d.sheet.find('recap');
  assert.equal(recap.find('row-refused'), null, 'the page saw no refusal, so it says none');
  assert.equal(recap.find('row-cancel-text').textContent, say(W.recapRead));
  assert.equal(recap.find('cancel-tx'), null, 'no slot for a cancel this page never sent');
  assert.equal(recap.find('row-key').textContent, '');
});

test('drawing a request that moved on: no clock for it, its line, and the phone page in the dock', async (t) => {
  const { w, owner } = await waiting(t);
  const d = drawn(w, owner);
  t.after(() => d.drawing.dispose());
  d.draw();
  assert.equal(d.block.find('clockblock').hidden, false);
  w.requests.get(1).status = 'Signed';
  await w.advance(1000);
  d.draw();
  assert.equal(d.block.find('clockblock').hidden, true);
  assert.equal(d.block.find('wait-label').hidden, true);
  assert.equal(d.block.find('owner-line').textContent, say(W.notWaiting));
  assert.deepEqual(d.dock.kids.map((k) => k.id), ['open-phone']);
});

test('drawing the rows that take Cancel away: C2, C10 and C11 put one button in the dock, and C3 adds the phone page under Cancel', async (t) => {
  const { w, owner } = await waiting(t);
  const d = drawn(w, owner);
  t.after(() => d.drawing.dispose());
  w.get = ['blocked', 'never'];
  d.draw();
  d.dock.kids[0].click();
  await w.advance(0);
  d.draw();
  assert.deepEqual(d.dock.kids.map((k) => k.id), ['retry-passkey']);
  d.dock.kids[0].click();
  assert.equal(w.calls.length, 1, 'that button opens no sheet');
  d.draw();
  assert.deepEqual(d.dock.kids.map((k) => k.id), ['cancel']);
  mock.timers.enable({ apis: ['setTimeout'] });
  t.after(() => mock.timers.reset());
  d.dock.kids[0].click();
  mock.timers.tick(12_000);
  await flush();
  d.draw();
  assert.deepEqual(d.dock.kids.map((k) => k.id), ['cancel', 'open-phone-link']);
  assert.equal(d.dock.kids[0].attrs['data-again'], '1');
  mock.timers.reset();
  const other = await waiting(t, { status: { ...OK_STATUS, owner: { up: false, why: null } } }, { unlockIn: 3000 });
  const e = drawn(other.w, other.owner);
  t.after(() => e.drawing.dispose());
  e.draw();
  assert.deepEqual(e.dock.kids.map((k) => k.id), ['open-phone']);
  await other.w.advance(3000);
  e.draw();
  assert.equal(other.owner.view().kind, 'unlocked');
  assert.equal(e.block.find('at-zero').hidden, true, '"Cancel works until they do." only where a Cancel is');
  other.w.status = structuredClone(OK_STATUS);
  await other.w.advance(6000);
  e.draw();
  assert.equal(e.dock.kids[0].id, 'cancel');
  assert.equal(e.block.find('at-zero').hidden, false);
  assert.equal(e.block.find('at-zero').textContent, say(W.atZero));
  other.w.status = { ...OK_STATUS, owner: { up: false, why: null } };
  await other.w.advance(6000);
  e.draw();
  assert.equal(e.block.find('owner-line').textContent, 'The relay says it can\'t send a cancel right now, so this page can\'t send one.');
  e.dock.kids[0].click();
  assert.ok(e.marks.includes('handoff'));
});

// ---------------------------------------------------------------- the Next line, for every view these tests drew

test('nextOf words every view the owner half gave: one sentence, at most 160 characters, none of the banned words, Done only when CANCELLED (T5)', () => {
  const owned = SEEN_VIEWS.filter((view) => view.state !== 'watching');
  assert.ok(owned.length > 50);
  const states = new Set();
  for (const view of owned) {
    const { text, tag } = nextOf(view);
    states.add(`${view.state}/${view.fail}`);
    assert.equal(typeof text, 'string');
    assert.ok(text.length > 0 && text.length <= 160, text);
    assert.doesNotMatch(text, /5:00|users|one tap|!/);
    assert.equal(tag === 'Done', view.step === 'cancelled', `${view.state} ${text}`);
  }
  for (const want of ['request/null', 'request/C1', 'request/C2', 'tapped/C3', 'request/C4', 'request/C5', 'request/C6', 'request/C7', 'request/C8', 'request/C9', 'request/C10', 'other/C11', 'tapped/null', 'cancel_sending/null', 'cancelled/null']) {
    assert.ok(states.has(want), `a test drew ${want}`);
  }
});

// ---------------------------------------------------------------- T7's reads, and where the recap sheet goes

test('the watch says how many requests its last read of the vault listed, and nothing when the node gave no vault (try.mjs T7)', async (t) => {
  const w = world();
  const owner = w.start();
  t.after(() => owner.stop());
  await w.advance(0);
  assert.equal(owner.view().state, 'watching');
  assert.equal(owner.view().pendingListed, 0, 'a read that got the vault, with no request on it');
  assert.equal(owner.view().readDown, false);
  // A node behind: no vault in the answer. That says nothing about requests.
  const real = w.ctx.views.vault;
  w.ctx.views.vault = async () => null;
  await w.advance(1000);
  assert.equal(owner.view().pendingListed, null);
  w.ctx.views.vault = real;
  // A request listed whose own read is not back yet: one listed, and the watch still only watches.
  w.propose(1);
  w.nulls.set(1, 1);
  await w.advance(1000);
  assert.equal(owner.view().state, 'watching');
  assert.equal(owner.view().pendingListed, 1);
  // Every read failing: after three, readDown.
  w.readFail = 3;
  await w.advance(3000);
  assert.equal(owner.view().readDown, true);
  await w.advance(1000);
  assert.equal(owner.view().readDown, false);
  assert.equal(owner.view().state, 'request');
});

// Boxes measured in Playwright's WebKit, iPhone 15 profile, at S7 on the local stage: the frame, the top of the lines under
// the rail, the clock's box, the stamp's bottom and the Done line's top, at five screen sizes.
const RECAP_SCREENS = {
  '375x548': { frame: { top: 0, bottom: 548 }, screenTop: 71, clockTop: 249, stampBottom: 352.9, nextTop: 439.6 },
  '320x568': { frame: { top: 0, bottom: 568 }, screenTop: 71, clockTop: 249, stampBottom: 354.1, nextTop: 459.6 },
  '390x664': { frame: { top: 0, bottom: 664 }, screenTop: 81, clockTop: 270.8, stampBottom: 394.9, nextTop: 543 },
  '428x746': { frame: { top: 0, bottom: 746 }, screenTop: 81, clockTop: 296.2, stampBottom: 453.7, nextTop: 625 },
  '390x844': { frame: { top: 0, bottom: 844 }, screenTop: 81, clockTop: 296.2, stampBottom: 446.2, nextTop: 723 },
};

test('the recap sheet covers none of the stamp, the digits, the Done line or the rail, on a short screen too (S7)', () => {
  assert.equal(typeof recapPlace, 'function', 'owner.mjs places the recap sheet');
  // The sheet as the browser lays it out: anchored at `bottom` (or `top`), as tall as its content up to maxHeight.
  const sheetBox = (at, f, content) => {
    const height = Math.min(content, at.maxHeight);
    if (at.where === 'below') {
      const bottom = f.frame.bottom - at.bottom;
      return { top: bottom - height, bottom };
    }
    const top = f.frame.top + at.top;
    return { top, bottom: top + height };
  };
  for (const [size, f] of Object.entries(RECAP_SCREENS)) {
    const at = recapPlace(f);
    for (const content of [40, 300, 5000]) {
      const box = sheetBox(at, f, content);
      // The stamp lies over the lower half of the digits: from the clock's top to the stamp's bottom stays in sight.
      assert.ok(box.bottom <= f.clockTop || box.top >= f.stampBottom, `${size}: over the digits or the stamp (${JSON.stringify(box)})`);
      assert.ok(box.bottom <= f.nextTop, `${size}: over the Done line`);
      assert.ok(box.top >= f.screenTop, `${size}: over the rail`);
    }
    assert.ok(at.maxHeight >= Math.min(RECAP_ROOM_PX, Math.max(f.nextTop - f.stampBottom, f.clockTop - f.screenTop) - 8), `${size}: the larger room is used`);
  }
  assert.equal(recapPlace(RECAP_SCREENS['390x844']).where, 'below', 'under the stamp where it has the room');
  assert.equal(recapPlace(RECAP_SCREENS['390x664']).where, 'below');
  assert.equal(recapPlace(RECAP_SCREENS['428x746']).where, 'below');
  assert.equal(recapPlace(RECAP_SCREENS['375x548']).where, 'above', 'a short screen: over the request\'s lines instead');
  assert.equal(recapPlace(RECAP_SCREENS['320x568']).where, 'above');
});
