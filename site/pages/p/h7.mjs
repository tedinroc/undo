// The phone test mode, opened with #h7=1. Make a passkey, cancel real test requests on the contract
// through the relay's owner key until a high-S signature appears or 8 tries are done, make a second passkey labelled
// operator, and say what happened in plain words. The last try is always the film's own call.
//
// A test request names a made-up coin, because the contract does not check coins and this mode moves nothing. Each try
// but the last uses `cancel`, since `cancel_all_and_rotate` suspends the spend key for T_known and would stop the next.
import {
  cancelArgs, cancelDigest, clock, credentialToFragment, fromBase64Url, nearTxLabel, RelayRefused, requestState, rotateArgs, rotateDigest, sendEverything, spendKeys,
} from '/site/lib/index.mjs';
import { concat, fromHex, toHex } from '/tools/lib/bytes.mjs';
import { buildPropose } from '/site/lib/index.mjs';
import { randomBytes } from '/tools/lib/crypto.mjs';
import { decodeTries, encodeTry, reportText, sFormSentence } from './h7-report.mjs';
import { ClockFace, h, hashBlock, setState, show } from './kit.mjs';
import { askAssertion, askNewPasskey, PasskeyFailed } from './passkey-ask.mjs';
import { recallCredential, recallH7, rememberCredential, rememberH7, writeFragment } from './phone-fragment.mjs';
import { openElsewhere, passkeyProblem, problemWords } from './sense.mjs';
import { chainNowOf, confirmVault, prepareVault, sendVault } from './vault-make.mjs';

const MAX_TRIES = 8;
const INTENT_MS = 10 * 60_000;
const PROPOSE_WINDOW_MS = 30 * 60_000;
const READ_WAIT_MS = 20_000;

/**
 * `kept` is what this tab made and saw, from sessionStorage, which a link cannot write: the report says only that.
 * The link holds where to look (the vault, its credential, the test seed), and claims nothing.
 *
 * A record of another vault's run is not this link's run: a link that names no vault, or another one, starts a run of
 * its own, so an earlier run's tries and operator passkey never land in a new vault's report. Only what Start again
 * kept, the tries with no vault yet, carries over.
 */
export function runH7(ctx, fragment, relayStatus) {
  const recalled = recallH7();
  const kept = !recalled.v || recalled.v === fragment.v ? recalled : {};
  const ours = Boolean(kept.v && kept.v === fragment.v);
  const st = {
    ctx, f: fragment, kept, relay: relayStatus, problems: [], tries: decodeTries(kept.log), answers: answersOf(kept.q), seed: fragment.k ? fromHex(fragment.k) : null,
    credential: null, passkeyFlags: ours ? flagsOf(kept.pk) : null, proofS: ours ? proofOf(kept.pk) : null, face: null, drawing: false, raf: null,
  };
  const known = fragment.c ?? (fragment.v ? recallCredential(fragment.v) : null);
  if (known) st.credential = fromBase64Url(known);
  window.undoH7 = st;
  route(st);
}

const answersOf = (q) => {
  const [recording, gestures] = (q ?? '').split('.');
  return { recording: recording || null, gestures: gestures || null };
};
const flagsOf = (pk) => {
  if (!pk) return null;
  return { be: pk.includes('be1'), bs: pk.includes('bs1') };
};
const proofOf = (pk) => (pk && pk.endsWith('.h') ? 'h' : pk && pk.endsWith('.l') ? 'l' : null);

function save(st) {
  st.kept.log = st.tries.map(encodeTry).join('~');
  rememberH7(st.kept);
  st.f.h7 = '1';
  writeFragment(st.f);
}

/** Another test vault: the tries so far count, nothing else carries over. */
function startOver(st) {
  st.f = { h7: '1', refused: [] };
  st.kept = { log: st.kept.log };
  st.passkeyFlags = null;
  st.proofS = null;
  rememberH7(st.kept);
  writeFragment(st.f);
  route(st);
}

function copyLine(st) {
  return h('button', { class: 'link', type: 'button', id: 'copy-small', onclick: () => copyReport(st) }, 'Copy what happened so far');
}

function report(st) {
  return reportText({
    sense: st.ctx.sense, config: st.ctx.config, passkeyFlags: st.passkeyFlags, proofS: st.proofS, tries: st.tries,
    operator: st.kept.op ? { pub: st.kept.op, cred: st.kept.opc } : null, answers: st.answers, vault: st.kept.v ?? null, problems: st.problems, awake: st.kept.aw ?? null,
  });
}

async function copyReport(st) {
  const text = report(st);
  try {
    await navigator.clipboard.writeText(text);
    st.copied = true;
    document.documentElement.dataset.copied = 'yes';
    const button = document.getElementById('copy-report');
    if (button) button.textContent = 'Copied';
  } catch {
    // Clipboard refused: leave the text selectable, which is the one thing that always works.
    const area = h('textarea', { class: 'report', id: 'report-area', readonly: true });
    area.value = text;
    document.getElementById('screen').append(area);
    area.focus();
    area.select();
  }
}

/** Something stopped the run. It says what, with the words it was given, and how to go on. */
function stopped(st, say, words, retry) {
  st.problems.push(words ? `${say} ${words}` : say);
  stopDrawing(st);
  setState('h7_stopped');
  show(
    h('p', { class: 'say', id: 'why' }, say),
    words ? h('p', { class: 'words', id: 'verbatim' }, words) : null,
    openElsewhere(st.ctx.sense) ? h('p', { class: 'small' }, openElsewhere(st.ctx.sense)) : null,
    h('div', { class: 'grow' }),
    retry ? h('button', { class: 'go', type: 'button', id: 'retry', onclick: retry }, 'Try again') : null,
    copyLine(st),
  );
}

function stoppedBy(st, err, retry) {
  if (err instanceof PasskeyFailed) {
    if (err.kind === 'blocked') {
      stopped(st, problemWords('webauthn_blocked'), err.message, retry);
      return;
    }
    if (err.kind === 'wrong_site') {
      stopped(st, 'This page isn\'t allowed to use a passkey here.', err.message, retry);
      return;
    }
    if (err.kind === 'dismissed') {
      stopped(st, 'The sheet closed before it signed.', null, retry);
      return;
    }
    stopped(st, 'The passkey call failed.', err.message, retry);
    return;
  }
  if (err instanceof RelayRefused) {
    const words = err.verbatim ?? `${err.code}: ${err.message}`;
    if (err.code === 'relay_down') stopped(st, 'The relay is down, so this test can\'t go on.', words, retry);
    else if (err.code === 'daily_ceiling') stopped(st, 'The relay hit today\'s limit, so this test can\'t go on.', words, retry);
    else if (err.code === 'rate_limited') stopped(st, `Too many of these from this connection. Wait ${err.retryAfterS ?? 60} s and try again.`, words, retry);
    else stopped(st, 'The relay refused that.', words, retry);
    return;
  }
  stopped(st, 'That did not work.', err.verbatim ?? `${err.name}: ${err.message}`, retry);
}

async function route(st) {
  const { views, reader, skew } = st.ctx;
  try {
    skew.add(await reader.blockTime());
    if (!st.f.v) {
      drawCheck(st);
      return;
    }
    const vault = await views.vault(st.f.v);
    if (!vault) {
      stopped(st, 'That test vault is not on this contract. Start again.', null, () => startOver(st));
      return;
    }
    st.vault = vault;
    if (st.kept.op) drawReport(st);
    else if (vault.k_s_suspended) drawOperator(st);
    else if (!st.seed) {
      stopped(st, 'This test vault\'s spend key is gone, so it can\'t ask again. Start another.', null, () => startOver(st));
    } else await drawTry(st);
  } catch (err) {
    stoppedBy(st, err, () => route(st));
  }
}

// ---------------------------------------------------------------- step 1: what this browser can do, then a passkey

function drawCheck(st) {
  const { sense } = st.ctx;
  const problem = passkeyProblem(sense) ?? (st.ctx.credentials ? null : 'no_webauthn');
  const relayUp = st.relay.general?.up && st.relay.owner?.up;
  setState('h7_check');
  show(
    h('p', { class: 'step' }, 'Test mode, not the film'),
    h('p', { class: 'say' }, 'First, a passkey for a test vault.'),
    h('ul', { class: 'facts', id: 'facts' },
      h('li', {}, `Secure page: ${sense.secure ? 'yes' : 'no'}`),
      h('li', {}, `Passkeys in this browser: ${sense.api ? 'yes' : 'no'}`),
      h('li', {}, `Face ID, fingerprint or screen lock: ${sense.platform === null ? 'this browser won\'t say' : sense.platform ? 'yes' : 'no'}`),
      h('li', { id: 'in-app-fact' }, `Opened inside an app: ${sense.inApp ?? 'no'}`),
      h('li', {}, `Relay: ${relayUp ? 'up' : `down (${st.relay.general?.why ?? st.relay.why ?? 'no answer'})`}`)),
    problem ? h('p', { class: 'notice warn', id: 'why', 'data-why': problem }, problemWords(problem)) : null,
    openElsewhere(sense) ? h('p', { class: 'small', id: 'in-app' }, openElsewhere(sense)) : null,
    h('div', { class: 'grow' }),
    !problem && relayUp ? h('button', { class: 'go', type: 'button', id: 'make', onclick: () => tapMakePasskey(st) }, 'Make a passkey') : null,
    copyLine(st),
  );
}

function hangLine() {
  return h('p', { class: 'notice warn', id: 'hang' }, 'No passkey sheet yet? This browser may be blocking passkeys. Open this page in Safari or Chrome.');
}

function tapMakePasskey(st) {
  const asking = askNewPasskey(st.ctx, { label: 'test vault', onHang: () => document.getElementById('screen').append(hangLine()) });
  setState('h7_wait');
  show(h('p', { class: 'say big' }, 'Waiting for your passkey'), h('p', { class: 'line dim' }, 'The sheet should say test vault.'));
  asking.then((got) => afterPasskey(st, got.passkey), (err) => stoppedBy(st, err, () => drawCheck(st)));
}

async function afterPasskey(st, passkey) {
  st.passkey = passkey;
  st.credential = passkey.credentialId;
  st.passkeyFlags = passkey.flags ? { be: passkey.flags.backupEligible, bs: passkey.flags.backupState } : null;
  setState('h7_wait');
  show(h('p', { class: 'say big' }, 'Passkey made.'), h('p', { class: 'line dim' }, 'Reading the second key from the signer.'));
  try {
    st.relay = await st.ctx.relay.status();
    st.prepared = await prepareVault(st.ctx, passkey);
  } catch (err) {
    stoppedBy(st, err, () => afterPasskey(st, passkey));
    return;
  }
  setState('h7_confirm');
  show(
    h('p', { class: 'step' }, 'Test mode, not the film'),
    h('p', { class: 'say' }, 'One more tap makes the test vault.'),
    h('div', { class: 'grow' }),
    h('button', { class: 'go', type: 'button', id: 'confirm', onclick: () => tapConfirm(st) }, 'Confirm with your passkey'),
  );
}

function tapConfirm(st) {
  const confirming = confirmVault(st.ctx, st.prepared, { guard: st.relay.relayAccount, onHang: () => document.getElementById('screen').append(hangLine()) });
  setState('h7_wait');
  show(h('p', { class: 'say big' }, 'Waiting for your passkey'));
  confirming.then((built) => makeVault(st, built), (err) => stoppedBy(st, err, () => {
    setState('h7_confirm');
    show(h('div', { class: 'grow' }), h('button', { class: 'go', type: 'button', id: 'confirm', onclick: () => tapConfirm(st) }, 'Confirm with your passkey'));
  }));
}

async function makeVault(st, built) {
  setState('h7_making');
  const lines = [];
  const draw = () => show(h('p', { class: 'say big' }, 'Making the test vault'), lines.map((text) => h('p', { class: 'line' }, text)));
  draw();
  st.proofS = built.highS ? 'h' : 'l';
  try {
    const { vault } = await sendVault(st.ctx, st.prepared, built.args, {
      powBits: st.relay.powBits,
      onLine: (step, hash) => {
        if (step === 'work') lines.push('Proof of work done.');
        if (step === 'sent') lines.push(nearTxLabel(st.ctx.config, hash));
        draw();
      },
    });
    st.seed = st.prepared.keys.seed;
    const cred = credentialToFragment(st.credential);
    rememberCredential(vault.id, cred);
    Object.assign(st.f, { v: vault.id, c: cred, k: toHex(st.seed) });
    Object.assign(st.kept, { v: vault.id, pk: `be${st.passkeyFlags?.be ? 1 : 0}.bs${st.passkeyFlags?.bs ? 1 : 0}.${st.proofS}` });
    save(st);
    route(st);
  } catch (err) {
    stoppedBy(st, err, () => makeVault(st, built));
  }
}

// ---------------------------------------------------------------- step 2: the tries

/** A live test request: one the contract already holds, or a new one through the relay. */
async function liveRequest(st) {
  const { views, reader, relay, config, skew } = st.ctx;
  const v = st.f.v;
  let vault = await views.vault(v);
  const chainNow = chainNowOf(skew);
  for (const id of [...vault.pending].sort((a, b) => b - a)) {
    const request = await views.request(v, id);
    if (request && requestState({ request, vault, chainNow }).cancellable) return { vault, request };
  }
  const script = fromHex(await views.script(v));
  const coin = { txid: toHex(randomBytes(32)), vout: 0, value: 2000 };
  const to = concat(Uint8Array.of(0x00, 0x14), randomBytes(20));
  const spend = sendEverything({ coins: [coin], to, script, feeRate: 2 });
  skew.add(await reader.blockTime());
  const args = buildPropose({
    contract: config.contract, vault, script, seed: st.seed, inputs: spend.inputs, to, amount: spend.amount, change: null, nonce: vault.spend_nonce,
    expiresAt: Math.floor(chainNowOf(skew)) + PROPOSE_WINDOW_MS,
  });
  const before = vault.spend_nonce;
  const sent = await relay.call('propose_btc', args);
  const deadline = Date.now() + READ_WAIT_MS;
  for (;;) {
    vault = await views.vault(v);
    if (vault.spend_nonce !== before && vault.pending.length) {
      const id = Math.max(...vault.pending);
      const request = await views.request(v, id);
      if (request) return { vault, request, proposed: sent.hash };
    }
    if (Date.now() > deadline) {
      const outcome = st.relay.relayAccount ? await reader.txOutcome(sent.hash, st.relay.relayAccount) : { known: false };
      throw new Error(`the contract did not take the test request: ${outcome.failure ?? `${nearTxLabel(config, sent.hash)} not read`}`);
    }
    await new Promise((r) => { setTimeout(r, 400); });
  }
}

function stopDrawing(st) {
  st.ctx.awake.stop();
  if (st.raf) cancelAnimationFrame(st.raf);
  st.raf = null;
  st.face?.dispose();
  st.face = null;
  clearInterval(st.skewTimer);
}

async function drawTry(st) {
  setState('h7_asking');
  stopDrawing(st);
  show(h('p', { class: 'step' }, `Try ${st.tries.length + 1} of ${MAX_TRIES}`), h('p', { class: 'say big' }, 'Asking the contract for a test request'));
  const { vault, request } = await liveRequest(st);
  st.vault = vault;
  const last = st.tries.length >= MAX_TRIES - 1 || st.tries.some((t) => t.s === 'h');
  const { config, skew } = st.ctx;
  const expiresAt = Math.floor(chainNowOf(skew)) + INTENT_MS;
  const v = st.f.v;
  let digest;
  let argsFor;
  if (last) {
    const newKs = spendKeys(randomBytes(32)).ks.pub;
    const nonce = vault.passkey_nonce;
    digest = rotateDigest({ contract: config.contract, vaultHex: v, newKs, nonce, expiresAt });
    argsFor = (assertion) => rotateArgs({ vaultHex: v, newKs, nonce, expiresAt, assertion });
  } else {
    digest = cancelDigest({ contract: config.contract, vaultHex: v, request: request.id, expiresAt });
    argsFor = (assertion) => cancelArgs({ vaultHex: v, request: request.id, expiresAt, assertion });
  }

  setState(last ? 'h7_rotate' : 'h7_try');
  const face = new ClockFace();
  st.face = face;
  const lastTry = st.tries[st.tries.length - 1];
  show(
    h('p', { class: 'step', id: 'try-count' }, `Try ${st.tries.length + 1} of ${MAX_TRIES}${last ? ', the last' : ''}`),
    h('p', { class: 'say' }, last ? 'Tap Cancel. This one is the film\'s own call, and it ends the test vault\'s key.' : 'Tap Cancel.'),
    h('p', { class: 'small' }, 'A real request on the contract, naming a made-up coin. Nothing can move.'),
    face.wrap, face.fuse,
    lastTry ? h('p', { class: 'line', id: 'last-try' }, `Try ${st.tries.length}: ${lastTry.s === 'h' ? 'high-S' : 'low-S'}. The contract took it.`) : null,
    h('p', { class: 'small', id: 's-so-far' }, sFormSentence(st.tries)),
    h('div', { class: 'grow' }),
    h('button', { id: 'cancel', type: 'button', onclick: () => tapTry(st, { digest, argsFor, last, request }) }, 'Cancel'),
  );
  face.fit();
  st.ctx.awake.start();
  const draw = () => {
    st.raf = requestAnimationFrame(draw);
    const c = clock(request.unlock, skew.sample(), Date.now(), request.proposed_at);
    if (c) {
      face.set(c.text);
      face.setFuse(c.fuse);
    }
  };
  draw();
  st.skewTimer = setInterval(() => { st.ctx.reader.blockTime().then((s) => skew.add(s)).catch(() => {}); }, 5000);
}

function tapTry(st, { digest, argsFor, last, request }) {
  if (st.busy) return;
  st.busy = true;
  const t0 = performance.now();
  const asking = askAssertion(st.ctx, { digest, credentialId: st.credential, onHang: () => document.getElementById('screen').append(hangLine()) });
  setState('h7_wait');
  document.getElementById('cancel')?.replaceWith(h('div', { class: 'slot', id: 'waiting' }, 'Waiting for your passkey'));
  finishTry(st, asking, { argsFor, last, request, t0, digest });
}

async function finishTry(st, asking, { argsFor, last, request, t0 }) {
  const { relay, views, reader, config } = st.ctx;
  try {
    const { assertion, evidence } = await asking;
    const sheetMs = Math.round(performance.now() - t0);
    setState('h7_sending');
    document.getElementById('waiting')?.replaceWith(h('div', { class: 'slot', id: 'sending' }, 'Sending'));
    const method = last ? 'cancel_all_and_rotate' : 'cancel';
    const sent = await relay.call(method, argsFor(assertion.args));
    const includedMs = Math.round(performance.now() - t0);
    const deadline = Date.now() + READ_WAIT_MS;
    let readMs = null;
    while (readMs === null) {
      const { vault, request: now } = await views.both(st.f.v, request.id);
      const s = requestState({ request: now, vault, chainNow: chainNowOf(st.ctx.skew), lastKnown: request });
      if (s.kind === 'cancelled') readMs = Math.round(performance.now() - t0);
      else {
        if (Date.now() > deadline) {
          const outcome = st.relay.relayAccount ? await reader.txOutcome(sent.hash, st.relay.relayAccount) : { known: false };
          throw new Error(outcome.failure ?? `${nearTxLabel(config, sent.hash)} sent, but the contract does not read cancelled yet`);
        }
        await new Promise((r) => { setTimeout(r, 400); });
      }
    }
    st.tries.push({
      m: last ? 'r' : 'c', s: assertion.highS ? 'h' : 'l', sheetMs, includedMs, readMs, hidden: evidence.hidden, blurred: evidence.blurred, pagehide: evidence.pagehide, stallMs: evidence.stallMs, hash: sent.hash,
    });
    st.kept.aw = st.ctx.awake.state;
    save(st);
    st.busy = false;
    stopDrawing(st);
    if (last) drawOperator(st);
    else await drawTry(st);
  } catch (err) {
    st.busy = false;
    stoppedBy(st, err, () => route(st));
  }
}

// ---------------------------------------------------------------- step 3: the operator passkey

function drawOperator(st) {
  stopDrawing(st);
  setState('h7_operator');
  const lastHash = st.tries[st.tries.length - 1]?.hash ?? null;
  show(
    h('p', { class: 'step' }, 'Test mode, not the film'),
    h('p', { class: 'say' }, sFormSentence(st.tries)),
    lastHash ? hashBlock(nearTxLabel(st.ctx.config, lastHash), lastHash, null) : null,
    h('p', { class: 'line' }, 'Last job: a second passkey, labelled operator. It is a different key from the vault\'s.'),
    h('div', { class: 'grow' }),
    h('button', { class: 'go', type: 'button', id: 'make-operator', onclick: () => tapOperator(st) }, 'Make the operator passkey'),
    copyLine(st),
  );
}

function tapOperator(st) {
  const asking = askNewPasskey(st.ctx, { label: 'operator', onHang: () => document.getElementById('screen').append(hangLine()) });
  setState('h7_wait');
  show(h('p', { class: 'say big' }, 'Waiting for your passkey'), h('p', { class: 'line dim' }, 'The sheet should say operator.'));
  asking.then(({ passkey }) => {
    st.kept.op = toHex(passkey.pubkey);
    st.kept.opc = credentialToFragment(passkey.credentialId);
    save(st);
    drawReport(st);
  }, (err) => stoppedBy(st, err, () => drawOperator(st)));
}

// ---------------------------------------------------------------- step 4: plain words

function answerRow(st, field, question, options) {
  return [
    h('p', { class: 'line' }, question),
    h('div', { class: 'pair' }, options.map(([value, text]) => h('button', {
      class: `go quiet${st.answers[field] === value ? ' picked' : ''}`,
      type: 'button',
      'data-answer': `${field}:${value}`,
      onclick: () => {
        st.answers[field] = value;
        st.kept.q = `${st.answers.recording ?? ''}.${st.answers.gestures ?? ''}`;
        save(st);
        drawReport(st);
      },
    }, text))),
  ];
}

function drawReport(st) {
  stopDrawing(st);
  setState('h7_report');
  show(
    h('p', { class: 'say big', id: 'done' }, 'Done. Copy this and send it.'),
    h('button', { class: 'go', type: 'button', id: 'copy-report', onclick: () => copyReport(st) }, 'Copy the report'),
    h('p', { class: 'line', id: 's-sentence' }, sFormSentence(st.tries)),
    answerRow(st, 'recording', 'If you recorded the screen: did it go blank while the sheet was up? A page can\'t see this.', [['blank', 'Blank'], ['shown', 'Not blank'], ['none', 'Didn\'t record']]),
    answerRow(st, 'gestures', 'How many touches or looks did one Cancel take?', [['one', 'One'], ['more', 'More']]),
    h('pre', { class: 'report', id: 'report' }, report(st)),
  );
  window.scrollTo(0, 0);
}
