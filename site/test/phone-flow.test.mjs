// What the phone page does on a phone that does not behave: a browser that reports no passkey manager, a passkey call
// that never settles, a sheet refused or closed, a reload, a relay out of reach or at a limit. Each scenario is the
// page's own module in Node (phone-flow-page.mjs) with a made-up browser, network and keychain; no Chrome, no chain.
// Every passkey call in every scenario must have been made inside the tap's own handler: that is the one rule Safari
// holds a page to for Face ID, and no check of navigator.userActivation shows it.
//
// The scenarios run side by side, a few at a time, because several wait out the page's own 12 s before it says that no
// sheet came. Nothing here says anything about a real phone, Safari, or Apple's sheet.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const PAGE = join(dirname(fileURLToPath(import.meta.url)), 'phone-flow-page.mjs');
const VAULT = 'ab'.repeat(32);
// The linked vault's passkey in the made-up keychain: twenty bytes of 7 (phone-flow-page.mjs).
const CRED = Buffer.from(new Uint8Array(20).fill(7)).toString('base64url');
const LINK = `#v=${VAULT}&c=${CRED}`;
const X_IOS = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Twitter for iPhone/11.20';
const IOS17 = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1';
const ANDROID = 'Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36';
const HANG_MS = 15_000;
// A Cancel whose passkey call never settles, left out while the request ends some other way.
const stuckThenEnded = (ended, endedState) => ({
  hash: LINK, stored: true, pending: true, get: ['never'],
  steps: [
    { until: { state: 'request' } }, { tap: 'cancel' }, { until: { id: 'hang' }, max: HANG_MS }, { snap: 'stuck' },
    { set: ended }, { until: { state: endedState } }, { snap: 'ended' },
    { set: { second: true } }, { until: { state: 'request' } }, { wait: 300 }, { snap: 'next' },
  ],
});

const made = (snapName = 'idle') => [{ tap: 'make' }, { until: { id: 'confirm' } }, { tap: 'confirm' }, { until: { state: 'idle' }, max: 12_000 }, { wait: 1200 }, { snap: snapName }];

const SCENARIOS = {
  // ---- a vault made here, start to end
  make: { steps: [{ snap: 'start' }, { tap: 'make' }, { until: { id: 'confirm' } }, { snap: 'confirm' }, { tap: 'confirm' }, { until: { state: 'idle' }, max: 12_000 }, { wait: 1200 }, { snap: 'idle' }] },

  // ---- A1: isUserVerifyingPlatformAuthenticatorAvailable() false on a phone
  platformNoVault: { platform: [false], steps: [{ snap: 'start' }] },
  platformRequest: { platform: [false], hash: LINK, pending: true, steps: [{ until: { state: 'request' } }, { snap: 'request' }] },
  platformAgain: { platform: [false, true], steps: [{ snap: 'before' }, { hide: true }, { show: true }, { until: { noId: 'platform-hint' } }, { snap: 'after' }] },
  platformOwnVault: { platform: [false], hash: LINK, stored: true, pending: true, steps: [{ until: { state: 'request' } }, { snap: 'request' }] },
  platformMade: { platform: [false], pendingAfterCreate: true, steps: [{ tap: 'make' }, { until: { id: 'confirm' } }, { snap: 'confirm' }, { tap: 'confirm' }, { until: { state: 'request' }, max: 12_000 }, { snap: 'request' }] },
  platformIos17: { platform: [false], ua: IOS17, steps: [{ snap: 'start' }] },
  platformAndroid: { platform: [false], ua: ANDROID, steps: [{ snap: 'start' }] },
  noWebauthn: { noWebauthn: true, steps: [{ snap: 'start' }] },

  // ---- A2: a passkey call that never settles
  hangCancel: {
    hash: LINK, stored: true, pending: true, get: ['never', 'ok'],
    steps: [{ until: { state: 'request' } }, { tap: 'cancel' }, { wait: 1000 }, { snap: 'waiting' }, { until: { id: 'hang' }, max: HANG_MS }, { snap: 'hang' }, { tap: 'cancel' }, { until: { state: 'cancelled' }, max: 12_000 }, { snap: 'cancelled' }],
  },
  hangLate: {
    hash: LINK, stored: true, pending: true, get: [{ ms: 13_500, deaf: true }, 'never'],
    steps: [{ until: { state: 'request' } }, { tap: 'cancel' }, { until: { id: 'hang' }, max: HANG_MS }, { tap: 'cancel' }, { wait: 3000 }, { snap: 'after the first call answered late' }],
  },
  hangMake: { create: ['never', 'ok'], steps: [{ tap: 'make' }, { wait: 1000 }, { snap: 'waiting' }, { until: { id: 'hang' }, max: HANG_MS }, { snap: 'hang' }, { tap: 'make' }, { until: { id: 'confirm' } }, { snap: 'confirm' }] },
  hangConfirm: {
    get: ['never', 'ok'],
    steps: [{ tap: 'make' }, { until: { id: 'confirm' } }, { tap: 'confirm' }, { wait: 1000 }, { snap: 'waiting' }, { until: { id: 'hang' }, max: HANG_MS }, { snap: 'hang' }, { tap: 'confirm' }, { until: { state: 'idle' }, max: 12_000 }, { snap: 'idle' }],
  },
  hangInApp: { ua: X_IOS, hash: LINK, pending: true, get: ['never'], steps: [{ until: { state: 'request' } }, { tap: 'cancel' }, { until: { id: 'hang' }, max: HANG_MS }, { snap: 'hang' }] },
  // Everything at once: an app's browser that reports no passkey manager, on a phone that only has the link, stuck.
  hangCrowded: {
    ua: X_IOS, platform: [false], hash: LINK, pending: true, get: ['never'],
    steps: [{ until: { state: 'request' } }, { snap: 'request' }, { tap: 'cancel' }, { wait: 1000 }, { snap: 'waiting' }, { until: { id: 'hang' }, max: HANG_MS }, { snap: 'hang' }],
  },

  // A refusal as late as a closed sheet, with a trace of one (the page lost focus), on the same crowded screen. A blur or
  // a stalled frame can come from something else, so it reads as one with no trace; the next tap's call never settles
  // here so its screen can be read.
  closedCrowded: {
    ua: X_IOS, platform: [false], hash: LINK, pending: true, get: ['dismiss', 'never'],
    steps: [{ until: { state: 'request' } }, { snap: 'request' }, { tap: 'cancel' }, { until: { text: 'Not cancelled' } }, { wait: 300 }, { snap: 'closed' }, { tap: 'cancel' }, { wait: 1000 }, { snap: 'waiting' }],
  },
  // A second instant refusal on the same crowded screen, once the link's id is dropped: no Cancel, and the way on is the
  // button right under the headline, with the lines on what to check under it, so it stays on a small screen.
  blockedTwice: {
    ua: X_IOS, platform: [false], hash: LINK, pending: true, get: ['fast', 'fast'],
    steps: [{ until: { state: 'request' } }, { tap: 'cancel' }, { until: { id: 'notice' } }, { wait: 300 }, { tap: 'cancel' }, { until: { state: 'no_button' } }, { wait: 300 }, { snap: 'blocked' }],
  },
  // The same screen after an instant first refusal of the passkey the link named: the id is dropped, the hint stays and
  // the in-app line makes room, as after a later refusal, so Cancel stays on a small screen. The next tap offers any
  // passkey here.
  blockedCrowded: {
    ua: X_IOS, platform: [false], hash: LINK, pending: true, get: ['fast', 'never'],
    steps: [{ until: { state: 'request' } }, { tap: 'cancel' }, { until: { id: 'notice' } }, { wait: 300 }, { snap: 'blocked' }, { tap: 'cancel' }, { wait: 1000 }, { snap: 'waiting' }],
  },

  // The same screen after a refusal that came as late as a closed sheet, with no trace of one: a person may have closed
  // a sheet that left none, or none came. Its words hold either way, the hint for a sheet that does not come stays, and
  // the in-app line makes room until the next tap.
  quietCrowded: {
    ua: X_IOS, platform: [false], hash: LINK, pending: true, get: ['quiet', 'never'],
    steps: [{ until: { state: 'request' } }, { tap: 'cancel' }, { until: { id: 'notice' } }, { wait: 300 }, { snap: 'quiet' }, { tap: 'cancel' }, { wait: 1000 }, { snap: 'waiting' }],
  },
  // The same inside an app, on a browser that reports a passkey manager: no hint, so the in-app line stays.
  quietInApp: { ua: X_IOS, hash: LINK, pending: true, get: ['quiet'], steps: [{ until: { state: 'request' } }, { tap: 'cancel' }, { until: { id: 'notice' } }, { wait: 300 }, { snap: 'quiet' }] },
  quietConfirm: { get: ['quiet'], steps: [{ tap: 'make' }, { until: { id: 'confirm' } }, { tap: 'confirm' }, { until: { id: 'made-note' } }, { snap: 'quiet' }] },
  quietMake: { create: ['quiet'], steps: [{ tap: 'make' }, { until: { id: 'made-why' } }, { snap: 'quiet' }] },

  // ---- the request ends while a Cancel's call is still out: the call is ended, and its line goes with it
  endCancelled: stuckThenEnded({ rotated: 'cd'.repeat(32) }, 'cancelled'),
  endSigned: stuckThenEnded({ first: 'signed' }, 'too_late'),
  endExpired: stuckThenEnded({ first: 'expired' }, 'expired'),

  // ---- a Make or Confirm call the page gave up on (the sceptic's probes of 4fcf70b, S1, S2, S3, S13)
  // S1: the first Make call is deaf to the abort and answers late, after the tap that asked again; the second never does.
  lateMake: { create: [{ ms: 13_500, deaf: true }, 'never'], steps: [{ tap: 'make' }, { until: { id: 'hang' }, max: HANG_MS }, { tap: 'make' }, { wait: 3000 }, { snap: 'after' }] },
  // S2: the same at Confirm.
  lateConfirm: { get: [{ ms: 13_500, deaf: true }, 'never'], steps: [{ tap: 'make' }, { until: { id: 'confirm' } }, { tap: 'confirm' }, { until: { id: 'hang' }, max: HANG_MS }, { tap: 'confirm' }, { wait: 6000 }, { snap: 'after' }] },
  // S3: a Confirm call that never settles, ended by the tap that asks again, whose own call is still out.
  abortConfirm: { get: ['never', 'never'], steps: [{ tap: 'make' }, { until: { id: 'confirm' } }, { tap: 'confirm' }, { until: { id: 'hang' }, max: HANG_MS }, { tap: 'confirm' }, { wait: 1500 }, { snap: 'after' }] },
  // S13: a slow Confirm sheet that leaves no trace answers after the line came.
  slowConfirm: { get: [13_000], steps: [{ tap: 'make' }, { until: { id: 'confirm' } }, { tap: 'confirm' }, { until: { id: 'hang' }, max: HANG_MS }, { until: { text: 'Signed.' }, max: 5000 }, { snap: 'signed' }] },

  // ---- A3: one instant refusal, then a call that works
  refusedMake: {
    create: ['fast', 'ok'], pendingAfterCreate: true,
    steps: [{ tap: 'make' }, { until: { id: 'retry-passkey' } }, { snap: 'refused' }, { tap: 'retry-passkey' }, { until: { id: 'confirm' } }, { tap: 'confirm' }, { until: { state: 'request' }, max: 12_000 }, { wait: 600 }, { snap: 'request' }],
  },
  refusedConfirm: {
    get: ['fast', 'ok'], pendingAfterCreate: true,
    steps: [{ tap: 'make' }, { until: { id: 'confirm' } }, { tap: 'confirm' }, { until: { id: 'made-note' } }, { snap: 'refused' }, { tap: 'confirm' }, { until: { state: 'request' }, max: 12_000 }, { wait: 600 }, { snap: 'request' }],
  },

  // ---- A4: an instant refusal at Cancel
  refusedCancelOwn: {
    hash: LINK, stored: true, pending: true, get: ['fast', 'ok'],
    steps: [{ until: { state: 'request' } }, { tap: 'cancel' }, { until: { id: 'retry-passkey' } }, { snap: 'refused' }, { tap: 'retry-passkey' }, { until: { id: 'cancel' } }, { tap: 'cancel' }, { until: { state: 'cancelled' }, max: 12_000 }, { snap: 'cancelled' }],
  },
  refusedCancelLink: { hash: LINK, pending: true, get: ['fast', 'ok'], steps: [{ until: { state: 'request' } }, { tap: 'cancel' }, { until: { id: 'notice' } }, { snap: 'refused' }] },

  // ---- B5: a reload before the thief link was copied
  reloaded: { hash: LINK, stored: true, steps: [{ until: { state: 'idle' } }, { wait: 1500 }, { snap: 'idle' }, { tap: 'new-vault' }] },
  visitor: { hash: LINK, steps: [{ until: { state: 'idle' } }, { wait: 1500 }, { snap: 'idle' }] },

  // ---- B6: the relay's status
  relayBack: { relayGet: ['fail', 'fail', 'ok'], steps: [{ snap: 'start' }, { until: { id: 'make' }, max: 22_000 }, { snap: 'back' }, { wait: 6000 }, { snap: 'later' }] },
  relayOut: { relayGet: ['fail'], steps: [{ wait: 40_000 }, { snap: '40 s' }] },
  relayHidden: { relayGet: ['fail', 'fail', 'ok'], steps: [{ hide: true }, { wait: 8000 }, { snap: 'hidden 8 s' }, { show: true }, { until: { relayGets: 2 }, max: 2000 }, { snap: 'shown' }, { wait: 2500 }, { fire: 'online' }, { until: { id: 'make' }, max: 2000 }, { snap: 'online' }] },
  // Coming back, a connection back and a restored page, one right after the other: one read, not three.
  relayBurst: { relayGet: ['fail'], steps: [{ wait: 3000 }, { show: true }, { wait: 300 }, { fire: 'online' }, { wait: 300 }, { fire: 'pageshow' }, { wait: 300 }, { snap: 'burst' }] },
  relayLimit: { generalDown: { why: 'daily_ceiling', resetsInMs: 3_600_000 }, steps: [{ snap: 'start' }, { wait: 8000 }, { snap: '8 s' }, { hide: true }, { show: true }, { until: { relayGets: 2 }, max: 2000 }, { snap: 'came back' }] },
  relayReserve: { generalDown: { why: 'relay_reserve' }, steps: [{ snap: 'start' }] },
  relayPage: { relayGet: ['page', 'ok'], steps: [{ snap: 'start' }, { until: { id: 'make' }, max: 8000 }, { snap: 'back' }] },
  relayRefused: { relayGet: ['refused'], steps: [{ snap: 'start' }, { wait: 6500 }, { snap: 'later' }] },
  // With a request up: no answer (a phone with no signal), a proxy's page, the relay's own no, each read 5 s apart; then
  // a read that answers brings Cancel back.
  requestStatus: {
    hash: LINK, stored: true, pending: true, relayGet: ['ok', 'fail', 'page', 'refused', 'ok'],
    steps: [
      { until: { state: 'request' } }, { snap: 'request' }, { until: { relayGets: 2 }, max: 8000 }, { wait: 400 }, { snap: 'no answer' },
      { until: { relayGets: 3 }, max: 8000 }, { wait: 400 }, { snap: 'page' }, { until: { relayGets: 4 }, max: 8000 }, { wait: 400 }, { snap: 'refused' },
      { until: { id: 'cancel' }, max: 8000 }, { snap: 'back' },
    ],
  },
  // The relay answers, and says its cancel side is down without saying why.
  ownerDown: { hash: LINK, stored: true, pending: true, ownerDown: true, steps: [{ until: { state: 'no_button' } }, { snap: 'down' }] },
  // The same, with "relay_down" as its own reason: it answered, so that is what it said, not what the page saw.
  ownerSaysDown: { hash: LINK, stored: true, pending: true, ownerDown: 'relay_down', steps: [{ until: { state: 'no_button' } }, { snap: 'down' }] },
  // A cancel whose answer never comes: the page's own 20 s run out, the relay sends it after all, and the contract says so.
  cancelTimedOut: {
    hash: LINK, stored: true, pending: true, post: { cancel_all_and_rotate: 'timeout' },
    steps: [
      { until: { state: 'request' } }, { tap: 'cancel' }, { until: { text: 'can\'t tell whether the cancel went out' }, max: 25_000 }, { snap: 'unanswered' },
      { until: { id: 'cancel' }, max: 4000 }, { snap: 'read again' }, { set: { rotated: 'cd'.repeat(32) } }, { until: { state: 'cancelled' } }, { snap: 'cancelled' },
    ],
  },
  // The phone loses its signal as it sends: the cancel gets no answer, and nor do the status reads after it.
  cancelUnreachable: {
    hash: LINK, stored: true, pending: true, netMs: 120, post: { cancel_all_and_rotate: 'fail' },
    steps: [
      { until: { state: 'request' } }, { set: { relayGet: ['fail'] }, tap: 'cancel' }, { until: { text: 'can\'t tell whether the cancel went out' } }, { snap: 'unanswered' },
      { until: { text: 'Can\'t reach the relay' }, max: 4000 }, { snap: 'unreachable' }, { wait: 6000 }, { snap: 'still' },
      { set: { relayGet: ['ok'] } }, { until: { id: 'cancel' }, max: 8000 }, { snap: 'back' },
    ],
  },

  // A relay that answered its status and can't make a vault says why in its own words, never that it is down.
  generalStore: { generalDown: { why: 'state_store_down' }, steps: [{ snap: 'start' }] },
  generalSetup: { generalDown: { why: 'relay_not_configured' }, steps: [{ snap: 'start' }] },
  generalSaysDown: { generalDown: { why: 'relay_down' }, steps: [{ snap: 'start' }] },
  // A cancel the relay answered with an error in its own code, which can come after its sender sent the cancel: the
  // relay had sent it here, and the contract says so.
  cancelErred: {
    hash: LINK, stored: true, pending: true, post: { cancel_all_and_rotate: { status: 500, body: { ok: false, code: 'relay_error', message: 'the relay failed' } } },
    steps: [
      { until: { state: 'request' } }, { tap: 'cancel' }, { until: { text: 'The relay hit an error.' } }, { wait: 300 }, { snap: 'erred' },
      { set: { rotated: 'cd'.repeat(32) } }, { until: { state: 'cancelled' } }, { snap: 'cancelled' },
    ],
  },
  // Codes the relay can give after its sender put the cancel out (a resend whose first send landed unseen): its key's
  // nonce taken, and a node's refusal of the resend. Neither says Not cancelled.
  cancelStale: {
    hash: LINK, stored: true, pending: true, post: { cancel_all_and_rotate: { status: 503, body: { ok: false, code: 'stale_nonce', message: 'nonce retries used up' } } },
    steps: [
      { until: { state: 'request' } }, { tap: 'cancel' }, { until: { id: 'notice' } }, { wait: 300 }, { snap: 'stale' },
      { set: { rotated: 'cd'.repeat(32) } }, { until: { state: 'cancelled' } }, { snap: 'cancelled' },
    ],
  },
  cancelNodeRefused: {
    hash: LINK, stored: true, pending: true, post: { cancel_all_and_rotate: { status: 422, body: { ok: false, code: 'tx_refused', message: 'the node refused the transaction', verbatim: '{"TxExecutionError":{"InvalidTxError":"NotEnoughBalance"}}' } } },
    steps: [{ until: { state: 'request' } }, { tap: 'cancel' }, { until: { id: 'notice' } }, { wait: 300 }, { snap: 'refused' }],
  },
  // A reason whose words are two sentences, given as the relay's own for its cancel side (the real relay never gives it).
  ownerBusy: { hash: LINK, stored: true, pending: true, ownerDown: 'rate_limited', steps: [{ until: { state: 'no_button' } }, { snap: 'down' }] },

  // ---- B7: the dispenser
  fundsLimit: { fundsDown: { why: 'daily_ceiling', resetsInMs: 3_600_000 }, steps: made() },

  // ---- B14: the idle screen's wake lock has a limit. The page's clock runs 60 times faster than its timers here, so
  // ten minutes on the page are ten seconds of this run.
  idleSleeps: {
    clockWarp: 60,
    steps: [
      ...made('idle'), { wait: 5000 }, { touch: true }, { wait: 6000 }, { snap: 'touched' }, { wait: 6500 }, { snap: 'left' },
      { set: { pendingAfterCreate: true } }, { until: { state: 'request' } }, { wait: 300 }, { snap: 'request' },
    ],
  },
  // The page that made the vault, inside its ten idle minutes, cancels a request: CANCELLED is not the idle screen.
  madeCancelled: {
    steps: [...made('idle'), { set: { pendingAfterCreate: true } }, { until: { state: 'request' } }, { tap: 'cancel' }, { until: { state: 'cancelled' }, max: 12_000 }, { wait: 1500 }, { snap: 'cancelled' }],
  },
  fundsDown: { hash: LINK, fundsDown: { why: 'esplora_down' }, steps: [{ until: { state: 'idle' } }, { wait: 1500 }, { snap: 'idle' }, { set: { fundsDown: null } }, { until: { id: 'fund' }, max: 40_000 }, { snap: 'funds back' }] },

  fundsHour: { post: { fund: { status: 429, body: { ok: false, code: 'rate_limited', message: 'too many calls', retry_after_s: 2580 } } }, steps: [...made('made'), { tap: 'fund' }, { until: { text: 'No coins sent.' } }, { snap: 'refused' }] },
  fundsDay: { post: { fund: { status: 429, body: { ok: false, code: 'daily_ceiling', message: 'the funds key is at today\'s limit', resets_at: Date.UTC(2026, 10, 15) } } }, steps: [...made('made'), { tap: 'fund' }, { until: { text: 'No coins sent.' } }, { snap: 'refused' }] },
  // A coin ask with no answer, and the relay's own state_store_down that funds.mjs sends after the coin went out: the
  // page can't tell, and once the balance reads the coin the notice goes. A Bitcoin node's refusal of the funding.
  fundsUnanswered: {
    post: { fund: 'fail' },
    steps: [...made('made'), { tap: 'fund' }, { until: { text: 'whether a coin was sent' } }, { wait: 300 }, { snap: 'unsure' }, { set: { coin: true } }, { until: { noId: 'notice' }, max: 8000 }, { snap: 'coin' }],
  },
  fundsStoreDown: {
    post: { fund: { status: 503, body: { ok: false, code: 'state_store_down', message: 'the coin went out, and the state store did not record it' } } },
    steps: [...made('made'), { tap: 'fund' }, { until: { text: 'whether a coin was sent' } }, { wait: 300 }, { snap: 'unsure' }, { set: { coin: true } }, { until: { noId: 'notice' }, max: 8000 }, { snap: 'coin' }],
  },
  // esplora_down after a broadcast that may yet land (funds.mjs keeps its claim): the page can't tell.
  fundsEsploraDown: {
    post: { fund: { status: 503, body: { ok: false, code: 'esplora_down', message: 'the node did not answer', retry_after_s: 120 } } },
    steps: [...made('made'), { tap: 'fund' }, { until: { text: 'whether a coin was sent' } }, { wait: 300 }, { snap: 'unsure' }, { set: { coin: true } }, { until: { noId: 'notice' }, max: 8000 }, { snap: 'coin' }],
  },
  // A short rate_limited: another funding holds the dispenser's coin, or another ask for this vault holds its claim and
  // its coin may be on its way. The page can't tell which.
  fundsBusy: {
    post: { fund: { status: 429, body: { ok: false, code: 'rate_limited', message: 'another funding holds the coin', retry_after_s: 5 } } },
    steps: [...made('made'), { tap: 'fund' }, { until: { text: 'whether a coin was sent' } }, { wait: 300 }, { snap: 'unsure' }, { set: { coin: true } }, { until: { noId: 'notice' }, max: 8000 }, { snap: 'coin' }],
  },
  // A first ask with no answer; the second tap meets the claim the first still holds (rate_limited, 95 s) while the
  // first one's coin lands. The balance is read at once after each answer, not 15 s later.
  fundsClaimBusy: {
    post: { fund: 'fail' },
    steps: [
      ...made('made'), { tap: 'fund' }, { until: { text: 'whether a coin was sent' } }, { wait: 300 }, { snap: 'unsure' }, { wait: 1500 },
      { set: { post: { fund: { status: 429, body: { ok: false, code: 'rate_limited', message: 'too many asks for coins', retry_after_s: 95 } } }, coin: true } },
      { tap: 'fund' }, { wait: 100 }, { until: { noId: 'notice' }, max: 4000 }, { snap: 'coin' },
    ],
  },
  // A refusal that says no coin was sent (would_refuse: the vault already holds one) still reads the balance at once.
  fundsHolds: {
    post: { fund: { status: 409, body: { ok: false, code: 'would_refuse', message: 'that vault already holds a coin' } } },
    steps: [...made('made'), { set: { coin: true } }, { tap: 'fund' }, { until: { text: 'No coins sent.' } }, { snap: 'refused' }, { until: { noId: 'notice' }, max: 4000 }, { snap: 'coin' }],
  },
  fundsNodeRefused: {
    post: { fund: { status: 422, body: { ok: false, code: 'tx_refused', message: 'the node refused the funding', verbatim: 'sendrawtransaction RPC error: {"code":-26,"message":"min relay fee not met"}' } } },
    steps: [...made('made'), { tap: 'fund' }, { until: { text: 'No coins sent.' } }, { snap: 'refused' }],
  },

  // ---- B8: a slow first sheet that leaves the page no trace
  slowSheet: { create: [13_000], steps: [{ tap: 'make' }, { until: { id: 'hang' }, max: HANG_MS }, { snap: 'hang' }, { until: { id: 'confirm' } }, { snap: 'confirm' }] },

  // ---- B9: the second sheet closed
  closedConfirm: {
    get: ['dismiss', 'ok'],
    steps: [{ tap: 'make' }, { until: { id: 'confirm' } }, { tap: 'confirm' }, { until: { id: 'made-note' } }, { snap: 'closed' }, { tap: 'confirm' }, { until: { state: 'idle' }, max: 12_000 }, { snap: 'idle' }],
  },
  closedMake: { create: ['dismiss'], steps: [{ tap: 'make' }, { until: { id: 'made-why' } }, { snap: 'closed' }] },

  // ---- B10: sent, and not read active
  notActive: {
    neverActive: true, clockWarp: 12,
    steps: [{ tap: 'make' }, { until: { id: 'confirm' } }, { tap: 'confirm' }, { until: { id: 'check-again' }, max: 30_000 }, { snap: 'gave up' }, { set: { neverActive: false } }, { tap: 'check-again' }, { until: { state: 'idle' }, max: 12_000 }, { wait: 300 }, { snap: 'idle' }],
  },

  noAnswer: { post: { create_vault: 'fail' }, steps: [{ tap: 'make' }, { until: { id: 'confirm' } }, { tap: 'confirm' }, { until: { id: 'made-why' } }, { snap: 'no answer' }] },
  // A create answered with JSON that has no code (a proxy's, not the relay's), and the relay's own error: either may come
  // after the creation went out.
  proxyMake: { post: { create_vault: { status: 502, body: { error: 'bad gateway' } } }, steps: [{ tap: 'make' }, { until: { id: 'confirm' } }, { tap: 'confirm' }, { until: { id: 'made-why' } }, { snap: 'proxy' }] },
  erredMake: { post: { create_vault: { status: 500, body: { ok: false, code: 'relay_error', message: 'the relay failed' } } }, steps: [{ tap: 'make' }, { until: { id: 'confirm' } }, { tap: 'confirm' }, { until: { id: 'made-why' } }, { snap: 'erred' }] },
  // The same race as cancelStale, for a creation: a stale nonce, or the state store lost while the relay looked for one.
  // The browser saved a passkey and the page can't read its key: a passkey was made, a vault was not.
  makeNoKey: { noPublicKey: true, steps: [{ tap: 'make' }, { until: { id: 'made-why' } }, { snap: 'nokey' }] },
  staleMake: { post: { create_vault: { status: 503, body: { ok: false, code: 'stale_nonce', message: 'nonce retries used up' } } }, steps: [{ tap: 'make' }, { until: { id: 'confirm' } }, { tap: 'confirm' }, { until: { id: 'made-why' } }, { snap: 'stale' }] },
  storeMake: { post: { create_vault: { status: 503, body: { ok: false, code: 'state_store_down', message: 'the state store is not answering' } } }, steps: [{ tap: 'make' }, { until: { id: 'confirm' } }, { tap: 'confirm' }, { until: { id: 'made-why' } }, { snap: 'store' }] },

  // ---- B11: the relay's limits
  hourLimit: {
    post: { create_vault: { status: 429, body: { ok: false, code: 'rate_limited', message: 'too many calls', retry_after_s: 2400 } } },
    steps: [{ tap: 'make' }, { until: { id: 'confirm' } }, { tap: 'confirm' }, { until: { id: 'made-why' } }, { snap: 'refused' }],
  },
  cancelLimit: {
    hash: LINK, stored: true, pending: true, post: { cancel_all_and_rotate: { status: 429, body: { ok: false, code: 'rate_limited', message: 'too many calls', retry_after_s: 50_000 } } },
    steps: [{ until: { state: 'request' } }, { tap: 'cancel' }, { until: { id: 'notice' } }, { snap: 'refused' }],
  },

  // ---- B12: inside an app's own browser
  inApp: { ua: X_IOS, create: ['fast'], steps: [{ snap: 'start' }, { tap: 'make' }, { until: { id: 'retry-passkey' } }, { snap: 'refused' }] },
};

// ---------------------------------------------------------------- running them

const LIMIT = 8;
let running = 0;
const queue = [];
const slot = () => new Promise((go) => {
  const start = () => {
    running += 1;
    go();
  };
  if (running < LIMIT) start();
  else queue.push(start);
});
const done = () => {
  running -= 1;
  queue.shift()?.();
};

function run(opts) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [PAGE, JSON.stringify(opts)], { stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    let err = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), 150_000);
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (code !== 0) return reject(new Error(`the page run ended with ${code}: ${err.slice(-600)}`));
      try {
        const page = JSON.parse(out.trim().split('\n').pop());
        page.snap = (label) => page.snaps.find((s) => s.label === label) ?? assert.fail(`no snap ${label}`);
        return resolve(page);
      } catch (e) {
        return reject(new Error(`no result from the page run: ${e.message}: ${out.slice(-300)} ${err.slice(-300)}`));
      }
    });
  });
}

// Every scenario starts when this file loads, a few at a time, and each test reads the ones it names.
const results = Object.fromEntries(Object.entries(SCENARIOS).map(([name, opts]) => {
  const result = slot().then(() => run(opts)).finally(done);
  result.catch(() => {});
  return [name, result];
}));

async function page(name) {
  const got = await results[name];
  assert.deepEqual(got.missed, [], `${name}: every step found what it waited for`);
  return got;
}

const T = { timeout: 200_000 };

// ---------------------------------------------------------------- the one rule

test('every passkey call, in every scenario, is made inside the tap\'s own handler, and carries a signal the page can abort', T, async () => {
  let seen = 0;
  for (const name of Object.keys(SCENARIOS)) {
    const got = await results[name];
    for (const call of got.calls) {
      seen += 1;
      assert.equal(call.inTap, true, `${name}: ${call.call} was not called synchronously from the tap: ${JSON.stringify(got.calls)}`);
      assert.equal(call.signal, true, `${name}: ${call.call} has no AbortSignal`);
    }
  }
  assert.ok(seen >= 30, `${seen} calls checked`);
  // The second asks, which end a call that is out before they ask again, are among them.
  for (const [name, kind] of [['hangCancel', 'get'], ['hangMake', 'create'], ['hangConfirm', 'get']]) {
    const mine = (await page(name)).calls.filter((c) => c.call === kind);
    assert.equal(mine.length, 2, name);
    assert.deepEqual(mine.map((c) => [c.inTap, c.aborted]), [[true, true], [true, false]], `${name}: the call that never settled was aborted by the tap that asked again`);
    assert.ok(mine[1].at >= mine[0].at + 12_000, `${name}: and only after the page had said no sheet came`);
  }
});

// ---------------------------------------------------------------- A1

test('A1: a phone whose browser reports no platform authenticator keeps Make and Cancel, with a hint that is right for the iOS its user agent names', T, async () => {
  // The made-up iPhone says iOS 26.2: a passcode, and Apple's path from iOS 18 (support.apple.com/en-us/120758).
  const HINT = 'This browser reports no passkey manager or screen lock it can use. If no passkey sheet comes up, check that this iPhone has a passcode and that AutoFill Passwords and Passkeys is on in Settings > General > AutoFill & Passwords, then come back to this page.';
  const start = (await page('platformNoVault')).snap('start');
  assert.equal(start.state, 'no_vault');
  assert.ok(start.buttons.includes('make'), 'Make a test vault stays');
  assert.equal(start.texts['platform-hint'], HINT);
  assert.equal(start.ids.includes('why'), false, 'and nothing says this phone cannot make a passkey');
  assert.doesNotMatch(start.text, /Face ID/);

  const request = (await page('platformRequest')).snap('request');
  assert.equal(request.state, 'request', 'the clock runs with its Cancel');
  assert.ok(request.buttons.includes('cancel'));
  assert.equal(request.texts['platform-hint'], HINT);

  // Asked again when the page comes back: a passkey manager turned on in Settings takes the hint away with no reload.
  const again = await page('platformAgain');
  assert.ok(again.snap('before').ids.includes('platform-hint'));
  assert.equal(again.snap('after').ids.includes('platform-hint'), false);
  assert.ok(again.snap('after').buttons.includes('make'));
  assert.equal(again.platformAsked, 2, 'the browser was asked twice');

  // Where a passkey has already answered, here or before in this browser, the browser's report is beside the point.
  assert.equal((await page('platformOwnVault')).snap('request').ids.includes('platform-hint'), false, 'this browser has used this vault\'s passkey');
  const madeHere = await page('platformMade');
  assert.equal(madeHere.snap('confirm').text.includes('This browser reports'), false, 'the first sheet came');
  assert.equal(madeHere.snap('request').ids.includes('platform-hint'), false);
  assert.ok(madeHere.snap('request').buttons.includes('cancel'));

  // The words follow the iOS version the user agent names: on 17 and before only the passcode, with no menu path that
  // version does not have; on Android its own step.
  const lead = 'This browser reports no passkey manager or screen lock it can use. If no passkey sheet comes up, ';
  assert.equal((await page('platformIos17')).snap('start').texts['platform-hint'], `${lead}check that this iPhone has a passcode, then come back to this page.`);
  assert.equal((await page('platformAndroid')).snap('start').texts['platform-hint'], `${lead}set a screen lock on this phone, then come back to this page.`);

  // The hard stop that remains: a browser with no WebAuthn at all.
  const none = (await page('noWebauthn')).snap('start');
  assert.equal(none.buttons.includes('make'), false);
  assert.match(none.texts.why, /no passkeys/);
});

// ---------------------------------------------------------------- A2

test('A2: a Cancel whose passkey call never settles gets its button back once the page has said no sheet came; that tap aborts the call and asks again, and sends one cancel', T, async () => {
  const got = await page('hangCancel');
  const waiting = got.snap('waiting');
  assert.equal(waiting.state, 'tapped');
  assert.deepEqual(waiting.buttons, [], 'nothing to tap while a sheet may be on its way');
  assert.ok(waiting.ids.includes('waiting'));
  const hang = got.snap('hang');
  assert.equal(hang.state, 'tapped');
  assert.deepEqual(hang.buttons, ['cancel'], 'the red button is back');
  assert.equal(hang.texts.hang, 'No passkey sheet yet? Tap Cancel again. If none comes, reload this page and try once more.');
  assert.equal(hang.ids.includes('waiting'), false);
  assert.equal(got.snap('cancelled').state, 'cancelled');
  assert.deepEqual(got.posts, ['cancel_all_and_rotate'], 'one cancel went to the relay');
  assert.equal(got.calls.filter((c) => c.call === 'get')[1].allow, 1, 'and the second ask still names this vault\'s passkey');
});

test('A2: the call the page gave up on, answering late, sends nothing and draws nothing', T, async () => {
  const got = await page('hangLate');
  const after = got.snap('after the first call answered late');
  assert.equal(after.state, 'tapped', 'the second ask still has the screen');
  assert.deepEqual(got.posts, [], 'the first call\'s assertion was not sent');
  assert.equal(got.calls.length, 2);
});

test('A2: Make and Confirm get their button back the same way, and the retry makes no second passkey for Confirm', T, async () => {
  const make = await page('hangMake');
  assert.deepEqual(make.snap('waiting').buttons, []);
  assert.deepEqual(make.snap('hang').buttons, ['make']);
  assert.equal(make.snap('hang').texts.hang, 'No passkey sheet yet? Tap Make a test vault again. If none comes, reload this page and try once more.');
  assert.ok(make.snap('confirm').buttons.includes('confirm'));
  assert.equal(make.snap('confirm').ids.includes('hang'), false);

  const confirm = await page('hangConfirm');
  assert.deepEqual(confirm.snap('waiting').buttons, []);
  assert.deepEqual(confirm.snap('hang').buttons, ['confirm']);
  assert.equal(confirm.snap('hang').texts.hang, 'No passkey sheet yet? Tap Confirm again. If none comes, reload this page and try once more.');
  assert.equal(confirm.snap('idle').state, 'idle');
  assert.equal(confirm.calls.filter((c) => c.call === 'create').length, 1, 'one passkey');
  assert.deepEqual(confirm.posts, ['create_vault']);

  // Inside an app the sentence still says where to go, and the button is back there too.
  const inApp = (await page('hangInApp')).snap('hang');
  assert.match(inApp.texts.hang, /may be blocking passkeys\. Open this page in Safari or Chrome, or tap Cancel to try once more\./);
  assert.deepEqual(inApp.buttons, ['cancel']);
});

test('A2: a Make or Confirm call the page gave up on draws nothing and sends nothing when it answers late; a Confirm the tap ended draws no "sheet closed"; the line goes when a slow sheet answers', T, async () => {
  // S1: the first Make call answers after the tap that asked again. Its passkey is not the vault's, and is never drawn.
  const make = await page('lateMake');
  assert.equal(make.drawn.some((d) => d.includes('Passkey made.')), false, `the dropped call's passkey was not drawn: ${make.drawn.slice(-3).join(' / ')}`);
  assert.equal(make.snap('after').state, 'creating');
  assert.match(make.snap('after').text, /Waiting for your passkey/, 'the screen still waits on the call that counts');
  // S2: the first Confirm call answers after the tap that asked again: its signature is not sent.
  const confirm = await page('lateConfirm');
  assert.deepEqual(confirm.posts, [], 'no create_vault from the call the page gave up on');
  assert.equal(confirm.drawn.some((d) => d.includes('Signed.')), false);
  // S3: the again-tap ended the first Confirm call; its AbortError must not say the sheet closed, or offer a Confirm
  // whose tap would end the call that is out now.
  const aborted = (await page('abortConfirm')).snap('after');
  assert.deepEqual(aborted.buttons, [], 'nothing to tap while the new sheet may be on its way');
  assert.equal(aborted.ids.includes('made-note'), false);
  assert.doesNotMatch(aborted.text, /The sheet closed|No passkey sheet came up/);
  // S13: a slow Confirm sheet that left no trace answers after 12 s: the line goes beside "Signed.".
  const slow = (await page('slowConfirm')).snap('signed');
  assert.match(slow.text, /Signed\./);
  assert.equal(slow.ids.includes('hang'), false, `the line is gone beside "Signed.": ${slow.text}`);
});

test('A2: on a crowded screen (an app\'s browser that reports no passkey manager), while the line about the sheet is up the hint and the in-app line step aside, so Cancel stays on a small screen', T, async () => {
  const got = await page('hangCrowded');
  const request = got.snap('request');
  assert.ok(request.ids.includes('platform-hint') && request.ids.includes('in-app'), `both are there before the tap: ${request.ids}`);
  assert.ok(got.snap('waiting').ids.includes('platform-hint'), 'and while the sheet may still come');
  const hang = got.snap('hang');
  assert.deepEqual(hang.buttons, ['cancel']);
  assert.match(hang.texts.hang, /This app's browser may be blocking passkeys\. Open this page in Safari or Chrome/, 'the line itself says to leave the app');
  assert.equal(hang.ids.includes('platform-hint'), false);
  assert.equal(hang.ids.includes('in-app'), false);
});

test('A2: a refusal after a trace of a sheet does not say the sheet closed either: a blur or a stalled frame can come from something else, so it says what holds in every case, and the hint stays', T, async () => {
  const got = await page('closedCrowded');
  const request = got.snap('request');
  assert.ok(request.ids.includes('platform-hint') && request.ids.includes('in-app'), `both are there before the tap: ${request.ids}`);
  const closed = got.snap('closed');
  assert.equal(closed.state, 'request');
  assert.equal(closed.texts.notice, 'Not cancelled. The passkey did not sign.');
  assert.doesNotMatch(closed.text, /sheet closed|If it offered no passkey/, 'no sheet the page can only guess at');
  assert.ok(closed.ids.includes('platform-hint'), `the hint for a sheet that did not come stays: ${closed.ids}`);
  assert.equal(closed.ids.includes('in-app'), false, 'the in-app line, said before the tap, makes room for the notice');
  assert.deepEqual(closed.buttons, ['cancel']);
  // The next tap clears the notice, and the in-app line comes back with it.
  const waiting = got.snap('waiting');
  assert.equal(waiting.state, 'tapped');
  assert.ok(waiting.ids.includes('platform-hint') && waiting.ids.includes('in-app'), `${waiting.ids}`);
  // An instant first refusal of the passkey a link named says only what holds whether no sheet came, no passkey, or a
  // sheet shut at once; the id is dropped, so the next tap offers any passkey here. As after a later refusal the hint
  // stays and the in-app line makes room, so Cancel stays on a small screen.
  const fast = await page('blockedCrowded');
  const blocked = fast.snap('blocked');
  assert.equal(blocked.texts.notice, 'Not cancelled. The passkey did not sign.');
  assert.doesNotMatch(blocked.text, /No passkey sheet came up|sheet closed/);
  assert.ok(blocked.ids.includes('platform-hint'), `the hint stays: ${blocked.ids}`);
  assert.equal(blocked.ids.includes('in-app'), false, `the in-app line makes room for the notice: ${blocked.ids}`);
  assert.deepEqual(blocked.buttons, ['cancel']);
  assert.equal(blocked.hash.includes('c='), false, 'the link\'s id is dropped');
  const again = fast.snap('waiting');
  assert.ok(again.ids.includes('platform-hint') && again.ids.includes('in-app'), `both back with the next tap: ${again.ids}`);
  assert.deepEqual(fast.calls.map((c) => c.allow), [1, 0], 'the next tap offers any passkey here');
});

test('A2: after a second instant refusal on the crowded screen, "Try the passkey again" sits right under the headline and the lines on what to check go under it, so a small screen keeps the button', T, async () => {
  const blocked = (await page('blockedTwice')).snap('blocked');
  assert.equal(blocked.state, 'no_button');
  assert.equal(blocked.texts.why, 'No passkey came back. This phone may not hold this vault\'s passkey, or this browser may be blocking passkeys.');
  const at = (id) => blocked.order.indexOf(id);
  assert.equal(at('retry-passkey'), at('why') + 1, `the button right under the headline: ${blocked.order}`);
  for (const id of ['that-phone', 'platform-hint', 'in-app', 'tool']) assert.ok(at(id) > at('retry-passkey'), `${id} under the button: ${blocked.order}`);
  assert.doesNotMatch(blocked.text, /No passkey sheet came up|sheet closed/);
});

test('A2: a refusal as late as a closed sheet but with no trace of one does not say the sheet closed: it says what holds either way, and the hint stays', T, async () => {
  const got = await page('quietCrowded');
  const quiet = got.snap('quiet');
  assert.equal(quiet.state, 'request');
  assert.equal(quiet.texts.notice, 'Not cancelled. The passkey did not sign.');
  assert.doesNotMatch(quiet.text, /sheet closed|If it offered no passkey/, 'no sheet the page did not see');
  assert.ok(quiet.ids.includes('platform-hint'), `the hint for a sheet that did not come stays: ${quiet.ids}`);
  assert.equal(quiet.ids.includes('in-app'), false, 'the in-app line, said before the tap, makes room for the notice');
  assert.deepEqual(quiet.buttons, ['cancel']);
  const waiting = got.snap('waiting');
  assert.equal(waiting.state, 'tapped');
  assert.ok(waiting.ids.includes('platform-hint') && waiting.ids.includes('in-app'), `both back with the next tap: ${waiting.ids}`);
  // With no hint up there is room, and inside an app the in-app line is the one to read: it stays.
  const inApp = (await page('quietInApp')).snap('quiet');
  assert.equal(inApp.texts.notice, 'Not cancelled. The passkey did not sign.');
  assert.equal(inApp.ids.includes('platform-hint'), false);
  assert.ok(inApp.ids.includes('in-app'), `${inApp.ids}`);
  // Make and Confirm, the same.
  const make = (await page('quietMake')).snap('quiet');
  assert.equal(make.texts['made-why'], 'No passkey came back, so nothing was made.');
  assert.ok(make.buttons.includes('make'));
  const confirm = (await page('quietConfirm')).snap('quiet');
  assert.equal(confirm.texts['made-note'], 'The passkey did not sign. Tap Confirm to try again.');
  assert.deepEqual(confirm.buttons, ['confirm']);
  for (const s of [make, confirm]) assert.doesNotMatch(s.text, /sheet closed/);
});

test('A2: a request that ends (cancelled elsewhere, signed, expired) while a Cancel\'s call is still out ends that call, and the next request shows no line about it', T, async () => {
  for (const [name, state] of [['endCancelled', 'cancelled'], ['endSigned', 'too_late'], ['endExpired', 'expired']]) {
    const got = await page(name);
    assert.ok(got.snap('stuck').ids.includes('hang'), `${name}: the line was up`);
    assert.equal(got.snap('ended').state, state);
    assert.equal(got.calls.length, 1, `${name}: nothing was asked again`);
    assert.equal(got.calls[0].aborted, true, `${name}: the call that never settled was ended when the request ended`);
    const next = got.snap('next');
    assert.equal(next.state, 'request', `${name}: ${next.text}`);
    assert.equal(next.ids.includes('hang'), false, `${name}: no line about a sheet nobody asked for: ${next.text}`);
    assert.ok(next.buttons.includes('cancel'), `${name}: and the new request has its Cancel`);
    assert.deepEqual(got.posts, []);
  }
});

// ---------------------------------------------------------------- A3

test('A3: one instant refusal at Make or at Confirm, then a call that works: the request that comes later has its Cancel', T, async () => {
  const make = await page('refusedMake');
  assert.equal(make.snap('refused').texts.why, 'No passkey came back, so nothing was made. If you opened this inside an app, open it in Safari or Chrome.');
  const atMake = make.snap('request');
  assert.equal(atMake.state, 'request', `not ${atMake.state}: ${atMake.text}`);
  assert.ok(atMake.buttons.includes('cancel'));
  assert.equal(atMake.ids.includes('retry-passkey'), false);

  const confirm = await page('refusedConfirm');
  const refused = confirm.snap('refused');
  assert.equal(refused.state, 'creating', 'the vault in the making is kept');
  assert.equal(refused.texts['made-note'], 'The passkey did not sign. Tap Confirm to try again.');
  assert.deepEqual(refused.buttons, ['confirm']);
  const atConfirm = confirm.snap('request');
  assert.equal(atConfirm.state, 'request', `not ${atConfirm.state}: ${atConfirm.text}`);
  assert.ok(atConfirm.buttons.includes('cancel'));
  assert.equal(confirm.calls.filter((c) => c.call === 'create').length, 1, 'and the retry made no second passkey');
});

// ---------------------------------------------------------------- A4

test('A4: an instant refusal at Cancel keeps the credential id this browser has used; an id only a link named is still dropped', T, async () => {
  const own = await page('refusedCancelOwn');
  const refused = own.snap('refused');
  assert.equal(refused.state, 'no_button');
  assert.ok(refused.hash.includes(`c=${CRED}`), `the id stays in the address bar: ${refused.hash}`);
  assert.equal(own.snap('cancelled').state, 'cancelled');
  assert.deepEqual(own.calls.map((c) => c.allow), [1, 1], 'the second ask names the same passkey, and offers no list');
  assert.deepEqual(own.stored, [`undo.passkey.${VAULT}`]);

  const link = await page('refusedCancelLink');
  const dropped = link.snap('refused');
  assert.equal(dropped.hash.includes('c='), false, 'a link\'s id is a guess, and one refusal drops it');
  assert.equal(dropped.texts.notice, 'Not cancelled. The passkey did not sign.');
  assert.ok(dropped.buttons.includes('cancel'));
});

// ---------------------------------------------------------------- B5, B13, B14

test('B5: the page that made a vault says to copy the link now; after a reload it says why the buttons are gone, that Cancel still works, and offers a new vault', T, async () => {
  const fresh = (await page('make')).snap('idle');
  assert.deepEqual(fresh.buttons, ['fund', 'thief-link', 'recovery']);
  assert.equal(fresh.texts['copy-now'], 'Copy it now. A reload forgets the spend key.');
  assert.ok(fresh.order.indexOf('copy-now') > fresh.order.indexOf('recovery'), 'under the buttons');
  assert.equal(fresh.ids.includes('no-seed'), false);

  const reloaded = await page('reloaded');
  const idle = reloaded.snap('idle');
  assert.equal(idle.texts['no-seed'], 'This page does not hold this vault\'s spend key (a reload forgets it), so it can\'t make a thief link. Cancel still works here. To try a theft, make a new test vault.');
  assert.deepEqual(idle.buttons, ['new-vault'], 'no test coin is offered to a vault whose spend key is gone');
  assert.deepEqual(reloaded.assigned, ['/p/'], 'Make a new test vault opens the page with no vault');
  // Nothing of the spend key or the cold key is kept anywhere a reload could read it back.
  for (const got of [await page('make'), reloaded]) {
    assert.deepEqual(got.session.filter((k) => !k.startsWith('undo-phone:')), []);
    assert.ok(got.stored.every((k) => k.startsWith('undo.passkey.')), `only the credential id is stored: ${got.stored}`);
  }

  // A phone that only opened someone's link never held the key, and is not told a reload lost it.
  const visitor = (await page('visitor')).snap('idle');
  assert.equal(visitor.ids.includes('no-seed'), false);
  assert.deepEqual(visitor.buttons, ['fund']);
});

test('B13: one line before each sheet says what the device will ask and why, and that the passkey can be deleted', T, async () => {
  const got = await page('make');
  assert.equal(got.snap('start').texts['before-sheet'], 'Next, this device asks to save a passkey named "test vault" for undo.example.test: this vault\'s cancel key. You can delete it afterwards.');
  assert.deepEqual(got.snap('start').order.slice(-3), ['before-sheet', 'make', 'foot'], 'right above the button');
  assert.equal(got.snap('confirm').texts['before-sheet'], 'One more sheet: your passkey signs this vault\'s creation, and the contract checks it.');
  assert.deepEqual(got.snap('confirm').order.slice(-2), ['before-sheet', 'confirm']);
  assert.equal(got.calls[0].name, 'test vault', 'the name the line says');
  assert.deepEqual(got.calls[0].selection, { residentKey: 'required', requireResidentKey: true, userVerification: 'required' });
});

test('B14: the idle screen holds the screen wake lock while this page holds the spend key, and not after a reload', T, async () => {
  const fresh = await page('make');
  assert.equal(fresh.snap('confirm').wake.asked, 0);
  assert.ok(fresh.snap('idle').wake.asked >= 1, 'asked for on the idle screen of the page that made the vault');
  assert.equal(fresh.snap('idle').wake.released, 0);
  assert.equal((await page('reloaded')).snap('idle').wake.asked, 0, 'a page with no spend key and no request lets the phone sleep');
});

test('B14: the idle screen lets the phone sleep ten minutes after it came up or was last touched, and a request takes the lock again', T, async () => {
  const got = await page('idleSleeps');
  const idle = got.snap('idle');
  assert.ok(idle.wake.asked >= 1);
  assert.equal(idle.wake.released, 0);
  assert.equal(got.snap('touched').wake.released, 0, 'a touch at six minutes keeps it ten more: still held at twelve');
  const left = got.snap('left');
  assert.equal(left.state, 'idle');
  assert.equal(left.wake.released, 1, 'let go once nobody touched the screen for ten minutes');
  const request = got.snap('request');
  assert.equal(request.state, 'request');
  assert.equal(request.wake.asked, left.wake.asked + 1, 'and taken again when a request comes up');
  assert.equal(request.wake.released, 1);
});

test('B14: the idle screen\'s ten minutes are the idle screen\'s only: a CANCELLED screen inside them lets the phone sleep', T, async () => {
  const got = await page('madeCancelled');
  const cancelled = got.snap('cancelled');
  assert.equal(cancelled.state, 'cancelled');
  assert.ok(cancelled.wake.asked >= 1, 'it was held on the idle screen and through the clock');
  assert.equal(cancelled.wake.released, cancelled.wake.asked, `every lock it took is let go: ${JSON.stringify(cancelled.wake)}`);
});

// ---------------------------------------------------------------- B6

test('B6: a relay out of reach at load is read again after 5, 10 and 20 s and then every 60 s, and the page says so and comes back on its own', T, async () => {
  const back = await page('relayBack');
  const start = back.snap('start');
  assert.equal(start.texts.why, 'Can\'t reach the relay. Trying again.');
  assert.equal(start.buttons.includes('make'), false);
  assert.ok(back.snap('back').buttons.includes('make'), 'Make a test vault appears when a read answers');
  assert.equal(back.snap('back').ids.includes('why'), false);
  assert.equal(back.relayGets.length, 3, `and then it is not read again: ${back.relayGets}`);
  const gaps = back.relayGets.slice(1).map((t, i) => t - back.relayGets[i]);
  assert.ok(gaps[0] >= 4900 && gaps[0] < 8000 && gaps[1] >= 9900 && gaps[1] < 13_000, `5 s, then 10 s: ${gaps}`);

  // What an idle tab costs while the relay stays out: 4 reads in the first 40 s (at 0, 5, 15 and 35 s), then one a minute.
  const out = await page('relayOut');
  assert.equal(out.relayGets.length, 4, `${out.relayGets}`);
  assert.equal(out.snap('40 s').texts.why, 'Can\'t reach the relay. Trying again.');
});

test('B6: a hidden tab asks nothing; coming back and a connection coming back each ask at once', T, async () => {
  const got = await page('relayHidden');
  assert.equal(got.snap('hidden 8 s').relayGets, 1, 'no read while hidden, though the 5 s wait ran out');
  assert.equal(got.snap('shown').relayGets, 2, 'one read on coming back');
  assert.ok(got.snap('online').buttons.includes('make'), 'and one when the connection came back');
  assert.equal(got.relayGets.length, 3);
  assert.equal((await page('relayBurst')).snap('burst').relayGets, 2, 'three of them inside 2 s ask once between them');
});

test('B6 and B11: a relay at its daily limit says when it resets, and is not asked again until then unless the page comes back', T, async () => {
  const got = await page('relayLimit');
  assert.match(got.snap('start').texts.why, /^The relay hit today's limit, so this page can't make a vault right now\. It resets at \d\d:\d\d UTC\.$/);
  assert.equal(got.snap('8 s').relayGets, 1, 'no read every few seconds for an answer that will not change');
  assert.equal(got.snap('came back').relayGets, 2);
  assert.equal((await page('relayReserve')).snap('start').texts.why, 'The relay is keeping what it has left for cancels, so this page can\'t make a vault right now.');
});

test('B6: a relay that answered its status and can\'t make a vault gives its own reason, never that it is down', T, async () => {
  assert.equal((await page('generalStore')).snap('start').texts.why, 'The relay can\'t reach its records right now, so this page can\'t make a vault.');
  assert.equal((await page('generalSetup')).snap('start').texts.why, 'The relay is not set up, so this page can\'t make a vault.');
  assert.equal((await page('generalSaysDown')).snap('start').texts.why, 'The relay says it can\'t make a vault right now.');
  for (const name of ['generalStore', 'generalSetup', 'generalSaysDown']) {
    const s = (await page(name)).snap('start');
    assert.doesNotMatch(s.text, /relay is down/, name);
    assert.equal(s.buttons.includes('make'), false, name);
  }
  // A reason whose words are two sentences reads as one: its first, then why this page can't.
  assert.equal((await page('ownerBusy')).snap('down').texts.why, 'Too many tries through the relay, so this page can\'t send a cancel.');
});

test('B6: a status read that got an answer is not said to be out of reach: a page that is not the relay\'s JSON, and the relay\'s own no, each say what came back, and the page asks again', T, async () => {
  const proxied = await page('relayPage');
  assert.equal(proxied.snap('start').texts.why, 'Something answered for the relay, but not with its status. Trying again.');
  assert.ok(proxied.snap('back').buttons.includes('make'), 'and Make comes when a read answers');
  const refused = await page('relayRefused');
  assert.equal(refused.snap('start').texts.why, 'The relay is not set up. Trying again.');
  assert.equal(refused.snap('later').relayGets, 2, 'it did try again');
  assert.equal(refused.snap('later').texts.why, 'The relay is not set up. Trying again.');
  for (const got of [proxied, refused]) assert.doesNotMatch(got.snap('start').text, /reach the relay/);
});

test('B6: with a request up, a status read that got no answer is not said to be a relay that is down; each answer says what came back, it reads again every 5 s, and Cancel comes back', T, async () => {
  const got = await page('requestStatus');
  assert.ok(got.snap('request').buttons.includes('cancel'));
  const lead = ', so this page can\'t send a cancel. Trying again.';
  for (const [label, words] of [['no answer', 'Can\'t reach the relay'], ['page', 'Something answered for the relay, but not with its status'], ['refused', 'The relay is not set up']]) {
    const s = got.snap(label);
    assert.equal(s.state, 'no_button', label);
    assert.equal(s.texts.why, `${words}${lead}`, label);
    assert.equal(s.buttons.includes('cancel'), false, label);
  }
  assert.ok(got.snap('back').buttons.includes('cancel'), 'a read that answers brings Cancel back');
  const gaps = got.relayGets.slice(1, 5).map((t, i) => t - got.relayGets[i]);
  assert.ok(gaps.every((g) => g >= 4500 && g < 7000), `it did try again, every 5 s: ${gaps}`);
  assert.equal(got.drawn.some((d) => /relay is down/i.test(d)), false, `no screen said the relay is down: ${got.drawn.filter((d) => /relay is down/i.test(d))}`);
  // A relay that answers and says its cancel side is down is said to have said so.
  for (const name of ['ownerDown', 'ownerSaysDown']) assert.equal((await page(name)).snap('down').texts.why, 'The relay says it can\'t send a cancel right now, so this page can\'t send one.', name);
});

test('B6: a cancel the relay did not answer may have gone out, so no screen says it did not: the page says it can\'t tell, keeps the signed cancel, and says what it reads of the relay after', T, async () => {
  const OWN = /^If the relay didn't send the cancel this page signed, any NEAR testnet account can, until \d\d:\d\d UTC: save it, then run [ |]*node tools\/cancel\.mjs/;
  const NEVER = /relay is down|didn't send the cancel this page signed\. Any|Not cancelled/;
  // The page's own 20 s ran out on the answer, and the relay had sent it: the contract shows it cancelled.
  const late = await page('cancelTimedOut');
  const unanswered = late.snap('unanswered');
  assert.equal(unanswered.state, 'no_button');
  assert.equal(unanswered.texts.why, 'The relay did not answer, so this page can\'t tell whether the cancel went out.');
  assert.match(unanswered.texts['own-path'], OWN);
  assert.ok(unanswered.buttons.includes('save-cancel'));
  assert.ok(unanswered.at - late.calls[0].at >= 19_500, `only once the page's own time ran out: ${unanswered.at - late.calls[0].at} ms after the tap`);
  const again = late.snap('read again');
  assert.deepEqual(again.buttons, ['save-cancel', 'cancel'], 'the status answered: Cancel is back, and the signed cancel stays');
  assert.match(again.texts['own-path'], OWN);
  assert.equal(late.snap('cancelled').state, 'cancelled');
  assert.deepEqual(late.posts, ['cancel_all_and_rotate']);
  assert.equal(late.drawn.some((d) => NEVER.test(d)), false, `${late.drawn.filter((d) => NEVER.test(d))}`);

  // No signal: the cancel got no answer, and nor did the status reads after it, which go on every 5 s.
  const lost = await page('cancelUnreachable');
  assert.equal(lost.snap('unanswered').texts.why, 'The relay did not answer, so this page can\'t tell whether the cancel went out.');
  const unreachable = lost.snap('unreachable');
  assert.equal(unreachable.texts.why, 'Can\'t reach the relay, so this page can\'t send a cancel. Trying again.');
  assert.match(unreachable.texts['own-path'], OWN, 'and the signed cancel is still not said to be unsent');
  const still = lost.snap('still');
  assert.ok(still.relayGets > unreachable.relayGets, `it did try again: ${unreachable.relayGets} then ${still.relayGets}`);
  assert.equal(still.texts.why, unreachable.texts.why);
  assert.ok(lost.snap('back').buttons.includes('cancel'), 'and Cancel comes back once a read answers');
  assert.equal(lost.drawn.some((d) => NEVER.test(d)), false, `${lost.drawn.filter((d) => NEVER.test(d))}`);

  // The relay's own error, which can come after its sender sent the cancel: its words, and nothing that says the cancel
  // did not go, with the signed cancel kept as one that may have gone out, and Cancel.
  const erred = await page('cancelErred');
  const said = erred.snap('erred');
  assert.equal(said.texts.notice, 'The relay hit an error.', 'not "Not cancelled"');
  assert.match(said.texts['own-path'], OWN, 'and the signed cancel is not said to be unsent');
  assert.ok(said.buttons.includes('cancel') && said.buttons.includes('save-cancel'), `${said.buttons}`);
  assert.equal(erred.snap('cancelled').state, 'cancelled', 'and it had gone out');
  assert.equal(erred.drawn.some((d) => NEVER.test(d)), false, `${erred.drawn.filter((d) => NEVER.test(d))}`);
});

test('B6: any code the relay can give after its sender put the cancel out (its key\'s nonce taken, a node\'s refusal of a resend) says no more than the relay said: no "Not cancelled", and the signed cancel kept as one that may have gone out', T, async () => {
  const OWN = /^If the relay didn't send the cancel this page signed, any NEAR testnet account can, until \d\d:\d\d UTC: save it, then run [ |]*node tools\/cancel\.mjs/;
  const stale = await page('cancelStale');
  const said = stale.snap('stale');
  assert.equal(said.state, 'request');
  assert.equal(said.texts.notice, 'The relay\'s key was busy. Try again.');
  assert.match(said.texts['own-path'], OWN);
  assert.ok(said.buttons.includes('cancel') && said.buttons.includes('save-cancel'), `${said.buttons}`);
  assert.equal(stale.snap('cancelled').state, 'cancelled', 'and it had gone out');
  assert.equal(stale.drawn.some((d) => /Not cancelled/.test(d)), false, `${stale.drawn.filter((d) => /Not cancelled/.test(d))}`);
  // A node's refusal of the transaction it was sent is the node's, not the NEAR contract's.
  const node = (await page('cancelNodeRefused')).snap('refused');
  assert.equal(node.texts.notice, 'A NEAR node refused the transaction.');
  assert.match(node.texts['own-path'], OWN);
  assert.doesNotMatch(node.text, /Not cancelled|NEAR contract refused/);
});

// ---------------------------------------------------------------- B7

test('B7: with the dispenser at its limit the idle screen says so, with the reset time when the status carries one, and that any coin sent to the address works', T, async () => {
  const limit = (await page('fundsLimit')).snap('idle');
  assert.match(limit.texts['no-funds'], /^This page can't get a test coin from the relay right now\. It resets at \d\d:\d\d UTC\. A Mutinynet coin you send to this address works too\.$/);
  assert.equal(limit.buttons.includes('fund'), false);
  assert.deepEqual(limit.buttons, ['thief-link', 'recovery']);

  const down = await page('fundsDown');
  assert.equal(down.snap('idle').texts['no-funds'], 'This page can\'t get a test coin from the relay right now. A Mutinynet coin you send to this address works too.');
  assert.ok(down.snap('funds back').buttons.includes('fund'), 'and the button comes when the relay can give one again');
});

test('B7 and B11: a coin the relay refuses for its hourly or daily limit says when the limit ends and that any coin sent to the address works; a node\'s refusal of the funding is a node\'s', T, async () => {
  assert.equal((await page('fundsHour')).snap('refused').texts.notice, 'No coins sent. This network address has used its test coin tries for this hour. Wait about 43 minutes, or use another network. A Mutinynet coin you send to this address works too.');
  assert.equal((await page('fundsDay')).snap('refused').texts.notice, 'No coins sent. The relay hit today\'s limit. It resets at 00:00 UTC. A Mutinynet coin you send to this address works too.');
  // A Bitcoin node's refusal of the funding is not the NEAR contract's, and no coin went.
  assert.equal((await page('fundsNodeRefused')).snap('refused').texts.notice, 'No coins sent. A Mutinynet node refused the relay\'s transaction. A Mutinynet coin you send to this address works too.');
});

test('B7: a coin ask with no answer, or with a code the relay can give after the coin went out, says the page can\'t tell, never "No coins sent" or that the relay is down; the notice goes once the balance reads a coin', T, async () => {
  for (const [name, words] of [['fundsUnanswered', 'The relay did not answer'], ['fundsStoreDown', 'The relay can\'t reach its records right now'], ['fundsEsploraDown', 'The relay can\'t reach Bitcoin right now'], ['fundsBusy', 'Too many tries through the relay']]) {
    const got = await page(name);
    const unsure = got.snap('unsure');
    assert.equal(unsure.texts.notice, `${words}, so this page can't tell whether a coin was sent.`, name);
    const coin = got.snap('coin');
    assert.equal(coin.state, 'idle', name);
    assert.equal(coin.texts.balance, '2,000 sats', `${name}: ${coin.text}`);
    assert.equal(coin.ids.includes('notice'), false, `${name}: the notice went with the coin: ${coin.text}`);
    assert.equal(got.drawn.some((d) => /No coins sent|relay is down/.test(d)), false, `${name}: ${got.drawn.filter((d) => /No coins sent|relay is down/.test(d))}`);
  }
});

// ---------------------------------------------------------------- B8

test('B7: a second tap that meets the claim of an ask still out (a short rate_limited) says the page can\'t tell, not "No coins sent", and any refusal reads the balance at once, so the coin ends the notice', T, async () => {
  const busy = await page('fundsClaimBusy');
  assert.equal(busy.snap('unsure').texts.notice, 'The relay did not answer, so this page can\'t tell whether a coin was sent.');
  const said = 'Too many tries through the relay, so this page can\'t tell whether a coin was sent.';
  assert.ok(busy.drawn.some((d) => d.includes(said)), `the second answer: ${busy.drawn.filter((d) => /coin/.test(d)).slice(-4)}`);
  assert.equal(busy.drawn.some((d) => /No coins sent/.test(d)), false, `${busy.drawn.filter((d) => /No coins sent/.test(d))}`);
  assert.deepEqual(busy.posts.filter((m) => m === 'fund'), ['fund', 'fund']);
  const coin = busy.snap('coin');
  assert.equal(coin.texts.balance, '2,000 sats', coin.text);
  assert.equal(coin.ids.includes('notice'), false, `read at once, not 15 s later: ${coin.text}`);
  assert.deepEqual(busy.missed, []);
  // A refusal that does say no coin was sent: the vault already holds one, and the balance read at once shows it.
  const holds = await page('fundsHolds');
  assert.match(holds.snap('refused').texts.notice ?? '', /^No coins sent\. /);
  const read = holds.snap('coin');
  assert.equal(read.texts.balance, '2,000 sats', read.text);
  assert.equal(read.ids.includes('notice'), false, `read at once, not 15 s later: ${read.text}`);
  assert.deepEqual(holds.missed, []);
});

test('B8: the line about a sheet that has not shown goes when the sheet answers', T, async () => {
  const got = await page('slowSheet');
  assert.ok(got.snap('hang').ids.includes('hang'), 'a 13 s sheet that left no trace got the line at 12 s');
  const confirm = got.snap('confirm');
  assert.match(confirm.text, /Passkey made\./);
  assert.equal(confirm.ids.includes('hang'), false, 'and it is gone beside "Passkey made."');
  assert.equal(got.calls.length, 1, 'the slow call was never aborted or asked twice');
  assert.equal(got.calls[0].aborted, false);
});

// ---------------------------------------------------------------- B9

test('B9: closing the second sheet keeps the Confirm screen and its keys; the retry makes no second passkey', T, async () => {
  const got = await page('closedConfirm');
  const closed = got.snap('closed');
  assert.equal(closed.state, 'creating');
  assert.equal(closed.texts['made-note'], 'The passkey did not sign. Tap Confirm to try again.');
  assert.deepEqual(closed.buttons, ['confirm']);
  assert.match(closed.text, /Passkey made\..*Second key read from the signer\./);
  assert.doesNotMatch(closed.text, /Nothing was made/);
  assert.equal(got.snap('idle').state, 'idle');
  assert.deepEqual(got.calls.map((c) => c.call), ['create', 'get', 'get']);
  assert.deepEqual(got.posts, ['create_vault']);
  // The first sheet closed is still what it was: nothing was made, and the start screen. Neither says a sheet closed:
  // the page saw only a trace of one, which something else can leave.
  const first = (await page('closedMake')).snap('closed');
  assert.equal(first.texts['made-why'], 'No passkey came back, so nothing was made.');
  for (const s of [closed, first]) assert.doesNotMatch(s.text, /sheet closed/);
  assert.ok(first.buttons.includes('make'));
});

// ---------------------------------------------------------------- B10

test('B10: a vault that was sent and does not read active: the hash stays on screen, the page says what is true, and Check again reads with the same keys', T, async () => {
  const got = await page('notActive');
  const gaveUp = got.snap('gave up');
  assert.equal(gaveUp.state, 'creating');
  assert.equal(gaveUp.texts['made-note'], 'The vault was sent, but the contract does not read it active yet.');
  assert.match(gaveUp.text, /NEAR testnet tx H{44}/);
  assert.doesNotMatch(gaveUp.text, /Nothing was made|No vault was made/);
  assert.deepEqual(gaveUp.buttons, ['check-again']);
  const idle = got.snap('idle');
  assert.equal(idle.state, 'idle');
  assert.deepEqual(idle.buttons, ['fund', 'thief-link', 'recovery'], 'the keys were kept, so the vault it made can still be robbed');
  assert.equal(got.calls.length, 2, 'no passkey call was made again');
  assert.equal(got.posts.filter((m) => m === 'create_vault').length, 1);
  // A send that got no answer may have gone out all the same: the page does not say nothing was made.
  const noAnswer = (await page('noAnswer')).snap('no answer');
  assert.equal(noAnswer.texts['made-why'], 'The relay did not answer, so this page can\'t tell whether a vault was made.');
  assert.doesNotMatch(noAnswer.text, /Nothing was made|No vault was made/);
  // An answer that is not the relay's own (a proxy's JSON with no code) is no answer from the relay, and the relay's own
  // error can come after its sender sent the creation: neither says no vault was made, nor that the relay is down.
  const proxy = (await page('proxyMake')).snap('proxy');
  assert.equal(proxy.texts['made-why'], 'The relay did not answer, so this page can\'t tell whether a vault was made.');
  const erred = (await page('erredMake')).snap('erred');
  assert.equal(erred.texts['made-why'], 'The relay hit an error, so this page can\'t tell whether a vault was made.');
  // So can any code the relay gives after its sender signed: a stale nonce, and the state store lost on the way.
  const stale = (await page('staleMake')).snap('stale');
  assert.equal(stale.texts['made-why'], 'The relay\'s key was busy, so this page can\'t tell whether a vault was made.');
  const store = (await page('storeMake')).snap('store');
  assert.equal(store.texts['made-why'], 'The relay can\'t reach its records right now, so this page can\'t tell whether a vault was made.');
  for (const s of [proxy, erred, stale, store]) assert.doesNotMatch(s.text, /Nothing was made|No vault was made|relay is down/);
  // A first sheet that saved a passkey the page can't read: not "Nothing was made".
  const nokey = (await page('makeNoKey')).snap('nokey');
  assert.equal(nokey.texts['made-why'], 'No vault was made. The passkey call failed.');
});

// ---------------------------------------------------------------- B11

test('B11: the relay\'s hourly limit reads in minutes with its cause, and a long wait on a cancel reads in hours', T, async () => {
  const hour = (await page('hourLimit')).snap('refused');
  assert.equal(hour.texts['made-why'], 'No vault was made. This network address has used its 3 vault tries for this hour. Wait about 40 minutes, or use another network.');
  assert.doesNotMatch(hour.text, /2400/);
  const cancel = (await page('cancelLimit')).snap('refused');
  assert.equal(cancel.texts.notice, 'Not cancelled. Too many tries through the relay. Wait about 14 hours and tap again.');
});

// ---------------------------------------------------------------- B12

test('B12: inside an app\'s browser the warning comes first and says what to do, and a Make with no sheet has its own sentence', T, async () => {
  const got = await page('inApp');
  const start = got.snap('start');
  assert.equal(start.order[0], 'in-app', 'before the page\'s own headline');
  assert.equal(start.texts['in-app'], 'You opened this inside the X app, where passkeys may not work. Open this page in Safari or Chrome itself: use the app\'s menu, or copy this page\'s address.');
  assert.ok(start.buttons.includes('make'), 'the button stays: only a tap finds out');
  const refused = got.snap('refused');
  assert.equal(refused.texts.why, 'No passkey came back, so nothing was made. If you opened this inside an app, open it in Safari or Chrome.');
  assert.doesNotMatch(refused.text, /this vault's passkey/, 'no vault exists yet');
  assert.deepEqual(refused.buttons, ['retry-passkey']);
});

// ---------------------------------------------------------------- C18

test('the proof of work has a line while it runs, replaced by "Proof of work done." when it ends', T, async () => {
  const { drawn } = await page('make');
  const working = drawn.findIndex((d) => /^creating: .*Signed\. \| Working: a small proof of work\./.test(d));
  const done = drawn.findIndex((d) => /^creating: .*Signed\. \| Proof of work done\./.test(d));
  assert.ok(working >= 0, `the line was drawn: ${drawn.filter((d) => d.startsWith('creating')).join('\n')}`);
  assert.ok(done > working, 'and then replaced');
  assert.equal(drawn.slice(done).some((d) => d.includes('Working: a small proof of work.')), false);
});
