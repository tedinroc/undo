// What this browser can do with a passkey, found out instead of assumed, so the page can say so. X's in-app browser
// is an open question and a real answer only comes from a phone. A page cannot see what a screen recording
// captures: what it can see is whether it was hidden, lost focus, or stopped drawing while the OS sheet was up.

/** A rejected assertion this fast, with no sign of a sheet, never reached a person. */
export const BLOCKED_MS = 700;
/** No settled promise and no sign of a sheet after this long: say it may be blocked. Never stop trying. */
export const SHEET_HANG_MS = 12_000;
const STALL_MS = 400;

export function inAppBrowser(ua) {
  if (/Twitter|\bX\/\d/.test(ua)) return 'the X app';
  if (/FBAN|FBAV|FB_IAB/.test(ua)) return 'the Facebook app';
  if (/Instagram/.test(ua)) return 'the Instagram app';
  if (/\bLine\//.test(ua)) return 'the LINE app';
  if (/MicroMessenger/.test(ua)) return 'the WeChat app';
  if (/;\s*wv\)/.test(ua)) return 'an app\'s built-in browser';
  if (/iPhone|iPad|iPod/.test(ua) && !/Safari\//.test(ua)) return 'an app\'s built-in browser';
  return null;
}

export function isMobile(nav) {
  if (typeof nav?.userAgentData?.mobile === 'boolean') return nav.userAgentData.mobile;
  const ua = nav?.userAgent ?? '';
  return /Android|iPhone|iPad|iPod/.test(ua) || (/Macintosh/.test(ua) && (nav?.maxTouchPoints ?? 0) > 1);
}

export async function sensePasskeys(win = globalThis) {
  const nav = win.navigator;
  const secure = win.isSecureContext === true;
  const PKC = win.PublicKeyCredential;
  const api = Boolean(secure && PKC && nav?.credentials && typeof nav.credentials.get === 'function' && typeof nav.credentials.create === 'function');
  let platform = null;
  if (api && typeof PKC.isUserVerifyingPlatformAuthenticatorAvailable === 'function') {
    try {
      platform = await Promise.race([
        PKC.isUserVerifyingPlatformAuthenticatorAvailable(),
        new Promise((resolve) => { setTimeout(() => resolve(null), 3000); }),
      ]);
    } catch {
      platform = null;
    }
  }
  const ua = nav?.userAgent ?? '';
  return { secure, api, platform, mobile: isMobile(nav), inApp: inAppBrowser(ua), ua };
}

/**
 * Null, or why this device cannot make an assertion. `blocked` is true once a tap has shown it. A browser that reports
 * no platform authenticator is not a reason: only a tap finds out, so the buttons stay and `platformHint` says what to do.
 */
export function passkeyProblem(sense, blocked = false) {
  if (!sense.secure) return 'not_secure';
  if (!sense.api) return 'no_webauthn';
  if (blocked) return 'webauthn_blocked';
  return null;
}

/**
 * The major iOS version a user agent names, or null. Safari from iOS 26 names 18.x there (Apple froze it), so this
 * reads 18 or more for every iOS from 18 on, and the real number for 16 and 17, which is all platformHint needs.
 */
export function iosMajor(ua) {
  const m = /\b(?:iPhone|iPad|iPod)\b[^)]*?\bOS (\d+)_\d+/.exec(ua ?? '');
  return m ? Number(m[1]) : null;
}

const appleDevice = (ua) => (/\biPad\b/.test(ua) ? 'iPad' : /\biPod\b/.test(ua) ? 'iPod touch' : /\biPhone\b/.test(ua) ? 'iPhone' : null);

/**
 * What to do, by what the user agent names. Before iOS 26.2 an iPhone's browser answered true almost always, and false
 * meant no passcode; from 26.2 it answers true only once a passkey manager is set up (Apple, developer forums thread
 * 808367). From iOS 18 that switch is "AutoFill Passwords and Passkeys" under Settings > General > AutoFill & Passwords
 * (support.apple.com/en-us/120758); on 17 and before passwords sit under Settings > Passwords (support.apple.com/en-us/
 * 104955), but there the answer was the passcode's. A user agent that says 18 may be any iOS from 18 to 26.x, so it gets
 * both steps. One that names no iOS version and no Android gets every step and names no menu path.
 */
function hintStep(ua) {
  const device = appleDevice(ua);
  const major = iosMajor(ua);
  if (device && major !== null && major >= 18) return `check that this ${device} has a passcode and that AutoFill Passwords and Passkeys is on in Settings > General > AutoFill & Passwords`;
  if (device && major !== null) return `check that this ${device} has a passcode`;
  if (/\bAndroid\b/.test(ua)) return 'set a screen lock on this phone';
  return 'turn one on (iPhone or iPad: set a passcode, and turn on AutoFill for passwords and passkeys in Settings; Android: set a screen lock)';
}

/**
 * What to say on a phone whose browser answers false to isUserVerifyingPlatformAuthenticatorAvailable(). The page
 * cannot tell what is missing, and the OS may still offer its own way through at the tap, so this is a hint beside the
 * button and never in place of it, and it says what to check rather than what the phone lacks. A laptop gets none: it
 * can reach a phone's passkey through the OS sheet.
 */
export const platformHint = (sense) => (sense.platform === false && sense.mobile
  ? `This browser reports no passkey manager or screen lock it can use. If no passkey sheet comes up, ${hintStep(sense.ua ?? '')}, then come back to this page.`
  : null);

/** Watches the page while an OS sheet may be up. `evidence()` says what the page saw. */
export function watchSheet(win = globalThis) {
  const doc = win.document;
  const now = () => win.performance.now();
  const started = now();
  const seen = { hidden: false, blurred: false, pagehide: false };
  let last = started;
  let gap = 0;
  let live = true;
  const onFrame = () => {
    const t = now();
    gap = Math.max(gap, t - last);
    last = t;
    if (live) win.requestAnimationFrame(onFrame);
  };
  const onVisibility = () => { if (doc.hidden) seen.hidden = true; };
  const onBlur = () => { seen.blurred = true; };
  const onPagehide = () => { seen.pagehide = true; };
  doc.addEventListener('visibilitychange', onVisibility);
  win.addEventListener('blur', onBlur);
  win.addEventListener('pagehide', onPagehide);
  win.requestAnimationFrame(onFrame);

  const evidence = () => {
    const stall = Math.max(gap, now() - last);
    return {
      ms: Math.round(now() - started),
      hidden: seen.hidden,
      blurred: seen.blurred,
      pagehide: seen.pagehide,
      stallMs: Math.round(stall),
      seen: seen.hidden || seen.blurred || seen.pagehide || stall >= STALL_MS,
    };
  };
  return {
    evidence,
    stop() {
      live = false;
      doc.removeEventListener('visibilitychange', onVisibility);
      win.removeEventListener('blur', onBlur);
      win.removeEventListener('pagehide', onPagehide);
      return evidence();
    },
  };
}

/**
 * What a rejected create or get means. NotAllowedError is the only word a browser gives for a person closing the
 * sheet, for no passkey, and for an embedding app that forbids WebAuthn, so time and the sheet's traces separate them.
 */
export function classifyPasskeyError(err, evidence) {
  const name = err?.name ?? 'Error';
  const message = err?.message ?? String(err);
  if (name === 'SecurityError') return { kind: 'wrong_site', name, message };
  if (name === 'NotSupportedError') return { kind: 'no_support', name, message };
  if (name === 'NotAllowedError' || name === 'AbortError') {
    return { kind: evidence.seen || evidence.ms >= BLOCKED_MS ? 'dismissed' : 'blocked', name, message };
  }
  return { kind: 'other', name, message };
}

/**
 * Keeps the screen on while the page wants it (phone.mjs keepAwake: while a clock runs, since a five-minute wait is
 * longer than most phones' auto-lock, and for a while on the idle screen). A page loses the lock when it is hidden, so
 * this asks again when it comes back. `state` is on, refused, or none (no such API).
 */
export function screenAwake(win = globalThis) {
  const nav = win.navigator;
  const out = { state: 'none', wanted: false, lock: null, asking: false };
  // One request at a time, and a lock that comes after it stopped being wanted is let go at once.
  const ask = async () => {
    if (!out.wanted || !nav?.wakeLock || out.lock || out.asking) return;
    out.asking = true;
    try {
      const lock = await nav.wakeLock.request('screen');
      out.state = 'on';
      lock.addEventListener?.('release', () => { if (out.lock === lock) out.lock = null; });
      if (out.wanted) out.lock = lock;
      else lock.release?.().catch?.(() => {});
    } catch {
      out.state = 'refused';
    } finally {
      out.asking = false;
    }
  };
  win.document?.addEventListener?.('visibilitychange', () => { if (!win.document.hidden) ask(); });
  out.start = () => {
    out.wanted = true;
    return ask();
  };
  out.stop = () => {
    out.wanted = false;
    out.lock?.release?.().catch?.(() => {});
    out.lock = null;
  };
  return out;
}

const PROBLEM_WORDS = {
  not_secure: 'This page was not opened over a secure connection, so passkeys are off.',
  no_webauthn: 'This browser has no passkeys, so this page can\'t cancel here. Open it in Safari or Chrome.',
  // Said after a refusal within BLOCKED_MS with no trace of a sheet: no sheet, no passkey, or a sheet shut at once look alike.
  webauthn_blocked: 'No passkey came back. This phone may not hold this vault\'s passkey, or this browser may be blocking passkeys.',
};

export const problemWords = (problem) => PROBLEM_WORDS[problem] ?? null;

/** Inside an app's own browser: where it is, and what to do about it, before any tap. */
export const openElsewhere = (sense) => (sense.inApp
  ? `You opened this inside ${sense.inApp}, where passkeys may not work. Open this page in Safari or Chrome itself: use the app's menu, or copy this page's address.`
  : null);

/**
 * A sheet that has not shown after SHEET_HANG_MS. `again` names the button the screen has put back. In a browser of its
 * own the call may only be stuck, so the way out is that button and then a reload; inside an app it is the app.
 */
export const hangWords = (sense, again) => (sense.inApp
  ? `No passkey sheet yet? This app's browser may be blocking passkeys. Open this page in Safari or Chrome, or tap ${again} to try once more.`
  : `No passkey sheet yet? Tap ${again} again. If none comes, reload this page and try once more.`);
