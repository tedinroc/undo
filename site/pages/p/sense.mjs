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

/** Null, or why this device cannot make an assertion. `blocked` is true once a tap has shown it. */
export function passkeyProblem(sense, blocked = false) {
  if (!sense.secure) return 'not_secure';
  if (!sense.api) return 'no_webauthn';
  if (blocked) return 'webauthn_blocked';
  // A laptop with no platform authenticator can still reach a phone's passkey through the OS sheet. A phone cannot.
  if (sense.platform === false && sense.mobile) return 'no_platform_authenticator';
  return null;
}

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
 * Keeps the screen on while a clock runs, since a five-minute wait is longer than most phones' auto-lock. A page loses
 * the lock when it is hidden, so this asks again when it comes back. `state` is on, refused, or none (no such API).
 */
export function screenAwake(win = globalThis) {
  const nav = win.navigator;
  const out = { state: 'none', wanted: false, lock: null };
  const ask = async () => {
    if (!out.wanted || !nav?.wakeLock || out.lock) return;
    try {
      out.lock = await nav.wakeLock.request('screen');
      out.state = 'on';
      out.lock.addEventListener?.('release', () => { out.lock = null; });
    } catch {
      out.state = 'refused';
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
  webauthn_blocked: 'No passkey sheet came up. Either this phone doesn\'t hold this vault\'s passkey, or this browser is blocking passkeys. If it does hold it, open this page in Safari or Chrome.',
  no_platform_authenticator: 'This phone has no Face ID, fingerprint or screen lock this browser can use, so it can\'t make or use a passkey here.',
};

export const problemWords = (problem) => PROBLEM_WORDS[problem] ?? null;

export const openElsewhere = (sense) => (sense.inApp ? `You opened this inside ${sense.inApp}. Passkeys may not work here. Open it in Safari or Chrome if no sheet appears.` : null);
