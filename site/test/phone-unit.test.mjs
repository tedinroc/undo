// The phone page's senses, in Node with a made-up window, and the page's rules a reader can check without a browser.
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { BLOCKED_MS, classifyPasskeyError, hangWords, inAppBrowser, iosMajor, isMobile, openElsewhere, passkeyProblem, platformHint, problemWords, screenAwake, sensePasskeys } from '../pages/p/sense.mjs';
import { OWN_PATH_LINE, ownCancelFile, ownCancelFileName, ownCancelWords, relayIsWhy, relayRefusedIt } from '../pages/p/own-cancel.mjs';
import { relayBodyProblem } from '../lib/relay-table.mjs';
import { build, importGraph } from '../build.mjs';

const PAGES = join(dirname(fileURLToPath(import.meta.url)), '../pages');
const read = (path) => readFileSync(join(PAGES, path), 'utf8');
const IPHONE = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1';
const X_IOS = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Twitter for iPhone/11.0';
const X_ANDROID = 'Mozilla/5.0 (Linux; Android 15; Pixel 9; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/130.0 Mobile Safari/537.36 TwitterAndroid';
const ANDROID = 'Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Mobile Safari/537.36';
const WEBVIEW_IOS = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148';

test('in-app browsers are named, plain Safari and Chrome are not', () => {
  assert.equal(inAppBrowser(IPHONE), null);
  assert.equal(inAppBrowser(ANDROID), null);
  assert.equal(inAppBrowser(X_IOS), 'the X app');
  assert.equal(inAppBrowser(X_ANDROID), 'the X app');
  assert.equal(inAppBrowser(WEBVIEW_IOS), 'an app\'s built-in browser');
  assert.equal(inAppBrowser('Mozilla/5.0 (Linux; Android 15; wv) AppleWebKit/537.36 Chrome/130 Mobile Safari/537.36'), 'an app\'s built-in browser');
});

test('mobile: client hints first, an iPad that calls itself a Mac still counts', () => {
  assert.equal(isMobile({ userAgentData: { mobile: true }, userAgent: 'x' }), true);
  assert.equal(isMobile({ userAgentData: { mobile: false }, userAgent: ANDROID }), false);
  assert.equal(isMobile({ userAgent: IPHONE }), true);
  assert.equal(isMobile({ userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15', maxTouchPoints: 5 }), true);
  assert.equal(isMobile({ userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15', maxTouchPoints: 0 }), false);
});

const PLATFORM = { isUserVerifyingPlatformAuthenticatorAvailable: async () => true };
const CREDS = { get() {}, create() {} };
const win = (over = {}) => {
  const { secure, pkc, creds, ua } = { secure: true, pkc: PLATFORM, creds: CREDS, ua: IPHONE, ...over };
  return { isSecureContext: secure, PublicKeyCredential: pkc, navigator: { credentials: creds, userAgent: ua } };
};

test('sense: each thing that can be missing is reported, and a throwing probe is unknown, not false', async () => {
  assert.deepEqual((({ secure, api, platform, mobile }) => ({ secure, api, platform, mobile }))(await sensePasskeys(win())), { secure: true, api: true, platform: true, mobile: true });
  assert.equal((await sensePasskeys(win({ secure: false }))).api, false);
  assert.equal((await sensePasskeys(win({ pkc: undefined }))).api, false);
  assert.equal((await sensePasskeys(win({ creds: undefined }))).api, false);
  assert.equal((await sensePasskeys(win({ pkc: { isUserVerifyingPlatformAuthenticatorAvailable: async () => false } }))).platform, false);
  assert.equal((await sensePasskeys(win({ pkc: { isUserVerifyingPlatformAuthenticatorAvailable: async () => { throw new Error('no'); } } }))).platform, null);
  assert.equal((await sensePasskeys(win({ pkc: {} }))).platform, null);
});

test('passkeyProblem: the order a person would want to hear it; a browser that reports no platform authenticator is not a reason to take the buttons away', () => {
  const ok = { secure: true, api: true, platform: true, mobile: true };
  assert.equal(passkeyProblem(ok), null);
  assert.equal(passkeyProblem({ ...ok, secure: false, api: false }), 'not_secure');
  assert.equal(passkeyProblem({ ...ok, api: false }), 'no_webauthn');
  assert.equal(passkeyProblem(ok, true), 'webauthn_blocked');
  // From iOS 26.2 the browser answers false with Face ID on and no passkey manager set up; on Android false means no
  // screen lock. Either way only a tap finds out what the OS then offers, so this is a hint and never a stop.
  assert.equal(passkeyProblem({ ...ok, platform: false }), null, 'a phone keeps Make and Cancel');
  assert.equal(passkeyProblem({ ...ok, platform: false }, true), 'webauthn_blocked', 'until a tap has shown no sheet comes');
  assert.equal(passkeyProblem({ ...ok, platform: false, mobile: false }), null, 'a laptop can reach a phone through the OS sheet');
  assert.equal(passkeyProblem({ ...ok, platform: null }), null, 'not knowing is not a reason to hide the button');
  assert.equal(problemWords('no_platform_authenticator'), null, 'and the sentence that blamed Face ID is gone');
});

test('platformHint: only on a phone whose browser said false, in words that are right for the iOS version or the Android its user agent names', () => {
  const LEAD = 'This browser reports no passkey manager or screen lock it can use. If no passkey sheet comes up, ';
  const ios = (version, device = 'iPhone') => `Mozilla/5.0 (${device}; CPU ${device === 'iPad' ? '' : 'iPhone '}OS ${version} like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/${version.replace('_', '.')} Mobile/15E148 Safari/604.1`;
  const hint = (ua) => platformHint({ secure: true, api: true, platform: false, mobile: true, ua });
  // Safari from iOS 26 says 18_6 (or 18_7) where the iOS version goes, and Version/26.x after it.
  const IOS26 = 'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.2 Mobile/15E148 Safari/604.1';
  const FROM_18 = `${LEAD}check that this iPhone has a passcode and that AutoFill Passwords and Passkeys is on in Settings > General > AutoFill & Passwords, then come back to this page.`;
  // Apple's own steps from iOS 18 (support.apple.com/en-us/120758): Settings, General, AutoFill & Passwords, and the
  // switch "AutoFill Passwords and Passkeys". Before 26.2 a false answer meant no passcode, so both steps are said.
  assert.equal(hint(IOS26), FROM_18);
  assert.equal(hint(ios('18_1')), FROM_18);
  assert.equal(hint(IPHONE), FROM_18);
  assert.equal(hint(ios('26_2')), FROM_18, 'a user agent that does give 26 reads the same');
  // On 16 and 17 that switch is not under General (support.apple.com/en-us/104955: Settings > Passwords), and the
  // answer was false only without a passcode: no menu path is named.
  for (const v of ['16_7', '17_5']) assert.equal(hint(ios(v)), `${LEAD}check that this iPhone has a passcode, then come back to this page.`, v);
  assert.equal(hint('Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/130.0 Mobile/15E148 Safari/604.1'), `${LEAD}check that this iPhone has a passcode, then come back to this page.`, 'Chrome on iOS reads the same');
  assert.equal(hint(ios('17_4', 'iPad')), `${LEAD}check that this iPad has a passcode, then come back to this page.`);
  assert.equal(hint(ios('18_2', 'iPad')), `${LEAD}check that this iPad has a passcode and that AutoFill Passwords and Passkeys is on in Settings > General > AutoFill & Passwords, then come back to this page.`);
  assert.equal(hint(ANDROID), `${LEAD}set a screen lock on this phone, then come back to this page.`);
  // An iPad that calls itself a Mac, or anything else that names neither: every step, and no menu path.
  const neither = `${LEAD}turn one on (iPhone or iPad: set a passcode, and turn on AutoFill for passwords and passkeys in Settings; Android: set a screen lock), then come back to this page.`;
  assert.equal(hint('Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15'), neither);
  assert.equal(hint(undefined), neither);
  for (const ua of [IOS26, ios('16_7'), ANDROID, 'x']) {
    assert.doesNotMatch(hint(ua), /Face ID|Touch ID|can't|cannot/, 'it does not say what this phone lacks, or that nothing can be done');
    assert.equal((hint(ua).match(/Settings > General/g) ?? []).length, ua === IOS26 ? 1 : 0, `a menu path only where the iOS version says it is right: ${ua}`);
  }
  assert.equal(iosMajor(IOS26), 18);
  assert.equal(iosMajor(ios('17_4', 'iPad')), 17);
  assert.equal(iosMajor(ANDROID), null);
  const phone = { secure: true, api: true, platform: false, mobile: true, ua: IPHONE };
  assert.equal(platformHint({ ...phone, platform: true }), null);
  assert.equal(platformHint({ ...phone, platform: null }), null, 'a browser that will not say gets no hint');
  assert.equal(platformHint({ ...phone, mobile: false }), null, 'a laptop gets none');
});

test('inside an app the page says where it is and what to do; a sheet that has not shown names the button that is back', () => {
  assert.equal(openElsewhere({ inApp: null }), null);
  assert.equal(openElsewhere({ inApp: 'the X app' }), 'You opened this inside the X app, where passkeys may not work. Open this page in Safari or Chrome itself: use the app\'s menu, or copy this page\'s address.');
  assert.equal(hangWords({ inApp: null }, 'Cancel'), 'No passkey sheet yet? Tap Cancel again. If none comes, reload this page and try once more.');
  assert.equal(hangWords({ inApp: 'the X app' }, 'Cancel'), 'No passkey sheet yet? This app\'s browser may be blocking passkeys. Open this page in Safari or Chrome, or tap Cancel to try once more.');
  assert.doesNotMatch(hangWords({ inApp: null }, 'Cancel'), /Safari or Chrome/, 'a browser of its own is not told to open a browser');
});

test('the screen wake lock: one ask at a time, a lock that comes after the page stopped wanting it is let go at once, and stop() lets go of the one it holds', async () => {
  const lock = () => ({ released: 0, addEventListener() {}, release() { this.released += 1; return Promise.resolve(); } });
  const asks = [];
  const nav = { wakeLock: { request: () => new Promise((grant) => { asks.push(grant); }) } };
  const awake = screenAwake({ navigator: nav, document: { hidden: false, addEventListener() {} } });
  // Wanted, and no longer wanted before the browser granted it: what a request that ends at once does.
  const late = lock();
  const asking = awake.start();
  awake.start();
  assert.equal(asks.length, 1, 'one ask at a time');
  awake.stop();
  asks[0](late);
  await asking;
  assert.equal(late.released, 1, 'a lock granted after stop() is let go as soon as it comes');
  assert.equal(awake.lock, null);
  // Wanted when it comes: kept, until stop().
  const held = lock();
  const again = awake.start();
  asks[1](held);
  await again;
  assert.equal(awake.lock, held);
  assert.equal(held.released, 0);
  awake.stop();
  assert.equal(held.released, 1);
  assert.equal(awake.lock, null);
});

test('the test mode and the operator check say only what they saw: no answer from the relay is not a relay that is down, and a refused passkey call is not a sheet that closed', () => {
  const h7 = read('p/h7.mjs');
  const op = read('p/operator-check.mjs');
  assert.doesNotMatch(h7, /relay is down|Relay: \$\{relayUp \? 'up' : `down/i);
  assert.match(h7, /if \(err\.code === 'relay_down'\) stopped\(st, 'The relay did not answer, so this test stopped here\.', words, retry\);/);
  assert.match(h7, /if \(err\.kind === 'dismissed'\) \{\n(\s+\/\/.*\n)?\s+stopped\(st, 'The passkey did not sign\.', null, retry\);/);
  // Any other code of the relay's may be one it gives after a send: not "refused".
  assert.match(h7, /else stopped\(st, 'The relay answered with an error, so this test stopped here\.', words, retry\);/);
  assert.match(op, /err\.kind === 'dismissed' \|\| err\.kind === 'blocked'\) \? 'The passkey did not sign\.'/);
  for (const text of [h7, op]) assert.doesNotMatch(text, /sheet closed|The relay refused that/);
});

test('an instant refusal says only what holds whether no sheet came, no passkey was there, or a sheet was shut at once; and the page claims no sheet, node or phone it did not see', () => {
  assert.equal(problemWords('webauthn_blocked'), 'No passkey came back. This phone may not hold this vault\'s passkey, or this browser may be blocking passkeys.');
  const page = read('p/phone.mjs');
  assert.doesNotMatch(page, /No passkey sheet came up|The sheet closed|sheetCame|Only the phone holding|has had its test coins|node has that transaction|doesn't know \$\{|No vault with this id|The sheet covered|your other devices can use it too|still checking its second key|The relay can't give a test coin/);
  assert.doesNotMatch(read('p/h7-report.mjs'), /While the sheet was up/);
  assert.doesNotMatch(read('p/h7.mjs'), /That test vault is not on this contract/);
  // The thief tab: one read is not a vault or a request that is not there, a dust coin is not no coin, a POST with no
  // answer may have landed, and a call the relay may have sent is not one the contract was not asked.
  const thief = read('t/thief.mjs');
  assert.doesNotMatch(thief, /That vault is not on this contract|That request is not on this contract|No coin in this vault yet|not sent yet/);
  assert.match(thief, /!err\.code \|\| relaySentNothing\(err\.code\) \? 'The NEAR contract was not asked\.' : 'This tab can\\'t tell whether the call went out\.'/);
});

test('classify: a fast NotAllowedError with no trace of a sheet is blocked; anything else is a person or a named fault', () => {
  const quiet = { ms: BLOCKED_MS - 1, seen: false };
  const slow = { ms: BLOCKED_MS, seen: false };
  const traced = { ms: 50, seen: true };
  const na = Object.assign(new Error('no'), { name: 'NotAllowedError' });
  assert.equal(classifyPasskeyError(na, quiet).kind, 'blocked');
  assert.equal(classifyPasskeyError(na, slow).kind, 'dismissed');
  assert.equal(classifyPasskeyError(na, traced).kind, 'dismissed');
  assert.equal(classifyPasskeyError(Object.assign(new Error('rp'), { name: 'SecurityError' }), slow).kind, 'wrong_site');
  assert.equal(classifyPasskeyError(Object.assign(new Error('x'), { name: 'NotSupportedError' }), slow).kind, 'no_support');
  assert.equal(classifyPasskeyError(new TypeError('x'), slow).kind, 'other');
  assert.equal(classifyPasskeyError(new TypeError('words'), slow).message, 'words', 'the browser\'s words are kept');
});

test('both addresses serve one page, with no inline script or style, and it holds no endpoint', () => {
  assert.equal(read('p/index.html'), read('phone/index.html'), '/p/ and /phone/ must not drift');
  const html = read('p/index.html');
  assert.equal(/<script(?![^>]*\bsrc=)/.test(html), false);
  assert.equal(/<style|\sstyle=|\son[a-z]+=/.test(html), false);
  assert.match(html, /signet test coins/, 'the chip is drawn before any script');
  for (const file of readdirSync(join(PAGES, 'p'))) {
    assert.equal(/https?:\/\/|\.testnet\b|\.pages\.dev/.test(read(`p/${file}`)), false, `${file} names a host`);
  }
});

test('the button says only what the design allows, and no text on the page says a time it did not read', () => {
  const page = read('p/phone.mjs');
  assert.match(page, /'Cancel'\)/);
  assert.match(page, /That key can\\'t ask again\./);
  assert.match(page, /cancel_all_and_rotate/);
  assert.match(read('p/passkey-ask.mjs'), /createPasskey/);
  assert.match(page, /label: 'test vault'/);
  assert.match(read('p/h7.mjs'), /label: 'operator'/);
  assert.equal(/\b5:00\b/.test(page), false, 'no fixed clock text');
  assert.equal(/Date\.now\(\)\s*[-+]\s*\d{5}/.test(page), false);
});

/** The text of one top-level function of a page module, from its `function` line to the brace that closes it. */
function functionText(source, name) {
  const start = source.search(new RegExp(`^(async )?function ${name}\\(`, 'm'));
  assert.ok(start >= 0, `${name} is a top-level function`);
  const end = source.indexOf('\n}\n', start);
  return source.slice(start, end + 2);
}

test('the one rule Safari holds a page to: from a tap to the passkey call nothing waits, on the first asks and on the asks that end a stuck call', () => {
  const page = read('p/phone.mjs');
  const asks = { onMakeVault: 'askNewPasskey(', onConfirm: 'confirmVault(', onCancelTap: 'askAssertion(', onCancelAgain: 'onCancelTap(', newMakingCall: 'new AbortController()' };
  for (const [name, ask] of Object.entries(asks)) {
    const text = functionText(page, name);
    assert.doesNotMatch(text, /^async /, `${name} is not async`);
    assert.ok(text.includes(ask), `${name} reaches ${ask}`);
    // The code only: a comment may say "no await".
    const before = text.slice(0, text.indexOf(ask)).replace(/^\s*\/\/.*$/gm, '');
    assert.doesNotMatch(before, /\bawait\b|\bfetch\(|setTimeout\(|\.then\(|requestAnimationFrame\(/, `${name} waits on nothing before ${ask}`);
  }
  // The handlers the buttons carry are those functions and nothing else.
  assert.match(page, /id: 'make', onclick: onMakeVault \}/);
  assert.match(page, /id: 'confirm', onclick: \(\) => onConfirm\(prepared, lines\) \}/);
  assert.match(page, /id: 'cancel', type: 'button', onclick: \(\) => onCancelTap\(\) \}/);
  assert.match(page, /id: 'cancel', type: 'button', 'data-again': '1', onclick: onCancelAgain \}/);
  assert.match(page, /id: 'retry-passkey', onclick: onMakeVault \}/);
  // A stuck call is ended before the new one is made, and only ever from one of those taps: no timer aborts a call
  // a person may still be answering, because a timer cannot tell a stuck call from a sheet still being read. The one
  // other place is a request the contract has ended (cancelled, signed, expired), where no sheet can help any more.
  const aborts = [...page.matchAll(/\.abort\.abort\(\)/g)].length;
  assert.equal(aborts, 3, 'three places end a call');
  assert.match(functionText(page, 'onCancelAgain'), /P\.tap = null;\n  old\.abort\.abort\(\);\n  onCancelTap\(old\.own\);/);
  assert.match(functionText(page, 'newMakingCall'), /P\.making = call;\n  if \(old && !old\.answered\) old\.abort\.abort\(\);/);
  assert.match(functionText(page, 'endTap'), /if \(P\.tap && !P\.tap\.answered\) P\.tap\.abort\.abort\(\);\n  P\.tap = null;\n  P\.hang = false;/);
  const judged = functionText(page, 'judge');
  assert.equal([...judged.matchAll(/endTap\(\);/g)].length, 3, 'cancelled, signed or signing, and expired end the tap');
  assert.doesNotMatch(judged, /P\.tap = null;/, 'and none of them drops it without ending its call');
  assert.equal([...page.matchAll(/endTap\(\);/g)].length, 3, 'and nothing else calls it');
  for (const file of ['p/phone.mjs', 'p/passkey-ask.mjs', 'p/sense.mjs', 'p/vault-make.mjs']) {
    assert.doesNotMatch(read(file), /setTimeout\([^)]*abort|AbortSignal\.timeout/, `${file} aborts nothing on a timer`);
  }
  // Between the page's function and the browser: the watch starts the call before it returns, and the second tap's
  // four signatures are made in the same turn as the assertion is asked for.
  const ask = read('p/passkey-ask.mjs');
  assert.doesNotMatch(functionText(ask, 'watched'), /^async |\bawait\b/);
  assert.match(functionText(ask, 'watched'), /pending = start\(\);/);
  assert.doesNotMatch(readFileSync(join(PAGES, '../lib/intents.mjs'), 'utf8').match(/export async function buildCreateArgs[\s\S]*?pop_p: await assert\(digest\),/)[0].replace('pop_p: await assert(digest),', ''), /\bawait\b/, 'nothing waits in buildCreateArgs before the passkey is asked');
});

test('the phone column: no pull to refresh where CSS can stop it, one column in the middle of a wide window, and a header that fits 320px', () => {
  const css = read('p/phone.css');
  assert.match(css, /html, body \{[^}]*overscroll-behavior-y: contain;/);
  assert.match(css, /@media \(min-width: 700px\) \{\n  body \{ max-width: 480px; margin: 0 auto; \}\n  \.stamp \{ font-size: 72px; \}\n  \.clock \{ font-size: 172px; \}\n\}/);
  assert.match(css, /\.stamp \{[^}]*font: 900 15vw\/1 var\(--sans\);/, 'a phone keeps the stamp it had: 15% of its width, which is 72px of 480');
  // A short phone: the dispenser's line on the idle screen and the steps of a vault in the making take less room, so
  // Recovery file and Check again stay on a 320x568 screen (measured in WebKit). Neither is on the request or CANCELLED
  // screen, which keep their layout.
  assert.match(css, /@media \(max-height: 620px\) \{\n  #no-funds \{ font-size: 15px; margin: 6px 0; \}\n  \.line\.made \{ font-size: 16px; margin: 4px 0; \}\n\}/);
  const phone = read('p/phone.mjs');
  assert.match(phone, /lines\.map\(\(text\) => h\('p', \{ class: 'line made' \}, text\)\)/, 'the steps of a vault in the making');
  assert.equal([...phone.matchAll(/'line made'/g)].length, 1, 'and nothing else');
  assert.match(phone, /h\('p', \{ class: 'line', id: 'no-funds' \}/);
  const landing = read('landing/landing.css');
  assert.match(landing, /@media \(max-width: 345px\) \{\n  \.top \.wordmark \{ font-size: 17px; \}\n  \.top \.chip \{ font-size: 12px; \}\n\}/);
  assert.match(read('replay/index.html'), /href="\/landing\/landing\.css"/, 'the replay page has the same header');
});

test('the spend key and the cold key are kept nowhere a reload could read them back: the page writes only the credential id and what it saw', () => {
  const page = read('p/phone.mjs');
  assert.equal(/localStorage|sessionStorage|indexedDB|document\.cookie/.test(page), false, 'phone.mjs touches no storage itself');
  const fragment = read('p/phone-fragment.mjs');
  assert.equal([...fragment.matchAll(/\.setItem\(/g)].length, 3, 'three writes: the test mode, what was seen, the credential id');
  assert.doesNotMatch(page, /remember(Seen|Credential|H7)\([^)]*(seed|cold)/);
  assert.match(page, /'Copy it now\. A reload forgets the spend key\.'/);
});

test('AUDIT-1: a cancel the relay will not send stays on the page as a file tools/cancel.mjs sends, and the page says how', () => {
  for (const code of ['not_this_relays', 'daily_ceiling', 'rate_limited', 'relay_down', 'rpc_down', 'tx_refused', 'relay_reserve']) assert.equal(relayRefusedIt(code), true, code);
  for (const code of ['assertion_refused', 'already_sent', 'bad_request', 'would_refuse']) assert.equal(relayRefusedIt(code), false, `${code} says the cancel itself would not work`);
  for (const why of ['daily_ceiling', 'not_this_relays', 'relay_down', 'owner_key_low']) assert.equal(relayIsWhy(why), true, why);
  for (const why of ['no_passkey_here', 'origin_not_allowed', 'wrong_site_for_passkey', 'frozen', 'not_cancellable']) assert.equal(relayIsWhy(why), false, why);
  const args = { vault: 'cd'.repeat(32), new_k_s: 'aa'.repeat(32), nonce: 3, expires_at: Date.UTC(2026, 10, 7, 13, 5), assertion: { authenticator_data: '00'.repeat(37), client_data_json: '7b7d', signature: '00'.repeat(64) } };
  const file = JSON.parse(ownCancelFile({ contract: 'tmp.example', method: 'cancel_all_and_rotate', args }));
  assert.deepEqual(Object.keys(file), ['format', 'contract', 'method', 'args']);
  assert.equal(file.format, 'undo-owner-call-v1', 'the format tools/cancel.mjs reads');
  assert.equal(relayBodyProblem({ method: file.method, args: file.args }), null, 'in the shape the relay and the contract take');
  assert.equal(ownCancelFileName(args.vault), 'undo-cancel-cdcdcdcd.json');
  const words = ownCancelWords({ expiresAt: args.expires_at, vaultHex: args.vault });
  assert.match(words, /^The relay didn't send the cancel this page signed\. Any NEAR testnet account can, until 13:05 UTC/);
  assert.match(words, /node tools\/cancel\.mjs --file undo-cancel-cdcdcdcd\.json --account YOUR-ACCOUNT/);
  // A send the relay did not answer may have gone out, so the page does not say it did not.
  const unsure = ownCancelWords({ expiresAt: args.expires_at, vaultHex: args.vault, unsure: true });
  assert.match(unsure, /^If the relay didn't send the cancel this page signed, any NEAR testnet account can, until 13:05 UTC: save it, then run node tools\/cancel\.mjs --file undo-cancel-cdcdcdcd\.json --account YOUR-ACCOUNT$/);
  assert.match(OWN_PATH_LINE, /tools\/cancel\.mjs/);
  assert.match(OWN_PATH_LINE, /tools\/freeze\.mjs --method cancel/);
  const page = read('p/phone.mjs');
  assert.match(page, /if \(signed && relayRefusedIt\(err\.code\)\) P\.signed = \{ \.\.\.signed, unsure: unanswered \|\| erred \};/, 'a refused tap keeps its signed call');
  assert.match(page, /const unanswered = err\.code === 'relay_down';/, 'and one with no answer is kept as one that may have gone out');
  assert.match(page, /const erred = !unanswered && !relaySentNothing\(err\.code\);/, 'and so is any code the relay can give after its sender sent it');
  assert.match(page, /onRelayRefused\(err, \{ method: 'cancel_all_and_rotate', args: callArgs/);
  assert.match(page, /'Save the signed cancel'/);
  assert.match(page, /'Sign a cancel to send yourself'/);
  assert.match(page, /ownCancelNodes\(\),\n\s+h\('button', \{ id: 'cancel'/, 'the request screen shows it too, after a refused tap');
});

test('the recovery file: the page that made the vault says to save it before the first Cancel, inside the button, because its Cancel leaves only the cold key', () => {
  const page = read('p/phone.mjs');
  const css = read('p/phone.css');
  // Why it matters, in the code: both keys come from one call in this tab, and the Cancel's new K_s has no secret here.
  assert.match(readFileSync(join(PAGES, '../lib/intents.mjs'), 'utf8'), /export function newVaultKeys\(\{ seed = randomBytes\(32\), cold = randomBytes\(32\) \} = \{\}\)/);
  assert.match(page, /const newKs = spendKeys\(randomBytes\(32\)\)\.ks\.pub;/, 'the page keeps only the public half of the key its Cancel installs');
  assert.match(page, /P\.seed = prepared\.keys\.seed;\n\s+P\.cold = prepared\.keys\.cold;/, 'and holds the spend seed and the cold key while it is open');
  // The line, where the button is, and only while the page still holds the cold key the file is built from.
  assert.match(page, /const RECOVERY_WHY = 'Save it before your first Cancel';/);
  assert.match(page, /if \(P\.seed\) \{\n[\s\S]{0,700}id: 'recovery', onclick: downloadRecovery \}, 'Recovery file', h\('span', \{ class: 'sub', id: 'recovery-why' \}, RECOVERY_WHY\)\)\);\n\s+out\.push\(h\('p', \{ class: 'small', id: 'copy-now' \}, 'Copy it now\. A reload forgets the spend key\.'\)\);\n\s+\}/);
  assert.equal(page.match(/RECOVERY_WHY/g).length, 2, 'said once');
  // In the button's own room: two lines in the height of one, so no button on that screen moves.
  assert.match(css, /\.go \{[^}]*font: 800 28px\/1\.1 var\(--sans\);[^}]*padding: 16px;/);
  assert.match(css, /\.go\.two \{ --sub: calc\(13px \* 1\.2 \+ 3px\); padding-top: calc\(16px - var\(--sub\) \/ 2\); padding-bottom: calc\(16px - var\(--sub\) \/ 2\); \}/);
  assert.match(css, /\.go \.sub \{ display: block; margin-top: 3px; font: 500 13px\/1\.2 var\(--sans\);/);
});

test('first paint: the HTML shows the chip and a loading line before any module, and the build preloads every module the page loads', () => {
  const html = read('p/index.html');
  assert.match(html, /<main id="screen"><p class="small" id="boot-line">Loading the page\. It reads the contract next\.<\/p>/, 'a line on screen before any script runs');
  assert.match(html, /<div id="chip" class="chip">signet test coins<\/div>/);
  const out = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'undo-phone-build-'));
  try {
    const config = JSON.parse(readFileSync(join(PAGES, '../config/testnet.json'), 'utf8'));
    build({ configObject: { ...config, contract: 'v1.s.undo-btc.testnet' }, out });
    const built = readFileSync(join(out, 'p/index.html'), 'utf8');
    const links = [...built.matchAll(/<link rel="modulepreload" href="([^"]+)">/g)].map((m) => m[1]);
    const reached = importGraph([join(PAGES, 'p/phone.mjs')], PAGES);
    assert.equal(links.length, reached.size - 1, 'one link for each module phone.mjs reaches, from the build\'s own walk');
    assert.ok(links.length > 40, `${links.length} links`);
    for (const url of links) assert.ok(existsSync(join(out, url)), `${url} is in the build`);
    assert.ok(links.includes('/site/lib/index.mjs') && links.includes('/p/kit.mjs') && links.includes('/tools/lib/bytes.mjs'));
    assert.ok(built.lastIndexOf('modulepreload') < built.indexOf('<script type="module" src="/p/phone.mjs">'), 'every link comes before the script');
    assert.equal(built, readFileSync(join(out, 'phone/index.html'), 'utf8'), 'the two addresses still serve one page');
    assert.equal(built.replace(/<link rel="modulepreload" href="[^"]+">\n/g, ''), html, 'and nothing else in it changed');
    assert.match(readFileSync(join(out, '_headers'), 'utf8'), /script-src 'self';/, 'same-origin links, under the same CSP');
  } finally {
    rmSync(out, { recursive: true, force: true });
  }
});
