// The phone page's senses, in Node with a made-up window, and the page's rules a reader can check without a browser.
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { BLOCKED_MS, classifyPasskeyError, inAppBrowser, isMobile, passkeyProblem, sensePasskeys } from '../pages/p/sense.mjs';
import { OWN_PATH_LINE, ownCancelFile, ownCancelFileName, ownCancelWords, relayIsWhy, relayRefusedIt } from '../pages/p/own-cancel.mjs';
import { relayBodyProblem } from '../lib/relay-table.mjs';

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

test('passkeyProblem: the order a person would want to hear it, and no platform authenticator only stops a phone', () => {
  const ok = { secure: true, api: true, platform: true, mobile: true };
  assert.equal(passkeyProblem(ok), null);
  assert.equal(passkeyProblem({ ...ok, secure: false, api: false }), 'not_secure');
  assert.equal(passkeyProblem({ ...ok, api: false }), 'no_webauthn');
  assert.equal(passkeyProblem(ok, true), 'webauthn_blocked');
  assert.equal(passkeyProblem({ ...ok, platform: false }), 'no_platform_authenticator');
  assert.equal(passkeyProblem({ ...ok, platform: false, mobile: false }), null, 'a laptop can reach a phone through the OS sheet');
  assert.equal(passkeyProblem({ ...ok, platform: null }), null, 'not knowing is not a reason to hide the button');
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
  assert.match(words, /until 13:05 UTC/);
  assert.match(words, /node tools\/cancel\.mjs --file undo-cancel-cdcdcdcd\.json --account YOUR-ACCOUNT/);
  assert.match(OWN_PATH_LINE, /tools\/cancel\.mjs/);
  assert.match(OWN_PATH_LINE, /tools\/freeze\.mjs --method cancel/);
  const page = read('p/phone.mjs');
  assert.match(page, /if \(signed && relayRefusedIt\(err\.code\)\) P\.signed = signed;/, 'a refused tap keeps its signed call');
  assert.match(page, /onRelayRefused\(err, \{ method: 'cancel_all_and_rotate', args: callArgs/);
  assert.match(page, /'Save the signed cancel'/);
  assert.match(page, /'Sign a cancel to send yourself'/);
  assert.match(page, /ownCancelNodes\(\),\n\s+h\('button', \{ id: 'cancel'/, 'the request screen shows it too, after a refused tap');
});
