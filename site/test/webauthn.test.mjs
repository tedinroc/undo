// WebAuthn into contract arguments. Fixtures here are built by hand to the shapes real authenticators give.
// A real phone is gate G3; a real browser with a virtual authenticator is browser.test.mjs.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { concat, fromHex, toHex } from '../../tools/lib/bytes.mjs';
import { p256, sha256 } from '../../tools/lib/crypto.mjs';
import { softAssertion } from '../../tools/lib/intent.mjs';
import { fromBuffer, toBase64Url } from '../lib/base64.mjs';
import { softCredentials } from '../lib/soft-authenticator.mjs';
import { assertionToArgs, createPasskey, derToRaw, FLAG_BE, FLAG_BS, FLAG_UP, FLAG_UV, flagsOf, getAssertion, isHighS, lowS, p256FromSpki, refusalOf } from '../lib/webauthn.mjs';

const label = (text) => sha256(new TextEncoder().encode(`undo-test-only:web:${text}`));
const ORIGIN = 'https://site.example';
const RP = 'site.example';
const RP_HASH = sha256(new TextEncoder().encode(RP));
const N = p256.CURVE.n;
const big = (b) => BigInt(`0x${toHex(b)}`);

const soft = (over = {}) => softCredentials({ secret: label('passkey'), origin: ORIGIN, rpId: RP, ...over });

function der(r, s) {
  const int = (x) => concat(Uint8Array.of(2, x.length), x);
  const body = concat(int(r), int(s));
  return concat(Uint8Array.of(0x30, body.length), body);
}
const filled = (n, v) => new Uint8Array(n).fill(v);

test('derToRaw: strips a sign byte, pads a short value, keeps the width', () => {
  const r = concat(Uint8Array.of(0), filled(32, 0x80));
  const s = filled(31, 0x11);
  const raw = derToRaw(der(r, s));
  assert.equal(raw.length, 64);
  assert.equal(toHex(raw.slice(0, 32)), toHex(filled(32, 0x80)));
  assert.equal(toHex(raw.slice(32)), `00${toHex(s)}`);
  // Two leading zero bytes in the value, the rarest real padding.
  assert.equal(toHex(derToRaw(der(filled(30, 0x01), filled(32, 0x7f))).slice(0, 2)), '0000');
});

test('derToRaw: refuses what is not strict DER', () => {
  const good = der(filled(32, 1), filled(32, 2));
  assert.throws(() => derToRaw(good.slice(1)));
  assert.throws(() => derToRaw(concat(good, Uint8Array.of(0))), 'trailing byte');
  assert.throws(() => derToRaw(der(filled(33, 1), filled(32, 2))), 'too long');
  assert.throws(() => derToRaw(der(concat(Uint8Array.of(0), filled(32, 1)), filled(32, 2))), 'needless zero');
  assert.throws(() => derToRaw(der(filled(32, 0x80), filled(32, 2))), 'negative');
  assert.throws(() => derToRaw(der(new Uint8Array(0), filled(32, 2))), 'empty');
});

test('lowS: flips only a high S, keeps r, and the result still verifies', () => {
  const digest = label('msg');
  const secret = label('passkey');
  const pub = p256.getPublicKey(secret, true);
  const sig = p256.sign(digest, secret, { prehash: false, lowS: true });
  const low = sig.toCompactRawBytes();
  const high = new p256.Signature(sig.r, N - sig.s).toCompactRawBytes();
  assert.equal(isHighS(low), false);
  assert.equal(isHighS(high), true);
  assert.equal(toHex(lowS(high)), toHex(low));
  assert.equal(toHex(lowS(low)), toHex(low));
  assert.equal(big(lowS(high).slice(0, 32)), sig.r);
  assert.ok(p256.verify(lowS(high), digest, pub, { prehash: false, lowS: true }));
  // The contract's p256_verify takes both forms; this checks the high one is itself valid, not malformed.
  assert.ok(p256.verify(high, digest, pub, { prehash: false, lowS: false }));
  assert.throws(() => lowS(new Uint8Array(63)));
});

test('getAssertion: a high-S authenticator comes out low-S, on one path', async () => {
  const digest = label('rotate');
  const out = await getAssertion({ credentials: soft({ highS: true }), digest, rpId: RP });
  assert.equal(out.highS, true, 'reported, because G3 logs the form of each tap');
  assert.equal(isHighS(fromHex(out.args.signature)), false);
  assert.equal(fromHex(out.args.signature).length, 64);
  const low = await getAssertion({ credentials: soft(), digest, rpId: RP });
  assert.equal(low.highS, false);
});

test('getAssertion passes what a browser needs: the challenge, the rp, required UV, and one allowed credential', async () => {
  const digest = label('rotate');
  const seen = [];
  const inner = soft();
  const credentials = { get: (options) => {
    seen.push(options.publicKey);
    return inner.get(options);
  } };
  await getAssertion({ credentials, digest, rpId: RP, credentialId: inner.credentialId });
  assert.equal(toHex(fromBuffer(seen[0].challenge)), toHex(digest));
  assert.equal(seen[0].userVerification, 'required');
  assert.equal(seen[0].rpId, RP);
  assert.equal(toHex(fromBuffer(seen[0].allowCredentials[0].id)), toHex(inner.credentialId));
  await assert.rejects(getAssertion({ credentials: inner, digest, rpId: RP, credentialId: label('other') }), /no credential/);
  await assert.rejects(getAssertion({ credentials: inner, digest, rpId: 'evil.example' }));
});

test('the page\'s arguments equal the shape tools/lib/intent.mjs softAssertion sends, field by field', async () => {
  const digest = label('rotate');
  const secret = label('passkey');
  const tools = softAssertion({ secret, digest, origin: ORIGIN, rpId: RP });
  const page = (await getAssertion({ credentials: soft(), digest, rpId: RP })).args;
  assert.deepEqual(Object.keys(page).sort(), Object.keys(tools).sort());
  assert.equal(page.authenticator_data, tools.authenticator_data, 'same bytes: rp hash, flags, sign count 1');
  const pageClient = JSON.parse(Buffer.from(fromHex(page.client_data_json)).toString());
  const toolsClient = JSON.parse(Buffer.from(fromHex(tools.client_data_json)).toString());
  assert.equal(pageClient.challenge, toolsClient.challenge);
  assert.equal(pageClient.type, toolsClient.type);
  assert.equal(pageClient.origin, toolsClient.origin);
  assert.equal(pageClient.crossOrigin, false, 'browsers send this, and the contract must read it');
});

const check = (assertion, digest, over = {}) => refusalOf({ assertion, digest, pubkey: p256.getPublicKey(label('passkey'), true), rpIdHash: RP_HASH, origins: [ORIGIN], ...over });

test('refusalOf: passes a good assertion, and refuses with the contract\'s own words', async () => {
  const digest = label('rotate');
  const args = async (over) => (await getAssertion({ credentials: soft(over), digest, rpId: RP })).args;
  assert.equal(check(await args(), digest), null);
  assert.equal(check(await args({ highS: true }), digest), null);
  assert.equal(check(await args({ flags: FLAG_UP }), digest), 'webauthn: user not verified');
  assert.equal(check(await args({ flags: FLAG_UV }), digest), 'webauthn: user not present');
  assert.equal(check(await args({ crossOrigin: true }), digest), 'webauthn: cross origin');
  assert.equal(check(await args(), label('other')), 'webauthn: wrong challenge');
  assert.equal(check(await args(), digest, { origins: ['https://other.example'] }), 'webauthn: origin not allowed');
  assert.equal(check(await args(), digest, { rpIdHash: label('rp') }), 'webauthn: wrong rp id');
  assert.equal(check(await args(), digest, { pubkey: p256.getPublicKey(label('other'), true) }), 'webauthn: bad signature');
  const good = await args();
  assert.equal(check({ ...good, authenticator_data: good.authenticator_data.slice(0, 60) }, digest), 'webauthn: short authenticator data');
  assert.equal(check({ ...good, client_data_json: toHex(new TextEncoder().encode('{')) }, digest), 'webauthn: bad client data');
  const wrongType = toHex(new TextEncoder().encode(JSON.stringify({ type: 'webauthn.create', challenge: toBase64Url(digest), origin: ORIGIN })));
  assert.equal(check({ ...good, client_data_json: wrongType }, digest), 'webauthn: wrong type');
});

test('assertionToArgs: accepts ArrayBuffer and Uint8Array alike, because browsers and fixtures differ', async () => {
  const cred = await soft().get({ publicKey: { rpId: RP, challenge: label('x') } });
  const fromBuffers = assertionToArgs(cred);
  const fromViews = assertionToArgs({ response: { authenticatorData: new Uint8Array(cred.response.authenticatorData), clientDataJSON: new Uint8Array(cred.response.clientDataJSON), signature: new Uint8Array(cred.response.signature) } });
  assert.deepEqual(fromBuffers, fromViews);
});

test('flagsOf reads BE and BS, which the page warns on', async () => {
  const cred = await soft({ flags: FLAG_UP | FLAG_UV | FLAG_BE | FLAG_BS }).get({ publicKey: { rpId: RP, challenge: label('x') } });
  assert.deepEqual(flagsOf(fromBuffer(cred.response.authenticatorData)), { up: true, uv: true, backupEligible: true, backupState: true });
});

test('createPasskey: the compressed key from a SPKI, asks for ES256 and UV, labelled test vault', async () => {
  const inner = soft();
  const seen = [];
  const out = await createPasskey({ credentials: { create: (o) => {
    seen.push(o.publicKey);
    return inner.create(o);
  } }, rpId: RP });
  assert.equal(toHex(out.pubkey), toHex(inner.publicKey));
  assert.equal(toHex(out.credentialId), toHex(inner.credentialId));
  assert.deepEqual(seen[0].pubKeyCredParams, [{ type: 'public-key', alg: -7 }]);
  assert.equal(seen[0].authenticatorSelection.userVerification, 'required');
  assert.equal(seen[0].user.name, 'test vault');
});

test('p256FromSpki refuses another curve, and a browser with no getPublicKey is told so', async () => {
  const secp256k1Spki = fromHex(`3056301006072a8648ce3d020106052b8104000a034200${'04'}${'11'.repeat(64)}`);
  assert.throws(() => p256FromSpki(secp256k1Spki), /not a P-256/);
  await assert.rejects(createPasskey({ credentials: { create: async () => ({ rawId: new ArrayBuffer(4), response: {} }) }, rpId: RP }), /cannot read/);
});
