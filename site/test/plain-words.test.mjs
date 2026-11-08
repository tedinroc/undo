// What the phone and the thief tab say in place of a contract's panic, a node's JSON or the relay's code, with no
// browser: one plain sentence for each shape a refusal arrives in, never the raw words. The pages that ship them are
// read as text too, so a raw message cannot slip back onto a screen beside the sentence.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { segwitAddress } from '../../tools/lib/btc.mjs';
import { sha256 } from '../../tools/lib/crypto.mjs';
import { contractWords, logRaw, noNodeWords, nodeRefusalWords, panicOf, passkeyErrorWords, passkeyWords, relayWords } from '../lib/plain-words.mjs';
import { RELAY_ERRORS } from '../lib/relay-table.mjs';
import { destinationWords } from '../pages/t/logic.mjs';

const PAGES = join(dirname(fileURLToPath(import.meta.url)), '../pages');
const label = (text) => sha256(new TextEncoder().encode(`undo-test-only:plain-words:${text}`));
// Words a viewer should never read: an error's own name, JSON, a node's RPC wording, or a code with underscores.
const RAW = /HostError|GuestPanic|panic_msg|ActionError|FunctionCallError|ExecutionError|RPC error|sendrawtransaction|TypeError|[{}"]|<html|\b[a-z]+_[a-z_]+\b|\bHTTP\b|\b[1-5]\d\d\b/;
const plainSentence = (text, what) => {
  assert.equal(typeof text, 'string', what);
  assert.doesNotMatch(text, RAW, `${what}: "${text}"`);
  assert.match(text, /^[A-Z].*[.]$/, `${what}: one sentence, "${text}"`);
};

test('a contract refusal reads as one sentence, from a view\'s HostError, a transaction\'s JSON, or the relay\'s words', () => {
  const view = 'wasm execution failed with error: HostError(GuestPanic { panic_msg: "SpendKeySuspended" })';
  const json = '{"ActionError":{"index":0,"kind":{"FunctionCallError":{"ExecutionError":"Smart contract panicked: SpendKeySuspended"}}}}';
  const escaped = JSON.stringify({ FunctionCallError: { HostError: { GuestPanic: { panic_msg: 'SpendKeySuspended' } } } });
  for (const raw of [view, json, escaped, JSON.stringify(json)]) {
    assert.equal(panicOf(raw), 'SpendKeySuspended', raw);
    assert.equal(contractWords(raw), 'That key can\'t ask again.', raw);
  }
  // A panic that carries numbers is still read by its name.
  assert.equal(contractWords('{"ActionError":{"index":0,"kind":{"FunctionCallError":{"ExecutionError":"Smart contract panicked: NotUnlocked { unlock: 1730000000000 }"}}}}'), 'It is not unlocked yet.');
  assert.equal(contractWords('wasm execution failed with error: HostError(GuestPanic { panic_msg: "BadNonce { expected: 4 }" })'), 'The vault changed after this was signed.');
  // Anything else is the contract refusing, in general words, and never the text it came in.
  for (const raw of ['{"ActionError":{"index":0,"kind":{"FunctionCallError":{"ExecutionError":"Smart contract panicked: words from a test"}}}}', 'Exceeded the prepaid gas.', '', null]) {
    assert.equal(contractWords(raw), 'The NEAR contract refused it.', String(raw));
  }
  for (const name of ['SpendKeySuspended', 'Unauthorized', 'BadNonce', 'IntentExpired', 'Frozen', 'Inactive', 'NotUnlocked', 'AlreadySigned', 'RetryWindowClosed', 'OutpointBusy', 'PendingCap']) {
    plainSentence(contractWords(`Smart contract panicked: ${name}`), name);
  }
});

test('a Bitcoin node\'s refusal reads as what it means, and an answer from no node says what answered', () => {
  const script = 'sendrawtransaction RPC error: {"code":-26,"message":"mempool-script-verify-flag-failed (Script evaluated without error but finished with a false/empty top stack element)"}';
  assert.equal(nodeRefusalWords(script), 'It needs a second signature.');
  assert.equal(nodeRefusalWords('sendrawtransaction RPC error: {"code":-26,"message":"min relay fee not met, 100 < 121"}'), 'Its fee is too low for the node to pass it on.');
  assert.equal(nodeRefusalWords('sendrawtransaction RPC error: {"code":-27,"message":"Transaction already in block chain"}'), 'The node already has this transaction.');
  assert.equal(nodeRefusalWords('sendrawtransaction RPC error: {"code":-25,"message":"bad-txns-inputs-missingorspent"}'), 'Its coin is already spent, or the node does not know it.');
  assert.equal(nodeRefusalWords('sendrawtransaction RPC error: {"code":-26,"message":"non-BIP68-final"}'), 'Its coin has not waited long enough for that path yet.');
  assert.equal(nodeRefusalWords('sendrawtransaction RPC error: {"code":-26,"message":"something new"}'), 'The node refused it for another reason.');
  assert.equal(noNodeWords({ kind: 'no_answer', error: 'the connection failed' }), 'The connection failed.');
  assert.equal(noNodeWords({ kind: 'no_answer', error: 'no answer in time' }), 'No answer in time.');
  // What answered in place of a node, in words: its HTTP status goes to the console, never onto the screen.
  assert.equal(noNodeWords({ kind: 'transient', status: 502, body: '<html><body>Bad Gateway: not a node</body></html>' }), 'Something on the way to the node got no good answer from it.');
  assert.equal(noNodeWords({ kind: 'transient', status: 503, body: 'Service Unavailable' }), 'Something on the way to the node said it isn\'t available right now.');
  assert.equal(noNodeWords({ kind: 'transient', status: 429, body: 'Too Many Requests' }), 'Something on the way to the node said too many tries.');
  assert.equal(noNodeWords({ kind: 'transient', status: 504, body: '' }), 'Something on the way to the node gave up waiting for it.');
  assert.equal(noNodeWords({ kind: 'transient', status: 500, body: '' }), 'Something on the way to the node hit an error.');
  assert.equal(noNodeWords({ kind: 'transient', status: 404, body: '<html></html>' }), 'Something on the way to the node answered instead of it.');
  assert.equal(noNodeWords({ kind: 'transient', status: 400, body: 'sendrawtransaction RPC error: {"code":-28,"message":"Loading block index…"}' }), 'The node was too busy to look at it.');
  assert.equal(noNodeWords({ kind: 'transient', status: 200, body: 'ab'.repeat(32) }), 'Something answered, but not with this transaction.');
  for (const words of [nodeRefusalWords(script), noNodeWords({ kind: 'transient', status: 418, body: '' })]) plainSentence(words, 'node words');
  for (const status of [400, 403, 404, 408, 429, 500, 502, 503, 504, 520]) plainSentence(noNodeWords({ kind: 'transient', status, body: '<html></html>' }), `HTTP ${status} from no node`);
});

test('every relay code has a sentence with no code in it, and a refusal that carries the contract\'s words reads as the contract\'s sentence', () => {
  for (const code of [...Object.keys(RELAY_ERRORS), 'relay_down']) plainSentence(relayWords({ code }), code);
  assert.equal(relayWords({ code: 'not_this_relays' }), 'This relay sends cancels only for vaults it made.');
  assert.equal(relayWords({ code: 'tx_refused', verbatim: '{"ActionError":{"index":0,"kind":{"FunctionCallError":{"ExecutionError":"Smart contract panicked: Unauthorized"}}}}' }), 'The contract did not take that signature.');
  assert.equal(relayWords({ code: 'would_refuse', verbatim: 'wasm execution failed with error: HostError(GuestPanic { panic_msg: "SpendKeySuspended" })' }), 'That key can\'t ask again.');
  assert.equal(relayWords({ code: 'rate_limited', retryAfterS: 7 }), 'Too many tries through the relay. Wait 7 s and try again.');
  assert.equal(relayWords({ code: 'something_new' }), 'The relay said no.');
  for (const refusal of ['webauthn: bad signature', 'webauthn: wrong rp id', 'webauthn: user not verified', 'webauthn signature must be 64 bytes']) plainSentence(passkeyWords(refusal), refusal);
  for (const kind of ['no_support', 'wrong_site', 'other']) plainSentence(passkeyErrorWords(kind), kind);
});

test('the raw words still reach the console, once for each new line', () => {
  const lines = [];
  const real = console.info;
  console.info = (line) => lines.push(line);
  try {
    logRaw('a test', 'raw words one');
    logRaw('a test', 'raw words one');
    logRaw('a test', { code: -26 });
    logRaw('a test', '');
  } finally {
    console.info = real;
  }
  assert.deepEqual(lines, ['undo: a test: raw words one', 'undo: a test: {"code":-26}']);
});

test('under send to, one sentence per refusal, naming the other network: "That is a regtest address; this vault is on Mutinynet."', () => {
  const program = label('to').slice(0, 20);
  assert.equal(destinationWords(segwitAddress('regtest', 0, program), 'mutinynet', 'Mutinynet'), 'That is a regtest address; this vault is on Mutinynet.');
  assert.equal(destinationWords(segwitAddress('mutinynet', 0, program), 'regtest', 'local regtest'), 'That is a signet or testnet address; this vault is on local regtest.');
  assert.equal(destinationWords(segwitAddress('mainnet', 0, program), 'mutinynet', 'Mutinynet'), 'This demo only sends to test addresses that start with tb1.');
  assert.equal(destinationWords(segwitAddress('mainnet', 0, program), 'regtest', 'local regtest'), 'This demo only sends to test addresses that start with bcrt1.');
  assert.equal(destinationWords(`bitcoin:${segwitAddress('mutinynet', 0, program)}`, 'mutinynet', 'Mutinynet'), 'That is a bitcoin: link. Paste only the address in it.');
  assert.equal(destinationWords('not an address', 'mutinynet', 'Mutinynet'), 'That address does not check out.');
  assert.equal(destinationWords(segwitAddress('mutinynet', 0, program), 'mutinynet', 'Mutinynet'), '', 'a good one: nothing to say');
  assert.equal(destinationWords('', 'mutinynet', 'Mutinynet'), '', 'an empty field: nothing to say yet');
});

test('the pages put no raw error text on a screen: no message, verbatim or code beside a sentence', () => {
  const thief = readFileSync(join(PAGES, 't/thief.mjs'), 'utf8');
  const phone = readFileSync(join(PAGES, 'p/phone.mjs'), 'utf8');
  for (const [name, source] of [['thief.mjs', thief], ['phone.mjs', phone]]) {
    assert.doesNotMatch(source, /`NEAR contract: \$\{/, `${name}: the contract's raw words after a label`);
    assert.doesNotMatch(source, /node: \$\{(answer\.body|S\.nodeWords)/, `${name}: a node's raw answer after a label`);
    assert.doesNotMatch(source, /words: (err|refusal|outcome)\b/, `${name}: an error's own words as a notice`);
    assert.doesNotMatch(source, /\[err\.code, err\.verbatim \?\? err\.message\]\.filter\(Boolean\)\.join\(': '\)\);?\s*$/m, `${name}: code and message joined for a screen`);
  }
  assert.doesNotMatch(thief, /textContent = errorWords|verbatim: errorWords/, 'thief.mjs: an error\'s words on a screen');
  assert.doesNotMatch(phone, /h\('p', \{ class: 'words' \}, (err|`\$\{err)/, 'phone.mjs: an error\'s words in the mono box');
});
