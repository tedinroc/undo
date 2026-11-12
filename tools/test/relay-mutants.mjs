#!/usr/bin/env node
// Breaks the relay, its state store and the pages' pure logic one line at a time, each in its own scratch copy of the
// tree, and checks that the site tests notice. A survivor means no test holds that rule down.
//
//   node tools/test/relay-mutants.mjs [NAME]     every mutant, or those whose name contains NAME
//   node tools/test/relay-mutants.mjs --no-stage [NAME]
//   node tools/test/relay-mutants.mjs --check    only that each mutant's text is in its file exactly once
//   node tools/test/relay-mutants.mjs --self-test
//
// Each mutant goes through three tiers and stops at the first that kills it: the site tests nearest its file, then the
// rest of site/test with no browser and no chain, then the stage tests, which run the real wasm on a local NEAR node with
// a mock signer, bitcoind on regtest, and the relay in real workerd (relay.workerd, sandbox, made-row, stage-made). It
// never starts Chrome: CHROME_BIN points nowhere, so a mutant only a Chrome test could kill reads NOT JUDGED, never
// killed. --no-stage leaves the stage tier out, and what only it could judge reads NOT JUDGED.
//
// A mutant is killed only when a test's own body fails. A hook that fails (a stage that did not start), a timeout, a
// test file that crashes before its tests run, or a run with nothing in it is NOT JUDGED, after one more try. A kill that
// rests only on the stage tests, or only on phone-boot.test.mjs, which times its reads, must fail the same test again,
// and phone-boot must also pass on the unbroken copy.
//
// The stage tier needs NEAR_SANDBOX_BIN_PATH, UNDO_WRANGLER_MODULES, UNDO_BITCOIN_BIN (default the repo's
// crates/undo-btc/.tools), UNDO_WASM_DIR (default <target>/near) and UNDO_LIBLZMA_DIR where the sandbox binary needs it.
// At most 4 test runs at once, and at most 3 of them stage runs, each of which starts one sandbox at a time.
import { spawn, spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '../..');

const H = 'site/functions/_relay/handler.mjs';
const A = 'site/functions/_relay/answer.mjs';
const O = 'site/functions/_relay/owner-check.mjs';
const F = 'site/functions/_relay/funds.mjs';
const N = 'site/functions/_relay/near-send.mjs';
const S = 'worker/undo-cron/src/undo-state.mjs';
const T = 'site/lib/relay-table.mjs';
const RS = 'site/lib/request-state.mjs';
const PE = 'site/lib/pending.mjs';
const FR = 'site/lib/fragment.mjs';
const BT = 'site/lib/bitcoin.mjs';
const IN = 'site/lib/intents.mjs';
const WA = 'site/lib/webauthn.mjs';
const TL = 'site/pages/t/logic.mjs';
const PF = 'site/pages/p/phone-fragment.mjs';
const OC = 'site/pages/p/own-cancel.mjs';
const HR = 'site/pages/p/h7-report.mjs';
const PW = 'site/lib/plain-words.mjs';
const SE = 'site/pages/p/sense.mjs';
const PA = 'site/pages/p/passkey-ask.mjs';
const VM = 'site/pages/p/vault-make.mjs';
const PH = 'site/pages/p/phone.mjs';
const RC = 'site/lib/relay-client.mjs';

// [name, file, old text, new text, a Chrome test that checks it]
const MUTANTS = [
  // ---------------------------------------------------------------- the relay's front door
  ['relay: any origin may call it', H, 'return origin !== (this.env.SITE_ORIGIN || new URL(request.url).origin);', 'return false;'],
  ['funds: any origin may call it', F, "if (relay.originProblem(request)) throw new Refusal('bad_origin'", "if (false) throw new Refusal('bad_origin'"],
  ['relay: a body of the wrong shape goes on', H, 'if (problem) throw new Refusal(problem,', 'if (false) throw new Refusal(problem,'],
  ['heartbeat: off the list, yet sent without the token', H, 'if (spec.operatorOnly && !this.operatorAsked(request)) throw', 'if (false) throw'],
  ['heartbeat: any token of the right length passes', H, 'return difference === 0;', 'return true;'],
  ['general: sends with no state store or salt', H, 'return bucket === OWNER || Boolean(this.state && this.env.IP_SALT);', 'return true;'],
  ['body: a declared length over the cap is read', A, "if (Number(request.headers.get('content-length') ?? 0) > MAX_RELAY_BODY) throw tooLarge();", ''],
  ['body: a chunked body past the cap is read', A, 'if (size > MAX_RELAY_BODY) {', 'if (false) {'],
  ['shape: a method that is not a string', T, "typeof body.method !== 'string' || ", ''],
  ['shape: a passkey signature of any length', T, 'isHex(a.signature, 64)', 'isHex(a.signature)'],
  ['shape: a WebAuthn object with fields the contract lacks', T, "only(a, ['authenticator_data', 'client_data_json', 'signature']) && ", ''],
  ['shape: a cancel naming both Passkey and Cold', T, ' && Object.keys(auth).length === 1', ''],
  ['shape: more than sixteen inputs', T, ' && a.inputs.length <= MAX_INPUTS', ''],
  ['shape: a creation with a caller-chosen policy', T, ' && a.policy === null', ''],
  ['heartbeat: on the public list', T, 'perVaultMinute: 2, operatorOnly: true', 'perVaultMinute: 2, operatorOnly: false'],
  ['fetch: follows redirects with signed bytes', A, "redirect: 'manual'", "redirect: 'follow'"],
  ['signature: one that cannot be read counts as good', A, '  } catch {\n    return false;', '  } catch {\n    return true;'],

  // ---------------------------------------------------------------- create_vault, propose, activate, execute
  ['create: any guard', H, 'if (args.guard !== this.account) throw', 'if (false) throw'],
  ['create: no proof of work', H, 'if (!checkPow(vault, body.pow, this.powBits)) throw', 'if (false) throw'],
  ['create: not signed by its spend key', H, 'if (!(await ed25519Verifies(fromHex(args.k_s), fromHex(args.pop_s), digest))) throw', 'if (false) throw'],
  ['create: of a vault that exists', H, "if ((await view('vault', { vault })) !== null) throw", 'if (false) throw'],
  ['create: two sends of one create both go', H, 'if (out.busy) throw', 'if (false) throw'],
  ['create: goes out though its hash was not kept', H, "if (!out.ok) throw new Refusal('state_store_down', { message: 'that vault cannot be recorded' })", "if (false) throw new Refusal('state_store_down', { message: 'that vault cannot be recorded' })"],
  ['create: vaults take the whole general ceiling', H, "const ceiling = method === 'create_vault' ? this.createCeiling() : this.ceilings[spec.key];", 'const ceiling = this.ceilings[spec.key];'],
  ['create: no per-address limit', T, 'pow: true, costMicro: CREATE_DEPOSIT_MILLI * 1000 + 2000, perIpHour: 3 }', 'pow: true, costMicro: CREATE_DEPOSIT_MILLI * 1000 + 2000, perIpHour: 0 }'],
  ['propose: not signed by its spend key', H, 'if (!(await ed25519Verifies(fromHex(row.k_s), fromHex(args.spend_sig), digest))) throw', 'if (false) throw'],
  ['execute: a signed request goes again', H, "if (request.status === 'Signed') throw", 'if (false) throw'],
  ['execute: a cancelled request goes', H, 'if (request.epoch !== vault.spend_epoch) throw', 'if (false) throw'],
  ['execute: an expired request goes', H, 'if (block.blockMs > request.expires_at) throw', 'if (false) throw'],
  ['execute: a request still locked goes', H, 'if (block.blockMs + UNLOCK_SLACK_MS < request.unlock) throw', 'if (false) throw'],
  ['execute: sixteen inputs cost one', H, 'if (inputs <= 1) return;', 'return;'],
  ['execute: inputs past the ceiling still go', H, 'if (!out.ok) throw new Refusal(out.code, { message: `the ${GENERAL}', 'if (false) throw new Refusal(out.code, { message: `the ${GENERAL}'],
  ['execute: gas for one input whatever the count', T, 'inputs * (signTgas + callbackTgas + 4) + 6', '(signTgas + callbackTgas + 4) + 6'],
  ['signing: past the retry window goes', H, 'if (closesAt !== null && block.blockMs >= closesAt) {', 'if (false) {'],
  ['signing: a sign call still out never blocks a retry', H, "if (!(request.in_flight > 0) || typeof request.first_execute_at !== 'number') return;", 'return;'],

  // ---------------------------------------------------------------- the owner key: made vaults, signatures, replay
  ['owner: a vault this relay did not make passes the handler', H, "if (made === null) throw new Refusal('not_this_relays'", "if (false) throw new Refusal('not_this_relays'"],
  ['owner: a made row alone makes the vault its own', H, 'const mine = made === undefined || made.confirmed ? true : await this.madeHere(args.vault, made, reader);', 'const mine = true;'],
  ['owner: a create the chain shows did not make it still counts', H, "if (mine === false) throw new Refusal('not_this_relays'", "if (false) throw new Refusal('not_this_relays'"],
  ['owner: what owner-check refuses goes', H, "if (problem) throw new Refusal('assertion_refused', { message: problem });", ''],
  ['owner: a vault the chain cannot vouch for counts as checked', H, 'return { checked: checked && mine === true, call:', 'return { checked, call:'],
  ['owner: an unchecked call is charged as checked', H, 'checked: ownerCall?.checked !== false,', 'checked: true,'],
  ['made-sends: a failed create reads as cannot-tell', H, "if (Object.hasOwn(status, 'Failure')) mine = false;", 'if (false) mine = false;'],
  ['made-sends: a create in any block will do', H, 'mine = Number(BigInt(block.header.timestamp_nanosec) / 1_000_000n) === row.created_at;', 'mine = true;'],
  ['owner: an expired intent goes', O, "if (args.expires_at + EXPIRY_GRACE_MS < now) return 'that intent has expired';", ''],
  ['owner: a challenge that is not this call', O, 'if (client.challenge !== toBase64Url(digest)) return', 'if (false) return'],
  ['owner: a passkey call\'s signature is not checked', O, 'return crypto.subtle.verify(algorithm, key, fromHex(assertion.signature), message);', 'return true;'],
  ['owner: a cold cancel\'s signature is not checked', O, 'return secp256k1.verify(signature.slice(0, 64), digest, fromHex(coldHex), { prehash: false, lowS: true });', 'return true;'],
  ['owner: with the read down, any call counts as checked', O, 'return { problem: null, checked: made ? (await signedBy(passkey, args, contract, made)) === true : false };', 'return { problem: null, checked: true };'],
  ['owner: a used passkey nonce', O, "if (method === 'cancel_all_and_rotate' && args.nonce < vault.passkey_nonce) return", 'if (false) return'],
  ['owner: a passkey nonce from far ahead', O, "if (method === 'cancel_all_and_rotate' && args.nonce > vault.passkey_nonce + NONCE_AHEAD_LIMIT) return", 'if (false) return'],
  ['owner: a request that is gone', O, "if (request === null) return refuse('no such request');", ''],
  ['owner: a request past cancelling', O, "if (request.status !== undefined && request.status !== 'Pending') return", 'if (false) return'],
  ['owner: a bad signature goes', O, 'if (signed === false) return refuse(', 'if (false) return refuse('],
  ['owner: a key on no curve counts as checked', O, 'return { problem: null, checked: signed === true };', 'return { problem: null, checked: signed !== false };'],
  ['replay row: a cancel\'s row does not name its request', O, "return `${method}:${args.auth.Passkey ? 'passkey' : 'cold'}:${args.request}:${args.expires_at}`;", "return `${method}:${args.auth.Passkey ? 'passkey' : 'cold'}:${args.expires_at}`;"],
  ['cancel: a day limit of 1200 per vault', T, '  cancel: { key: OWNER, tgas: 30, costMicro: 600, perVaultMinute: 6, perVaultDay: 12,', '  cancel: { key: OWNER, tgas: 30, costMicro: 600, perVaultMinute: 6, perVaultDay: 1200,'],

  // ---------------------------------------------------------------- charges, limits, refunds, the reserve
  ['per-address: read from a header the caller sets', H, "hashIp(this.env.IP_SALT, request.headers.get('cf-connecting-ip'))", "hashIp(this.env.IP_SALT, request.headers.get('x-forwarded-for'))"],
  ['per-address: IPv6 counted per address, not per /64', A, "return all.slice(0, 4).map((h) => h.toString(16)).join(':');", "return all.map((h) => h.toString(16)).join(':');"],
  ['per-address: kept without the salt', A, 'utf8(`${salt}|${limitAddress(ip)}`)', 'utf8(`${limitAddress(ip)}`)'],
  ['state down: a cancel has no per-vault limit', H, 'this.limitWithoutState(args.vault, spec);\n        return', 'return'],
  ['no state: a cancel has no per-vault limit', H, 'if (seen > spec.perVaultMinute) throw', 'if (false) throw'],
  ['refund: a send a node refused keeps its charge', H, 'if (!degraded && (err instanceof StateDown', 'if (false && (err instanceof StateDown'],
  ['refund: a refusal after the charge keeps it', H, '      await this.refund(method, charged);\n      throw err;', '      throw err;'],
  ['reserve: general sends may take what cancels need', H, 'if (free - (charged.hold ?? holdYocto(0)) < this.ownerReserve) {', 'if (false) {'],
  ['reserve: keeps only the floor, not a day of cancels', T, 'OWNER_FLOOR_YOCTO + BigInt(Math.ceil(ownerCeilingMicro)) * 1_000_000_000_000_000_000n;\n', 'OWNER_FLOOR_YOCTO;\n'],
  ['state down mid-send: a general send falls back to a chain nonce', H, 'if (!(fallBack && err instanceof StateDown)) throw err;', 'if (!(err instanceof StateDown)) throw err;'],
  ['status: owner up past its ceiling', H, 'if (owner.up && read.spent.owner + RELAY_METHODS.cancel_all_and_rotate.costMicro > this.ceilings.owner)', 'if (false)'],
  ['status: general up when no vault fits', H, 'if (general.up && read.spent.general + RELAY_METHODS.create_vault.costMicro > this.createCeiling()) {', 'if (false) {'],
  ['status: general up whatever the reserve', H, 'if (fits(createHold()) && fits(executeHold(STATUS_EXECUTE_INPUTS, gas))) return null;', 'return null;'],
  ['status: a low allowance reads up', H, 'if (allowance !== undefined && allowance !== null && BigInt(allowance) < KEY_FLOOR_YOCTO) return', 'if (false) return'],
  ['status: a key refused for allowance stays up', H, "if (spec.key === OWNER && err instanceof Refusal && err.code === 'tx_refused'", "if (false && err instanceof Refusal && err.code === 'tx_refused'"],
  ['send: any node refusal re-signs', N, 'if (!stale && !expired) throw', 'if (false) throw'],
  ['send: re-signs without limit', N, 'if (retries >= MAX_RESIGNS) throw', 'if (false) throw'],
  ['send: a send with no answer re-signs', N, '    return { unknown: true };', "    return { invalid: 'Expired' };"],

  // ---------------------------------------------------------------- the state store
  ['state: past the daily ceiling', S, "if (spent + cost > ceiling) return { ok: false, code: 'daily_ceiling', bucket: key, resets_at: resetsAt(now) };\n    if (share", "if (false) return { ok: false, code: 'daily_ceiling', bucket: key, resets_at: resetsAt(now) };\n    if (share"],
  ['state: unchecked calls past their share', S, 'if (share && this.spentToday(share.bucket, now) + cost > share.ceiling) return', 'if (false) return'],
  ['state: no per-address limit', S, 'if (seen >= perIpHour) return', 'if (false) return'],
  ['state: no per-vault limit', S, 'if (seen >= limit) return', 'if (false) return'],
  ['state: unchecked calls do not count against their share', S, 'const buckets = share ? [key, share.bucket] : [key];', 'const buckets = [key];'],
  ['state: owner calls for a vault this relay did not make', S, "if (owner && (typeof vault !== 'string' || !this.madeRow(vault))) return", 'if (false) return'],
  ['replay row: one signed call sent twice', S, "if (owner && this.first('SELECT at FROM owner_sent WHERE vault = ? AND call = ?', vault, call)) return", 'if (false) return'],
  ['replay row: never written', S, "this.sql.exec('INSERT INTO owner_sent VALUES (?, ?, ?)', vault, call, now);", ''],
  ['state: unchecked calls get the checked limits', S, 'const unchecked = owner && checked === false;', 'const unchecked = false;'],
  ['state: unchecked calls get the checked per-minute limit', S, 'limit: spec.uncheckedPerVaultMinute', 'limit: spec.perVaultMinute'],
  ['refund: every refund gives back the per-vault counts', S, 'if (!counters) return { ok: true };', ''],
  ['refund: a send that never landed keeps its replay row', S, 'if (Array.isArray(ticket.sent)) this.sql.exec(', 'if (false) this.sql.exec('],
  ['refund: a create that never landed keeps its made row', S, "if (typeof ticket.made === 'string') this.dropMade(ticket.made);", ''],
  ['made: a second send of one create is not busy', S, 'busy: now - row.at < CLAIM_MS', 'busy: false'],
  ['made-sends: a stale answer about another hash changes the row', S, "if (!this.first('SELECT hash FROM made_sends WHERE vault = ? AND hash = ?', vault, hash)) return", 'if (false) return'],
  ['made-sends: a create that did not make the vault confirms it', S, "if (made) this.sql.exec('UPDATE made_sends SET confirmed = 1", "if (true) this.sql.exec('UPDATE made_sends SET confirmed = 1"],
  ['nonce: a lease does not move the row', S, 'row.next_nonce + 1, now, key);', 'row.next_nonce, now, key);'],
  ['nonce: a seed may move back', S, 'const nonce = Math.max(known, chain + 1);', 'const nonce = chain + 1;'],
  ['state: a day limit pruned after two hours', S, "this.sql.exec('DELETE FROM vault_counter WHERE window_start < ?', now - 2 * DAY);", "this.sql.exec('DELETE FROM vault_counter WHERE window_start < ?', now - 2 * HOUR);"],
  ['replay row: pruned at once', S, "this.sql.exec('DELETE FROM owner_sent WHERE at < ?', now - 2 * DAY);", "this.sql.exec('DELETE FROM owner_sent WHERE at < ?', now);"],

  // ---------------------------------------------------------------- test coins
  ['funds: no proof of work', F, 'if (!checkPow(fundsPowTarget(vault), body.pow, relay.powBits)) throw', 'if (false) throw'],
  ['funds: the creation\'s proof of work also pays a coin', F, 'checkPow(fundsPowTarget(vault), body.pow, relay.powBits)', 'checkPow(vault, body.pow, relay.powBits)'],
  ['funds: a vault this relay did not make reads as made', F, 'const made = await relay.madeRow(vault);', 'const made = (await relay.madeRow(vault)) ?? { confirmed: true };'],
  ['funds: a vault whose create did not make it', F, 'if (mine === false) throw', 'if (false) throw'],
  ['funds: a vault the chain cannot vouch for', F, 'if (mine === null) throw', 'if (false) throw'],
  ['funds: a vault holding a coin gets another', F, 'if (listed.length > 0) throw', 'if (false) throw'],
  ['funds: pays twice what it counts', F, '      value: sats,\n', '      value: sats * 2,\n'],
  ['funds: over the limit or ceiling still pays', F, 'if (!claim.ok) {', 'if (false) {'],
  ['funds: a vault already paid is paid again', F, 'if (claim.already) return', 'if (false) return'],
  ['funds: a send that may have landed gives its claim back', F, 'keep.keepClaim = true;', ''],
  ['funds: two asks at once both pay', S, 'if (row && now - row.at < CLAIM_MS) return', 'if (false) return'],
  ['funds: no limit or ceiling on coins', S, 'if (!out.ok) return out;', ''],
  ['funds: a coin is not leased', S, "this.markCoins(picked, 'reserved', now + LEASE_MS);", ''],
  ['funds: a spent coin comes back on refresh', S, "this.sql.exec(\"INSERT OR IGNORE INTO dispenser_utxos VALUES (?, ?, ?, 'free', NULL)\", c.txid", "this.sql.exec(\"INSERT OR REPLACE INTO dispenser_utxos VALUES (?, ?, ?, 'free', NULL)\", c.txid"],
  // The record is written later than its claim, so the at check alone refuses a drop by the claim's time. This one
  // is killed by a drop that names the record's own time, where only the txid check holds.
  ['funds: a drop forgets a paid vault, and gives back its coin\'s charge', S, 'SELECT at FROM funded_vaults WHERE vault = ? AND txid IS NULL', 'SELECT at FROM funded_vaults WHERE vault = ?'],
  ['funds: a late drop takes back a claim another call took over', S, 'if (!row || row.at !== at) return { ok: true, dropped: false };', 'if (!row) return { ok: true, dropped: false };'],
  ['funds: a drop that matches no standing claim gives back what it names', S, 'if (!row || row.at !== at) return { ok: true, dropped: false };', 'if (row && row.at !== at) return { ok: true, dropped: false };'],
  ['funds: a claim taken over gives back a charge it never made', S, 'let charged = 0;', 'let charged = sats;'],
  ['funds: a claim that moved nothing keeps its charge', S, '        charged = sats;\n', ''],
  ['funds: a drop gives its sats back to the next day\'s ceiling', S, 'charged, dayOf(at), FUNDS', 'charged, dayOf(at) + 1, FUNDS'],
  ['funds: a drop gives back what a coin costs, not what its claim charged', F, 'charged: claim.charged', 'charged: conf.sats'],
  ['funds: a drop names the time of the drop, not of its claim', F, 'at: claim.at', 'at: relay.nowFn()'],
  ['funds: a coin out whose record failed gives its claim back', F, 'paid.keepClaim = true;', ''],
  ['funds: a coin out whose inputs were not marked spent gives its claim back', F, "      try {\n        await relay.state.call('commitCoin', { coins, change });\n", "      await relay.state.call('commitCoin', { coins, change });\n      try {\n"],

  // ---------------------------------------------------------------- what the phone shows
  ['phone: a request of an old epoch is not cancelled', RS, "if (request.epoch !== vault.spend_epoch) return state('cancelled'", "if (false) return state('cancelled'"],
  ['phone: a lagging vault read says cancelled', RS, 'if (request.epoch > vault.spend_epoch) return', 'if (false) return'],
  ['phone: a signed request of an old epoch reads cancelled', RS, "if (request.status === 'Signed') return state('signed');", ''],
  ['phone: a signing request reads by its epoch', RS, "if (request.status === 'Signing') return state('signing');", ''],
  ['phone: an expired request reads unlocked', RS, "if (chainNow > request.expires_at) return state('expired');", ''],
  ['phone: a pruned signed request reads cancelled', RS, "if (lastKnown.status !== 'Pending') return state('signed', 'pruned');", ''],
  ['phone: no cancel at zero', RS, "cancellable: kind === 'waiting' || kind === 'unlocked',", "cancellable: kind === 'waiting',"],
  ['phone: expired sticks', RS, "const TERMINAL = new Set(['cancelled', 'signed']);", "const TERMINAL = new Set(['cancelled', 'signed', 'expired']);"],
  ['phone: cancelled holds against a signature', RS, "if (next.kind === 'signed' || next.kind === 'signing') return next;", ''],
  ['phone: a lagging read undoes cancelled', RS, 'if (!previous || !previous.terminal) return next;', 'return next;'],
  ['phone: a Cancel button on what cannot be cancelled', RS, 'if (!s.cancellable) return', 'if (false) return'],
  ['phone: a Cancel button with the owner key down', RS, 'if (!relay.owner.up) return', 'if (false) return'],
  ['signing: a self-spend\'s retries close', RS, " || request.tier === 'SelfSpend')", ')'],
  ['phone: a self-spend can take the screen from a drain', PE, 'const paysOut = (item) => (item.request.to === selfSpk ? 0 : 1);', 'const paysOut = () => 1;'],
  ['phone: the smallest request takes the screen', PE, 'realValue(b.request) - realValue(a.request)', 'realValue(a.request) - realValue(b.request)'],
  ['phone: an ended request takes the screen from a live one', PE, 'const focus = [...live].sort(biggest)[0] ?? [...ended].sort(latest)[0] ?? null;', 'const focus = [...seen].sort(latest)[0] ?? null;'],
  ['phone: a coin worth other than declared goes unflagged', PE, 'if (fact.value !== coin.value) differs = true;', ''],
  ['phone: any script matches the vault', BT, 'export const scriptMatchesVault = (script, vault) => equal(p2wshSpk(script), fromHex(vault.script_pubkey));', 'export const scriptMatchesVault = () => true;'],
  ['phone: the rotate digest leaves out the new key', IN, 'args: argBytes.cancel_all_and_rotate({ newKs })', 'args: argBytes.cancel_all_and_rotate({ newKs: new Uint8Array(32) })'],
  ['phone: the cancel digest leaves out the request', IN, 'args: argBytes.cancel({ request })', 'args: argBytes.cancel({ request: 0 })'],
  ['phone: a high-S signature is sent as it is', WA, 'return s > HALF_N ? concat(raw.slice(0, 32), bytes32(N - s)) : raw;', 'return raw;'],
  ['own cancel: not_this_relays reads as the cancel\'s fault', OC, "'not_this_relays', 'daily_ceiling', 'rate_limited', 'relay_down',", "'daily_ceiling', 'rate_limited', 'relay_down',"],

  // ---------------------------------------------------------------- what the thief tab sends, and when it stops
  ['thief: a bc1 address reads as another test network\'s', TL, "return refused.hrp === 'bc' ? 'not_test_address' : 'other_network';", "return 'other_network';"],
  ['thief: a malformed address is taken', TL, "  if (refused) return 'bad_address';\n", ''],
  ['thief: base58 or upper case taken', TL, "  if (!address.startsWith(prefix)) return 'not_test_address';\n", ''],
  ['thief: one network for every vault', TL, 'const refused = refusalOf(address, network);', "const refused = refusalOf(address, 'mutinynet');"],
  ['thief: a bitcoin: link reads as junk', TL, "if (refused?.code === 'uri') return 'uri';", ''],
  ['thief: a destination before the network is known', TL, "if (prefix === null || prefix === 'bc1') return 'no_network';", ''],
  ['thief: the other network goes unnamed', TL, "return `That is a ${refusalOf(text, network).networkName} address; this vault is on ${place}.`;", "return 'That address does not check out.';"],
  ['thief: a relay reason shown as its code', TL, "return `${relayWords({ code: status.general?.why }).replace(/\\.$/, '')}, so this tab", "return `${status.general?.why}, so this tab"],
  ['phone link: the destination on one network for all', PF, 'const to = spkToAddress(network, Uint8Array.of(0x00, 0x14, ...random20));', "const to = spkToAddress('mutinynet', Uint8Array.of(0x00, 0x14, ...random20));"],
  ['words: a contract refusal shown in its own words', PW, "return (name && Object.hasOwn(CONTRACT_WORDS, name) ? CONTRACT_WORDS[name] : null) ?? 'The NEAR contract refused it.';", 'return String(raw);'],
  ['words: a view\'s panic not read', PW, 'if (view) return view[1].trim();', ''],
  ['words: a relay code shown as itself', PW, "return (err?.code && Object.hasOwn(RELAY_WORDS, err.code) ? RELAY_WORDS[err.code] : null) ?? 'The relay said no.';", 'return err?.code ?? \'The relay said no.\';'],
  ['words: a relay refusal with the contract\'s words read as the relay\'s', PW, "if ((err?.code === 'would_refuse' || (err?.code === 'tx_refused' && panicOf(err.verbatim))) && err.verbatim) return contractWords(err.verbatim);", ''],
  ['words: a node\'s script refusal unnamed', PW, "if (kind === 'script') return 'It needs a second signature.';", ''],
  ['words: a proxy\'s page read as a busy node', PW, "if (status === 400 && !/<html/i.test(answer.body ?? '')) return", 'if (status >= 400) return'],
  ['words: an answer from no node shows its HTTP status', PW, "return Object.hasOwn(NOT_A_NODE, status) ? NOT_A_NODE[status] : 'Something on the way to the node answered instead of it.';", 'return `Something on the way answered HTTP ${status}, not a node.`;'],
  ['words: raw words logged twice in a row', PW, '  if (line === lastLogged) return;\n', ''],
  ['footer: a full-access key on the contract account is not read as one', PW, "if (permission === 'FullAccess') return 'present';", ''],
  ['footer: no key list reads as no key', PW, "if (!Array.isArray(keys)) return 'unknown';", "if (!Array.isArray(keys)) return 'none';"],
  ['footer: a key the page cannot read counts as harmless', PW, "if (permission === null || typeof permission !== 'object' || !Object.hasOwn(permission, 'FunctionCall')) state = 'unknown';", ''],
  ['thief: a seed with junk around it is taken', TL, '/^[0-9a-f]{64}$/.test(hex)', '/[0-9a-f]{64}/.test(hex)'],
  ['thief: resends on any refusal that starts with Not', TL, "failure.includes('NotUnlocked')", "failure.includes('Not')"],
  ['thief: a signing request is not live', TL, " || state?.kind === 'signing'", ''],
  ['thief: the oldest request first', TL, '.sort((a, b) => b - a)', '.sort((a, b) => a - b)'],
  ['thief: one more send after it left signing', TL, '    const after = signingStop(read());\n    if (after) return after;', '    signingStop(read());'],
  ['thief: keeps sending after it left signing', TL, "if (!signing) return 'left_signing';", ''],
  ['thief: keeps sending after the retry window', TL, "return closesAt !== null && chainNow >= closesAt ? 'retry_closed' : null;", 'return null;'],
  ['thief: Send everything pays no fee', BT, 'const amount = total - fee;', 'const amount = total;'],

  // ---------------------------------------------------------------- links: what a fragment may say
  ['link: fields taken unchecked', FR, "if (fits(name, value)) out[name] = name === 'r' ? Number(value) : value;\n    else refused.push(name);", "out[name] = name === 'r' ? Number(value) : value;"],
  ['link: a short vault id is taken', FR, 'v: /^[0-9a-f]{64}$/,          // vault id', 'v: /^[0-9a-f]{1,64}$/,          // vault id'],
  ['link: a request id with a leading zero is taken', FR, 'r: /^(0|[1-9][0-9]{0,15})$/,', 'r: /^[0-9]{1,20}$/,'],
  ['link: a request id past 2^53 is taken', FR, " && (name !== 'r' || Number.isSafeInteger(Number(text)))", ''],
  ['link: a destination of any characters', FR, 'to: /^[a-z0-9]{14,90}$/,', 'to: /^.{14,90}$/,'],
  ['link: the seed stays in the address bar', FR, 'delete fields.k;', ''],
  ['phone link: its own fields taken unchecked', PF, 'if (EXTRA[name].test(value)) out[name] = value;\n    else out.refused.push(name);', 'out[name] = value;'],
  ['operator check: a short nonce is taken', PF, 'opproof: /^[0-9a-f]{64}$/,', 'opproof: /^[0-9a-f]{1,64}$/,'],
  ['phone: stored test-mode fields read unchecked', PF, "if (typeof raw?.[name] === 'string' && rule.test(raw[name])) out[name] = raw[name];", "if (typeof raw?.[name] === 'string') out[name] = raw[name];"],
  ['phone: a stored credential id read unchecked', PF, 'return value && CREDENTIAL_ID.test(value) ? value : null;', 'return value || null;'],

  // ---------------------------------------------------------------- the phone page on a phone that does not behave
  ['sense: a phone whose browser reports no platform authenticator loses Make and Cancel', SE, "  if (blocked) return 'webauthn_blocked';\n  return null;", "  if (blocked) return 'webauthn_blocked';\n  if (sense.platform === false && sense.mobile) return 'no_platform_authenticator';\n  return null;"],
  ['sense: a laptop gets the phone\'s hint', SE, 'export const platformHint = (sense) => (sense.platform === false && sense.mobile', 'export const platformHint = (sense) => (sense.platform === false'],
  ['sense: iOS 17 is told a menu path it does not have', SE, 'if (device && major !== null && major >= 18) return', 'if (device && major !== null) return'],
  ['sense: Safari on iOS 26, which says 18, is read as before 18', SE, 'if (device && major !== null && major >= 18) return', 'if (device && major !== null && major >= 19) return'],
  ['sense: an Android phone is told the iPhone\'s steps', SE, "  if (/\\bAndroid\\b/.test(ua)) return 'set a screen lock on this phone';\n", ''],
  ['sense: a browser that will not say gets the hint', SE, 'export const platformHint = (sense) => (sense.platform === false && sense.mobile', 'export const platformHint = (sense) => (!sense.platform && sense.mobile'],
  ['sense: a browser of its own is told to open a browser', SE, 'export const hangWords = (sense, again) => (sense.inApp', 'export const hangWords = (sense, again) => (true'],
  ['passkey: the page\'s signal is dropped on the way to the browser', WA, 'const withSignal = (signal) => (signal ? { signal } : {});', 'const withSignal = () => ({});'],
  ['passkey: only the Level 2 word for a discoverable credential', WA, "residentKey: 'required', requireResidentKey: true,", "residentKey: 'required',"],
  ['passkey: an assertion is asked for with no signal', PA, 'timeoutMs: 60_000, signal }), { onHang, signal })', 'timeoutMs: 60_000 }), { onHang, signal })'],
  ['passkey: a new passkey is asked for with no signal', PA, 'rpId: ctx.config.rpId, label, signal }), { onHang, signal })', 'rpId: ctx.config.rpId, label }), { onHang, signal })'],
  ['words: the hourly limit read in seconds', PW, 'if (s < 120) return `${s} s`;', 'if (s < 120_000) return `${s} s`;'],
  ['words: a day\'s wait read in minutes', PW, 'if (s < 7200) return `about ${Math.ceil(s / 60)} minutes`;', 'if (s < Infinity) return `about ${Math.ceil(s / 60)} minutes`;'],
  ['words: a wait rounded down to nothing', PW, 'const s = Math.max(1, Math.ceil(Number(seconds) || 0));', 'const s = Math.floor(Number(seconds) || 0);'],
  ['words: a reset time from no time', PW, "export const resetWords = (at) => (Number.isFinite(at) && at > 0 ?", 'export const resetWords = (at) => (true ?'],
  ['make: time asleep counts against the wait for the vault', VM, 'awake += Math.min(Math.max(0, at - last), STEP_COUNTS_MS);', 'awake += Math.max(0, at - last);'],
  ['make: the wait for the vault never gives up', VM, 'if (awake > ACTIVE_WAIT_MS) throw', 'if (false) throw'],
  ['make: giving up forgets the creation was sent', VM, "new Error('the contract has not read this vault active yet'), { sentHash: hash });", "new Error('the contract has not read this vault active yet'), {});"],
  ['make: activate goes to a vault no node knows', VM, 'if (vault && !activated && awake > ACTIVE_WAIT_MS / 2) {', 'if (!activated && awake > ACTIVE_WAIT_MS / 2) {'],
  ['make: no line while the proof of work runs', VM, "  onLine('working');\n", ''],
  ['phone: a stuck Cancel is asked again without ending the call that is out', PH, '  P.tap = null;\n  old.abort.abort();\n  onCancelTap(old.own);', '  P.tap = null;\n  onCancelTap(old.own);'],
  ['phone: the button comes back before the page has said no sheet came', PH, 'const again = !P.hang ? null : P.tap?.own', 'const again = P.tap?.own'],
  ['phone: a call the page gave up on, answering late, is sent', PH, '    if (P.tap !== tap) return;\n    assertion = got.assertion;', '    assertion = got.assertion;'],
  ['phone: one instant refusal leaves the next request with no Cancel', PH, 'function passkeyAnswered() {\n  P.passkeyOk = true;\n  P.blocked = false;', 'function passkeyAnswered() {\n  P.passkeyOk = true;'],
  ['phone: an instant refusal drops the credential id this browser has used', PH, 'if (!P.credential || P.credentialTrusted) return false;', 'if (!P.credential) return false;'],
  ['phone: the line about a sheet that has not shown stays beside "Passkey made."', PH, "  P.hangMaking = null;\n  passkeyAnswered();\n  lines.push('Passkey made.');", "  passkeyAnswered();\n  lines.push('Passkey made.');"],
  ['phone: a closed second sheet starts the vault over', PH, "if (err instanceof PasskeyFailed && (err.kind === 'dismissed' || err.kind === 'blocked')) {\n      if (err.kind === 'blocked') logRaw", "if (false) {\n      if (err.kind === 'blocked') logRaw"],
  ['phone: a vault that was sent reads as nothing made', PH, 'if (err?.sentHash) drawSent(prepared, said, err.sentHash);\n    else makeFailed', 'if (false) drawSent(prepared, said, err.sentHash);\n    else makeFailed'],
  ['phone: a send with no answer reads as no vault made', PH, "if (err instanceof RelayRefused && !relaySentNothing(err.code)) {\n    drawNoVault(", "if (false) {\n    drawNoVault("],
  ['phone: with no vault the relay is read once', PH, '  P.relayTimer = setTimeout(() => readRelayAgain(true), wait);\n', ''],
  ['phone: with no vault a relay that is out is asked every 5 s for good', PH, 'const RELAY_AGAIN_MS = [5000, 10_000, 20_000, 60_000];', 'const RELAY_AGAIN_MS = [5000];'],
  ['phone: coming back, a connection back and a restored page each ask, with no gap between them', PH, '  if (!timed && Date.now() - P.statusAt < RELAY_AGAIN_GAP_MS) return;\n', ''],
  ['phone: a hidden tab keeps asking the relay', PH, 'if (!relayHoldsMake() || P.relayReading || document.hidden) return;', 'if (!relayHoldsMake() || P.relayReading) return;'],
  ['phone: a relay at its daily limit is asked every minute until it resets', PH, 'if (Number.isFinite(resets) && resets > Date.now()) wait =', 'if (false) wait ='],
  ['phone: a relay out of reach reads as down', PH, "  if (!P.relay.reachable) return unreadStatusWords(P.relay);\n", ''],
  ['words: a proxy\'s page for the relay reads as out of reach', PW, '  if (!status?.answered) return', '  if (!status?.answered || !status.code) return'],
  ['words: the relay\'s own no reads as some other page', PW, "  if (!status.code) return 'Something answered", "  if (true) return 'Something answered"],
  ['words: a relay status with no answer reads as an answer', PW, "  if (!status?.answered) return 'Can\\'t reach the relay';\n", ''],
  ['phone: the request screen says a relay it got no answer from is down', PH, "  if (why === 'relay_down') return P.relay.reachable ? NO_BUTTON_WORDS.relay_owner_down : relayDownWords(P.relay);\n", ''],
  ['phone: a relay that answered relay_down reads as one that did not answer', PH, "return P.relay.reachable ? NO_BUTTON_WORDS.relay_owner_down : relayDownWords(P.relay);", 'return relayDownWords(P.relay);'],
  ['phone: a relay that answered with its cancel side down reads as down', PH, "  relay_owner_down: 'The relay says it can\\'t send a cancel right now, so this page can\\'t send one.',", "  relay_owner_down: 'The relay is down, so this page can\\'t send a cancel.',"],
  ['phone: a cancel the relay did not answer reads as a status read', PH, "  if (relay.cancelUnanswered) return 'The relay did not answer", "  if (false) return 'The relay did not answer"],
  ['phone: a cancel the relay did not answer reads as one it did not send', PH, 'P.signed = { ...signed, unsure: unanswered || erred };', 'P.signed = { ...signed, unsure: false };'],
  ['own cancel: a send with no answer reads as not sent', OC, '    unsure\n      ? `If the relay', '    false\n      ? `If the relay'],
  ['thief: a relay it got no answer from reads as down', TL, 'if (!status.reachable) return `${unreadRelayWords(status)}, so this tab may', 'if (!status.reachable) return `The relay is down, so this tab may'],
  ['relay client: an answer that is not JSON reads as no answer', RC, '{ answered: res !== undefined }', '{ answered: false }'],
  ['relay client: the relay\'s own no loses its code', RC, "code: typeof data?.code === 'string' ? data.code : null }", 'code: null }'],
  ['phone: a test coin is offered to a vault whose spend key is gone', PH, 'const keyGone = !P.seed && P.credentialTrusted;', 'const keyGone = false;'],
  ['phone: the dispenser at its limit says nothing', PH, "      else out.push(h('p', { class: 'line', id: 'no-funds' }", "      else if (false) out.push(h('p', { class: 'line', id: 'no-funds' }"],
  ['phone: a coin refused for the hour says only to wait', PH, "if (err.code === 'rate_limited' && err.retryAfterS > 120) return `This network address has used its test coin tries", "if (false) return `This network address has used its test coin tries"],
  ['phone: the idle screen lets the phone holding the spend key go dark', PH, " || (id === 'idle' && P.seed && Date.now() < P.idleAwakeUntil));", ');'],
  ['phone: the idle screen keeps the phone awake for as long as it is left there', PH, " && Date.now() < P.idleAwakeUntil));", '));'],
  ['phone: a touch on the idle screen does not keep it awake longer', PH, "      P.idleAwakeUntil = Date.now() + IDLE_AWAKE_MS;\n      keepAwake('idle');", "      keepAwake('idle');"],
  ['sense: the wake lock is asked for twice while the first ask is out', SE, 'if (!out.wanted || !nav?.wakeLock || out.lock || out.asking) return;', 'if (!out.wanted || !nav?.wakeLock || out.lock) return;'],
  ['phone: a request that ends leaves its stuck passkey call out', PH, '  if (P.tap && !P.tap.answered) P.tap.abort.abort();\n  P.tap = null;\n  P.hang = false;', '  P.tap = null;\n  P.hang = false;'],
  ['phone: a request that ends leaves the line about its sheet for the next one', PH, '  if (P.tap && !P.tap.answered) P.tap.abort.abort();\n  P.tap = null;\n  P.hang = false;', '  if (P.tap && !P.tap.answered) P.tap.abort.abort();\n  P.tap = null;'],
  ['phone: the hint stays beside the line about a sheet that has not shown', PH, 'const hint = aside ? null : hintNow();', 'const hint = hintNow();'],
  ['phone: the in-app line stays beside the line about a sheet that has not shown', PH, 'const elsewhere = aside || (P.notice?.inAppAside === true && hint) ? null : openElsewhere(ctx.sense);', 'const elsewhere = openElsewhere(ctx.sense);'],
  ['phone: the hint steps aside after a refused passkey', PH, 'const aside = P.hang;', 'const aside = P.hang || P.notice !== null;'],
  ['sense: a wake lock granted after the page stopped wanting it is kept', SE, '      if (out.wanted) out.lock = lock;\n      else lock.release?.().catch?.(() => {});', '      out.lock = lock;'],
  ['phone: the idle screen\'s wake lock is wanted on any screen', PH, "(id === 'idle' && P.seed && Date.now() < P.idleAwakeUntil)", '(P.seed && Date.now() < P.idleAwakeUntil)'],
  ['phone: a Make call the page gave up on draws its passkey', PH, '  // A call this page gave up on, answering late: a newer tap is making the vault.\n  if (P.making !== call) return;\n', ''],
  ['phone: a Confirm call the page gave up on sends the vault', PH, '  call.answered = true;\n  if (P.making !== call) return;\n  P.hangMaking = null;\n  passkeyAnswered();\n  const said', '  call.answered = true;\n  P.hangMaking = null;\n  passkeyAnswered();\n  const said'],
  ['phone: a Confirm call the tap ended reads as a closed sheet', PH, '    call.answered = true;\n    if (P.making !== call) return;\n    P.hangMaking = null;\n    // The passkey from the first tap', '    call.answered = true;\n    P.hangMaking = null;\n    // The passkey from the first tap'],
  ['phone: the line about a sheet that has not shown stays beside "Signed."', PH, '  if (P.making !== call) return;\n  P.hangMaking = null;\n  passkeyAnswered();\n  const said', '  if (P.making !== call) return;\n  passkeyAnswered();\n  const said'],
  ['phone: the hint stays after a passkey call answered here', PH, 'const hintNow = () => (P.passkeyOk || P.credentialTrusted ? null : platformHint(ctx.sense));', 'const hintNow = () => platformHint(ctx.sense);'],
  ['phone: the browser is asked about its passkeys once', PH, '    if (document.hidden) return;\n    senseAgain();\n', '    if (document.hidden) return;\n'],
  ['phone: inside an app the warning comes after the headline', PH, "    elsewhere ? h('p', { class: 'notice warn', id: 'in-app' }, elsewhere) : null,\n    h('p', { class: 'say big' }, 'A cancel button for test Bitcoin.'),", "    h('p', { class: 'say big' }, 'A cancel button for test Bitcoin.'),\n    elsewhere ? h('p', { class: 'notice warn', id: 'in-app' }, elsewhere) : null,"],

  // ---------------------------------------------------------------- the test mode's report
  ['h7: the creation tap\'s S form swapped', HR, "proofS === 'h' ? 'high-S' : 'low-S'", "proofS === 'h' ? 'low-S' : 'high-S'"],
  ['h7: each try\'s S form swapped', HR, "${t.s === 'h' ? 'high-S' : 'low-S'}", "${t.s === 'h' ? 'low-S' : 'high-S'}"],
  ['h7: no high-S claimed after one try', HR, 'if (tries.length >= 8) return', 'if (tries.length >= 1) return'],
  ['h7: the call names swapped', HR, "const call = t.m === 'r' ? 'cancel_all_and_rotate' : 'cancel';", "const call = t.m === 'r' ? 'cancel' : 'cancel_all_and_rotate';"],
  ['h7: the report leaves out the S-form sentence', HR, '  lines.push(sFormSentence(tries));\n', ''],
].map(([name, file, from, to, chrome = null]) => ({ name, file, from, to, chrome }));

// ---------------------------------------------------------------- which tests

const SITE_TEST = 'site/test';
const STAGE = ['relay.workerd.test.mjs', 'sandbox.test.mjs', 'made-row.test.mjs', 'stage-made.test.mjs'].map((f) => `${SITE_TEST}/${f}`);
// Each times its reads against a fetch that answers after a delay, so a busy machine can fail it. phone-flow.test.mjs
// also waits out the page's own timers in child processes, a few at a time.
const TIMED = [`${SITE_TEST}/phone-boot.test.mjs`, `${SITE_TEST}/phone-flow.test.mjs`];
const FAST = readdirSync(join(REPO, SITE_TEST)).filter((f) => f.endsWith('.test.mjs')).map((f) => `${SITE_TEST}/${f}`).filter((f) => !STAGE.includes(f)).sort();
const NEAREST = [
  ['site/functions/_relay/', ['relay.test.mjs']],
  ['worker/undo-cron/', ['relay.test.mjs']],
  [T, ['relay.test.mjs', 'lib.test.mjs']],
  [RS, ['lib.test.mjs']],
  [PE, ['lib.test.mjs']],
  [FR, ['lib.test.mjs', 'thief-link.test.mjs']],
  [BT, ['step.test.mjs', 'lib.test.mjs']],
  [IN, ['step.test.mjs']],
  [WA, ['webauthn.test.mjs']],
  [TL, ['thief.test.mjs', 'thief-link.test.mjs', 'plain-words.test.mjs']],
  [PW, ['plain-words.test.mjs']],
  [PF, ['h7-link.test.mjs', 'thief-link.test.mjs']],
  [OC, ['phone-unit.test.mjs']],
  [HR, ['h7-link.test.mjs']],
  [SE, ['phone-unit.test.mjs']],
  [VM, ['vault-make.test.mjs']],
  [PA, ['phone-flow.test.mjs']],
  [PH, ['phone-unit.test.mjs', 'phone-flow.test.mjs']],
  [RC, ['lib.test.mjs', 'phone-flow.test.mjs']],
];

/** The tiers a mutant of `file` goes through, nearest tests first. */
export function tiersFor(file, { stage = true } = {}) {
  const nearest = (NEAREST.find(([prefix]) => file.startsWith(prefix))?.[1] ?? []).map((f) => `${SITE_TEST}/${f}`);
  const tiers = [];
  if (nearest.length) tiers.push({ name: 'nearest', files: nearest, kind: 'fast' });
  tiers.push({ name: 'site', files: FAST.filter((f) => !nearest.includes(f)), kind: 'fast' });
  if (stage) tiers.push({ name: 'stage', files: STAGE, kind: 'stage' });
  return tiers;
}

// ---------------------------------------------------------------- reading a run

const lastCount = (stdout, label) => {
  const all = [...String(stdout ?? '').matchAll(new RegExp(`^# ${label} (\\d+)$`, 'gm'))];
  return all.length ? Number(all[all.length - 1][1]) : null;
};

/** Every `not ok` in a TAP run: its name, failureType, file, and whether it is a whole file that exited on its own. */
export function failures(stdout) {
  const lines = String(stdout ?? '').split('\n');
  const out = [];
  lines.forEach((line, i) => {
    const m = /^(\s*)not ok \d+ - (.*)$/.exec(line);
    if (!m) return;
    const indent = `${m[1]}  `;
    const fields = {};
    for (let j = i + 1; j < lines.length && lines[j].startsWith(indent) && !/^\s*(not )?ok \d+ /.test(lines[j]); j += 1) {
      const f = /^\s*(failureType|location|exitCode): (.*)$/.exec(lines[j]);
      if (f && !(f[1] in fields)) fields[f[1]] = f[2].replace(/^'|'$/g, '');
    }
    out.push({
      name: m[2].replace(/ # (SKIP|TODO).*$/, ''),
      type: fields.failureType ?? null,
      file: fields.location ? fields.location.replace(/:\d+:\d+$/, '') : null,
      wholeFile: 'exitCode' in fields,
    });
  });
  return out;
}

/**
 * The verdict on one run: killed, SURVIVED or NOT JUDGED. Killed only when a test's own body failed. `allRun` is for
 * the stage tier: a run where any test skipped did not test what it says.
 */
export function judge(run, { allRun = false } = {}) {
  if (run.error || run.status === null || run.status === undefined) return { verdict: 'NOT JUDGED', why: `the run did not finish: ${run.error ?? 'killed'}` };
  const pass = lastCount(run.stdout, 'pass');
  const skipped = lastCount(run.stdout, 'skipped') ?? 0;
  if (run.status === 0) {
    if (!(pass > 0)) return { verdict: 'NOT JUDGED', why: 'no test ran' };
    if (allRun && skipped > 0) return { verdict: 'NOT JUDGED', why: `${skipped} tests skipped` };
    return { verdict: 'SURVIVED', why: null };
  }
  const failed = failures(run.stdout);
  const own = failed.filter((f) => f.type === 'testCodeFailure' && !f.wholeFile);
  if (own.length) return { verdict: 'killed', why: null, by: own };
  const kinds = [...new Set(failed.map((f) => (f.wholeFile ? 'a file exited' : f.type)))].join(', ') || 'nothing';
  return { verdict: 'NOT JUDGED', why: `the run failed, but no test failed on its own: ${kinds}` };
}

/** What a mutant reads as once every tier has passed. */
export function afterAllTiers(mutant, { stage }) {
  if (!stage) return { verdict: 'NOT JUDGED', why: 'it passed every tier that ran, and the stage tests were left out' };
  if (mutant.chrome) return { verdict: 'NOT JUDGED', why: `only a Chrome test checks this: ${mutant.chrome}` };
  return { verdict: 'SURVIVED', why: null };
}

/** Whether a kill must be seen twice: it rests only on the stage tests, or only on the timed test. */
export function needsSecondLook(tier, by) {
  if (tier.kind === 'stage') return { again: true, pristine: false };
  const timedOnly = by.length > 0 && by.every((f) => TIMED.some((t) => f.file?.endsWith(t)));
  return { again: timedOnly, pristine: timedOnly };
}

function selfTest() {
  const tap = (body, summary) => `TAP version 13\n${body}\n1..1\n# tests 3\n${summary}\n`;
  const assertFail = "not ok 2 - refuses a cancel\n  ---\n  duration_ms: 0.5\n  type: 'test'\n  location: '/r/site/test/relay.test.mjs:4:1'\n  failureType: 'testCodeFailure'\n  error: |-\n    1 !== 2\n  code: 'ERR_ASSERTION'\n  ...";
  const hookFail = "not ok 1 - t1\n  ---\n  location: '/r/site/test/relay.workerd.test.mjs:3:1'\n  failureType: 'hookFailed'\n  error: 'stage did not start'\n  ...";
  const fileExit = "not ok 1 - relay.test.mjs\n  ---\n  location: '/r/site/test/relay.test.mjs:1:1'\n  failureType: 'testCodeFailure'\n  exitCode: 1\n  signal: ~\n  error: 'test failed'\n  ...";
  const timeout = "not ok 1 - slow\n  ---\n  location: '/r/site/test/sandbox.test.mjs:2:1'\n  failureType: 'testTimeoutFailure'\n  error: 'test timed out after 100ms'\n  ...";
  const cancelled = "not ok 1 - inner\n  ---\n  failureType: 'cancelledByParent'\n  ...";
  const nested = "# Subtest: suite\n    not ok 1 - inner\n      ---\n      location: '/r/site/test/thief.test.mjs:9:3'\n      failureType: 'testCodeFailure'\n      ...\nnot ok 1 - suite\n  ---\n  failureType: 'subtestsFailed'\n  ...";
  const timed = "not ok 1 - phone boot\n  ---\n  location: '/r/site/test/phone-boot.test.mjs:9:1'\n  failureType: 'testCodeFailure'\n  ...";
  const cases = [
    ['a green run', judge({ status: 0, stdout: tap('ok 1 - a', '# pass 3\n# fail 0\n# skipped 0') }).verdict, 'SURVIVED'],
    ['a green run with nothing in it', judge({ status: 0, stdout: tap('', '# pass 0\n# fail 0\n# skipped 3') }).verdict, 'NOT JUDGED'],
    ['a stage run that skipped', judge({ status: 0, stdout: tap('', '# pass 2\n# fail 0\n# skipped 1') }, { allRun: true }).verdict, 'NOT JUDGED'],
    ['a site run that skipped Chrome tests', judge({ status: 0, stdout: tap('', '# pass 2\n# fail 0\n# skipped 1') }).verdict, 'SURVIVED'],
    ['an assertion failed', judge({ status: 1, stdout: tap(assertFail, '# pass 2\n# fail 1') }).verdict, 'killed'],
    ['a test in a suite failed', judge({ status: 1, stdout: tap(nested, '# pass 0\n# fail 1') }).verdict, 'killed'],
    ['a stage that did not start', judge({ status: 1, stdout: tap(hookFail, '# pass 0\n# fail 2') }).verdict, 'NOT JUDGED'],
    ['a file that crashed before its tests', judge({ status: 1, stdout: tap(fileExit, '# pass 0\n# fail 1') }).verdict, 'NOT JUDGED'],
    ['a file that ran out of memory', judge({ status: 1, stdout: tap(fileExit.replace("exitCode: 1\n  signal: ~", "exitCode: ~\n  signal: 'SIGABRT'"), '# pass 0\n# fail 1') }).verdict, 'NOT JUDGED'],
    ['a test that timed out', judge({ status: 1, stdout: tap(timeout, '# pass 0\n# fail 1') }).verdict, 'NOT JUDGED'],
    ['a cancelled test', judge({ status: 1, stdout: tap(cancelled, '# pass 0\n# fail 0\n# cancelled 1') }).verdict, 'NOT JUDGED'],
    ['a red run with no failing test', judge({ status: 1, stdout: tap('', '# pass 3\n# fail 0') }).verdict, 'NOT JUDGED'],
    ['a run killed at its time limit', judge({ status: null, stdout: tap(assertFail, '# fail 1'), error: 'ETIMEDOUT' }).verdict, 'NOT JUDGED'],
    ['a run that could not start', judge({ status: null, stdout: '', error: 'ENOENT' }).verdict, 'NOT JUDGED'],
    ['the failing test is named', judge({ status: 1, stdout: tap(assertFail, '# fail 1') }).by?.[0]?.name, 'refuses a cancel'],
    ['the failing file is read', judge({ status: 1, stdout: tap(nested, '# fail 1') }).by?.[0]?.file, '/r/site/test/thief.test.mjs'],
    ['a kill only phone-boot saw is looked at twice, on the unbroken copy too', JSON.stringify(needsSecondLook({ kind: 'fast' }, judge({ status: 1, stdout: tap(timed, '# fail 1') }).by)), '{"again":true,"pristine":true}'],
    ['a kill relay.test.mjs saw stands', JSON.stringify(needsSecondLook({ kind: 'fast' }, judge({ status: 1, stdout: tap(assertFail, '# fail 1') }).by)), '{"again":false,"pristine":false}'],
    ['a stage kill is looked at twice', needsSecondLook({ kind: 'stage' }, []).again, true],
    ['every tier passed, stage left out', afterAllTiers({ chrome: null }, { stage: false }).verdict, 'NOT JUDGED'],
    ['every tier passed, only Chrome checks it', afterAllTiers({ chrome: 'x' }, { stage: true }).verdict, 'NOT JUDGED'],
    ['every tier passed', afterAllTiers({ chrome: null }, { stage: true }).verdict, 'SURVIVED'],
    ['the relay\'s mutants start at relay.test.mjs', tiersFor(H)[0].files.join(), `${SITE_TEST}/relay.test.mjs`],
    ['the site tier has no stage test', tiersFor(H)[1].files.some((f) => STAGE.includes(f)), false],
    ['a file with no nearest tests starts at the site tier, and the stage tier is last', tiersFor('site/lib/clock.mjs').map((t) => t.name).join(), 'site,stage'],
  ];
  const wrong = cases.filter(([, got, want]) => got !== want);
  for (const [name, got, want] of wrong) console.log(`WRONG ${name}: ${got}, not ${want}`);
  console.log(`self-test: ${cases.length - wrong.length} of ${cases.length}`);
  return wrong.length ? 1 : 0;
}

function check() {
  let wrong = 0;
  const names = new Set();
  for (const m of MUTANTS) {
    const count = readFileSync(join(REPO, m.file), 'utf8').split(m.from).length - 1;
    if (count !== 1) {
      wrong += 1;
      console.log(`NOT APPLIED ${m.name}: found ${count} times in ${m.file}`);
    }
    if (names.has(m.name)) {
      wrong += 1;
      console.log(`NAME TWICE ${m.name}`);
    }
    names.add(m.name);
  }
  console.log(`${MUTANTS.length - wrong} of ${MUTANTS.length} mutants apply`);
  return wrong ? 1 : 0;
}

// ---------------------------------------------------------------- running

const live = new Set();
const killGroup = (pid, signal) => {
  try {
    process.kill(-pid, signal);
  } catch {
    // Gone already.
  }
};
const stopAll = () => {
  for (const pid of live) killGroup(pid, 'SIGKILL');
};

class Slots {
  constructor(n) {
    Object.assign(this, { n, waiting: [] });
  }

  async take() {
    if (this.n > 0) {
      this.n -= 1;
      return;
    }
    await new Promise((r) => this.waiting.push(r));
  }

  give() {
    const next = this.waiting.shift();
    if (next) next();
    else this.n += 1;
  }
}

const NODE_RUNS = new Slots(4);
const STAGE_RUNS = new Slots(3);
// The site tier takes under a minute. A loop a mutant makes endless is stopped by its test's own cap (thief.test.mjs
// caps resendWhileSigning's waits), so the limit only bounds a run that hangs, and leaves room for a busy machine.
const TIME_LIMIT = { fast: 600_000, stage: 1_500_000 };

/** One `node --test` in its own process group, so a time limit stops the sandbox, bitcoind and workerd it started too. */
async function runTests(copy, files, kind, env) {
  if (kind === 'stage') await STAGE_RUNS.take();
  await NODE_RUNS.take();
  try {
    return await new Promise((done) => {
      let stdout = '';
      let stderr = '';
      let error = null;
      const child = spawn(process.execPath, ['--test', '--test-concurrency=1', '--test-reporter=tap', ...files.map((f) => join(copy, f))], {
        cwd: join(copy, 'site'), env, detached: true, stdio: ['ignore', 'pipe', 'pipe'],
      });
      live.add(child.pid);
      child.stdout.on('data', (d) => { stdout += d; });
      child.stderr.on('data', (d) => { stderr += d; });
      const timer = setTimeout(() => {
        error = 'ETIMEDOUT';
        killGroup(child.pid, 'SIGTERM');
        setTimeout(() => killGroup(child.pid, 'SIGKILL'), 10_000).unref();
      }, TIME_LIMIT[kind]);
      child.on('error', (err) => { error = err.code ?? err.name; });
      child.on('close', (status) => {
        clearTimeout(timer);
        live.delete(child.pid);
        // Whatever the files left running in the group goes with them.
        killGroup(child.pid, 'SIGKILL');
        done({ status: error ? null : status, stdout, stderr, error });
      });
    });
  } finally {
    NODE_RUNS.give();
    if (kind === 'stage') STAGE_RUNS.give();
  }
}

function trackedFiles() {
  const out = spawnSync('git', ['-C', REPO, 'ls-files', '-z'], { encoding: 'utf8' });
  if (out.status !== 0) throw new Error('git ls-files failed: this harness copies the files git tracks');
  return out.stdout.split('\0').filter(Boolean);
}

/** The tracked files only: no build output, no node_modules, nothing a test left behind. */
function makeTemplate(dir) {
  for (const file of trackedFiles()) {
    const from = join(REPO, file);
    const to = join(dir, file);
    mkdirSync(dirname(to), { recursive: true });
    copyFileSync(from, to);
    chmodSync(to, statSync(from).mode & 0o777);
  }
}

function freshCopy(template, dir) {
  rmSync(dir, { recursive: true, force: true });
  cpSync(template, dir, { recursive: true });
  return dir;
}

function envFor(kind, tmp, stageVars) {
  const env = { ...process.env, TMPDIR: tmp, CHROME_BIN: '/nonexistent-chrome-undo-mutants' };
  // On this kind of Mac a Node that used fetch can hang at exit reading the keychain with this set.
  delete env.NODE_USE_SYSTEM_CA;
  if (kind === 'stage') return { ...env, ...stageVars };
  for (const name of ['NEAR_SANDBOX_BIN_PATH', 'UNDO_WASM_DIR', 'UNDO_WRANGLER_MODULES']) delete env[name];
  return env;
}

function stageVariables() {
  const wasmDir = process.env.UNDO_WASM_DIR || join(process.env.CARGO_TARGET_DIR || join(REPO, 'target'), 'near');
  const bitcoin = process.env.UNDO_BITCOIN_BIN || join(REPO, 'crates/undo-btc/.tools/bitcoin-32.1/bin');
  const missing = [];
  if (!process.env.NEAR_SANDBOX_BIN_PATH) missing.push('NEAR_SANDBOX_BIN_PATH');
  if (!process.env.UNDO_WRANGLER_MODULES) missing.push('UNDO_WRANGLER_MODULES');
  for (const f of ['undo_vault.wasm', 'mock_signer.wasm']) if (!existsSync(join(wasmDir, f))) missing.push(`${f} in UNDO_WASM_DIR`);
  if (!existsSync(join(bitcoin, 'bitcoind'))) missing.push('bitcoind in UNDO_BITCOIN_BIN');
  return { missing, vars: { UNDO_WASM_DIR: wasmDir, UNDO_BITCOIN_BIN: bitcoin } };
}

const short = (by) => by.slice(0, 2).map((f) => `${f.file ? relative(REPO, f.file).replace(/^.*?site\/test\//, '') : '?'}: ${f.name.slice(0, 90)}`).join('; ');
const tail = (run) => `${run.stdout ?? ''}\n${run.stderr ?? ''}`.trim().split('\n').slice(-6).join('\n    ');

async function judgeMutant(m, { template, dir, stage, stageVars }) {
  const copy = freshCopy(template, join(dir, 'repo'));
  const tmp = join(dir, 'tmp');
  rmSync(tmp, { recursive: true, force: true });
  mkdirSync(tmp, { recursive: true });
  const path = join(copy, m.file);
  const text = readFileSync(path, 'utf8');
  if (text.split(m.from).length - 1 !== 1) return { verdict: 'NOT APPLIED', why: `found ${text.split(m.from).length - 1} times` };
  writeFileSync(path, text.replace(m.from, () => m.to));
  const parse = spawnSync(process.execPath, ['--check', path], { encoding: 'utf8' });
  if (parse.status !== 0) return { verdict: 'NOT APPLIED', why: `does not parse: ${parse.stderr.split('\n').find((l) => /Error/.test(l)) ?? ''}` };
  for (const tier of tiersFor(m.file, { stage })) {
    const run = () => runTests(copy, tier.files, tier.kind, envFor(tier.kind, tmp, stageVars));
    let out = await run();
    let v = judge(out, { allRun: tier.kind === 'stage' });
    if (v.verdict === 'NOT JUDGED') {
      out = await run();
      v = judge(out, { allRun: tier.kind === 'stage' });
    }
    if (v.verdict === 'NOT JUDGED') return { ...v, why: `${tier.name} tier, twice: ${v.why}\n    ${tail(out)}` };
    if (v.verdict === 'SURVIVED') continue;
    const look = needsSecondLook(tier, v.by);
    if (look.again) {
      const files = [...new Set(v.by.map((f) => relative(copy, f.file)))];
      const again = judge(await runTests(copy, files, tier.kind, envFor(tier.kind, tmp, stageVars)));
      const same = again.verdict === 'killed' && again.by.some((f) => v.by.some((g) => g.name === f.name));
      if (!same) return { verdict: 'NOT JUDGED', why: `${tier.name} tier: ${short(v.by)} failed once, and not again` };
      if (look.pristine) {
        writeFileSync(path, text);
        const control = judge(await runTests(copy, files, tier.kind, envFor(tier.kind, tmp, stageVars)));
        if (control.verdict !== 'SURVIVED') return { verdict: 'NOT JUDGED', why: `${tier.name} tier: ${short(v.by)} fails on the unbroken copy too, on this machine now` };
      }
    }
    return { verdict: 'killed', why: `${tier.name}: ${short(v.by)}` };
  }
  return afterAllTiers(m, { stage });
}

async function main() {
  const args = process.argv.slice(2);
  if (args[0] === '--self-test') return selfTest();
  if (args[0] === '--check') return check();
  const stage = !args.includes('--no-stage');
  const only = args.find((a) => !a.startsWith('--')) ?? '';
  const mutants = MUTANTS.filter((m) => m.name.includes(only));
  const { missing, vars: stageVars } = stageVariables();
  if (stage && missing.length) {
    console.log(`STAGE NOT SET: ${missing.join(', ')}. Set them, or pass --no-stage.`);
    return 2;
  }
  const base = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'undo-relay-mutants-'));
  const stop = () => {
    stopAll();
    rmSync(base, { recursive: true, force: true });
    process.exit(130);
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
  const started = Date.now();
  try {
    const template = join(base, 'template');
    makeTemplate(template);
    // The control: an unbroken copy, on exactly the tests that judge the mutants. A red one would read as a kill for
    // every mutant, and a stage run that skipped would read as a survivor.
    const control = join(base, 'control');
    freshCopy(template, join(control, 'repo'));
    mkdirSync(join(control, 'tmp-fast'), { recursive: true });
    mkdirSync(join(control, 'tmp-stage'), { recursive: true });
    const [fast, staged] = await Promise.all([
      runTests(join(control, 'repo'), FAST, 'fast', envFor('fast', join(control, 'tmp-fast'), stageVars)),
      stage ? runTests(join(control, 'repo'), STAGE, 'stage', envFor('stage', join(control, 'tmp-stage'), stageVars)) : null,
    ]);
    for (const [label, run, allRun] of [['site tests', fast, false], ['stage tests', staged, true]]) {
      if (!run) continue;
      const v = judge(run, { allRun });
      if (v.verdict !== 'SURVIVED') {
        console.log(`BASELINE FAILED: the ${label} are not green on an unbroken copy (${v.why ?? short(v.by)}), so no score means anything.\n    ${tail(run)}`);
        return 2;
      }
      console.log(`baseline green: ${lastCount(run.stdout, 'pass')} ${label} pass on an unbroken copy, ${lastCount(run.stdout, 'skipped') ?? 0} skipped`);
    }
    rmSync(control, { recursive: true, force: true });

    const results = new Array(mutants.length);
    let next = 0;
    let finished = 0;
    const worker = async (w) => {
      const dir = join(base, `w${w}`);
      for (let i = next++; i < mutants.length; i = next++) {
        const m = mutants[i];
        const r = await judgeMutant(m, { template, dir, stage, stageVars });
        results[i] = r;
        finished += 1;
        console.log(`[${finished}/${mutants.length}] ${r.verdict === 'killed' ? 'KILLED' : r.verdict} ${m.name}${r.why ? ` (${r.why})` : ''}`);
      }
      rmSync(dir, { recursive: true, force: true });
    };
    await Promise.all([0, 1, 2, 3].map(worker));

    const by = (verdict) => mutants.filter((_, i) => results[i].verdict === verdict);
    const survived = by('SURVIVED');
    const notApplied = by('NOT APPLIED');
    const notJudged = by('NOT JUDGED');
    const killed = by('killed');
    if (survived.length || notJudged.length) console.log('');
    for (const m of [...survived, ...notJudged]) {
      const r = results[mutants.indexOf(m)];
      console.log(`${r.verdict} ${m.name}\n    ${m.file}: ${JSON.stringify(m.from)} -> ${JSON.stringify(m.to)}`);
    }
    console.log(`\n${killed.length} of ${mutants.length} killed, ${survived.length} survived, ${notApplied.length} not applied, ${notJudged.length} not judged, in ${Math.round((Date.now() - started) / 60_000)} min`);
    return survived.length || notApplied.length || notJudged.length ? 1 : 0;
  } finally {
    stopAll();
    rmSync(base, { recursive: true, force: true });
  }
}

process.exitCode = await main();
