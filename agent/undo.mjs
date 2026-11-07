#!/usr/bin/env node
// undo: the agent's side of an Undo for Bitcoin vault.
//
//   undo propose --to <tb1 address> --amount <sats|all> [--memo TEXT] [--fee-rate N]
//   undo check   --to <tb1 address> --amount <sats|all> [--memo TEXT] [--fee-rate N]
//   undo status  [--request N]
//   undo keys    [--new] [--allowance '0.25 NEAR']
//   undo init    --near-network testnet|sandbox --contract ID --vault HEX --account ID --seed-file FILE
//                [--rpc URL] [--esplora URL]
//
// Every command takes --file FILE (else $UNDO_AGENT_FILE, else ./undo-agent.json) and --json.
//
// It signs with two things only: the vault's spend seed (K_s and K_u) and a NEAR function-call key
// scoped to propose_btc and execute. It holds no passkey and no cold key, so it has no cancel,
// rotate or policy command, and the contract would refuse one from these keys anyway.
//
// Exit 0: done. 1: refused, by the contract, by NEAR, or by a rule here. 2: bad usage or agent file.
// 3: a network read failed, and nothing was sent.
import { readFileSync } from 'node:fs';
import { parseArgs, UsageError } from '../tools/lib/args.mjs';
import { addressToSpk } from '../tools/lib/btc.mjs';
import { fixedHex, fromHex, toHex } from '../tools/lib/bytes.mjs';
import { randomBytes } from '../tools/lib/crypto.mjs';
import { spendKeys } from '../tools/lib/keys.mjs';
import { action, failureOf, Near, returnValue, RpcError, TGAS } from '../tools/lib/near.mjs';
import { signSpend } from '../tools/lib/spend.mjs';
import { CoinError, freeCoins, selectCoins } from './lib/coins.mjs';
import { addKeyTokens, AGENT_METHODS, agentFilePath, ConfigError, FORMAT, loadAgent, networkInfo, newNearKey, parseAgent, shownName, writeAgent } from './lib/config.mjs';
import { clock, coinLabel, contractWords, runtimeWords, sats, spkToAddress, tierText, viewWords } from './lib/format.mjs';

const PROPOSE_TGAS = 30n;
const INTENT_MS = 10 * 60_000;
const DEFAULT_ALLOWANCE = '0.25 NEAR';
const MEMO_MAX = 140;

class Refused extends Error {
  constructor(message, lines = [], json = {}) {
    super(message);
    this.lines = lines;
    this.json = json;
  }
}
class NetworkError extends Error {}

const SPEND_FLAGS = { to: 'text', amount: 'text', memo: 'text', 'fee-rate': 'text', file: 'text', json: 'flag' };
const SPECS = {
  propose: SPEND_FLAGS,
  check: SPEND_FLAGS,
  status: { request: 'int', file: 'text', json: 'flag' },
  keys: { new: 'flag', allowance: 'text', file: 'text', json: 'flag' },
  init: { 'near-network': 'text', contract: 'text', vault: 'text', account: 'text', 'seed-file': 'text', rpc: 'text', esplora: 'text', file: 'text', json: 'flag' },
};

const USAGE = `usage:
  undo propose --to <tb1 address> --amount <sats|all> [--memo TEXT]
  undo check   --to <tb1 address> --amount <sats|all> [--memo TEXT]
  undo status  [--request N]
  undo keys    [--new]
  undo init    --near-network testnet --contract ID --vault HEX --account ID --seed-file FILE
every command takes --file FILE (default $UNDO_AGENT_FILE, then ./undo-agent.json) and --json`;

// ---------------------------------------------------------------- reading the contract

async function read(what, fn) {
  try {
    return await fn();
  } catch (err) {
    if (err instanceof Refused) throw err;
    throw new NetworkError(`could not read ${what}: ${err.message}`);
  }
}

async function connect(agent) {
  const near = new Near(agent.rpc, { timeoutMs: 20_000 });
  const instance = await read(`the contract ${agent.contract} on ${agent.network.label}`, () => near.view(agent.contract, 'instance'));
  // The agent CLI is for test coins. A real-coin instance is refused before any key is used.
  if (instance.network === 'mainnet' || instance.preset !== 'TestCoin') throw new Refused('this contract is not a test-coin instance: the agent CLI runs on test coins only');
  const vault = await read('the vault', () => near.view(agent.contract, 'vault', { vault: agent.vaultHex }));
  if (!vault) throw new Refused(`no vault ${agent.vaultHex} on ${agent.contract} (${agent.network.label})`);
  return { near, instance, vault, btc: instance.network, coins: coinLabel(agent.network, instance.network) };
}

function keyState(agent, vault) {
  if (toHex(agent.spend.ks.pub) !== vault.k_s) return { ok: false, text: 'not this agent\'s: the owner installed another spend key, and the contract refuses this one' };
  if (vault.k_s_suspended) return { ok: false, text: 'suspended by the owner\'s rotation: the contract refuses every proposal from it' };
  return { ok: true, text: 'this agent\'s, active' };
}

/** A refused view call, in the contract's words. Anything else is a network failure. */
function viewRefusal(err) {
  if (!(err instanceof RpcError) || !err.data) return null;
  const d = err.data;
  const text = d.view ?? d.cause?.info?.vm_error ?? (typeof d.data === 'string' ? d.data : null);
  return text ? viewWords(text) : null;
}

/** The access key on chain, read-only. Refuses a key that can do more than the agent needs. */
async function keyPermission(near, agent) {
  let access;
  try {
    access = await near.rpc('query', { request_type: 'view_access_key', account_id: agent.accountId, public_key: agent.nearKey.publicKey, finality: 'optimistic' }, { attempts: 3 });
  } catch (err) {
    if (/UNKNOWN_ACCESS_KEY|UNKNOWN_ACCOUNT/.test(err.message)) return null;
    throw new NetworkError(`could not read the agent's NEAR key: ${err.message}`);
  }
  // Some nodes answer a missing key as a result with an error field, not as an RPC error.
  if (access?.error) {
    if (/does not exist/.test(access.error)) return null;
    throw new NetworkError(`could not read the agent's NEAR key: ${access.error}`);
  }
  return access.permission;
}

function describePermission(permission, contract) {
  if (permission === null) return { ok: false, text: 'not on chain yet' };
  if (permission === 'FullAccess') return { ok: false, text: 'FULL ACCESS: this key can do anything the account can. Use a function-call key (undo keys)' };
  const fc = permission.FunctionCall;
  if (!fc) return { ok: false, text: `unknown permission ${JSON.stringify(permission)}` };
  const methods = fc.method_names ?? [];
  const allowance = fc.allowance === null ? 'unlimited' : `${(Number(BigInt(fc.allowance) / 10n ** 18n) / 1e6).toFixed(4)} NEAR`;
  const text = `function-call key, contract ${fc.receiver_id}, methods ${methods.length ? methods.join(', ') : '(any)'}, allowance ${allowance}`;
  if (fc.receiver_id !== contract) return { ok: false, text: `${text}: not scoped to ${contract}` };
  // An empty list means every method on the contract.
  if (methods.length === 0) return { ok: false, text: `${text}: an empty method list allows every method` };
  const extra = methods.filter((m) => !AGENT_METHODS.includes(m));
  if (extra.length) return { ok: false, text: `${text}: wider than the agent needs (${extra.join(', ')})` };
  return { ok: true, text };
}

// ---------------------------------------------------------------- a spend: plan, check, propose

function spendInput(args) {
  if (!args.to) throw new UsageError('needs --to <tb1 address>');
  if (!args.amount) throw new UsageError('needs --amount <sats|all>');
  let amount;
  if (args.amount === 'all') amount = 'all';
  else if (/^[0-9]+$/.test(args.amount) && Number.isSafeInteger(Number(args.amount)) && Number(args.amount) > 0) amount = Number(args.amount);
  else throw new UsageError('--amount takes a whole number of sats or all');
  const memo = args.memo ?? null;
  // The contract's rule (crates/undo-core/src/guard.rs memo_ok). check_propose does not see the memo.
  if (memo !== null && (memo.length > MEMO_MAX || !/^[\x20-\x7e]*$/.test(memo))) throw new UsageError(`--memo takes printable ASCII, at most ${MEMO_MAX} characters`);
  const rate = args['fee-rate'] === undefined ? 2 : Number(args['fee-rate']);
  if (!Number.isFinite(rate) || rate < 1 || rate > 50) throw new UsageError('--fee-rate takes 1 to 50 sat/vB');
  return { to: args.to, amount, memo, rate };
}

async function plan(agent, ctx, input) {
  let spk;
  try {
    spk = addressToSpk(ctx.btc, input.to);
  } catch (err) {
    throw new Refused(`--to is not a ${ctx.btc} address: ${err.message}`);
  }
  const { near, vault } = ctx;
  const listed = await read(`coins at ${vault.address} from ${new URL(agent.esplora).host}`, () => freeCoins({
    esploraUrl: agent.esplora,
    address: vault.address,
    isFree: async (u) => (await near.view(agent.contract, 'outpoint', { vault: agent.vaultHex, txid: u.txid, vout: u.vout })).state === 'Free',
  }));
  let selection;
  try {
    selection = selectCoins({ coins: listed.coins, amount: input.amount, destLen: spk.length, rate: input.rate, cap: vault.policy.fee_cap_tx });
  } catch (err) {
    if (err instanceof CoinError) throw new Refused(err.message, listed.unconfirmed ? [`${listed.unconfirmed} unconfirmed coin(s) not counted`] : []);
    throw err;
  }
  let check;
  try {
    check = await near.view(agent.contract, 'check_propose', {
      vault: agent.vaultHex,
      inputs: selection.inputs.map(({ txid, vout, value }) => ({ txid, vout, value })),
      to: toHex(spk),
      amount: selection.amount,
      change: selection.change,
    });
  } catch (err) {
    const words = viewRefusal(err);
    if (words === null) throw new NetworkError(`could not run check_propose: ${err.message}`);
    if (input.checkOnly) throw new Refused(`the contract would refuse: ${words}`, [], { refusal: words, by: 'check_propose' });
    throw new Refused(`refused by the contract: ${words}`, ['its free check_propose view said so: nothing signed, nothing sent'], { refusal: words, by: 'check_propose' });
  }
  return { spk, selection, check, address: input.to };
}

function coinLine({ inputs, total, fee, change }) {
  const from = `${inputs.length} coin${inputs.length === 1 ? '' : 's'} (${sats(total)}), fee ${sats(fee)}`;
  return from + (change === null ? ', no change' : `, change ${sats(change)} back to the vault`);
}

async function cmdCheck(agent, args) {
  const input = { ...spendInput(args), checkOnly: true };
  const ctx = await connect(agent);
  const p = await plan(agent, ctx, input);
  const key = keyState(agent, ctx.vault);
  const lines = [
    `check only: nothing signed, nothing sent  [free view, ${agent.network.label}, ${ctx.coins}]`,
    `would propose ${sats(p.selection.amount)} to ${p.address}`,
    `from          ${coinLine(p.selection)}`,
    `tier          ${tierText(p.check.tier)}`,
    `wait          ${clock(p.check.delay_ms)} after propose${p.check.unguarded && p.check.tier === 'New' ? ' (guard offline: the unguarded new-destination wait)' : ''}`,
    `spend key     ${key.text}`,
  ];
  return { lines, json: { command: 'check', network: agent.network.name, to: p.address, amount: p.selection.amount, inputs: p.selection.inputs, change: p.selection.change, fee: p.selection.fee, tier: p.check.tier, delay_ms: p.check.delay_ms, unguarded: p.check.unguarded, spend_key: key.text } };
}

async function cmdPropose(agent, args) {
  const input = spendInput(args);
  if (!agent.nearKey) throw new ConfigError('the agent file has no NEAR key: run undo keys --new, then have the owner add it');
  const ctx = await connect(agent);
  const { near, vault } = ctx;
  const permission = describePermission(await keyPermission(near, agent), agent.contract);
  if (!permission.ok) throw new Refused(`the agent's NEAR key on ${agent.accountId} is ${permission.text}. Nothing sent`);
  const p = await plan(agent, ctx, input);
  const script = await read('the vault script', () => near.view(agent.contract, 'script', { vault: agent.vaultHex }));
  const now = await read('the block time', () => near.nowMs());
  const signed = signSpend.propose({
    seed: agent.seed,
    contract: agent.contract,
    vault: agent.vault,
    script: fromHex(script, 'script'),
    spk: fromHex(vault.script_pubkey, 'script_pubkey'),
    inputs: p.selection.inputs,
    to: p.spk,
    amount: p.selection.amount,
    change: p.selection.change,
    nonce: vault.spend_nonce,
    expiresAt: now + INTENT_MS,
    memo: input.memo,
  });
  let sent;
  try {
    sent = await near.sendAndWait(agent.nearKey, agent.contract, [action.call('propose_btc', signed.args, PROPOSE_TGAS * TGAS, 0n)]);
  } catch (err) {
    if (err instanceof RpcError && err.data) throw new Refused(`refused by NEAR before the contract ran: ${runtimeWords(err)}`, ['nothing reached the contract'], { refusal: runtimeWords(err), by: 'near' });
    throw new NetworkError(`propose_btc was signed but not confirmed: ${err.message}. Check undo status before sending again`);
  }
  const failure = failureOf(sent.result);
  if (failure) {
    const words = contractWords(failure);
    throw new Refused(`refused by the contract: ${words}`, [`${agent.network.label} tx ${sent.hash}`], { refusal: words, by: 'contract', tx: sent.hash, tx_chain: agent.network.label });
  }
  const id = returnValue(sent.result);
  const request = await read('the new request', () => near.view(agent.contract, 'request', { vault: agent.vaultHex, request: id }));
  const blockNow = await read('the block time', () => near.nowMs());
  const lines = [
    `Undo for Bitcoin  ·  agent spend key  ·  ${agent.network.label}  ·  ${ctx.coins}`,
    `proposed   ${sats(request.amount)} to ${p.address}`,
    `request    #${id}`,
    `tier       ${tierText(request.tier)}`,
    `wait       ${clock(request.unlock - request.proposed_at)}, set by the contract${p.check.unguarded && request.tier === 'New' ? ' (guard offline: the unguarded new-destination wait)' : ''}`,
    `unlocks in ${clock(request.unlock - blockNow)}`,
    'The owner\'s phone can cancel it until then. This key cannot.',
    `${agent.network.label} tx ${sent.hash}`,
    'Public now: the amount and destination, in the contract\'s queue.',
  ];
  return {
    lines,
    json: { command: 'propose', network: agent.network.name, request: id, tier: request.tier, amount: request.amount, to: p.address, unlock: request.unlock, proposed_at: request.proposed_at, block_time: blockNow, unlocks_in_ms: request.unlock - blockNow, tx: sent.hash, tx_chain: agent.network.label },
  };
}

// ---------------------------------------------------------------- status

function requestState(r, vault, now) {
  if (r === null) return 'not in the queue: cancelled (passkey, cold key or rotation), or signed and pruned';
  if (r.status === 'Pending' && r.epoch !== vault.spend_epoch) return 'dead: the owner\'s rotation cancelled every older request';
  if (r.status === 'Pending' && now > r.expires_at) return 'expired: never executed';
  if (r.status === 'Pending' && now < r.unlock) return `waiting, unlocks in ${clock(r.unlock - now)}${r.hold_active ? ' (includes a guard hold)' : ''}`;
  if (r.status === 'Pending') return 'unlocked: anyone may execute it now';
  if (r.status === 'Signing') return 'signing: the contract asked the signer';
  return 'signed: the Bitcoin transaction is ready (final_tx view)';
}

async function cmdStatus(agent, args) {
  const ctx = await connect(agent);
  const { near, vault } = ctx;
  const status = await read('status', () => near.view(agent.contract, 'status', { vault: agent.vaultHex }));
  const now = await read('the block time', () => near.nowMs());
  const ids = args.request !== undefined ? [args.request] : vault.pending;
  const rows = [];
  for (const id of ids) {
    const r = await read(`request ${id}`, () => near.view(agent.contract, 'request', { vault: agent.vaultHex, request: id }));
    rows.push({ id, request: r, state: requestState(r, vault, now) });
  }
  const key = keyState(agent, vault);
  const lines = [
    `Undo for Bitcoin  ·  vault ${agent.vaultHex.slice(0, 8)}…${agent.vaultHex.slice(-4)}  ·  ${agent.network.label} contract ${agent.contract}  ·  ${ctx.coins}`,
    `the contract says${status.ok ? '' : ' (needs attention)'}:`,
    ...status.lines.map((l) => `  ${l}`),
    rows.length ? 'requests:' : 'requests: none pending',
    ...rows.map(({ id, request: r, state }) => (r
      ? `  #${id}  ${r.tier}  ${sats(r.amount)} to ${spkToAddress(ctx.btc, r.to)}  ${state}`
      : `  #${id}  ${state}`)),
    `spend key: ${key.text}`,
    'Anyone can read this queue: amounts and destinations are public.',
  ];
  return {
    lines,
    json: { command: 'status', network: agent.network.name, ok: status.ok, contract_lines: status.lines, block_time: now, requests: rows.map(({ id, request: r, state }) => ({ id, state, status: r?.status ?? null, tier: r?.tier ?? null, amount: r?.amount ?? null, unlock: r?.unlock ?? null })), spend_key: key.text },
  };
}

// ---------------------------------------------------------------- keys and init

const shellWord = (t) => (/^[A-Za-z0-9_.,:/@=+-]+$/.test(t) ? t : `'${t.replace(/'/g, `'\\''`)}'`);

async function cmdKeys(agent, args, path) {
  let { nearKey } = agent;
  let made = false;
  if (!nearKey) {
    if (!args.new) throw new ConfigError('the agent file has no NEAR key yet: run undo keys --new to make one on this machine');
    const fresh = newNearKey(randomBytes);
    writeAgent(path, { ...agent.raw, private_key: fresh.text }, { replace: true });
    nearKey = { ...fresh.key, accountId: agent.accountId };
    made = true;
  } else if (args.new) {
    throw new ConfigError('the agent file already has a NEAR key; undo keys --new never replaces one');
  }
  const allowance = args.allowance ?? DEFAULT_ALLOWANCE;
  if (!/^[0-9]+(\.[0-9]+)? NEAR$/.test(allowance)) throw new UsageError('--allowance looks like \'0.25 NEAR\'');
  const nearNetwork = agent.network.local ? 'sandbox' : 'testnet';
  const tokens = addKeyTokens({ account: agent.accountId, publicKey: nearKey.publicKey, contract: agent.contract, allowance, network: nearNetwork });
  let onChain = { ok: false, text: 'not read' };
  try {
    onChain = describePermission(await keyPermission(new Near(agent.rpc, { timeoutMs: 15_000 }), { ...agent, nearKey }), agent.contract);
  } catch (err) {
    onChain = { ok: false, text: `could not read (${err.message})` };
  }
  const lines = [
    `Give this agent a spend key  ·  ${agent.network.label}`,
    made ? `made a new NEAR key on this machine and saved it in ${shownName(path)}` : `NEAR key from ${shownName(path)}`,
    `agent account  ${agent.accountId}`,
    `public key     ${nearKey.publicKey}`,
    `contract       ${agent.contract}`,
    `methods        ${AGENT_METHODS.join(', ')}`,
    `allowance      ${allowance}, for gas only`,
    '',
    'The owner adds it from the agent account\'s full-access key (near-cli-rs 0.30):',
    '',
    `  near ${tokens.map(shellWord).join(' ')}`,
    '',
    'What this key cannot do:',
    '  cancel, cancel_all_and_rotate, set_policy, clear_hold, add_destination: NEAR refuses any method',
    '    not listed above, and each of them also needs the owner\'s passkey or cold key, which this',
    '    machine does not hold.',
    '  shorten a wait: propose_btc takes no delay. The contract sets it from the tier.',
    '  attach a deposit or move NEAR: a function-call key cannot.',
    '',
    `on chain now   ${onChain.text}  [${agent.network.label}, read only]`,
  ];
  return { lines, json: { command: 'keys', network: agent.network.name, account: agent.accountId, public_key: nearKey.publicKey, contract: agent.contract, methods: AGENT_METHODS, allowance, near_cli: tokens, on_chain: onChain, made } };
}

async function cmdInit(args, path) {
  for (const need of ['near-network', 'contract', 'vault', 'account', 'seed-file']) {
    if (args[need] === undefined) throw new UsageError(`init needs --${need}`);
  }
  networkInfo(args['near-network']);
  let seed;
  try {
    seed = fixedHex(readFileSync(args['seed-file'], 'utf8').trim(), 32, 'seed file');
  } catch (err) {
    throw new ConfigError(err.code ? `seed file: ${err.code}` : err.message);
  }
  const fresh = newNearKey(randomBytes);
  const data = {
    undo_agent: FORMAT,
    near_network: args['near-network'],
    ...(args.rpc ? { rpc: [args.rpc] } : {}),
    contract: args.contract,
    vault: args.vault,
    ...(args.esplora ? { esplora: args.esplora } : {}),
    account_id: args.account,
    seed: toHex(seed),
    private_key: fresh.text,
  };
  const agent = parseAgent(JSON.stringify(data));
  const ctx = await connect(agent);
  if (toHex(spendKeys(seed).ks.pub) !== ctx.vault.k_s) throw new Refused('this seed does not hold the vault\'s spend key. Nothing written');
  try {
    writeAgent(path, data);
  } catch (err) {
    if (err.code === 'EEXIST') throw new ConfigError(`${shownName(path)} exists; init never writes over an agent file`);
    throw err;
  }
  return {
    lines: [
      `wrote ${shownName(path)} (mode 600): the vault's spend seed and a new NEAR key, nothing else`,
      `vault ${agent.vaultHex} on ${agent.contract}, ${agent.network.label}, ${ctx.coins}`,
      'next: undo keys, and have the owner add the key it prints',
    ],
    json: { command: 'init', file: shownName(path), public_key: fresh.key.publicKey },
  };
}

// ---------------------------------------------------------------- main

async function main(argv) {
  const [command, ...rest] = argv;
  if (!Object.hasOwn(SPECS, command ?? '')) throw new UsageError(USAGE);
  const args = parseArgs(rest, SPECS[command]);
  const path = agentFilePath(args.file);
  if (command === 'init') return cmdInit(args, path);
  const agent = loadAgent(path);
  return { propose: cmdPropose, check: cmdCheck, status: cmdStatus, keys: cmdKeys }[command](agent, args, path);
}

const wantsJson = process.argv.includes('--json');
main(process.argv.slice(2)).then((out) => {
  if (wantsJson) console.log(JSON.stringify(out.json, null, 2));
  else for (const line of out.lines) console.log(line);
}, (err) => {
  if (err instanceof UsageError) {
    console.error(err.message);
    process.exit(2);
  }
  if (err instanceof ConfigError) {
    console.error(`undo: ${err.message}`);
    process.exit(2);
  }
  if (err instanceof Refused) {
    if (wantsJson) console.log(JSON.stringify({ refused: err.message, ...err.json }, null, 2));
    else for (const line of [err.message, ...err.lines]) console.log(line);
    process.exit(1);
  }
  console.error(`undo: ${err instanceof NetworkError ? '' : 'stopped: '}${err.message}`);
  process.exit(3);
});
