// Shared by the go-live scripts. Nothing here sends a transaction on its own: each script builds a plan, prints it,
// and sends it only with --live, after its own checks. Mainnet is refused whatever the flags say.
//
// Two networks. `testnet` is the real one, read through public RPC, written only with --live and keys from the
// near-cli credentials folder. `sandbox` is a local node with a mock signer, for rehearsing every step here; its
// keys come from NEAR_CREDENTIALS_DIR/sandbox/<account>.json, and the label on its lines is [mock-signer].
import { existsSync, mkdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { b } from '../../tools/lib/borsh.mjs';
import { base58Encode, concat, fromHex, toHex, utf8 } from '../../tools/lib/bytes.mjs';
import { sha256 } from '../../tools/lib/crypto.mjs';
import { loadCredentials, Near, NEAR } from '../../tools/lib/near.mjs';

export const HERE = dirname(fileURLToPath(import.meta.url));
export const REPO = resolve(HERE, '../..');

/** The one site every instance serves. Fixed at creation: the contract has no setter for it. */
export const SITE = Object.freeze({ origin: 'https://undo-btc.pages.dev', rpId: 'undo-btc.pages.dev', btcNetwork: 'mutinynet' });

export const NETWORKS = Object.freeze({
  testnet: Object.freeze({
    rpc: ['https://test.rpc.fastnear.com', 'https://rpc.testnet.near.org'],
    parent: 's.undo-btc.testnet',
    relay: 's.undo-relay.testnet',
    signer: 'v1.signer-prod.testnet',
    label: 'live-testnet',
  }),
  sandbox: Object.freeze({ rpc: null, parent: null, relay: null, signer: null, label: 'mock-signer' }),
});

/** The relay's owner key may call these and nothing else (site/lib/relay-table.mjs, the owner bucket). */
export const OWNER_METHODS = Object.freeze(['cancel', 'cancel_all_and_rotate']);
export const CRON_METHODS = Object.freeze(['heartbeat']);
/** OWNER_ALLOWANCE_NEAR in site/lib/relay-table.mjs. */
export const OWNER_ALLOWANCE_NEAR = 8;
export const CRON_ALLOWANCE_NEAR = 2;

export const EMPTY_CODE = '11111111111111111111111111111111';
const LABEL = /^[a-z0-9]+(-[a-z0-9]+)*$/;
export const TEMP_PREFIX = 'tmp-';

export class Refused extends Error {}

// ---------------------------------------------------------------- output

/** Every result line names what it ran on, as SPEC 8 asks. */
export const line = (verdict, label, text) => console.log(`${verdict.padEnd(4)} [${label}] ${text}`);
export const plan = (text) => console.log(`PLAN ${text}`);
export const note = (text) => console.log(`     ${text}`);

export function tally(results) {
  const failed = results.filter((r) => r === 'FAIL').length;
  return { failed, passed: results.filter((r) => r === 'PASS').length, skipped: results.filter((r) => r === 'SKIP').length };
}

// ---------------------------------------------------------------- modes

/**
 * Exactly one of --dry-run and --live. A plan with neither is refused, so a typo never sends. Returns
 * { network, live, defaults }.
 */
export function modeOf(a, usage) {
  if (a['dry-run'] && a.live) throw new Refused('give --dry-run or --live, not both');
  if (!a['dry-run'] && !a.live) throw new Refused(`give --dry-run or --live\n${usage}`);
  const network = a.network ?? 'testnet';
  if (!Object.hasOwn(NETWORKS, network)) throw new Refused(`--network is testnet or sandbox\n${usage}`);
  if (network === 'sandbox' && !a.rpc) throw new Refused('--network sandbox needs --rpc');
  return { network, live: Boolean(a.live), defaults: NETWORKS[network] };
}

/** The node, after it says which chain it is. Never mainnet. Testnet must say testnet; a sandbox must not. */
export async function connect(network, rpcFlag, { offline = false } = {}) {
  const urls = rpcFlag ? [rpcFlag] : NETWORKS[network].rpc;
  const near = new Near(urls, { timeoutMs: 30_000 });
  if (offline) return { near, status: null };
  let status;
  try {
    status = await near.status();
  } catch (err) {
    throw new Refused(`the RPC did not answer status: ${err.message}`);
  }
  if (status.chain_id === 'mainnet') throw new Refused('this is mainnet. These scripts never run there');
  if (network === 'testnet' && status.chain_id !== 'testnet') throw new Refused(`expected testnet, the RPC says ${status.chain_id}`);
  if (network === 'sandbox' && (status.chain_id === 'testnet' || status.chain_id === 'mainnet')) throw new Refused(`--network sandbox pointed at ${status.chain_id}`);
  return { near, status };
}

export function checkLabel(label, { temp }) {
  if (typeof label !== 'string' || !LABEL.test(label) || label.length > 40) throw new Refused('--name is lower-case letters, digits and single dashes, at most 40, with no dots');
  if (temp && !label.startsWith(TEMP_PREFIX)) throw new Refused(`a temporary instance's name starts with ${TEMP_PREFIX}`);
  if (!temp && label.startsWith(TEMP_PREFIX)) throw new Refused(`${TEMP_PREFIX} is kept for temporary instances, which the teardown script may delete`);
}

export const utcStamp = (ms = Date.now()) => new Date(ms).toISOString().replace(/[-:]/g, '').replace('T', '-').slice(0, 13).toLowerCase();

// ---------------------------------------------------------------- keys and files

/** A signing key for an account, read only at --live. Its secret never leaves this process. */
export function signingKey(network, account) {
  const key = loadCredentials(network, account);
  if (key.looseMode) console.log(`WARN the key file for ${account} is readable by others`);
  return key;
}

/** True when `path` sits inside a git work tree, which would one day publish it. */
export function insideGitTree(path) {
  let dir = resolve(dirname(path));
  for (;;) {
    if (existsSync(join(dir, '.git'))) return true;
    const up = dirname(dir);
    if (up === dir) return false;
    dir = up;
  }
}

/** Written whole or not at all, 0600 in a 0700 folder. Refuses a path a repo could publish. */
export function writePrivate(path, value) {
  if (insideGitTree(path)) throw new Refused('that file would sit inside a git work tree. Pick a path outside every repo');
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
  renameSync(tmp, path);
}

export function readJson(path, what) {
  let text;
  try {
    text = readFileSync(path, 'utf8');
  } catch (err) {
    throw new Refused(`${what}: ${err.code ?? 'cannot read'}`);
  }
  try {
    return JSON.parse(text);
  } catch {
    // Never quote the text: it may be a key.
    throw new Refused(`${what} is not JSON`);
  }
}

export const modeIsPrivate = (path) => (statSync(path).mode & 0o077) === 0;

export function wasmFacts(path) {
  if (!existsSync(path)) throw new Refused('no wasm at that path. Run scripts/build.sh, or pass --wasm');
  const bytes = readFileSync(path);
  const digest = sha256(bytes);
  return { bytes, size: bytes.length, sha256: toHex(digest), codeHash: base58Encode(digest) };
}

export const defaultWasm = () => join(process.env.CARGO_TARGET_DIR ?? join(REPO, 'target'), 'near', 'undo_vault.wasm');

/** Where the private files go unless a flag says otherwise. Outside every repo, under the user's home. */
export const privateDir = () => process.env.UNDO_GOLIVE_DIR ?? join(process.env.HOME ?? '.', '.config', 'undo-golive');

/** The operator passkey as phone/h7 prints it: {"pubkey": 33-byte hex, "rp_id_hash": hex of sha256(rp id)}. */
export function readOperatorPasskey(path, rpId) {
  const raw = readJson(path, 'operator passkey file');
  const value = raw.operator_passkey ?? raw;
  const pubkey = String(value.pubkey ?? '').toLowerCase();
  const rpIdHash = String(value.rp_id_hash ?? '').toLowerCase();
  if (!/^(02|03)[0-9a-f]{64}$/.test(pubkey)) throw new Refused('operator passkey: pubkey must be a compressed P-256 key, 33 bytes as hex');
  const want = toHex(sha256(utf8(rpId)));
  if (rpIdHash !== want) throw new Refused(`operator passkey: rp_id_hash is not sha256("${rpId}"). A passkey made on another site cannot sign for this one`);
  return { pubkey, rp_id_hash: rpIdHash };
}

// ---------------------------------------------------------------- actions tools/lib/near.mjs has no builder for

/** DeleteAccount: the whole balance, freed storage included, goes to the beneficiary. */
export const deleteAccountAction = (beneficiary) => concat(Uint8Array.of(7), b.str(beneficiary));

/** For printing a plan. Never prints a secret: keys are public keys, args are what goes on chain anyway. */
export const describe = {
  createAccount: () => 'CreateAccount',
  transfer: (yocto) => `Transfer ${formatNear(yocto)} NEAR`,
  addFullKey: (publicKey) => `AddKey ${publicKey} FullAccess`,
  addCallKey: (publicKey, receiver, methods, allowanceYocto) => `AddKey ${publicKey} FunctionCall receiver=${receiver} methods=[${methods.join(', ')}] allowance=${formatNear(allowanceYocto)} NEAR`,
  deploy: (facts) => `DeployContract ${facts.size} bytes, sha256 ${facts.sha256}, code hash ${facts.codeHash}`,
  call: (method, args, tgas, depositYocto = 0n) => `FunctionCall ${method} ${tgas} Tgas deposit ${formatNear(depositYocto)} NEAR args ${JSON.stringify(args)}`,
  deleteKey: (publicKey) => `DeleteKey ${publicKey}`,
  deleteAccount: (beneficiary) => `DeleteAccount beneficiary=${beneficiary}`,
};

export function formatNear(yocto) {
  const v = BigInt(yocto);
  const whole = v / NEAR;
  const frac = (v % NEAR).toString().padStart(24, '0').slice(0, 4);
  return `${whole}.${frac}`;
}

export const nearOf = (n) => (BigInt(Math.round(Number(n) * 1000)) * NEAR) / 1000n;

/** Prints one transaction of a plan. */
export function planTx(n, { signer, receiver, actions }) {
  plan(`tx ${n}: signer ${signer} -> receiver ${receiver}`);
  for (const a of actions) note(`- ${a}`);
}

/** The key at final, or null. A node may answer a missing key as an error, or as a result holding `error`. */
export async function accessKey(near, account, publicKey) {
  let out;
  try {
    out = await near.rpc('query', { request_type: 'view_access_key', account_id: account, public_key: publicKey, finality: 'final' }, { attempts: 3 });
  } catch (err) {
    if (/UNKNOWN_ACCESS_KEY|does not exist/.test(`${err.message} ${JSON.stringify(err.data ?? '')}`)) return null;
    throw err;
  }
  return out?.error || !out?.permission ? null : out;
}

/** Waits for keys a transaction just added to read at final, which lags inclusion by a block or two. */
export async function untilFinal(near, account, publicKeys, { tries = 40, ms = 500 } = {}) {
  for (let i = 0; i < tries; i += 1) {
    const seen = await Promise.all(publicKeys.map((k) => accessKey(near, account, k)));
    if (seen.every(Boolean)) return true;
    await new Promise((r) => setTimeout(r, ms));
  }
  return false;
}

/**
 * The failure of the receipt that ran a transaction's own actions, or null. Unlike failureOf, it ignores the gas
 * refund, which fails by design after DeleteAccount: the refund is addressed to the account just deleted.
 */
export function ownFailure(result) {
  if (result?.status?.Failure) return JSON.stringify(result.status.Failure);
  const first = result?.transaction_outcome?.outcome?.receipt_ids?.[0];
  const receipt = (result?.receipts_outcome ?? []).find((r) => r.id === first);
  return receipt?.outcome?.status?.Failure ? JSON.stringify(receipt.outcome.status.Failure) : null;
}

/** Does the key on chain have exactly this permission? Returns null, or what differs. */
export function permissionProblem(access, want) {
  if (!access) return 'not on the account';
  const p = access.permission;
  if (want.full) return p === 'FullAccess' ? null : `permission is ${JSON.stringify(p)}, expected FullAccess`;
  const fc = p?.FunctionCall;
  if (!fc) return `permission is ${JSON.stringify(p)}, expected a function-call key`;
  if (fc.receiver_id !== want.receiver) return `receiver is ${fc.receiver_id}, expected ${want.receiver}`;
  const methods = [...fc.method_names].sort().join(',');
  if (methods !== [...want.methods].sort().join(',')) return `methods are [${fc.method_names.join(', ')}], expected [${want.methods.join(', ')}]`;
  if (fc.allowance === null || fc.allowance === undefined) return 'allowance is unlimited, expected a cap';
  if (BigInt(fc.allowance) > want.allowance) return `allowance ${formatNear(fc.allowance)} NEAR is above ${formatNear(want.allowance)}`;
  return null;
}

export { fromHex, toHex };
