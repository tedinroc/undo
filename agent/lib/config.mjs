// The agent file: the only secret the agent CLI reads. It holds the vault's spend seed (K_s and K_u,
// derived by HKDF) and one NEAR function-call key. It never holds the owner's passkey (K_p) or cold
// key (K_e): the loader refuses any field it does not know, so a recovery file or a passkey secret
// pasted in by mistake stops the CLI before anything is signed.
import { readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename } from 'node:path';
import { base58Encode, fixedHex, toHex } from '../../tools/lib/bytes.mjs';
import { checkEndpoints, ESPLORA_ALLOW, NEAR_RPC_ALLOW } from '../../tools/lib/esplora.mjs';
import { spendKeys } from '../../tools/lib/keys.mjs';
import { keyFromSecret, parseSecretKey } from '../../tools/lib/near.mjs';

export const FORMAT = 1;
export const DEFAULT_FILE = 'undo-agent.json';

/** What the agent's NEAR key may call. Anything wider is refused before a transaction is signed. */
export const AGENT_METHODS = ['propose_btc', 'execute'];

/** The near-cli-rs 0.30 command that adds the agent's key, as tokens, so a test can check it parses. */
export function addKeyTokens({ account, publicKey, contract, allowance, network }) {
  return ['account', 'add-key', account, 'grant-function-call-access', '--allowance', allowance, '--contract-account-id', contract,
    '--function-names', AGENT_METHODS.join(','), 'use-manually-provided-public-key', publicKey, 'network-config', network, 'sign-with-legacy-keychain', 'send'];
}

const FIELDS = ['undo_agent', 'near_network', 'rpc', 'contract', 'vault', 'esplora', 'seed', 'account_id', 'private_key'];
// Names that mean someone put owner material in the agent's file. Named in the refusal.
const OWNER_WORDS = /cold|leaf|passkey|k_e|k_p|recovery|webauthn|intent/i;

export class ConfigError extends Error {}

/** Only the file's name is ever printed: a screen or a log must not show a local path. */
export const shownName = (path) => basename(path);

export function agentFilePath(flag) {
  return flag ?? process.env.UNDO_AGENT_FILE ?? DEFAULT_FILE;
}

/** NEAR networks this CLI runs on. Mainnet is refused: this build moves test coins only. */
export function networkInfo(name) {
  if (name === 'testnet') return { name, label: 'NEAR testnet', local: false };
  if (name === 'sandbox') return { name, label: 'NEAR sandbox', local: true };
  if (name === 'mainnet') throw new ConfigError('near_network mainnet is refused: this build moves test coins only');
  throw new ConfigError('near_network must be testnet or sandbox');
}

/** Parses and checks an agent file's text. Exported for tests. */
export function parseAgent(text) {
  let data;
  try {
    data = JSON.parse(text);
  } catch {
    // The text holds a key, so it is never quoted back.
    throw new ConfigError('agent file is not JSON');
  }
  if (data === null || typeof data !== 'object' || Array.isArray(data)) throw new ConfigError('agent file is not a JSON object');
  for (const name of Object.keys(data)) {
    if (FIELDS.includes(name)) continue;
    if (OWNER_WORDS.test(name)) {
      throw new ConfigError(`agent file has "${name}": an agent never holds the owner's passkey or cold key. Remove it and keep it off this machine`);
    }
    throw new ConfigError(`agent file has an unknown field "${name}"`);
  }
  if (data.undo_agent !== FORMAT) throw new ConfigError(`agent file must say "undo_agent": ${FORMAT}`);
  const network = networkInfo(data.near_network);
  const rpc = data.rpc ?? (network.local ? null : [NEAR_RPC_ALLOW[1], NEAR_RPC_ALLOW[0]]);
  if (!Array.isArray(rpc) || rpc.length === 0 || !rpc.every((u) => typeof u === 'string')) throw new ConfigError('rpc must be a list of URLs');
  const esplora = data.esplora ?? (network.local ? null : ESPLORA_ALLOW[0]);
  if (typeof esplora !== 'string') throw new ConfigError('esplora must be a URL');
  try {
    checkEndpoints({ regtest: network.local, esplora, rpc });
  } catch (err) {
    throw new ConfigError(`${err.message} (${network.local ? 'a sandbox file takes only this machine' : 'testnet takes the listed hosts only'})`);
  }
  if (typeof data.contract !== 'string' || !/^[a-z0-9._-]{2,64}$/.test(data.contract)) throw new ConfigError('contract must be a NEAR account id');
  if (typeof data.account_id !== 'string' || !/^[a-z0-9._-]{2,64}$/.test(data.account_id)) throw new ConfigError('account_id must be a NEAR account id');
  let vault;
  let seed;
  try {
    vault = fixedHex(data.vault, 32, 'vault');
    seed = fixedHex(data.seed, 32, 'seed');
  } catch (err) {
    throw new ConfigError(err.message);
  }
  let nearKey = null;
  if (data.private_key !== undefined) {
    try {
      nearKey = { ...parseSecretKey(data.private_key), accountId: data.account_id };
    } catch {
      throw new ConfigError('private_key is not an ed25519 NEAR key');
    }
  }
  return { network, rpc, esplora, contract: data.contract, vault, vaultHex: toHex(vault), seed, spend: spendKeys(seed), accountId: data.account_id, nearKey, raw: data };
}

/** Reads the file. A key file anyone else on the machine can read is refused, as ssh refuses one. */
export function loadAgent(path) {
  let mode;
  try {
    mode = statSync(path).mode;
  } catch (err) {
    throw new ConfigError(`no agent file ${basename(path)} (${err.code}). Make one with: undo init`);
  }
  if ((mode & 0o077) !== 0) throw new ConfigError(`agent file ${basename(path)} is readable by others: chmod 600 it`);
  return { ...parseAgent(readFileSync(path, 'utf8')), path };
}

/** Writes with mode 600 from the first byte, never over an existing file unless asked. */
export function writeAgent(path, data, { replace = false } = {}) {
  writeFileSync(path, `${JSON.stringify(data, null, 2)}\n`, { mode: 0o600, flag: replace ? 'w' : 'wx' });
}

export function newNearKey(randomBytes) {
  const key = keyFromSecret(randomBytes(32));
  // near-cli's file form: 64 bytes, the secret then the public key.
  const full = new Uint8Array(64);
  full.set(key.secret, 0);
  full.set(key.pub, 32);
  return { key, text: `ed25519:${base58Encode(full)}` };
}
