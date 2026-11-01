// The one value that points a page at a network. There are no default endpoints anywhere in site/lib:
// a page with no config, or a config it refuses, stops and says so, so a local run cannot fall through
// to a live host and a live page cannot fall through to a local one.

export class ConfigError extends Error {}

const MODES = {
  // Every label a screen shows comes from the mode, so a local run cannot pass for a live one.
  testnet: { chip: 'signet test coins', near: 'NEAR testnet', bitcoin: 'Mutinynet' },
  local: { chip: 'local test coins, mock signer', near: 'local NEAR sandbox', bitcoin: 'local regtest' },
};

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

function url(text, field) {
  let parsed;
  try {
    parsed = new URL(text);
  } catch {
    throw new ConfigError(`config: ${field} is not a URL`);
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') throw new ConfigError(`config: ${field} is not http or https`);
  return parsed;
}

function checkHost(text, field, mode) {
  const parsed = url(text, field);
  const local = LOCAL_HOSTS.has(parsed.hostname);
  if (mode === 'local' && !local) throw new ConfigError(`config: ${field} leaves this machine in local mode`);
  if (mode !== 'local' && (local || parsed.protocol !== 'https:')) throw new ConfigError(`config: ${field} must be a public https host in ${mode} mode`);
}

function samePath(text, field) {
  if (typeof text !== 'string' || !text.startsWith('/') || text.startsWith('//')) throw new ConfigError(`config: ${field} must be a path on this origin`);
}

/** Returns a frozen copy, or throws naming the first field it refuses. */
export function checkConfig(raw) {
  if (!raw || typeof raw !== 'object') throw new ConfigError('config: missing');
  const { mode } = raw;
  if (!Object.hasOwn(MODES, mode)) throw new ConfigError('config: mode must be testnet or local');
  if (typeof raw.contract !== 'string' || !raw.contract) throw new ConfigError('config: contract is missing');
  if (!Array.isArray(raw.rpc) || raw.rpc.length === 0) throw new ConfigError('config: rpc needs at least one URL');
  raw.rpc.forEach((u, i) => checkHost(u, `rpc[${i}]`, mode));
  if (typeof raw.esplora !== 'string') throw new ConfigError('config: esplora is missing');
  checkHost(raw.esplora, 'esplora', mode);
  if (raw.esplora.endsWith('/')) throw new ConfigError('config: esplora must not end in a slash');
  samePath(raw.relay, 'relay');
  samePath(raw.funds, 'funds');
  for (const field of ['btcTxUrl', 'btcAddressUrl', 'nearTxUrl']) {
    if (raw[field] === null) continue;
    if (typeof raw[field] !== 'string') throw new ConfigError(`config: ${field} is missing`);
    checkHost(raw[field], field, mode);
  }
  if (typeof raw.rpId !== 'string' || !raw.rpId) throw new ConfigError('config: rpId is missing');
  if (raw.softPasskey !== true && raw.softPasskey !== false) throw new ConfigError('config: softPasskey must be true or false');
  if (raw.softPasskey && mode !== 'local' && !raw.softPasskeyLabel) throw new ConfigError('config: a software passkey on a public page needs softPasskeyLabel');
  return Object.freeze({ ...raw, rpc: Object.freeze([...raw.rpc]), labels: Object.freeze({ ...MODES[mode] }) });
}

/** A page's only way to get its config. Same origin, no cache, no fallback. */
export async function loadConfig({ fetchFn = globalThis.fetch, path = '/undo-config.json' } = {}) {
  let res;
  try {
    res = await fetchFn(path, { cache: 'no-store' });
  } catch {
    throw new ConfigError('config: could not be fetched');
  }
  if (!res.ok) throw new ConfigError(`config: HTTP ${res.status}`);
  return checkConfig(await res.json());
}

// Every hash on a screen names its chain, through these.
export const nearTxLabel = (config, hash) => `${config.labels.near} tx ${hash}`;
export const btcTxLabel = (config, txid) => `${config.labels.bitcoin} txid ${txid}`;
export const btcAddressLabel = (config, address) => `${config.labels.bitcoin} address ${address}`;

const fill = (template, value) => (template ? template.replace('{}', encodeURIComponent(value)) : null);
export const nearTxLink = (config, hash) => fill(config.nearTxUrl, hash);
export const btcTxLink = (config, txid) => fill(config.btcTxUrl, txid);
export const btcAddressLink = (config, address) => fill(config.btcAddressUrl, address);
