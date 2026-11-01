// Typed reads of the contract's views. Field names stay the contract's own, so a builder can check them
// against contracts/undo/src/api.rs. A missing or wrongly typed field that a page reads is an error here,
// not a blank on a screen. Other fields pass through untouched, so a contract that adds one breaks nothing.
import { base58Decode, concat } from '../../tools/lib/bytes.mjs';

export class ShapeError extends Error {}

const is = {
  int: (v) => Number.isSafeInteger(v) && v >= 0,
  intOrNull: (v) => v === null || is.int(v),
  bool: (v) => v === true || v === false,
  str: (v) => typeof v === 'string',
  strOrNull: (v) => v === null || typeof v === 'string',
  hex: (v) => typeof v === 'string' && /^([0-9a-f]{2})*$/.test(v),
  ints: (v) => Array.isArray(v) && v.every(is.int),
  array: (v) => Array.isArray(v),
  object: (v) => v !== null && typeof v === 'object',
};

function check(name, raw, fields) {
  if (!is.object(raw)) throw new ShapeError(`${name}: not an object`);
  for (const [field, kind] of Object.entries(fields)) {
    if (!is[kind](raw[field])) throw new ShapeError(`${name}.${field}: expected ${kind}`);
  }
  return raw;
}

const POLICY = {
  t_known_ms: 'int', t_new_ms: 'int', t_new_unguarded_ms: 'int', hold_ms: 'int', t_stuck_ms: 'int',
  fee_cap_tx: 'int', fee_budget_24h: 'int', outflow_cap_24h: 'int',
};

export function parseInstance(raw) {
  check('instance', raw, {
    signer: 'str', domain_id: 'int', sign_tgas: 'int', callback_tgas: 'int', network: 'str', origins: 'array',
    policy: 'object', expiry_window_ms: 'int', block_ms: 'int', csv_min: 'int', csv_max: 'int', restrict_create: 'bool',
    guard_model: 'str',
  });
  check('instance.policy', raw.policy, POLICY);
  return raw;
}

export function parseVault(raw) {
  check('vault', raw, {
    id: 'hex', active: 'bool', k_s: 'hex', k_s_suspended: 'bool', k_u: 'hex', k_m: 'hex', k_e_leaf: 'hex', k_e_intent: 'hex',
    passkey: 'hex', rp_id_hash: 'hex', backup_eligible: 'bool', backup_state: 'bool', guard: 'strOrNull', guard_online: 'bool',
    last_heartbeat: 'intOrNull', created_at: 'int', csv: 'int', script_pubkey: 'hex', address: 'str', policy: 'object',
    spend_epoch: 'int', frozen_until: 'intOrNull', spend_nonce: 'int', passkey_nonce: 'int', cold_nonce: 'int',
    pending: 'ints', storage_credit: 'str',
  });
  check('vault.policy', raw.policy, POLICY);
  return { ...raw, storage_credit: BigInt(raw.storage_credit) };
}

const STATUSES = new Set(['Pending', 'Signing', 'Signed']);

export function parseRequest(raw) {
  check('request', raw, {
    id: 'int', kind: 'str', status: 'str', epoch: 'int', inputs: 'array', to: 'hex', amount: 'int', change: 'intOrNull',
    tier: 'str', fee: 'int', proposed_at: 'int', base_unlock: 'int', unlock: 'int', expires_at: 'int',
    first_execute_at: 'intOrNull', attempt: 'int', in_flight: 'int', sigs: 'array', assessed: 'bool', assess_hold: 'bool',
    assess_reason: 'str', hold_used: 'bool', hold_active: 'bool',
  });
  if (!STATUSES.has(raw.status)) throw new ShapeError(`request.status: unknown ${raw.status}`);
  raw.inputs.forEach((c, i) => check(`request.inputs[${i}]`, c, { txid: 'hex', vout: 'int', value: 'int' }));
  return raw;
}

export function parseStatus(raw) {
  check('status', raw, { ok: 'bool', lines: 'array' });
  return raw;
}

export function parseCheck(raw) {
  return check('check_propose', raw, { tier: 'str', delay_ms: 'int', fee: 'int', unguarded: 'bool' });
}

/** `secp256k1:<base58 of x || y>`, as the signer's view returns it, compressed. */
export function parseSignerKey(text) {
  if (typeof text !== 'string' || !text.startsWith('secp256k1:')) throw new ShapeError('signer returned something that is not a key');
  const xy = base58Decode(text.slice('secp256k1:'.length));
  if (xy.length !== 64) throw new ShapeError('signer key is not 64 bytes');
  return concat(Uint8Array.of(2 + (xy[63] & 1)), xy.slice(0, 32));
}

export function contractViews(reader, contract) {
  const view = (method, args) => reader.view(contract, method, args);
  return {
    instance: async () => parseInstance(await view('instance', {})),
    vault: async (vault) => {
      const raw = await view('vault', { vault });
      return raw === null ? null : parseVault(raw);
    },
    request: async (vault, request) => {
      const raw = await view('request', { vault, request });
      return raw === null ? null : parseRequest(raw);
    },
    status: async (vault = null) => parseStatus(await view('status', vault === null ? {} : { vault })),
    delayNow: (vault) => view('delay_now', { vault }),
    script: (vault) => view('script', { vault }),
    finalTx: (vault, request) => view('final_tx', { vault, request }),
    checkPropose: async (vault, { inputs, to, amount, change = null }) => parseCheck(await view('check_propose', { vault, inputs, to, amount, change })),
    /** Both, for one poll. A request is judged against the vault read beside it. */
    both: async (vault, request) => {
      const [v, r] = await Promise.all([
        view('vault', { vault }).then((raw) => (raw === null ? null : parseVault(raw))),
        view('request', { vault, request }).then((raw) => (raw === null ? null : parseRequest(raw))),
      ]);
      return { vault: v, request: r };
    },
  };
}

/** K_m as the signer derives it for this vault, asked directly. Path and predecessor are the contract's. */
export async function derivedKey(reader, { signer, domainId, contract, vaultHex }) {
  return parseSignerKey(await reader.view(signer, 'derived_public_key', { path: `undo/${vaultHex}`, predecessor: contract, domain_id: domainId }));
}
