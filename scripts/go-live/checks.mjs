// Readbacks shared by the deploy script and 50-readback: what the chain says, against what a run asked for.
import { line, note, SITE, TEMP_PREFIX } from './lib.mjs';

/** The full-access keys on an account, as public key strings. */
export async function fullAccessKeys(near, account) {
  const list = await near.rpc('query', { request_type: 'view_access_key_list', account_id: account, finality: 'final' });
  return (list?.keys ?? []).filter((k) => k.access_key?.permission === 'FullAccess').map((k) => k.public_key);
}

/** A temporary instance keeps the deployer's key, so step 90 can delete it. The real one must end with none. */
export const isTemp = (contract) => contract.startsWith(TEMP_PREFIX);

/**
 * Full-access keys on the contract account. `mode` is 'require-none' (the real instance after step 60: any key is a
 * FAIL, because its holder could replace the code at once, without the upgrade wait), 'before-lock' (the real
 * instance right after step 10: said, and left for step 60, which needs Ted's yes) or 'temp'. Returns a verdict or
 * null for an INFO line.
 */
export async function fullAccessVerdict({ near, contract, mode, label }) {
  const keys = await fullAccessKeys(near, contract);
  const list = keys.join(', ');
  if (keys.length === 0) {
    line('PASS', label, `${contract} has no full-access key: its code changes only through upgrade_propose and its public wait`);
    return 'PASS';
  }
  if (mode === 'temp') {
    line('INFO', label, `${contract} keeps ${keys.length} full-access key(s) (${list}): a temporary instance can be replaced or deleted by the deployer key, which step 90 uses`);
    return null;
  }
  if (mode === 'before-lock') {
    line('INFO', label, `${contract} still has ${keys.length} full-access key(s) (${list}). Until 60-lock-instance.mjs removes it (Ted's yes, cannot be undone), its holder can replace the code at once, so the README's operator row and C11 are not yet true for it`);
    return null;
  }
  line('FAIL', label, `${contract} has ${keys.length} full-access key(s) (${list}): its holder could replace the code at once, without the upgrade wait. Run 60-lock-instance.mjs, after Ted's yes`);
  return 'FAIL';
}

/** Compares what the instance says with what this run asked for. Returns the verdicts. */
export async function readBack({ near, contract, expect, facts, label }) {
  const out = [];
  const say = (ok, text) => {
    line(ok ? 'PASS' : 'FAIL', label, text);
    out.push(ok ? 'PASS' : 'FAIL');
  };
  const account = await near.account(contract);
  if (facts) say(account?.code_hash === facts.codeHash, `code hash on ${contract} is ${account?.code_hash ?? 'none'}, this wasm's is ${facts.codeHash}`);
  else line('INFO', label, `code hash on ${contract} is ${account?.code_hash ?? 'none'} (no --wasm given to compare)`);
  let instance;
  try {
    instance = await near.view(contract, 'instance');
  } catch (err) {
    say(false, `instance view: ${err.message}`);
    return out;
  }
  console.log('READBACK instance view:');
  for (const [k, v] of Object.entries(instance)) note(`${k}: ${JSON.stringify(v)}`);
  const same = (name, got, want) => say(JSON.stringify(got) === JSON.stringify(want), `${name} reads ${JSON.stringify(got)}${JSON.stringify(got) === JSON.stringify(want) ? '' : `, expected ${JSON.stringify(want)}`}`);
  same('preset', instance.preset, 'TestCoin');
  same('signer', instance.signer, expect.signer);
  same('network', instance.network, SITE.btcNetwork);
  same('origins', instance.origins, [SITE.origin]);
  same('operator', instance.operator, expect.parent);
  same('restrict_create', instance.restrict_create, false);
  same('sign_tgas', instance.sign_tgas, expect.signTgas);
  if (expect.operatorPasskey) same('operator_passkey', instance.operator_passkey, expect.operatorPasskey.pubkey);
  else line('INFO', label, `operator_passkey reads ${JSON.stringify(instance.operator_passkey)} (not compared: no passkey file given)`);
  same('pending_upgrade', instance.pending_upgrade ?? null, null);
  const keys = await fullAccessVerdict({ near, contract, mode: expect.fullAccess ?? (isTemp(contract) ? 'temp' : 'require-none'), label });
  if (keys) out.push(keys);
  try {
    const status = await near.view(contract, 'status', {});
    console.log('READBACK status view:');
    for (const text of status.lines ?? []) note(text);
  } catch (err) {
    say(false, `status view: ${err.message}`);
  }
  return out;
}

