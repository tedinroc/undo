// Readbacks shared by the deploy script and 50-readback: what the chain says, against what a run asked for.
import { line, note, SITE } from './lib.mjs';

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
  try {
    const status = await near.view(contract, 'status', {});
    console.log('READBACK status view:');
    for (const text of status.lines ?? []) note(text);
  } catch (err) {
    say(false, `status view: ${err.message}`);
  }
  return out;
}

