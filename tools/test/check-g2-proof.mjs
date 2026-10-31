#!/usr/bin/env node
// Refuses a G2 proof that is not a live result, and one whose verdict goes further than its contents.
// A failed live run is still a true proof, and passes here. With UNDO_TOOLS_CHECK_BIN set, it also runs
// libbitcoinconsensus over the transactions, with controls that must fail.
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const MUTINYNET_GENESIS = '00000008819873e925422c1ff0f99f7cc9bbb232af63a077a480a3633bee1ef6';
const bin = process.env.UNDO_TOOLS_CHECK_BIN;
const problems = [];
const need = (ok, text) => {
  if (!ok) problems.push(text);
};

let p;
try {
  p = JSON.parse(readFileSync(process.argv[2], 'utf8'));
} catch {
  console.log('G2 PROOF FAIL: not readable as JSON');
  process.exit(1);
}
need(p.schema === 'undo-g2-v1', 'not a G2 proof');
need(p.label === 'live-mutinynet', `its label is ${p.label}, not a live run`);
need(p.gate === 'G2', 'it does not name gate G2');
need(p.chain_id === 'testnet', `NEAR chain ${p.chain_id}`);
need(p.bitcoin?.network === 'mutinynet' && p.bitcoin?.genesis === MUTINYNET_GENESIS, 'not Mutinynet');

const s = p.summary ?? {};
need(typeof s.gate_complete === 'boolean', 'it does not say whether the gate is complete');
if (s.pass) {
  need(p.cosigned?.readback?.height > 0, 'pass without a co-signed spend read back');
  need(p.cosigned?.ku_control?.refusal === 'script', 'pass without the script refusing a spend with no K_u signature');
  need(p.escape?.early?.refusal === 'bip68', 'pass without the early refusal');
  need(p.escape?.csv_control?.refusal === 'script', 'pass without the script refusing an escape one block short');
  need(p.escape?.readback?.blocks_after_coin >= p.csv_blocks, 'pass without the escape mined at maturity');
}
if (s.gate_complete) {
  need(s.pass === true && s.finished === true, 'gate complete without a finished, passing run');
  need(Boolean(p.browser?.real_post), 'gate complete without a browser POST on record');
}

if (bin && s.pass && problems.length === 0) {
  const verify = (raw, values) => spawnSync(bin, ['verify', raw, p.vault.spk, values.join(',')], { encoding: 'utf8' }).status;
  const valueOf = (role) => p.coins.find((c) => c.role === role)?.value;
  const cosign = valueOf('cosign');
  const escape = valueOf('escape');
  need(verify(p.cosigned.raw, [cosign]) === 0, 'consensus refuses the co-signed spend');
  need(verify(p.cosigned.raw, [cosign + 1]) !== 0, 'control passed: a wrong value was accepted');
  need(verify(p.cosigned.ku_control.raw, [cosign]) !== 0, 'consensus accepts the spend with no K_u signature');
  need(verify(p.escape.raw, [escape]) === 0, 'consensus refuses the escape');
  need(verify(p.escape.csv_control.raw, [escape]) !== 0, 'consensus accepts the escape one block short');
}

if (problems.length) {
  for (const text of problems) console.log(`G2 PROOF FAIL: ${text}`);
  process.exit(1);
}
console.log(`G2 PROOF OK: ${s.pass ? 'chain lines pass' : 'an honest failure'}, gate_complete ${s.gate_complete}${bin && s.pass ? ', consensus agrees' : ''}`);
