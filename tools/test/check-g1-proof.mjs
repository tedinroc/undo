#!/usr/bin/env node
// Runs libbitcoinconsensus over every final transaction in a G1 proof, with a control that must fail.
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const bin = process.env.UNDO_TOOLS_CHECK_BIN;
if (!bin) throw new Error('set UNDO_TOOLS_CHECK_BIN');
const proof = JSON.parse(readFileSync(process.argv[2], 'utf8'));
const runs = [];
const collect = (node) => {
  if (Array.isArray(node)) node.forEach(collect);
  else if (node && typeof node === 'object') {
    if (node.final_tx) runs.push(node);
    Object.values(node).forEach(collect);
  }
};
collect(proof.stages);
if (runs.length === 0) {
  console.log('FAIL no final transactions in this proof');
  process.exit(1);
}
let bad = 0;
const verify = (run, values) => spawnSync(bin, ['verify', run.final_tx, run.script_pubkey, values.join(',')], { encoding: 'utf8' }).status;
for (const run of runs) {
  if (verify(run, run.input_values) !== 0) {
    console.log(`FAIL consensus refused request ${run.request} of ${run.vault}`);
    bad += 1;
  }
  const wrong = [...run.input_values];
  wrong[0] += 1;
  if (verify(run, wrong) === 0) {
    console.log(`FAIL control passed for request ${run.request}: a wrong value must be refused`);
    bad += 1;
  }
}
if (bad) process.exit(1);
console.log(`PASS [consensus-lib] ${runs.length} final transactions accepted, ${runs.length} wrong-value controls refused`);
