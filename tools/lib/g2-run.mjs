// Where a live G2 run keeps its state and writes its record. The first run has no name: private/g2 and
// proofs/g2.json. A run on another contract takes a name, and with it a folder and a file of its own, so the
// earlier record stays byte for byte what it was.
import { basename, join } from 'node:path';

export class RunNameError extends Error {}

// A letter first and no dash: `g2-NAME` can then never read as a folder --new-run moved aside, which ends in digits.
const RUN_NAME = /^[a-z][a-z0-9]{0,15}$/;

/** The state folder and the proof file of a live run. No name is the first run's. */
export function liveRunPaths(repo, name) {
  if (name === undefined || name === null) return { stateDir: join(repo, 'private', 'g2'), out: join(repo, 'proofs', 'g2.json') };
  if (typeof name !== 'string' || !RUN_NAME.test(name)) throw new RunNameError('--run takes a short name: a lowercase letter, then lowercase letters and digits, 16 in all at most');
  return { stateDir: join(repo, 'private', `g2-${name}`), out: join(repo, 'proofs', `g2-${name}.json`) };
}

/** Of the names beside a state folder, the ones --new-run made from it: its own name, a dash, then digits only. */
export function movedAside(stateDir, names) {
  const base = basename(stateDir);
  return names.filter((name) => name.startsWith(`${base}-`) && /^[0-9]+$/.test(name.slice(base.length + 1))).sort();
}

/**
 * A proof file already there, read as text: null if it is the record of a run on `contract`, and otherwise the
 * account it names, which a run on `contract` would write over.
 */
export function recordOfAnotherRun(text, contract) {
  let kept;
  try {
    kept = JSON.parse(text);
  } catch {
    return 'something this driver cannot read';
  }
  const account = kept?.contract?.account;
  if (account === contract) return null;
  return typeof account === 'string' && account ? account : 'something this driver cannot read';
}
