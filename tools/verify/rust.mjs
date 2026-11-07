// The Rust referees verify.sh and demo.sh lean on, built on demand with the repo's own lock files:
// tools/rust-check (libbitcoinconsensus over a transaction) and undo-btc's recovery-dry-run.
import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { join, resolve } from 'node:path';

const rustEnv = () => {
  const env = { ...process.env, CARGO_BUILD_JOBS: process.env.CARGO_BUILD_JOBS ?? '3', CARGO_TERM_COLOR: 'never' };
  // scripts/build.sh's wasm flags are not for host tools.
  delete env.RUSTFLAGS;
  delete env.CARGO_ENCODED_RUSTFLAGS;
  return env;
};

let hasCargo;
export const cargoAvailable = () => {
  hasCargo ??= spawnSync('cargo', ['--version'], { encoding: 'utf8' }).status === 0;
  return hasCargo;
};

/** Builds one binary and returns { bin } or { bin: null, why }. */
export function buildBin({ cwd, args, bin }) {
  if (!cargoAvailable()) return { bin: null, why: 'cargo is not installed' };
  const out = spawnSync('cargo', ['build', '--locked', '-q', ...args], { cwd, env: rustEnv(), encoding: 'utf8' });
  if (out.status !== 0) return { bin: null, why: `cargo build failed: ${(out.stderr || '').trim().split('\n').slice(-3).join(' / ')}` };
  const target = process.env.CARGO_TARGET_DIR ? resolve(process.env.CARGO_TARGET_DIR) : join(cwd, 'target');
  const path = join(target, 'debug', bin);
  return existsSync(path) ? { bin: path } : { bin: null, why: `built, but ${bin} is not where cargo puts it` };
}

const built = new Map();
/** tools/rust-check's undo-tools-check, or UNDO_TOOLS_CHECK_BIN when set. */
export function toolsCheck(repo) {
  if (process.env.UNDO_TOOLS_CHECK_BIN) return { bin: process.env.UNDO_TOOLS_CHECK_BIN };
  if (!built.has(repo)) built.set(repo, buildBin({ cwd: join(repo, 'tools/rust-check'), args: [], bin: 'undo-tools-check' }));
  return built.get(repo);
}

/**
 * libbitcoinconsensus on every input: { verdict, why }. verdict is true when every input passes (exit 0), false when
 * the referee ran and refused an input (exit 1, with an "input N: refused" line), and null otherwise: the referee was
 * not built, or it crashed or answered anything else. A crash is never read as a refusal, so a broken referee cannot
 * make a "refused" control pass.
 */
export function consensusJudge(repo, raw, spk, values) {
  const c = toolsCheck(repo);
  if (!c.bin) return { verdict: null, why: c.why, crashed: false };
  const out = spawnSync(c.bin, ['verify', raw, spk, values.join(',')], { encoding: 'utf8' });
  if (out.status === 0 && /^consensus ok$/m.test(out.stdout ?? '')) return { verdict: true, why: null, crashed: false };
  if (out.status === 1 && /^input \d+: refused: /m.test(out.stdout ?? '')) return { verdict: false, why: null, crashed: false };
  const said = `${out.stderr ?? ''}`.trim().split('\n')[0]?.slice(0, 160) ?? '';
  const how = out.status === null ? `was killed by ${out.signal ?? 'a signal'}` : `exited ${out.status}`;
  return { verdict: null, why: `the referee ${how} without a verdict${said ? `: ${said}` : ''}`, crashed: true };
}

/** The verdict alone: true, false, or null when there is none (not built, or crashed). */
export function consensusVerdict(repo, raw, spk, values) {
  return consensusJudge(repo, raw, spk, values).verdict;
}
