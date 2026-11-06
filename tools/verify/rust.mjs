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

/** libbitcoinconsensus on every input: true, false, or null when the referee could not be built. */
export function consensusVerdict(repo, raw, spk, values) {
  const c = toolsCheck(repo);
  if (!c.bin) return null;
  return spawnSync(c.bin, ['verify', raw, spk, values.join(',')], { encoding: 'utf8' }).status === 0;
}
