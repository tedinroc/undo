// Real workerd for the relay's tests: the Pages Functions as `wrangler@3 pages functions build` bundles them,
// undo-cron as `wrangler@3 deploy --dry-run` bundles it, both under Miniflare with the Durable Object bound
// across by script name, as on Cloudflare. Nothing here deploys, logs in or reads an account.
//
// Set UNDO_WRANGLER_MODULES to a node_modules folder holding wrangler 3 and its miniflare. Not installed by this
// repo, which has no install step. No network: wrangler runs with metrics off and a blank config folder.
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const SITE = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CRON = resolve(SITE, '../worker/undo-cron');

export const COMPATIBILITY_DATE = readFileSync(join(SITE, 'wrangler.toml'), 'utf8').match(/compatibility_date = "([^"]+)"/)[1];

export const workerdAvailable = () => Boolean(process.env.UNDO_WRANGLER_MODULES);

const modules = () => process.env.UNDO_WRANGLER_MODULES;

export function loadMiniflare() {
  const require = createRequire(join(modules(), 'wrangler/package.json'));
  return require(require.resolve('miniflare'));
}

function wrangler(args, cwd, home) {
  const out = spawnSync(process.execPath, [join(modules(), 'wrangler/bin/wrangler.js'), ...args], {
    cwd,
    encoding: 'utf8',
    env: { PATH: process.env.PATH, HOME: home, XDG_CONFIG_HOME: join(home, 'xdg'), WRANGLER_SEND_METRICS: 'false', WRANGLER_LOG_PATH: join(home, 'logs') },
  });
  if (out.status !== 0) throw new Error(`wrangler ${args[0]} failed:\n${out.stdout}\n${out.stderr}`);
  return out.stdout;
}

/** Builds both with the real tool. Returns the two bundles, and the folder to delete. */
export function bundleBoth() {
  const dir = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'undo-workerd-'));
  mkdirSync(join(dir, 'xdg'), { recursive: true });
  wrangler(['pages', 'functions', 'build', '--outdir', join(dir, 'pages'), '--compatibility-date', COMPATIBILITY_DATE], SITE, dir);
  const dry = wrangler(['deploy', '--dry-run', '--outdir', join(dir, 'cron')], CRON, dir);
  return { dir, pages: join(dir, 'pages/index.js'), cron: join(dir, 'cron/index.js'), dry, remove: () => [dir, join(SITE, '.wrangler'), join(CRON, '.wrangler')].forEach((path) => rmSync(path, { recursive: true, force: true })) };
}

const script = (path) => ({ modules: true, script: readFileSync(path, 'utf8') });

/**
 * `pages` maps a worker name to { bindings, state }. All run the same bundle and bind UNDO_STATE on undo-cron by
 * script name, unless `state` points the binding at another class in `extra`.
 */
export function startWorkerd({ Miniflare }, { bundles, cronEnv = {}, pages, extra = [] }) {
  return new Miniflare({
    workers: [
      ...Object.entries(pages).map(([name, { bindings, state }]) => ({
        name,
        ...script(bundles.pages),
        compatibilityDate: COMPATIBILITY_DATE,
        bindings,
        durableObjects: { UNDO_STATE: { className: 'UndoState', scriptName: 'undo-cron', useSQLite: true, ...state } },
      })),
      {
        name: 'undo-cron',
        ...script(bundles.cron),
        compatibilityDate: COMPATIBILITY_DATE,
        bindings: cronEnv,
        durableObjects: { UNDO_STATE: { className: 'UndoState', useSQLite: true } },
      },
      ...extra,
    ],
  });
}
