#!/usr/bin/env node
// Builds the Pages output from the one config value. No bundler: it walks the import graph from the pages
// and site/lib, and copies exactly what is reached, at the same relative paths the files have in the repo,
// so a page runs the same bytes as tools/ with no rewriting.
//
//   node site/build.mjs --config site/config/testnet.json [--out site/dist] [--allow-unfilled]
//
// Refuses: a config checkConfig refuses, a Node or bare import anywhere in the graph, a file outside the
// allowed folders, and any source map. Writes undo-config.json and _headers, whose connect-src comes from
// the config, so a built page can only reach the hosts its config names.
import { copyFileSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkConfig } from './lib/config.mjs';

const SITE = dirname(fileURLToPath(import.meta.url));
const REPO = resolve(SITE, '..');
const ALLOWED = ['site/lib/', 'tools/lib/', 'tools/vendor/noble/'];
const IMPORT = /^\s*(?:import|export|\})[^'"\n]*\bfrom\s+['"]([^'"]+)['"]|^\s*import\s+['"]([^'"]+)['"]|\bimport\(\s*['"]([^'"]+)['"]\s*\)/gm;

export class BuildRefused extends Error {}

const toRepo = (path) => relative(REPO, path).split(sep).join('/');

function walkFiles(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? walkFiles(path) : [path];
  });
}

/** Every module a set of roots reaches, as absolute paths. */
export function importGraph(roots, pagesDir) {
  const seen = new Set();
  const queue = [...roots];
  while (queue.length > 0) {
    const file = queue.pop();
    if (seen.has(file)) continue;
    seen.add(file);
    const text = readFileSync(file, 'utf8');
    if (text.includes('sourceMappingURL')) throw new BuildRefused(`source map reference in ${toRepo(file)}`);
    for (const match of text.matchAll(IMPORT)) {
      const spec = match[1] ?? match[2] ?? match[3];
      if (!spec.startsWith('.') && !spec.startsWith('/')) throw new BuildRefused(`${toRepo(file)} imports ${spec}, which a page cannot load`);
      const target = spec.startsWith('/') ? join(REPO, spec) : resolve(dirname(file), spec);
      if (!existsSync(target)) throw new BuildRefused(`${toRepo(file)} imports a file that is not there: ${spec}`);
      const repoPath = toRepo(target);
      const inPages = pagesDir && target.startsWith(pagesDir + sep);
      if (!inPages && !ALLOWED.some((prefix) => repoPath.startsWith(prefix))) throw new BuildRefused(`${toRepo(file)} reaches ${repoPath}, outside what a page may ship`);
      queue.push(target);
    }
  }
  return seen;
}

const originOf = (url) => new URL(url).origin;

export function headersFor(config) {
  const connect = [...new Set(["'self'", ...config.rpc.map(originOf), originOf(config.esplora)])].join(' ');
  const csp = [
    "default-src 'none'", "script-src 'self'", "style-src 'self'", "img-src 'self' data:", "media-src 'self'",
    "font-src 'self'", `connect-src ${connect}`, "base-uri 'none'", "form-action 'none'", "frame-ancestors 'none'",
  ].join('; ');
  return [
    '/*',
    `  Content-Security-Policy: ${csp}`,
    '  Referrer-Policy: no-referrer',
    '  X-Content-Type-Options: nosniff',
    '  Permissions-Policy: publickey-credentials-get=(self), publickey-credentials-create=(self), clipboard-write=(self)',
    '',
  ].join('\n');
}

export function build({ configPath, out = join(SITE, 'dist'), allowUnfilled = false, configObject = null }) {
  const config = checkConfig(configObject ?? JSON.parse(readFileSync(configPath, 'utf8')));
  if (!allowUnfilled && config.contract.startsWith('FILL-AT-DEPLOY')) throw new BuildRefused('config: the contract is not filled in');

  const pagesDir = join(SITE, 'pages');
  const pageFiles = walkFiles(pagesDir);
  const roots = [join(SITE, 'lib/index.mjs'), ...pageFiles.filter((f) => f.endsWith('.mjs'))];
  if (config.softPasskey) roots.push(join(SITE, 'lib/soft-authenticator.mjs'));
  const graph = importGraph(roots, pagesDir);

  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  const copy = (from, to) => {
    if (from.endsWith('.map')) throw new BuildRefused(`source map: ${toRepo(from)}`);
    mkdirSync(dirname(to), { recursive: true });
    copyFileSync(from, to);
  };
  for (const file of pageFiles) copy(file, join(out, relative(pagesDir, file)));
  for (const file of graph) {
    if (!file.startsWith(pagesDir + sep)) copy(file, join(out, toRepo(file)));
  }
  for (const license of ['tools/vendor/noble/curves/LICENSE', 'tools/vendor/noble/hashes/LICENSE']) copy(join(REPO, license), join(out, license));

  writeFileSync(join(out, 'undo-config.json'), `${JSON.stringify({ ...config, labels: undefined }, null, 2)}\n`);
  writeFileSync(join(out, '_headers'), headersFor(config));
  writeFileSync(join(out, '_routes.json'), `${JSON.stringify({ version: 1, include: ['/api/*'], exclude: [] })}\n`);
  return { out, files: walkFiles(out).length, modules: graph.size, config };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const value = (name) => (args.includes(name) ? args[args.indexOf(name) + 1] : undefined);
  const configPath = value('--config');
  if (!configPath) {
    console.error('usage: node site/build.mjs --config FILE [--out DIR] [--allow-unfilled]');
    process.exit(2);
  }
  try {
    const result = build({ configPath, out: value('--out') ? resolve(value('--out')) : undefined, allowUnfilled: args.includes('--allow-unfilled') });
    console.log(`BUILT ${result.config.mode}: ${result.files} files, ${result.modules} modules`);
  } catch (err) {
    console.error(`BUILD REFUSED: ${err.message}`);
    process.exit(1);
  }
}
