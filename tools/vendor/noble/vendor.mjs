#!/usr/bin/env node
// Copies the parts of @noble/curves and @noble/hashes that the tools import into this folder.
//
//   vendor.mjs --curves-tgz FILE --hashes-tgz FILE    check integrity, unpack, copy, write MANIFEST.json
//   vendor.mjs --check                                compare the copies with MANIFEST.json, offline
//
// Only two edits are made to each file: bare @noble imports become relative paths, because there is
// no node_modules here, and the sourceMappingURL comment goes, because no map files are copied.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync, rmSync, existsSync, copyFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const PINS = {
  curves: { version: '1.9.7', integrity: 'sha512-gbKGcRUYIjA3/zCCNaWDciTMFI0dCkvou3TL8Zmy5Nc7sJ47a0jtOeZoTaMxkuqRo9cRhjOdZJXegxYE5FN/xw==' },
  hashes: { version: '1.8.0', integrity: 'sha512-jCs9ldd7NwzpgXDIf6P3+NrHh9/sD6CQdxHyjQI+h/6rDNo88ypBxxz45UDuZHz9r3tNz7N/VInSVoVdtXEI4A==' },
};
const ENTRY = {
  curves: ['secp256k1.js', 'ed25519.js', 'nist.js'],
  hashes: ['sha2.js', 'sha3.js', 'hmac.js', 'hkdf.js', 'legacy.js', 'utils.js'],
};

const sha = (algo, bytes) => createHash(algo).update(bytes);
const sha256hex = (bytes) => sha('sha256', bytes).digest('hex');

function importsOf(text) {
  const found = [];
  for (const m of text.matchAll(/^(?:import|export)\s[^;]*?from\s+['"]([^'"]+)['"]/gm)) found.push(m[1]);
  return found;
}

function target(spec, pkg, file) {
  const bare = spec.match(/^@noble\/(curves|hashes)\/(.+)$/);
  if (bare) {
    const name = bare[2].endsWith('.js') ? bare[2] : `${bare[2]}.js`;
    return { pkg: bare[1], file: name };
  }
  if (spec.startsWith('.')) return { pkg, file: relative('.', join(dirname(file), spec)) };
  throw new Error(`unexpected import ${spec} in ${pkg}/${file}`);
}

function rewrite(text, pkg, file) {
  return text
    .replace(/from\s+['"](@noble\/(?:curves|hashes)\/[^'"]+)['"]/g, (_, spec) => {
      const t = target(spec, pkg, file);
      let rel = relative(dirname(join(pkg, file)), join(t.pkg, t.file));
      if (!rel.startsWith('.')) rel = `./${rel}`;
      return `from '${rel}'`;
    })
    .replace(/^\/\/# sourceMappingURL=.*$\n?/m, '');
}

function vendor(tgz) {
  const work = mkdtempSync(join(tmpdir(), 'noble-'));
  const manifest = { note: 'Vendored ESM from npm. See vendor.mjs for the only edits made.', packages: {}, files: {} };
  try {
    const roots = {};
    for (const pkg of ['curves', 'hashes']) {
      const bytes = readFileSync(tgz[pkg]);
      const integrity = `sha512-${sha('sha512', bytes).digest('base64')}`;
      if (integrity !== PINS[pkg].integrity) throw new Error(`integrity mismatch for ${pkg}`);
      const dir = join(work, pkg);
      mkdirSync(dir);
      execFileSync('tar', ['xzf', tgz[pkg], '-C', dir]);
      const meta = JSON.parse(readFileSync(join(dir, 'package', 'package.json'), 'utf8'));
      if (meta.version !== PINS[pkg].version) throw new Error(`version mismatch for ${pkg}`);
      roots[pkg] = join(dir, 'package');
      manifest.packages[pkg] = { name: `@noble/${pkg}`, version: meta.version, integrity };
    }
    rmSync(join(HERE, 'curves'), { recursive: true, force: true });
    rmSync(join(HERE, 'hashes'), { recursive: true, force: true });

    const queue = [];
    for (const pkg of ['curves', 'hashes']) for (const file of ENTRY[pkg]) queue.push({ pkg, file });
    const seen = new Set();
    while (queue.length) {
      const { pkg, file } = queue.pop();
      const key = `${pkg}/${file}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const text = readFileSync(join(roots[pkg], 'esm', file), 'utf8');
      for (const spec of importsOf(text)) queue.push(target(spec, pkg, file));
      const out = join(HERE, pkg, file);
      mkdirSync(dirname(out), { recursive: true });
      const edited = rewrite(text, pkg, file);
      writeFileSync(out, edited);
      manifest.files[key] = sha256hex(Buffer.from(edited));
    }
    for (const pkg of ['curves', 'hashes']) copyFileSync(join(roots[pkg], 'LICENSE'), join(HERE, pkg, 'LICENSE'));
    manifest.files = Object.fromEntries(Object.entries(manifest.files).sort());
    writeFileSync(join(HERE, 'MANIFEST.json'), `${JSON.stringify(manifest, null, 2)}\n`);
    console.log(`vendored ${Object.keys(manifest.files).length} files`);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

function check() {
  const manifest = JSON.parse(readFileSync(join(HERE, 'MANIFEST.json'), 'utf8'));
  let bad = 0;
  for (const [file, hash] of Object.entries(manifest.files)) {
    const path = join(HERE, file);
    if (!existsSync(path) || sha256hex(readFileSync(path)) !== hash) {
      console.log(`MISMATCH ${file}`);
      bad += 1;
    }
  }
  for (const pkg of Object.keys(PINS)) {
    if (manifest.packages[pkg].integrity !== PINS[pkg].integrity) {
      console.log(`PIN MISMATCH ${pkg}`);
      bad += 1;
    }
  }
  if (bad) process.exit(1);
  console.log(`vendor ok: ${Object.keys(manifest.files).length} files match`);
}

const args = process.argv.slice(2);
if (args[0] === '--check') {
  check();
} else if (args[0] === '--curves-tgz' && args[2] === '--hashes-tgz') {
  vendor({ curves: resolve(args[1]), hashes: resolve(args[3]) });
} else {
  console.error('usage: vendor.mjs --check | --curves-tgz FILE --hashes-tgz FILE');
  process.exit(2);
}
