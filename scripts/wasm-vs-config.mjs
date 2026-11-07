#!/usr/bin/env node
// Says whether a built contract wasm is the one deploy/testnet.json records as deployed. scripts/build.sh calls it
// after every build, so a rebuild that does not reproduce the deployed bytes says so at once.
//
//   node scripts/wasm-vs-config.mjs WASM [CONFIG]
//
// Exit 0: the same bytes, or nothing deployed to compare with. 1: different bytes. 2: usage or an unreadable file.
// Different bytes from the same source usually mean another toolchain: the README names the rustc and wasm-opt
// versions the recorded hashes came from.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { basename, dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const [wasmPath, configArg] = process.argv.slice(2);
if (!wasmPath) {
  console.error('usage: wasm-vs-config.mjs WASM [CONFIG]');
  process.exit(2);
}
const configPath = resolve(configArg ?? join(REPO, 'deploy', 'testnet.json'));
let bytes;
let config;
try {
  bytes = readFileSync(wasmPath);
  config = JSON.parse(readFileSync(configPath, 'utf8'));
} catch (err) {
  console.error(`wasm-vs-config: ${err.code ?? err.message}`);
  process.exit(2);
}
const got = createHash('sha256').update(bytes).digest('hex');
const where = `${basename(dirname(configPath))}/${basename(configPath)}`;
const want = typeof config.wasm_sha256 === 'string' ? config.wasm_sha256.toLowerCase() : null;
if (config.placeholder || !want) {
  console.log(`${basename(wasmPath)} sha256 ${got}: ${where} records no deployed wasm yet, so there is nothing to compare`);
  process.exit(0);
}
const chain = config.network === 'testnet' ? 'NEAR testnet' : `NEAR ${config.network}`;
if (got === want) {
  console.log(`${basename(wasmPath)} sha256 ${got}: the same bytes as the wasm ${where} records for ${config.contract} on ${chain}`);
  process.exit(0);
}
console.log(`${basename(wasmPath)} sha256 ${got}: NOT the wasm ${where} records for ${config.contract} on ${chain} (${want}). Another source or another toolchain`);
process.exit(1);
