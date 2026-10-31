// Prints a wasm file's imports and exports, one per line, using the runtime's own parser.
import { readFileSync } from "node:fs";

const file = process.argv[2];
if (!file) {
  console.error("usage: wasm-symbols.mjs FILE");
  process.exit(2);
}
const module = new WebAssembly.Module(readFileSync(file));
for (const { module: from, name } of WebAssembly.Module.imports(module)) {
  console.log(`import ${from}.${name}`);
}
for (const { name, kind } of WebAssembly.Module.exports(module)) {
  console.log(`export ${kind} ${name}`);
}
