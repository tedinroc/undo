// The static import closure of a built page's module scripts, as V8 itself parses each file (vm.SourceTextModule), not
// as site/build.mjs's walk reads them. Needs --experimental-vm-modules, so preload.test.mjs starts it in a child.
//
//   node --experimental-vm-modules module-closure.mjs OUT_DIR /p/phone.mjs [/more/entry.mjs ...]
//
// Prints the sorted URL paths of every module the entries reach, the entries included. Nothing is run, only parsed.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import vm from 'node:vm';

const [out, ...entries] = process.argv.slice(2);
const seen = new Set();
const queue = [...entries];
while (queue.length > 0) {
  const url = queue.pop();
  if (seen.has(url)) continue;
  seen.add(url);
  const module = new vm.SourceTextModule(readFileSync(join(out, url), 'utf8'), { identifier: url });
  const specifiers = module.moduleRequests ? module.moduleRequests.map((r) => r.specifier) : module.dependencySpecifiers;
  for (const spec of specifiers) queue.push(new URL(spec, `https://page.invalid${url}`).pathname);
}
process.stdout.write(`${JSON.stringify([...seen].sort())}\n`);
