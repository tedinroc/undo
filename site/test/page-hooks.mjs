// Lets Node import a page's modules: they import /site/... and /tools/... the way the built site serves them, and
// this maps those onto this tree. Register it with module.register before the first import of a page module.
import { pathToFileURL } from 'node:url';
import { dirname, resolve as resolvePath } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolvePath(dirname(fileURLToPath(import.meta.url)), '../..');

export async function resolve(specifier, context, next) {
  if (specifier.startsWith('/site/') || specifier.startsWith('/tools/')) return next(pathToFileURL(`${REPO}${specifier}`).href, context);
  return next(specifier, context);
}
