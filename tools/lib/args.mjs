// A strict flag parser. An unknown flag is an error: a typo in a tool that signs must not be ignored.
export function parseArgs(argv, spec) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    const flag = argv[i];
    if (!flag.startsWith('--') || !Object.hasOwn(spec, flag.slice(2))) throw new UsageError(`unknown argument ${flag}`);
    const name = flag.slice(2);
    if (spec[name] === 'flag') {
      out[name] = true;
    } else {
      i += 1;
      if (i >= argv.length) throw new UsageError(`${flag} needs a value`);
      out[name] = spec[name] === 'int' ? parseIntStrict(flag, argv[i]) : argv[i];
    }
  }
  return out;
}

function parseIntStrict(flag, text) {
  if (!/^[0-9]+$/.test(text) || !Number.isSafeInteger(Number(text))) throw new UsageError(`${flag} needs a whole number`);
  return Number(text);
}

export class UsageError extends Error {}

export async function askYes(prompt) {
  process.stdout.write(`${prompt} `);
  const chunks = [];
  for await (const chunk of process.stdin) {
    chunks.push(chunk);
    if (chunk.includes(10)) break;
  }
  return Buffer.concat(chunks).toString('utf8').trim() === 'yes';
}
