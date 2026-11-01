// Measures the relay's CPU in workerd on this machine: local numbers, not Cloudflare's. Prints per-call wall time
// with no real I/O in the way, and the workerd process's CPU over the same calls. `cold` is the first call in a
// freshly started workerd, the case a 10 ms limit is about.
//   UNDO_WRANGLER_MODULES=... node site/test/relay-bench.mjs
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { toHex } from '../../tools/lib/bytes.mjs';
import { ed25519, sha256 } from '../../tools/lib/crypto.mjs';
import { rotateArgs, rotateDigest } from '../lib/intents.mjs';
import { softCredentials } from '../lib/soft-authenticator.mjs';
import { createPasskey, getAssertion } from '../lib/webauthn.mjs';
import { COMPATIBILITY_DATE, loadMiniflare } from './workerd.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const dir = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'undo-bench-'));
const require = createRequire(join(process.env.UNDO_WRANGLER_MODULES, 'wrangler/package.json'));
const esbuild = require(require.resolve('esbuild'));
const label = (t) => sha256(new TextEncoder().encode(`undo-test-only:bench:${t}`));

const bundle = join(dir, 'bench.js');
esbuild.buildSync({ entryPoints: [join(HERE, 'relay-bench-worker.mjs')], bundle: true, format: 'esm', outfile: bundle, logLevel: 'silent', target: 'es2022' });
const empty = join(dir, 'empty.js');
writeFileSync(empty, "export default { fetch: () => new Response('ok') };");

const { Miniflare } = loadMiniflare();
const start = (path) => new Miniflare({ modules: true, script: readFileSync(path, 'utf8'), compatibilityDate: COMPATIBILITY_DATE });
const pid = () => execFileSync('pgrep', ['-n', '-P', String(process.pid), 'workerd'], { encoding: 'utf8' }).trim();
function cpuMs(p) {
  const [m, s] = execFileSync('ps', ['-o', 'time=', '-p', p], { encoding: 'utf8' }).trim().split(':');
  return (Number(m) * 60 + Number(s)) * 1000;
}

// A cancel with a real assertion, so the relay's real checks run.
const soft = softCredentials({ secret: label('passkey'), origin: 'http://x', rpId: 'x' });
const made = await createPasskey({ credentials: soft, rpId: 'x' });
const vaultHex = toHex(label('vault'));
const newKs = ed25519.getPublicKey(label('new'));
const digest = rotateDigest({ contract: 'c.test', vaultHex, newKs, nonce: 0, expiresAt: 9e12 });
const { args: assertion } = await getAssertion({ credentials: soft, digest, rpId: 'x', credentialId: made.credentialId });
const cancel = { body: JSON.stringify({ method: 'cancel_all_and_rotate', args: rotateArgs({ vaultHex, newKs, nonce: 0, expiresAt: 9e12, assertion }) }), view: { passkey: toHex(made.pubkey), passkey_nonce: 0 } };
const heartbeat = { body: JSON.stringify({ method: 'heartbeat', args: { vault: vaultHex } }), view: null };

const CASES = {
  'build and sign a transaction (WebCrypto Ed25519)': { path: '/tx', n: 2000 },
  'whole relay POST, heartbeat, I/O answered from memory': { path: '/relay', n: 500, body: heartbeat },
  'whole relay POST, cancel with its P-256 check, I/O from memory': { path: '/relay', n: 500, body: cancel },
  'funding transaction (noble secp256k1, 1 input)': { path: '/funding', n: 100 },
  'whole funds POST, I/O answered from memory': { path: '/funds', n: 100, body: { body: JSON.stringify({ vault: vaultHex, pow: 0 }), view: { active: true, script_pubkey: `0020${'07'.repeat(32)}` } } },
};

const call = (mf, path, n, body) => mf.dispatchFetch(`http://x${path}?n=${n}`, body ? { method: 'POST', body: JSON.stringify(body) } : {});

async function warm() {
  const mf = start(bundle);
  await mf.ready;
  const p = pid();
  for (const [name, c] of Object.entries(CASES)) {
    await (await call(mf, c.path, Math.ceil(c.n / 10), c.body)).text(); // warm the JIT
    const cpu0 = cpuMs(p);
    const t0 = performance.now();
    const res = await call(mf, c.path, c.n, c.body);
    const text = await res.text();
    const wall = performance.now() - t0;
    if (!res.ok) throw new Error(`${name}: ${text}`);
    console.log(`warm  ${name}: ${(wall / c.n).toFixed(3)} ms wall, ${((cpuMs(p) - cpu0) / c.n).toFixed(3)} ms process CPU, n=${c.n}, inside ${JSON.parse(text).inside_ms} ms`);
  }
  await mf.dispose();
}

async function cold(rounds = 5) {
  for (const [name, c] of Object.entries(CASES)) {
    const samples = [];
    for (let i = 0; i < rounds; i += 1) {
      const mf = start(bundle);
      await mf.ready;
      await (await call(mf, '/null', 1)).text(); // a request path, warm; the code under test is not
      const t0 = performance.now();
      const nul = await call(mf, '/null', 1);
      await nul.text();
      const control = performance.now() - t0;
      const t1 = performance.now();
      const res = await call(mf, c.path, 1, c.body);
      await res.text();
      samples.push(performance.now() - t1 - control);
      await mf.dispose();
    }
    samples.sort((a, b) => a - b);
    console.log(`cold  ${name}: median ${samples[2].toFixed(1)} ms, min ${samples[0].toFixed(1)}, max ${samples[rounds - 1].toFixed(1)} over ${rounds} fresh workerds, minus a null call`);
  }
}

async function startup(rounds = 5) {
  const time = async (path) => {
    const samples = [];
    for (let i = 0; i < rounds; i += 1) {
      const t0 = performance.now();
      const mf = start(path);
      await mf.ready;
      const res = await mf.dispatchFetch('http://x/null');
      await res.text();
      samples.push(performance.now() - t0);
      await mf.dispose();
    }
    return samples.sort((a, b) => a - b)[2];
  };
  const a = await time(empty);
  const b = await time(bundle);
  console.log(`start empty worker ${a.toFixed(0)} ms, relay bundle ${b.toFixed(0)} ms, difference ${(b - a).toFixed(0)} ms, medians of ${rounds}`);
}

try {
  await warm();
  await cold();
  await startup();
} finally {
  rmSync(dir, { recursive: true, force: true });
}
