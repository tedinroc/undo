#!/usr/bin/env node
// The testnet Pages output under `wrangler pages dev`, which applies _headers, _routes.json and Pages' folder redirects
// the way the live site will, and in one Chrome with every public host blocked. So it reads the live labels and the live
// CSP on real pages and sends nothing anywhere. No secret is set and no Durable Object runs, so the relay is off, and
// the pages must say so. It does not log in, deploy or read an account: wrangler runs with a blank home.
//
//   node tools/test/pages-dev-check.mjs        Needs UNDO_WRANGLER_MODULES and Chrome. Exits 0 only if all pass.
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { build } from '../../site/build.mjs';
import { chromeAvailable, startChrome } from '../../site/test/chrome.mjs';

const SITE = resolve(dirname(fileURLToPath(import.meta.url)), '../../site');
const modules = process.env.UNDO_WRANGLER_MODULES;
if (!modules || !chromeAvailable()) {
  console.error('pages-dev-check: needs UNDO_WRANGLER_MODULES and Chrome. Nothing ran.');
  process.exit(2);
}
const sleep = (ms) => new Promise((r) => { setTimeout(r, ms); });
const results = [];
const check = (name, ok, detail = '') => {
  results.push(Boolean(ok));
  console.log(`${ok ? 'PASS' : 'FAIL'} ${name}${detail === '' ? '' : `: ${detail}`}`);
};
const freePort = () => new Promise((res) => {
  const s = createServer().listen(0, '127.0.0.1', () => {
    const { port } = s.address();
    s.close(() => res(port));
  });
});

const config = JSON.parse(readFileSync(join(SITE, 'config/testnet.json'), 'utf8'));
const publicHosts = [...config.rpc, config.esplora].map((u) => `*${new URL(u).hostname}*`);
const home = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'undo-pages-dev-'));
const port = await freePort();
const origin = `http://127.0.0.1:${port}`;
build({ configPath: join(SITE, 'config/testnet.json'), allowUnfilled: true });
const wrangler = spawn(process.execPath, [join(modules, 'wrangler/bin/wrangler.js'), 'pages', 'dev', '--port', String(port), '--ip', '127.0.0.1'], {
  cwd: SITE,
  stdio: ['ignore', 'pipe', 'pipe'],
  detached: true,
  env: { PATH: process.env.PATH, HOME: home, XDG_CONFIG_HOME: join(home, 'xdg'), WRANGLER_SEND_METRICS: 'false', WRANGLER_LOG_PATH: join(home, 'logs'), CI: '1' },
});
let wranglerLog = '';
wrangler.stdout.on('data', (c) => { wranglerLog += c; });
wrangler.stderr.on('data', (c) => { wranglerLog += c; });

let chrome = null;
async function stop() {
  await chrome?.stop().catch(() => {});
  try {
    process.kill(-wrangler.pid, 'SIGKILL');
  } catch {
    // Already gone.
  }
  await sleep(300);
  for (const path of [home, join(SITE, '.wrangler'), join(SITE, 'dist')]) rmSync(path, { recursive: true, force: true });
}

const noFollow = (path) => fetch(`${origin}${path}`, { redirect: 'manual' });
try {
  let up = false;
  for (let i = 0; i < 120 && !up; i += 1) {
    await sleep(500);
    up = await fetch(`${origin}/undo-config.json`).then((r) => r.ok).catch(() => false);
  }
  if (!up) throw new Error(`wrangler pages dev never answered:\n${wranglerLog.slice(-1500)}`);

  for (const path of ['/t', '/p', '/thief', '/phone']) {
    const res = await noFollow(path);
    check(`${path} redirects to its folder`, res.status >= 300 && res.status < 400 && res.headers.get('location')?.endsWith(`${path}/`), `${res.status} ${res.headers.get('location')}`);
  }
  for (const path of ['/t/', '/p/', '/thief/', '/phone/']) {
    const res = await noFollow(path);
    const csp = res.headers.get('content-security-policy') ?? '';
    check(`${path} is served with the built CSP`, res.status === 200 && csp.includes("script-src 'self'") && csp.includes('connect-src') && !csp.includes('127.0.0.1'), res.status);
    check(`${path} is served with a referrer policy`, res.headers.get('referrer-policy') === 'no-referrer');
    await res.arrayBuffer();
  }
  const root = await noFollow('/');
  const rootText = await root.text();
  console.log(`NOTE / answers ${root.status}, ${rootText.length} bytes${root.status === 200 ? '' : ': the landing page does not exist yet'}`);
  const headersFile = await noFollow('/_headers');
  check('/_headers is not served', headersFile.status === 404, headersFile.status);
  await headersFile.arrayBuffer();
  const status = await fetch(`${origin}/api/relay`);
  const statusBody = await status.json();
  check('/api/relay reaches the Function and says it has no secrets', statusBody.code === 'relay_not_configured', `${status.status} ${statusBody.code}`);
  check('its answer carries no key name or value', !JSON.stringify(statusBody).match(/RELAY_|DISPENSER|ed25519/));
  const funds = await fetch(`${origin}/api/funds`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
  check('/api/funds answers JSON', (await funds.json()).ok === false, funds.status);
  const missing = await noFollow('/api/other');
  check('an unknown /api path is refused by the Function', missing.status === 404, missing.status);
  await missing.arrayBuffer();

  chrome = await startChrome({ width: 1080, height: 1350, scale: 1 });
  const { cdp } = chrome;
  const csp = [];
  const exceptions = [];
  await cdp.send('Network.enable');
  await cdp.send('Log.enable');
  await cdp.send('Network.setBlockedURLs', { urls: publicHosts });
  cdp.ws.addEventListener('message', (event) => {
    const { method, params } = JSON.parse(event.data);
    if (method === 'Log.entryAdded' && /Content Security Policy/i.test(params.entry.text)) csp.push(params.entry.text);
    if (method === 'Runtime.exceptionThrown') exceptions.push(params.exceptionDetails.exception?.description ?? params.exceptionDetails.text);
  });
  const js = (expr) => cdp.page(`return (${expr});`);
  const open = async (path) => {
    await cdp.send('Page.navigate', { url: 'about:blank' });
    await sleep(100);
    await cdp.send('Page.navigate', { url: `${origin}${path}` });
    await sleep(2500);
  };

  await open('/t/');
  check('thief tab, no vault: the live chip', (await js('document.getElementById("chip").textContent')) === 'signet test coins');
  check('thief tab, no vault: says so', (await js('document.getElementById("root").dataset.state')) === 'no_vault', await js('document.getElementById("plain-text").textContent'));
  await open(`/t/#v=${'ab'.repeat(32)}&k=${'cd'.repeat(32)}`);
  await sleep(3000);
  check('thief tab, RPC blocked: the key is out of the address bar', !(await js('location.hash')).includes('k='));
  check('thief tab, RPC blocked: says it cannot read NEAR', /Can't read the NEAR contract/.test(await js('document.getElementById("plain-text").textContent')), await js('document.getElementById("plain-text").textContent'));
  await open('/p/');
  check('phone, no vault: the live chip', (await js('document.getElementById("chip").textContent')) === 'signet test coins');
  await sleep(4000);
  const text = await js('document.body.innerText');
  check('phone, RPC blocked: says it cannot read NEAR, and offers nothing to tap', /Can't read the NEAR contract/.test(text) && !(await js('Boolean(document.querySelector("#cancel, #make"))')), text.replace(/\s+/g, ' ').slice(0, 120));
  check('no CSP violation on any page', csp.length === 0, csp.slice(0, 2).join(' | '));
  check('no uncaught exception on any page', exceptions.length === 0, exceptions.slice(0, 2).join(' | '));
} catch (err) {
  check('the check ran', false, err.message);
} finally {
  await stop();
}
const failed = results.filter((ok) => !ok).length;
console.log(`pages-dev-check: ${results.length - failed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
