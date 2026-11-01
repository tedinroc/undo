// One headless Chrome, driven over CDP, with a virtual authenticator so navigator.credentials really runs.
// Every agent on this machine may run at most one: call stop() in `after`, and it is killed with its profile.
import { spawn } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const CHROME = process.env.CHROME_BIN ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';

export const chromeAvailable = () => existsSync(CHROME);

export class Cdp {
  constructor(ws) {
    this.ws = ws;
    this.id = 0;
    this.waiting = new Map();
    ws.addEventListener('message', (event) => {
      const data = JSON.parse(event.data);
      const pending = this.waiting.get(data.id);
      if (!pending) return;
      this.waiting.delete(data.id);
      if (data.error) pending.reject(new Error(JSON.stringify(data.error)));
      else pending.resolve(data.result);
    });
  }

  send(method, params = {}) {
    const id = (this.id += 1);
    return new Promise((resolve, reject) => {
      this.waiting.set(id, { resolve, reject });
      this.ws.send(JSON.stringify({ id, method, params }));
    });
  }

  /** Runs an async function body in the page and returns its JSON value, or throws what the page threw. */
  async page(body) {
    const { result, exceptionDetails } = await this.send('Runtime.evaluate', { expression: `(async () => { ${body} })()`, awaitPromise: true, returnByValue: true, userGesture: true });
    if (exceptionDetails) throw new Error(`page threw: ${exceptionDetails.exception?.description ?? exceptionDetails.text}`);
    return result.value;
  }

  async open(url) {
    await this.send('Page.navigate', { url });
    for (let i = 0; i < 100; i += 1) {
      const { result } = await this.send('Runtime.evaluate', { expression: 'location.href + " " + document.readyState', returnByValue: true });
      if (result.value.startsWith(url) && result.value.endsWith('complete')) return;
      await new Promise((r) => setTimeout(r, 50));
    }
    throw new Error('the page did not load');
  }
}

export async function startChrome({ width = null, height = null, scale = null, headless = true } = {}) {
  const profile = mkdtempSync(join(process.env.TMPDIR ?? tmpdir(), 'undo-chrome-'));
  const flags = [headless ? '--headless=new' : null, '--remote-debugging-port=0', `--user-data-dir=${profile}`, '--no-first-run', '--no-default-browser-check', '--disable-extensions', '--disable-gpu', 'about:blank'].filter(Boolean);
  const chrome = spawn(CHROME, flags, { stdio: ['ignore', 'ignore', 'pipe'] });
  const wsUrl = await new Promise((resolve, reject) => {
    let text = '';
    const timer = setTimeout(() => reject(new Error('Chrome gave no debugging URL')), 30_000);
    chrome.stderr.on('data', (chunk) => {
      text += chunk;
      const match = text.match(/DevTools listening on (ws:\/\/\S+)/);
      if (match) {
        clearTimeout(timer);
        resolve(match[1]);
      }
    });
    chrome.on('exit', () => reject(new Error('Chrome exited')));
  });
  const { port } = new URL(wsUrl);
  const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
  const ws = new WebSocket(list.find((t) => t.type === 'page').webSocketDebuggerUrl);
  await new Promise((resolve, reject) => {
    ws.addEventListener('open', resolve);
    ws.addEventListener('error', reject);
  });
  const cdp = new Cdp(ws);
  await cdp.send('Page.enable');
  await cdp.send('Runtime.enable');
  if (width) await cdp.send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: scale ?? 1, mobile: false });
  return {
    cdp,
    /** navigator.credentials on this tab now answers from Chrome's virtual authenticator, with no sheet. */
    async addPasskeyDevice() {
      await cdp.send('WebAuthn.enable');
      await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } });
    },
    async stop() {
      ws.close();
      chrome.kill('SIGKILL');
      await new Promise((r) => setTimeout(r, 300));
      rmSync(profile, { recursive: true, force: true });
    },
  };
}
