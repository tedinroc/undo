// A stand-in for an ntfy server on 127.0.0.1, for the watcher's tests. It takes ntfy's two publish forms (JSON to
// `/`, and a body to `/<topic>` with headers), answers the way ntfy does, and keeps every message with the time it
// arrived. `failNext(n, status)` makes the next n publishes fail, for retry tests. It never forwards anything.
//
//   const ntfy = await startMockNtfy();   ntfy.url   ntfy.messages   await ntfy.waitFor((m) => ..., 10_000)
//
// Run as a script, it stays up and prints each message:  node tools/test/mock-ntfy.mjs [PORT]
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { fileURLToPath } from 'node:url';

const TOPIC = /^[A-Za-z0-9_-]{1,64}$/;

export async function startMockNtfy({ port = 0, log = null } = {}) {
  const messages = [];
  const listeners = new Set();
  let failures = [];
  const server = createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks).toString('utf8');
    const url = new URL(req.url, 'http://local');
    const reply = (status, obj) => {
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(`${JSON.stringify(obj)}\n`);
    };
    if (req.method === 'GET') {
      // Poll form: GET /<topic>/json?poll=1, the cached messages of one topic.
      const topic = url.pathname.split('/')[1];
      const lines = messages.filter((m) => m.topic === topic).map((m) => JSON.stringify({ id: m.id, time: Math.floor(m.receivedAt / 1000), event: 'message', topic, title: m.title, message: m.message, click: m.click }));
      res.writeHead(200, { 'content-type': 'application/x-ndjson' });
      res.end(lines.length ? `${lines.join('\n')}\n` : '');
      return;
    }
    if (req.method !== 'POST' && req.method !== 'PUT') return reply(405, { code: 40500, http: 405, error: 'method not allowed' });
    const failure = failures.shift();
    if (failure) return reply(failure, { code: failure * 100, http: failure, error: 'mock failure' });
    let msg;
    if (url.pathname === '/' || url.pathname === '') {
      let json;
      try {
        json = JSON.parse(body);
      } catch {
        return reply(400, { code: 40024, http: 400, error: 'invalid request: request body must be message JSON' });
      }
      msg = { topic: json.topic, title: json.title ?? null, message: json.message ?? '', priority: json.priority ?? 3, click: json.click ?? null, actions: json.actions ?? [], tags: json.tags ?? [], form: 'json' };
    } else {
      msg = {
        topic: url.pathname.slice(1), title: req.headers.title ?? req.headers['x-title'] ?? null, message: body, priority: Number(req.headers.priority ?? req.headers['x-priority'] ?? 3), click: req.headers.click ?? req.headers['x-click'] ?? null, actions: [], tags: [], form: 'path',
      };
    }
    if (!TOPIC.test(msg.topic ?? '')) return reply(400, { code: 40009, http: 400, error: 'invalid topic' });
    if (Buffer.byteLength(msg.message) > 4096) return reply(413, { code: 41301, http: 413, error: 'message too large' });
    const receivedAt = Date.now();
    const stored = { id: randomBytes(6).toString('base64url'), receivedAt, query: url.search, ...msg };
    messages.push(stored);
    log?.(stored);
    for (const l of [...listeners]) l(stored);
    return reply(200, { id: stored.id, time: Math.floor(receivedAt / 1000), expires: Math.floor(receivedAt / 1000) + 43200, event: 'message', topic: stored.topic, title: stored.title ?? undefined, message: stored.message, priority: stored.priority, click: stored.click ?? undefined });
  });
  await new Promise((r) => { server.listen(port, '127.0.0.1', r); });
  const url = `http://127.0.0.1:${server.address().port}`;
  return {
    url,
    messages,
    failNext(n, status = 503) {
      failures = [...failures, ...Array(n).fill(status)];
    },
    /** Resolves with the first message, already here or still to come, that `match` accepts. Rejects after timeoutMs. */
    waitFor(match, timeoutMs) {
      const found = messages.find(match);
      if (found) return Promise.resolve(found);
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          listeners.delete(listener);
          reject(new Error('mock ntfy: no matching message in time'));
        }, timeoutMs);
        const listener = (m) => {
          if (!match(m)) return;
          clearTimeout(timer);
          listeners.delete(listener);
          resolve(m);
        };
        listeners.add(listener);
      });
    },
    stop: () => new Promise((r) => {
      server.closeAllConnections?.();
      server.close(() => r());
    }),
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const ntfy = await startMockNtfy({ port: Number(process.argv[2] ?? 0), log: (m) => console.log(`${new Date(m.receivedAt).toISOString()} ${m.title ?? ''} | ${m.message.split('\n')[0]} | tap ${m.click ?? '-'}`) });
  console.log(`mock ntfy on ${ntfy.url}`);
}
