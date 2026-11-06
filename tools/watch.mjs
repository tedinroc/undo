#!/usr/bin/env node
// Watches one vault and pushes a phone alert for every new Pending request, however it was proposed: through the
// relay, with near-cli, or from any other account. Read-only public RPC in, one ntfy message per request out.
//
//   node tools/watch.mjs init --contract ID [--vault ID|LINK] [--network testnet|local] [--config PATH]
//   node tools/watch.mjs run [--vault ID|LINK] [--dry-run] [--once] [--config PATH]
//   node tools/watch.mjs phone-test [--count 5] [--limit-s 10] [--config PATH]
//
// The config holds the ntfy topic, which is the only thing between a stranger and these alerts. `init` writes it
// with mode 600 and refuses any folder inside a git work tree. Nothing else ever prints the topic. docs/watch.md
// says what ntfy.sh and the phone's push service can see, and how to check delivery before relying on it.
import { appendFileSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { parseArgs, UsageError } from './lib/args.mjs';
import {
  CONFIG_FORMAT, ConfigError, contractReads, DEFAULT_NTFY, DEFAULT_PAGE_ORIGIN, gitTreeAbove, loadWatchConfig, makeTopic, NETWORKS, ntfyPublisher, RpcDown, RpcPool,
  StateStore, statePathFor, TESTNET_RPC, testAlert, topicTag, vaultFrom, Watcher, writePrivateFile, checkWatchConfig,
} from './lib/watch.mjs';

const DEFAULT_CONFIG = process.env.UNDO_WATCH_CONFIG || join(homedir(), '.undo-watch', 'config.json');
const STATUS_EVERY_MS = 60_000;
const BLIND_AFTER_MS = 30_000;

const stamp = (ms = Date.now()) => {
  const d = new Date(ms);
  return `${d.toTimeString().slice(0, 8)}.${String(d.getMilliseconds()).padStart(3, '0')}`;
};
const say = (line) => console.log(`${stamp()} ${line}`);
const short = (vault) => `${vault.slice(0, 8)}…${vault.slice(-4)}`;
export const logPathFor = (statePath) => statePath.replace(/\.json$/, '.log.jsonl');
const phoneTestPath = (configPath, topic) => join(dirname(resolve(configPath)), `phone-test-${topicTag(topic)}.json`);

function usage() {
  console.error('usage: node tools/watch.mjs init|run|phone-test [flags]   (see the head of this file, or docs/watch.md)');
  process.exit(2);
}

// ---------------------------------------------------------------- init

function init(argv) {
  const a = parseArgs(argv, {
    network: 'text', contract: 'text', vault: 'text', rpc: 'text', 'page-origin': 'text', 'ntfy-server': 'text', config: 'text', 'poll-ms': 'int', priority: 'int', force: 'flag',
  });
  const network = a.network ?? 'testnet';
  if (!Object.hasOwn(NETWORKS, network)) throw new UsageError('--network must be testnet or local. There is no mainnet watcher');
  if (!a.contract) throw new UsageError('--contract is needed: the Undo instance this vault lives on');
  const vault = a.vault === undefined ? null : vaultFrom(a.vault);
  if (a.vault !== undefined && !vault) throw new UsageError('--vault must be a vault id or a phone-page link with #v=');
  const local = network === 'local';
  const rpc = a.rpc ? a.rpc.split(',').map((u) => u.trim()).filter(Boolean) : local ? null : [...TESTNET_RPC];
  if (!rpc) throw new UsageError('--rpc is needed in local mode');
  if (local && (!a['page-origin'] || !a['ntfy-server'])) throw new UsageError('--page-origin and --ntfy-server are needed in local mode, both on this machine');
  const path = resolve(a.config ?? DEFAULT_CONFIG);
  const tree = gitTreeAbove(path);
  if (tree) throw new ConfigError(`config: ${path} is inside a git work tree. The topic must never be committed: pick a folder outside any repo`);
  const raw = {
    format: CONFIG_FORMAT,
    network,
    contract: a.contract,
    vault,
    rpc,
    page_origin: a['page-origin'] ?? DEFAULT_PAGE_ORIGIN,
    ntfy_server: a['ntfy-server'] ?? DEFAULT_NTFY,
    ntfy_topic: makeTopic(),
    priority: a.priority ?? 5,
    poll_ms: a['poll-ms'] ?? 2000,
  };
  const config = checkWatchConfig(raw);
  writePrivateFile(path, `${JSON.stringify(raw, null, 2)}\n`, { force: Boolean(a.force) });
  const server = new URL(config.ntfy_server).host;
  console.log(`Wrote ${path} (mode 600). It holds your ntfy topic: keep it out of every repo, screenshot and film.`);
  console.log('');
  console.log('On the phone that will cancel:');
  console.log('  1. Install the ntfy app (App Store: "ntfy", by Philipp Heckel; or Google Play / F-Droid).');
  console.log('  2. Open it and allow notifications when it asks.');
  console.log(`  3. Tap +, type this topic exactly, keep the server ${server}, and tap Subscribe:`);
  console.log('');
  console.log(`       ${config.ntfy_topic}`);
  console.log('');
  console.log('  4. iPhone: Settings > Notifications > ntfy: Allow, Lock Screen, Banners, Show Previews: Always.');
  console.log('     Check that no Focus mode silences ntfy.');
  console.log('');
  console.log('Then, on this machine:');
  console.log('  node tools/watch.mjs phone-test          5 test pushes, press Enter as each one shows; needs 5/5 within 10 s');
  console.log(`  node tools/watch.mjs run${vault ? '' : ' --vault <vault id or phone link>'}      watch and alert`);
  console.log('');
  console.log(`Anyone who learns the topic can read these alerts and send fake ones. Make a new one any time: init --force (${config.labels.label}).`);
}

// ---------------------------------------------------------------- run

function interruptibleSleep() {
  let wake = null;
  return {
    sleep: (ms) => new Promise((r) => {
      const t = setTimeout(() => { wake = null; r(); }, ms);
      wake = () => { clearTimeout(t); wake = null; r(); };
    }),
    wake: () => wake?.(),
  };
}

async function run(argv) {
  const a = parseArgs(argv, { config: 'text', vault: 'text', 'dry-run': 'flag', once: 'flag', 'poll-ms': 'int', state: 'text' });
  const configPath = resolve(a.config ?? DEFAULT_CONFIG);
  const config = loadWatchConfig(configPath);
  const vault = a.vault !== undefined ? vaultFrom(a.vault) : config.vault;
  if (!vault) throw new UsageError(a.vault !== undefined ? '--vault must be a vault id or a phone-page link with #v=' : 'no vault: pass --vault <vault id or phone link>');
  const dryRun = Boolean(a['dry-run']);
  const pollMs = a['poll-ms'] ?? config.poll_ms;
  if (pollMs < config.labels.minPollMs) throw new UsageError(`--poll-ms must be at least ${config.labels.minPollMs} on ${config.network}`);
  const statePath = resolve(a.state ?? statePathFor(configPath, { contract: config.contract, vault, dryRun }));
  const logPath = logPathFor(statePath);
  const label = config.labels.label;

  const pool = new RpcPool(config.rpc);
  const reads = contractReads(pool, config.contract);
  const state = new StateStore(statePath, { contract: config.contract, vault, network: config.network });
  const record = (obj) => {
    try {
      appendFileSync(logPath, `${JSON.stringify({ at: Date.now(), network: config.network, ...obj })}\n`, { mode: 0o600 });
    } catch {
      // The JSON log is for measuring. An alert never waits on it.
    }
  };
  const push = dryRun ? null : ntfyPublisher({ server: config.ntfy_server, topic: config.ntfy_topic });
  const pause = interruptibleSleep();
  const watcher = new Watcher({ config, vault, reads, push, state, log: say, record, dryRun, sleep: pause.sleep });

  let stopping = false;
  const stop = () => {
    stopping = true;
    pause.wake();
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);

  const where = new URL(config.ntfy_server).host;
  say(`WATCH ${label} vault ${short(vault)} on ${config.labels.near} contract ${config.contract}, every ${(pollMs / 1000).toFixed(1)} s. Alerts ${dryRun ? 'printed here, not sent (dry run)' : `to ${where}, topic from the config, not shown`}.`);
  if (!dryRun && config.network !== 'local' && !existsSync(phoneTestPath(configPath, config.ntfy_topic))) {
    say('NOTE no phone test has passed for this topic yet. Run: node tools/watch.mjs phone-test. Until it passes 5/5, no film shows this alert.');
  }

  // A node on the wrong network would answer every view with "no such account", which reads like a quiet vault.
  for (let i = 0; !stopping; i += 1) {
    try {
      const chainId = await reads.chainId();
      const want = config.labels.chainId;
      if (want ? chainId !== want : chainId === 'mainnet' || chainId === 'testnet') {
        say(`STOP ${label} the RPC answers for chain ${chainId}, not ${want ?? 'a local node'}. Nothing was watched.`);
        process.exit(1);
      }
      break;
    } catch (err) {
      say(`READ FAILED ${label} status: ${err.message}. Trying again.`);
      if (a.once) process.exit(1);
      await pause.sleep(Math.min(pollMs * (i + 1), 15_000));
    }
  }

  let ready = false;
  let failingSince = null;
  let lastStatus = Date.now();
  let lastPending = [];
  while (!stopping) {
    try {
      const { vault: v, events } = await watcher.pollOnce();
      if (v === null) {
        say(`NO VAULT ${label} ${short(vault)} is not on ${config.contract}. Check --vault and the config's contract.`);
        if (a.once) process.exit(1);
      } else {
        lastPending = v.pending;
        if (!ready) {
          ready = true;
          say(`READY ${label} first read from ${pool.lastHost}: ${v.pending.length} pending${v.pending.length ? ` (${v.pending.join(', ')})` : ''}.`);
        }
      }
      if (failingSince) say(`READ OK ${label} again, after ${((Date.now() - failingSince) / 1000).toFixed(0)} s blind.`);
      failingSince = null;
      if (events.some((e) => e.kind === 'push_failed')) say(`ALERT NOT SENT ${label}: the next poll tries again. Watch the phone page by hand meanwhile.`);
    } catch (err) {
      const now = Date.now();
      if (!failingSince) failingSince = now;
      const blind = now - failingSince;
      const detail = err instanceof RpcDown ? err.tried.map((t) => `${t.host} ${t.status ?? t.cause ?? t.error}`).join(', ') : err.message;
      say(`${blind >= BLIND_AFTER_MS ? 'BLIND' : 'READ FAILED'} ${label} ${err.message}${detail && detail !== err.message ? ` (${detail})` : ''}${blind >= BLIND_AFTER_MS ? `: no read for ${(blind / 1000).toFixed(0)} s, so no alert can come. Watch the phone page by hand.` : ''}`);
      if (a.once) process.exit(1);
    }
    if (a.once) break;
    if (Date.now() - lastStatus >= STATUS_EVERY_MS) {
      lastStatus = Date.now();
      say(`OK ${label} ${watcher.polls} reads, pending [${lastPending.join(', ')}], last RPC ${pool.lastHost ?? 'none'}.`);
    }
    await pause.sleep(pollMs);
  }
  state.save();
  say(`STOPPED ${label} after ${watcher.polls} reads. State kept, so a restart sends nothing twice.`);
  process.exit(0);
}

// ---------------------------------------------------------------- phone test

function lineReader() {
  const rl = createInterface({ input: process.stdin, terminal: false });
  const lines = [];
  const waiters = [];
  let ended = false;
  rl.on('line', (line) => {
    const w = waiters.shift();
    if (w) w.resolve(line);
    else lines.push(line);
  });
  rl.on('close', () => {
    ended = true;
    for (const w of waiters.splice(0)) w.resolve(null);
  });
  return {
    next(timeoutMs) {
      if (lines.length) return Promise.resolve(lines.shift());
      if (ended) return Promise.resolve(null);
      return new Promise((resolveLine) => {
        const w = { resolve: (v) => { clearTimeout(w.timer); resolveLine(v); } };
        w.timer = setTimeout(() => {
          waiters.splice(waiters.indexOf(w), 1);
          resolveLine(undefined);
        }, timeoutMs);
        waiters.push(w);
      });
    },
    close: () => rl.close(),
  };
}

async function phoneTest(argv) {
  const a = parseArgs(argv, { config: 'text', count: 'int', 'limit-s': 'int', 'wait-s': 'int', 'dry-run': 'flag' });
  const configPath = resolve(a.config ?? DEFAULT_CONFIG);
  const config = loadWatchConfig(configPath);
  const count = a.count ?? 5;
  const limitMs = (a['limit-s'] ?? 10) * 1000;
  const waitMs = (a['wait-s'] ?? 30) * 1000;
  if (count < 1 || count > 20) throw new UsageError('--count must be 1 to 20');
  const push = a['dry-run'] ? async (alert) => { console.log(`DRY RUN would push: ${alert.title} | ${alert.message.split('\n')[0]}`); return { id: null }; } : ntfyPublisher({ server: config.ntfy_server, topic: config.ntfy_topic });
  const input = lineReader();
  console.log(`Phone test: ${count} pushes to ${new URL(config.ntfy_server).host}. Lock the phone and lay it face up where you can see it.`);
  console.log('After each push, press Enter the moment the phone lights up with it. Type m and Enter if it never comes.');
  const results = [];
  for (let i = 1; i <= count; i += 1) {
    console.log('');
    console.log(`Press Enter to send ${i}/${count}.`);
    if ((await input.next(10 * 60_000)) == null) break;
    let sentAt;
    let id;
    try {
      ({ id } = await push(testAlert({ config, index: i, count })));
      sentAt = Date.now();
    } catch (err) {
      console.log(`  ${i}/${count} NOT SENT: ${err.message}`);
      results.push({ index: i, sent: false, error: err.message });
      continue;
    }
    console.log(`  sent ${i}/${count} at ${stamp(sentAt)}${id ? `, ntfy id ${id}` : ''}. Waiting for your Enter (up to ${waitMs / 1000} s)...`);
    const line = await input.next(waitMs);
    const seenMs = Date.now() - sentAt;
    if (line === undefined || line === null || line.trim().toLowerCase() === 'm') {
      console.log(`  ${i}/${count} MISSED`);
      results.push({ index: i, sent: true, seen: false });
    } else {
      console.log(`  ${i}/${count} seen after ${(seenMs / 1000).toFixed(1)} s${seenMs > limitMs ? ` (over ${limitMs / 1000} s)` : ''}`);
      results.push({ index: i, sent: true, seen: true, seen_ms: seenMs });
    }
  }
  const ask = async (question) => {
    console.log('');
    console.log(`${question} [y/n]`);
    const answer = await input.next(10 * 60_000);
    return typeof answer === 'string' && /^y/i.test(answer.trim()) ? true : typeof answer === 'string' && /^n/i.test(answer.trim()) ? false : null;
  };
  const content = await ask('With the phone locked, did the lock screen show the words (sats, "unlocks in"), not just "ntfy" or "Notification"?');
  const topicShown = await ask('Did any alert show the topic name anywhere on the lock screen or banner?');
  input.close();

  const inTime = results.filter((r) => r.seen && r.seen_ms <= limitMs).length;
  const pass = !a['dry-run'] && results.length === count && inTime === count && content === true && topicShown === false;
  const times = results.map((r) => (r.seen ? (r.seen_ms / 1000).toFixed(1) : r.sent ? 'missed' : 'not sent')).join(' ');
  const summary = `PHONE TEST ${pass ? 'PASS' : 'FAIL'} [live-ntfy, timed by hand] ${inTime}/${count} within ${limitMs / 1000} s: ${times}; lock-screen words ${content === true ? 'yes' : content === false ? 'no' : 'no answer'}; topic shown ${topicShown === true ? 'yes' : topicShown === false ? 'no' : 'no answer'}`;
  console.log('');
  console.log(summary);
  if (!a['dry-run']) {
    const report = { format: 'undo-watch-phone-test-v1', at: Date.now(), topic_tag: topicTag(config.ntfy_topic), server: new URL(config.ntfy_server).host, count, limit_ms: limitMs, results, lock_screen_words: content, topic_shown: topicShown, pass, summary };
    const path = join(dirname(configPath), `phone-test-${topicTag(config.ntfy_topic)}-${Date.now()}.json`);
    writePrivateFile(path, `${JSON.stringify(report, null, 1)}\n`);
    if (pass) writePrivateFile(phoneTestPath(configPath, config.ntfy_topic), `${JSON.stringify(report, null, 1)}\n`, { force: true });
    console.log(`Saved ${path}`);
  }
  if (!pass) {
    console.log('Not good enough to film. Common causes: Show Previews not Always, a Focus mode, Low Power Mode, the app never opened since install. Fix one, then run this again.');
    process.exitCode = 1;
  }
}

// ---------------------------------------------------------------- main

const [command, ...rest] = process.argv.slice(2);
const commands = { init, run, 'phone-test': phoneTest };
if (!Object.hasOwn(commands, command ?? '')) usage();
try {
  await commands[command](rest);
} catch (err) {
  if (err instanceof UsageError || err instanceof ConfigError) {
    console.error(`watch: ${err.message}`);
    process.exit(2);
  }
  throw err;
}
