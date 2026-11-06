# Phone alerts: `tools/watch.mjs`

A thief with your spend key does not need the relay or the page. Any NEAR account can send `propose_btc` with near-cli. So the alert does not come from the relay. A small watcher on your own computer reads your vault's queue from public NEAR RPC. For each new Pending request it pushes one alert to your phone through [ntfy](https://ntfy.sh). How the request was sent does not matter.

The watcher holds no key, signs nothing and sends no transaction. It reads public views (`vault`, `request`, `block`) and makes one HTTPS POST per alert.

## What an alert says

```
Undo for Bitcoin: a spend is waiting
2,000 sats to tb1qkaq3lndkl5… unlocks in 4:58
signet test coins. Not you? Tap to cancel.
https://undo-btc.pages.dev/p/#v=<vault>&r=<request>
```

- **Amount.** Counted the way the phone page counts it: every coin when there is no change, otherwise the amount sent.
- **Destination.** The first 14 characters of the address. The phone page shows all of it.
- **Time.** `unlocks in M:SS` is read off the chain's clock when the alert is sent, and rounded up. If this computer's clock is behind the chain, the later of the two clocks is used, so any error makes the time look shorter, not longer.
- **Link.** Tapping the alert opens the phone page. The vault and the request travel in the `#` fragment, which a browser never sends to a server. There is no query string.

The watcher skips a request that is already signing, was cancelled by a rotation, or has expired, and says so in its log. When an alerted request leaves the queue, the log says whether it was cancelled or executed, and how many seconds after the alert.

## Setup

```
node tools/watch.mjs init --contract <instance>.testnet [--vault <vault id or phone link>]
```

This writes `~/.undo-watch/config.json` with mode 600 and a new random topic of 22 characters (about 131 bits). It prints the topic once, together with the subscribe steps. `init` will not write inside a git work tree, and no other command prints the topic. The fallback RPC list is the same one as in `site/config/testnet.json`. To get a new topic, run `init --force`.

On the phone:

1. Install the ntfy app and open it once. Allow notifications.
2. Tap **+**, type the topic exactly, keep the server `ntfy.sh`, then tap **Subscribe**.
3. iPhone: go to **Settings > Notifications > ntfy** and turn on Allow, Lock Screen and Banners. Set **Show Previews** to **Always**. With the default, When Unlocked, the lock screen shows only that a notification came, not what it says. Check that no Focus mode silences ntfy.

Then:

```
node tools/watch.mjs phone-test                       # 5 test pushes, see below
caffeinate -i node tools/watch.mjs run --vault <id or phone link>
node tools/watch.mjs run --dry-run --once             # prints what it would send, sends nothing
```

`caffeinate -i` keeps a Mac awake while it watches. A computer that is asleep or offline sends nothing. The state file next to the config records every request already alerted, so a restart sends nothing twice. If the watcher stopped after marking an alert but before ntfy answered, the restart sends that one again with "(may repeat)" in the title. A dry run keeps its own state file and never touches the real one.

## Before you rely on it: 5 pushes on your phone

ntfy's delivery to a phone was not tested here. Run `phone-test` on the phone you will use, and again before any film or demo shows an alert. It sends 5 alerts marked TEST, one each time you press Enter. Lock the phone and lay it face up. Press Enter again the moment the screen lights up. At the end it asks two questions: did the locked screen show the words, and did the topic appear anywhere? It passes only if all 5 arrived within 10 seconds, the words were visible while locked, and the topic was not shown. The result is saved next to the config. That file names the topic by a one-way tag and does not contain the topic itself. Until a test passes, `run` prints a reminder.

These times come from a person pressing Enter, so allow about a third of a second for reaction time. They measure ntfy to the phone only. The watcher's log has the part before that.

## How fast

**Local, one run on 2026-11-07 [mock-signer].** Setup: a local NEAR sandbox, the mock signer, a mock ntfy on the same computer, and the default 2 s poll. Over 12 alerts, the time from the `propose_btc` block to ntfy's answer had a median of 1.17 s, and ranged from 0.74 to 1.75 s. Almost all of it was waiting for the next poll. The push itself took about 0.01 s.

**Testnet, read only, the same day [live-testnet].** Each RPC was read 8 times.

| RPC | Median `vault` read |
|---|---|
| `test.rpc.fastnear.com` | 0.40 s |
| `near-testnet.drpc.org` | 0.22 s |
| `rpc.testnet.near.org` | 3.45 s |

The first read on each connection was slower. The latest optimistic block was 0.8 to 1.7 s old when it arrived.

So on testnet an alert should leave about 1 to 3 s after its block. That is an estimate, not a measurement. Not measured at all:

- ntfy.sh to Firebase to Apple or Google, then to the phone
- the difference between this computer's clock and the chain's

Each alert's numbers are written to `state-*.log.jsonl` next to the config: `latency_ms` from block to ntfy, `detect_ms` from block to the read that saw it, `push_ms` from that read to ntfy, and `clock_skew_ms`.

## What ntfy.sh, and anyone with the topic, can see

**The whole message.** That is the amount, the destination prefix, the unlock time, and the vault id and request number in the link. All of these are already public on NEAR: the queue shows each request's amount and destination before any Bitcoin moves. What the alert adds is a link between this vault and the IP address of the computer sending it and the phone receiving it. ntfy.sh sees that link.

- **Stored for a while.** ntfy.sh keeps messages for 12 hours by default, so a phone that was offline can still fetch them.
- **Passed to the phone's push service.** ntfy.sh also passes each message to Firebase Cloud Messaging. iPhones receive it through Apple's push service.
- **Topics are public.** On ntfy.sh, anyone who knows the topic can read the cached alerts and post their own. A fake alert could carry a fake link. Only follow a link to the page you use, and trust what that page reads from the contract, not what an alert says. Keep the topic out of screenshots, films and repos.
- **Self-hosting.** You can run your own ntfy server and pass `--ntfy-server`. For instant delivery to an iPhone, a self-hosted server still sends ntfy.sh a "poll request" carrying only the message id, and the phone fetches the content from your server.

Sources: ntfy's publishing, configuration and known-issues pages, read 2026-11-06 **[R]**.

## iPhone delivery: what can go wrong

From ntfy's known-issues page **[R]**, not checked on a phone here:

- The banner may appear while the app's own list doesn't refresh until you pull it down.
- Notifications can stop arriving altogether. ntfy blames Firebase and APNs for this. Removing the subscription and adding it again usually fixes it.
- An alert that reads "New message" with no text means the phone could not fetch the content.

From general knowledge of iOS, not measured:

- Show Previews set to When Unlocked hides the text on the lock screen.
- Focus modes and Low Power Mode can hold back or silence alerts.
- If the app was never opened after install, it may receive nothing.

ntfy.sh's limits per visitor IP **[R]**: 60 requests in a burst, then one every 5 seconds; 250 messages a day; 4,096 bytes per message. One alert is one request.

**No alert does not mean nothing is waiting.** If the watcher cannot read NEAR, it prints `READ FAILED` and, after 30 s, `BLIND`. If ntfy refuses an alert, it prints `ALERT NOT SENT` and retries on every poll while the request waits. Either way, no alert reaches the phone. The phone page and the `status` view are the record. An alert is only a reason to open them.

## Tests

```
node --test tools/test/watch.test.mjs          # offline: stand-in RPC and ntfy on 127.0.0.1
node tools/test/watch-sandbox.mjs              # the real wasm on a local NEAR node, mock signer, mock ntfy
```

The sandbox test proposes three ways and expects exactly one alert for each:

- with near-cli, signed by a stranger's account, with no relay involved
- through the relay's own handler (`site/functions/_relay/handler.mjs`, run in Node)
- directly from `tools/lib`

It then checks that a restart sends nothing twice and that a dry run sends nothing. It prints the latency of every alert.

It needs `NEAR_SANDBOX_BIN_PATH`, `UNDO_WASM_DIR` and `UNDO_NEAR_BIN`. near-cli runs with a throwaway HOME that knows only the sandbox network, and on macOS under `sandbox-exec` with everything but localhost denied. The tests reach no live host.

Under a sandbox that blocks the keychain, `NODE_USE_SYSTEM_CA=1` makes Node 22 hang at exit after any `fetch`. If a run never exits, unset that variable.
