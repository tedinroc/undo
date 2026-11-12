# The relay's limits

The phone page, the thief tab and `./demo.sh` send their NEAR calls through a relay that pays the gas, and the relay's dispenser sends the test coins. The relay is a convenience: the contract takes the same passkey-signed cancel from any NEAR testnet account (`tools/cancel.mjs` sends one the phone page signed), and the cold key in the recovery file works with no relay.

This page holds the relay's accounting, which the README points to from "Try a cancel yourself".

## Shared limits

The relay's daily limits are shared by everyone who uses it, `./demo.sh` runs included:

- with this tree's defaults, at most 13 new vaults and 20 test coins a day in all;
- the live relay is set higher for the judging window (`CEILING_GENERAL_MICRO=1500000`, `CEILING_FUNDS_SATS=100000`): at most 32 new vaults and 50 test coins a day in all;
- from one IP address, 3 vaults and 2 test coins an hour, counted from 00:00 UTC.

So it can be full. When it is, the phone page says so in a sentence, and `./demo.sh` prints `SKIP demo (relay)` and points to `./verify.sh A` and `B`.

## When the coin count can run one over

The coin count can run one over for each relay fault of one kind: if a coin went out but the relay failed to record it, or its broadcast got no answer and landed anyway, the same vault can get a second coin once its owner spends the first; a request that stalls for over two minutes before its coin goes out can also end with two coins. A coin claim made before 00:00 UTC and taken over after it counts on the earlier day, the day it was charged.

## Where this is in the code

`site/lib/relay-table.mjs` has each relayed method's cost and its limit per address; `site/functions/_relay/handler.mjs` and `site/functions/_relay/funds.mjs` have the daily ceilings and the dispenser; `worker/undo-cron/src/undo-state.mjs` keeps the counts.
