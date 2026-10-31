#!/usr/bin/env bash
# H2. Creates the three NEAR testnet accounts Undo signs with. A person runs this, because agents do
# not create accounts or use faucets. Keys go to ~/.near-credentials, outside the repo. Testnet only.
#
#   scripts/human/01-testnet-accounts.sh [EXTRA_NAME...]
#
# EXTRA_NAME is a further account to create the same way, without the .testnet ending.
# Safe to run again: an account that is already there and has its key file is skipped.
set -euo pipefail
umask 077
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
NAMES=(undo-btc undo-relay undo-guard)
for extra in "$@"; do
  if ! printf '%s' "$extra" | grep -Eq '^[a-z0-9]+(-[a-z0-9]+)*$'; then
    echo "Not a usable account name: $extra. Stopping." >&2
    exit 1
  fi
  NAMES+=("$extra")
done
RPC=https://test.rpc.fastnear.com
export PATH="$HOME/.local/bin:$PATH"

cat <<PLAN
This will:
  1. Make the private folder beside the repo, if it is not there: the blocked list, the quota log
     and the handoff note. Anything already in it is kept.
  2. Install near-cli 0.30.1 to ~/.local/bin, if near is not there, after checking its checksum.
  3. Ask the NEAR testnet faucet to create and fund these accounts, if they do not exist yet:
PLAN
for n in "${NAMES[@]}"; do echo "       $n.testnet"; done
cat <<PLAN
  4. Save each account's key to ~/.near-credentials/testnet/, readable only by you.
     These are plain files so agents can sign unattended. They hold test keys only.
  5. Print each account's balance.
It costs nothing, touches no mainnet account and sends no money. near-cli also writes its own
settings file under ~/Library/Application Support/near-cli.
PLAN
printf 'Type yes to go ahead: '
read -r answer || answer=""
if [ "$answer" != "yes" ]; then
  echo "Stopped. Nothing was changed."
  exit 0
fi

"$HERE/00-private-setup.sh"
command -v near >/dev/null 2>&1 || "$HERE/install-near-cli.sh"
if ! near --version 2>/dev/null | grep -q '0\.30\.1'; then
  echo "This script was checked against near-cli 0.30.1, and another version is on your PATH. Stopping." >&2
  exit 1
fi

creds="$HOME/.near-credentials/testnet"

account_state() {
  local body
  body="$(curl -s -m 20 -H 'content-type: application/json' "$RPC" \
    -d '{"jsonrpc":"2.0","id":"h2","method":"query","params":{"request_type":"view_account","finality":"final","account_id":"'"$1"'"}}')" || return 1
  case "$body" in
    *UNKNOWN_ACCOUNT*) echo free ;;
    *'"amount"'*) echo taken ;;
    *) return 1 ;;
  esac
}

for n in "${NAMES[@]}"; do
  account="$n.testnet"
  state="$(account_state "$account")" || { echo "Could not read $account from the RPC. Stopping, run this again." >&2; exit 1; }
  if [ "$state" = taken ]; then
    if [ -f "$creds/$account.json" ]; then
      echo "$account already exists and its key is here. Skipping."
      continue
    fi
    echo "$account already exists, and no key for it is on this machine. Someone else may hold it. Stopping." >&2
    exit 1
  fi
  echo "Creating $account"
  near account create-account sponsor-by-faucet-service "$account" autogenerate-new-keypair save-to-legacy-keychain network-config testnet create
  [ -f "$creds/$account.json" ] || { echo "near finished, but $account's key file is not there. Stopping." >&2; exit 1; }
done

chmod -R go-rwx "$HOME/.near-credentials"
for n in "${NAMES[@]}"; do
  near account view-account-summary "$n.testnet" network-config testnet now
done
cat <<DONE

Done. The G1 run needs about 6 NEAR on undo-btc.testnet. If it has less, add some by hand at
near-faucet.io, about 5 minutes. Tell the agents the accounts are ready. Do not paste any key.
DONE
