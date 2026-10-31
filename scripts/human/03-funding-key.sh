#!/usr/bin/env bash
# H9, on 11/5 and only if the mainnet proof goes ahead. Makes two mainnet keys and moves no money:
# the deployer's NEAR implicit account, and the Bitcoin funding key. No key prints to the screen.
#
#   scripts/human/03-funding-key.sh
#
# Safe to run again: an existing key is kept and its address printed.
set -euo pipefail
umask 077
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
DEPLOYER_DIR="$HOME/.config/undo/mainnet-deployer"
export PATH="$HOME/.local/bin:$PATH"

cat <<PLAN
This makes MAINNET keys, for real coins. It will:
  1. Make the deployer's NEAR key with near-cli, offline, in ~/.config/undo/mainnet-deployer/,
     readable only by you. The account exists on chain only once you fund it.
  2. Make the Bitcoin funding key and put it in your macOS login Keychain, as the item
     "undo-funding-key". Your Mac may ask you to allow this.
  3. Print the two addresses. It prints no secret.
It sends nothing, spends nothing and contacts nothing. Existing keys are kept, never replaced.
Both keys sit on this Mac under your user, so anything running as you could read them. Keep only
what the proof needs on them, and the coins go home on 11/8.
PLAN
printf 'Type yes to go ahead: '
read -r answer || answer=""
if [ "$answer" != "yes" ]; then
  echo "Stopped. Nothing was changed."
  exit 0
fi

command -v near >/dev/null 2>&1 || { echo "near is not installed. Run install-near-cli.sh first." >&2; exit 1; }
if ! near --version 2>/dev/null | grep -q '0\.30\.1'; then
  echo "This script was checked against near-cli 0.30.1, and another version is on your PATH. Stopping." >&2
  exit 1
fi

mkdir -p "$DEPLOYER_DIR"
chmod 700 "$DEPLOYER_DIR"
shopt -s nullglob
files=("$DEPLOYER_DIR"/*.json)
if [ "${#files[@]}" -eq 0 ]; then
  near account create-account fund-later use-auto-generation save-to-folder "$DEPLOYER_DIR"
  files=("$DEPLOYER_DIR"/*.json)
fi
if [ "${#files[@]}" -ne 1 ]; then
  echo "Expected one key file in ~/.config/undo/mainnet-deployer, found ${#files[@]}. Stopping." >&2
  exit 1
fi
chmod 600 "${files[0]}"
deployer="$(basename "${files[0]}" .json)"
case "$deployer" in
  *[!0-9a-f]*) echo "The key file name is not an implicit account. Stopping." >&2; exit 1 ;;
esac
if [ "${#deployer}" -ne 64 ]; then
  echo "The key file name is not an implicit account. Stopping." >&2
  exit 1
fi

funding="$(node "$HERE/../../tools/human-key.mjs" funding)"
echo "$funding"
btc="$(printf '%s\n' "$funding" | sed -n 's/^ADDRESS //p')"
[ -n "$btc" ] || { echo "No funding address. Do not withdraw anything." >&2; exit 1; }

cat <<NEXT

On MAX, withdraw:
  NEAR to the deployer: $deployer
  BTC to the funding key: $btc
The amounts come from the agents. Withdraw a small test amount first if MAX lets you.
Then give the agents a Bitcoin address you control at home. Every leftover sat goes there on 11/8.
NEXT
