#!/usr/bin/env bash
# H3. Prints the Mutinynet address to paste into faucet.mutinynet.com. Makes its key the first time.
# The key is a plain file so agents can sign unattended. It only ever holds Mutinynet test coins.
#
#   scripts/human/02-dispenser-address.sh
set -euo pipefail
umask 077
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
KEY="$HOME/.config/undo/dispenser-mutinynet.json"

cat <<PLAN
This will:
  1. Make a new Mutinynet test key at ~/.config/undo/dispenser-mutinynet.json, readable only by you.
     If that file exists, it is kept and not changed.
  2. Print its address. It prints no secret.
It sends nothing and touches no account. Never send real Bitcoin to this address.
PLAN
printf 'Type yes to go ahead: '
read -r answer || answer=""
if [ "$answer" != "yes" ]; then
  echo "Stopped. Nothing was changed."
  exit 0
fi

node "$HERE/../../tools/human-key.mjs" dispenser --file "$KEY"
cat <<NEXT

Next: open faucet.mutinynet.com, sign in (if it asks for GitHub, use tedinroc only), press Get coins,
and paste the ADDRESS above. The agents can read the key file, so you need not tell them the address.
NEXT
