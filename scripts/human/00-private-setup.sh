#!/usr/bin/env bash
# Makes the private folder beside the repo that the plan expects: the blocked list, the quota log and
# the handoff note. Nothing here is published, and the folder is outside the repo on purpose.
#
#   scripts/human/00-private-setup.sh
#
# Keeps anything already there. UNDO_PRIVATE_DIR and UNDO_BLOCKED_SOURCE change the paths, for tests.
# UNDO_CF_ACCOUNT_ID, if set, goes into the handoff note. 01-testnet-accounts.sh runs this first.
set -euo pipefail
umask 077
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO="$(cd "$HERE/../.." && pwd -P)"
DIR="${UNDO_PRIVATE_DIR:-$REPO/../private}"
SOURCE="${UNDO_BLOCKED_SOURCE:-$REPO/../plan/blocked-words.txt}"

case "$(cd "$(dirname "$DIR")" && pwd -P)/$(basename "$DIR")/" in
  "$REPO"/*) echo "The private folder must be outside the repo. Stopping." >&2; exit 1 ;;
esac
[ -s "$SOURCE" ] || { echo "No blocked list to start from. Stopping." >&2; exit 1; }

mkdir -p "$DIR"
chmod 700 "$DIR"
if [ -e "$DIR/blocked-names.txt" ]; then
  echo "blocked-names.txt is already there. Keeping it."
else
  cp "$SOURCE" "$DIR/blocked-names.txt"
  chmod 600 "$DIR/blocked-names.txt"
  echo "Wrote blocked-names.txt."
fi
if [ -e "$DIR/quota-log.csv" ]; then
  echo "quota-log.csv is already there. Keeping it."
else
  printf 'date,workflow,entry,tokens,card_percent\n' > "$DIR/quota-log.csv"
  echo "Wrote quota-log.csv."
fi
if [ -e "$DIR/HANDOFF.md" ]; then
  echo "HANDOFF.md is already there. Keeping it."
else
  # The public account's login is in the OS preferences folder, and a login elsewhere in a home
  # folder wins over it, so a deploy runs with an empty HOME. These are this machine's values, and
  # they go only into the private note.
  prefs="$HOME/Library/Preferences"
  if [ -f "$prefs/.wrangler/config/default.toml" ]; then
    found="A login file is at that path. Whether it still works, and for which account, is unchecked."
  else
    found="No login file was at that path when this ran."
  fi
  cat > "$DIR/HANDOFF.md" <<NOTE
# Handoff

Update at each gate. Outside the repo, and never copied into it.

## Wrangler environment for the public Cloudflare account

Every deploy runs under this, and stops unless \`wrangler whoami\` under it shows the expected email:

    HOME=<an empty scratch folder> XDG_CONFIG_HOME=$prefs npm_config_cache=$HOME/.npm CLOUDFLARE_ACCOUNT_ID=${UNDO_CF_ACCOUNT_ID:-<fill in>}

$found

## Last gate passed

None yet.

## Next step

Gate G1, once the accounts and test coins exist.
NOTE
  echo "Wrote HANDOFF.md."
fi
echo "Done. Check the wrangler environment in HANDOFF.md before the first deploy."
