#!/usr/bin/env bash
# Builds the Pages output and the Functions bundle exactly as site/deploy.sh does, without deploying, and reads what
# would go out: no local path, no key, no source map, no off-list handle, no host the config does not name.
#
#   tools/test/pages-output-check.sh OUT_DIR
#
# Needs UNDO_WRANGLER_MODULES for the Functions bundle. Exits 0 only if every line reads OK. The blocked list stays
# outside the repo, read by scripts/check-identity.sh, and no hit prints the word it matched.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO="$(cd "$HERE/../.." && pwd -P)"
OUT="${1:?usage: pages-output-check.sh OUT_DIR}"
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd -P)"
fail=0
ok() { echo "OK   $1"; }
bad() { echo "FAIL $1"; fail=1; }

node "$REPO/site/build.mjs" --config "$REPO/site/config/testnet.json" --allow-unfilled --out "$OUT/pages" || exit 1
scan=("$OUT/pages")
if [ -n "${UNDO_WRANGLER_MODULES:-}" ]; then
  home="$(mktemp -d "${TMPDIR:-/tmp}/undo-pages-home.XXXXXX")"
  (cd "$REPO/site" && env -i PATH="$PATH" HOME="$home" XDG_CONFIG_HOME="$home/xdg" WRANGLER_SEND_METRICS=false WRANGLER_LOG_PATH="$home/logs" \
    node "$UNDO_WRANGLER_MODULES/wrangler/bin/wrangler.js" pages functions build --outdir "$OUT/functions" --compatibility-date "$(sed -n 's/^compatibility_date = "\(.*\)"$/\1/p' wrangler.toml)" >/dev/null) || bad 'wrangler built the Functions bundle'
  rm -rf "$home" "$REPO/site/.wrangler"
  scan+=("$OUT/functions")
else
  echo 'SKIP the Functions bundle: UNDO_WRANGLER_MODULES is not set'
fi
echo "     $(find "${scan[@]}" -type f | wc -l | tr -d ' ') files, $(du -sk "${scan[@]}" | awk '{s+=$1} END {print s}') KB"

# Source maps: the file, and a pointer to one.
maps="$(find "${scan[@]}" -type f -name '*.map' | wc -l | tr -d ' ')"
[ "$maps" = 0 ] && ok "no .map file" || bad "$maps .map files"
pointers="$(grep -rIl 'sourceMappingURL' "${scan[@]}" | wc -l | tr -d ' ')"
[ "$pointers" = 0 ] && ok "no sourceMappingURL" || bad "$pointers files with sourceMappingURL"

# Local paths: this machine's, and the shape of anybody's.
# Bracketed so this script does not trip the identity scan of the tree.
shape='(/[U]sers/|/[h]ome/[a-z]|/[p]rivate/tmp|[C]:.[U]sers|[f]ile://|[.]near-credentials|[.]config/undo)'
paths="$(grep -rIlE "$shape" "${scan[@]}" | wc -l | tr -d ' ')"
[ "$paths" = 0 ] && ok "no local path shape" || { bad "$paths files with a local path shape"; grep -rIlE "$shape" "${scan[@]}"; }
here="$(grep -rIlF -e "$REPO" -e "$HOME" "${scan[@]}" | wc -l | tr -d ' ')"
[ "$here" = 0 ] && ok "no path of this checkout or this home" || bad "$here files name this checkout or home"

# Keys: every shape the repo's scan knows, then a plain look for a near secret or a literal env value.
if "$REPO/scripts/secret-scan.sh" --files $(find "${scan[@]}" -type f) >/dev/null; then ok "secret-scan on every file"; else bad "secret-scan"; fi
near="$(grep -rIlE 'ed25519:[1-9A-HJ-NP-Za-km-z]{70,}|-----BEGIN [A-Z ]*PRIVATE' "${scan[@]}" | wc -l | tr -d ' ')"
[ "$near" = 0 ] && ok "no NEAR secret key, no PEM" || bad "$near files hold a key shape"
for name in RELAY_GENERAL_KEY RELAY_OWNER_KEY DISPENSER_SECRET IP_SALT; do
  in_pages="$(grep -rIl "$name" "$OUT/pages" | wc -l | tr -d ' ')"
  [ "$in_pages" = 0 ] && ok "$name appears in no page" || bad "$name appears in $in_pages page files"
done
hex="$(grep -rIoE '\b[0-9a-f]{64}\b' "$OUT/pages/undo-config.json" "$OUT/pages/_headers" "$OUT/pages/p" "$OUT/pages/t" "$OUT/pages/site" | wc -l | tr -d ' ')"
[ "$hex" = 0 ] && ok "no 32-byte hex literal in the pages or site/lib" || bad "$hex 32-byte hex literals in the pages or site/lib"

# Handles, subdomains and names on the blocked list, from outside the repo.
if "$REPO/scripts/check-identity.sh" --files $(find "${scan[@]}" -type f); then ok "identity scan on every file"; else bad "identity scan"; fi

# Hosts: everything a page names must be in the config. The vendored crypto's comments cite papers, so it is left out,
# and a separate line checks it holds no fetch at all.
allowed='mutinynet\.com|test\.rpc\.fastnear\.com|near-testnet\.drpc\.org|rpc\.testnet\.near\.org|testnet\.nearblocks\.io|undo-btc\.pages\.dev'
hosts="$(grep -rIhoE 'https?://[A-Za-z0-9.-]+' "$OUT/pages" --exclude=LICENSE --exclude-dir=vendor | sed -E 's#https?://##' | sort -u | grep -vE "^($allowed)$" | grep -vE '^(www\.w3\.org|example\.[a-z]+)$' || true)"
if [ -z "$hosts" ]; then ok "every host in the pages is on the list"; else bad "hosts off the list:"; printf '     %s\n' $hosts; fi

vendored="$(grep -rIlE '\b(fetch|XMLHttpRequest|WebSocket|sendBeacon)\(' "$OUT/pages/tools/vendor" | wc -l | tr -d ' ')"
[ "$vendored" = 0 ] && ok "the vendored crypto makes no network call" || bad "$vendored vendored files call the network"

# Config files: no account, no preview hostnames.
for toml in "$REPO/site/wrangler.toml" "$REPO/worker/undo-cron/wrangler.toml"; do
  if grep -qE '^[[:space:]]*account_id' "$toml"; then bad "account_id in ${toml#"$REPO"/}"; else ok "no account_id in ${toml#"$REPO"/}"; fi
done
if grep -q '^workers_dev = false' "$REPO/worker/undo-cron/wrangler.toml" && grep -q '^preview_urls = false' "$REPO/worker/undo-cron/wrangler.toml"; then ok "workers_dev and preview_urls are off"; else bad "workers_dev or preview_urls is not off"; fi

exit "$fail"
