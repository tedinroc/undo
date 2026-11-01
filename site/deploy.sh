#!/usr/bin/env bash
# Builds the site, scans what would go out, and deploys it with its Functions. Deploy worker/undo-cron first.
# --check-only stops after the account and secret checks.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO="$(cd "$HERE/.." && pwd -P)"
# shellcheck source=../worker/undo-cron/require-account.sh
source "$REPO/worker/undo-cron/require-account.sh"
W="${WRANGLER:-npx --yes wrangler@3}"
PROJECT="undo-btc"

require_account
if grep -qE '^[[:space:]]*account_id' "$HERE/wrangler.toml"; then
  echo "deploy: refused: account_id in wrangler.toml" >&2
  exit 1
fi
cd "$HERE"
# shellcheck disable=SC2086
listed="$($W pages secret list --project-name "$PROJECT" 2>&1 || true)"
require_secrets "$listed" CONTRACT_ID RELAY_ACCOUNT RELAY_GENERAL_KEY RELAY_OWNER_KEY DISPENSER_SECRET IP_SALT
if [ "${1:-}" = "--check-only" ]; then
  echo "deploy: checks passed, nothing sent"
  exit 0
fi
node build.mjs --config config/testnet.json
"$REPO/scripts/outward-check.sh" --bundle "$HERE/dist"
# What the Functions become, scanned before it goes: a bundle can carry a path that no source file does.
scan="$(mktemp -d "${TMPDIR:-/tmp}/undo-functions.XXXXXX")"
trap 'rm -rf "$scan"' EXIT
# shellcheck disable=SC2086
$W pages functions build --outdir "$scan" --compatibility-date "$(sed -n 's/^compatibility_date = "\(.*\)"$/\1/p' wrangler.toml)"
if find "$HERE/dist" "$scan" -name '*.map' | grep -q .; then
  echo "deploy: refused: a source map would go out" >&2
  exit 1
fi
"$REPO/scripts/check-identity.sh" --files "$scan"/*
# shellcheck disable=SC2086
$W pages deploy dist --project-name "$PROJECT" --branch main --commit-dirty=true
