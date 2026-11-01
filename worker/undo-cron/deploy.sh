#!/usr/bin/env bash
# Deploys the state store and the canary cron. Deploy this before the Pages project, which binds its class.
# --check-only stops after every check.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO="$(cd "$HERE/../.." && pwd -P)"
# shellcheck source=require-account.sh
source "$HERE/require-account.sh"
W="${WRANGLER:-npx --yes wrangler@3}"

require_account
grep -q '^workers_dev = false$' "$HERE/wrangler.toml" || { echo "deploy: refused: workers_dev is not false" >&2; exit 1; }
grep -q '^preview_urls = false$' "$HERE/wrangler.toml" || { echo "deploy: refused: preview_urls is not false" >&2; exit 1; }
if grep -qE '^[[:space:]]*account_id' "$HERE/wrangler.toml"; then
  echo "deploy: refused: account_id in wrangler.toml" >&2
  exit 1
fi
cd "$HERE"
# shellcheck disable=SC2086
listed="$($W secret list 2>&1 || true)"
require_secrets "$listed" CONTRACT_ID RELAY_ACCOUNT RELAY_CRON_KEY
if [ "${1:-}" = "--check-only" ]; then
  echo "deploy: checks passed, nothing sent"
  exit 0
fi
"$REPO/scripts/secret-scan.sh"
"$REPO/scripts/check-identity.sh" --tree
# shellcheck disable=SC2086
$W deploy
