#!/usr/bin/env bash
# Step 0. Is this shell set up to deploy under the public Cloudflare account, and only that one?
#
#   scripts/go-live/00-env-check.sh --dry-run    local checks only; prints the commands --live would run
#   scripts/go-live/00-env-check.sh --live       also runs wrangler 3 --version and whoami under wrangler.sh
#
# The environment comes from outside the repo: CLOUDFLARE_ACCOUNT_ID, GOLIVE_XDG_CONFIG_HOME and GOLIVE_NPM_CACHE
# (see wrangler.sh). whoami must show the public account and that account id; its output is never printed, only
# whether it matched. Exit 0 when every line is PASS, 1 when any is FAIL, 2 on usage.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=env.sh
source "$HERE/env.sh"

mode="${1:-}"
case "$mode" in
  --dry-run) GOLIVE_LABEL=static ;;
  --live) GOLIVE_LABEL=live-cloudflare ;;
  *) echo "usage: 00-env-check.sh --dry-run | --live" >&2; exit 2 ;;
esac
fail=0

node_major="$(node -p 'process.versions.node.split(".")[0]' 2>/dev/null || echo 0)"
if [ "$node_major" -ge 20 ]; then golive_say PASS "node $node_major"; else golive_say FAIL "node 20 or newer is needed"; fail=1; fi
if command -v npx >/dev/null; then golive_say PASS "npx is on PATH"; else golive_say FAIL "npx is not on PATH"; fail=1; fi
golive_env_problems || fail=1
cron_toml="$GOLIVE_REPO/worker/undo-cron/wrangler.toml"
if [ -f "$cron_toml" ]; then
  if grep -q '^workers_dev = false$' "$cron_toml" && grep -q '^preview_urls = false$' "$cron_toml"; then
    golive_say PASS "undo-cron has workers_dev and preview_urls off"
  else
    golive_say FAIL "undo-cron must set workers_dev = false and preview_urls = false"; fail=1
  fi
fi
config="$GOLIVE_REPO/site/config/testnet.json"
if [ -f "$config" ]; then
  contract="$(node -p "require('$config').contract" 2>/dev/null || echo '?')"
  case "$contract" in
    FILL-AT-DEPLOY*) golive_say INFO "site/config/testnet.json names no contract yet: fill it after step 10" ;;
    *) golive_say INFO "site/config/testnet.json names $contract" ;;
  esac
fi

if [ "$mode" = "--dry-run" ]; then
  golive_say PLAN "$WRANGLER --version   (must print 3.x)"
  golive_say PLAN "$WRANGLER whoami      (must show the tedinroc account and CLOUDFLARE_ACCOUNT_ID; output not printed)"
  echo "DRY RUN: wrangler was not run."
  exit "$fail"
fi

if [ "$fail" -ne 0 ]; then
  echo "STOP: fix the lines above before asking wrangler anything."
  exit 1
fi
# shellcheck disable=SC2086
version="$($WRANGLER --version 2>/dev/null | grep -Eo '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
case "$version" in
  3.*) golive_say PASS "wrangler $version" ;;
  '') golive_say FAIL "wrangler did not print a version"; fail=1 ;;
  *) golive_say FAIL "wrangler $version is not 3.x: v4 sends Pages commands to Workers"; fail=1 ;;
esac
if golive_require_account_lib && require_account >/dev/null 2>&1; then
  golive_say PASS "wrangler whoami shows the tedinroc account and this account id"
else
  # Run it again for its own refusal line, which names no value.
  require_account 2>&1 | sed 's/^/     /' || true
  golive_say FAIL "wrangler whoami did not show the tedinroc account with this account id"; fail=1
fi
exit "$fail"
