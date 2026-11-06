#!/usr/bin/env bash
# Step 40. Deploys the undo-cron Worker, then the Pages project that binds its Durable Object. Both deploy
# scripts' --check-only runs go first, so nothing is sent unless both pass: the account, the secrets, the tomls.
#
#   scripts/go-live/40-deploy.sh --dry-run      offline: builds the site, runs the outward check, prints the commands
#   scripts/go-live/40-deploy.sh --check-only   also runs both deploy scripts' --check-only (reads, sends nothing)
#   scripts/go-live/40-deploy.sh --live         check-only for both, then the Worker, then Pages
#
# The site's config must name the contract the relay's secrets name: pass --contract to have it compared.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=env.sh
source "$HERE/env.sh"
REPO="$GOLIVE_REPO"

usage() { echo "usage: 40-deploy.sh (--dry-run | --check-only | --live) [--contract ACCOUNT]" >&2; exit 2; }
mode='' contract=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run|--check-only|--live) [ -z "$mode" ] || usage; mode="$1"; shift ;;
    --contract) contract="${2:-}"; shift 2 || usage ;;
    *) usage ;;
  esac
done
[ -n "$mode" ] || usage
GOLIVE_LABEL=static
cron_deploy="$REPO/worker/undo-cron/deploy.sh"
site_deploy="$REPO/site/deploy.sh"
config="$REPO/site/config/testnet.json"
for f in "$cron_deploy" "$site_deploy" "$config"; do
  [ -f "$f" ] || { golive_say FAIL "${f#"$REPO"/} is missing (merge the web branch first)"; exit 1; }
done

named="$(node -p "require('$config').contract")"
h7="$(node -p "require('$config').h7 === true")"
case "$named" in
  FILL-AT-DEPLOY*) golive_say FAIL "site/config/testnet.json names no contract: set it to the instance from step 10"; exit 1 ;;
esac
if [ -n "$contract" ] && [ "$named" != "$contract" ]; then
  golive_say FAIL "site/config/testnet.json names $named, the relay's secrets name $contract"; exit 1
fi
golive_say PASS "site/config/testnet.json names $named"
[ "$h7" = "true" ] && golive_say INFO "test mode is on in this config (h7): fine for H7, set false for the final deploy"

# What would go out, built and scanned here first, with no network.
work="$(mktemp -d "${TMPDIR:-/tmp}/undo-golive-40.XXXXXX")"
trap 'rm -rf "$work"' EXIT
if node "$REPO/site/build.mjs" --config "$config" --out "$work/dist" >"$work/build.log" 2>&1; then
  golive_say PASS "$(cat "$work/build.log")"
else
  golive_say FAIL "the site does not build: $(cat "$work/build.log")"; exit 1
fi
if "$REPO/scripts/outward-check.sh" --bundle "$work/dist" >"$work/outward.log" 2>&1; then
  golive_say PASS "outward check on the built site: $(tail -1 "$work/outward.log")"
else
  sed 's/^/     /' "$work/outward.log" | tail -20
  golive_say FAIL "outward check on the built site"; exit 1
fi

if [ "$mode" = "--dry-run" ]; then
  golive_say PLAN "WRANGLER=$WRANGLER worker/undo-cron/deploy.sh --check-only"
  golive_say PLAN "WRANGLER=$WRANGLER site/deploy.sh --check-only"
  golive_say PLAN "WRANGLER=$WRANGLER worker/undo-cron/deploy.sh          (the Worker and its Durable Object first)"
  golive_say PLAN "WRANGLER=$WRANGLER site/deploy.sh                      (then Pages, which binds that class)"
  echo "DRY RUN: wrangler was not run, nothing sent."
  exit 0
fi

GOLIVE_LABEL=live-cloudflare
golive_env_problems >/dev/null || { golive_env_problems; echo "STOP: the environment is not ready (00-env-check.sh)"; exit 1; }
"$cron_deploy" --check-only || { echo "STOP: the Worker's checks failed. Nothing sent."; exit 1; }
"$site_deploy" --check-only || { echo "STOP: the Pages project's checks failed. Nothing sent."; exit 1; }
if [ "$mode" = "--check-only" ]; then
  echo "CHECK ONLY: both deploy scripts' checks passed. Nothing sent."
  exit 0
fi
"$cron_deploy" || { echo "STOP: the Worker deploy failed. Pages was not deployed."; exit 1; }
golive_say SENT "Worker undo-cron deployed"
"$site_deploy" || { echo "STOP: the Pages deploy failed. The Worker is up; run 40-deploy.sh --live again once fixed."; exit 1; }
golive_say SENT "Pages project undo-btc deployed. Next: 50-readback.mjs"
