#!/usr/bin/env bash
# Step 30. Sets the undo-cron Worker's and the undo-btc Pages project's secrets by name, from the private file
# 20-relay-keys.mjs wrote and the Mutinynet dispenser file. A value goes from its file to wrangler's stdin and
# nowhere else (secrets-put.mjs): never an argument, never printed. Afterwards each name must be in wrangler's list.
#
#   scripts/go-live/30-secrets.sh --dry-run --secrets FILE --dispenser FILE [--canary VAULT]
#   scripts/go-live/30-secrets.sh --live    --secrets FILE --dispenser FILE [--canary VAULT]
#
# --live needs 00-env-check.sh to pass first: it stops unless wrangler whoami shows the public account.
# If undo-cron does not exist yet, wrangler 3 may create it when the first secret goes in; run 40-deploy.sh next,
# which deploys it with workers_dev and preview_urls off. Exit 0 when every name is set and listed.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
# shellcheck source=env.sh
source "$HERE/env.sh"

usage() { echo "usage: 30-secrets.sh (--dry-run | --live) --secrets FILE --dispenser FILE [--canary VAULT]" >&2; exit 2; }
mode='' secrets='' dispenser='' canary=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --dry-run|--live) [ -z "$mode" ] || usage; mode="$1"; shift ;;
    --secrets) secrets="${2:-}"; shift 2 || usage ;;
    --dispenser) dispenser="${2:-}"; shift 2 || usage ;;
    --canary) canary=(--canary "${2:-}"); shift 2 || usage ;;
    *) usage ;;
  esac
done
[ -n "$mode" ] && [ -n "$secrets" ] && [ -n "$dispenser" ] || usage

if [ "$mode" = "--live" ]; then
  GOLIVE_LABEL=live-cloudflare
  golive_env_problems >/dev/null || { golive_env_problems; echo "STOP: the environment is not ready (00-env-check.sh)"; exit 1; }
  golive_require_account_lib || exit 1
  require_account || { echo "STOP: not the public account, nothing set"; exit 1; }
fi
status=0
node "$HERE/secrets-put.mjs" --target worker --secrets "$secrets" ${canary[@]+"${canary[@]}"} "$mode" || status=1
if [ "$status" -ne 0 ] && [ "$mode" = "--live" ]; then
  echo "STOP: the Worker's secrets did not all go in, so the Pages project was not touched"
  exit 1
fi
node "$HERE/secrets-put.mjs" --target pages --secrets "$secrets" --dispenser "$dispenser" "$mode" || status=1
exit "$status"
