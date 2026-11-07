#!/usr/bin/env bash
# wrangler 3 under the public account's environment, and nothing else from the calling shell: a fresh empty HOME,
# the config folder that holds that account's login, and the npm cache. No API token, no other login, no metrics.
#
#   GOLIVE_XDG_CONFIG_HOME   the folder whose .wrangler/config holds the public account's login (required)
#   GOLIVE_NPM_CACHE         the npm cache npx uses (required)
#   CLOUDFLARE_ACCOUNT_ID    passed through when set; scripts that deploy refuse without it
#   GOLIVE_WRANGLER_BIN      what to run instead of `npx --yes wrangler@3`, for a pinned copy or a test stub
#
# stdin passes through, which is how 30-secrets.sh hands a value to `secret put` without an argument or an echo.
set -euo pipefail
: "${GOLIVE_XDG_CONFIG_HOME:?wrangler.sh: set GOLIVE_XDG_CONFIG_HOME to the folder holding the public account login}"
: "${GOLIVE_NPM_CACHE:?wrangler.sh: set GOLIVE_NPM_CACHE}"
[ -d "$GOLIVE_XDG_CONFIG_HOME" ] || { echo "wrangler.sh: GOLIVE_XDG_CONFIG_HOME is not a folder" >&2; exit 2; }
scratch="$(mktemp -d "${TMPDIR:-/tmp}/undo-wrangler-home.XXXXXX")"
trap 'rm -rf "$scratch"' EXIT
pass=(PATH="$PATH" HOME="$scratch" XDG_CONFIG_HOME="$GOLIVE_XDG_CONFIG_HOME" npm_config_cache="$GOLIVE_NPM_CACHE"
  WRANGLER_SEND_METRICS=false WRANGLER_LOG_PATH="$scratch/logs" TERM="${TERM:-dumb}")
[ -z "${CLOUDFLARE_ACCOUNT_ID:-}" ] || pass+=(CLOUDFLARE_ACCOUNT_ID="$CLOUDFLARE_ACCOUNT_ID")
# shellcheck disable=SC2086
env -i "${pass[@]}" ${GOLIVE_WRANGLER_BIN:-npx --yes wrangler@3} "$@"
