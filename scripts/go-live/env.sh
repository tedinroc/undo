# Sourced by the go-live shell scripts. Checks the environment every Cloudflare step runs under, and points
# WRANGLER at wrangler.sh, which the repo's deploy scripts and require-account.sh then use. Prints names, never values.
GOLIVE_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
GOLIVE_REPO="$(cd "$GOLIVE_HERE/../.." && pwd -P)"
export WRANGLER="${WRANGLER:-$GOLIVE_HERE/wrangler.sh}"
GOLIVE_PROJECT="undo-btc"
GOLIVE_WORKER="undo-cron"

golive_say() { printf '%-4s [%s] %s\n' "$1" "${GOLIVE_LABEL:-static}" "$2"; }

# Prints one line per problem and returns how many there were. Reads no secret and no login.
golive_env_problems() {
  local n=0 toml
  if [ -z "${CLOUDFLARE_ACCOUNT_ID:-}" ]; then
    golive_say FAIL "CLOUDFLARE_ACCOUNT_ID is not set in the environment"; n=$((n + 1))
  elif ! printf '%s' "$CLOUDFLARE_ACCOUNT_ID" | grep -Eq '^[0-9a-f]{32}$'; then
    golive_say FAIL "CLOUDFLARE_ACCOUNT_ID is not 32 lower-case hex characters"; n=$((n + 1))
  else
    golive_say PASS "CLOUDFLARE_ACCOUNT_ID is set (ends ${CLOUDFLARE_ACCOUNT_ID: -4})"
  fi
  for var in GOLIVE_XDG_CONFIG_HOME GOLIVE_NPM_CACHE; do
    if [ -z "${!var:-}" ]; then golive_say FAIL "$var is not set"; n=$((n + 1))
    elif [ ! -d "${!var}" ]; then golive_say FAIL "$var is not a folder"; n=$((n + 1))
    else golive_say PASS "$var is a folder"; fi
  done
  if [ -n "${CLOUDFLARE_API_TOKEN:-}${CF_API_TOKEN:-}" ]; then
    golive_say WARN "an API token is set in this shell. wrangler.sh drops it; the login file decides the account"
  fi
  for toml in "$GOLIVE_REPO/site/wrangler.toml" "$GOLIVE_REPO/worker/undo-cron/wrangler.toml"; do
    if [ ! -f "$toml" ]; then golive_say FAIL "${toml#"$GOLIVE_REPO"/} is missing (merge the web branch first)"; n=$((n + 1))
    elif grep -qE '^[[:space:]]*account_id' "$toml"; then golive_say FAIL "account_id in ${toml#"$GOLIVE_REPO"/}"; n=$((n + 1))
    else golive_say PASS "no account_id in ${toml#"$GOLIVE_REPO"/}"; fi
  done
  return "$n"
}

golive_require_account_lib() {
  local lib="$GOLIVE_REPO/worker/undo-cron/require-account.sh"
  [ -f "$lib" ] || { golive_say FAIL "worker/undo-cron/require-account.sh is missing (merge the web branch first)"; return 1; }
  # shellcheck source=/dev/null
  source "$lib"
}
