# Sourced by both deploy scripts. Stops unless `wrangler whoami`, under the environment it is given, shows the
# public account and the account id set for this deploy. It never prints what whoami said.
# WRANGLER may name another wrangler 3. CLOUDFLARE_ACCOUNT_ID comes from the environment, never a config file.
PUBLIC_ACCOUNT="tedinroc"

require_account() {
  if [ -z "${CLOUDFLARE_ACCOUNT_ID:-}" ]; then
    echo "deploy: refused: set CLOUDFLARE_ACCOUNT_ID in the environment" >&2
    return 1
  fi
  local who
  # shellcheck disable=SC2086
  if ! who="$(${WRANGLER:-npx --yes wrangler@3} whoami 2>&1)"; then
    echo "deploy: refused: wrangler whoami failed" >&2
    return 1
  fi
  if ! printf '%s\n' "$who" | grep -qi -F -e "$PUBLIC_ACCOUNT"; then
    echo "deploy: refused: wrangler whoami does not show the $PUBLIC_ACCOUNT account" >&2
    return 1
  fi
  if ! printf '%s\n' "$who" | grep -q -F -e "$CLOUDFLARE_ACCOUNT_ID"; then
    echo "deploy: refused: this login cannot see CLOUDFLARE_ACCOUNT_ID" >&2
    return 1
  fi
  echo "deploy: account checked"
}

# The names in $1 (one list per line of what wrangler printed) must include every name after it.
require_secrets() {
  local listed="$1" name missing=0
  shift
  for name in "$@"; do
    if ! printf '%s\n' "$listed" | grep -q -F -e "$name"; then
      echo "deploy: refused: secret $name is not set" >&2
      missing=1
    fi
  done
  return "$missing"
}
