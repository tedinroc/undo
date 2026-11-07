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
  local row
  row="$(printf '%s\n' "$who" | grep -F -e "$CLOUDFLARE_ACCOUNT_ID" || true)"
  if [ -z "$row" ]; then
    echo "deploy: refused: this login cannot see CLOUDFLARE_ACCOUNT_ID" >&2
    return 1
  fi
  # The id must be the public account's own: its row names that account, or it is the only account this login sees
  # (a login named for the public account, with one account). A login that sees several accounts passes only for
  # the row that names the public one, so CLOUDFLARE_ACCOUNT_ID cannot point at another account it can reach.
  if ! printf '%s\n' "$row" | grep -qi -F -e "$PUBLIC_ACCOUNT"; then
    local ids
    ids="$(printf '%s\n' "$who" | grep -oE '(^|[^0-9a-f])[0-9a-f]{32}([^0-9a-f]|$)' | grep -oE '[0-9a-f]{32}' | sort -u)"
    if [ "$ids" != "$CLOUDFLARE_ACCOUNT_ID" ]; then
      echo "deploy: refused: the row for CLOUDFLARE_ACCOUNT_ID does not name the $PUBLIC_ACCOUNT account" >&2
      return 1
    fi
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
