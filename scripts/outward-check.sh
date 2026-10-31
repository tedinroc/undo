#!/usr/bin/env bash
# Gate for every outward action: each deploy to any chain, each Pages or Worker deploy, each
# push, each issue or post body. Anything that went out before this passed needs a fresh account
# name, because wasm on chain cannot be taken back.
#
#   outward-check.sh --wasm FILE     the exact file about to be deployed; repeatable
#   outward-check.sh --bundle DIR    a site bundle; repeatable
#   outward-check.sh --file FILE     an issue body, post text or other file; repeatable
#
# With no --wasm, every built wasm in <target>/near is checked, and finding none is a failure.
# The tree, the secret scan, proofs/ and every wrangler.toml are always checked.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
REPO="$(cd "$HERE/.." && pwd -P)"
TARGET="${CARGO_TARGET_DIR:-$REPO/target}"

wasm=()
bundles=()
files=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --wasm) wasm+=("${2:?}"); shift 2 ;;
    --bundle) bundles+=("${2:?}"); shift 2 ;;
    --file) files+=("${2:?}"); shift 2 ;;
    *) echo "OUTWARD ERROR: unknown option" >&2; exit 2 ;;
  esac
done

if [ "${#wasm[@]}" -eq 0 ]; then
  shopt -s nullglob
  wasm=("$TARGET"/near/*.wasm)
  shopt -u nullglob
  if [ "${#wasm[@]}" -eq 0 ]; then
    echo "OUTWARD ERROR: no built wasm, run scripts/build.sh first" >&2
    exit 2
  fi
fi

status=0
worst() { [ "$1" -le "$status" ] || status="$1"; }

"$HERE/check-identity.sh" --wasm "${wasm[@]}"; worst $?
"$HERE/check-identity.sh" --tree; worst $?
"$HERE/secret-scan.sh"; worst $?

for f in "${wasm[@]}"; do
  case "$(basename "$f")" in
    undo_vault*) "$HERE/check-wasm.sh" --file "$f"; worst $? ;;
  esac
done

extra=()
if [ "${#files[@]}" -gt 0 ]; then
  extra+=("${files[@]}")
fi
if [ "${#bundles[@]}" -gt 0 ]; then
  for dir in "${bundles[@]}"; do
    [ -d "$dir" ] || { echo "OUTWARD ERROR: no bundle at $(basename "$dir")" >&2; exit 2; }
    while IFS= read -r -d '' f; do
      case "$f" in
        *.map) echo "OUTWARD FAIL: source map in bundle: ${f#"$dir"/}"; worst 1 ;;
      esac
      extra+=("$f")
    done < <(find "$dir" -type f -print0)
  done
fi
# proofs/ may hold ignored files too, so read the folder rather than the git listing.
while IFS= read -r -d '' f; do
  extra+=("$f")
done < <(find "$REPO/proofs" -type f -print0 2>/dev/null)
if [ "${#extra[@]}" -gt 0 ]; then
  "$HERE/check-identity.sh" --files "${extra[@]}"; worst $?
  "$HERE/secret-scan.sh" --files "${extra[@]}"; worst $?
fi

# An account id in a config file links the deploy to a Cloudflare account.
while IFS= read -r -d '' f; do
  case "$f" in
    wrangler.toml|*/wrangler.toml)
      if grep -nE '^[[:space:]]*account_id[[:space:]]*=' "$REPO/$f" >/dev/null; then
        echo "OUTWARD FAIL: account_id in $f"
        worst 1
      fi
      ;;
  esac
done < <(git -C "$REPO" ls-files -z --cached --others --exclude-standard)

if [ "$status" -ne 0 ]; then
  echo "OUTWARD FAIL: this action must not happen"
  exit "$status"
fi
echo "OUTWARD OK"
