#!/usr/bin/env bash
# Fails on any local path, username, hostname or blocked word.
#
#   check-identity.sh                  built wasm in <target>/near, plus the tree
#   check-identity.sh --tree           the tree only: file names and file contents
#   check-identity.sh --wasm FILE...   these wasm files only
#   check-identity.sh --files FILE...  these text or binary files only
#
# A wasm file is read twice: with `strings`, as a person would, and as raw bytes. Exit 0 means
# clean, 1 means a hit, 2 means the check could not run. There is no way to skip a part.
set -uo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib-identity.sh"
identity_load_patterns || exit 2

hits=0

hit() {
  echo "IDENTITY HIT: $1 [$2]"
  hits=$((hits + 1))
}

scan_file() {
  local file="$1" name="$2" i out
  [ -f "$file" ] || return 0
  for i in "${!IDENTITY_PATTERNS[@]}"; do
    out="$(LC_ALL=C grep -a -n -i -F -e "${IDENTITY_PATTERNS[$i]}" -- "$file" 2>/dev/null | cut -d: -f1 | head -5 | tr '\n' ' ')"
    [ -z "$out" ] || hit "$name: line ${out% }" "${IDENTITY_LABELS[$i]}"
  done
}

scan_name() {
  local name="$1" i
  for i in "${!IDENTITY_PATTERNS[@]}"; do
    if printf '%s\n' "$name" | LC_ALL=C grep -q -i -F -e "${IDENTITY_PATTERNS[$i]}"; then
      hit "file name $name" "${IDENTITY_LABELS[$i]}"
    fi
  done
}

scan_wasm() {
  local file="$1" i count text
  if [ ! -s "$file" ]; then
    echo "IDENTITY ERROR: no wasm at $(basename "$file")" >&2
    exit 2
  fi
  if ! command -v strings >/dev/null 2>&1; then
    echo "IDENTITY ERROR: strings is not installed" >&2
    exit 2
  fi
  text="$(mktemp "${TMPDIR:-/tmp}/undo-strings.XXXXXX")"
  strings -a "$file" > "$text"
  count="$(wc -l < "$text" | tr -d ' ')"
  # A contract always has far more printable runs than this. Fewer means strings read nothing.
  if [ "$count" -lt 50 ]; then
    rm -f "$text"
    echo "IDENTITY ERROR: strings found only $count lines in $(basename "$file")" >&2
    exit 2
  fi
  for i in "${!IDENTITY_PATTERNS[@]}"; do
    if LC_ALL=C grep -a -q -i -F -e "${IDENTITY_PATTERNS[$i]}" -- "$text"; then
      hit "$(basename "$file") strings: $(LC_ALL=C grep -a -c -i -F -e "${IDENTITY_PATTERNS[$i]}" -- "$text") lines" "${IDENTITY_LABELS[$i]}"
    fi
    if LC_ALL=C grep -a -q -i -F -e "${IDENTITY_PATTERNS[$i]}" -- "$file"; then
      hit "$(basename "$file") raw bytes" "${IDENTITY_LABELS[$i]}"
    fi
  done
  rm -f "$text"
  echo "wasm $(basename "$file"): sha256 $(shasum -a 256 "$file" | cut -d' ' -f1), $(wc -c < "$file" | tr -d ' ') bytes, $count strings read, ${#IDENTITY_PATTERNS[@]} patterns"
}

scan_tree() {
  local path count=0 base
  if ! git -C "$IDENTITY_REPO" rev-parse --git-dir >/dev/null 2>&1; then
    echo "IDENTITY ERROR: not a git checkout" >&2
    exit 2
  fi
  while IFS= read -r -d '' path; do
    count=$((count + 1))
    scan_name "$path"
    scan_file "$IDENTITY_REPO/$path" "$path"
    # The name appears only in author, license and AI-disclosure files.
    case "$path" in
      LICENSE|README.md|Cargo.toml|.githooks/*|scripts/*) ;;
      *)
        if LC_ALL=C grep -a -q -F -e "Ted Ch""en" -- "$IDENTITY_REPO/$path" 2>/dev/null; then
          hit "$path" "author name outside author, license and disclosure"
        fi
        ;;
    esac
  done < <(identity_tree_files)
  if [ "$count" -eq 0 ]; then
    echo "IDENTITY ERROR: the tree listing is empty" >&2
    exit 2
  fi
  echo "tree: $count files, ${#IDENTITY_PATTERNS[@]} patterns"
}

case "${1:-}" in
  --tree)
    scan_tree
    ;;
  --wasm)
    shift
    [ "$#" -gt 0 ] || { echo "IDENTITY ERROR: --wasm needs a file" >&2; exit 2; }
    for f in "$@"; do scan_wasm "$f"; done
    ;;
  --files)
    shift
    [ "$#" -gt 0 ] || { echo "IDENTITY ERROR: --files needs a file" >&2; exit 2; }
    for f in "$@"; do
      [ -f "$f" ] || { echo "IDENTITY ERROR: no file $(basename "$f")" >&2; exit 2; }
      scan_name "$(basename "$f")"
      scan_file "$f" "$(basename "$f")"
    done
    echo "files: $# files, ${#IDENTITY_PATTERNS[@]} patterns"
    ;;
  '')
    shopt -s nullglob
    built=("$IDENTITY_TARGET"/near/*.wasm)
    shopt -u nullglob
    if [ "${#built[@]}" -eq 0 ]; then
      echo "IDENTITY ERROR: no built wasm, run scripts/build.sh first" >&2
      exit 2
    fi
    for f in "${built[@]}"; do scan_wasm "$f"; done
    scan_tree
    ;;
  *)
    echo "IDENTITY ERROR: unknown option" >&2
    exit 2
    ;;
esac

if [ "$hits" -gt 0 ]; then
  echo "IDENTITY FAIL: $hits hits"
  exit 1
fi
echo "IDENTITY OK"
