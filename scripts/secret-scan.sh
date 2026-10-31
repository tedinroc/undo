#!/usr/bin/env bash
# Fails on anything shaped like key material.
#
#   secret-scan.sh                 the tree: every file git could publish
#   secret-scan.sh --files FILE... these files
#
# Output names the file and line, never the value. Exit 0 clean, 1 hit, 2 could not run.
# SECRET_PATTERNS is also read by the pre-push hook, which sources this file with
# SECRET_SCAN_LIB_ONLY=1 to scan history.
set -uo pipefail

B58='[1-9A-HJ-NP-Za-km-z]'
SECRET_PATTERNS=(
  # NEAR ed25519 secret key. A public key is about 44 characters, a secret key about 88.
  "ed25519:${B58}{70,}"
  # Named key fields holding a literal value.
  "(private_key|secret_key|seed_phrase|master_key)[\"' :=]+[\"'][^\"']{16,}"
  # PEM blocks.
  "-----BEGIN [A-Z ]*PRIVATE KEY-----"
  # Bitcoin extended keys and WIF, mainnet and test networks.
  # Zero is not base58 but is still inside a token, so it counts as a non-boundary: without
  # that, a stretch of a hex checksum between two zeros looks like a WIF key.
  "(^|[^0-9A-Za-z])[xt]prv${B58}{50,}"
  "(^|[^0-9A-Za-z])[5KLc9]${B58}{50,51}([^0-9A-Za-z]|$)"
  # This project's own formats: 32 secret bytes as hex. A recovery file names it cold_key, a
  # dispenser file secret, and a seed file holds it alone on a line.
  "(cold_key|cold_secret|leaf_key|leaf_secret|intent_key|intent_secret|secret|seed)[\"' :=]+[\"']?[0-9a-fA-F]{64}([^0-9a-fA-F]|\$)"
  "^[[:space:]]*[0-9a-fA-F]{64}[[:space:]]*\$"
  # Service tokens.
  "gh[opsu]_[A-Za-z0-9]{30,}"
  "github_pat_[A-Za-z0-9_]{30,}"
  "sk-[A-Za-z0-9_-]{30,}"
  "AKIA[0-9A-Z]{16}"
  # An env-style assignment holding a literal rather than a reference.
  "[A-Z_]*(API_KEY|API_TOKEN|SECRET)[A-Z_]*=[^ \$\"'{<(]{8,}"
)

[ "${SECRET_SCAN_LIB_ONLY:-0}" = 1 ] && return 0

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
hits=0

scan() {
  local file="$1" name="$2" i lines
  [ -f "$file" ] || return 0
  for i in "${!SECRET_PATTERNS[@]}"; do
    lines="$(LC_ALL=C grep -a -n -E -e "${SECRET_PATTERNS[$i]}" -- "$file" 2>/dev/null | cut -d: -f1 | head -5 | tr '\n' ' ')"
    if [ -n "$lines" ]; then
      echo "SECRET HIT: $name: line ${lines% } [rule $((i + 1))]"
      hits=$((hits + 1))
    fi
  done
}

count=0
if [ "${1:-}" = "--files" ]; then
  shift
  [ "$#" -gt 0 ] || { echo "SECRET ERROR: --files needs a file" >&2; exit 2; }
  for f in "$@"; do
    [ -f "$f" ] || { echo "SECRET ERROR: no file $(basename "$f")" >&2; exit 2; }
    scan "$f" "$(basename "$f")"
    count=$((count + 1))
  done
else
  while IFS= read -r -d '' path; do
    scan "$REPO/$path" "$path"
    count=$((count + 1))
  done < <(git -C "$REPO" ls-files -z --cached --others --exclude-standard)
  [ "$count" -gt 0 ] || { echo "SECRET ERROR: the tree listing is empty" >&2; exit 2; }
fi

if [ "$hits" -gt 0 ]; then
  echo "SECRET FAIL: $hits hits"
  exit 1
fi
echo "SECRET OK: $count files, ${#SECRET_PATTERNS[@]} rules"
