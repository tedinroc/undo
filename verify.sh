#!/usr/bin/env bash
# Checks this repo's claims without a key, a wallet or a browser. CLAIMS.md lists each line.
#
#   ./verify.sh          tier A, then tier B
#   ./verify.sh A        read-only checks against public NEAR RPC and the Mutinynet API, plus a
#                        recovery-file dry run and a static check. Needs Node 20+; Rust for the
#                        consensus lines, which say SKIP without it
#   ./verify.sh B        offline Rust tests: the vault state machine and Bitcoin consensus. Needs Rust
#
# Every line reads PASS, SKIP or FAIL, a claim number from CLAIMS.md, and a label for where it ran:
# [live-testnet] [live-mutinynet] [replay] [consensus-lib] [unit] [static], or [mock-signer] against
# a local stage. A network failure prints SKIP (network), never FAIL. INFO lines are totals, or a
# record read from proofs/ that this run did not check again. Exit 0 means no FAIL.
# UNDO_CONFIG names another deployment file than deploy/testnet.json.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
# Node's bundled CA list is enough for the public endpoints here. With NODE_USE_SYSTEM_CA=1, Node 22 on
# macOS reads the keychain on the first TLS connection, and where that read is blocked it hangs with no timeout.
unset NODE_USE_SYSTEM_CA
tier="${1:-all}"
status=0

need_node() {
  if ! command -v node >/dev/null 2>&1; then
    echo "SKIP tier-A [static] node is not installed: tier A needs Node 20 or later"
    return 1
  fi
  local major
  major="$(node -p 'process.versions.node.split(".")[0]')"
  if [ "$major" -lt 20 ]; then
    echo "SKIP tier-A [static] node $major is too old: tier A needs Node 20 or later"
    return 1
  fi
}

case "$tier" in
  A|a|all|B|b) ;;
  *) echo "usage: ./verify.sh [A|B]" >&2; exit 2 ;;
esac

if [ "$tier" != B ] && [ "$tier" != b ]; then
  if need_node; then
    node tools/verify/tier-a.mjs || status=1
  fi
  [ "$tier" = all ] && echo
fi
if [ "$tier" != A ] && [ "$tier" != a ]; then
  tools/verify/tier-b.sh
  case $? in 0) ;; 3) ;; *) status=1 ;; esac
fi
exit "$status"
