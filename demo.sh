#!/usr/bin/env bash
# Self-test on a vault you just created, with no browser and no key of your own: a throwaway vault
# with a software passkey, a proposal to a new address, a passkey cancel, then a send to a known
# address that the signer signs after its wait. Through the relay that deploy/testnet.json names,
# which pays the NEAR. No coin moves. Needs Node 20+, and Rust for the last line.
#
#   ./demo.sh                  against deploy/testnet.json
#   UNDO_CONFIG=FILE ./demo.sh against another deployment file, such as a local stage
#
# If the relay is down or at its daily limit, or nothing is deployed yet, it prints SKIP and points
# to ./verify.sh A (replay of real hashes) and ./verify.sh B (offline tests). Exit 0 PASS, 1 FAIL, 3 SKIP.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
if ! command -v node >/dev/null 2>&1; then
  echo "SKIP demo node is not installed: demo.sh needs Node 20 or later"
  exit 3
fi
exec node tools/demo/demo.mjs "$@"
