#!/usr/bin/env bash
# Builds this crate's code to wasm with paths remapped, then fails if `strings` finds a local path,
# username, hostname or blocked word in the result. The scan is the repo's own check-identity.sh.
#
#   check-wasm-identity.sh            remapped build must be clean
#   check-wasm-identity.sh --control  also proves the scan can fail, on a planted path and on a
#                                     build with no remap
#
# Exit 0 clean, 1 hit, 2 could not run.
set -euo pipefail

CRATE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
REPO="$(cd "$CRATE/../.." && pwd -P)"
SCAN="$REPO/scripts/check-identity.sh"
[ -x "$SCAN" ] || { echo "no $(basename "$SCAN")" >&2; exit 2; }

CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
TARGET="${CARGO_TARGET_DIR:-$CRATE/target}"
export CARGO_HOME CARGO_TARGET_DIR="$TARGET" CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}"
unset CARGO_ENCODED_RUSTFLAGS

for p in "$HOME" "$REPO" "$TARGET" "$CARGO_HOME"; do
  case "$p" in
    *[[:space:]]*) echo "paths with spaces are not supported" >&2; exit 2 ;;
  esac
done

build() {
  cargo build -q --offline --manifest-path "$CRATE/wasm-probe/Cargo.toml" --target wasm32-unknown-unknown --release
}

WASM="$TARGET/wasm32-unknown-unknown/release/undo_btc_wasm_probe.wasm"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/undo-btc-identity.XXXXXX")"
trap 'rm -rf "$OUT"' EXIT

# Widest prefix first and the registry last: rustc applies the last matching remap.
export RUSTFLAGS="-C link-arg=-s --remap-path-prefix=$HOME=/home --remap-path-prefix=$REPO=/src --remap-path-prefix=$TARGET=/target --remap-path-prefix=$CARGO_HOME=/cargo"
build
cp "$WASM" "$OUT/clean.wasm"
echo "remapped build: $(wc -c < "$OUT/clean.wasm" | tr -d ' ') bytes, $(strings -a "$OUT/clean.wasm" | wc -l | tr -d ' ') strings"
"$SCAN" --wasm "$OUT/clean.wasm"

[ "${1:-}" = "--control" ] || exit 0

# Control 1: plant a path. The scan must fail, so a clean result above means something.
cp "$OUT/clean.wasm" "$OUT/planted.wasm"
printf '%s' "$HOME/some/source.rs" >> "$OUT/planted.wasm"
if "$SCAN" --wasm "$OUT/planted.wasm" >/dev/null 2>&1; then
  echo "CONTROL FAIL: the scan passed a wasm with a planted path"
  exit 1
fi
echo "control: planted path caught"

# Control 2: the same code with no remap must have hits, or the remap is not what made it clean.
export RUSTFLAGS="-C link-arg=-s"
build
cp "$WASM" "$OUT/unmapped.wasm"
hits="$("$SCAN" --wasm "$OUT/unmapped.wasm" 2>&1 | grep -c 'IDENTITY HIT' || true)"
if [ "$hits" -eq 0 ]; then
  echo "CONTROL FAIL: a build with no remap has no identity hits"
  exit 1
fi
echo "control: build with no remap has $hits identity hits"
