#!/usr/bin/env bash
# The only way to build contract wasm. All rustflags live here, in one place:
#  - Cargo uses RUSTFLAGS instead of target.*.rustflags, so a second source would be dropped.
#  - near-sdk needs --cfg near, or panics lose their text and hashes compile into the wasm.
#  - Absolute paths are computed here and never committed. rustc applies the last matching
#    remap, so the order is widest first and the registry last.
#
#   build.sh              both contracts into <target>/near
#   build.sh --out DIR    the same, into DIR
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$REPO"

out=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --out) out="$2"; shift 2 ;;
    *) echo "build.sh: unknown option" >&2; exit 2 ;;
  esac
done

command -v wasm-opt >/dev/null || { echo "build.sh: wasm-opt not on PATH" >&2; exit 2; }

CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
TARGET="${CARGO_TARGET_DIR:-$REPO/target}"
out="${out:-$TARGET/near}"

# RUSTFLAGS is split on whitespace, so a path with a space would silently break a flag.
for p in "$HOME" "$REPO" "$TARGET" "$CARGO_HOME"; do
  case "$p" in
    *[[:space:]]*) echo "build.sh: paths with spaces are not supported" >&2; exit 2 ;;
  esac
done

# CARGO_ENCODED_RUSTFLAGS would win over RUSTFLAGS and drop everything below.
unset CARGO_ENCODED_RUSTFLAGS
export CARGO_HOME CARGO_TARGET_DIR="$TARGET" CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}"
export RUSTFLAGS="--cfg near -C link-arg=-s --remap-path-prefix=$HOME=/home --remap-path-prefix=$REPO=/src --remap-path-prefix=$TARGET=/target --remap-path-prefix=$CARGO_HOME=/cargo"

cargo build -q --locked -p undo-vault -p mock-signer --target wasm32-unknown-unknown --release
names=(undo_vault mock_signer)

mkdir -p "$out"
for name in "${names[@]}"; do
  wasm-opt -Oz --enable-bulk-memory --enable-sign-ext --enable-mutable-globals --enable-nontrapping-float-to-int --strip-debug \
    "$TARGET/wasm32-unknown-unknown/release/$name.wasm" -o "$out/$name.wasm"
  printf '%s %s bytes sha256 %s\n' "$name.wasm" "$(wc -c < "$out/$name.wasm" | tr -d ' ')" "$(shasum -a 256 "$out/$name.wasm" | cut -d' ' -f1)"
done
