#!/usr/bin/env bash
# Builds undo-core for wasm32 with path remapping and fails if the output names this machine.
# Machine values are read at run time, so this script names nobody. Set CARGO_TARGET_DIR first.
set -euo pipefail
cd "$(dirname "$0")"
: "${CARGO_TARGET_DIR:?set CARGO_TARGET_DIR}"
: "${CARGO_HOME:=$HOME/.cargo}"
crate_root="$(cd .. && pwd)"
# The last matching prefix wins, so the widest comes first.
export RUSTFLAGS="--cfg near -C link-arg=-s --remap-path-prefix=$HOME=/home --remap-path-prefix=$crate_root=/src --remap-path-prefix=$CARGO_HOME=/cargo"
export CARGO_TARGET_DIR="$CARGO_TARGET_DIR/wasm-paths"
cargo build -q -p undo-core --target wasm32-unknown-unknown --release
rlib="$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/libundo_core.rlib"
test -s "$rlib"
pattern="$HOME|/Us""ers/|$(id -un)|$(hostname -s)|Documents|Codex"
if strings "$rlib" | grep -E "$pattern" >/dev/null; then
  echo "FAIL: $(strings "$rlib" | grep -cE "$pattern") strings name this machine" >&2
  exit 1
fi
echo "PASS: wasm32 rlib has no local path, username or hostname ($(wc -c < "$rlib" | tr -d ' ') bytes)"
