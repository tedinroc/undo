#!/usr/bin/env bash
# Proves the repo's guards can both pass and fail. Every "refused" case must fail with its own
# expected message, so a script that crashes does not count as a refusal. Planted files are
# removed on exit. Makes no commit: hooks are invoked through `git hook run`.
#
#   prove-a1.sh                   all checks
#   prove-a1.sh --dirty FILE      also require the gate to refuse FILE, a wasm known to hold local paths
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$REPO"
TARGET="${CARGO_TARGET_DIR:-$REPO/target}"
S="$REPO/scripts"
LIST="${UNDO_BLOCKED_WORDS:-$REPO/../plan/blocked-words.txt}"
WORK="$TARGET/prove-a1"
rm -rf "$WORK"
mkdir -p "$WORK"
export TMPDIR="$WORK"

dirty=""
[ "${1:-}" = "--dirty" ] && dirty="${2:?}"

planted=()
cleanup() {
  if [ "${#planted[@]}" -gt 0 ]; then rm -f "${planted[@]}"; fi
}
trap cleanup EXIT

passes=0
wrong=0

accepted() {
  local label="$1"; shift
  local out
  if out="$("$@" 2>&1)"; then
    echo "PASS accepted: $label"
    passes=$((passes + 1))
  else
    echo "WRONG should be accepted: $label"
    printf '%s\n' "$out" | tail -5 | sed 's/^/    /'
    wrong=$((wrong + 1))
  fi
}

refused() {
  local label="$1" expect="$2"; shift 2
  local out code
  out="$("$@" 2>&1)"
  code=$?
  if [ "$code" -ne 0 ] && printf '%s\n' "$out" | grep -q -F -e "$expect"; then
    echo "PASS refused: $label"
    passes=$((passes + 1))
  else
    echo "WRONG should be refused with '$expect' (exit $code): $label"
    printf '%s\n' "$out" | tail -5 | sed 's/^/    /'
    wrong=$((wrong + 1))
  fi
}

first_word="$(grep -v -E '^(#|$)' "$LIST" | head -1)"
[ -n "$first_word" ] || { echo "cannot read a word from the blocked list" >&2; exit 2; }

echo "== build"
accepted "scripts/build.sh" "$S/build.sh"
for f in undo_vault mock_signer; do
  [ -s "$TARGET/near/$f.wasm" ] || { echo "no $f.wasm" >&2; exit 2; }
done
wasm="$TARGET/near/undo_vault.wasm"
before="$(shasum -a 256 "$wasm" | cut -d' ' -f1)"
accepted "check-wasm on the default build" "$S/check-wasm.sh"
accepted "identity check on built wasm and tree" "$S/check-identity.sh"
accepted "secret scan on the tree" "$S/secret-scan.sh"
accepted "outward gate on the default build" "$S/outward-check.sh"

echo "== a plain build without scripts/build.sh"
refused "plain cargo build has no --cfg near" "build with scripts/build.sh" \
  env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS CARGO_TARGET_DIR="$WORK/plain" \
  cargo build -q --locked -p undo-vault --target wasm32-unknown-unknown --release

echo "== the export check can fail"
# The contract has no EVM code to build, so the export check's control is a small fixture.
wasm-opt "$REPO/tests/fixtures/evm_control.wat" -o "$WORK/evm_control.wasm" 2>/dev/null
refused "check-wasm on a wasm exporting propose_evm" "exports propose_evm" "$S/check-wasm.sh" --file "$WORK/evm_control.wasm"
accepted "rebuild" "$S/build.sh"
after="$(shasum -a 256 "$wasm" | cut -d' ' -f1)"
if [ "$before" = "$after" ]; then
  echo "PASS default wasm has the same sha256 after a rebuild"
  passes=$((passes + 1))
else
  echo "WRONG default wasm changed after a rebuild: $before then $after"
  wrong=$((wrong + 1))
fi
refused "check-wasm on a missing file" "no wasm" "$S/check-wasm.sh" --file "$WORK/does-not-exist.wasm"
promise_canary="$REPO/contracts/undo/src/canary-$$.rs"
planted+=("$promise_canary")
printf 'use near_sdk::{env, Promise};\n' > "$promise_canary"
refused "contract source that imports Promise" "high-level Promise API" "$S/check-wasm.sh"
printf 'fn f() { Self::ext(a); }\n' > "$promise_canary"
refused "contract source that uses Self::ext" "high-level Promise API" "$S/check-wasm.sh"
rm -f "$promise_canary"
accepted "check-wasm after removing the planted source" "$S/check-wasm.sh"

echo "== the wasm identity check catches each kind of leak"
plant_wasm() {
  local out="$WORK/planted-$1.wasm"
  cp "$wasm" "$out"
  printf '%s' "$2" >> "$out"
  printf '%s' "$out"
}
for spec in "home:$HOME" "user:$(id -un)" "host:$(hostname -s)" "word:$first_word" "upper:$(printf '%s' "$first_word" | tr '[:lower:]' '[:upper:]')"; do
  name="${spec%%:*}"
  value="${spec#*:}"
  refused "wasm with a planted value: $name" "IDENTITY HIT" "$S/check-identity.sh" --wasm "$(plant_wasm "$name" "$value")"
done
refused "outward gate on a planted wasm" "OUTWARD FAIL" "$S/outward-check.sh" --wasm "$WORK/planted-home.wasm"
if [ -n "$dirty" ]; then
  refused "outward gate on a known dirty wasm" "IDENTITY HIT" "$S/outward-check.sh" --wasm "$dirty"
fi

echo "== the check fails closed"
refused "blocked list missing" "blocked list not readable" env UNDO_BLOCKED_WORDS="$WORK/no-such-list" "$S/check-identity.sh"
: > "$WORK/empty-list"
refused "blocked list empty" "blocked list is empty" env UNDO_BLOCKED_WORDS="$WORK/empty-list" "$S/check-identity.sh"
printf '# only a comment\n\n' > "$WORK/comment-list"
refused "blocked list with only comments" "blocked list is empty" env UNDO_BLOCKED_WORDS="$WORK/comment-list" "$S/check-identity.sh"
printf 'a\n' > "$WORK/short-list"
refused "blocked list with a one-letter word" "too short" env UNDO_BLOCKED_WORDS="$WORK/short-list" "$S/check-identity.sh"
refused "no wasm to check" "no built wasm" env CARGO_TARGET_DIR="$WORK/empty-target" "$S/check-identity.sh"
refused "named wasm missing" "no wasm" "$S/check-identity.sh" --wasm "$WORK/does-not-exist.wasm"
refused "outward gate with no wasm" "no built wasm" env CARGO_TARGET_DIR="$WORK/empty-target" "$S/outward-check.sh"

echo "== the tree check"
canary="$REPO/docs/canary-$$.txt"
planted+=("$canary")
printf 'a line\nmentions %s here\n' "$first_word" > "$canary"
refused "new file with a blocked word in it" "IDENTITY HIT" "$S/check-identity.sh" --tree
rm -f "$canary"
printf 'path %s/somewhere\n' "$HOME" > "$canary"
refused "new file with the home path in it" "IDENTITY HIT" "$S/check-identity.sh" --tree
rm -f "$canary"
named="$REPO/docs/$first_word-$$.txt"
planted+=("$named")
printf 'clean\n' > "$named"
refused "new file with a blocked word in its name" "IDENTITY HIT" "$S/check-identity.sh" --tree
rm -f "$named"
printf '%s\n' "Ted Ch""en" > "$canary"
refused "author name in a page or doc" "author name outside" "$S/check-identity.sh" --tree
rm -f "$canary"
accepted "tree is clean again" "$S/check-identity.sh" --tree

echo "== the secret scan"
fake_token="gh""p_$(printf 'a%.0s' $(seq 1 36))"
printf 'token %s\n' "$fake_token" > "$canary"
refused "new file with a token shape" "SECRET HIT" "$S/secret-scan.sh"
rm -f "$canary"
fake_near="ed25519:$(printf 'A%.0s' $(seq 1 88))"
printf '{"key":"%s"}\n' "$fake_near" > "$canary"
refused "new file with a NEAR secret key shape" "SECRET HIT" "$S/secret-scan.sh"
rm -f "$canary"
printf '{"key":"ed25519:%s"}\n' "$(printf 'A%.0s' $(seq 1 44))" > "$canary"
accepted "a NEAR public key shape is fine" "$S/secret-scan.sh"
rm -f "$canary"

echo "== the secret scan on this project's own key formats"
accepted "scripts/test-secret-scan.sh" "$S/test-secret-scan.sh"

echo "== commit-msg, through git"
msg="$WORK/msg"
printf 'Add the vault\n\nBody text.\n' > "$msg"
accepted "plain message" git hook run commit-msg -- "$msg"
printf 'Add the vault\n\nCo-Authored-By: Someone <a@example.com>\n' > "$msg"
refused "Co-Authored-By trailer" "refused" git hook run commit-msg -- "$msg"
printf 'Add the vault\n\nco-authored-by: Someone <a@example.com>\n' > "$msg"
refused "lower-case trailer" "refused" git hook run commit-msg -- "$msg"
printf 'Add the vault\n\nGenerated with Claude Code\n' > "$msg"
refused "generated-by line" "refused" git hook run commit-msg -- "$msg"
printf 'Add the vault\n\n# ------------------------ >8 ------------------------\n+Co-Authored-By: only in the diff\n' > "$msg"
accepted "trailer text only below the verbose diff line" git hook run commit-msg -- "$msg"

echo "== pre-commit, through git"
accepted "identity set, TZ=Asia/Taipei" env TZ=Asia/Taipei git hook run pre-commit
refused "TZ=America/Los_Angeles" "timezone" env TZ=America/Los_Angeles git hook run pre-commit
refused "a different author email" "not the public identity" \
  env TZ=Asia/Taipei GIT_AUTHOR_EMAIL=someone@example.com git hook run pre-commit
refused "a different committer name" "not the public identity" \
  env TZ=Asia/Taipei GIT_COMMITTER_NAME=Someone git hook run pre-commit

echo "== pre-push, through git, without commits"
good_url="git@github.com:tedinroc/undo.git"
stdin="$WORK/stdin"
: > "$stdin"
accepted "no refs, clean tree, right remote" git hook run --to-stdin="$stdin" pre-push -- origin "$good_url"
refused "another owner's remote" "is not tedinroc/undo" git hook run --to-stdin="$stdin" pre-push -- origin "git@github.com:someone/undo.git"
refused "a lookalike owner" "is not tedinroc/undo" git hook run --to-stdin="$stdin" pre-push -- origin "git@github.com:nottedinroc/undo.git"
refused "another host" "is not tedinroc/undo" git hook run --to-stdin="$stdin" pre-push -- origin "https://example.com/tedinroc/undo.git"
printf 'refs/heads/main 1111111111111111111111111111111111111111 refs/heads/main 0000000000000000000000000000000000000000\n' > "$stdin"
refused "a ref whose history cannot be read" "cannot read its history" git hook run --to-stdin="$stdin" pre-push -- origin "$good_url"
: > "$stdin"
printf 'mentions %s\n' "$first_word" > "$canary"
refused "blocked word in the tree" "IDENTITY HIT" git hook run --to-stdin="$stdin" pre-push -- origin "$good_url"
rm -f "$canary"
printf 'token %s\n' "$fake_token" > "$canary"
refused "secret in the tree" "SECRET HIT" git hook run --to-stdin="$stdin" pre-push -- origin "$good_url"
rm -f "$canary"
refused "blocked list missing" "blocked list not readable" env UNDO_BLOCKED_WORDS="$WORK/no-such-list" git hook run --to-stdin="$stdin" pre-push -- origin "$good_url"

echo
accepted "final identity check on built wasm and tree" "$S/check-identity.sh"
echo "$passes passed, $wrong wrong"
if [ -n "$(git -C "$REPO" rev-list -n 1 --all 2>/dev/null)" ]; then
  echo "note: this repo has commits"
else
  echo "repo has no commits"
fi
[ "$wrong" -eq 0 ]
