#!/usr/bin/env bash
# The secret scan must know the shapes this project itself writes, and git must ignore the files
# that hold them. Every value here is made up at run time and never written inside the repo.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
SCAN="$REPO/scripts/secret-scan.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
bad=0
hex64="$(printf 'ab%.0s' $(seq 1 32))"

must_hit() {
  local name="$1" file="$WORK/plant"
  printf '%s\n' "$2" > "$file"
  if "$SCAN" --files "$file" > "$WORK/out" 2>&1; then
    echo "FAIL the scan missed $name"
    bad=1
  else
    grep -q "SECRET HIT" "$WORK/out" || { echo "FAIL $name: no hit line"; bad=1; }
    if grep -q "$hex64" "$WORK/out"; then
      echo "FAIL $name: the scan printed the value"
      bad=1
    fi
    echo "PASS hit: $name"
  fi
}

must_pass() {
  local name="$1" file="$WORK/plant"
  printf '%s\n' "$2" > "$file"
  if "$SCAN" --files "$file" > "$WORK/out" 2>&1; then
    echo "PASS clean: $name"
  else
    echo "FAIL false alarm: $name"
    bad=1
  fi
}

must_hit "a recovery file's cold key" "{\"format\":\"undo-recovery-v1\",\"cold_key\": \"$hex64\"}"
must_hit "a dispenser file's secret" "{\"format\":\"undo-dispenser-v1\",\"secret\": \"$hex64\"}"
must_hit "a seed file, the value alone on a line" "$hex64"
must_hit "an env-style seed" "seed=$hex64"
must_hit "uppercase hex" "\"cold_key\": \"$(printf 'AB%.0s' $(seq 1 32))\""

must_hit "a generic key field" "{\"key\": \"$hex64\"}"
must_hit "a short name" "sk = \"$hex64\""
must_hit "privkey" "privkey: $hex64"
must_hit "a 0x prefix" "key=0x$hex64"
must_hit "a hex! literal bound to a key" "let key = hex!(\"$hex64\");"
must_hit "a typed hex! literal" "const COLD_SK: [u8; 32] = hex!(\"$hex64\");"
must_hit "a NEAR secp256k1 secret" "\"secret_key_field\": \"secp256k1:$(printf 'z%.0s' $(seq 1 44))\""
must_pass "a NEAR secp256k1 public key" "\"pk\": \"secp256k1:$(printf 'z%.0s' $(seq 1 88))\""
must_pass "a hex! digest" "let digest = hex!(\"$hex64\");"
must_pass "a hex! txid" "const TXID: [u8; 32] = hex!(\"$hex64\");"
must_pass "a name that only ends in key" "vault_key = $hex64"
must_pass "a monkey" "monkey: $hex64"
must_pass "a txid" "{\"txid\": \"$hex64\", \"vout\": 0}"
must_pass "a vault id" "{\"vault\": \"$hex64\"}"
must_pass "a digest in a sentence" "digest $hex64 was signed"
must_pass "a checksum field" "checksum = \"$hex64\""
must_pass "an empty secret field" "\"secret\": \"\""
topic="$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 22)"
must_hit "a watcher config's ntfy topic" "{\"ntfy_server\": \"https://ntfy.sh\", \"ntfy_topic\": \"$topic\"}"
must_hit "an ntfy.sh topic URL" "subscribe at https://ntfy.sh/$topic"
must_pass "an ntfy.sh docs link" "see https://ntfy.sh/docs/publish/"
must_pass "a topic placeholder" "https://ntfy.sh/<topic>"

for path in proofs/vault-recovery.json recovery.json proofs/recovery-1.json my-seed.txt seed-backup.txt x.seed \
  dispenser.json funding-key.json cold-file.json vault-cold-key.txt .undo-watch/config.json undo-watch.json undo-watch-config.json; do
  if git -C "$REPO" check-ignore -q --no-index "$path"; then
    echo "PASS ignored: $path"
  else
    echo "FAIL git would publish $path"
    bad=1
  fi
done
for path in tools/lib/recovery.mjs crates/undo-btc/src/recovery.rs crates/undo-btc/tests/recovery.rs tools/lib/cold-intent.mjs; do
  if git -C "$REPO" check-ignore -q --no-index "$path"; then
    echo "FAIL source file is ignored: $path"
    bad=1
  fi
done

[ "$bad" -eq 0 ] && echo "SECRET FORMATS OK" || { echo "SECRET FORMATS FAILED"; exit 1; }
