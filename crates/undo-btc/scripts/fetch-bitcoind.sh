#!/usr/bin/env bash
# Downloads the official Bitcoin Core release used by tests/regtest.rs into .tools/ (gitignored).
#
# The hash below was copied from the release's SHA256SUMS on bitcoincore.org. It catches a changed
# download. The signatures in SHA256SUMS.asc are not checked here, so this is trust in that site
# and in this pinned value, nothing stronger.
set -euo pipefail

VERSION=32.1
case "$(uname -s)-$(uname -m)" in
  Darwin-arm64)  NAME="bitcoin-$VERSION-arm64-apple-darwin.tar.gz"; SHA=cd3dcdacb4ff861e862b2d7df4786ecef66472e2468dca1673a70dd761e064e7 ;;
  Linux-x86_64)  NAME="bitcoin-$VERSION-x86_64-linux-gnu.tar.gz"; SHA=61545c17c3120fb7412f896d248b11993af04ec8817aad3649c55b2afb044963 ;;
  *) echo "fetch-bitcoind: no pinned release for this platform" >&2; exit 2 ;;
esac

CRATE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
DEST="$CRATE/.tools/bitcoin-$VERSION"
if [ -x "$DEST/bin/bitcoind" ] && [ -x "$DEST/bin/bitcoin-cli" ]; then
  echo "bitcoind $VERSION already present"
  exit 0
fi

WORK="$CRATE/.tools/download-$$"
mkdir -p "$WORK"
trap 'rm -rf "$WORK"' EXIT
curl -sSfL --max-time 600 -o "$WORK/$NAME" "https://bitcoincore.org/bin/bitcoin-core-$VERSION/$NAME"

if command -v sha256sum >/dev/null 2>&1; then
  GOT="$(sha256sum "$WORK/$NAME" | cut -d' ' -f1)"
else
  GOT="$(shasum -a 256 "$WORK/$NAME" | cut -d' ' -f1)"
fi
if [ "$GOT" != "$SHA" ]; then
  echo "fetch-bitcoind: hash mismatch, nothing installed" >&2
  exit 1
fi

mkdir -p "$DEST/bin"
tar -xzf "$WORK/$NAME" -C "$WORK" "bitcoin-$VERSION/bin/bitcoind" "bitcoin-$VERSION/bin/bitcoin-cli"
mv "$WORK/bitcoin-$VERSION/bin/bitcoind" "$WORK/bitcoin-$VERSION/bin/bitcoin-cli" "$DEST/bin/"
"$DEST/bin/bitcoind" -version | head -1
