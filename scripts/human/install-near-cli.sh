#!/usr/bin/env bash
# Installs near-cli-rs from its official GitHub release into ~/.local/bin, after checking the release's
# own SHA-256 file. Run by 01-testnet-accounts.sh when near is missing, or by hand.
set -euo pipefail
umask 022
VERSION=0.30.1
ASSET=near-cli-rs-aarch64-apple-darwin
BASE="https://github.com/near/near-cli-rs/releases/download/v$VERSION"

if [ "$(uname -sm)" != "Darwin arm64" ]; then
  echo "This release asset is for Apple silicon only. See the near-cli-rs releases page." >&2
  exit 1
fi
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
curl -fsSL -o "$work/$ASSET.tar.gz" "$BASE/$ASSET.tar.gz"
curl -fsSL -o "$work/$ASSET.tar.gz.sha256" "$BASE/$ASSET.tar.gz.sha256"
want="$(cut -d' ' -f1 "$work/$ASSET.tar.gz.sha256")"
got="$(shasum -a 256 "$work/$ASSET.tar.gz" | cut -d' ' -f1)"
if [ -z "$want" ] || [ "$want" != "$got" ]; then
  echo "Checksum does not match the release. Nothing installed." >&2
  exit 1
fi
mkdir -p "$HOME/.local/bin"
tar xzf "$work/$ASSET.tar.gz" -C "$work" "$ASSET/near"
install -m 755 "$work/$ASSET/near" "$HOME/.local/bin/near"
echo "Installed near $VERSION to ~/.local/bin/near, checksum $got"
