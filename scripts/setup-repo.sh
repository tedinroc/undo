#!/usr/bin/env bash
# Run once per clone. Git does not carry hooks or local identity across a clone.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
git config core.hooksPath .githooks
git config user.name "Ted Chen"
git config user.email "37988075+tedinroc@users.noreply.github.com"
echo "hooks: $(git config core.hooksPath), identity: $(git config user.name) <$(git config user.email)>"
