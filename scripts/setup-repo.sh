#!/usr/bin/env bash
# For the author's own clone only: sets the commit hooks and the identity this repository is published under.
# Nobody needs it to build, test or verify anything, and it never runs unasked: without --author it changes nothing.
#
#   scripts/setup-repo.sh --author    hooks plus the author's name and noreply address, in this clone's config
#   scripts/setup-repo.sh --hooks     the hooks alone
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
case "${1:-}" in
  --author)
    git config core.hooksPath .githooks
    git config user.name "Ted Chen"
    git config user.email "37988075+tedinroc@users.noreply.github.com"
    echo "hooks: $(git config core.hooksPath), identity: $(git config user.name) <$(git config user.email)>" ;;
  --hooks)
    git config core.hooksPath .githooks
    echo "hooks: $(git config core.hooksPath). Identity left as it was. The pre-commit hook accepts only the author's identity." ;;
  *)
    echo "setup-repo.sh: nothing changed. This is for the author's clone: --author sets the hooks and the author's identity, --hooks the hooks alone. Building and verifying need neither." >&2
    exit 2 ;;
esac
