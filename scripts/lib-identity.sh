# Shared by the identity scripts and the git hooks. Source it, do not run it.
#
# Every pattern is built at run time: machine values come from this machine, and the blocked
# list comes from a file outside the repo, so nothing here names anybody. Output reports where
# a hit is and which rule fired, never the matched text, so a log cannot leak the list.

IDENTITY_REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
IDENTITY_TARGET="${CARGO_TARGET_DIR:-$IDENTITY_REPO/target}"
# The plan's place for the list is private/ beside the repo. Until that exists, the copy in plan/.
if [ -r "$IDENTITY_REPO/../private/blocked-names.txt" ]; then
  IDENTITY_BLOCKED_DEFAULT="$IDENTITY_REPO/../private/blocked-names.txt"
else
  IDENTITY_BLOCKED_DEFAULT="$IDENTITY_REPO/../plan/blocked-words.txt"
fi
IDENTITY_BLOCKED_FILE="${UNDO_BLOCKED_WORDS:-$IDENTITY_BLOCKED_DEFAULT}"
IDENTITY_PATTERNS=()
IDENTITY_LABELS=()

identity_add() {
  # Skip empty values: an empty pattern would match everything. Skip very short ones: they
  # would only produce noise. "localhost" is a default hostname, not an identity.
  local label="$1" value="$2"
  [ "${#value}" -ge 3 ] || return 0
  [ "$value" != "localhost" ] || return 0
  IDENTITY_PATTERNS+=("$value")
  IDENTITY_LABELS+=("$label")
}

# Fails closed: a missing or empty list stops the caller, it does not pass.
identity_load_patterns() {
  IDENTITY_PATTERNS=()
  IDENTITY_LABELS=()
  if [ ! -r "$IDENTITY_BLOCKED_FILE" ]; then
    echo "IDENTITY ERROR: blocked list not readable (set UNDO_BLOCKED_WORDS)" >&2
    return 2
  fi
  local line n=0 words=0
  while IFS= read -r line || [ -n "$line" ]; do
    n=$((n + 1))
    line="${line%$'\r'}"
    case "$line" in ''|'#'*) continue ;; esac
    if [ "${#line}" -lt 3 ]; then
      echo "IDENTITY ERROR: blocked list line $n is too short" >&2
      return 2
    fi
    IDENTITY_PATTERNS+=("$line")
    IDENTITY_LABELS+=("blocked list line $n")
    words=$((words + 1))
  done < "$IDENTITY_BLOCKED_FILE"
  if [ "$words" -eq 0 ]; then
    echo "IDENTITY ERROR: blocked list is empty" >&2
    return 2
  fi

  # Split so that this file does not match its own scan.
  identity_add "local path form" "/Us""ers/"
  identity_add "local path form" "/ho""me/"
  identity_add "local path form" "/var/fol""ders/"
  identity_add "local path form" "/private/t""mp/"
  identity_add "home directory" "$HOME"
  identity_add "username" "$(id -un)"
  identity_add "hostname" "$(hostname -s 2>/dev/null || true)"
  identity_add "hostname" "$(hostname 2>/dev/null || true)"
  if command -v scutil >/dev/null 2>&1; then
    identity_add "hostname" "$(scutil --get LocalHostName 2>/dev/null || true)"
    identity_add "computer name" "$(scutil --get ComputerName 2>/dev/null || true)"
  fi
}

# Prints every file git could ever publish from the tree, tracked or new, NUL separated.
identity_tree_files() {
  git -C "$IDENTITY_REPO" ls-files -z --cached --others --exclude-standard
}
