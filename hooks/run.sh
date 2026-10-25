#!/usr/bin/env bash
# Launch the pivyon-shield PreToolUse hook.
#
# Cheap pre-filter first: most Bash calls (ls, git, tests) and most edits
# never touch a package manager or a manifest, so they exit here in a few
# milliseconds without starting Python. The patterns are in prefilter-*.txt. Anything this lets through is parsed
# properly by the Python side, which is the real judge.
set -u

input="$(cat)"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

case "$input" in
  *'"tool_name":"Bash"'* | *'"tool_name": "Bash"'*)
    printf '%s' "$input" | grep -Eq -f "$here/prefilter-commands.txt" || exit 0
    ;;
  *)
    printf '%s' "$input" | grep -Eiq -f "$here/prefilter-files.txt" || exit 0
    ;;
esac

export PYTHONUTF8=1
export PYTHONDONTWRITEBYTECODE=1
script="$here/../scripts/shield.py"
if command -v cygpath >/dev/null 2>&1; then
  script="$(cygpath -w "$script")"
fi

# python3 first; on Windows it may be the Microsoft Store stub, so probe it.
for py in python3 python "py -3"; do
  if $py -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' >/dev/null 2>&1; then
    printf '%s' "$input" | $py "$script" hook
    exit 0
  fi
done
# No Python 3.8+: fail open, but say so once per call on stderr.
echo "pivyon-shield: Python 3.8+ not found; packages were not checked." >&2
exit 0
