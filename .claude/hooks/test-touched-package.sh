#!/usr/bin/env bash
# Run the unit tests of the package that was just edited.
#
# Accuracy is the product: a change to an engine, the catalog or the resolver
# must not sit unverified even for one turn. Anything outside packages/*/src is
# a no-op so editing pages or docs stays instant.

set -uo pipefail

payload=$(cat)
file=$(printf '%s' "$payload" | sed -n 's/.*"file_path"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)

[ -z "$file" ] && exit 0

case "$file" in
  */packages/*/src/*|*/packages/*/test/*) ;;
  *) exit 0 ;;
esac

pkg_dir=${file%%/src/*}
pkg_dir=${pkg_dir%%/test/*}
[ -f "$pkg_dir/package.json" ] || exit 0

name=$(basename "$pkg_dir")
if ! output=$(cd "$pkg_dir" && pnpm vitest run --reporter=dot 2>&1); then
  # Advisory, not blocking: a half-written engine legitimately fails between
  # edits. CI is the hard gate; this is the early warning.
  printf 'packages/%s tests are RED after this edit:\n\n%s\n' "$name" "$(printf '%s' "$output" | tail -30)" >&2
fi

exit 0
