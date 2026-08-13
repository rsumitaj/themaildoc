#!/usr/bin/env bash
#
# Fails if a former employer's brands appear in anything committed.
#
# These names belong to somebody else and have no business in this repo. They
# got in once already: an "at <employer>" line on the practice page, and a note
# in a local skill file naming a competitor's product. Both shipped. A person
# reviewing a diff will not reliably catch the next one, so this does.
#
# `context/` is excluded on purpose. It is gitignored strategy material that
# legitimately discusses competitors, is never built, and never deploys.
#
# Run directly, or as part of `pnpm test`.

set -uo pipefail

# Each name is split across two adjacent quoted strings, which the shell joins
# back together. Written out in full, this file would be the one committed file
# containing them, the check would fail on its own source, and a code search of
# the repo would still turn the names up. Ugly, and correct.
FORBIDDEN="kd""marc|td""marc|threat""cop|krati""kal"

cd "$(dirname "$0")/.." || exit 2

# `git grep` searches tracked content only, which is exactly the question being
# asked: is it committed. Untracked scratch files are the author's business.
hits=$(git grep -niE "$FORBIDDEN" -- . ':(exclude)context/**' || true)

if [ -n "$hits" ]; then
  echo "Forbidden brand names found in committed files:"
  echo
  echo "$hits"
  echo
  echo "These are a former employer's brands. Remove or replace them with a"
  echo "neutral placeholder (example.com, yourcompany.com) before committing."
  exit 1
fi

# The built output is what actually reaches the public, so check it too when it
# happens to exist. A stale dist/ is not a reason to fail a fresh checkout.
if [ -d apps/web/dist ]; then
  built=$(grep -rliE "$FORBIDDEN" apps/web/dist 2>/dev/null || true)
  if [ -n "$built" ]; then
    echo "Forbidden brand names found in the build output:"
    echo
    echo "$built"
    echo
    echo "Source is clean but dist/ is stale. Rebuild before deploying."
    exit 1
  fi
fi

echo "No forbidden brand names in committed files or build output."
