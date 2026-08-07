#!/usr/bin/env bash
#
# R56 hard gate — dependency isolation.
#
# `oc-crypto`, `oc-policy`, `oc-keyagent` and `oc-session-key` must not depend
# on any async runtime or network stack, not even as dev-dependencies. This is
# what keeps the Key-Agent's attack surface auditable: no runtime means no
# hidden task that can open a socket.
#
# Referenced by:
#   - .github/workflows/ci.yml (hard-gates job)
#
# Usage: ci/check_deps.sh

set -uo pipefail

cd "$(dirname "$0")/.."

ISOLATED_CRATES=(oc-crypto oc-policy oc-keyagent oc-session-key)
FORBIDDEN='tokio|reqwest|tungstenite|hyper|async-std|smol'

status=0

for crate in "${ISOLATED_CRATES[@]}"; do
  tree="$(cargo tree -p "$crate" 2>/dev/null)"
  if [ -z "$tree" ]; then
    echo "R56 ERROR: could not compute dependency tree for $crate"
    status=1
    continue
  fi

  # Match the crate name at the start of a tree entry (after the box-drawing
  # prefix) so a substring such as "tokio-util" in an unrelated path, or the
  # crate's own name, does not trigger a false positive.
  hits="$(printf '%s\n' "$tree" \
    | sed -E 's/^[^a-zA-Z]*//' \
    | grep -oE "^($FORBIDDEN) v[0-9][^ ]*" \
    | sort -u)"

  if [ -n "$hits" ]; then
    echo "R56 VIOLATION: forbidden async/network dependency in $crate:"
    printf '  %s\n' $hits
    status=1
  else
    echo "R56 PASS: $crate is free of ($FORBIDDEN)"
  fi
done

if [ "$status" -ne 0 ]; then
  echo
  echo "R56 FAILED. The isolated crates must not gain an async runtime or"
  echo "network stack. If a new dependency pulled one in transitively,"
  echo "disable its default features rather than relaxing this gate."
fi

exit $status
