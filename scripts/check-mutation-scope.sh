#!/usr/bin/env bash
# Fail if an unbounded mutation command reappears in a build or CI file.
#
# Whole-workspace mutation runs take hours and rarely finish, so they are
# prohibited: the only permitted forms are a diff-scoped (`--in-diff`), a
# file-scoped (`--file`), or a branch-scoped (`--since`) run.
#
# The Justfile and the Makefile both call this script, so `just
# check-mutation-scope` and `make check-mutation-scope` enforce the same rule.
set -euo pipefail
status=0
for file in Justfile justfile Makefile makefile .github/workflows/*.yml .github/workflows/*.yaml; do
  [ -f "$file" ] || continue
  offenders=$(grep -nE 'cargo[[:space:]]+mutants' "$file" \
    | grep -vE '^[0-9]+:[[:space:]]*#' \
    | grep -vE -- '--in-diff|--file|--list|--since|-f[[:space:]]' \
    || true)
  if [ -n "$offenders" ]; then
    echo "error: $file runs an unbounded mutation command:" >&2
    printf '%s\n' "$offenders" >&2
    echo "       Whole-workspace mutation runs are prohibited. Use the diff-scoped 'just mutants'." >&2
    status=1
  fi
done
exit "$status"
