#!/usr/bin/env bash
# Diff-scoped mutation gate.
#
# Whole-workspace mutation runs are prohibited: a `cargo mutants` run over the
# whole workspace takes hours and rarely finishes, so it is never a gate and
# never a completion check. Only the lines the current change touched are
# mutated, within the /pb-build budget: at most 3 files, 60 mutants, 300 s.
#
# The Justfile and the Makefile both call this script, so `just mutants` and
# `make mutants` run exactly the same gate.
#
# Usage: scripts/mutation-diff.sh [workspace-relative-rs-file ...]
set -euo pipefail
max_files=3
max_mutants=60
max_seconds=300

base=""
upstream=$(git rev-parse --abbrev-ref --symbolic-full-name '@{upstream}' 2>/dev/null || true)
for ref in "$upstream" origin/main origin/master main master; do
  [ -n "$ref" ] || continue
  if git rev-parse --verify --quiet "$ref" >/dev/null 2>&1; then
    base=$(git merge-base HEAD "$ref" 2>/dev/null || true)
    [ -n "$base" ] && break
  fi
done
[ -n "$base" ] || base=HEAD

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
if [ "$#" -gt 0 ]; then
  printf '%s\n' "$@" | sed '/^[[:space:]]*$/d' > "$work/files"
else
  git diff --name-only --diff-filter=ACMR "$base" -- '*.rs' | sort -u > "$work/files"
fi
file_count=$(grep -c . "$work/files" || true)
if [ "$file_count" -eq 0 ]; then
  echo "error: no changed Rust files against $base; there is nothing to mutate." >&2
  echo "       Whole-workspace mutation is prohibited: it takes hours and rarely finishes." >&2
  exit 2
fi
if [ "$file_count" -gt "$max_files" ]; then
  echo "error: $file_count files exceed the ${max_files}-file mutation budget." >&2
  echo "       Mutate fewer files at a time; never raise the budget, never run the workspace." >&2
  exit 3
fi

: > "$work/diff"
while IFS= read -r file; do
  [ -n "$file" ] || continue
  git diff --no-ext-diff --no-textconv "$base" -- "$file" >> "$work/diff" || true
done < "$work/files"
if ! grep -q '^diff --git ' "$work/diff"; then
  echo "error: the diff against $base is empty; there is nothing to mutate." >&2
  exit 2
fi
RUSTC_WRAPPER= cargo mutants --workspace --all-features --in-diff "$work/diff" --list --no-times > "$work/list" 2>&1 \
  || { cat "$work/list" >&2; echo "error: cargo-mutants could not list the mutants." >&2; exit 1; }
mutant_count=$(grep -Ec ':[0-9]+:[0-9]+:' "$work/list" || true)
if [ "$mutant_count" -gt "$max_mutants" ]; then
  echo "error: $mutant_count mutants exceed the ${max_mutants}-mutant budget." >&2
  echo "       Narrow the change; never raise the budget, never fall back to a workspace run." >&2
  exit 3
fi
if [ "$mutant_count" -eq 0 ]; then
  echo "ok: no mutants in the changed lines."
  exit 0
fi

echo "mutating $mutant_count mutant(s) in $file_count file(s) (budget: $max_mutants mutants / ${max_seconds}s)"
if command -v timeout >/dev/null 2>&1; then
  timeout "$max_seconds" env RUSTC_WRAPPER= cargo mutants --workspace --all-features --in-diff "$work/diff" --timeout-multiplier 2 --no-times
elif command -v gtimeout >/dev/null 2>&1; then
  gtimeout "$max_seconds" env RUSTC_WRAPPER= cargo mutants --workspace --all-features --in-diff "$work/diff" --timeout-multiplier 2 --no-times
else
  echo "warning: neither 'timeout' nor 'gtimeout' is available; the ${max_seconds}s wall-clock cap is not enforced." >&2
  echo "         Install coreutils ('brew install coreutils') to get 'gtimeout'." >&2
  env RUSTC_WRAPPER= cargo mutants --workspace --all-features --in-diff "$work/diff" --timeout-multiplier 2 --no-times
fi
