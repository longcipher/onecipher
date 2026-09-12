#!/usr/bin/env bash
# Justfile <-> Makefile mirror check (deny/CI refinement).
# Fails if any `just` recipe lacks a `make` target or if the command bodies
# drift. Both files must be updated in the same PR.
# Usage: ./scripts/check-makefile-mirror.sh
set -euo pipefail
cd "$(dirname "$0")/.."

# Recipe/target names: Justfile `^name[ params]:` lines (strip params),
# Makefile `^name:` lines.
just_recipes=$(grep -E '^[a-z0-9_-]+[ :]' Justfile | sed -E 's/^([a-z0-9_-]+).*/\1/' | sort -u)
make_targets=$(grep -E '^[a-z0-9_-]+:' Makefile | cut -d: -f1 | sort -u)

fail=0
for r in $just_recipes; do
  # `default` (just --list) maps to `help` in the Makefile.
  if [ "$r" = "default" ]; then
    if ! echo "$make_targets" | grep -qx "help"; then
      echo "MIRROR GAP: just recipe 'default' needs 'make help'"
      fail=1
    fi
    continue
  fi
  if ! echo "$make_targets" | grep -qx "$r"; then
    echo "MIRROR GAP: just recipe '$r' has no 'make $r' target"
    fail=1
  fi
done
for t in $make_targets; do
  if ! echo "$just_recipes" | grep -qx "$t"; then
    # `help` exists only in the Makefile (Justfile uses built-in --list).
    if [ "$t" != "help" ]; then
      echo "MIRROR GAP: make target '$t' has no 'just $t' recipe"
      fail=1
    fi
  fi
done

# Spot-check command bodies for key security recipes (full AST diff is
# overkill; these are the gates that must not drift silently).
for pair in "no-std:cargo check -p oc-signer --no-default-features" "skill-check:check-skill-consistency" "makefile-check:check-makefile-mirror" "deny:cargo deny check"; do
  name="${pair%%:*}"
  needle="${pair#*:}"
  if ! grep -q "$needle" Justfile; then
    echo "MIRROR DRIFT: Justfile '$name' missing '$needle'"
    fail=1
  fi
  if ! grep -q "$needle" Makefile; then
    echo "MIRROR DRIFT: Makefile '$name' missing '$needle'"
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "makefile-mirror FAILED: update Justfile + Makefile together"
  exit 1
fi
echo "makefile-mirror PASS"
