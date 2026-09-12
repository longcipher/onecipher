#!/usr/bin/env bash
# SKILL <-> clap consistency gate (D11).
# Fails if any top-level `Commands::` variant in `bin/oc-cli/src/cli.rs` is
# missing from `SKILL.md` or `docs/cli-reference.md`.
# Usage: ./scripts/check-skill-consistency.sh
set -euo pipefail
cd "$(dirname "$0")/.."

CLI=bin/oc-cli/src/cli.rs
SKILL=SKILL.md
REF=docs/cli-reference.md

# Extract top-level variant names only: 4-space indent + UpperCamelCase +
# `{` or `,` terminator (fields live at 8+ spaces or lowercase, so they are
# excluded by construction).
variants=$(awk '/pub\(crate\) enum Commands \{/{flag=1;next} /^\}/{if(flag){exit}} flag' "$CLI" \
  | grep -Eo '^    [A-Z][A-Za-z0-9_]*' \
  | tr -d ' ' \
  | sort -u)

fail=0
for v in $variants; do
  # Map variant -> CLI kebab name: WalletRpc->wallet-rpc, AgentSecret->agent-secret, etc.
  # Simple heuristic: insert `-` before each uppercase (except first), lowercase all.
  kebab=$(echo "$v" | sed -E 's/([a-z0-9])([A-Z])/\1-\2/g' | tr '[:upper:]' '[:lower:]')
  if ! grep -qi "$v\|$kebab" "$SKILL"; then
    echo "SKILL GAP: Commands::$v ($kebab) missing from $SKILL"
    fail=1
  fi
  if ! grep -qi "$v\|$kebab" "$REF"; then
    echo "REF GAP: Commands::$v ($kebab) missing from $REF"
    fail=1
  fi
done

if [ "$fail" -ne 0 ]; then
  echo "skill-consistency FAILED: update SKILL.md + docs/cli-reference.md with the CLI change"
  exit 1
fi
echo "skill-consistency PASS (${variants} variants covered)"
