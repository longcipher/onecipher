#!/usr/bin/env bash
#
# T41 supply-chain gate — mandatory in CI, graceful locally.
#
# The BDD scenarios in `supply_chain.feature` SKIP when a tool is missing so
# that local development without cargo-cyclonedx/cargo-vet/cargo-audit still
# passes. CI must not silently skip: this script turns each available tool into
# a hard gate (fails the job on a real finding) and reports a clear status for
# tools that are not installed.
#
# Usage:
#   ci/supply_chain_gate.sh          # run every installed tool as a gate
#   ci/supply_chain_gate.sh --skip-missing   # exit 0 even if a tool is absent
#
# Referenced by: .github/workflows/ci.yml (supply-chain job)

set -uo pipefail

cd "$(dirname "$0")/.."

SKIP_MISSING=0
if [[ "${1:-}" == "--skip-missing" ]]; then
  SKIP_MISSING=1
fi

status=0

tool_available() {
  cargo "$1" --help >/dev/null 2>&1
}

run_gate() {
  local name="$1"
  local tool="$2"
  shift 2

  if tool_available "$tool"; then
    echo "T41: running $name ($tool)..."
    if cargo "$tool" "$@"; then
      echo "T41 PASS: $name"
    else
      echo "T41 FAIL: $name reported findings"
      status=1
    fi
  else
    echo "T41 SKIP: $tool is not installed"
    if [[ "$SKIP_MISSING" -eq 0 ]]; then
      status=1
    fi
  fi
}

# 1. CVE scan over the full workspace dependency tree.
run_gate "cargo-audit CVE scan" "audit"

# 2. Vet check for the isolated (R56) crates' dependency trees.
#    cargo-vet filters by package; run on the whole tree like the BDD step.
run_gate "cargo-vet supply-chain review" "vet"

if [[ "$status" -ne 0 ]]; then
  echo
  echo "T41 GATE FAILED. Install the missing tool(s) (cargo install cargo-audit"
  echo "cargo-vet) or fix the reported findings. Use --skip-missing to bypass"
  echo "on machines that intentionally lack them."
  exit 1
fi

echo "T41 GATE PASS"
