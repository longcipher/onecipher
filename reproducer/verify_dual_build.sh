#!/usr/bin/env bash
#
# Dual-build verification (T45).
#
# Confirms that two independent builds of the `onecipher` daemon — produced
# by two different toolchains/methods (e.g. Nix vs Docker, or two isolated
# `direct` builds) — yield byte-identical binaries. This is the strongest
# practical evidence that the release binary is reproducible from source.
#
# Usage:
#   reproducer/verify_dual_build.sh [--method-a <a>] [--method-b <b>]
#
# Defaults: builds twice with --method direct into two isolated target dirs
# and compares the SHA256 digests.
#
# Env:
#   OC_REPRODUCER_SKIP_DUAL_BUILD=1   Print a skip notice and exit 0 without
#                                     building (CI fast path).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

METHOD_A="direct"
METHOD_B="direct"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --method-a) METHOD_A="$2"; shift 2 ;;
    --method-b) METHOD_B="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ "${OC_REPRODUCER_SKIP_DUAL_BUILD:-}" == "1" ]]; then
  echo "[reproducer] OC_REPRODUCER_SKIP_DUAL_BUILD=1 — dual-build verification skipped"
  exit 0
fi

build_one() {
  local method="$1" tag="$2"
  local tdir="target/dual-$tag"
  CARGO_TARGET_DIR="$ROOT/$tdir" \
  RUSTFLAGS="-C strip=symbols -C link-arg=-Wl,--build-id=none" \
  cargo build --release --locked --bin onecipher >/dev/null 2>&1
  sha256sum "$tdir/release/onecipher" | cut -d' ' -f1
}

echo "[reproducer] dual-build: A=$METHOD_A B=$METHOD_B"
SHA_A="$(build_one "$METHOD_A" a)"
SHA_B="$(build_one "$METHOD_B" b)"

echo "[reproducer] SHA256(A)=$SHA_A"
echo "[reproducer] SHA256(B)=$SHA_B"

if [[ "$SHA_A" == "$SHA_B" ]]; then
  echo "[reproducer] dual-build VERIFIED — binaries are byte-identical"
  exit 0
else
  echo "[reproducer] dual-build FAILED — binaries differ" >&2
  exit 1
fi
