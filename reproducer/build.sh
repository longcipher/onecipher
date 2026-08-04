#!/usr/bin/env bash
#
# OneCipher reproducible-build reproducer.
#
# Builds the `onecipher` daemon binary — which statically links the
# Key-Agent (oc-keyagent) library — in a byte-reproducible way. This is the
# open-source analog that lets a security-conscious user rebuild the exact
# binary that ships in the release and verify its SHA256.
#
# Reproducibility is guaranteed by:
#   * A pinned toolchain (Rust nightly via `../../rust-toolchain.toml`, resolved via rustup).
#   * `Cargo.lock` being honored (`--locked`).
#   * Strip + build-id suppression RUSTFLAGS (`-C strip=symbols`,
#     `-C link-arg=-Wl,--build-id=none`) so the emitted binary does not
#     embed a non-deterministic build-id or debug symbols.
#   * An isolated target dir (`target/reproducible`) so it never clobbers
#     the regular `target/release` artifacts (which keep their symbols for
#     symbol-table inspections elsewhere in the conformance suite).
#
# Methods:
#   --method direct   Local cargo + rustc (default). Requires a Rust toolchain.
#   --method nix      Build inside the Nix flake (reproducer/flake.nix).
#   --method docker   Build inside the Dockerfile (reproducer/Dockerfile).
#
# Env:
#   OC_REPRODUCER_SKIP_BUILD=1   Emit the manifest with a placeholder SHA256
#                                and exit 0 without building (CI fast path).
#
# Output:
#   target/reproducible/release/onecipher
#   reproducer/manifest.json      { "sha256", "cargo_lock_sha256", "rustc", "method" }

set -euo pipefail

METHOD="direct"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --method) METHOD="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BIN="onecipher"
OUT_DIR="target/reproducible/release"
OUT_BIN="$OUT_DIR/$BIN"
MANIFEST="reproducer/manifest.json"

# RUSTFLAGS required for byte-reproducibility (see header).
export RUSTFLAGS="-C strip=symbols -C link-arg=-Wl,--build-id=none"
# Isolate the reproducible build so it does not disturb regular artifacts.
export CARGO_TARGET_DIR="$ROOT/target/reproducible"

skip_build() {
  local sha256
  sha256="$(sha256sum Cargo.lock 2>/dev/null | cut -d' ' -f1 || echo "skipped")"
  cat > "$MANIFEST" <<EOF
{
  "built": false,
  "method": "$METHOD",
  "sha256": "skipped",
  "cargo_lock_sha256": "$sha256",
  "rustc": "skipped"
}
EOF
  echo "[reproducer] OC_REPRODUCER_SKIP_BUILD=1 — emitted placeholder manifest at $MANIFEST"
}

if [[ "${OC_REPRODUCER_SKIP_BUILD:-}" == "1" ]]; then
  skip_build
  exit 0
fi

case "$METHOD" in
  direct)
    echo "[reproducer] building $BIN via local cargo (method=direct)"
    cargo build --release --locked --bin "$BIN"
    ;;
  nix)
    echo "[reproducer] building $BIN via nix (method=nix)"
    nix build -L .#onecipher
    mkdir -p "$OUT_DIR"
    cp -f "$(nix path-info .#onecipher)/bin/$BIN" "$OUT_BIN"
    ;;
  docker)
    echo "[reproducer] building $BIN via docker (method=docker)"
    docker build -t onecipher-repro -f reproducer/Dockerfile "$ROOT"
    mkdir -p "$OUT_DIR"
    docker create --name onecipher-repro-tmp onecipher-repro
    docker cp "onecipher-repro-tmp:/out/$BIN" "$OUT_BIN"
    docker rm -f onecipher-repro-tmp >/dev/null
    ;;
  *)
    echo "unknown method: $METHOD" >&2
    exit 2
    ;;
esac

# Emit the release manifest consumed by the BDD `Then` steps.
SHA256="$(sha256sum "$OUT_BIN" | cut -d' ' -f1)"
LOCK_SHA="$(sha256sum Cargo.lock | cut -d' ' -f1)"
RUSTC_VER="$(rustc --version)"
cat > "$MANIFEST" <<EOF
{
  "built": true,
  "method": "$METHOD",
  "sha256": "$SHA256",
  "cargo_lock_sha256": "$LOCK_SHA",
  "rustc": "$RUSTC_VER"
}
EOF

echo "[reproducer] built $OUT_BIN (sha256=$SHA256)"
echo "[reproducer] manifest at $MANIFEST"
