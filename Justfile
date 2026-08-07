# OneCipher Justfile — common dev tasks.
#
# Install `just`: https://github.com/casey/just
#   brew install just
#
# List recipes:  just
# Run a recipe:  just <recipe>

# Default recipe — display help.
default:
    @just --list

# ============================================================
# Formatting & Linting
# ============================================================

# Format all code (rustfmt nightly + cargo sort + shear unused deps).
format:
    cargo sort -w -g
    cargo +nightly fmt --all
    cargo shear --fix

# Auto-fix clippy warnings.
fix:
    RUSTC_WRAPPER= cargo +nightly clippy --fix --allow-dirty --all

# Run all lints (clippy + fmt check + cargo sort + shear + duplicate-dep ratchet).
lint:
    cargo +nightly fmt --all -- --check
    RUSTC_WRAPPER= cargo +nightly clippy --all -- -D warnings
    cargo sort -w -g -c
    cargo shear
    ./scripts/check-duplicate-deps.sh

# ============================================================
# Testing
# ============================================================

# Run all unit + integration tests.
test:
    cargo test --workspace --all-features

# Run all tests (alias for `test`).
test-all: test

# Run mutation testing on the full workspace (requires cargo-mutants).
mutants:
    cargo mutants --workspace --all-features

# Run incremental mutation testing (only files changed vs main).
mutants-incremental:
    cargo mutants --in-place --since main --all-features

# ============================================================
# Build
# ============================================================

# Build the entire workspace.
build:
    cargo build --workspace

# Build a release binary (onecipher).
release bin="onecipher":
    cargo build --release --bin {{bin}}

# Check all targets compile (faster than build).
check:
    cargo check --all-targets --all-features

# ============================================================
# Maintenance
# ============================================================

# Clean build artifacts.
clean:
    cargo clean

# Generate documentation for the workspace.
docs:
    cargo doc --no-deps --open

# Full CI check (lint + test + build).
ci: lint test build

# Install all required development tools.
setup:
    cargo install cargo-sort
    cargo install cargo-shear
    rustup toolchain install nightly --component rustfmt clippy

# Run cargo audit to check for known vulnerabilities.
audit:
    cargo audit

# R12 hard gate check — source-level isolation (no TcpListener/TcpStream in isolated crates).
r12-check:
    @echo "R12a: checking source-level TCP isolation..."
    @! rg -n 'TcpListener|TcpStream' crates/oc-keyagent/src/ crates/oc-crypto/src/ crates/oc-policy/src/ crates/oc-session-key/src/ || (echo "R12a FAILED: TCP types found in isolated crates" && exit 1)
    @echo "R12a: PASS — no TCP types in isolated crate sources"

# Report crates resolved at more than one version (duplicate-dependency ratchet).
deps-duplicates:
    ./scripts/check-duplicate-deps.sh --list

# Enforce the duplicate-dependency baseline.
deps-check:
    ./scripts/check-duplicate-deps.sh
