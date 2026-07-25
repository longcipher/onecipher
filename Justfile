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

# Run all lints (clippy + fmt check + cargo sort + shear + R56 dep check).
lint:
    cargo +nightly fmt --all -- --check
    RUSTC_WRAPPER= cargo +nightly clippy --all -- -D warnings
    cargo sort -w -g -c
    cargo shear
    # R56 hard gate — verify no forbidden async/network crates in dep tree.
    cargo tree -p oc-crypto -e features
    cargo tree -p oc-policy -e features
    cargo tree -p oc-keyagent -e features
    cargo tree -p oc-session-key -e features

# ============================================================
# Testing
# ============================================================

# Run all unit + integration tests (excluding conformance BDD).
test:
    cargo test --workspace --all-features --exclude oc-conformance

# Run the BDD conformance scenarios (cucumber-driven).
bdd:
    cargo test -p oc-conformance --test conformance

# Run all tests (unit + integration + conformance BDD).
test-all:
    cargo test --workspace --all-features
    cargo test -p oc-conformance --test conformance

# Run a single conformance feature (pass the feature name, e.g. `just bdd-one audit_cli`).
bdd-one feature:
    cargo test -p oc-conformance --test conformance -- {{feature}}

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
ci: lint test-all build

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
