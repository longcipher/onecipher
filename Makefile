# OneCipher Makefile — mirror of the Justfile for environments without `just`.
#
# POLICY: every `just <recipe>` must have a `make <target>` with the SAME
# command body. CI enforces the mirror via `scripts/check-makefile-mirror.sh`.
# When adding a recipe, update BOTH files in the same PR.
#
# List targets:  make help
# Run a target:  make <target>

.PHONY: help format fix lint test test-all mutants mutants-incremental e2e build release check clean docs ci setup audit r12-check deps-duplicates deps-check no-std no-std-thumbv7m skill-check makefile-check deny security

help:
	@echo "OneCipher make targets (mirror of Justfile):"
	@echo "  format test build check ci lint audit deny security no-std skill-check makefile-check ..."

format:
	cargo sort -w -g
	cargo +nightly fmt --all
	cargo shear --fix

fix:
	RUSTC_WRAPPER= cargo +nightly clippy --fix --allow-dirty --all

lint:
	cargo +nightly fmt --all -- --check
	RUSTC_WRAPPER= cargo +nightly clippy --all -- -D warnings
	cargo sort -w -g -c
	cargo shear
	./scripts/check-duplicate-deps.sh

test:
	cargo test --workspace --all-features

test-all: test

mutants:
	cargo mutants --workspace --all-features

mutants-incremental:
	cargo mutants --in-place --since main --all-features

e2e:
	cargo build --release --bin onecipher
	./scripts/e2e.sh

build:
	cargo build --workspace

release:
	cargo build --release --bin onecipher

check:
	cargo check --all-targets --all-features

clean:
	cargo clean

docs:
	cargo doc --no-deps --open

ci: lint test build

setup:
	cargo install cargo-sort
	cargo install cargo-shear
	rustup toolchain install nightly --component rustfmt clippy

audit:
	cargo audit

r12-check:
	@echo "R12a: checking source-level TCP isolation..."
	@! rg -n 'TcpListener|TcpStream' crates/oc-keyagent/src/ crates/oc-crypto/src/ crates/oc-policy/src/ crates/oc-session-key/src/ || (echo "R12a FAILED: TCP types found in isolated crates" && exit 1)
	@echo "R12a: PASS — no TCP types in isolated crate sources"

deps-duplicates:
	./scripts/check-duplicate-deps.sh --list

deps-check:
	./scripts/check-duplicate-deps.sh

no-std:
	cargo check -p oc-signer --no-default-features

no-std-thumbv7m:
	rustup target add thumbv7m-none-eabi
	cargo check -p oc-signer --no-default-features --target thumbv7m-none-eabi

skill-check:
	./scripts/check-skill-consistency.sh

makefile-check:
	./scripts/check-makefile-mirror.sh

deny:
	cargo deny check advisories licenses bans sources

security: deny audit
