# Contributing to OneCipher

## Getting Started

```bash
git clone https://github.com/longcipher/onecipher.git
cd onecipher
just setup    # install cargo-sort, cargo-shear, nightly toolchain
just build    # build the workspace
just test     # run unit + integration tests
```

## Development Workflow

1. Fork and create a feature branch from `main`
2. Write code following the existing conventions
3. Add tests for new functionality
4. Run the full check: `just ci` (lint + test + build)
5. Open a PR against `main`

## Code Style

- **Formatting**: `cargo +nightly fmt` (enforced in CI)
- **Linting**: `cargo +nightly clippy -- -D warnings` (pedantic + nursery)
- **Sorting**: `cargo sort -w -g` (workspace members sorted)
- **No unused deps**: `cargo shear`

## Hard Gates (Non-Negotiable)

These invariants are enforced by CI and must never be violated:

- **R56**: `oc-crypto`, `oc-policy`, `oc-keyagent`, `oc-session-key` must NOT depend on `tokio`, `reqwest`, `tungstenite`, `hyper`, `async-std`, or `smol`
- **R12**: The release binary must NOT contain TCP-specific symbols
- **R51/R52**: `oc-crypto` must have zero I/O and zero network dependencies
- **R55**: Key-Agent must use sync `std::thread` + `std::os::unix::net`, NOT tokio

## Testing

```bash
just test      # unit + integration tests
just mutants   # mutation testing (cargo-mutants)
just test-all   # alias for `just test`
```

- Unit tests: colocated with implementation (`#[cfg(test)]`)
- Property tests: `proptest` for invariant checking
- Mutation tests: `cargo-mutants` to verify test quality — surviving mutants
  indicate gaps that need new tests or stronger assertions

## Commit Messages

Follow conventional commits:

- `feat:` new feature
- `fix:` bug fix
- `refactor:` code change that neither fixes a bug nor adds a feature
- `test:` adding or updating tests
- `docs:` documentation changes
- `chore:` maintenance tasks
- `ci:` CI/CD changes

## Security

See [SECURITY.md](SECURITY.md) for reporting vulnerabilities. Never commit
secrets, keys, or credentials. Sensitive material must use `HardenedBytes`
or `secrecy::SecretBox` — never plain `String` or `Vec<u8>`.

## License

By contributing, you agree that your contributions will be licensed under
the Apache License 2.0.
