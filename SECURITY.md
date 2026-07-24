# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**DO NOT** open a public GitHub issue for security vulnerabilities.

Instead, please report them responsibly via email to:
**security@onecipher.dev** (or the repository owner's email if the domain is not yet active).

### What to include

- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### Response timeline

- **Acknowledgment**: within 48 hours
- **Initial assessment**: within 5 business days
- **Fix or mitigation**: within 30 days for critical/high severity

### Scope

The following are in scope:

- Private key extraction or leakage
- Policy engine bypass (signing without authorization)
- Memory hardening failures (sensitive material in core dumps)
- Audit log tampering
- Vault encryption weaknesses
- Sandbox escape (seccomp/prctl bypass on Linux)
- Dependency supply chain issues

### Bug Bounty

We do not currently offer a paid bug bounty program. We will credit reporters
in release notes (unless anonymity is requested).

## Security Design

See [docs/security-model.md](docs/security-model.md) for the full security
architecture, including:

- R56 hard gate (dependency isolation)
- R12 hard gate (no TCP in Key-Agent binary)
- Memory hardening (mlock + MADV_DONTDUMP + zeroize)
- age X25519 encryption at rest
- Policy Engine v2 (11-step pre-signing evaluation)
- Audit log (SHA-256 chained, Ed25519 signed)
- Sandbox (seccomp + prctl on Linux)
