# OneCipher vs 1Password Developer Surfaces

## Scope

This document compares OneCipher's current developer-facing product surface with
the 1Password developer pages reviewed for this pass:

- `https://www.1password.dev/ssh/agent`
- `https://www.1password.dev/security-for-ai`
- `https://www.1password.dev/environments`
- `https://www.1password.dev/cli`
- `https://www.1password.dev/sdks`

The goal is product parity analysis for plugin surfaces and password / secret
management, not a statement that the two products should converge fully.

## Repository Architecture Summary

OneCipher already has three strong foundations:

1. `extension/`:
   a production-grade MV3 browser wallet extension with consent queue,
   sender authentication, loopback-only daemon transport, and test coverage.
2. `crates/oc-secret` + `bin/oc-cli/src/commands/secret.rs`:
   a unified secret plane for passwords, TOTP seeds, notes, and other
   user secrets, backed by `age` encryption and audited reads.
3. `bin/oc-cli/src/commands/env_cmd.rs` + `agent_secret.rs`:
   agent-friendly secret injection and token-gated secret access for
   automation.

The current shape is therefore:

- strong custody core
- strong wallet/browser-extension surface
- good CLI automation primitives
- materially improved developer-plugin packaging
- materially improved "environment workflow" productization

## Implemented Capability Inventory

### Already strong

- Browser extension wallet with explicit consent and security invariants.
- Password storage with metadata (`url`, `username`) and password generation.
- TOTP storage and code generation.
- Unified CLI / TUI secret browsing.
- Optional git-backed encrypted vault sync.
- Agent-mode secret access via API token + per-key secret permissions.
- Runtime environment injection with `onecipher env --name ... -- command`.
- Policy-gated signing and passkey-aware wallet RPC surface.
- Audit logging across secret and signing operations.

### Already comparable in spirit to 1Password

- "Secret never leaves the hardened path" philosophy.
- Runtime injection instead of encouraging plaintext config.
- A browser extension surface that does not hold long-lived wallet keys.
- AI-agent-friendly CLI ergonomics (`--json`, non-interactive flows, token mode).

## Gap Analysis vs 1Password

### 1. Plugin packaging

1Password has productized plugin bundles for Claude Code and Cursor:

- MCP registration
- agent skill / workflow instructions
- pre-command validation hook
- environment management UX

OneCipher originally had the low-level pieces, but not the plugin bundle.
This pass closes a meaningful part of that gap:

- project-local plugin bootstrap via `onecipher plugin init`
- project-local environment manifest via `.onecipher/environments.toml`
- a local stdio MCP server for environment metadata + validation
- `onecipher env --validate` for hook / wrapper workflows

### 2. Environment product layer

1Password Environments adds a product abstraction above raw secrets:

- named environments
- variable-name inventory without secret disclosure
- mounted local `.env` files
- MCP operations that expose names but not secret values

OneCipher currently exposes:

- raw secret items
- directory-prefix batch injection
- direct command execution with injected environment variables

This pass closes several missing pieces:

- named environment abstraction
- metadata-only environment listing API
- secret-reference syntax designed for config and SDK workflows

Still missing:

- local `.env` mount lifecycle

### 3. SSH / shell ecosystem

1Password also ships:

- SSH agent workflows
- Git signing workflows
- shell plugins for third-party CLIs

OneCipher has daemon auto-spawn and strong local custody, but today it does not
present a dedicated SSH-agent product surface comparable to the 1Password
developer story.

## This Pass: Implemented Improvements

This pass now closes a larger slice of the developer-workflow gap:

1. Explicit secret references in `onecipher env`
2. Repository-local environment manifests
3. Validation flow for hooks and wrappers
4. Project-local plugin bootstrap for Claude/Cursor/Codex
5. Local stdio MCP server for environment metadata

### 1. Explicit references

`onecipher env` supports explicit secret references:

```bash
onecipher env \
  --reference OPENAI_API_KEY=oc://api-keys/openai \
  --reference GITHUB_OTP=oc://github-2fa?field=otp \
  -- ./run-agent.sh
```

New behavior:

- `--reference KEY=oc://secret[?field=secret|notes|otp|metadata]`
- `--print --format dotenv|json` to emit an ephemeral rendered environment
  instead of running a child command

### 2. Repository-local manifests

OneCipher now supports `.onecipher/environments.toml`:

```toml
version = 1
default_environment = "dev"

[environments.dev]
OPENAI_API_KEY = "oc://api-keys/openai"
GITHUB_OTP = "oc://github-2fa?field=otp"
```

That manifest can be discovered upward from the current directory or passed
explicitly with `--manifest`.

### 3. Validation flow

Hook / wrapper flows can now validate an environment without printing secret
values:

```bash
onecipher env --environment dev --validate
onecipher env --environment dev --validate --format json
```

### 4. Plugin bootstrap

`onecipher plugin init` now writes project-local config files for:

- Claude Code: `.mcp.json`
- Cursor: `.cursor/mcp.json`
- Codex: `.codex/config.toml`

The generated configs all launch `onecipher mcp serve`.

### 5. MCP server

OneCipher now exposes a local stdio MCP server with metadata-safe tools:

- `onecipher_list_environments`
- `onecipher_list_environment_variables`
- `onecipher_validate_environment`

The MCP server intentionally does not return secret values.

### Why this matters

This makes OneCipher much closer to the 1Password CLI/SDK/plugin workflow:

- config keeps stable references, not plaintext values
- runtime resolves only what the command needs
- OTP can be referenced explicitly
- wrappers, hooks, and plugin shims can validate without disclosing values
- IDE / agent clients get a first-class MCP bootstrap path
- MCP clients can inspect environment metadata without learning secret values

## Remaining Gaps

Ordered by product leverage:

1. Add a mounted local `.env` lifecycle (ephemeral file / FIFO-backed flow).
2. Generate client-specific pre-command hook files, not only MCP configs.
3. Add environment creation/edit/list UX in Web UI or TUI.
4. Add a dedicated SSH agent / Git signing developer workflow if SSH parity is
   a product requirement.

## Acceptance Notes

The current pass is broader than the initial narrow improvement, but it still
stops short of full 1Password parity:

- no FIFO-mounted `.env` implementation
- no secret-returning MCP tools
- no dedicated SSH agent surface
- no browser password autofill / end-user password-manager UX

It does, however, turn the previous building blocks into an actual developer
workflow product surface instead of just raw primitives.
