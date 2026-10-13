# Browser Extension Wallet — Design

> Design document for the OneCipher browser extension wallet (`extension/`) and the
> multi-end architecture it belongs to (OneCipher Wallet Protocol, "OCWP").
> Status: **implemented** (P0–P4 of §11, plus the §11.1 review pass; the
> extension lives in `extension/`, WXT + React, with OCWP support in
> `bin/oc-cli/src/commands/wallet_rpc/ocwp/`).

## 1. Purpose and Scope

### 1.1 Goal

Build a Manifest V3 browser extension wallet at `extension/` that:

1. Adopts every excellent design property of the reference project
   `/Volumes/akext/tmp/clawd-wallet` (MV3 permission minimalism, three-layer
   message architecture, per-request consent queue, sender authentication,
   storage layering, sandbox-based security testing).
2. Uses OneCipher as its custody and policy core — the extension holds **no key
   material**; keys live in `oc-vault`, policy gates live in `oc-policy`, signing
   goes through `oc-signer`.
3. Is one **end** of a multi-end architecture (CLI / browser extension / mobile /
   server) that shares one authoritative state store (the OneCipher daemon).

### 1.2 Non-Goals (v1)

- No key generation, key import, or key storage inside the extension. Wallet
  creation/import stays in the daemon (CLI / Web UI), exactly as today.
- No WalletConnect v2 pairing from the extension (that is `oc-netagent`'s role).
- No `window.fetch` patching, no payment interception, no HTTP 402 handling —
  payments MUST pass through untouched (reference: clawd-wallet's
  `http402Preserved` evidence).
- No telemetry, analytics, or crash reporting of any kind.
- No non-EVM provider in v1. The protocol is chain-neutral from day one; a
  Solana provider module is additive (same consent queue, same protocol).
- No cloud sync infrastructure. Cross-device sync is either daemon-attached
  (§7.2, v2) or user-managed `.ocbk` backup export/import (§7.3).

### 1.3 Terminology

| Term | Meaning |
|---|---|
| **End** | A client of the OneCipher custody core: CLI, Web UI, browser extension, mobile app, server automation. |
| **Daemon** | The `onecipher` daemon process (`onecipher daemon` / `onecipher wallet-rpc serve`). Owns keys, policies, signing, audit. |
| **OCWP** | OneCipher Wallet Protocol — the JSON-RPC 2.0 surface all ends speak (§5). |
| **Site** | A dApp origin (e.g. `https://app.uniswap.org`) that the user has connected. |
| **Consent** | The explicit Approve/Reject decision the user makes in extension-owned UI for every connection, signature, and transaction. |
| **Session** | A daemon-side unlocked state (`oc_unlock` → `session_id`) with TTL, created from a wallet passphrase. |

---

## 2. Reference Analysis: clawd-wallet

`/Volumes/akext/tmp/clawd-wallet` is a Solana Manifest V3 wallet: ~3,000 lines of
TypeScript, zero UI framework, 6 runtime dependencies, no backend. Its security
posture is the reference invariant: *every connection, signature, and transfer
requires an explicit approval, locked down by 28 vm-sandbox unit tests, a
Playwright end-to-end test, and an auditable JSON evidence file.*

### 2.1 Feature Adoption Matrix

| # | clawd-wallet property | Decision | Where in this design |
|---|---|---|---|
| F1 | MV3, `permissions: ["storage"]` only; no `tabs`/`activeTab`/`scripting`/`notifications` | **Adopt** | §4.2 |
| F2 | `host_permissions` narrowed to what is strictly needed (clawd needed `<all_urls>` for arbitrary Solana RPC) | **Adopt, tighter**: loopback-only (`http://127.0.0.1/*`, `http://localhost/*`) because RPC is proxied by the daemon | §4.2 |
| F3 | Three-layer architecture: `injected.ts` (page realm) → `content.ts` (isolated world) → `background.ts` (service worker) | **Adopt** | §4.2 |
| F4 | Channel names inlined in content/injected to avoid shared-chunk breakage under `web_accessible_resources` | **Adopt** | §4.2 |
| F5 | `enqueueAction` pending queue: `resolve`/`reject` stored in a `Map`, dApp promise stays unsettled until the user decides | **Adopt** | §4.4 |
| F6 | `approveAction` consumes the entry *before* awaiting (double-click cannot execute twice) | **Adopt** | §4.4 |
| F7 | Re-validation at approval time: session still unlocked, origin still authorized | **Adopt + extend**: also re-run `oc_policy_preview` at click time | §4.4 |
| F8 | `providerOrigin()` sender auth: `sender.id` + `tab.id` + protocol + `origin`/`url` consistency, all from Chrome (unforgeable) | **Adopt** | §4.5 |
| F9 | `requirePopupSender()`: exact protocol + host + pathname match for popup commands | **Adopt** | §4.5 |
| F10 | Fail-closed routing: unknown message types rejected | **Adopt** | §4.5 |
| F11 | `authorizedOrigins` model: connect once, **sign every time**; per-site Revoke in popup | **Adopt** | §4.4, §4.8 |
| F12 | Auto-approval removed entirely (`agentMode` forced `false` on read; `popup_setAgentMode` always errors) | **Adopt**: no auto-approve code path may exist in the extension | §8 INV-2 |
| F13 | `chrome.storage.session` for unlocked state (survives MV3 SW suspension, wiped on browser close) | **Adapt**: stores the daemon **session handle**, never key material | §4.6 |
| F14 | Dual-mode popup (`popup.html` + `?view=notification`), notification window reuse with `windows.get(populate)` + `tabs.length > 0` liveness check | **Adopt** | §4.8 |
| F15 | Notification window closes itself when the queue empties; render-race guard (`showingBackup`) | **Adopt** (guard renamed to the consent-render race) | §4.4 |
| F16 | PBKDF2-SHA256(600k) → AES-256-GCM vault, iterations stored per vault | **Reject**: the extension holds no secrets; custody stays in `oc-vault` (age). The "KDF parameters in the envelope" idea is already OneCipher's age model | §6 |
| F17 | Custom RPC endpoint management (`customRpcUrl`, cluster→authoritative-endpoint reverse lookup) | **Adopt**: daemon-side chain registry + extension custom-chain UI | §4.10 |
| F18 | Realm-safe binary handling (`ArrayBuffer.isView`, `TextDecoder` with `ignoreBOM: true`) | **Adopt** for `personal_sign` hex→UTF-8 preview and typed-data rendering | §4.3 |
| F19 | HTTP 402 passthrough; no fetch patch; test asserts `fetch` identity unchanged | **Adopt** | §8 INV-8 |
| F20 | Security tests: `node:vm` sandbox running **built bundles** with a fake `chrome` object; sentinel arrays (`network`, `captures`, `popups`); forged-sender matrix; Playwright e2e on a disposable profile; evidence JSON | **Adopt wholesale**, extended with "no key material in storage" sentinels | §9 |
| F21 | Documented security posture (per-primitive rationale, re-enablement requirements for disabled features) | **Adopt**: `extension/SECURITY.md` mirrors `extension` decisions; this doc is the normative spec | §12 |
| F22 | Solana-specific: `window.solana` provider, Ed25519 signing, `signMessage` semantics | **Adapt**: EVM v1 uses `window.ethereum` (EIP-1193 + EIP-6963), secp256k1 via `oc-signer`. Solana is a later provider module over the same OCWP consent queue | §4.3 |

### 2.2 Lessons Codified from clawd-wallet's Consent-Fix Postmortem

From `clawd-wallet/docs/wallet-consent-fix.md` (re-enablement requirements):

> A future implementation must bind each action to the validated sender origin,
> show the exact operation in extension-owned UI, require an explicit decision,
> and reject stale or reused approvals. **A site connection alone grants none of
> these permissions.**

This is normative for OneCipher's extension and is enforced as INV-2/INV-4/INV-10 (§8).

---

## 3. Multi-End Architecture

### 3.1 End Taxonomy

```text
┌───────────────┐  ┌──────────────────┐  ┌────────────────┐  ┌────────────────────┐
│  CLI          │  │ Browser Extension│  │ Mobile (v2)    │  │ Server / Automation│
│  `onecipher`  │  │ extension/ (TS)  │  │ iOS / Android  │  │ API token (oc_key_)│
│  (exists)     │  │ (this design)    │  │ (reserved)     │  │ (exists)           │
└──────┬────────┘  └────────┬─────────┘  └───────┬────────┘  └─────────┬──────────┘
       │ UDS (prost frames) │ HTTP loopback     │ TLS + pairing       │ HTTP(S)
       │ + direct vault I/O │ (OCWP, JSON-RPC)  │ (OCWP, reserved)    │ (OCWP)
       ▼                    ▼                   ▼                     ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                        OneCipher Daemon (custody core)                            │
│  oc-vault (keys, age) · oc-policy (gates, budgets) · oc-signer (chains)          │
│  oc-keyagent (UDS, passkeys, session keys, audit) · oc-secret (user secrets)     │
│  approval queue + audit log + session store (new, §6)                             │
└──────────────────────────────────────────────────────────────────────────────────┘
```

| End | Transport | Auth | Consent model | Status |
|---|---|---|---|---|
| CLI | UDS prost frames + direct vault I/O | OS user / passphrase / API token | Interactive (human at terminal) | Exists |
| Web UI | loopback HTTP (`oc-webui`) | WebAuthn session / CLI token | Approval queue (mpsc + oneshot + DashMap + WAL) | Exists |
| Browser extension | loopback HTTP (OCWP) | Daemon session + optional Passkey step-up | **Per-request consent in extension UI** (this design) | **New** |
| Mobile | TLS + device pairing (reserved) | Device Ed25519 identity | Per-request consent in app UI | Reserved (§7.2) |
| Server / automation | HTTP(S) (OCWP) | API token `oc_key_…` | **No human consent — policy replaces it** (budgets, rate limits, alerts) | Exists (token path) |

### 3.2 Custody Core Responsibilities (unchanged crate boundaries)

The daemon remains the single source of truth. The extension MUST NOT
re-implement any of:

- Key custody (`oc-vault`: age-encrypted keyfiles, `0700`/`0600`, `.ocbk` backups).
- Policy evaluation (`oc-policy` v1 rules for the signing path; v2 11-step for
  session keys; v3 experimental DSL).
- Signing (`oc-signer`: EVM/Solana/Bitcoin/Cosmos/Tron/Ton/Sui/…, EIP-712,
  EIP-7702, EIP-4337 via `oc-keyagent`).
- Audit (JSONL audit log in `oc-keyagent`).
- Secret storage (`oc-secret`: age + TOTP — untouched by v1 extension).

Hard-gate boundaries are preserved: nothing in `oc-keyagent`, `oc-crypto`,
`oc-policy`, `oc-session-key` changes; the OCWP server lives in `bin/oc-cli`
(§6, D7), which already links the full stack.

### 3.3 Protocol: OneCipher Wallet Protocol (OCWP)

- **Encoding**: JSON-RPC 2.0, single request per `POST /` (no batching in v1).
- **Binary fields**: base64 STANDARD (consistent with the existing
  `wallet-rpc` surface).
- **Method namespace**: `oc_*`. The existing `ledgerflow_*` methods remain as
  thin aliases over shared handlers — the sister project `ledgerflow`
  compatibility is a hard requirement.
- **Versioning**: `oc_hello` returns `protocol_version` (integer, starts at 1).
  A client/server version mismatch MUST be rejected with error `4200` and a
  `data.protocol_version` hint.
  *Enforcement is client-side and continuous*: the extension records the
  version `oc_hello` negotiated and refuses every subsequent method while it
  disagrees. Checking only inside `oc_hello` would leave every later call free
  to speak a dialect the daemon never agreed to.
- **Specification**: §5 (methods, errors, examples).

### 3.4 Transport and Connection Security

| Rule | Detail |
|---|---|
| Loopback only | The daemon binds `127.0.0.1` exclusively (existing `parse_loopback`, R12c/R12e). The extension client MUST reject any non-loopback daemon URL at configuration time. |
| Origin pinning | The daemon MUST require `Origin: chrome-extension://<extension-id>` and the id MUST be in the daemon's `extension_ids` allowlist (config `[wallet_rpc] extension_ids`, CLI `--allow-extension <id>`, repeatable; default: empty = deny all). |
| Anti-DNS-rebinding | The daemon MUST reject requests whose `Host` header host is not `127.0.0.1` / `localhost` / `[::1]`. |
| CORS | Preflight `OPTIONS` answered with `Access-Control-Allow-Origin` echoing the validated extension origin, `Access-Control-Allow-Headers: content-type`. No wildcard. |
| No secrets in transit beyond loopback | Passphrases transit only to `127.0.0.1`. TLS is not required on loopback (same trust assumption as `oc-webui`); remote ends (§7.2) require TLS. |
| Rate limiting | Per-session and per-origin request budgets on `oc_rpc` (§5.3). |

### 3.5 Authentication and Session Model

Two mechanisms, layered:

1. **Session unlock (primary, interactive ends).**
   `oc_unlock {wallet, passphrase, policies?}` → daemon caches
   `Arc<Zeroizing<String>>` passphrase + wallet id + selected policy ids in an
   in-memory session store (§6.2) and returns `session_id`. Default TTL: 900 s
   absolute / 300 s idle (configurable). Every subsequent method carries
   `session_id`. `oc_lock`, vault lock, and TTL expiry invalidate sessions.
   Signing still decrypts per request via `oc_wallet::decrypt_signing_key`
   (no long-lived key cache; the enclave subprocess default `OC_ENCLAVE=on`
   is unchanged).

2. **Passkey step-up (high-risk operations).**
   When the daemon or policy requires fresh user presence, the response is
   error `4100` with `data.require_passkey = true`. The extension then calls
   `oc_passkey_challenge` → signs the returned challenge → retries the
   original request with `passkey: {challenge_hex, signature_hex, credential_id}`,
   verified by `oc_keyagent::handler::authorize_passkey`. Reuses the existing
   WebAuthn stack; the extension is a *client* of the protocol, never a verifier.

   **Implementation deviation — software authenticator (accepted).** Design
   originally specified `navigator.credentials.get()` against the returned
   `rp_id`. A `chrome-extension://` page cannot host a real WebAuthn relying
   party (the RP must be a registrable domain suffix of the origin), so that
   call cannot succeed here. The extension therefore implements a **software
   authenticator**: it generates an ECDSA P-256 keypair via WebCrypto, registers
   the public key over `oc_passkey_register`, and signs challenges locally.

   Because this introduces the one private key the extension holds, its
   storage class is the control: the private JWK lives in
   **`chrome.storage.session`** (§4.6) — the same lifetime class as the session
   handle, wiped when the browser closes — and never in `chrome.storage.local`,
   where it would outlive the session and the browser. Consequences, all
   accepted and covered by the §9.3 sentinels: the credential is re-registered
   after a browser restart, and INV-1 is amended to name it (§8.1). A hardware
   WebAuthn path that works from an extension origin remains OQ-3.

   **Challenge binding.** A challenge is bound to the session that requested it
   and is single-use with a 120 s TTL, so a proof minted for one session's
   authorization cannot authorize another's. A mismatched session does **not**
   consume the binding — otherwise any other allowlisted extension could
   invalidate a pending step-up by guessing the challenge, turning a replay
   defence into a denial of service.

3. **API tokens (server/automation end only).**
   `oc_key_…` tokens map to `oc_wallet::key_ops` sign paths where policy is
   already enforced pre-signing. Tokens MUST NOT be usable from the extension
   (interactive end); the daemon rejects token-shaped credentials on `oc_unlock`.

4. **Session ↔ origin binding.** `oc_unlock` records the validated
   `chrome-extension://<id>` that created the session, and every
   session-scoped method refuses a session unlocked by a different origin.
   Without it, any extension on the `extension_ids` allowlist could drive a
   session another extension had authenticated. `oc_lock` and
   `oc_session_status` are bound the same way; an unknown or foreign session is
   reported as "locked" rather than as an error, so a probe cannot tell a live
   id from a dead one.

### 3.6 State Ownership and Sync Model

"Sync" is not a separate subsystem: **the daemon's state is the truth, and
ends are views over it.**

| Artifact | Source of truth | Same-device sync | Cross-device sync |
|---|---|---|---|
| Wallet keyfiles | `oc-vault` (`~/.onecipher/wallets/`) | Immediate (shared files) | `.ocbk` export/import (§7.3) |
| Accounts / addresses | Derived from keyfiles | Immediate | Follows keyfiles |
| Policies | `oc-wallet::policy_store` (+ `.sig` sidecars) | Immediate | `.ocbk` (open question OQ-2: policy signing key) |
| Session keys / budgets | `oc-policy` `PolicyState` counters | Immediate | Daemon-attached only (§7.2) |
| Authorized sites | **New** daemon `sites.json` (§6.4) | Immediate | Daemon-attached only; per-device until then |
| Audit log | `oc-keyagent` JSONL | Read via `oc_audit_tail` | Local only |
| Custom chains | **New** daemon chain registry (§6.5) | Immediate | `.ocbk` / daemon-attached |
| Extension UI prefs | `chrome.storage.local` (per browser profile) | n/a | Not synced (intentionally local) |
| User secrets (TOTP…) | `oc-secret` | CLI/TUI only in v1 | `.ocbk` |

Consequences: on one device, CLI, Web UI, and extension are consistent by
construction. Across devices, either attach the remote end to the daemon
(§7.2, reserved) or move the encrypted vault (§7.3). No plaintext ever leaves
a device in either model.

### 3.7 Trust Boundaries

```text
 page realm (dApp, untrusted)
   │ window.postMessage, channel + source checked
 isolated world (content.ts, ours, untrusted input)
   │ chrome.runtime.sendMessage, sender authenticated (F8)
 service worker (background.ts, ours)
   │ HTTP loopback, Origin + Host + session authenticated
 daemon (trusted computing base for custody/policy)
```

Everything left of the daemon is treated as potentially compromised; the
daemon's policy engine and audit log are the backstop (INV-1 makes extension
compromise non-fatal for keys).

---

## 4. Extension Architecture (MV3)

### 4.1 Directory Layout (as built)

WXT + React, so the layout differs from the original plan below. The
dependency-injected pure modules the design called for are all present and all
unit-tested; what changed is that they live under `src/lib/` rather than a flat
`src/`, and the test suite is Vitest + Playwright rather than bare `node:test`.

```text
extension/
├── package.json                # react + react-dom at runtime; everything else dev-only
├── tsconfig.json               # strict, extends the WXT base
├── vitest.config.ts            # happy-dom, tests/**/*.test.ts
├── wxt.config.ts               # MV3 manifest input
├── README.md                   SECURITY.md
├── public/icon/icon-{16,32,48,128}.png
├── src/
│   ├── protocol.ts             # channels, method names, error codes, types
│   ├── evm-tx.ts               # EIP-1193 ⇄ OCWP tx normalization (§4.3/§4.11)
│   ├── request-policy.ts       # providerOrigin() / requirePopupSender() (F8/F9)
│   ├── passkey.ts              # software-authenticator step-up (§3.5, OQ-3)
│   ├── background/router.ts    # testable routing / consent / executor core
│   ├── consent/
│   │   ├── queue.ts            # pendingActions Map, enqueue/approve/decline/expire
│   │   ├── decode.ts           # tx / message / typed-data human rendering
│   │   └── policy-view.ts      # policy verdict + risk badges (§4.8)
│   ├── daemon/client.ts        # OCWP HTTP client (loopback validation, version pin)
│   ├── storage/{config,sites,session-store,passkey}.ts
│   └── entrypoints/            # WXT entrypoints: background, content, injected, popup
├── tests/                      # 10 Vitest files (157 tests) incl. §9.3 sentinels
├── e2e/run.mjs                 # Playwright consent flow over the built bundle
├── scripts/{gen-icons.mjs, stub-daemon.mjs}
└── vectors/ocwp-v1/*.json      # shared with the Rust daemon tests (§5.4)
```

The `just` recipes are `ext-build`, `ext-test`, `ext-e2e`, `ext-conformance`
(the same vectors run by both ends), and `ext-pack` (store-ready zip).

Runtime dependencies: **none** beyond Node/browser built-ins. Transaction and
typed-data rendering is display-only (signing is remote), so a ~200-line
RLP/hex utility plus a built-in 4-byte selector table replaces viem/ethers.
This keeps the auditable surface as small as clawd-wallet's.

### 4.2 MV3 Components

`public/manifest.json` (normative shape):

```json
{
  "manifest_version": 3,
  "name": "OneCipher Wallet",
  "version": "0.1.0",
  "description": "Policy-gated EVM wallet. Keys stay in your OneCipher vault; every connection, signature and transaction needs explicit approval.",
  "icons": { "16": "icons/icon-16.png", "32": "icons/icon-32.png",
             "48": "icons/icon-48.png", "128": "icons/icon-128.png" },
  "action": {
    "default_title": "OneCipher Wallet",
    "default_popup": "popup.html",
    "default_icon": { "16": "icons/icon-16.png", "48": "icons/icon-48.png",
                      "128": "icons/icon-128.png" }
  },
  "background": { "service_worker": "background.js", "type": "module" },
  "content_scripts": [{
    "matches": ["http://*/*", "https://*/*"],
    "js": ["content.js"],
    "run_at": "document_start"
  }],
  "web_accessible_resources": [{
    "resources": ["injected.js"],
    "matches": ["http://*/*", "https://*/*"]
  }],
  "host_permissions": ["http://127.0.0.1/*", "http://localhost/*"],
  "permissions": ["storage"],
  "minimum_chrome_version": "116"
}
```

Notes:

- No `tabs` permission: `chrome.tabs.query`/`sendMessage` to our own content
  scripts and `chrome.windows.*` need none (same trick as F1).
- No `options_page`: settings live inside the popup (F14 pattern).
- Default MV3 CSP applies (no `eval`, no remote code).
- No `externally_connectable`: only our content script can open a channel.
- Firefox: add `browser_specific_settings.gecko.id`; `chrome.storage.session`
  requires Firefox ≥ 128 with an in-memory fallback (re-unlock after SW
  restart); use a tiny `chrome`/`browser` promise shim.

### 4.3 dApp-Facing Provider

`injected.ts` exposes a standards-compliant EVM provider:

- **EIP-1193**: `request({method, params})`, `on`/`removeListener`, `enable()`
  (legacy alias of `eth_requestAccounts`), events `accountsChanged`,
  `chainChanged`, `connect`, `disconnect`, `message`.
- **EIP-6963**: announces via `eip6963:announceProvider` with
  `providerInfo = {uuid (per-install, persisted), name: "OneCipher Wallet",
  icon: <inline SVG data URI>, rdns: "com.onecipher.wallet"}`; listens for
  `eip6963:requestProvider`. Multi-wallet coexistence is first-class; the
  extension never fights over `window.ethereum`.
- **Legacy**: if `window.ethereum` is unset, define it with
  `writable: false, configurable: true` and dispatch `ethereum#initialized`
  (F18-adjacent race discipline from clawd-wallet). Flags: `isOneCipher: true`
  only — the extension does **not** claim `isMetaMask`.
- **Realm safety (F18)**: `ArrayBuffer.isView()` instead of `instanceof`
  checks; `TextDecoder("utf-8", {fatal: true, ignoreBOM: true})` for
  `personal_sign` preview so signed bytes match the dApp's bytes; hex
  normalization at the boundary.
- **No fetch patching (F19)**: the provider never touches `window.fetch`;
  HTTP 402 responses pass through untouched.

dApp method → OCWP mapping (v1):

| dApp method (EIP-1193) | Extension handling | OCWP method |
|---|---|---|
| `eth_requestAccounts` | Consent: connect prompt (origin, account, chain) | `oc_connect_site` (+ `oc_accounts`) |
| `eth_accounts` | Local: authorized sites + session (EVM accounts only) | `oc_accounts` |
| `eth_chainId`, `net_version` | Local (**per-site** chain selection, §4.10) | — |
| `personal_sign` | Consent: message preview (UTF-8 + hex fallback) | `oc_sign_message` |
| `eth_signTypedData` / `_v4` | Consent: EIP-712 domain + message tree | `oc_sign_typed_data` |
| `eth_signTransaction` | Consent: full tx detail | `oc_sign_transaction` |
| `eth_sendTransaction` | Consent: tx detail + simulation + policy preview | `oc_send_transaction` |
| `wallet_switchEthereumChain` | Local + persist **per site** | — |
| `wallet_addEthereumChain` | Local custom-chain entry (validated) | `oc_chain_registry` (read) |
| `wallet_watchAsset` | Local UI confirm, no daemon call | — |
| `eth_call`, `eth_estimateGas`, `eth_getBalance`, `eth_getTransactionCount`, `eth_gasPrice`, `eth_maxPriorityFeePerGas`, `eth_getTransactionReceipt` | Proxied (read-only) | `oc_rpc` |
| anything else | Rejected `4200` (fail-closed) | — |

#### Transaction field mapping (normative)

A dApp speaks camelCase hex quantities; OCWP speaks snake_case. The mapping is
one-directional and lossless — every field the dApp set is carried through:

| EIP-1193 (dApp) | OCWP (`transaction`) | Note |
|---|---|---|
| `chainId: "0x1"` | `chain_id: "eip155:1"` | **hex → CAIP-2, `eip155:` is decimal** |
| `value`, `nonce`, `gas`, `gasPrice`, `maxFeePerGas`, `maxPriorityFeePerGas` | same, decimal | `"0x3e8"` → `"1000"` |
| `gas` | `gas_limit` | renamed |
| `input` | `data` | renamed (alias) |
| `type: "0x2"` | `type: "0x02"` | `0x00` / `0x02` / `0x04` accepted |
| `authorizationList[]` | `authorization_list[]` | EIP-7702; entries must be unsigned |

Two rules make this mapping safety-critical rather than cosmetic:

1. **`account_id` follows the transaction's chain, not the wallet's.** A dApp
   that names `chainId: 0x1` must be served a mainnet account even when the
   wallet is pointed at Base. The daemon also re-checks and rejects
   (`-32602`) any structured transaction whose `chain_id` differs from the
   signing account's chain, so a client bug cannot silently sign onto the
   wrong chain.
2. **Absent means absent.** A field the dApp did not send is not sent to the
   daemon as `0` or as the daemon's default — the daemon fills it only when it
   is genuinely missing. Sending `0` for an omitted `maxFeePerGas` would
   discard the fee ceiling the user actually approved.

`0x03` (EIP-4844 blob) and `0x01` (EIP-2930 access list) are rejected rather
than re-encoded as a different envelope — the extension refuses before a
consent prompt is shown, and the daemon refuses again if some other client
asks.

### 4.4 Consent and Approval Queue

Core data structure in the service worker (F5/F6/F7/F11/F15):

```ts
type PendingAction = {
  id: string;                    // crypto.randomUUID()
  kind: "connect" | "sign_message" | "sign_typed_data" |
        "sign_transaction" | "send_transaction";
  origin: string;                // validated sender origin (F8)
  tabId?: number;
  ocwp: { method: string; params: unknown };  // exact daemon request
  view: ConsentView;             // pre-decoded human rendering (decode.ts)
  createdAt: number;
  expiresAt: number;             // now + APPROVAL_TTL_MS (default 300_000)
  resolve: (result: unknown) => void;
  reject: (error: { code: number; message: string }) => void;
};
const pendingActions = new Map<string, PendingAction>();
```

Flow:

```text
dApp → provider.request() → postMessage → content.ts
  → background: providerOrigin(sender)                    [F8, fail-closed]
  → if (connect): enqueue → notification window → Approve
        → oc_connect_site (records site in daemon) → accountsChanged
  → if (sign/send):
        enqueue (ocwp request pre-built, view pre-decoded)
        → open/reuse notification window (F14 liveness check)
        → user reviews: origin · method · decoded details · policy badge · simulation
        → Approve → consume-before-await (F6):
             1. pending.delete(id)
             2. re-validate: session unlocked? site still authorized? (F7)
             3. oc_policy_preview(request) — deny ⇒ reject with mapped code
             4. daemon.call(request) — step-up 4100 ⇒ WebAuthn retry (§3.5)
             5. action.resolve(result)
        → Reject → consume; reject({code: 4001, "User rejected the request"})
        → TTL expiry → consume; reject({code: 4001, "Approval window expired"})
```

Guarantees:

- The dApp promise NEVER settles before an explicit user decision (tested).
- A webpage can never forge approval: `popup:request` messages are rejected
  unless the sender is the extension's own popup/notification page (F9).
- Session expiry mid-queue does **not** drop the request: the notification
  window renders an inline unlock form; after `oc_unlock` the popup re-invokes
  approve with the retained action id (F15-style render-race guard applies to
  this path too).
- Multiple pending requests render as a queue list; the window closes itself
  when the queue empties (F14/F15).
- No auto-approve path exists anywhere in the codebase (INV-2). The old
  clawd-wallet `agentMode` hole is structurally impossible here: there is no
  config flag that can bypass `enqueue`.

### 4.5 Sender Authentication (`request-policy.ts`)

Direct port of F8/F9/F10, with EVM-specific additions:

- `providerOrigin(sender)`: require `sender.id === chrome.runtime.id`,
  `sender.tab?.id !== undefined`, `sender.url` present, protocol
  `http:`/`https:`, and — if `sender.origin` is defined — strict equality with
  `new URL(sender.url).origin`. Reject opaque (`"null"`) origins.
- `requirePopupSender(sender)`: exact protocol + host + pathname match against
  `chrome-extension://<id>/popup.html` (so `popup.html.evil` and
  web-hosted lookalikes fail).
- Routing is a strict allowlist of message envelopes
  (`oc:request`, `popup:request`, `oc:event`); everything else is rejected
  fail-closed (F10), including stale content-script shapes from older
  extension versions.
- The forged-sender matrix from §9.2 is the acceptance test for this module.

### 4.6 Local Storage Split

| Store | Contents | Lifetime |
|---|---|---|
| `chrome.storage.local` `oc:config` | `daemonUrl` (loopback-validated), theme, wallet default chain, custom chains, verified-contract list | Persistent |
| `chrome.storage.local` `oc:sites` | Authorized origins + **each origin's chain binding** (mirror of daemon `sites.json`) | Persistent |
| `chrome.storage.session` `oc:session` | `{session_id, wallet, expires_at_unix}` — a **handle**, never key material | Browser session (F13) |
| `chrome.storage.session` `oc:passkey` | private JWK of the step-up software authenticator (see §3.5 deviation) | Browser session |
| SW module memory | `pendingActions`, account/chain caches, daemon health | SW lifetime |

INV-1: no *wallet* mnemonic, private key, passphrase, or API token is ever
written to any `chrome.storage` area or kept in SW memory. The security test
suite asserts this with a storage sentinel that pattern-matches everything
`storage.set` receives (§9.3).

The single exception is named and bounded: the step-up software-authenticator
key (§3.5), which authorizes nothing but a fresh EIP-7702 confirmation, held
only in `chrome.storage.session` and therefore wiped with the browser.

### 4.7 Daemon Client (`daemon/client.ts`)

- Base URL validation: only `http://127.0.0.1:<port>` / `http://localhost:<port>`
  accepted; anything else is refused client-side (R12c alignment).
- Health: `oc_hello` probe on popup open and on SW startup (non-blocking);
  connection states drive UI (`daemon-offline` screen with the exact
  `onecipher daemon` / `onecipher wallet-rpc serve` command to run).
- Single in-flight request per call; no retry of non-idempotent methods
  (`oc_sign_*`, `oc_send_transaction` are never auto-retried).
- All errors normalized to `{code, message, data?}` (§5.4).

### 4.8 UI Screens

**Action popup (`popup.html`)**

- *Locked*: wallet selector + passphrase → `oc_unlock`; daemon-offline state;
  daemon URL settings; "session expires in mm:ss".
- *Unlocked*: account list with balances (via `oc_rpc`), chain selector,
  connected-sites list with per-site Revoke (`oc_revoke_site`), recent activity
  (`oc_audit_tail`), session-key summary (reserved), Lock button (`oc_lock`),
  policy summary for the active wallet.

**Notification window (`popup.html?view=notification`)** — the consent surface:

- Queue list; each item shows: origin (full, never truncated in the header),
  method-specific title, decoded details, policy badge, simulation summary,
  Approve / Reject.
- `sign_message`: UTF-8 preview with hex fallback (F18), byte length, and a
  "show raw hex" toggle.
- `sign_typed_data`: EIP-712 `domain` block (name/version/chainId/
  verifyingContract), `primaryType`, and a rendered message tree; a warning
  badge when `verifyingContract` is not in the user's verified-contract list.
- `send_transaction` / `sign_transaction`: from/to, value (human + wei), data
  with built-in selector table (`transfer`, `approve`, …), **the fee ceiling the
  dApp pinned** (max fee / priority fee), tx type (0x00/0x02/0x04-EIP-7702
  delegation flag), nonce, chain.
- Risk badges (from `policy-view.ts`): unlimited-approve detection
  (`approve(spender, 2^256-1)`), first-time recipient, value above the
  policy's warn threshold, **simulation revert**, unverified contract, and an
  explicit EIP-7702 delegation notice naming the address that is being granted
  code-execution rights.
- **Policy badge + simulation, shown before the click.** The two verdicts are
  computed when the action is enqueued and attached to the snapshot the window
  renders, so the user does not have to approve blind (or approve first and
  discover the revert afterwards). Both are advisory: a green badge never
  authorizes anything, and the daemon re-evaluates policy at approve time
  (INV-2 / INV-4). An unavailable preview keeps the request visible and says so
  rather than silently pretending it passed.
- The window closes itself when the queue empties (F15), with the
  render-race guard for state broadcasts.

### 4.9 Policy and Risk Display

`oc_policy_preview` (§5.3) returns `{decision, reasons[], matched_policy_ids}`
plus the exact fields the decision was made on (`tx_type`, `to`, `value`,
`data`), so the badge can show *what* was judged, not just the verdict. The
extension renders it as a badge but **never** as an authorization: a green
badge does not skip consent (INV-2), and a red badge rejects with the mapped
error code before the daemon is asked to sign. Deny reasons map to codes:

**Preview parity is a requirement, not a nicety.** `oc_policy_preview` accepts
either the documented flat shape (`to`/`value`/`data`/`raw_hex`/`typed_data`)
**or** a full `transaction` object, and both are projected through the same
`project_tx()` the signing path uses. A preview that read different fields than
enforcement would render a green badge for a transaction policy denies — the
consent UI becomes an instrument that actively misleads the user.

| Policy outcome | Error code |
|---|---|
| default deny / rule mismatch | `4300` + reason string |
| `BudgetExceeded` | `4301` |
| `RateLimitMinute` / `RateLimitHour` | `4302` |
| `Whitelist` | `4303` |
| `Expired` | `4304` |
| `PolicyMissing` | `4305` |
| `Cooldown` | `4306` |
| `PasskeyForged` / step-up required | `4100` (+ `data.require_passkey`) |

**Provider events are addressed, not broadcast.** `accountsChanged` carries
wallet addresses, so it is relayed only to the tabs of origins that are
actually connected (§4.2). A global relay would disclose the address to every
page the browser happens to have open.

### 4.10 Chain Management

- The daemon owns the chain registry (EVM chains from `oc-core` + user custom
  chains, §6.5); `oc_hello`/`oc_chain_registry` serve it to the extension.
- **Per-site chain selection.** A site's chain is part of its connection, stored
  per origin in `oc:sites`. `eth_chainId` / `net_version` /
  `eth_sendTransaction` resolve against the *requesting origin's* binding, and
  `wallet_switchEthereumChain` writes only that origin. An origin that has
  never been connected falls back to the wallet default in `oc:config`.
  A single global chain would let one dApp move another dApp's chain out from
  under it — cross-site interference any attacker page can trigger at will.
- `wallet_addEthereumChain` adds a **local** custom chain after validation
  (numeric `chainId`, `https:` RPC URL, block-explorer optional) — mirroring
  clawd-wallet's "cluster → authoritative endpoint" reverse-lookup discipline
  (F17): a stored chain id always resolves to the registry's endpoint, never
  to a stale persisted URL.

### 4.11 Transaction Resolution (normative)

Structured transactions are normalized once, in `lib/evm-tx.ts`, before a
consent view is built (field table in §4.3). Two invariants the extension
guarantees before the daemon is ever called:

- **The chain is the dApp's.** `account_id` is derived from the transaction's
  own `chainId` when present; the daemon re-validates it (§6.3) and rejects a
  mismatch, so neither end can sign onto a chain the user did not approve.
- **An unsupported envelope is refused, not coerced.** `0x03` (EIP-4844) and
  `0x01` (EIP-2930) are rejected at the boundary; no path re-encodes a typed
  transaction into a different type.

The daemon fills only genuinely-absent fields (`nonce`, `gas_limit`,
`max_fee_per_gas`, `max_priority_fee_per_gas`) from the chain RPC, and a
caller-supplied `from` must equal the signing account — a mismatch would
otherwise fetch another account's nonce and broadcast an unsignable
transaction.

---

## 5. Protocol Specification (OCWP v1)

### 5.1 Envelope

```http
POST / HTTP/1.1
Host: 127.0.0.1:18080
Origin: chrome-extension://<32-char-extension-id>
Content-Type: application/json

{"jsonrpc":"2.0","id":1,"method":"oc_unlock","params":{
  "wallet":"default","passphrase":"…","policies":[]}}
```

```json
{"jsonrpc":"2.0","id":1,"result":{
  "session_id":"…","wallet_id":"…","expires_at_unix":1760000000,
  "accounts":[{"account_id":"…","address":"0x…","chain_id":"eip155:56","derivation_path":"m/44'/60'/0'/0/0"}]}}
```

Error:

```json
{"jsonrpc":"2.0","id":1,"error":{
  "code":4301,"message":"Budget exceeded",
  "data":{"reason":"budget_exceeded","policy_id":"pol_123"}}}
```

### 5.2 Methods

All methods except `oc_hello` require `session_id` (server/automation end:
`Authorization: Bearer oc_key_…` instead, §3.5).

#### Session and handshake

| Method | Params | Result |
|---|---|---|
| `oc_hello` | `{}` | `{protocol_version, daemon_version, chains[], features[], extension_ids?}` |
| `oc_unlock` | `{wallet, passphrase, policies?: string[]}` | `{session_id, wallet_id, expires_at_unix, accounts[]}` |
| `oc_lock` | `{session_id}` | `{}` |
| `oc_session_status` | `{session_id}` | `{unlocked, wallet_id, expires_at_unix}` |
| `oc_passkey_challenge` | `{credential_id?}` | `{challenge_hex, rp_id, timeout_ms}` |

#### Accounts and sites

| Method | Params | Result |
|---|---|---|
| `oc_accounts` | `{session_id}` | `{accounts[]}` |
| `oc_connect_site` | `{session_id, origin, account_id, chain_id}` | `{sites[]}` |
| `oc_revoke_site` | `{session_id, origin}` | `{}` |
| `oc_list_sites` | `{session_id}` | `{sites[{origin, account_id, chain_id, connected_at, last_seen_at}]}` |

#### Signing (policy-evaluated, §6.3)

| Method | Params | Result |
|---|---|---|
| `oc_sign_transaction` | `{session_id, account_id, chain_id, transaction}` | `{raw_transaction, tx_hash?}` |
| `oc_send_transaction` | same | `{tx_hash}` (sign + broadcast) |
| `oc_sign_message` | `{session_id, account_id, message: b64, encoding: "utf8" or "hex"}` | `{signature, public_key}` |
| `oc_sign_typed_data` | `{session_id, account_id, typed_data: <EIP-712 JSON>}` | `{signature, public_key}` |
| `oc_sign_authorization` | `{session_id, account_id, authorization}` (EIP-7702) | `{signature, authorization_hash}` |

`transaction` is either `{"raw":"0x…"}` (unsigned RLP, signed via
`oc-signer::encode_signed_transaction`) or a structured EVM object
(`{to, value, data, gas_limit, max_fee_per_gas, max_priority_fee_per_gas, nonce, chain_id, type}`)
that the daemon fills and encodes as type-2 (the existing
`ledgerflow_sign_payment` builder, generalized).

Field names are accepted in both spellings (`max_fee_per_gas` /
`maxFeePerGas`, `gas` / `gas_limit`, `data` / `input`, `chain_id` /
`chainId`), and quantities as either decimal or `0x` hex. Both `eip155:8453`
(CAIP-2, **decimal**) and `0x2105` (EIP-1193, **hex**) are accepted for
`chain_id` — the radices differ, so conflating them would sign onto the wrong
chain.

Envelope types: `type` is absent or `"0x2"` → EIP-1559; `"0x0"` → legacy
(EIP-155 signed); `"0x4"` → EIP-7702, which requires an `authorizationList` of
unsigned `{address, chainId?, nonce}` tuples that the daemon signs and splices
into the type-4 envelope. `"0x1"` (EIP-2930 access list) and `"0x3"`
(EIP-4844 blob) are rejected rather than re-encoded.

A structured transaction that names a `chain_id` different from its
`account_id` chain is rejected with `-32602`, and a `from` that is not the
signing account is likewise rejected: silently substituting either would
produce a transaction the user did not approve.

#### Read proxy and simulation

| Method | Params | Result |
|---|---|---|
| `oc_rpc` | `{session_id, chain_id, method, params}` | raw JSON-RPC result |
| `oc_simulate` | `{session_id, chain_id, transaction}` | `{ok, gas_used?, revert_reason?}` |
| `oc_chain_registry` | `{session_id}` | `{chains[{chain_id, name, rpc_url, explorer_url?, native_currency}]}` |

`oc_rpc` method allowlist (v1): `eth_chainId`, `eth_blockNumber`,
`eth_getBalance`, `eth_call`, `eth_estimateGas`, `eth_getTransactionCount`,
`eth_gasPrice`, `eth_maxPriorityFeePerGas`, `eth_getTransactionReceipt`,
`eth_getCode`. Limits: 10 s timeout, 1 MiB response cap, 30 rps / burst 60 per
origin, no `eth_sendRawTransaction` (broadcasting is daemon-side only, via
`oc_send_transaction`).

#### Policy, audit, reserved

| Method | Params | Result |
|---|---|---|
| `oc_policy_preview` | `{session_id, chain_id}` + EITHER `{to, value, data, raw_hex?, typed_data?}` OR `{transaction}` | `{decision, reasons[], matched_policy_ids[], tx_type, to, value, data}` |
| `oc_audit_tail` | `{session_id, limit}` | `{events[]}` |
| `oc_session_keys_*` | — | reserved (v1.1; `oc-keyagent` already exposes the primitives) |
| `oc_secrets_*`, `oc_pair_*`, WS push | — | reserved (§7.2) |

### 5.3 Error Codes

| Code | Meaning |
|---|---|
| `4001` | User rejected (also approval-window expiry) |
| `4100` | Unauthorized: locked, session expired, origin not allowed, step-up required (`data.require_passkey`) |
| `4200` | Unsupported method / protocol version mismatch (`data.protocol_version`) |
| `4300`–`4306` | Policy denial (§4.9) |
| `4900` | Disconnected (daemon unreachable) |
| `4901` | Chain not connected for this site |
| `-32600` / `-32601` / `-32602` / `-32603` / `-32000` | JSON-RPC standard |

### 5.4 Conformance Vectors

Wire-level request/response pairs live in `extension/vectors/ocwp-v1/*.json`
and are executed by both the Rust daemon tests (`serde_json`) and the
TypeScript client tests, so the two implementations cannot drift (§9.4).

---

## 6. Daemon-Side Changes

All changes are confined to `bin/oc-cli` (the `wallet_rpc` module, generalized)
plus small additive changes in `oc-wallet` / `oc-policy` / `oc-core` where
noted. No changes to `oc-keyagent`, `oc-crypto`, `oc-policy` evaluation
semantics, `oc-vault` formats, or `oc-secret`.

### 6.1 Module Generalization (D7)

`bin/oc-cli/src/commands/wallet_rpc/` gains the `oc_*` method set; existing
`ledgerflow_*` methods remain as aliases over the same handlers. No new
workspace crate (avoids link-order questions around `oc-keyagent`/BoringSSL
that already constrain `oc-webui`).

### 6.2 Session Store

- In-memory `DashMap<session_id, SessionEntry>` where
  `SessionEntry { wallet_id, wallet_name, passphrase: Arc<Zeroizing<String>>, policy_ids: Vec<String>, created_at, expires_at, last_activity }`.
- TTL: absolute 900 s / idle 300 s defaults, configurable
  (`[wallet_rpc] session_ttl_secs`, `session_idle_secs`).
- Vault lock and `oc_lock` invalidate all sessions for the wallet.
- Sessions are process-memory only; daemon restart = re-unlock (acceptable;
  the extension shows the unlock screen).

### 6.3 Policy Enforcement on the Extension Signing Path

Today policy is enforced only on the API-token path
(`oc_wallet::key_ops::enforce_policy_and_decrypt_key`). For OCWP signing the
daemon MUST also evaluate policy in owner mode:

1. `oc_unlock` records the selected policy ids (default: all policies in the
   vault) and the pinned extension origin (§3.5).
2. Every `oc_sign_*` / `oc_send_transaction` builds an
   `oc_core::PolicyContext` from the request (chain_id, wallet_id, tx
   to/value/data/raw_hex, typed_data when applicable) and runs
   `oc_policy::evaluate_policies`.
3. Deny → mapped error code (§4.9), request never reaches the signer.
4. `oc_policy_preview` is the same evaluation without signing — used by the
   consent UI at enqueue time and re-run at approve time (F7).

**Field projection is shared.** Preview and enforcement both resolve the
transaction through `project_tx()` (§5.2), so a preview can never disagree with
the decision that follows it.

**Audit is mandatory on this path (INV-12).** Every completed
`oc_sign_*` / `oc_send_transaction` / `oc_sign_authorization` writes an entry
to the strong audit channel (`audit-strong.jsonl`) with the method, pinned
origin, chain, transaction type, `to`/`value`, and any EIP-7702 delegation
targets; `oc_send_transaction` additionally records the broadcast result. An
unwritable log is logged and never blocks a policy-allowed signature, but the
write is never optional — without it, `oc_audit_tail` shows nothing for
extension activity and the invariant is simply false.

**Validate before networking.** Every caller-supplied field is checked before
the daemon fills absent ones from the chain RPC. A malformed request must come
back as `-32602` without any RPC round trip; otherwise a clear client bug
surfaces as an opaque "endpoint unreachable".

### 6.4 Sites Registry

New `~/.onecipher/sites.json` (0600): `{origin → {account_id, chain_id,
connected_at, last_seen_at}}`, written by `oc_connect_site`, read by
`oc_list_sites`, deleted by `oc_revoke_site`. Centralizing this (instead of
extension-local-only) makes revocation global across ends (§3.6). The
extension keeps a cache in `chrome.storage.local` for offline rendering.

### 6.5 Chain Registry

New `~/.onecipher/chains.json` (0600): built-in EVM chains from `oc-core` plus
user custom chains (`chain_id`, `name`, `rpc_url`, `explorer_url`,
`native_currency`), served by `oc_chain_registry`, consumed by `oc_rpc` /
`oc_simulate` / `oc_send_transaction` for endpoint resolution.

### 6.6 Connection Hardening

- `Origin` allowlist (`[wallet_rpc] extension_ids`, `--allow-extension`).
- `Host` header validation (anti-DNS-rebinding, §3.4).
- CORS preflight for the extension origin only.
- `oc_rpc` allowlist + rate limits (§5.2).

### 6.7 Passkey Step-Up

Reuses `oc_keyagent::handler::{generate_passkey_challenge, authorize_passkey}`.
Requirement: `StoredPasskeyPubkey` gains an `rp_id` field (default `localhost`
for existing Web UI passkeys) so extension-RP passkeys verify against the
extension's RP id; verification uses the recorded `rp_id` per credential.
Backward compatible: existing records load with `rp_id = "localhost"`.

---

## 7. Multi-End Sync Details

### 7.1 Same Device (implemented by construction)

CLI, Web UI, and extension share `~/.onecipher`; the daemon is the only
writer of signing-relevant state. No sync protocol needed.

### 7.2 Cross Device — Daemon-Attached (reserved, v2)

For a mobile end attaching to a daemon on an always-on host:

1. `oc_pair_begin` (CLI on the daemon host) → 8-digit pairing code +
   ephemeral X25519 public key + nonce.
2. Mobile scans/enters code → `oc_pair_finish {code, device_name,
   device_pubkey}` → daemon stores a device record
   (`~/.onecipher/devices/<id>.json`: Ed25519 identity, name, created_at,
   revoked flag) and returns the channel parameters.
3. Subsequent OCWP runs over TLS to the daemon host; every request carries a
   device Ed25519 signature over the canonical request body plus the
   daemon-issued nonce (replay protection).
4. Revocation from CLI/Web UI is immediate (device record check per request).

Out of scope for v1; the method namespace is reserved so the wire format does
not churn later.

### 7.3 Cross Device — Vault Sync (available today)

`oc-vault` `.ocbk` export/import moves the encrypted vault between devices
through user-controlled storage. Properties: no plaintext leaves a device;
wallet ids are stable UUIDs so distinct wallets merge conflict-free; same-id
conflicts require an explicit user choice. Policy export carries the open
question OQ-2 (policy signing key) — until resolved, policies are re-created
and re-signed on the target device.

---

## 8. Security Model

### 8.1 Invariants (normative, each mapped to a test in §9)

| ID | Invariant |
|---|---|
| **INV-1** | The extension never holds, logs, or persists *wallet* key material, passphrases, or API tokens — in any storage area, SW memory, or message. The one bounded exception is the step-up software-authenticator key (§3.5), held only in `chrome.storage.session` and wiped with the browser. |
| INV-2 | Every connection, signature, and transaction requires an explicit Approve in extension-owned UI. No auto-approve code path exists. |
| INV-3 | Approval entries are single-consumption: consume-before-await makes double execution impossible. |
| INV-4 | Approval re-validates session state, site authorization, and policy at click time; stale or reused approvals are rejected. |
| INV-5 | dApp requests are accepted only from this extension's content scripts: `sender.id` + `tab.id` + protocol + origin/url consistency, all Chrome-provided. |
| INV-6 | Popup/notification commands are accepted only from the extension's own popup page (exact protocol + host + pathname). |
| INV-7 | Unknown message envelopes are rejected fail-closed. |
| INV-8 | The extension never patches `window.fetch` and never touches HTTP 402 responses. |
| INV-9 | The daemon connection is loopback-only; `Origin` must be an allowlisted `chrome-extension://` id; `Host` must be loopback (anti-rebinding). A session is additionally usable only from the origin that unlocked it (§3.5). |
| INV-10 | A site connection grants no signing rights by itself; each sign/send prompts. |
| INV-11 | Passphrases transit only over loopback to the daemon and are never logged (daemon-side `Zeroizing`). |
| INV-12 | Every signing request is evaluated by the policy engine and written to the audit log, regardless of end. |
| INV-13 | The daemon's session TTL bounds the blast radius of an unlocked browser: expiry forces re-unlock. |
| INV-14 | A dApp's requested chain and fee ceiling survive the hop to the daemon verbatim: `account_id` is bound to the transaction's own chain, and omitted fields are never substituted with `0` or a daemon default. |
| INV-15 | A policy badge or simulation result is never an authorization. The consent prompt shows them, the daemon re-evaluates policy at approve time, and neither a green badge nor a failed preview can skip or block the user's own decision. |
| INV-16 | A passkey step-up challenge is bound to the session that requested it, is single-use, and expires in 120 s. A challenge minted for one session's authorization cannot authorize another's. |
| INV-17 | A structured transaction whose `chain_id` differs from the signing account's chain is rejected, never silently re-encoded onto the account's chain. |

### 8.2 Threat Model

| # | Threat | Mitigation |
|---|---|---|
| T1 | Malicious dApp requests signatures | INV-2/INV-5/INV-10 + decoded consent UI + policy + simulation |
| T2 | Phishing page imitating the wallet UI | Extension pages only exist under `chrome-extension://`; consent UI always shows the full origin; no web page can open the notification window's channel (INV-6) |
| T3 | Malicious page script forging postMessage | Channel + `event.source === window` checks in `content.ts`; only our content script can reach the SW (INV-5) |
| T4 | Compromised service worker (supply chain) | INV-1 limits blast radius to consent bypass attempts; daemon policy + audit remain the gate; minimal dependency surface; CSP |
| T5 | Local malicious process talking to the daemon port | INV-9 (Origin allowlist, Host validation, loopback bind), session TTL (INV-13) |
| T6 | DNS rebinding against the loopback port | INV-9 Host validation |
| T7 | OCWP request replay (remote end, v2) | Nonce + device signature (§7.2); v1 is loopback-only |
| T8 | Double-click / duplicate approval | INV-3 |
| T9 | Approval after revocation (site revoked, wallet locked, policy changed while pending) | INV-4 |
| T10 | Screenshot / screen capture by a page | The extension requests no capture permissions and exposes no capture API; the e2e sentinel asserts zero captures (F20) |
| T11 | Shoulder surfing / unattended unlocked browser | Idle TTL, explicit Lock, `chrome.storage.session` wiped on browser close (F13) |
| T12 | Extension update silently changing behavior | Store review + version-pinned release + evidence JSON per release (§9.5) |

### 8.3 Hard-Gate Alignment

- **R12c/R12e**: the daemon binds loopback only (unchanged); the extension
  client refuses non-loopback daemon URLs (§4.7).
- **R56/R55/R51/R52**: untouched — no new async/network deps in
  `oc-keyagent`/`oc-crypto`/`oc-policy`/`oc-session-key`; all OCWP server code
  lives in `bin/oc-cli` (tokio context, same as today).
- The TypeScript extension is outside the cargo workspace; its "hard gates"
  are INV-1…INV-13 enforced by §9's test suite in CI.

---

## 9. Testing Strategy

### 9.1 Test Layers

| Layer | Runner | What it covers |
|---|---|---|
| Unit | `vitest run` (happy-dom) — 157 tests, 10 files | routing/sender auth, tx normalization, consent invariants, decode, storage, protocol, conformance |
| Sentinels | `tests/security.test.ts` | storage / network / capture / `fetch` sentinels (§9.3) |
| E2E | `extension/e2e/run.mjs` — Playwright, disposable Chromium profile, stub OCWP daemon | the **built** bundle: connect → sign → reject, HTTP 402 passthrough |
| Conformance | `extension/vectors/ocwp-v1/*.json`, run by both ends | wire-level parity (§9.4) |
| Daemon | `cargo test -p oc-cli --bin onecipher` | 263 tests: conformance vectors, step-up binding, origin pinning, tx validation |

*Deviation, recorded.* The reference project runs its unit suite inside a
`node:vm` sandbox over the **built bundles**, which catches packaging
regressions source-level tests cannot see. This implementation unit-tests the
dependency-injected pure modules directly (routing, consent, normalization,
storage) under `vitest` + `happy-dom`, and closes the packaging gap at the
e2e layer instead: `e2e/run.mjs` loads `.output/chrome-mv3` into a real
Chromium via `--load-extension`, so every entrypoint — `background.js`,
`content-scripts/content.js`, `injected.js` and the popup — is exercised as
built. The two are complementary; only the e2e shape proves the three-layer
injection actually works.

### 9.2 Sender Matrix and Routing

- Forged-sender matrix: webpages impersonating the popup for every
  `popup:*` method; opaque (`"null"`) origins; origin/url mismatch; other
  extension ids; `popup.html.evil` path confusion; web-hosted
  `popup.html` lookalikes; missing `tab.id`; missing `url`. All MUST be
  rejected `4100`.
- Unknown envelopes rejected fail-closed (INV-7).

### 9.3 Consent Invariants and Sentinels

For every signing method (`personal_sign`, `eth_signTypedData`,
`eth_signTransaction`, `eth_sendTransaction`, connect):

- The dApp promise is unsettled before Approve (`settled === false`).
- The pending action carries the exact origin, decoded details, and the
  pre-built OCWP request.
- Spoofed `popup:approve` from a web sender is rejected; still unsettled.
- Reject → `4001`; queue drains.
- Concurrent double-approve → exactly one execution (INV-3).
- Revoke-during-pending / lock-during-pending → `4100` at approve time
  (INV-4).

Sentinels (`tests/security.test.ts`, run against the real router with stub
browser/storage/network surfaces):

- `network`: every URL the extension requests is the configured loopback
  daemon — the stub throws for anything else, so an off-loopback request is a
  test failure rather than a log line.
- `captures`: zero `captureVisibleTab` calls (the stub throws, so the sentinel
  asserts the tripwire is armed *and* that nothing tripped it).
- `storage`: every value passed to `storage.local.set` and
  `storage.session.set` is pattern-matched against mnemonic / raw-key /
  passphrase / API-token shapes, and the unlock passphrase must not appear in
  any of them (INV-1). The `session`-only confinement of the step-up key is
  asserted separately.
- `fetch` identity unchanged (INV-8): `window.fetch` is the same object before
  and after a full consent flow.

### 9.4 Protocol Conformance

`extension/vectors/ocwp-v1/*.json` wire pairs run against the Rust daemon
tests and the TS client tests (`just ext-conformance`).

### 9.5 End-to-End (Playwright)

- Disposable Chromium profile (`launchPersistentContext` + `mkdtemp`),
  `--load-extension=dist`; the user's real profile is never touched.
- Fixture dApp page drives `window.ethereum` through connect → sign → reject
  paths; the daemon runs against a fixture wallet (never funded).
- Signature correctness verified end-to-end (recover signer from the returned
  signature).
- Results written to `extension/docs/verification/e2e.json` as auditable
  evidence (F20): profile disposal, zero captures, zero non-daemon network
  calls, HTTP 402 preserved.

### 9.6 Rust Side

`cargo test` coverage for §6: session TTL/idle expiry, policy denial mapping,
origin/Host rejection, `oc_rpc` allowlist and rate limits, `ledgerflow_*`
alias compatibility, conformance vectors.

---

## 10. Build, Packaging, CI

- **Toolchain**: Node ≥ 20.19 (Vite 7 floor), TypeScript strict, Vite
  multi-entry (`background`, `content`, `injected`, `popup`) with flat
  `[name].js` outputs and inlined channel constants (F4).
- **Scripts**: `dev` (watch), `build`, `typecheck`, `test`, `test:e2e`
  (Playwright), `zip` (store-ready archive).
- **Repo integration**: `extension/` is an npm project at the repo root, NOT a
  cargo workspace member. `Justfile`/`Makefile` expose `just ext-build`,
  `just ext-test`, `just ext-e2e`, `just ext-conformance` (both ends of the
  vectors) and `just ext-pack`; the two files are kept in lockstep by
  `scripts/check-makefile-mirror.sh`.
- **CI**: the `extension` job runs `npm ci`, `typecheck`, `test`, `build`, then
  the **Rust half** of the conformance vectors (`cargo test -p oc-cli --bin
  onecipher vectors`), then installs Chromium and runs the consent e2e. The
  e2e evidence (`extension/e2e/verification/e2e.json`) is uploaded on every run
  so a failure can be inspected rather than guessed at.
- `just ci` / `make ci` run `lint test build ext-build ext-test ext-conformance
  ext-e2e ext-pack`. The Rust gates (`lint`, `test`, `build`) are unchanged.
  `ext-pack` is part of the recipe because the store-ready zip is the shipped
  artifact: a build that compiles but cannot be packaged is not a passing build.
- **Versioning**: extension version is independent semver; `oc_hello`
  `protocol_version` governs client/server compatibility.

---

## 11. Implementation Phases

| Phase | Deliverable | Exit criteria | Status |
|---|---|---|---|
| P0 | This design document | Reviewed and approved | Done |
| P1 | Daemon OCWP core | `cargo test` green; `ledgerflow_*` aliases unchanged; vectors pass both ends | Done |
| P2 | Extension skeleton | `npm run build` + typecheck; sender-matrix tests green | Done |
| P3 | Consent queue + notification UI + popup | Consent invariant tests green per method | Done |
| P4 | Security + e2e suites, evidence JSON, README/SECURITY, CI + Justfile wiring | `just ci` green end-to-end | Done |
| P5 | Multi-end completion: mobile pairing spec + server token flow documented; optional Solana provider | Design docs only for mobile | **Open** |

### 11.1 Review pass (added after P4)

A review of the document against the implementation found defects on both
ends. All are closed; the notable ones and the rules that now pin them:

| Finding | Resolution | Guard |
|---|---|---|
| dApp `chainId` dropped → signed on the wallet's active chain | `account_id` bound to the tx's chain; daemon rejects a mismatch | INV-14 / INV-17 |
| EIP-1193 camelCase fee/gas/input fields ignored → fee ceiling discarded | Lossless mapping in `lib/evm-tx.ts`; both spellings accepted | INV-14 |
| `oc_policy_preview` always evaluated an empty request → always "allow" | preview and enforcement share `project_tx()` | INV-15 |
| OCWP signing wrote no audit entry (INV-12 was false) | every sign/send/authorization records to the strong channel | INV-12 |
| step-up challenge not bound to its session | `StepUpStore`: single-use, 120 s TTL, session-scoped | INV-16 |
| sessions usable from any allowlisted origin | session records the unlocking origin | INV-9 |
| `personal_sign` returned an object, not a signature | returns the signature string | EIP-1193 |
| non-EVM accounts surfaced in `eth_*` results | EVM-only filtering | v1 scope (§1.2) |
| chain selection was global — one dApp moved every dApp's chain | per-origin chain binding | §4.3 / §4.10 |
| step-up private JWK persisted in `chrome.storage.local` | `chrome.storage.session` only; §3.5 records the deviation | INV-1 |
| consent UI had no policy badge and never called `oc_simulate` | badges + simulation computed at enqueue time | INV-15 |
| "first-time recipient" / "value over threshold" / "unverified contract" badges absent | `lib/consent/policy-view.ts` | §4.8 |
| popup offered a hardcoded chain list and no balances | chains and balances come from the daemon | §4.8 / §4.10 |
| `accountsChanged` broadcast to every tab | addressed to connected sites only | §4.9 |
| `protocol_version` checked only in `oc_hello` | a negotiated mismatch blocks every later method | §3.3 |
| e2e / conformance / pack absent from CI; test suite leaked a rejection | all wired; unhandled rejection fixed | §10 |

Three further defects were introduced *by* the fixes and caught by the tests
written alongside them: CAIP-2 `eip155:` references were parsed as hex
(`eip155:8453` read as chain 33875), `StepUpStore::consume` let a foreign
session destroy another session's pending challenge, and `field()` stopped its
null-search on the first key so a real `maxFeePerGas` could be hidden by a
`null`. The guard against the last class is the rule that a request's field
search continues past explicit `null`.

## 12. Decisions (ADR-style)

| ID | Decision | Alternatives rejected | Rationale |
|---|---|---|---|
| D1 | Extension holds **no keys**; custody stays in the daemon | Self-contained extension vault (clawd-wallet model) | Multi-end sync requires one authoritative store; avoids duplicating age/crypto in TS; keeps INV-1 achievable by construction; policy + audit apply uniformly |
| D2 | Loopback HTTP as the extension↔daemon transport | Chrome native messaging | Reuses the existing `wallet_rpc` server; cross-browser (Firefox); no separate host installer. Native messaging remains a future hardening option |
| D3 | EIP-1193 + EIP-6963 standards for the dApp surface | Custom injection API only | dApp compatibility; multi-wallet coexistence without `window.ethereum` fights |
| D4 | Session unlock (passphrase → TTL session) + policy-driven Passkey step-up | Per-signature WebAuthn | UX; step-up preserves strong user presence for high-risk ops |
| D5 | TypeScript + Vite, zero UI framework, zero runtime deps | React/Vue + viem | Matches the proven reference architecture; smallest auditable surface; display-only decoding needs no chain SDK |
| D6 | `extension/` lives outside the cargo workspace | New `crates/oc-*` member | It is an npm project; Rust gates are unaffected; avoids workspace lint inheritance noise |
| D7 | OCWP server stays in `bin/oc-cli` (`wallet_rpc` module generalized); `ledgerflow_*` kept as aliases | New `crates/oc-wallet-rpc` crate | No link-order risk around `oc-keyagent`/BoringSSL (cf. `oc-webui` constraint); minimal workspace churn; extract later if a second Rust consumer appears |
| D8 | Policy evaluation extended to owner-mode OCWP signing | Token-only enforcement (status quo) | The extension is an interactive end; without this, dApp-originated owner-mode signing bypasses the policy engine, contradicting the product thesis |
| D9 | Authorized sites centralized in the daemon (`sites.json`) | Extension-local only | Global revocation across ends (§3.6) |
| D10 | Read-only RPC proxied through the daemon | Direct dApp→RPC from the extension | Keeps `host_permissions` loopback-only (F2), central endpoint management, audit, rate limits |

---

## 13. Open Questions

| ID | Question | Default if unresolved |
|---|---|---|
| OQ-1 | Should the notification window show a favicon / site title (requires a `tabs`-free fetch of the page, which CORS usually blocks)? | No favicon in v1; full origin string only |
| OQ-2 | Cross-device policy sync: does `.ocbk` carry `policy_signing.key`, or does each device sign its own policies? | Each device signs its own; policies re-created on import |
| OQ-3 | Passkey RP id for the extension: per-extension-id RP ids vs a daemon-mediated RP | Per-extension-id RP id recorded in `StoredPasskeyPubkey.rp_id` (§6.7) |
| OQ-4 | Firefox `storage.session` fallback behavior on older versions | In-memory session; re-unlock after SW restart, with a UI notice |
| OQ-5 | Should `oc_rpc` expose `eth_getLogs` for dApp history UIs? | Not in v1; additive later with stricter limits |

---

## 14. References

- Reference project: `/Volumes/akext/tmp/clawd-wallet` (`README.md`,
  `SECURITY.md`, `docs/wallet-consent-fix.md`, `tests/security.test.mjs`,
  `tests/browser-consent.mjs`).
- OneCipher: `docs/architecture.md`, `docs/security-model.md`,
  `docs/webui-approval-design.md`, `docs/policy-engine.md`,
  `docs/signing-interface.md`, `docs/supported-chains.md`.
- Standards: EIP-1193, EIP-6963, EIP-712, EIP-1559, EIP-7702, EIP-4337,
  Chrome Extension Manifest V3.
