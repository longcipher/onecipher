# OneCipher Wallet Extension — Security Posture

Normative spec: [`docs/extension-wallet-design.md`](../docs/extension-wallet-design.md)
(§8 Security Model). This document summarizes what the extension does and does
not trust, and which invariants the test suite enforces.

## Custody

The extension is **keyless for custody**. It never generates, derives, or
transmits a *wallet* key, and it never sees a passphrase after handing it to the
daemon. Custody belongs to the OneCipher daemon (`oc-vault`, age-encrypted
keyfiles, per-request signing enclave). The extension's most sensitive artifact
is the daemon **session handle** (`session_id` + expiry), held in
`chrome.storage.session` (memory-only, wiped when the browser closes) —
mirroring the reference architecture's unlocked-state layer.

### The one exception: the step-up authenticator

Design §3.5 originally specified `navigator.credentials.get()` for EIP-7702
step-up. A `chrome-extension://` page cannot host a real WebAuthn relying party
(the RP must be a registrable-domain suffix of the origin), so that call cannot
succeed from an extension. The extension therefore runs a **software
authenticator**: an ECDSA P-256 keypair generated via WebCrypto, its public half
registered over `oc_passkey_register`, signing daemon-issued challenges on
demand.

Controls on that one key:

- **`chrome.storage.session` only** — never `chrome.storage.local`, so it cannot
  outlive the browser session. Re-registering after a restart is the accepted
  cost.
- **Bounded blast radius.** It authorizes nothing but a *fresh* EIP-7702
  confirmation. It cannot sign a transaction, unlock a wallet, or read state.
- **Session-bound, single-use challenges.** `oc_passkey_challenge` binds the
  challenge to the session that requested it; the daemon rejects a proof from a
  different session, consumes the challenge on first use, and expires it after
  120 s. A mismatched session does *not* consume the binding — otherwise any
  allowlisted extension could invalidate another's pending step-up.

A hardware WebAuthn path that works from an extension origin is tracked as
design OQ-3. Until then this is the strongest available construction, and its
limit is the extension process itself — which is exactly why the daemon's
policy engine, audit log, and TTL are the backstop rather than anything here.

## Trust model

| Layer | Trust level | Enforcement |
|---|---|---|
| dApp page realm | Untrusted | postMessage channel + `event.source` checks; EIP-1193 surface is an allowlist |
| Content script | Ours, untrusted input | Sender authentication in the worker uses Chrome-provided fields (`sender.id`, `sender.tab`, `sender.url`, `sender.origin`) that pages cannot forge |
| Popup / notification window | Ours | Exact protocol+host+pathname match on `popup.html`; webpages cannot impersonate it |
| Loopback daemon | Trusted computing base | Origin allowlist (`chrome-extension://` IDs), Host-header loopback check (anti DNS-rebinding), sessions with TTL, policy engine, audit log |

## Invariants (each mapped to tests)

| ID | Invariant | Test |
|---|---|---|
| INV-1 | No *wallet* mnemonic / key / passphrase / API token ever enters `chrome.storage` or worker memory. The one exception is the step-up key above, `chrome.storage.session` only | `tests/security.test.ts` storage sentinel over the full consent flow |
| INV-2 | Every connection, signature, and transaction requires explicit approval; no auto-approve code path exists | consent-queue + router tests |
| INV-3 | Approvals are single-consumption: consume-before-await makes double execution impossible | `queue.approve` concurrency test |
| INV-4 | Approval re-validates session, site authorization, and policy at click time | revoked-mid-flight + policy-deny tests |
| INV-5 | dApp requests only from this extension's content scripts (Chrome sender fields) | `tests/request-policy.test.ts` forged-sender matrix |
| INV-6 | Popup commands only from the extension's own `popup.html` (exact URL match) | sender-matrix lookalike cases |
| INV-7 | Unknown message envelopes are rejected fail-closed | routing tests |
| INV-8 | No `window.fetch` patching; HTTP 402 passes through untouched | e2e `http402Preserved` + fetch-identity sentinel |
| INV-9 | Loopback-only daemon URLs, extension-ID allowlist, and a session usable only from the origin that unlocked it | `validateLoopbackUrl` tests + daemon `validate_connection` / `touch_for_origin` tests |
| INV-10 | A site connection grants no signing rights | connect-once/sign-always router tests |
| INV-11 | Passphrases transit only over loopback and are never logged | daemon `Zeroizing` + storage sentinel |
| INV-12 | Every signing request reaches the daemon's audit log | daemon audit assertions |
| INV-13 | Session TTL and idle expiry force re-unlock | daemon session tests |
| INV-14 | A dApp's requested chain and fee ceiling reach the daemon verbatim; omitted fields are never replaced with `0` | `tests/evm-tx.test.ts` + router normalization tests |
| INV-15 | A policy badge or simulation result is never an authorization | `tests/consent-queue.test.ts` + router assessment tests |
| INV-16 | A step-up challenge is session-bound, single-use, and expires in 120 s | daemon `StepUpStore` tests |
| INV-17 | A structured transaction whose chain differs from the signing account's chain is rejected | `evm-tx` + daemon `resolve_transaction` tests |

## Additional enforcements added after the first review pass

- **Per-site chain isolation.** A site's chain is part of its connection. One
  dApp calling `wallet_switchEthereumChain` cannot move another dApp's chain,
  which a single global setting would have allowed any attacker page to do.
- **Addressed provider events.** `accountsChanged` is relayed only to the tabs
  of origins that are actually connected; a global relay disclosed wallet
  addresses to every open page.
- **Addressable consent UI.** The policy verdict and the simulation result are
  attached when the action is enqueued, so the user sees them before clicking.
  A failed preview keeps the request visible and says so — it never silently
  passes and never silently blocks.
- **Protocol version is enforced continuously.** A negotiated mismatch blocks
  every later method, not just the handshake.
- **Consent failures surface.** An `openNotification` failure fails the request
  rather than leaving the dApp promise hanging forever.

## Deliberate non-features

- No auto-approval mode of any kind (the reference project's `agentMode` hole
  is structurally impossible: there is no flag that bypasses the consent queue).
- No telemetry, analytics, or crash reporting.
- No payment interception; `window.fetch` is never patched.
- No remote code; the MV3 default CSP applies.
- No non-EVM provider in v1 (protocol is chain-neutral; Solana is additive later).

## Vulnerability reporting

See the repository security policy (`SECURITY.md` at the repo root / 'security-model' docs).
