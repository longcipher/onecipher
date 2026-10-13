# OneCipher Wallet — Browser Extension

Policy-gated EVM wallet extension (Manifest V3) for the OneCipher daemon.
Built with [WXT](https://wxt.dev) + React. Normative design:
[`docs/extension-wallet-design.md`](../docs/extension-wallet-design.md).

**The extension holds no key material.** Keys live in the OneCipher daemon's
`oc-vault` (age-encrypted); policy gates live in `oc-policy`; signing goes
through `oc-signer` (per-request enclave subprocess by default). The extension
is the dApp-facing consent surface: every connection, signature, and
transaction requires an explicit Approve in extension-owned UI.

## Architecture

```text
dApp page (window.ethereum, EIP-1193 + EIP-6963)
  ↕ window.postMessage (channel: onecipher-ocwp)
content script (isolated world, the only bridge)
  ↕ browser.runtime.sendMessage (sender-authenticated)
service worker (consent queue + OCWP client)
  ↕ HTTP loopback (JSON-RPC 2.0, session + Origin allowlist)
OneCipher daemon (oc-vault · oc-policy · oc-signer · audit)
```

- `src/entrypoints/injected.ts` — in-page EIP-1193 provider (unlisted script).
- `src/entrypoints/content.ts` — isolated-world bridge (document_start).
- `src/entrypoints/background.ts` — service worker wiring.
- `src/lib/background/router.ts` — testable routing/consent core.
- `src/lib/consent/queue.ts` — pending queue: consume-before-await, TTL,
  approval-time re-validation (INV-2/3/4).
- `src/lib/request-policy.ts` — Chrome-sender authentication (INV-5/6).
- `src/lib/consent/decode.ts` — display-only tx/message/EIP-712 decoding.
- `src/lib/consent/policy-view.ts` — policy verdict → risk badges: first-time
  recipient, value over the user's warn threshold, unverified contract.

## Setup

1. Build and run the daemon with the OCWP surface enabled, allowlisting this
   extension's ID (shown on the extension's settings page / `chrome://extensions`):

   ```bash
   onecipher wallet-rpc serve \
     --allow-extension <extension-id> \
     --session-ttl-secs 900 --session-idle-secs 300
   ```

   Daemon environment equivalents: `OC_WALLET_RPC_LISTEN`,
   `OC_WALLET_RPC_EXTENSION_IDS` (comma-separated), `OC_WALLET_RPC_SESSION_TTL_SECS`,
   `OC_WALLET_RPC_SESSION_IDLE_SECS`, `OC_WALLET_RPC_REQUIRE_PASSKEY_EIP7702`.

2. Load the extension:

   ```bash
   npm install
   npm run build          # → .output/chrome-mv3
   npm run dev            # or: auto-opening Chromium with the extension loaded
   ```

   Chrome → `chrome://extensions` → Developer mode → "Load unpacked" →
   select `.output/chrome-mv3`.

3. In the popup: Settings → set the daemon URL (loopback only) → Unlock with
   the wallet passphrase. Optionally register a passkey for EIP-7702 step-up.

## Development

```bash
npm run typecheck    # tsc --noEmit
npm run test         # vitest unit + sentinel suite (157 tests, 10 files)
npm run build        # wxt build → .output/chrome-mv3
npm run test:e2e     # Playwright consent flow vs scripts/stub-daemon.mjs
npm run zip          # store-ready zip
```

The e2e run leaves auditable evidence in `e2e/verification/e2e.json`
(disposable profile, zero captures, HTTP 402 preserved).

## Security properties

See `SECURITY.md` and design doc §8. The headline invariants, each covered by
tests:

- INV-1 no key material in the extension (storage sentinel in the test suite).
- INV-2 every connection/signature/transaction prompts; no auto-approve path.
- INV-3 approvals are single-consumption (consume-before-await).
- INV-4 approvals re-validate session/site/policy at click time.
- INV-5/6 Chrome-sender authentication for dApp and popup messages.
- INV-8 no fetch patching; HTTP 402 passes through untouched.
- INV-9 loopback-only daemon connections; extension ID allowlist on the daemon.

## Firefox

`npm run build:firefox`. `chrome.storage.session` requires Firefox ≥ 128;
older versions fall back to an in-memory session (re-unlock after worker
restarts).
