# Sign-in with Wallet (SIWW) — Generic IAM Integration

> How any IAM / relying party can integrate OneCipher as a signing wallet using
> standard WalletConnect v2, **without any browser extension** and **without any
> OneCipher-specific account-system dependency**.
>
> OneCipher speaks standard protocols. The capabilities described here are generic:
> `personal_sign`-family methods, a dedicated `onecipher_signAuth` method, the
> WalletConnect v2 Auth protocol (`wc_authRequest`), and CAIP-122 Sign-In with X
> (`solana_signIn`, Key-Agent `SignSiwx`, `onecipher sign-in`). Any OIDC/OAuth IAM
> can consume them.

## 1. Integration Model

```text
┌─────────────────────────┐         ┌─────────────────────────────┐
│ Relying Party (IAM)     │         │ User machine                 │
│  e.g. an OIDC provider  │         │  OneCipher daemon (wallet)   │
│                         │         │                              │
│  - issues nonce/challenge│        │  - key custody (local only)  │
│  - verifies signature   │         │  - policy engine + audit     │
│  - binds address ↔ user │         │  - WebUI/CLI human approval  │
└───────────┬─────────────┘         └──────────────┬───────────────┘
            │                                      │
            └───────────────► WC v2 relay (WSS) ◄──┘
                    dApp side              wallet side
                 (browser, CLI, SDK)   (OneCipher daemon)
```

Roles:

| Role | Who | Direction |
|---|---|---|
| Wallet | OneCipher daemon (`oc-walletconnect` wallet role) | outbound WSS to relay |
| dApp | The IAM's web portal / CLI / SDK | outbound WSS to relay |
| Relay | any WC v2 relay (`wss://relay.walletconnect.com` or self-hosted) | encrypted relay |

The private key never leaves the daemon; the IAM only ever sees addresses and signatures.

## 2. Signing Capabilities Exposed Over WC v2

### 2.1 Standard methods (already supported)

| Method | Use | Auth gate |
|---|---|---|
| `personal_sign` / `eth_sign` | EIP-191 message signing | passkey-gated (P0-2) |
| `eth_signTypedData_v4` | EIP-712 typed data | passkey-gated |
| `eth_sendTransaction` / `eth_signTransaction` | EVM tx | passkey-gated |
| `solana_signMessage` | Solana offchain message (raw ed25519 via `SignAuth` with the real chain id) | passkey-gated |
| `solana_signTransaction` | Solana | passkey-gated |
| `solana_signIn` | CAIP-122 Solana Sign-In (Key-Agent `SignSiwx`: parse fail-closed, chain-bound, single-use) | passkey or daemon-internal token |
| `onecipher_listWallets` / `onecipher_getBalance` | read-only | none |
| `onecipher_generateChallenge` | obtain passkey challenge | none |

### 2.2 `onecipher_signAuth` — auth-class signature (recommended for sign-in)

A dedicated, **low-risk** message-signing method for authentication flows. Direct
callers must provide an explicit Passkey proof; the daemon's internal
WalletConnect path may instead inject a daemon-internal capability token.
Human confirmation is still provided by the daemon's approval flow (WebUI / CLI / policy).

```jsonc
// request
{
  "chain_id": "eip155:1",      // CAIP-2
  "message":  "<EIP-4361 text>",
  "wallet_id": "optional",     // default wallet when omitted
  "auth": {                    // required for direct/local callers
    "challenge_hex": "...",
    "signature_hex": "...",
    "credential_id": "..."
  }
}
// response
{
  "signature":  "0x...",
  "address":    "0x...",       // chain-standard address
  "chain_id":   "eip155:1",
  "public_key": "0x...",       // included for non-EVM chains (needed for verification)
}
```

Behaviour:

- Signs the raw `message` bytes using the chain's message-signing convention
  (EVM: `personal_sign`/EIP-191; Solana: raw bytes ed25519; Cosmos: ADR-036; …) —
  identical to OneCipher's existing `signMessage` path.
- Gated by the daemon's approval flow when enabled; risk class `auth`.
- Subject to the policy engine (chain allowlist, expiry, …).
- When `wallet_id` is omitted, the default wallet must have an account for the
  requested `chain_id`; OneCipher does not silently fall back to another chain's account.
- Generic: no realm, issuer, or account-system fields are hardcoded.

Implementation notes:

- **Direct/local calls are passkey-gated.** Local JSON-RPC callers must
  present a `PasskeyAuthorization`; the Key-Agent verifies it before signing.
- **WalletConnect daemon calls use an internal token.** `wc_authRequest` and
  daemon-owned `onecipher_signAuth` requests do not forward a passkey proof
  over the relay. Instead, the daemon injects a startup-minted internal token,
  and the Key-Agent derives the device-bound unlock token from the process
  device key (`~/.onecipher/audit_device.key`).
- `public_key` is returned as `0x`-prefixed hex (33-byte compressed
  secp256k1 for EVM-family chains, 32-byte ed25519 otherwise).

### 2.3 WalletConnect v2 Auth protocol (`wc_authRequest`)

The daemon also supports the standard WC v2 Auth handshake — a **one-time**
pairing that returns a signature for an EIP-4361 (SIWE) message, no session
required (implemented in the `oc-walletconnect` Auth module + the Net-Agent
method router):

```jsonc
// wc_authRequest params (per WC v2 Auth spec)
{
  "type":    "eip4361",
  "chainId": "eip155:1",
  "aud":     "https://iam.example.com",
  "domain":  "iam.example.com",
  "nonce":   "<server nonce>",
  "statement": "Sign in with your wallet",
  "resources": []
}
// response result
{ "signature": "0x...", "hash": "0x...", "payload": {...} }
```

Supported types: `eip4361` (EIP-191 signature over the SIWE message) for EVM;
`eip191` for generic EVM messages. Solana chains take the CAIP-122 branch:
the daemon builds the Sign-In text (`{domain} wants you to sign in with your
Solana account:`, genesis-hash or alias chain id), gates it through policy +
approval, and signs via the Key-Agent's replay-protected `SignSiwx` path
(message hash consumed single-use before signing). Other namespaces return
`METHOD_NOT_SUPPORTED` (use `onecipher_signAuth` there).

### 2.4 CAIP-122 Sign-In with X (EVM + Solana)

The message model lives in `oc-siwx` (ABNF parse, `AuthOpts` domain/nonce
binding, 60s skew, DoS bounds); pure-crypto verification in `oc-signer`
(`EvmVerifier`: EIP-191 + low-s gate + EIP-55; `SolanaVerifier`: Ed25519,
weak-key rejection); contract/counterfactual verification in `oc-netagent`
(`RpcVerifier`: EIP-1271 `isValidSignature`, ERC-6492 deployless simulation,
`eth_chainId` pre-check, per-chain RPC map, URL-free errors).

Local tooling (no daemon, no RPC unless noted):

```bash
onecipher sign-in message --chain eip155:1 --domain example.com \
  --address 0x... --uri https://example.com/login   # exact signing text
onecipher sign-in parse --message-file msg.txt [--json]
onecipher sign-in verify --message-file msg.txt --signature 0x... \
  --domain example.com --nonce <nonce>               # EOAs offline
onecipher sign-in verify --message-file msg.txt --signature 0x... \
  --domain example.com --nonce <nonce> \
  --rpc-url https://...                             # EIP-1271 / ERC-6492
onecipher sign-in nonce
```

Verification rules (both local and daemon paths): the original bytes are
hashed (never a re-serialization); `domain` + `nonce` binding is mandatory;
failures exit non-zero / return typed errors (`Invalid*` malformed,
`VerificationFailed` crypto-false, `Backend` transport).

## 3. Configuration (all optional, generic)

| Config key | Env | Default | Meaning |
|---|---|---|---|
| `wc.relay_url` | `OC_WC_RELAY_URL` | `wss://relay.walletconnect.com` | WC v2 relay |
| `wc.project_id` | `OC_WC_PROJECT_ID` | — | WalletConnect Cloud project id (required by public relay) |
| `wc.trusted_origins` | — | `[]` (deny all) | dApp origin allowlist for session proposals; `example.com` matches `app.example.com` (dot-boundary) |
| `wc.attestation` | `OC_WC_ATTESTATION` | — | relay Verify attestation JWT |

`trusted_origins` is **deny-by-default**: with an empty list every `wc_sessionPropose`
is rejected. Add the relying party's origin(s) before expecting it to connect:

```bash
onecipher config set wc.trusted_origins '["iam.example.com"]'
onecipher config set wc.relay_url 'wss://relay.walletconnect.com'
onecipher config set wc.project_id 'YOUR_PROJECT_ID'
```

## 4. Recommended Sign-in Flow for an IAM

1. **IAM** (web portal, acting as a WC dApp) generates a pairing URI and shows a
   QR / copyable string.
2. **User** pastes the URI into OneCipher (`onecipher wc connect <uri>`) or the
   OneCipher WebUI "Connect dApp" page; the daemon validates the dApp origin against
   `wc.trusted_origins` and settles the session.
3. **IAM** issues a single-use nonce (bound to its auth session) and assembles an
   EIP-4361 message (`domain`/`uri` = its own origin).
4. **IAM** calls `onecipher_signAuth` (or `wc_authRequest`) with a chain-bound message.
   Direct/local `onecipher_signAuth` calls include `auth`; `wc_authRequest` is
   authorized by the daemon's internal token path.
5. **OneCipher WebUI** displays the human-readable message (parsed EIP-4361 fields:
   domain, URI, nonce, expiry, statement — or the structured CAIP-122 summary
   with the sign-in domain highlighted for `solana_signIn`); the user approves;
   policy is evaluated; the signature is returned over the relay.
6. **IAM** verifies the signature (EVM: `ecrecover(keccak256("\x19Ethereum Signed
   Message:\n" + len + message), v, r, s)`; Ed25519 chains: verify with the stored
   public key), matches it to a bound address, and issues its own tokens.

Security notes for the IAM:

- The nonce MUST be single-use, short-TTL, and bound to the auth session / user.
- The signed message MUST include the nonce and the IAM's domain/URI; verify both.
- Bind addresses to accounts only after signature verification (store
  `chain_id + address (+ public_key for Ed25519)` — never the private key).
- Use different `URI` paths (e.g. `/wallet/bind` vs `/`) or distinct statements to
  separate "bind" and "login" purposes and prevent confusion attacks.

## 5. Reference Implementation

See the `longcipher-account` project (`docs/wallet-integration.md`) for a complete
OIDC-IAM integration that consumes `onecipher_signAuth`: challenge issuance, signature
verification, credential binding (`CredentialType::Wallet`), realm-level enablement,
and the portal-side dApp flow — all built on the standard methods defined here.
It is one example of a relying party; any OIDC/OAuth IAM can apply the same pattern.
