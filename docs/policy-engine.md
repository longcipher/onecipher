# Policy Engine

> How transaction policies are defined, evaluated, and enforced before any key material is touched.

## Access Model

```
sign_transaction(wallet, chain, tx, credential)
                                       │
                          ┌────────────┴────────────┐
                          │                          │
                     passphrase                 ows_key_...
                          │                          │
                     owner mode                 agent mode
                     no policy                  policies enforced
                     argon2id decrypt             HKDF decrypt
```

| Caller | Authentication | Policy Evaluation |
|---|---|---|
| **Owner** | Passphrase | **None.** Full access to all wallets. |
| **Agent** | `ows_key_...` token | **All policies attached to the API key** are evaluated. Every policy must allow (AND semantics). |

The credential itself determines the access tier. No bypass flags. The owner uses the passphrase; agents use tokens. Different agents get different tokens with different policies.

If the owner wants policy-constrained access for themselves, they create an API key and use the token instead of the passphrase.

## API Key Cryptography

### Token-as-capability

When the owner creates an API key, OneCipher decrypts the wallet secret using the owner's passphrase and **re-encrypts it under a key derived from the API token**. The encrypted copy is stored in the API key file. The agent presents the token with each signing request; the token serves as both authentication and decryption capability.

### Key derivation (HKDF-SHA256)

API tokens are 256-bit random values (`ows_key_<64 hex chars>`). HKDF-SHA256 derives the encryption key:

```
token = ows_key_<random 256 bits, hex-encoded>
salt  = random 32 bytes (stored in CryptoEnvelope)
prk   = HKDF-Extract(salt, token)
key   = HKDF-Expand(prk, "ows-api-key-v1", 32)  →  AES-256-GCM key
```

### Key creation flow

```bash
onecipher key create --name "claude-agent" --wallet agent-treasury --policy spending-limit
```

1. Owner enters wallet passphrase
2. OneCipher decrypts the wallet secret using argon2id(passphrase)
3. Generates random token: `T = "ows_key_" + hex(random 256 bits)`
4. Generates random salt S
5. Derives key: `K = HKDF-SHA256(S, T, "ows-api-key-v1", 32)`
6. Encrypts the wallet secret with K via AES-256-GCM
7. Stores key file with `token_hash: SHA256(T)`, policy IDs, and encrypted secret copy
8. Displays T once — owner provisions it to the agent
9. Zeroizes the decrypted secret from memory

### Agent signing flow

```
Agent calls: sign_transaction(wallet, chain, tx, "ows_key_a1b2c3...")

1. Detect ows_key_ prefix → agent mode
2. SHA256(token) → look up API key file
3. Check expires_at (if set)
4. Verify wallet is in key's wallet_ids scope
5. Load policies from key's policy_ids
6. Build PolicyContext (chain ID, wallet ID, API key ID, transaction context, spending context, timestamp)
7. Evaluate all policies (AND semantics, short-circuit on first deny)
8. If denied → return POLICY_DENIED error (key material never touched)
9. HKDF-SHA256(salt, token) → AES key → decrypt secret from key.wallet_secrets
10. Resolve the chain-specific signing key from that secret
11. Sign transaction
12. Zeroize decrypted secret and derived key
13. Return signature
```

### Revocation

Delete the API key file. The encrypted secret copy is gone. `SHA256(T)` matches nothing. The token is useless. The original wallet and other API keys are unaffected.

## Declarative Policy Rules

These rule types are evaluated in-process (microseconds, no subprocess).

### `allowed_chains`

Restricts which CAIP-2 chain IDs can be signed for.

```json
{ "type": "allowed_chains", "chain_ids": ["eip155:8453", "eip155:84532"] }
```

### `expires_at`

Time-bound access (compares `PolicyContext.timestamp` to this ISO-8601 string).

```json
{ "type": "expires_at", "timestamp": "2026-04-01T00:00:00Z" }
```

### `allowed_typed_data_contracts`

Restricts which smart contracts an API key can sign EIP-712 typed data for. The rule checks the `domain.verifyingContract` field against an allowlist of addresses.

```json
{
  "type": "allowed_typed_data_contracts",
  "contracts": ["0x000000000022D473030F116dDEE9F6B43aC78BA3"]
}
```

**Behavior:**
- For `sign_message` and `sign_transaction` calls, this rule **passes through**.
- For `sign_typed_data` calls where the domain includes a `verifyingContract`, the address must be in the `contracts` list (case-insensitive).
- For `sign_typed_data` calls where the domain **omits** `verifyingContract`, the rule **denies**.

## Custom Executable Policies

For anything declarative rules can't express — on-chain simulation, external API calls, complex business logic.

### Protocol

```
echo '<PolicyContext JSON>' | /path/to/policy-executable
```

- The executable receives the full `PolicyContext` as a single JSON object on stdin
- The executable MUST write a single `PolicyResult` JSON object to stdout
- A non-zero exit code is treated as a denial
- Stderr is captured and may be surfaced in denial details

### Evaluation order within a policy

When a policy has both `rules` (declarative) and `executable` (custom):

1. Declarative rules evaluate first (in-process, fast)
2. If declarative rules deny → skip executable (no subprocess spawned)
3. If declarative rules allow → spawn executable for final verdict
4. Both must allow

### Example: Value limit policy

```python
#!/usr/bin/env python3
"""Reject transactions exceeding 0.01 ETH."""
import json, sys
ctx = json.load(sys.stdin)
value = int(ctx["transaction"].get("value", "0"))
limit = 10_000_000_000_000_000  # 0.01 ETH
if value > limit:
    json.dump({"allow": False, "reason": "Value exceeds limit"}, sys.stdout)
else:
    json.dump({"allow": True}, sys.stdout)
```

Policy file:

```json
{
  "id": "value-limit",
  "name": "Max 0.01 ETH per transaction",
  "version": 1,
  "created_at": "2026-01-01T00:00:00Z",
  "rules": [{ "type": "allowed_chains", "chain_ids": ["eip155:8453"] }],
  "executable": "/home/user/.onecipher/plugins/policies/value-limit.py",
  "action": "deny"
}
```

### Example: Transaction simulation policy

```python
#!/usr/bin/env python3
"""Simulate transaction via eth_call before allowing."""
import json, sys, urllib.request

ctx = json.load(sys.stdin)
tx = ctx["transaction"]
rpc = {"eip155:8453": "https://mainnet.base.org"}.get(ctx["chain_id"])
if not rpc:
    json.dump({"allow": False, "reason": f"No RPC for {ctx['chain_id']}"}, sys.stdout)
    sys.exit(0)

payload = json.dumps({
    "jsonrpc": "2.0", "id": 1, "method": "eth_call",
    "params": [{"to": tx["to"], "value": hex(int(tx["value"])), "data": tx["data"]}, "latest"]
}).encode()
try:
    resp = json.load(urllib.request.urlopen(
        urllib.request.Request(rpc, data=payload, headers={"Content-Type": "application/json"}), timeout=4))
    if "error" in resp:
        json.dump({"allow": False, "reason": f"Reverted: {resp['error']['message']}"}, sys.stdout)
    else:
        json.dump({"allow": True}, sys.stdout)
except Exception as e:
    json.dump({"allow": False, "reason": str(e)}, sys.stdout)
```

## Policy File Format

Policies are JSON files stored in `~/.onecipher/policies/`:

```json
{
  "id": "base-agent-limits",
  "name": "Base Agent Safety Limits",
  "version": 1,
  "created_at": "2026-03-22T10:00:00Z",
  "rules": [
    { "type": "allowed_chains", "chain_ids": ["eip155:8453", "eip155:84532"] },
    { "type": "expires_at", "timestamp": "2026-12-31T23:59:59Z" }
  ],
  "executable": null,
  "config": null,
  "action": "deny"
}
```

| Field | Type | Required | Description |
|---|---|---|---|
| `id` | string | yes | Unique policy identifier |
| `name` | string | yes | Human-readable policy name |
| `version` | integer | yes | Policy schema version (currently `1`) |
| `created_at` | string | yes | ISO 8601 creation timestamp |
| `rules` | array | no | Declarative rules (see above) |
| `executable` | string | no | Absolute path to a custom policy executable |
| `config` | object | no | Static configuration passed to the executable via `PolicyContext.policy_config` |
| `action` | string | yes | Currently `"deny"` only |

A policy MUST have at least one of `rules` or `executable`.

## PolicyContext

The JSON object available to policy evaluation:

```json
{
  "chain_id": "eip155:8453",
  "wallet_id": "3198bc9c-6672-5ab3-d995-4942343ae5b6",
  "api_key_id": "7a2f1b3c-4d5e-6f7a-8b9c-0d1e2f3a4b5c",
  "transaction": {
    "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD0C",
    "value": "100000000000000000",
    "raw_hex": "0x02f8...",
    "data": "0x"
  },
  "spending": {
    "daily_total": "50000000000000000",
    "date": "2026-03-22"
  },
  "timestamp": "2026-03-22T10:35:22Z"
}
```

| Field | Type | Description |
|---|---|---|
| `chain_id` | string | CAIP-2 chain identifier |
| `wallet_id` | string | Wallet ID in scope |
| `api_key_id` | string | API key UUID |
| `transaction.to` | string | Recipient address (EVM) |
| `transaction.value` | string | Value in wei |
| `transaction.data` | string | Calldata hex |
| `transaction.raw_hex` | string | Raw unsigned transaction hex |
| `spending.daily_total` | string | Cumulative value signed today (wei) |
| `timestamp` | string | ISO-8601 signing request time |

### `typed_data` (optional)

Present only for `sign_typed_data` calls:

```json
{
  "typed_data": {
    "verifying_contract": "0x000000000022D473030F116dDEE9F6B43aC78BA3",
    "domain_chain_id": 8453,
    "primary_type": "PermitSingle",
    "domain_name": "Permit2",
    "domain_version": "1",
    "raw_json": "{...full EIP-712 JSON...}"
  }
}
```

## PolicyResult

```json
{ "allow": true }
```

```json
{ "allow": false, "reason": "Daily spending limit exceeded: 0.95 / 1.0 ETH" }
```

## Timeout and Failure Semantics

For custom executable policies only (declarative rules cannot fail):

| Scenario | Behavior |
|---|---|
| Executable exits with code 0, valid JSON on stdout | Use the `PolicyResult` as the verdict |
| Executable exits with non-zero code | **Deny.** Treat as `{ "allow": false }`. |
| Executable does not produce valid JSON on stdout | **Deny.** |
| Executable does not exit within 5 seconds | **Deny.** Kill the process. |
| Executable not found or not executable | **Deny.** |
| Unknown declarative rule type | **Deny.** Fail closed on unrecognized rules. |

The default-deny stance ensures that policy failures are never silently bypassed.

## Policy Attachment

Policies are attached to API keys, not wallets:

```bash
# Create a policy
onecipher policy create --file base-agent-limits.json

# Create an API key with wallet scope and policy attachment
onecipher key create --name "claude-agent" --wallet agent-treasury --policy base-agent-limits
# => ows_key_a1b2c3d4e5f6...  (shown once, store securely)
```

An API key can have multiple policies attached. All attached policies are evaluated — every policy must allow the transaction for it to proceed (AND semantics). Evaluation short-circuits on the first denial.

## Common Policy Patterns

### Time-limited access

```json
{ "type": "expires_at", "timestamp": "2026-12-31T23:59:59Z" }
```

### Chain restriction + expiry

```json
{
  "id": "base-limits",
  "name": "Base Agent Safety Limits",
  "version": 1,
  "created_at": "2026-01-01T00:00:00Z",
  "rules": [
    { "type": "allowed_chains", "chain_ids": ["eip155:8453", "eip155:84532"] },
    { "type": "expires_at", "timestamp": "2026-12-31T23:59:59Z" }
  ],
  "action": "deny"
}
```

### Multiple policies on one key (AND semantics)

```bash
onecipher key create --name "agent" --wallet treasury --policy base-limits --policy permit2-only
```

## CLI Management

```bash
onecipher policy list                    # list all policies
onecipher policy show --id base-limits   # show policy details
onecipher policy delete --id base-limits # delete a policy
onecipher key list                       # list all API keys
```

## References

- [ERC-4337 Session Keys](https://eips.ethereum.org/EIPS/eip-4337)
