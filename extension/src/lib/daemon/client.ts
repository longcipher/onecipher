// OCWP daemon client — thin JSON-RPC 2.0 wrapper over loopback HTTP
// (design §4.7). The client never retries non-idempotent methods and
// normalizes every failure to the shared `RpcErrorShape`.

import {
  CODE_DISCONNECTED,
  CODE_UNAUTHORIZED,
  CODE_UNSUPPORTED,
  DAEMON_DEFAULT_URL,
  DAEMON_TIMEOUT_MS,
  OCWP_PROTOCOL_VERSION,
  rpcError,
  type ChainEntry,
  type OcAccount,
  type PolicyPreview,
  type RpcErrorShape,
  type SiteEntry,
} from '../protocol';

export interface HelloResult {
  protocol_version: number;
  daemon_version: string;
  chains: ChainEntry[];
  features: string[];
  extension_ids: string[];
}

export interface UnlockResult {
  session_id: string;
  wallet_id: string;
  index: number;
  expires_at_unix: number;
  accounts: OcAccount[];
}

export interface SessionStatus {
  unlocked: boolean;
  wallet_id?: string;
  expires_at_unix?: number;
}

export interface SignMessageResult {
  signature: string;
  public_key: string;
  recovery_id?: number | null;
}

export interface TransactionResult {
  raw_transaction?: string;
  tx_hash?: string;
  recovery_id?: number | null;
}

export interface PasskeyChallenge {
  challenge_hex: string;
  rp_id: string;
  timeout_ms: number;
}

/// A passkey step-up proof over a daemon-issued challenge (design §3.5).
/// The daemon binds the challenge to the session that requested it and
/// consumes it on first use.
export interface PasskeyProof {
  challenge_hex: string;
  signature_hex: string;
  credential_id: string;
}

/// Validate that a daemon URL is loopback-only (INV-9, R12c alignment).
export function validateLoopbackUrl(rawUrl: string): string {
  let url: URL;
  try {
    url = new URL(rawUrl.trim());
  } catch {
    throw rpcError(-32602, 'daemon URL is not a valid URL');
  }
  if (url.protocol !== 'http:') {
    throw rpcError(-32602, 'daemon URL must use http:// on loopback');
  }
  const host = url.hostname.replace(/^\[|\]$/g, '');
  if (host !== '127.0.0.1' && host !== 'localhost' && host !== '::1') {
    throw rpcError(-32602, 'daemon URL must be loopback (127.0.0.1 / localhost)');
  }
  const port = url.port === '' ? '80' : url.port;
  return `http://${host}:${port}`;
}

export class OcwpClient {
  readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  /// Version negotiated by the last successful `oc_hello` (design §3.3).
  /// `null` until the handshake happens; once known, a daemon that reports a
  /// different version is rejected before any state-changing call is sent.
  private negotiatedVersion: number | null = null;

  constructor(baseUrl: string = DAEMON_DEFAULT_URL, fetchImpl: typeof fetch = fetch) {
    this.baseUrl = validateLoopbackUrl(baseUrl);
    // `fetch` must stay bound to its global or the worker throws
    // "Illegal invocation" when it is invoked as `this.fetchImpl(...)`.
    this.fetchImpl = fetchImpl.bind(globalThis);
  }

  /// POST one JSON-RPC 2.0 request; binary fields are base64 STANDARD.
  async call<T = unknown>(method: string, params: Record<string, unknown> = {}): Promise<T> {
    // §3.3: a client/server version mismatch MUST be rejected with 4200 and a
    // `data.protocol_version` hint. Checking only inside `hello()` left every
    // later call free to speak a dialect the daemon never agreed to.
    if (method !== 'oc_hello' && this.negotiatedVersion !== null) {
      if (this.negotiatedVersion !== OCWP_PROTOCOL_VERSION) {
        throw rpcError(CODE_UNSUPPORTED, 'client and daemon speak different OCWP versions', {
          protocol_version: this.negotiatedVersion,
        });
      }
    }
    let response: Response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}/`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
        signal: AbortSignal.timeout(DAEMON_TIMEOUT_MS),
      });
    } catch (error) {
      throw rpcError(
        CODE_DISCONNECTED,
        `daemon unreachable at ${this.baseUrl}: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
    let payload: {
      result?: T;
      error?: { code?: number; message?: string; data?: unknown };
    };
    try {
      payload = await response.json();
    } catch {
      throw rpcError(-32603, 'daemon returned malformed JSON');
    }
    if (payload.error) {
      throw rpcError(
        payload.error.code ?? -32000,
        payload.error.message ?? 'daemon error',
        payload.error.data,
      );
    }
    return payload.result as T;
  }

  // -- session and handshake ------------------------------------------------

  async hello(): Promise<HelloResult> {
    const result = await this.call<HelloResult>('oc_hello');
    if (result.protocol_version !== OCWP_PROTOCOL_VERSION) {
      // Record the daemon's version so every later call refuses up front
      // rather than discovering the mismatch mid-consent.
      this.negotiatedVersion = result.protocol_version;
      throw rpcError(CODE_UNSUPPORTED, 'daemon speaks a different OCWP version', {
        protocol_version: result.protocol_version,
      });
    }
    this.negotiatedVersion = result.protocol_version;
    return result;
  }

  async unlock(
    wallet: string,
    passphrase: string,
    policies?: string[],
    index?: number,
  ): Promise<UnlockResult> {
    return this.call<UnlockResult>('oc_unlock', { wallet, passphrase, policies, index });
  }

  async lock(sessionId: string): Promise<void> {
    await this.call('oc_lock', { session_id: sessionId });
  }

  async sessionStatus(sessionId: string): Promise<SessionStatus> {
    return this.call<SessionStatus>('oc_session_status', { session_id: sessionId });
  }

  async accounts(sessionId: string): Promise<{ accounts: OcAccount[] }> {
    return this.call('oc_accounts', { session_id: sessionId });
  }

  // -- sites and chains ------------------------------------------------------

  async connectSite(sessionId: string, origin: string, accountId: string, chainId: string): Promise<void> {
    await this.call('oc_connect_site', { session_id: sessionId, origin, account_id: accountId, chain_id: chainId });
  }

  async revokeSite(sessionId: string, origin: string): Promise<{ revoked: boolean }> {
    return this.call('oc_revoke_site', { session_id: sessionId, origin });
  }

  async listSites(sessionId: string): Promise<{ sites: SiteEntry[] }> {
    return this.call('oc_list_sites', { session_id: sessionId });
  }

  async chainRegistry(sessionId: string): Promise<{ chains: ChainEntry[] }> {
    return this.call('oc_chain_registry', { session_id: sessionId });
  }

  async addCustomChain(sessionId: string, chain: Partial<ChainEntry> & { chain_id: string; name: string }): Promise<ChainEntry> {
    return this.call('oc_add_custom_chain', { session_id: sessionId, chain });
  }

  // -- signing (consent + policy upstream) -----------------------------------

  async signTransaction(
    sessionId: string,
    accountId: string,
    transaction: Record<string, unknown>,
    passkey?: PasskeyProof,
  ): Promise<TransactionResult> {
    return this.call('oc_sign_transaction', { session_id: sessionId, account_id: accountId, transaction, passkey });
  }

  async sendTransaction(
    sessionId: string,
    accountId: string,
    transaction: Record<string, unknown>,
    passkey?: PasskeyProof,
  ): Promise<TransactionResult> {
    return this.call('oc_send_transaction', { session_id: sessionId, account_id: accountId, transaction, passkey });
  }

  async signMessage(
    sessionId: string,
    accountId: string,
    messageB64: string,
    passkey?: PasskeyProof,
  ): Promise<SignMessageResult> {
    return this.call('oc_sign_message', { session_id: sessionId, account_id: accountId, message: messageB64, encoding: 'hex', passkey });
  }

  async signTypedData(
    sessionId: string,
    accountId: string,
    typedData: unknown,
    passkey?: PasskeyProof,
  ): Promise<SignMessageResult> {
    return this.call('oc_sign_typed_data', { session_id: sessionId, account_id: accountId, typed_data: typedData, passkey });
  }

  async signAuthorization(
    sessionId: string,
    accountId: string,
    address: string,
    nonce: string,
    passkey?: PasskeyProof,
  ): Promise<{ signature: string; recovery_id?: number | null }> {
    return this.call('oc_sign_authorization', {
      session_id: sessionId,
      account_id: accountId,
      address,
      nonce,
      passkey,
    });
  }

  // -- read proxy and simulation ----------------------------------------------

  async rpc(
    sessionId: string,
    origin: string,
    chainId: string,
    method: string,
    params: unknown[],
    passkey?: PasskeyProof,
  ): Promise<unknown> {
    const wrapped = await this.call<{ result: unknown }>('oc_rpc', {
      session_id: sessionId,
      origin,
      chain_id: chainId,
      method,
      params,
      passkey,
    });
    return wrapped.result;
  }

  async simulate(
    sessionId: string,
    accountId: string,
    transaction: Record<string, unknown>,
    from: string,
  ): Promise<{ ok: boolean; gas_used?: unknown; revert_reason?: string }> {
    return this.call('oc_simulate', { session_id: sessionId, account_id: accountId, transaction, from });
  }

  async policyPreview(sessionId: string, request: Record<string, unknown>): Promise<PolicyPreview> {
    return this.call<PolicyPreview>('oc_policy_preview', { session_id: sessionId, ...request });
  }

  async auditTail(sessionId: string, limit = 50): Promise<{ events: unknown[] }> {
    return this.call('oc_audit_tail', { session_id: sessionId, limit });
  }

  // -- passkey step-up (design §3.5 / §6.7) ------------------------------------

  async passkeyChallenge(sessionId: string, credentialId: string): Promise<PasskeyChallenge> {
    return this.call('oc_passkey_challenge', { session_id: sessionId, credential_id: credentialId });
  }

  async passkeyRegister(
    sessionId: string,
    credentialId: string,
    algorithm: 'p256' | 'ed25519',
    publicKeyB64: string,
    rpId?: string,
  ): Promise<{ registered: boolean; wallet_id: string }> {
    return this.call('oc_passkey_register', {
      session_id: sessionId,
      credential_id: credentialId,
      algorithm,
      public_key: publicKeyB64,
      rp_id: rpId,
    });
  }
}

/// Is this error the passkey step-up demand (4100 + require_passkey)?
export function requiresPasskey(error: unknown): boolean {
  const shape = error as RpcErrorShape | undefined;
  return (
    shape !== null &&
    typeof shape === 'object' &&
    shape.code === CODE_UNAUTHORIZED &&
    (shape.data as { require_passkey?: boolean } | undefined)?.require_passkey === true
  );
}
