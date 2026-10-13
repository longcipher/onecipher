// Background router — the testable core of the service worker
// (design §4.3/§4.4). All browser globals are injected via `RouterContext`
// so the routing/sender/consent invariants are unit-testable with FakeBrowser
// or plain stubs.

import {
  CODE_UNSUPPORTED,
  CODE_USER_REJECTED,
  rpcError,
  type OcAccount,
  type PopupMethod,
  type PopupState,
  type ConsentAssessment,
  type PendingActionView,
  type PolicyPreview,
  type ProviderEvent,
  type RpcErrorShape,
  type SimulationSummary,
} from '../protocol';
import { toRpcError } from '../consent/queue';
import type { ConsentQueue } from '../consent/queue';
import { providerOrigin, requirePopupSender, type SenderLike } from '../request-policy';
import type { OcwpClient } from '../daemon/client';
import type { ExtensionConfig } from '../storage/config';
import type { SessionHandle as StoredSession } from '../protocol';
import { buildConnectView, buildMessageView, buildTransactionView, buildTypedDataView } from '../consent/decode';
import { hexChainId, normalizeChainReference, normalizeEvmTx } from '../evm-tx';
import { generatePasskey, registerPasskey, signPasskeyChallenge } from '../passkey';
import { requiresPasskey } from '../daemon/client';

/// Persisted-config + sites + session stores, abstracted for tests.
export interface RouterStores {
  config: {
    load(): Promise<ExtensionConfig>;
    save(config: ExtensionConfig): Promise<void>;
  };
  sites: {
    isAuthorized(origin: string): Promise<boolean>;
    /// Chain this origin last selected (per-site chain binding, §4.3/§4.10).
    chainFor(origin: string): Promise<string | null>;
    /// Record a `wallet_switchEthereumChain` for this origin.
    setChain(origin: string, chainId: string): Promise<void>;
    upsert(origin: string, accountId: string, chainId: string): Promise<void>;
    remove(origin: string): Promise<void>;
    list(): Promise<Array<{ origin: string; account_id: string; chain_id: string; connected_at: number; last_seen_at: number }>>;
  };
  session: {
    load(): Promise<StoredSession | null>;
    save(handle: StoredSession): Promise<void>;
    clear(): Promise<void>;
  };
  passkey: {
    load(): Promise<{ credentialId: string; jwk: JsonWebKey } | null>;
    save(material: { credentialId: string; jwk: JsonWebKey }): Promise<void>;
  };
}

/// Browser-facing side effects, injected for testability.
export interface RouterEnv {
  broadcast(event: ProviderEvent, data: unknown): Promise<void>;
  openNotification(): Promise<void>;
  closeNotification(): Promise<void>;
}

export interface RouterContext {
  extensionId: string;
  popupUrl: string;
  daemon: OcwpClient;
  queue: ConsentQueue;
  stores: RouterStores;
  env: RouterEnv;
  /// Replace the daemon client after the user changes the URL.
  setDaemon(client: OcwpClient): void;
}

export type RuntimeRequest = { type: 'oc:request'; id: string; method: string; params?: unknown } | {
  type: 'popup:request';
  method: PopupMethod;
  params?: Record<string, unknown>;
};

// ---------------------------------------------------------------------------
// Provider (dApp) request handling
// ---------------------------------------------------------------------------

const RPC_PROXY_METHODS = new Set([
  'eth_call', 'eth_estimateGas', 'eth_getBalance', 'eth_getTransactionCount',
  'eth_gasPrice', 'eth_maxPriorityFeePerGas', 'eth_getTransactionReceipt', 'eth_getCode',
  'eth_blockNumber',
]);

function requireObject(value: unknown, what: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object') throw rpcError(-32602, `${what} must be an object`);
  return value as Record<string, unknown>;
}

function requireStringArray(value: unknown, what: string): string[] {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== 'string')) {
    throw rpcError(-32602, `${what} must be an array of strings`);
  }
  return value as string[];
}

/// The chain this origin operates on: its own binding if it has one,
/// otherwise the wallet default. Per-site resolution is what stops one dApp's
/// `wallet_switchEthereumChain` from moving another dApp's chain (D-6).
async function siteChainId(ctx: RouterContext, origin: string): Promise<string> {
  const perSite = await ctx.stores.sites.chainFor(origin);
  if (perSite !== null) return perSite;
  const config = await ctx.stores.config.load();
  return config.activeChainId;
}

/// EVM accounts only. v1 is an EVM wallet (design §1.2); handing a dApp a
/// Solana address in an `eth_*` result is both a protocol violation and an
/// unnecessary disclosure of accounts the site was never granted (D-5).
async function sessionEvmAccounts(ctx: RouterContext, session: StoredSession | null): Promise<OcAccount[]> {
  if (!session) return [];
  const { accounts } = await ctx.daemon.accounts(session.sessionId);
  return accounts.filter((account) => account.chain_id.startsWith('eip155:'));
}

/// Build the human-readable consent view + OCWP request for a provider method.
///
/// `accountId` is the account the request will be executed with. For
/// transactions it is bound to the *transaction's* chain, not the site's or
/// the wallet's, so a dApp that explicitly asks for chain X is never silently
/// served a transaction for chain Y (D-1).
async function buildConsent(
  ctx: RouterContext,
  origin: string,
  method: string,
  params: unknown[],
): Promise<{ kind: import('../protocol').ConsentKind; view: import('../protocol').ConsentView; ocwp: { method: string; params: Record<string, unknown> } } | null> {
  const siteChain = await siteChainId(ctx, origin);
  switch (method) {
    case 'eth_requestAccounts': {
      return {
        kind: 'connect',
        view: buildConnectView(origin, siteChain),
        ocwp: { method: 'oc_connect_site', params: { origin, account_id: siteChain, chain_id: siteChain } },
      };
    }
    case 'personal_sign':
    case 'eth_sign': {
      const message = params[0];
      if (typeof message !== 'string') throw rpcError(-32602, 'personal_sign expects a hex message');
      const clean = message.startsWith('0x') ? message.slice(2) : message;
      if (!/^[0-9a-fA-F]*$/.test(clean) || clean.length % 2 !== 0) {
        throw rpcError(-32602, 'personal_sign message must be hex');
      }
      const b64 = btoa(String.fromCharCode(...(clean.match(/.{2}/g) ?? []).map((byte) => Number.parseInt(byte, 16))));
      return {
        kind: 'sign_message',
        view: buildMessageView(b64, 'hex'),
        ocwp: { method: 'oc_sign_message', params: { account_id: siteChain, message: b64, encoding: 'hex' } },
      };
    }
    case 'eth_signTypedData':
    case 'eth_signTypedData_v3':
    case 'eth_signTypedData_v4': {
      const raw = params[0] ?? params[1];
      if (typeof raw !== 'string') throw rpcError(-32602, 'signTypedData expects a JSON string');
      let typedData: Record<string, unknown>;
      try {
        typedData = requireObject(JSON.parse(raw), 'typed data');
      } catch {
        throw rpcError(-32602, 'signTypedData payload is not valid JSON');
      }
      return {
        kind: 'sign_typed_data',
        view: buildTypedDataView(typedData),
        ocwp: { method: 'oc_sign_typed_data', params: { account_id: siteChain, typed_data: typedData } },
      };
    }
    case 'eth_signTransaction':
    case 'eth_sendTransaction': {
      const tx = requireObject(params[0], 'transaction');
      const kind = method === 'eth_sendTransaction' ? 'send_transaction' as const : 'sign_transaction' as const;
      // Normalize first: this maps every EIP-1193 field the daemon needs and
      // reports the chain the transaction will actually be signed on (D-1/D-2).
      const normalized = normalizeEvmTx(tx, siteChain);
      return {
        kind,
        view: buildTransactionView(kind, normalized.transaction, normalized.chainId, normalized.delegations),
        ocwp: {
          method: kind === 'send_transaction' ? 'oc_send_transaction' : 'oc_sign_transaction',
          params: { account_id: normalized.chainId, transaction: normalized.transaction },
        },
      };
    }
    default:
      return null;
  }
}

/// Handle a dApp request arriving from a content script. Returns the
/// JSON-RPC-style `{ result }` / `{ error }` envelope relayed to the page.
export async function handleProviderRequest(
  ctx: RouterContext,
  message: { id: string; method: string; params?: unknown },
  sender: SenderLike,
): Promise<{ result?: unknown; error?: RpcErrorShape }> {
  let origin: string;
  try {
    origin = providerOrigin(sender, ctx.extensionId).origin;
  } catch (error) {
    return { error: toRpcError(error) };
  }
  try {
    const params = Array.isArray(message.params) ? message.params : [];
    const method = message.method;

    // --- Local (no daemon) methods ------------------------------------------
    if (method === 'eth_chainId' || method === 'net_version') {
      // Per-site: each origin sees the chain it selected, so a dApp's chain
      // switch never leaks into another dApp's view (D-6).
      const chain = await siteChainId(ctx, origin);
      return { result: method === 'eth_chainId' ? hexChainId(chain) : chain.slice('eip155:'.length) };
    }
    if (method === 'wallet_switchEthereumChain') {
      const target = requireObject(params[0], 'chain')['chainId'];
      if (typeof target !== 'string' || !/^0x[0-9a-fA-F]+$/.test(target)) {
        throw rpcError(-32602, 'chainId must be a hex quantity');
      }
      const chain = normalizeChainReference(target);
      if (await ctx.stores.sites.isAuthorized(origin)) {
        // Connected site: the switch is this origin's business alone.
        await ctx.stores.sites.setChain(origin, chain);
      } else {
        // Not yet connected — record it as the wallet default so the upcoming
        // connect prompt reflects the chain the dApp asked for.
        const config = await ctx.stores.config.load();
        config.activeChainId = chain;
        await ctx.stores.config.save(config);
      }
      await ctx.env.broadcast('chainChanged', target);
      return { result: null };
    }
    if (method === 'wallet_addEthereumChain') {
      const chain = requireObject(params[0], 'chain');
      const chainIdHex = chain['chainId'];
      const rpcUrls = requireStringArray(chain['rpcUrls'] ?? [], 'rpcUrls');
      if (typeof chainIdHex !== 'string') throw rpcError(-32602, 'chainId is required');
      const chainId = `eip155:${BigInt(chainIdHex).toString(10)}`;
      const rpcUrl = rpcUrls[0];
      if (!rpcUrl || !(rpcUrl.startsWith('https://') || rpcUrl.startsWith('http://127.0.0.1') || rpcUrl.startsWith('http://localhost'))) {
        throw rpcError(-32602, 'a valid https:// rpcUrls[0] is required');
      }
      const config = await ctx.stores.config.load();
      config.customChains = [
        ...config.customChains.filter((entry) => entry.chain_id !== chainId),
        {
          chain_id: chainId,
          name: typeof chain['chainName'] === 'string' ? chain['chainName'] : chainId,
          rpc_url: rpcUrl,
          explorer_url: Array.isArray(chain['blockExplorerUrls']) && typeof chain['blockExplorerUrls'][0] === 'string'
            ? chain['blockExplorerUrls'][0]
            : undefined,
          native_currency: 'ETH',
          is_evm: true,
          builtin: false,
        },
      ];
      await ctx.stores.config.save(config);
      return { result: null };
    }
    if (method === 'wallet_watchAsset') {
      // v1: accept silently (asset display bookkeeping is UI-only).
      return { result: true };
    }

    const session = await ctx.stores.session.load();
    const unlocked = session !== null && (await isSessionFresh(ctx, session));

    if (method === 'eth_requestAccounts') {
      // F11: an authorized site with a fresh session connects silently.
      if (unlocked && (await ctx.stores.sites.isAuthorized(origin))) {
        const accounts = await sessionEvmAccounts(ctx, session);
        return { result: accounts.map((account) => account.address) };
      }
      const consent = await buildConsent(ctx, origin, method, params);
      if (!consent) throw rpcError(CODE_UNSUPPORTED, `method not supported: ${method}`);
      const accounts = await ctx.queue.enqueue({ ...consent, origin });
      return { result: accounts };
    }
    if (method === 'eth_accounts') {
      if (unlocked && (await ctx.stores.sites.isAuthorized(origin))) {
        const accounts = await sessionEvmAccounts(ctx, session);
        return { result: accounts.map((account) => account.address) };
      }
      return { result: [] };
    }

    // --- Sign/send: consent ALWAYS required (INV-2/INV-10) -------------------
    if (!unlocked) throw rpcError(4100, 'Wallet is locked');

    const consent = await buildConsent(ctx, origin, method, params);
    if (consent) {
      const result = await ctx.queue.enqueue({ ...consent, origin });
      return { result };
    }

    // --- Read-only proxy ------------------------------------------------------
    if (RPC_PROXY_METHODS.has(method)) {
      if (!session) throw rpcError(4100, 'Wallet is locked');
      const chainId = await siteChainId(ctx, origin);
      const result = await withPasskeyStepUp(ctx, session, (passkey) =>
        ctx.daemon.rpc(session.sessionId, origin, chainId, method, params, passkey),
      );
      return { result };
    }

    throw rpcError(CODE_UNSUPPORTED, `method not supported: ${method}`);
  } catch (error) {
    return { error: toRpcError(error) };
  }
}

// ---------------------------------------------------------------------------
// Consent executor (approval-time pipeline)
// ---------------------------------------------------------------------------

async function isSessionFresh(ctx: RouterContext, session: StoredSession): Promise<boolean> {
  try {
    const status = await ctx.daemon.sessionStatus(session.sessionId);
    return status.unlocked === true;
  } catch {
    return false;
  }
}

/// Best-effort account list for UI snapshots: a daemon hiccup renders an
/// empty list rather than breaking the popup. Never used on a signing path.
async function trySessionEvmAccounts(
  ctx: RouterContext,
  session: StoredSession | null,
): Promise<OcAccount[]> {
  if (!session) return [];
  try {
    return await sessionEvmAccounts(ctx, session);
  } catch {
    return [];
  }
}

function evmAccount(accounts: OcAccount[]): OcAccount {
  const evm = accounts.find((account) => account.chain_id.startsWith('eip155:'));
  if (!evm) throw rpcError(-32603, 'wallet has no EVM account');
  return evm;
}

/// A step-up proof over a daemon-issued challenge.
export type PasskeyProof = {
  challenge_hex: string;
  signature_hex: string;
  credential_id: string;
};

/// Run a daemon call; on `require_passkey` demand, sign a fresh challenge
/// with the registered software passkey and retry once.
///
/// The proof is threaded into the retry by the *callable*, not by a closure
/// that quietly drops it — a retry that re-sends the identical request without
/// the proof just earns the same `4100` and the user is stuck (D-10).
async function withPasskeyStepUp<T>(
  ctx: RouterContext,
  session: StoredSession,
  call: (passkey?: PasskeyProof) => Promise<T>,
): Promise<T> {
  try {
    return await call();
  } catch (error) {
    if (!requiresPasskey(error)) throw error;
    const material = await ctx.stores.passkey.load();
    if (!material) throw rpcError(4100, 'passkey confirmation required — register a passkey in settings');
    const challenge = await ctx.daemon.passkeyChallenge(session.sessionId, material.credentialId);
    const signatureHex = await signPasskeyChallenge(material, challenge.challenge_hex);
    return await call({
      challenge_hex: challenge.challenge_hex,
      signature_hex: signatureHex,
      credential_id: material.credentialId,
    });
  }
}

export function createConsentExecutor(ctx: RouterContext): import('../consent/queue').ConsentExecutor {
  return {
    async validate(action: PendingActionView): Promise<void> {
      const session = await ctx.stores.session.load();
      if (!session || !(await isSessionFresh(ctx, session))) {
        throw rpcError(4100, 'Wallet is locked — unlock to continue');
      }
      if (action.kind !== 'connect' && !(await ctx.stores.sites.isAuthorized(action.origin))) {
        // F7/INV-4: revocation during the pending window invalidates approval.
        throw rpcError(4100, 'Origin authorization was revoked');
      }
    },
    async assess(action: PendingActionView): Promise<ConsentAssessment> {
      const session = await ctx.stores.session.load();
      if (!session) return { policy: null, simulation: null };
      const { method, params } = action.ocwp;
      const chainId = String(params['account_id'] ?? '');

      // Policy preview. Sent in the documented flat shape (§5.2) so the
      // daemon projects the same fields it enforces — a nested-only payload
      // would silently evaluate an empty request and always allow (D-3).
      let policy: PolicyPreview | null = null;
      try {
        const request: Record<string, unknown> = { chain_id: chainId };
        if (method === 'oc_send_transaction' || method === 'oc_sign_transaction') {
          const transaction = (params['transaction'] ?? {}) as Record<string, unknown>;
          request['transaction'] = transaction;
          if (typeof transaction['to'] === 'string') request['to'] = transaction['to'];
          if (typeof transaction['value'] === 'string') request['value'] = transaction['value'];
          if (typeof transaction['data'] === 'string') request['data'] = transaction['data'];
        } else if (method === 'oc_sign_typed_data') {
          request['typed_data'] = params['typed_data'] ?? {};
        }
        policy = await ctx.daemon.policyPreview(session.sessionId, request);
      } catch {
        policy = null; // advisory only; the daemon enforces on the real path
      }

      // Simulation (design §4.8): only meaningful for a transaction send.
      let simulation: SimulationSummary | null = null;
      if (method === 'oc_send_transaction') {
        const accounts = await sessionEvmAccounts(ctx, session);
        const evm = evmAccount(accounts);
        try {
          const result = await ctx.daemon.simulate(
            session.sessionId,
            chainId,
            (params['transaction'] ?? {}) as Record<string, unknown>,
            evm.address,
          );
          simulation = {
            ok: result.ok === true,
            gasUsed: typeof result.gas_used === 'string' ? result.gas_used : undefined,
            revertReason: result.revert_reason,
          };
        } catch {
          simulation = null;
        }
      }
      return { policy, simulation };
    },
    async execute(action: PendingActionView): Promise<unknown> {
      const session = await ctx.stores.session.load();
      if (!session) throw rpcError(4100, 'Wallet is locked');
      const { method, params } = action.ocwp;
      const accounts = await sessionEvmAccounts(ctx, session);
      const evm = evmAccount(accounts);
      if (method === 'oc_connect_site') {
        await ctx.daemon.connectSite(
          session.sessionId,
          String(params['origin']),
          String(params['account_id']),
          String(params['chain_id']),
        );
        await ctx.stores.sites.upsert(
          String(params['origin']),
          String(params['account_id']),
          String(params['chain_id']),
        );
        const addresses = accounts.map((account) => account.address);
        await ctx.env.broadcast('accountsChanged', addresses);
        return addresses;
      }
      if (method === 'oc_sign_message') {
        const result = await withPasskeyStepUp(ctx, session, (passkey) =>
          ctx.daemon.signMessage(session.sessionId, String(params['account_id']), String(params['message']), passkey),
        );
        // EIP-1193/EIP-191: the dApp gets the signature string, not an object.
        // Returning a wrapper breaks every consumer (D-4).
        return result.signature;
      }
      if (method === 'oc_sign_typed_data') {
        const result = await ctx.daemon.signTypedData(
          session.sessionId,
          String(params['account_id']),
          params['typed_data'],
        );
        return result.signature;
      }
      if (method === 'oc_sign_transaction' || method === 'oc_send_transaction') {
        const transaction = params['transaction'] as Record<string, unknown>;
        const result =
          method === 'oc_send_transaction'
            ? await ctx.daemon.sendTransaction(session.sessionId, String(params['account_id']), transaction)
            : await ctx.daemon.signTransaction(session.sessionId, String(params['account_id']), transaction);
        if (method === 'oc_send_transaction') return result.tx_hash ?? null;
        return result.raw_transaction ?? null;
      }
      throw rpcError(CODE_UNSUPPORTED, `consent executor: unsupported ${method}`);
    },
  };
}

// ---------------------------------------------------------------------------
// Popup request handling
// ---------------------------------------------------------------------------

export async function handlePopupRequest(
  ctx: RouterContext,
  message: { method: PopupMethod; params?: Record<string, unknown> },
  sender: SenderLike,
): Promise<unknown> {
  requirePopupSender(sender, ctx.extensionId, ctx.popupUrl);
  const params = message.params ?? {};
  switch (message.method) {
    case 'popup_getState': {
      const session = await ctx.stores.session.load();
      const unlocked = session !== null && (await isSessionFresh(ctx, session));
      const accounts = unlocked ? await trySessionEvmAccounts(ctx, session) : [];
      const config = await ctx.stores.config.load();
      let hello: { protocol_version: number } | null = null;
      let daemonError = '';
      try {
        hello = await ctx.daemon.hello();
      } catch (error) {
        hello = null;
        daemonError =
          error instanceof Error
            ? error.message
            : ((error as { message?: string }).message ?? String(error));
      }
      const state: PopupState = {
        daemonReachable: hello !== null,
        daemonError,
        protocolVersion: hello?.protocol_version,
        session: unlocked ? { sessionId: session.sessionId, walletId: session.walletId, wallet: session.wallet, expiresAtUnix: session.expiresAtUnix } : null,
        accounts,
        activeChainId: config.activeChainId,
        sites: await ctx.stores.sites.list(),
        pendingActions: ctx.queue.list(),
      };
      return state;
    }
    case 'popup_unlock': {
      const wallet = String(params['wallet'] ?? 'default');
      const passphrase = String(params['passphrase'] ?? '');
      const unlocked = await ctx.daemon.unlock(wallet, passphrase);
      await ctx.stores.session.save({
        sessionId: unlocked.session_id,
        walletId: unlocked.wallet_id,
        wallet,
        expiresAtUnix: unlocked.expires_at_unix,
      });
      return {
        sessionId: unlocked.session_id,
        accounts: unlocked.accounts,
        expiresAtUnix: unlocked.expires_at_unix,
      };
    }
    case 'popup_lock': {
      const session = await ctx.stores.session.load();
      if (session) {
        try {
          await ctx.daemon.lock(session.sessionId);
        } catch {
          // Session may already be gone; clearing the local handle is enough.
        }
      }
      await ctx.stores.session.clear();
      // Revoke every site: locking the wallet must end every dApp session,
      // not just the local handle. Then tell the sites themselves.
      for (const site of await ctx.stores.sites.list()) {
        await ctx.stores.sites.remove(site.origin);
      }
      await ctx.env.broadcast('accountsChanged', []);
      return null;
    }
    case 'popup_listActions': {
      return ctx.queue.list();
    }
    case 'popup_approveAction': {
      const id = String(params['id'] ?? '');
      if (!ctx.queue.get(id)) throw rpcError(CODE_USER_REJECTED, 'unknown or already-resolved action');
      await ctx.queue.approve(id);
      return null;
    }
    case 'popup_declineAction': {
      ctx.queue.decline(String(params['id'] ?? ''), params['reason'] as string | undefined);
      return null;
    }
    case 'popup_switchChain': {
      const chainId = normalizeChainReference(String(params['chainId'] ?? ''));
      // With an origin, this changes that site's binding; without one, it
      // moves the wallet default that unconnected origins fall back to.
      const origin = typeof params['origin'] === 'string' ? params['origin'] : null;
      if (origin !== null && (await ctx.stores.sites.isAuthorized(origin))) {
        await ctx.stores.sites.setChain(origin, chainId);
      } else {
        const config = await ctx.stores.config.load();
        config.activeChainId = chainId;
        await ctx.stores.config.save(config);
      }
      await ctx.env.broadcast('chainChanged', hexChainId(chainId));
      return chainId;
    }
    case 'popup_revokeSite': {
      const origin = String(params['origin'] ?? '');
      const session = await ctx.stores.session.load();
      if (session) {
        try {
          await ctx.daemon.revokeSite(session.sessionId, origin);
        } catch {
          // Local revocation still applies even if the daemon is unreachable.
        }
      }
      await ctx.stores.sites.remove(origin);
      return null;
    }
    case 'popup_setDaemonUrl': {
      const url = String(params['url'] ?? '');
      const config = await ctx.stores.config.load();
      config.daemonUrl = url;
      await ctx.stores.config.save(config);
      ctx.setDaemon(new (ctx.daemon.constructor as new (url: string) => OcwpClient)(url));
      return config.daemonUrl;
    }
    case 'popup_setCustomChain': {
      const session = await ctx.stores.session.load();
      if (!session) throw rpcError(4100, 'Wallet is locked');
      const chain = requireObject(params['chain'], 'chain');
      const saved = await ctx.daemon.addCustomChain(session.sessionId, {
        chain_id: String(chain['chain_id'] ?? ''),
        name: String(chain['name'] ?? ''),
        rpc_url: chain['rpc_url'] === undefined ? undefined : String(chain['rpc_url']),
        explorer_url: chain['explorer_url'] === undefined ? undefined : String(chain['explorer_url']),
        native_currency: String(chain['native_currency'] ?? 'ETH'),
      });
      const config = await ctx.stores.config.load();
      config.customChains = [
        ...config.customChains.filter((entry) => entry.chain_id !== saved.chain_id),
        saved,
      ];
      await ctx.stores.config.save(config);
      return saved;
    }
    case 'popup_activity': {
      const session = await ctx.stores.session.load();
      if (!session) throw rpcError(4100, 'Wallet is locked');
      return (await ctx.daemon.auditTail(session.sessionId, Number(params['limit'] ?? 50))).events;
    }
    case 'popup_registerPasskey': {
      const session = await ctx.stores.session.load();
      if (!session) throw rpcError(4100, 'Wallet is locked');
      const material = await generatePasskey();
      await registerPasskey(ctx.daemon, session.sessionId, material);
      await ctx.stores.passkey.save(material);
      return { registered: true, credentialId: material.credentialId };
    }
    default:
      throw rpcError(CODE_UNSUPPORTED, `popup method not supported: ${String(message.method)}`);
  }
}

/// Route any runtime message. Unknown envelopes fail closed (INV-7).
export async function handleRuntimeMessage(
  ctx: RouterContext,
  message: unknown,
  sender: SenderLike,
): Promise<{ result?: unknown; error?: RpcErrorShape } | unknown> {
  if (message === null || typeof message !== 'object') {
    return { error: rpcError(CODE_UNSUPPORTED, 'unsupported message') };
  }
  const envelope = message as Record<string, unknown>;
  if (envelope['type'] === 'oc:request') {
    const req = envelope as unknown as { id: string; method: string; params?: unknown };
    return handleProviderRequest(ctx, req, sender);
  }
  if (envelope['type'] === 'popup:request') {
    try {
      const result = await handlePopupRequest(
        ctx,
        envelope as unknown as { method: PopupMethod; params?: Record<string, unknown> },
        sender,
      );
      return result;
    } catch (error) {
      throw toRpcError(error);
    }
  }
  // Fail-closed: stale content scripts / other extensions get nothing.
  throw rpcError(CODE_UNSUPPORTED, 'unsupported message type');
}
