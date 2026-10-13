// Shared protocol constants and wire types for the OneCipher Wallet extension.
//
// Three strictly-separated message envelopes (design §4.5, fail-closed):
//  - `oc:request`   content script → service worker (dApp requests)
//  - `popup:request` popup/notification pages → service worker
//  - `oc:event`     service worker → content scripts → page (provider events)
// Everything else is rejected by the router (INV-7).

/// postMessage channel page → content script (dApp → provider bridge).
export const OC_REQUEST_CHANNEL = 'onecipher-ocwp';
/// postMessage channel content script → page (responses).
export const OC_REPLY_CHANNEL = 'onecipher-ocwp-reply';
/// postMessage channel content script → page (provider events).
export const OC_EVENT_CHANNEL = 'onecipher-ocwp-event';

// EIP-6963 multi-provider discovery.
export const EIP6963_ANNOUNCE = 'eip6963:announceProvider';
export const EIP6963_REQUEST = 'eip6963:requestProvider';
export const EIP6963_RDNS = 'com.onecipher.wallet';
export const EIP6963_PROVIDER_NAME = 'OneCipher Wallet';
/// Legacy EIP-1193 announcement event.
export const ETHEREUM_INITIALIZED = 'ethereum#initialized';

/// OCWP protocol version implemented by this client (must match the daemon).
export const OCWP_PROTOCOL_VERSION = 1;
/// Default loopback daemon endpoint (matches `onecipher wallet-rpc serve`).
export const DAEMON_DEFAULT_URL = 'http://127.0.0.1:18080';
/// How long an unanswered consent request stays pending before expiry.
export const APPROVAL_TTL_MS = 300_000;
/// Connection/boot probe timeout for the daemon client.
export const DAEMON_TIMEOUT_MS = 10_000;

// ---------------------------------------------------------------------------
// OCWP error codes (mirror bin/oc-cli/src/commands/wallet_rpc/ocwp/errors.rs)
// ---------------------------------------------------------------------------

export const CODE_USER_REJECTED = 4001;
export const CODE_UNAUTHORIZED = 4100;
export const CODE_UNSUPPORTED = 4200;
export const CODE_POLICY_DENIED = 4300;
export const CODE_BUDGET_EXCEEDED = 4301;
export const CODE_RATE_LIMITED = 4302;
export const CODE_NOT_WHITELISTED = 4303;
export const CODE_EXPIRED = 4304;
export const CODE_POLICY_MISSING = 4305;
export const CODE_COOLDOWN = 4306;
export const CODE_DISCONNECTED = 4900;
export const CODE_CHAIN_NOT_CONNECTED = 4901;

/// Normalized JSON-RPC error shape shared across all layers.
export interface RpcErrorShape {
  code: number;
  message: string;
  data?: unknown;
}

export function rpcError(code: number, message: string, data?: unknown): RpcErrorShape {
  return data === undefined ? { code, message } : { code, message, data };
}

// ---------------------------------------------------------------------------
// Message envelopes
// ---------------------------------------------------------------------------

/// Page → content script request.
export interface OcRequestMessage {
  channel: typeof OC_REQUEST_CHANNEL;
  id: string;
  method: string;
  params?: unknown;
}

/// Content script → page reply.
export interface OcReplyMessage {
  channel: typeof OC_REPLY_CHANNEL;
  id: string;
  result?: unknown;
  error?: RpcErrorShape;
}

/// Content script → page provider event.
export interface OcEventMessage {
  channel: typeof OC_EVENT_CHANNEL;
  event: ProviderEvent;
  data?: unknown;
}

/// Runtime envelope: content script → service worker.
export interface OcRuntimeRequest {
  type: 'oc:request';
  id: string;
  method: string;
  params?: unknown;
}

/// Runtime envelope: popup/notification page → service worker.
export interface PopupRuntimeRequest {
  type: 'popup:request';
  method: PopupMethod;
  params?: unknown;
}

/// Runtime envelope: service worker → content scripts.
export interface OcRuntimeEvent {
  type: 'oc:event';
  event: ProviderEvent;
  data?: unknown;
}

export type RuntimeMessage = OcRuntimeRequest | PopupRuntimeRequest;

/// EIP-1193 provider events forwarded to dApps.
export type ProviderEvent = 'accountsChanged' | 'chainChanged' | 'connect' | 'disconnect';

// ---------------------------------------------------------------------------
// Consent queue types (design §4.4)
// ---------------------------------------------------------------------------

export type ConsentKind =
  | 'connect'
  | 'sign_message'
  | 'sign_typed_data'
  | 'sign_transaction'
  | 'send_transaction';

/// Human-readable rendering of a pending request (decode.ts output).
export interface ConsentField {
  label: string;
  value: string;
  /// `code` renders monospace; `warn` renders in the danger color.
  kind?: 'text' | 'code' | 'warn';
}

export interface ConsentView {
  title: string;
  summary: string;
  fields: ConsentField[];
  warnings: string[];
}

export interface PendingActionView {
  id: string;
  kind: ConsentKind;
  origin: string;
  view: ConsentView;
  expiresAt: number;
  /// Pre-built OCWP request executed after approval.
  ocwp: { method: string; params: Record<string, unknown> };
  /// Policy verdict + dry-run result, computed when the action is enqueued so
  /// the consent window can show them BEFORE the user clicks (design §4.8).
  /// Advisory only: a green badge never authorizes anything (INV-2), and the
  /// same evaluation is re-run at approve time (INV-4).
  assessment?: ConsentAssessment | null;
}

/// Dry-run summary for a transaction request (design §4.8 "simulation").
export interface SimulationSummary {
  ok: boolean;
  /// Hex gas estimate, when the chain answered.
  gasUsed?: string;
  /// Revert reason when `eth_call` failed.
  revertReason?: string;
}

/// A risk badge on a consent card (design §4.1 `policy-view.ts`).
export interface RiskBadge {
  /// `danger` = can move funds or rights; `warn` = look before you click;
  /// `info` = neutral context.
  level: 'info' | 'warn' | 'danger';
  label: string;
}

/// What the daemon says about a pending request: the policy verdict, the
/// dry-run result, and the request's own risk badges. All three are shown to
/// the user; none is an authorization.
export interface ConsentAssessment {
  policy: PolicyPreview | null;
  simulation: SimulationSummary | null;
  /// Risk badges from `lib/consent/policy-view.ts` (first-time recipient,
  /// value over the warn threshold, unverified contract, ...). Optional so a
  /// partial stub still compiles; the executor always fills it in.
  riskBadges?: RiskBadge[];
  /// Populated only for a transaction send.
  tx?: Record<string, unknown> | null;
}

/// Policy preview shape returned by `oc_policy_preview` (design §4.9).
export interface PolicyPreview {
  method?: string;
  decision: 'allow' | 'deny';
  reasons: Array<{ code: string; message: string }>;
  matched_policy_ids: string[];
  /// Envelope the decision was made on, echoed back by the daemon.
  tx_type?: string;
  to?: string | null;
  value?: string | null;
  data?: string | null;
}

// ---------------------------------------------------------------------------
// Popup methods (popup:request)
// ---------------------------------------------------------------------------

export type PopupMethod =
  | 'popup_getState'
  | 'popup_unlock'
  | 'popup_lock'
  | 'popup_listActions'
  | 'popup_approveAction'
  | 'popup_declineAction'
  | 'popup_switchChain'
  | 'popup_revokeSite'
  | 'popup_setDaemonUrl'
  | 'popup_setCustomChain'
  | 'popup_activity'
  | 'popup_registerPasskey';

export interface SessionHandle {
  sessionId: string;
  walletId: string;
  wallet: string;
  expiresAtUnix: number;
}

export interface OcAccount {
  account_id: string;
  chain_id: string;
  address: string;
  derivation_path: string;
}

export interface SiteEntry {
  origin: string;
  account_id: string;
  chain_id: string;
  connected_at: number;
  last_seen_at: number;
}

export interface ChainEntry {
  chain_id: string;
  name: string;
  rpc_url?: string;
  explorer_url?: string;
  native_currency: string;
  is_evm: boolean;
  builtin: boolean;
}

/// Popup state snapshot returned by `popup_getState`.
export interface PopupState {
  daemonReachable: boolean;
  /// Why the daemon probe failed (empty when reachable).
  daemonError?: string;
  protocolVersion?: number;
  session: SessionHandle | null;
  accounts: OcAccount[];
  activeChainId: string;
  sites: SiteEntry[];
  /// Each pending action carries its own `assessment` (policy + simulation).
  pendingActions: PendingActionView[];
  /// Chain ids the popup may present (design §4.8 "chain selector").
  chains: string[];
  /// Native balance per chain, `wei === null` when the read failed.
  balances: Array<{ chainId: string; wei: string | null }>;
  /// Value above which a transfer is flagged, from `oc:config`.
  warnThresholdWei?: string;
  /// Contracts the user has marked verified, from `oc:config`.
  verifiedContracts?: string[];
}
