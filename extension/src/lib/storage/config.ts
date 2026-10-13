// chrome.storage.local config (design §4.6). The extension persists NO key
// material — only connection settings, UI prefs, and the passkey public-side
// JWK used for step-up signing (a software authenticator; the design doc
// documents this trade-off, §3.5 / OQ-3).

import { DAEMON_DEFAULT_URL, type ChainEntry } from '../protocol';
import { validateLoopbackUrl } from '../daemon/client';

export interface ExtensionConfig {
  daemonUrl: string;
  activeChainId: string;
  customChains: ChainEntry[];
  verifiedContracts: string[];
  /// JWK of the software passkey (ECDSA P-256) used for step-up.
  passkeyJwk: JsonWebKey | null;
  passkeyCredentialId: string | null;
  /// Value (wei) above which a transfer is flagged in the consent UI
  /// (design §4.8 "value above the policy's warn threshold"). User-editable,
  /// not a policy: it decorates the prompt, it does not gate it.
  warnThresholdWei: string;
  /// Recipients this browser profile has previously sent value to, lowercased.
  /// Feeds the "first-time recipient" badge. Local-only: it is a per-device
  /// convenience, and the daemon's sites registry stays authoritative for
  /// authorization (design §3.6).
  knownRecipients: string[];
  /// Native balance last seen per chain id, cached for the popup between
  /// refreshes. Never a source of truth — the popup re-reads via `oc_rpc`.
  balanceCache: Record<string, string>;
}

export const DEFAULT_CONFIG: ExtensionConfig = {
  daemonUrl: DAEMON_DEFAULT_URL,
  activeChainId: 'eip155:1',
  customChains: [],
  verifiedContracts: [],
  passkeyJwk: null,
  passkeyCredentialId: null,
  /// 1 ETH. A deliberately conservative default: the point is that a large
  /// transfer is never silent, and the user can raise it.
  warnThresholdWei: '1000000000000000000',
  knownRecipients: [],
  balanceCache: {},
};

const CONFIG_KEY = 'oc:config';

/// Harden a partially-stored config into a fully-populated one.
///
/// Stored data is untrusted input: a config written by an older build, a
/// hand-edited `storage.local`, or a truncated write must all load as a valid
/// config rather than propagating `undefined` into the badge rules (where a
/// missing `knownRecipients` would silently disable the first-time-recipient
/// check).
export function normalizeConfig(raw: Partial<ExtensionConfig> | undefined): ExtensionConfig {
  const merged: ExtensionConfig = { ...DEFAULT_CONFIG, ...raw };
  return {
    ...merged,
    daemonUrl: DAEMON_DEFAULT_URL,
    customChains: Array.isArray(merged.customChains) ? merged.customChains : [],
    verifiedContracts: Array.isArray(merged.verifiedContracts)
      ? merged.verifiedContracts.filter((entry): entry is string => typeof entry === 'string')
      : [],
    knownRecipients: Array.isArray(merged.knownRecipients)
      ? merged.knownRecipients.filter((entry): entry is string => typeof entry === 'string')
      : [],
    balanceCache:
      merged.balanceCache !== null && typeof merged.balanceCache === 'object'
        ? merged.balanceCache
        : {},
    warnThresholdWei:
      typeof merged.warnThresholdWei === 'string' && /^\d+$/.test(merged.warnThresholdWei.trim())
        ? merged.warnThresholdWei.trim()
        : DEFAULT_CONFIG.warnThresholdWei,
    passkeyJwk: merged.passkeyJwk ?? null,
    passkeyCredentialId:
      typeof merged.passkeyCredentialId === 'string' ? merged.passkeyCredentialId : null,
  };
}

export async function loadConfig(storage: {
  local: { get(key: string): Promise<Record<string, unknown>> };
}): Promise<ExtensionConfig> {
  const stored = await storage.local.get(CONFIG_KEY);
  // INV-9: a non-loopback daemon URL is never honored, even if stored.
  const merged = normalizeConfig(stored[CONFIG_KEY] as Partial<ExtensionConfig> | undefined);
  try {
    merged.daemonUrl = validateLoopbackUrl(merged.daemonUrl);
  } catch {
    merged.daemonUrl = DAEMON_DEFAULT_URL;
  }
  return merged;
}

export async function saveConfig(
  storage: { local: { set(value: Record<string, unknown>): Promise<void> } },
  config: ExtensionConfig,
): Promise<void> {
  // Written back as a whole object with the validated URL only — a partial
  // write could drop `knownRecipients` and quietly disable a risk badge.
  await storage.local.set({
    [CONFIG_KEY]: { ...normalizeConfig(config), daemonUrl: validateLoopbackUrl(config.daemonUrl) },
  });
}
