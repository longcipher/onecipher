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
}

export const DEFAULT_CONFIG: ExtensionConfig = {
  daemonUrl: DAEMON_DEFAULT_URL,
  activeChainId: 'eip155:1',
  customChains: [],
  verifiedContracts: [],
  passkeyJwk: null,
  passkeyCredentialId: null,
};

const CONFIG_KEY = 'oc:config';

export async function loadConfig(storage: {
  local: { get(key: string): Promise<Record<string, unknown>> };
}): Promise<ExtensionConfig> {
  const stored = await storage.local.get(CONFIG_KEY);
  const raw = stored[CONFIG_KEY] as Partial<ExtensionConfig> | undefined;
  const merged: ExtensionConfig = { ...DEFAULT_CONFIG, ...raw };
  // INV-9: a non-loopback daemon URL is never honored, even if stored.
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
  await storage.local.set({ [CONFIG_KEY]: { ...config, daemonUrl: validateLoopbackUrl(config.daemonUrl) } });
}
