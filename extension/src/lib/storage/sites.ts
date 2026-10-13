// chrome.storage.local mirror of the daemon's `sites.json` (design §6.4).
// The daemon store is authoritative; this cache exists for offline rendering
// and last-seen bookkeeping in the popup.

import type { SiteEntry } from '../protocol';

const SITES_KEY = 'oc:sites';

export async function loadSitesCache(storage: {
  local: { get(key: string): Promise<Record<string, unknown>> };
}): Promise<SiteEntry[]> {
  const stored = await storage.local.get(SITES_KEY);
  return (stored[SITES_KEY] as SiteEntry[] | undefined) ?? [];
}

export async function saveSitesCache(
  storage: { local: { set(value: Record<string, unknown>): Promise<void> } },
  sites: SiteEntry[],
): Promise<void> {
  await storage.local.set({ [SITES_KEY]: sites });
}

/// Is this origin currently authorized (per the cache)?
export async function isSiteAuthorized(storage: {
  local: { get(key: string): Promise<Record<string, unknown>> };
}, origin: string): Promise<boolean> {
  const sites = await loadSitesCache(storage);
  return sites.some((site) => site.origin === origin);
}

/// The chain this origin last selected (design §4.3/§4.10 per-site chain).
///
/// Per-site, not global: chain selection is part of a site's connection, so
/// one dApp switching chains must not move every other dApp's chain under it.
export async function siteChainId(storage: {
  local: { get(key: string): Promise<Record<string, unknown>> };
}, origin: string): Promise<string | null> {
  const sites = await loadSitesCache(storage);
  return sites.find((site) => site.origin === origin)?.chain_id ?? null;
}

/// Record a chain switch for an origin. Unconnected origins are a no-op: a
/// site that has never been approved has no chain binding to change.
export async function setSiteChain(
  storage: {
    local: {
      get(key: string): Promise<Record<string, unknown>>;
      set(value: Record<string, unknown>): Promise<void>;
    };
  },
  origin: string,
  chainId: string,
): Promise<void> {
  const sites = await loadSitesCache(storage);
  let changed = false;
  const next = sites.map((site) => {
    if (site.origin !== origin) return site;
    changed = true;
    return { ...site, chain_id: chainId, last_seen_at: Math.floor(Date.now() / 1000) };
  });
  if (changed) await saveSitesCache(storage, next);
}

/// Record/refresh a site in the cache (called after the daemon confirms).
export async function upsertSite(
  storage: {
    local: {
      get(key: string): Promise<Record<string, unknown>>;
      set(value: Record<string, unknown>): Promise<void>;
    };
  },
  origin: string,
  accountId: string,
  chainId: string,
): Promise<SiteEntry[]> {
  const sites = await loadSitesCache(storage);
  const now = Math.floor(Date.now() / 1000);
  const existing = sites.find((site) => site.origin === origin);
  const entry: SiteEntry = existing
    ? { ...existing, account_id: accountId, chain_id: chainId, last_seen_at: now }
    : { origin, account_id: accountId, chain_id: chainId, connected_at: now, last_seen_at: now };
  const next = existing ? sites.map((site) => (site.origin === origin ? entry : site)) : [...sites, entry];
  await saveSitesCache(storage, next);
  return next;
}

export async function removeSite(
  storage: {
    local: {
      get(key: string): Promise<Record<string, unknown>>;
      set(value: Record<string, unknown>): Promise<void>;
    };
  },
  origin: string,
): Promise<SiteEntry[]> {
  const sites = (await loadSitesCache(storage)).filter((site) => site.origin !== origin);
  await saveSitesCache(storage, sites);
  return sites;
}
