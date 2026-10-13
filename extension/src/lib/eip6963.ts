// EIP-6963 provider identity (design §4.3).
//
// The spec requires `providerInfo.uuid` to be stable per provider *instance*.
// Generating it at injection time (as this did originally) hands out a new uuid
// on every page load, so a dApp that discovered the wallet twice holds two
// distinct entries for one wallet — the deduplication EIP-6963 exists to
// provide is silently defeated, and `uuid`s multiply across tabs and reloads.
//
// The provider runs in the page realm and cannot reach `chrome.storage`, so
// the uuid is minted once in the content script, persisted under
// `chrome.storage.local`, and handed to the page via `window` before the
// provider script is injected.

const UUID_KEY = 'oc:eip6963:uuid';

const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function randomUuid(): string {
  return crypto.randomUUID();
}

/// Get the persisted provider uuid, minting one on first use.
export async function providerUuid(storage: {
  local: { get(key: string): Promise<Record<string, unknown>>; set(value: Record<string, unknown>): Promise<void> };
}): Promise<string> {
  const stored = await storage.local.get(UUID_KEY);
  const existing = stored[UUID_KEY];
  if (typeof existing === 'string' && UUID_PATTERN.test(existing)) {
    return existing;
  }
  // A malformed or absent value is replaced rather than trusted: an invalid
  // uuid breaks discovery for dApps that validate the shape.
  const uuid = randomUuid();
  await storage.local.set({ [UUID_KEY]: uuid });
  return uuid;
}

/// Read the uuid the content script published into the page.
///
/// Falls back to a process-lifetime value so the provider still works when it
/// is loaded without the content script (unit tests, direct injection).
export function pageUuid(): string {
  const published = (globalThis as { __oneCipherUuid?: unknown }).__oneCipherUuid;
  if (typeof published === 'string' && UUID_PATTERN.test(published)) return published;
  const fallback = (globalThis as { __oneCipherUuidFallback?: string }).__oneCipherUuidFallback;
  if (fallback !== undefined && UUID_PATTERN.test(fallback)) return fallback;
  const generated = randomUuid();
  (globalThis as { __oneCipherUuidFallback?: string }).__oneCipherUuidFallback = generated;
  return generated;
}
