// Software-passkey material — `chrome.storage.session`, never `local`.
//
// This is the ONE private key the extension holds, and its storage class is a
// deliberate deviation from design §3.5's `navigator.credentials.get()` (see
// OQ-3): a `chrome-extension://` origin cannot host a real WebAuthn relying
// party, so the extension implements a software authenticator instead.
//
// Because of that, the key is held in **session** storage — the same lifetime
// class as the unlocked-session handle (survives MV3 service-worker
// suspension, wiped when the browser closes). It is deliberately NOT in
// `chrome.storage.local`, where it would outlive the session and the browser
// and would violate INV-1's "no key material in any storage area".
//
// `chrome.storage.session` landed in Chrome 102 and Firefox 128. On an older
// browser there is no session area at all, so — exactly as for the session
// handle (design OQ-4) — the key falls back to process memory. That is
// strictly *better* than persisting it: the trade is a re-registration after
// a worker restart, in exchange for the key never touching disk.
//
// Consequences, accepted and covered by the §9.3 sentinels: the step-up
// credential is lost on browser restart, and the user re-registers from
// settings. The key can authorize nothing but a fresh EIP-7702 confirmation,
// and the daemon binds each challenge to the session that requested it
// (single use, 120 s).

const PASSKEY_KEY = 'oc:passkey';

export interface StoredPasskey {
  credentialId: string;
  jwk: JsonWebKey;
}

interface Area {
  get(key: string): Promise<Record<string, unknown>>;
  set(value: Record<string, unknown>): Promise<void>;
  remove(key: string): Promise<void>;
}

type Storage = { session?: Area };

/// Process-memory fallback for browsers without `storage.session` (OQ-4).
/// Never a fallback to `local` — see the header.
const memoryPasskey: { value: StoredPasskey | null } = { value: null };

function usableArea(storage: Storage): Area | null {
  const area = storage.session;
  if (area === undefined || area === null) return null;
  if (typeof area.get !== 'function' || typeof area.set !== 'function') return null;
  return area;
}

/// True when this browser has no `storage.session` at all (design OQ-4).
export function passkeyUsesMemoryFallback(storage: Storage): boolean {
  return usableArea(storage) === null;
}

/// Read the stored material. A malformed record is rejected rather than
/// trusted: material without a credential id cannot produce a valid proof.
export async function loadPasskey(storage: Storage): Promise<StoredPasskey | null> {
  const area = usableArea(storage);
  if (area === null) return memoryPasskey.value;
  const stored = await area.get(PASSKEY_KEY);
  const raw = stored[PASSKEY_KEY] as StoredPasskey | undefined;
  if (raw === null || typeof raw !== 'object') return null;
  if (typeof raw.credentialId !== 'string' || raw.credentialId.length === 0) return null;
  if (raw.jwk === null || typeof raw.jwk !== 'object') return null;
  return raw;
}

export async function savePasskey(storage: Storage, material: StoredPasskey): Promise<void> {
  const area = usableArea(storage);
  if (area === null) {
    memoryPasskey.value = material;
    return;
  }
  await area.set({ [PASSKEY_KEY]: material });
}

/// Drop the step-up key (explicit re-registration, or a reset).
export async function clearPasskey(storage: Storage): Promise<void> {
  memoryPasskey.value = null;
  const area = usableArea(storage);
  if (area === null) return;
  await area.remove(PASSKEY_KEY);
}

/// Test seam: forget the in-memory fallback between cases.
export function resetMemoryFallback(): void {
  memoryPasskey.value = null;
}
