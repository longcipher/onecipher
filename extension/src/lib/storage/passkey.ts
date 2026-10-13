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
// Consequence, accepted and documented: the step-up credential is lost on
// browser restart, and the user re-registers from settings. The key can
// authorize nothing but a fresh EIP-7702 confirmation, and the daemon binds
// each challenge to the session that requested it (single use, 120 s).

const PASSKEY_KEY = 'oc:passkey';

export interface StoredPasskey {
  credentialId: string;
  jwk: JsonWebKey;
}

interface SessionArea {
  get(key: string): Promise<Record<string, unknown>>;
  set(value: Record<string, unknown>): Promise<void>;
  remove(key: string): Promise<void>;
}

export async function loadPasskey(storage: { session: SessionArea }): Promise<StoredPasskey | null> {
  const stored = await storage.session.get(PASSKEY_KEY);
  const raw = stored[PASSKEY_KEY] as StoredPasskey | undefined;
  // Guard against a legacy `local`-era payload being replayed into the session
  // area: a material without a credential id cannot produce a valid proof.
  if (!raw || typeof raw.credentialId !== 'string' || raw.credentialId.length === 0) return null;
  if (!raw.jwk || typeof raw.jwk !== 'object') return null;
  return raw;
}

export async function savePasskey(
  storage: { session: SessionArea },
  material: StoredPasskey,
): Promise<void> {
  await storage.session.set({ [PASSKEY_KEY]: material });
}

/// Drop the step-up key (explicit re-registration, or a reset).
export async function clearPasskey(storage: { session: SessionArea }): Promise<void> {
  await storage.session.remove(PASSKEY_KEY);
}