// chrome.storage.session — the unlocked-session HANDLE only (F13/design §4.6).
// Survives MV3 service-worker suspension, wiped when the browser closes.
//
// INV-1: no wallet key material, passphrase, or API token ever touches this
// store. The step-up software-authenticator key shares the same storage class
// and lifetime (see `storage/passkey.ts` for why it is a deliberate deviation
// from §3.5 and what it can and cannot authorize).

import type { SessionHandle } from '../protocol';

const SESSION_KEY = 'oc:session';

/// In-memory fallback for browsers without `storage.session` (older Firefox).
const memorySession: { value: SessionHandle | null } = { value: null };

function sessionArea(storage: {
  session?: {
    get(key: string): Promise<Record<string, unknown>>;
    set(value: Record<string, unknown>): Promise<void>;
    remove(key: string): Promise<void>;
  };
}): 'session' | 'memory' {
  return storage.session ? 'session' : 'memory';
}

export async function loadSessionHandle(storage: {
  session?: { get(key: string): Promise<Record<string, unknown>> };
}): Promise<SessionHandle | null> {
  if (sessionArea(storage as never) === 'memory') return memorySession.value;
  const stored = await storage.session?.get(SESSION_KEY);
  return (stored?.[SESSION_KEY] as SessionHandle | undefined) ?? null;
}

export async function saveSessionHandle(
  storage: { session?: { set(value: Record<string, unknown>): Promise<void> } },
  handle: SessionHandle,
): Promise<void> {
  if (sessionArea(storage as never) === 'memory') {
    memorySession.value = handle;
    return;
  }
  await storage.session?.set({ [SESSION_KEY]: handle });
}

export async function clearSessionHandle(storage: {
  session?: { remove(key: string): Promise<void> };
}): Promise<void> {
  memorySession.value = null;
  await storage.session?.remove(SESSION_KEY);
}
