// INV-1 storage discipline: what may be written where.
//
// The extension holds no wallet key material. The one private key it does own
// — the step-up software-authenticator key — is confined to
// `chrome.storage.session` so it never outlives the browser session (D-8),
// and these tests hold that line.

import { describe, expect, it } from 'vitest';
import { clearPasskey, loadPasskey, savePasskey } from '../src/lib/storage/passkey';
import {
  loadSessionHandle,
  saveSessionHandle,
  clearSessionHandle,
} from '../src/lib/storage/session-store';
import { loadConfig, saveConfig, DEFAULT_CONFIG } from '../src/lib/storage/config';
import {
  loadSitesCache,
  saveSitesCache,
  setSiteChain,
  siteChainId,
  upsertSite,
  removeSite,
} from '../src/lib/storage/sites';

/// A storage area with the full (get + set + remove) surface. An `Area` also
/// exposes its backing `values`, so the secret-shape assertions can inspect
/// what was actually persisted.
interface Area {
  values: Record<string, unknown>;
  get(key: string): Promise<Record<string, unknown>>;
  set(value: Record<string, unknown>): Promise<void>;
  remove(key: string): Promise<void>;
}

function area(): Area {
  const values: Record<string, unknown> = {};
  return {
    values,
    get: async (key) => (key in values ? { [key]: values[key] } : {}),
    set: async (value) => {
      Object.assign(values, value);
    },
    remove: async (key) => {
      delete values[key];
    },
  };
}

/// A browser-shaped storage namespace, plus direct access to the areas.
function makeStorage() {
  const local = area();
  const session = area();
  return {
    local,
    session,
    /// Hand to the store modules: structurally compatible with every accepted
    /// shape, and no `as never` casts hiding a real mismatch.
    chrome: { local, session },
  };
}

/// Mnemonic / raw-key / API-token shapes INV-1 forbids in any storage area.
const SECRET_SHAPES = [
  /(?:abandon|ability|able|about|above|absent|absorb|abstract|absurd|abuse|access|accident)(?:\s+\w+){11,}/,
  /"?0x[0-9a-fA-F]{64}"?/,
  /oc_key_[0-9a-fA-F]{32,}/,
];

function assertNoSecrets(label: string, values: Record<string, unknown>) {
  const serialized = JSON.stringify(values);
  for (const shape of SECRET_SHAPES) {
    expect(shape.test(serialized), `${label} must not contain a secret (${shape})`).toBe(false);
  }
}

describe('step-up passkey storage (INV-1, D-8)', () => {
  it('round-trips through session storage', async () => {
    const s = makeStorage();
    const material = {
      credentialId: 'oc-ext-0011',
      jwk: { kty: 'EC', crv: 'P-256', d: 'AAAA', x: 'BBBB', y: 'CCCC' },
    };
    await savePasskey((s.chrome), material);
    expect(await loadPasskey(s.chrome)).toEqual(material);
    await clearPasskey(s.chrome);
    expect(await loadPasskey(s.chrome)).toBeNull();
  });

  it('never writes the step-up key to persistent local storage', async () => {
    const s = makeStorage();
    await savePasskey((s.chrome), {
      credentialId: 'oc-ext-0011',
      jwk: { kty: 'EC', crv: 'P-256', d: 'AAAA', x: 'BBBB', y: 'CCCC' },
    });
    // The whole point: the key is gone when the browser closes.
    expect(Object.keys(s.local.values)).toHaveLength(0);
    expect(s.session.values['oc:passkey']).toBeDefined();
  });

  it('rejects a malformed stored material instead of trusting it', async () => {
    const s = makeStorage();
    await s.session.set({ 'oc:passkey': { jwk: {} } });
    expect(await loadPasskey(s.chrome)).toBeNull();
    await s.session.set({ 'oc:passkey': { credentialId: 'x', jwk: null } });
    expect(await loadPasskey(s.chrome)).toBeNull();
    await s.session.set({ 'oc:passkey': { credentialId: '', jwk: {} } });
    expect(await loadPasskey(s.chrome)).toBeNull();
  });
});

describe('session handle storage (§4.6)', () => {
  it('stores only a handle, and no secret', async () => {
    const s = makeStorage();
    await saveSessionHandle(s.chrome, {
      sessionId: 'a'.repeat(64),
      walletId: 'w-1',
      wallet: 'default',
      expiresAtUnix: 9999999999,
    });
    const handle = await loadSessionHandle(s.chrome);
    expect(handle?.sessionId).toBe('a'.repeat(64));
    assertNoSecrets('session store', s.session.values);
    await clearSessionHandle(s.chrome);
    expect(await loadSessionHandle(s.chrome)).toBeNull();
  });
});

describe('config storage', () => {
  it('keeps the daemon URL loopback-only even if tampered with', async () => {
    const s = makeStorage();
    await s.local.set({
      'oc:config': { ...DEFAULT_CONFIG, daemonUrl: 'http://evil.example:18080' },
    });
    const config = await loadConfig(s.chrome);
    expect(config.daemonUrl).toBe('http://127.0.0.1:18080');
  });

  it('refuses to persist a non-loopback daemon URL', async () => {
    const s = makeStorage();
    await expect(
      saveConfig(s.chrome, { ...DEFAULT_CONFIG, daemonUrl: 'http://10.0.0.5:18080' }),
    ).rejects.toMatchObject({ code: -32602 });
  });
});

describe('sites storage (per-site chains, D-6)', () => {
  it('tracks a chain per origin independently', async () => {
    const s = makeStorage();
    await upsertSite(s.chrome, 'https://a.example', 'eip155:1', 'eip155:1');
    await upsertSite(s.chrome, 'https://b.example', 'eip155:1', 'eip155:8453');
    expect(await siteChainId(s.chrome, 'https://a.example')).toBe('eip155:1');
    expect(await siteChainId(s.chrome, 'https://b.example')).toBe('eip155:8453');
    await setSiteChain(s.chrome, 'https://a.example', 'eip155:137');
    // Switching a.example must not move b.example (design §4.3/§4.10).
    expect(await siteChainId(s.chrome, 'https://a.example')).toBe('eip155:137');
    expect(await siteChainId(s.chrome, 'https://b.example')).toBe('eip155:8453');
    await removeSite(s.chrome, 'https://a.example');
    expect(await siteChainId(s.chrome, 'https://a.example')).toBeNull();
  });

  it('keeps connected_at stable across refreshes and persists', async () => {
    const s = makeStorage();
    await upsertSite(s.chrome, 'https://a.example', 'eip155:1', 'eip155:1');
    const first = (await loadSitesCache(s.chrome))[0]!;
    await upsertSite(s.chrome, 'https://a.example', 'eip155:1', 'eip155:137');
    const second = (await loadSitesCache(s.chrome))[0]!;
    expect(second.connected_at).toBe(first.connected_at);
    expect(second.chain_id).toBe('eip155:137');
    expect(await loadSitesCache(s.chrome)).toHaveLength(1);
    await saveSitesCache(s.chrome, []);
    expect(await loadSitesCache(s.chrome)).toEqual([]);
  });

  it('never writes key material', async () => {
    const s = makeStorage();
    await upsertSite(s.chrome, 'https://a.example', 'eip155:1', 'eip155:1');
    assertNoSecrets('sites store', s.local.values);
  });
});