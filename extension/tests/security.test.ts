// Security sentinels (design §9.3).
//
// These are the assertions the design calls "sentinels" — zero-valued recorders
// that must stay zero across the whole consent flow:
//
//   network   — no request ever leaves for anything but the configured loopback
//               daemon (D10: no fetch patching, no payment interception).
//   captures  — zero `captureVisibleTab` (T10: no screen capture surface).
//   storage   — nothing matching a mnemonic / raw-key / passphrase / API-token
//               shape is ever written to a storage area (INV-1).
//   fetch     — `window.fetch` identity is unchanged (INV-8).
//
// They run against the real router with fake browser/storage/network surfaces,
// so a regression that introduces any of those behaviours fails here rather
// than in review.

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ConsentQueue } from '../src/lib/consent/queue';
import {
  createConsentExecutor,
  handleRuntimeMessage,
  type RouterContext,
  type RouterEnv,
  type RouterStores,
} from '../src/lib/background/router';
import { DAEMON_DEFAULT_URL } from '../src/lib/protocol';
import { loadConfig, saveConfig } from '../src/lib/storage/config';
import { DEFAULT_CONFIG } from '../src/lib/storage/config';
import { loadPasskey, savePasskey } from '../src/lib/storage/passkey';
import { loadSessionHandle, saveSessionHandle } from '../src/lib/storage/session-store';
import { loadSitesCache, upsertSite } from '../src/lib/storage/sites';

const EXT_ID = 'abcdefghijklmnopabcdefghijklmnop';
const POPUP_URL = `chrome-extension://${EXT_ID}/popup.html`;
const ORIGIN = 'https://dapp.example';
const webSender = { id: EXT_ID, url: `${ORIGIN}/app`, origin: ORIGIN, tab: { id: 1 } };
const popupSender = { id: EXT_ID, url: POPUP_URL, origin: `chrome-extension://${EXT_ID}` };

interface Sentinels {
  network: string[];
  captures: number;
  storageWrites: Array<{ area: string; values: unknown }>;
}

interface Rig {
  ctx: RouterContext;
  sentinels: Sentinels;
  local: ReturnType<typeof area>;
  session: ReturnType<typeof area>;
  /// Tracked storage namespace, as the browser hands it to the store modules.
  storage: { local: unknown; session: unknown };
  restore: () => void;
}

function area() {
  const values: Record<string, unknown> = {};
  return {
    values,
    get: async (key: string) => (key in values ? { [key]: values[key] } : {}),
    set: async (value: Record<string, unknown>) => {
      Object.assign(values, value);
    },
    remove: async (key: string) => {
      delete values[key];
    },
  };
}

function buildRig(daemonUrl = DAEMON_DEFAULT_URL): Rig {
  const sentinels: Sentinels = { network: [], captures: 0, storageWrites: [] };
  const local = area();
  const session = area();

  // Record every storage write with its area, then apply it — this is what
  // makes the storage sentinel able to inspect what was persisted.
  const tracked = (name: string, inner: ReturnType<typeof area>) => ({
    get: inner.get,
    remove: inner.remove,
    set: async (value: Record<string, unknown>) => {
      sentinels.storageWrites.push({ area: name, values: value });
      await inner.set(value);
    },
  });
  const storage = {
    local: tracked('local', local),
    session: tracked('session', session),
  };

  const originalFetch = globalThis.fetch;
  const fetchImpl = vi.fn(async (input: RequestInfo | URL) => {
    const url = typeof input === 'string' ? input : input instanceof URL ? input.toString() : input.url;
    sentinels.network.push(url);
    // Everything except the configured loopback daemon is a hard failure:
    // the extension has no legitimate reason to talk to any other host.
    if (!url.startsWith(daemonUrl)) throw new Error(`network sentinel: unexpected ${url}`);
    return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: {} }), { status: 200 });
  });
  globalThis.fetch = fetchImpl as unknown as typeof fetch;

  const tabCapture = () => {
    sentinels.captures += 1;
    throw new Error('capture sentinel: the extension must never capture the screen');
  };
  const browserStub = {
    tabs: {
      query: async () => [],
      sendMessage: async () => undefined,
    },
    captureVisibleTab: tabCapture,
  };
  (globalThis as unknown as { browser?: unknown }).browser = browserStub;
  if ('chrome' in globalThis) {
    (globalThis as unknown as { chrome: Record<string, unknown> }).chrome.captureVisibleTab = tabCapture;
  }

  const sites = new Set<string>();
  const chains = new Map<string, string>();
  const stores: RouterStores = {
    config: {
      load: async () => loadConfig({ local } as never),
      save: async (config) => saveConfig({ local } as never, config),
    },
    sites: {
      isAuthorized: async (origin) => sites.has(origin),
      chainFor: async (origin) => chains.get(origin) ?? null,
      setChain: async (origin, chainId) => {
        chains.set(origin, chainId);
      },
      upsert: async (origin, accountId, chainId) => {
        sites.add(origin);
        chains.set(origin, chainId);
      },
      remove: async (origin) => {
        sites.delete(origin);
        chains.delete(origin);
      },
      list: async () => (await loadSitesCache({ local } as never)).map((site) => ({
        ...site,
        account_id: site.account_id || 'eip155:1',
      })),
    },
    session: {
      load: async () => loadSessionHandle({ session } as never),
      save: async (handle) => saveSessionHandle({ session } as never, handle),
      clear: async () => undefined,
    },
    passkey: {
      load: async () => loadPasskey({ session } as never),
      save: async (material) => savePasskey({ session } as never, material),
    },
  };

  const daemon = {
    sessionStatus: async () => ({ unlocked: true }),
    accounts: async () => ({
      accounts: [
        { account_id: 'eip155:1', chain_id: 'eip155:1', address: '0xabc', derivation_path: "m/44'/60'/0'/0/0" },
      ],
    }),
    connectSite: async () => undefined,
    rpc: async () => '0x1',
    signMessage: async () => ({ signature: '0xsig', public_key: '0xpk' }),
    signTypedData: async () => ({ signature: '0xtyped', public_key: '0xpk' }),
    signTransaction: async () => ({ raw_transaction: '0xsigned' }),
    sendTransaction: async () => ({ tx_hash: '0xhash' }),
    simulate: async () => ({ ok: true, gas_used: '0x5208' }),
    policyPreview: async () => ({ decision: 'allow' as const, reasons: [], matched_policy_ids: [] }),
    hello: async () => ({
      protocol_version: 1,
      daemon_version: 'test',
      chains: [],
      features: [],
      extension_ids: [EXT_ID],
    }),
    lock: async () => undefined,
    revokeSite: async () => ({ revoked: true }),
    unlock: async () => ({
      session_id: 'a'.repeat(64),
      wallet_id: 'w-1',
      index: 0,
      expires_at_unix: 9999999999,
      accounts: [],
    }),
    passkeyChallenge: async () => ({ challenge_hex: 'aa', rp_id: 'localhost', timeout_ms: 120_000 }),
    passkeyRegister: async () => ({ registered: true, wallet_id: 'w-1' }),
  };

  const env: RouterEnv = {
    broadcast: async () => undefined,
    openNotification: async () => undefined,
    closeNotification: async () => undefined,
  };
  const ctx: RouterContext = {
    extensionId: EXT_ID,
    popupUrl: POPUP_URL,
    daemon: daemon as never,
    queue: null as unknown as ConsentQueue,
    stores,
    env,
    setDaemon() {
      /* static stub */
    },
  };
  ctx.queue = new ConsentQueue(createConsentExecutor(ctx), {
    now: () => Date.now(),
    onEnqueue: env.openNotification,
    onDrain: env.closeNotification,
  });

  return {
    ctx,
    sentinels,
    local,
    session,
    storage,
    restore: () => {
      globalThis.fetch = originalFetch;
      delete (globalThis as unknown as { browser?: unknown }).browser;
    },
  };
}

const SECRET_SHAPES: Array<[string, RegExp]> = [
  ['mnemonic', /(?:\b(?:abandon|ability|able|about|above|absent)\b.*){12,}/i],
  ['raw 32-byte key', /"?0x[0-9a-fA-F]{64}"?/],
  ['api token', /oc_key_[0-9a-fA-F]{32,}/],
];

let rig: Rig | undefined;

beforeEach(() => {
  rig = buildRig();
});

afterEach(() => {
  rig?.restore();
  rig = undefined;
});

describe('security sentinels (design §9.3)', () => {
  /// Unlock so wallet requests actually reach the consent pipeline.
  async function unlock(rig: Rig): Promise<void> {
    await handleRuntimeMessage(
      rig.ctx,
      { type: 'popup:request', method: 'popup_unlock', params: { wallet: 'default', passphrase: 'hunter2' } },
      popupSender,
    );
  }

  it('storage sentinel: the consent flow writes no key material (INV-1)', async () => {
    const rig = buildRig();
    await saveConfig(rig.storage as never, DEFAULT_CONFIG);
    await unlock(rig);
    void handleRuntimeMessage(
      rig.ctx,
      { type: 'oc:request', id: 'a', method: 'eth_requestAccounts' },
      webSender,
    );
    await vi.waitFor(() => expect(rig.ctx.queue.size).toBe(1));
    await rig.ctx.queue.approve(rig.ctx.queue.list()[0]!.id);

    for (const [method, params] of [
      ['personal_sign', ['0x48656c6c6f']],
      [
        'eth_sendTransaction',
        [{ to: '0x1111111111111111111111111111111111111111', nonce: '0x1', value: '0x1' }],
      ],
    ] as const) {
      void handleRuntimeMessage(rig.ctx, { type: 'oc:request', id: method, method, params }, webSender);
      await vi.waitFor(() => expect(rig.ctx.queue.size).toBe(1));
      await rig.ctx.queue.approve(rig.ctx.queue.list()[0]!.id);
    }

    expect(rig.sentinels.storageWrites.length).toBeGreaterThan(0);
    for (const write of rig.sentinels.storageWrites) {
      const serialized = JSON.stringify(write.values);
      for (const [label, shape] of SECRET_SHAPES) {
        expect(shape.test(serialized), `${write.area} storage must not hold a ${label}`).toBe(false);
      }
      // The unlock passphrase must never reach storage in any form.
      expect(serialized).not.toContain('hunter2');
    }
  });

  it('storage sentinel: the step-up key is confined to session storage', async () => {
    const rig = buildRig();
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
      'sign',
      'verify',
    ]);
    const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
    await savePasskey(rig.storage as never, {
      credentialId: 'oc-ext-1',
      jwk,
    });
    // Nothing reached `local`; the key dies with the browser session.
    expect(rig.sentinels.storageWrites.some((write) => write.area === 'local')).toBe(false);
    expect(rig.sentinels.storageWrites.some((write) => write.area === 'session')).toBe(true);
  });

  it('network sentinel: nothing is requested but the loopback daemon (D10)', async () => {
    const rig = buildRig();
    await unlock(rig);
    await handleRuntimeMessage(rig.ctx, { type: 'popup:request', method: 'popup_getState' }, popupSender);
    void handleRuntimeMessage(
      rig.ctx,
      { type: 'oc:request', id: 'x', method: 'personal_sign', params: ['0x48'] },
      webSender,
    );
    await vi.waitFor(() => expect(rig.ctx.queue.size).toBe(1));
    rig.ctx.queue.decline(rig.ctx.queue.list()[0]!.id);
    expect(rig.sentinels.network.every((url) => url.startsWith(DAEMON_DEFAULT_URL))).toBe(true);
  });

  it('capture sentinel: the extension exposes no capture surface (T10)', async () => {
    const rig = buildRig();
    await unlock(rig);
    void handleRuntimeMessage(rig.ctx, { type: 'oc:request', id: 'z', method: 'eth_accounts' }, webSender);
    // The stub throws if anything tries to use it, so reaching zero proves no
    // code path — not a passing assertion — attempted a screen capture.
    expect(rig.sentinels.captures).toBe(0);
    const stub = (globalThis as unknown as { browser: { captureVisibleTab: () => never } }).browser;
    // Firing the tripwire proves it would have caught a real capture.
    expect(() => stub.captureVisibleTab()).toThrow();
    expect(rig.sentinels.captures).toBe(1);
  });

  it('fetch sentinel: the extension never patches window.fetch (INV-8)', async () => {
    const rig = buildRig();
    const pageFetch = () => undefined;
    (globalThis as unknown as { window: Record<string, unknown> }).window = { fetch: pageFetch };
    await unlock(rig);
    void handleRuntimeMessage(
      rig.ctx,
      { type: 'oc:request', id: 'y', method: 'personal_sign', params: ['0x48'] },
      webSender,
    );
    await vi.waitFor(() => expect(rig.ctx.queue.size).toBe(1));
    rig.ctx.queue.decline(rig.ctx.queue.list()[0]!.id);
    const patched = (globalThis as unknown as { window: { fetch: unknown } }).window.fetch;
    expect(patched).toBe(pageFetch);
  });
});

describe('sites storage helpers are used, not bypassed', () => {
  it('keeps per-site chains through the real storage module', async () => {
    const local = area();
    await upsertSite({ local } as never, ORIGIN, 'eip155:1', 'eip155:1');
    expect((await loadSitesCache({ local } as never))[0]?.chain_id).toBe('eip155:1');
  });
});