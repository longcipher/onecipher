// MV3 service worker: wires the router with browser APIs (design §4.2).
// All invariant logic lives in `lib/background/router.ts` (unit-tested);
// this file is glue only.

import { browser } from 'wxt/browser';
import { OcwpClient } from '../lib/daemon/client';
import { ConsentQueue } from '../lib/consent/queue';
import { DAEMON_DEFAULT_URL } from '../lib/protocol';
import {
  createConsentExecutor,
  handleRuntimeMessage,
  type RouterContext,
  type RouterEnv,
  type RouterStores,
} from '../lib/background/router';
import { loadConfig, saveConfig, type ExtensionConfig } from '../lib/storage/config';
import { loadSessionHandle, saveSessionHandle, clearSessionHandle } from '../lib/storage/session-store';
import {
  isSiteAuthorized,
  loadSitesCache,
  removeSite,
  setSiteChain,
  siteChainId,
  upsertSite,
} from '../lib/storage/sites';
import { loadPasskey, savePasskey } from '../lib/storage/passkey';

export default defineBackground(() => {
  const extensionId = browser.runtime.id;
  const popupUrl = browser.runtime.getURL('/popup.html');

  // ------------------------------------------------------------------
  // Notification window lifecycle (F14): one reused popup window hosting
  // popup.html?view=notification. A window that is tearing down may still
  // be reported by Chrome, so liveness requires at least one live tab.
  // ------------------------------------------------------------------
  let notificationWindowId: number | null = null;

  async function openNotification(): Promise<void> {
    if (notificationWindowId !== null) {
      try {
        const win = await browser.windows.get(notificationWindowId, { populate: true });
        if (win?.id !== undefined && (win.tabs?.length ?? 0) > 0) {
          await browser.windows.update(win.id, { focused: true });
          return;
        }
      } catch {
        // Window is gone; fall through and open a fresh one.
      }
      notificationWindowId = null;
    }
    const win = await browser.windows.create({
      url: `${popupUrl}?view=notification`,
      type: 'popup',
      width: 360,
      height: 600,
    });
    notificationWindowId = win?.id ?? null;
  }

  async function closeNotification(): Promise<void> {
    if (notificationWindowId === null) return;
    try {
      await browser.windows.remove(notificationWindowId);
    } catch {
      // Already closed.
    }
    notificationWindowId = null;
  }

  browser.windows.onRemoved.addListener((windowId: number) => {
    if (windowId === notificationWindowId) notificationWindowId = null;
  });

  // ------------------------------------------------------------------
  // Event broadcast: service worker → content scripts → page.
  //
  // Addressed, not global: `accountsChanged` carries the wallet's addresses,
  // so relaying it to every tab would disclose them to origins that were never
  // granted the connection (D-12). Tabs without a receiver are tolerated
  // (F15-adjacent fire-and-forget).
  // ------------------------------------------------------------------
  async function broadcast(
    event: import('../lib/protocol').ProviderEvent,
    data: unknown,
    allowedOrigins: readonly string[] | null,
  ): Promise<void> {
    const tabs = await browser.tabs.query({});
    for (const tab of tabs) {
      if (tab.id === undefined) continue;
      if (allowedOrigins !== null) {
        const tabUrl = tab.url;
        if (!tabUrl) continue;
        let origin: string;
        try {
          origin = new URL(tabUrl).origin;
        } catch {
          continue; // chrome://, about:, extension pages
        }
        if (!allowedOrigins.includes(origin)) continue;
      }
      try {
        await browser.tabs.sendMessage(tab.id, { type: 'oc:event', event, data });
      } catch {
        // No content script in this tab — ignore.
      }
    }
  }

  /// Broadcast `accountsChanged` to connected sites only.
  async function broadcastToSites(event: import('../lib/protocol').ProviderEvent, data: unknown): Promise<void> {
    const sites = await loadSitesCache(browser.storage);
    await broadcast(event, data, sites.map((site) => site.origin));
  }

  // ------------------------------------------------------------------
  // Stores (chrome.storage-backed implementations of RouterStores)
  // ------------------------------------------------------------------
  const configStore = {
    load: (): Promise<ExtensionConfig> => loadConfig(browser.storage),
    save: (config: ExtensionConfig): Promise<void> => saveConfig(browser.storage, config),
  };
  const stores: RouterStores = {
    config: configStore,
    sites: {
      isAuthorized: (origin) => isSiteAuthorized(browser.storage, origin),
      chainFor: (origin) => siteChainId(browser.storage, origin),
      setChain: async (origin, chainId) => {
        await setSiteChain(browser.storage, origin, chainId);
      },
      upsert: async (origin, accountId, chainId) => {
        await upsertSite(browser.storage, origin, accountId, chainId);
      },
      remove: async (origin) => {
        await removeSite(browser.storage, origin);
      },
      list: () => loadSitesCache(browser.storage),
    },
    session: {
      load: () => loadSessionHandle(browser.storage),
      save: (handle) => saveSessionHandle(browser.storage, handle),
      clear: () => clearSessionHandle(browser.storage),
    },
    passkey: {
      // Session storage only — the step-up key must not outlive the browser
      // session (INV-1, OQ-3).
      load: () => loadPasskey(browser.storage),
      save: (material) => savePasskey(browser.storage, material),
    },
  };

  // ------------------------------------------------------------------
  // Router context
  // ------------------------------------------------------------------
  let daemon = new OcwpClient(DAEMON_DEFAULT_URL);
  const env: RouterEnv = { broadcast: broadcastToSites, openNotification, closeNotification };
  const queue = new ConsentQueue(
    // Executor is bound after ctx exists (it closes over ctx).
    null as never,
    { now: () => Date.now(), onEnqueue: openNotification, onDrain: closeNotification },
  );
  const ctx: RouterContext = {
    extensionId,
    popupUrl,
    daemon,
    queue,
    stores,
    env,
    setDaemon(client: OcwpClient) {
      daemon = client;
      ctx.daemon = client;
    },
  };
  // The executor needs ctx; assign it now that ctx is built.
  (queue as unknown as { executor: unknown }).executor = createConsentExecutor(ctx);

  // Seed the daemon client with the persisted URL.
  void configStore.load().then((config) => {
    ctx.setDaemon(new OcwpClient(config.daemonUrl));
    // Design §4.7: probe `oc_hello` on SW startup as well as on popup open.
    // The SW is suspended and resumed constantly; waiting for the first popup
    // open means the daemon-offline screen is wrong until then.
    void probeDaemon(ctx);
  });

  // Probe again on every resume: the daemon may have died or started while the
  // SW was suspended, and the popup reads this without its own round trip.
  browser.runtime.onStartup?.addListener?.(() => void probeDaemon(ctx));

  // ------------------------------------------------------------------
  // Message routing — strict envelope allowlist, fail-closed (F10/INV-7).
  // The promise-returning listener is supported by both the polyfill-based
  // `browser` API and FakeBrowser.
  // ------------------------------------------------------------------
  // ------------------------------------------------------------------
  // Daemon health (design §4.7). The SW is suspended and resumed constantly,
  // so the probe runs at startup and after every URL change rather than only
  // when a popup happens to open. The outcome is cached without a round trip:
  // a popup opening on resume reads it immediately.
  // ------------------------------------------------------------------
  let lastProbe: { ok: boolean; error?: string } = { ok: false, error: 'not yet probed' };

  async function probeDaemon(ctx: RouterContext): Promise<void> {
    try {
      await ctx.daemon.hello();
      lastProbe = { ok: true };
    } catch (error) {
      lastProbe = {
        ok: false,
        error: error instanceof Error ? error.message : String(error),
      };
    }
  }

  // Test/diagnostic hook (e2e evidence): queue size, window id, request log.
  const requestLog: string[] = [];  const debugHost = globalThis as unknown as {
    __ocDebug?: {
      queueSize(): number;
      notificationWindowId(): number | null;
      requestLog(): string[];
      /// Whether the last `oc_hello` probe reached the daemon.
      daemonReachable(): boolean;
    };
  };
  debugHost.__ocDebug = {
    queueSize: () => queue.size,
    notificationWindowId: () => notificationWindowId,
    requestLog: () => [...requestLog],
    daemonReachable: () => lastProbe.ok,
  };
  browser.runtime.onMessage.addListener((message: unknown, sender) => {    requestLog.push(
      `${Math.floor(Date.now() / 1000)} ${String((message as { type?: string })?.type)}:${
        String((message as { method?: string })?.method ?? '')
      }`,
    );
    if (requestLog.length > 20) requestLog.shift();
    return handleRuntimeMessage(ctx, message, sender);
  });
});
