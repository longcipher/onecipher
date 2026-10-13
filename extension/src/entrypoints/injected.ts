// In-page EIP-1193 provider (design §4.3). Runs in the page's main realm as
// an unlisted script; communicates ONLY via window.postMessage through the
// content-script bridge. Never touches fetch (INV-8) — HTTP 402 passes
// through untouched.

import {
  EIP6963_ANNOUNCE,
  EIP6963_PROVIDER_NAME,
  EIP6963_RDNS,
  EIP6963_REQUEST,
  ETHEREUM_INITIALIZED,
  OC_EVENT_CHANNEL,
  OC_REPLY_CHANNEL,
  OC_REQUEST_CHANNEL,
  type OcEventMessage,
  type OcReplyMessage,
} from '../lib/protocol';
import { pageUuid } from '../lib/eip6963';

export default defineUnlistedScript(() => {
  if (window.__oneCipherInjected) return;
  window.__oneCipherInjected = true;

  type Listener = (...args: unknown[]) => void;

  class OneCipherProvider {
    isOneCipher = true;
    private listeners = new Map<string, Set<Listener>>();

    request({ method, params }: { method: string; params?: unknown[] | object }): Promise<unknown> {
      if (typeof method !== 'string' || method.length === 0) {
        return Promise.reject(new Error('request: method must be a non-empty string'));
      }
      const id = `req-${crypto.randomUUID()}`;
      return new Promise((resolve, reject) => {
        const onMessage = (event: MessageEvent) => {
          if (event.source !== window) return;
          const data = event.data as OcReplyMessage | undefined;
          if (!data || typeof data !== 'object') return;
          if (data.channel !== OC_REPLY_CHANNEL || data.id !== id) return;
          window.removeEventListener('message', onMessage);
          if (data.error) {
            const error = new Error(data.error.message);
            (error as Error & { code?: number; data?: unknown }).code = data.error.code;
            (error as Error & { code?: number; data?: unknown }).data = data.error.data;
            reject(error);
          } else {
            resolve(data.result);
          }
        };
        window.addEventListener('message', onMessage);
        window.postMessage({ channel: OC_REQUEST_CHANNEL, id, method, params }, '*');
      });
    }

    enable(): Promise<unknown[]> {
      return this.request({ method: 'eth_requestAccounts' }) as Promise<unknown[]>;
    }

    on(event: string, listener: Listener): void {
      const set = this.listeners.get(event) ?? new Set<Listener>();
      set.add(listener);
      this.listeners.set(event, set);
    }

    removeListener(event: string, listener: Listener): void {
      this.listeners.get(event)?.delete(listener);
    }

    emit(event: string, ...args: unknown[]): void {
      for (const listener of this.listeners.get(event) ?? []) {
        try {
          listener(...args);
        } catch {
          // Listener errors must not break the provider.
        }
      }
    }
  }

  const provider = new OneCipherProvider();

  // Relay worker events into provider events.
  window.addEventListener('message', (event: MessageEvent) => {
    if (event.source !== window) return;
    const data = event.data as OcEventMessage | undefined;
    if (!data || typeof data !== 'object' || data.channel !== OC_EVENT_CHANNEL) return;
    provider.emit(data.event, data.data);
    if (data.event === 'disconnect') {
      provider.emit('disconnect', data.data);
    }
  });

  // EIP-6963 multi-provider discovery: publish a per-install uuid, then
  // announce. Announcing before the uuid is available would hand dApps an id
  // that changes on the next discovery round.
  const providerInfo = {
    uuid: pageUuid(),
    name: EIP6963_PROVIDER_NAME,
    icon: ICON_SVG_URI,
    rdns: EIP6963_RDNS,
  };
  const detail = Object.freeze({ info: providerInfo, provider });
  const announce = () => {
    window.dispatchEvent(new CustomEvent(EIP6963_ANNOUNCE, { detail }));
  };
  announce();
  window.addEventListener(EIP6963_REQUEST, announce);

  // Legacy window.ethereum: only claim it when no other wallet is present.
  // `writable: false` prevents page scripts from swapping the reference.
  if (typeof window.ethereum === 'undefined') {
    try {
      Object.defineProperty(window, 'ethereum', {
        get: () => provider,
        set: () => undefined,
        configurable: false,
        enumerable: true,
      });
      window.dispatchEvent(new Event(ETHEREUM_INITIALIZED));
    } catch {
      // A hostile page already defined a non-configurable property; EIP-6963
      // still works, which is precisely why discovery is announced first.
    }
  }
});

/// Inline SVG data URI for EIP-6963 providerInfo.icon.
const ICON_SVG_URI =
  'data:image/svg+xml,' +
  encodeURIComponent(
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="#101828"/><path d="M9 10h14v3H12.5v3H21v3h-8.5v3H23v3H9z" fill="#4ade80"/></svg>`,
  );

declare global {
  interface Window {
    __oneCipherInjected?: boolean;
    ethereum?: unknown;
  }
}
