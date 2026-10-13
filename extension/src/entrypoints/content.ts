// Content script (isolated world): the ONLY bridge between the page realm
// and the service worker (design §4.2/F3). Strict channel + source checks;
// the page cannot reach `browser.runtime` itself.

import { browser } from 'wxt/browser';
import {
  OC_EVENT_CHANNEL,
  OC_REPLY_CHANNEL,
  OC_REQUEST_CHANNEL,
  type OcEventMessage,
  type OcReplyMessage,
  type OcRequestMessage,
} from '../lib/protocol';

export default defineContentScript({
  matches: ['http://*/*', 'https://*/*'],
  runAt: 'document_start',
  main() {
    // Inject the in-page provider (unlisted script, web_accessible_resources).
    // At `document_start` the <head> may not exist yet — fall back to the
    // document element (classic document_start pitfall).
    const script = document.createElement('script');
    script.src = browser.runtime.getURL('/injected.js');
    (document.head ?? document.documentElement).prepend(script);

    // Page → worker: relay only well-formed requests on our channel.
    window.addEventListener('message', (event: MessageEvent) => {
      if (event.source !== window) return; // same-frame only
      const data = event.data as OcRequestMessage | undefined;
      if (!data || typeof data !== 'object' || data.channel !== OC_REQUEST_CHANNEL) return;
      if (typeof data.id !== 'string' || typeof data.method !== 'string') return;
      void browser.runtime
        .sendMessage({ type: 'oc:request', id: data.id, method: data.method, params: data.params })
        .then((response: { result?: unknown; error?: { code: number; message: string; data?: unknown } } | undefined) => {
          const reply: OcReplyMessage = {
            channel: OC_REPLY_CHANNEL,
            id: data.id,
            result: response?.result,
            error: response?.error,
          };
          window.postMessage(reply, '*');
        })
        .catch((error: unknown) => {
          const reply: OcReplyMessage = {
            channel: OC_REPLY_CHANNEL,
            id: data.id,
            error: { code: 4900, message: error instanceof Error ? error.message : String(error) },
          };
          window.postMessage(reply, '*');
        });
    });

    // Worker → page: relay provider events.
    browser.runtime.onMessage.addListener((message: { type?: string; event?: string; data?: unknown }) => {
      if (message?.type !== 'oc:event') return;
      const relay: OcEventMessage = {
        channel: OC_EVENT_CHANNEL,
        event: (message.event ?? 'disconnect') as OcEventMessage['event'],
        data: message.data,
      };
      window.postMessage(relay, '*');
    });
  },
});
