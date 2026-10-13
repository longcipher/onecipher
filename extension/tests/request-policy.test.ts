// Sender-authentication matrix (design §4.5/§9.2, F8/F9/INV-5/INV-6).
// Mirrors the reference project's forged-sender matrix: every spoofed shape
// MUST be rejected with 4100.

import { describe, expect, it } from 'vitest';
import { providerOrigin, requirePopupSender, type SenderLike } from '../src/lib/request-policy';

const EXT_ID = 'abcdefghijklmnopabcdefghijklmnop';
const POPUP_URL = `chrome-extension://${EXT_ID}/popup.html`;
const WEB_ORIGIN = 'https://dapp.example';
const webSender: SenderLike = {
  id: EXT_ID,
  url: `${WEB_ORIGIN}/trade`,
  origin: WEB_ORIGIN,
  tab: { id: 1 },
};
const popupSender: SenderLike = { id: EXT_ID, url: POPUP_URL, origin: `chrome-extension://${EXT_ID}` };

describe('providerOrigin', () => {
  it('accepts a well-formed content-script sender', () => {
    expect(providerOrigin(webSender, EXT_ID)).toEqual({ origin: WEB_ORIGIN, tabId: 1 });
  });

  it('rejects other extensions, missing tabs, and missing urls', () => {
    for (const sender of [
      { ...webSender, id: 'other-extension' },
      { ...webSender, tab: undefined },
      { ...webSender, tab: null },
      { ...webSender, url: undefined },
      { id: EXT_ID },
    ] satisfies SenderLike[]) {
      expect(() => providerOrigin(sender, EXT_ID)).toThrowError(/content script/);
    }
  });

  it('rejects opaque, conflicting, and extension origins', () => {
    for (const sender of [
      { ...webSender, origin: 'null' },
      { ...webSender, origin: 'https://trusted.example' },
      { ...webSender, url: `${POPUP_URL}`, origin: undefined },
    ] satisfies SenderLike[]) {
      expect(() => providerOrigin(sender, EXT_ID)).toThrowError(/origin/i);
    }
  });

  it('rejects non-http(s) URL schemes', () => {
    expect(() =>
      providerOrigin({ ...webSender, url: 'chrome-extension://whatever/x', origin: undefined }, EXT_ID),
    ).toThrowError(/http/);
  });
});

describe('requirePopupSender', () => {
  it('accepts the extension popup page itself', () => {
    expect(() => requirePopupSender(popupSender, EXT_ID, POPUP_URL)).not.toThrow();
  });

  it('rejects lookalike URLs, webpages, other extensions, and missing urls', () => {
    for (const sender of [
      { ...popupSender, id: 'other-extension' },
      { ...popupSender, origin: WEB_ORIGIN, tab: { id: 1 } },
      { ...popupSender, url: `${POPUP_URL}.evil` },
      { ...popupSender, url: 'https://dapp.example/popup.html' },
      { ...popupSender, url: `chrome-extension://other/popup.html` },
      { id: EXT_ID },
    ] satisfies SenderLike[]) {
      expect(() => requirePopupSender(sender, EXT_ID, POPUP_URL)).toThrowError(/popup/i);
    }
  });

  it('accepts query parameters on the popup URL (notification mode)', () => {
    const notification: SenderLike = {
      id: EXT_ID,
      url: `${POPUP_URL}?view=notification`,
      origin: `chrome-extension://${EXT_ID}`,
    };
    expect(() => requirePopupSender(notification, EXT_ID, POPUP_URL)).not.toThrow();
  });
});
