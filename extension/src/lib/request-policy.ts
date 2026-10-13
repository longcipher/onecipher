// Sender authentication — direct port of the reference project's
// `request-policy.ts` (design §4.5, F8/F9). Every check uses Chrome-provided
// sender fields, which a page cannot forge.

import { CODE_UNAUTHORIZED, rpcError, type RpcErrorShape } from './protocol';

/// Minimal structural shape of `browser.runtime.MessageSender`.
export interface SenderLike {
  id?: string;
  url?: string;
  origin?: string;
  tab?: { id?: number } | null;
}

export interface ValidatedOrigin {
  origin: string;
  tabId: number | undefined;
}

function unauthorized(message: string): RpcErrorShape {
  return rpcError(CODE_UNAUTHORIZED, message);
}

/// Validate a dApp request sender: it MUST be a web page reached through this
/// extension's own content script. Returns the site origin for consent UI and
/// site-authorization bookkeeping.
///
/// - `sender.id` must equal our extension id (Chrome-provided).
/// - `sender.tab.id` must be present (content scripts always have one; popup
///   and other extension pages do not).
/// - `sender.url` must be http(s); opaque `about:`/`chrome-extension:` senders
///   are rejected.
/// - `sender.origin` (when present) must equal the URL origin exactly —
///   mismatched or `"null"` (sandboxed iframe) origins are rejected.
export function providerOrigin(sender: SenderLike, extensionId: string): ValidatedOrigin {
  if (sender.id !== extensionId || sender.tab?.id === undefined || !sender.url) {
    throw unauthorized(
      'Wallet requests must come from a web page via this extension content script',
    );
  }
  let url: URL;
  try {
    url = new URL(sender.url);
  } catch {
    throw unauthorized('Invalid wallet request origin');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw unauthorized('Wallet requests must originate from http(s) pages');
  }
  if (sender.origin !== undefined) {
    if (sender.origin === 'null') {
      throw unauthorized('Sandboxed (opaque) origins are not allowed');
    }
    if (sender.origin !== url.origin) {
      throw unauthorized('Request origin does not match sender URL');
    }
  }
  return { origin: url.origin, tabId: sender.tab.id };
}

/// Validate a popup/notification command sender: only the extension's own
/// `popup.html` page may drive approvals. The check is exact — protocol +
/// host + pathname — so `popup.html.evil` and web-hosted lookalikes fail.
export function requirePopupSender(
  sender: SenderLike,
  extensionId: string,
  popupUrl: string,
): void {
  let expected: URL;
  try {
    expected = new URL(popupUrl);
  } catch {
    throw unauthorized('Popup commands are restricted to the wallet popup');
  }
  let actual: URL;
  try {
    actual = new URL(sender.url ?? '');
  } catch {
    throw unauthorized('Popup commands are restricted to the wallet popup');
  }
  const expectedOrigin = `${expected.protocol}//${expected.host}`;
  const same =
    sender.id === extensionId &&
    (sender.origin === undefined || sender.origin === expectedOrigin) &&
    actual.protocol === expected.protocol &&
    actual.host === expected.host &&
    actual.pathname === expected.pathname;
  if (!same) {
    throw unauthorized('Popup commands are restricted to the wallet popup');
  }
}
