// Popup-side API: every call goes through the popup:request runtime envelope
// (sender-authenticated by the router — INV-6).

import { browser } from 'wxt/browser';
import type { PopupMethod, PopupState } from '../../lib/protocol';

export class PopupApiError extends Error {
  constructor(
    readonly code: number,
    message: string,
  ) {
    super(message);
  }
}

export async function popupCall<T>(method: PopupMethod, params: Record<string, unknown> = {}): Promise<T> {
  const response = (await browser.runtime.sendMessage({ type: 'popup:request', method, params })) as
    | { error?: { code: number; message: string } }
    | T;
  if (response !== null && typeof response === 'object' && 'error' in (response as object)) {
    const error = (response as { error: { code: number; message: string } }).error;
    throw new PopupApiError(error.code, error.message);
  }
  return response as T;
}

export function getState(): Promise<PopupState> {
  return popupCall<PopupState>('popup_getState');
}

export function unlock(wallet: string, passphrase: string): Promise<unknown> {
  return popupCall('popup_unlock', { wallet, passphrase });
}

export function lock(): Promise<void> {
  return popupCall('popup_lock');
}

export function approveAction(id: string): Promise<void> {
  return popupCall('popup_approveAction', { id });
}

export function declineAction(id: string, reason?: string): Promise<void> {
  return popupCall('popup_declineAction', { id, reason });
}

export function switchChain(chainId: string): Promise<string> {
  return popupCall('popup_switchChain', { chainId });
}

export function revokeSite(origin: string): Promise<void> {
  return popupCall('popup_revokeSite', { origin });
}

export function setDaemonUrl(url: string): Promise<string> {
  return popupCall('popup_setDaemonUrl', { url });
}

export function activity(limit = 50): Promise<unknown[]> {
  return popupCall('popup_activity', { limit });
}

export function registerPasskey(): Promise<{ registered: boolean; credentialId: string }> {
  return popupCall('popup_registerPasskey');
}
