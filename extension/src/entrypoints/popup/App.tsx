// Popup app: dual-mode (F14) — `?view=notification` renders the consent
// queue surface (notification window); otherwise the wallet home.

import { useCallback, useEffect, useState } from 'react';
import { browser } from 'wxt/browser';
import type { PopupState } from '../../lib/protocol';
import { PopupApiError, getState, registerPasskey, setDaemonUrl } from './api';
import { ConsentScreen } from './components/ConsentScreen';
import { UnlockScreen } from './components/UnlockScreen';
import { HomeScreen } from './components/HomeScreen';

type View = 'home' | 'unlock' | 'settings';

// `?view=notification` selects the consent surface via `isNotification` below;
// the two flags are independent, so a notification window can still show
// settings while a queue is pending.
function currentView(): View {
  return 'home';
}

export function App() {
  const isNotification = new URLSearchParams(window.location.search).get('view') === 'notification';
  const [state, setState] = useState<PopupState | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<View>(currentView());

  const refresh = useCallback(async () => {
    try {
      const next = await getState();
      setState(next);
      setError(next.daemonReachable ? null : 'OneCipher daemon is not reachable');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : String(cause));
    }
  }, []);

  useEffect(() => {
    void refresh();
    const interval = window.setInterval(() => void refresh(), 2000);
    return () => window.clearInterval(interval);
  }, [refresh]);

  if (state === null) {
    return (
      <main className="app">
        <p className="muted">{error ?? 'Loading…'}</p>
      </main>
    );
  }

  // Notification mode: the consent queue IS the whole screen.
  if (isNotification) {
    return (
      <ConsentScreen
        state={state}
        onRefresh={refresh}
        onError={setError}
      />
    );
  }

  if (error !== null && !state.daemonReachable) {
    return (
      <main className="app">
        <h1>OneCipher Wallet</h1>
        <p className="error">{error}</p>
        {state.daemonError && <p className="muted">probe: {state.daemonError}</p>}
        <p className="muted">
          Start the daemon with <code>onecipher daemon</code> or{' '}
          <code>onecipher wallet-rpc serve</code>, then add this extension's ID to
          the allowlist (<code>--allow-extension</code> /{' '}
          <code>OC_WALLET_RPC_EXTENSION_IDS</code>).
        </p>
      </main>
    );
  }

  const unlocked = state.session !== null;

  return (
    <main className="app">
      <header className="header">
        <h1>OneCipher Wallet</h1>
        {unlocked && (
          <button className="ghost" onClick={() => void refresh()}>
            ↻
          </button>
        )}
      </header>
      {error !== null && <p className="error">{error}</p>}
      {view === 'settings' ? (
        <SettingsView state={state} onBack={() => setView('home')} onRefresh={refresh} onError={setError} />
      ) : !unlocked ? (
        <UnlockScreen onUnlocked={() => refresh()} onError={setError} />
      ) : (
        <HomeScreen
          state={state}
          onRefresh={refresh}
          onOpenSettings={() => setView('settings')}
          onError={setError}
        />
      )}
    </main>
  );
}

function SettingsView(props: {
  state: PopupState;
  onBack: () => void;
  onRefresh: () => Promise<void>;
  onError: (message: string) => void;
}) {
  const [daemonUrl, setDaemonUrlState] = useState('');
  const [passkeyStatus, setPasskeyStatus] = useState<string | null>(null);
  useEffect(() => {
    void (async () => {
      const { loadConfig } = await import('../../lib/storage/config');
      const config = await loadConfig(browser.storage);
      setDaemonUrlState(config.daemonUrl);
    })();
  }, []);
  return (
    <section>
      <button className="ghost" onClick={props.onBack}>
        ← Back
      </button>
      <h2>Settings</h2>
      <label className="field">
        <span>Daemon URL (loopback only)</span>
        <input
          value={daemonUrl}
          onChange={(event) => setDaemonUrlState(event.target.value)}
          placeholder="http://127.0.0.1:18080"
        />
      </label>
      <button
        onClick={() => {
          void (async () => {
            try {
              const normalized = await setDaemonUrl(daemonUrl);
              setDaemonUrlState(normalized);
              props.onError('');
              await props.onRefresh();
            } catch (cause) {
              props.onError(cause instanceof Error ? cause.message : String(cause));
            }
          })();
        }}
      >
        Save daemon URL
      </button>
      <h2>Passkey step-up</h2>
      <p className="muted">
        Registers a software passkey (P-256) with the daemon for EIP-7702 confirmation.
      </p>
      <button
        onClick={() => {
          void (async () => {
            try {
              const result = await registerPasskey();
              setPasskeyStatus(`Registered: ${result.credentialId}`);
            } catch (cause) {
              props.onError(
                cause instanceof PopupApiError || cause instanceof Error ? cause.message : String(cause),
              );
            }
          })();
        }}
      >
        Register passkey
      </button>
      {passkeyStatus && <p className="muted">{passkeyStatus}</p>}
    </section>
  );
}
