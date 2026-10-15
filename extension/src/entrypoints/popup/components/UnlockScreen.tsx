// Unlock screen: wallet + passphrase → oc_unlock (daemon-side session).

import { useState } from 'react';
import { unlock } from '../api';

export function UnlockScreen(props: { onUnlocked: () => Promise<void>; onError: (message: string) => void }) {
  const [wallet, setWallet] = useState('default');
  const [passphrase, setPassphrase] = useState('');
  const [busy, setBusy] = useState(false);

  const submit = async () => {
    if (busy || passphrase.length === 0) return;
    setBusy(true);
    try {
      await unlock(wallet, passphrase);
      props.onError('');
      await props.onUnlocked();
    } catch (cause) {
      props.onError(cause instanceof Error ? cause.message : String(cause));
      // Clear the passphrase on failure so re-typing is required —
      // a failed unlock hint must never stay in the field for a shoulder-surfer.
      setPassphrase('');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section>
      <label className="field">
        <span>Wallet</span>
        <input value={wallet} onChange={(event) => setWallet(event.target.value)} disabled={busy} />
      </label>
      <label className="field">
        <span>Passphrase</span>
        <input
          type="password"
          value={passphrase}
          onChange={(event) => setPassphrase(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === 'Enter' && passphrase.length > 0 && !busy) void submit();
          }}
          disabled={busy}
          autoFocus
        />
      </label>
      <button disabled={busy || passphrase.length === 0} onClick={() => void submit()}>
        {busy ? 'Unlocking…' : 'Unlock'}
      </button>
      <p className="muted">
        Keys never leave the OneCipher daemon — the extension only holds a
        session handle that expires automatically.
      </p>
    </section>
  );
}
