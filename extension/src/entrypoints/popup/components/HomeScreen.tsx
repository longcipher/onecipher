// Wallet home: accounts + balances + chain selector + connected sites + recent
// activity (design §4.8).
//
// The chain selector is driven by the `chains` list the daemon reported, not a
// hardcoded table — otherwise a chain added via `wallet_addEthereumChain` or a
// custom `chains.json` entry would be unreachable from the UI (design §4.10).

import { useEffect, useState } from 'react';
import type { PopupState } from '../../../lib/protocol';
import { formatWei } from '../../../lib/consent/decode';
import { activity, lock, revokeSite, switchChain } from '../api';

export function HomeScreen(props: {
  state: PopupState;
  onRefresh: () => Promise<void>;
  onOpenSettings: () => void;
  onError: (message: string) => void;
}) {
  const { state, onRefresh, onOpenSettings, onError } = props;
  const [tab, setTab] = useState<'accounts' | 'sites' | 'activity'>('accounts');
  const [events, setEvents] = useState<unknown[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const session = state.session;
  if (!session) return null;

  useEffect(() => {
    if (tab !== 'activity') return;
    void activity()
      .then(setEvents)
      .catch((cause: unknown) => onError(cause instanceof Error ? cause.message : String(cause)));
  }, [tab, onError]);

  const expiresIn = Math.max(0, session.expiresAtUnix - Math.floor(Date.now() / 1000));
  const chains = state.chains.length > 0 ? state.chains : ['eip155:1'];
  const balanceFor = (chainId: string): string | null =>
    state.balances.find((entry) => entry.chainId === chainId)?.wei ?? null;
  // Policy summary for the active wallet (design §4.8): what the user's own
  // thresholds are, so a consent badge is never the first they hear of them.
  const threshold = state.warnThresholdWei ?? '';

  const call = async (label: string, fn: () => Promise<unknown>) => {
    setBusy(label);
    try {
      await fn();
      await onRefresh();
    } catch (cause: unknown) {
      onError(cause instanceof Error ? cause.message : String(cause));
    } finally {
      setBusy(null);
    }
  };

  return (
    <section>
      <p className="muted session-line">
        <strong>{session.wallet}</strong> · unlocked · expires in {Math.floor(expiresIn / 60)}m
        {expiresIn % 60}s
      </p>

      <nav className="tabs">
        {(['accounts', 'sites', 'activity'] as const).map((entry) => (
          <button
            key={entry}
            className={tab === entry ? 'active' : ''}
            onClick={() => setTab(entry)}
          >
            {entry === 'accounts' ? 'Accounts' : entry === 'sites' ? 'Sites' : 'Activity'}
          </button>
        ))}
      </nav>

      {tab === 'accounts' && (
        <>
          <label className="field">
            <span>Default chain</span>
            <select
              value={chains.includes(state.activeChainId) ? state.activeChainId : ''}
              disabled={busy !== null}
              onChange={(event) => {
                void call('switch', () => switchChain(event.target.value));
              }}
            >
              {/* Keep an option for a chain the daemon did not report, so a
                  stored value never renders as a blank selector. */}
              {!chains.includes(state.activeChainId) && (
                <option value={state.activeChainId}>{state.activeChainId}</option>
              )}
              {chains.map((chainId) => (
                <option key={chainId} value={chainId}>
                  {chainId}
                </option>
              ))}
            </select>
          </label>
          <ul className="accounts">
            {state.accounts.map((account) => {
              const balance = balanceFor(account.chain_id);
              const isActive = account.chain_id === state.activeChainId;
              return (
                <li key={`${account.chain_id}:${account.address}`}>
                  <span className="code">{shorten(account.address)}</span>
                  <span className="muted">
                    {account.chain_id}
                    {isActive && <span className="badge-pill">active</span>} · {balance === null ? '—' : formatWei(balance)}
                  </span>
                </li>
              );
            })}
          </ul>
          {threshold !== '' && (
            <p className="muted policy-summary">
              Warns above {formatWei(threshold)} to a first-time recipient
              {state.verifiedContracts !== undefined &&
                ` · ${state.verifiedContracts.length} verified contract(s)`}
            </p>
          )}
          <button
            className="ghost"
            disabled={busy !== null}
            onClick={() => void call('lock', lock)}
          >
            {busy === 'lock' ? 'Locking…' : 'Lock'}
          </button>
        </>
      )}

      {tab === 'sites' && (
        <>
          {state.sites.length === 0 && <p className="muted">No connected sites.</p>}
          <ul className="sites">
            {state.sites.map((site) => (
              <li key={site.origin}>
                <span className="code">{site.origin}</span>
                <span className="muted">{site.chain_id}</span>
                <button
                  className="ghost danger"
                  disabled={busy !== null}
                  onClick={() => void call(`revoke:${site.origin}`, () => revokeSite(site.origin))}
                >
                  {busy === `revoke:${site.origin}` ? '…' : 'Revoke'}
                </button>
              </li>
            ))}
          </ul>
        </>
      )}

      {tab === 'activity' && (
        <ul className="activity">
          {events.length === 0 && <p className="muted">No audit events.</p>}
          {events.slice(0, 20).map((event, index) => (
            <li key={index}>
              <span className="muted">{eventKind(event)}</span>
              <span className="code event-detail">{eventDetail(event)}</span>
            </li>
          ))}
        </ul>
      )}

      <button className="ghost settings-link" onClick={onOpenSettings}>
        ⚙ Settings
      </button>
    </section>
  );
}

function shorten(address: string): string {
  return address.length <= 14 ? address : `${address.slice(0, 8)}…${address.slice(-6)}`;
}

function eventKind(event: unknown): string {
  if (event !== null && typeof event === 'object') {
    const record = event as Record<string, unknown>;
    const kind = record['event_type'] ?? record['type'] ?? record['op'] ?? 'entry';
    return String(kind);
  }
  return String(event);
}

function eventDetail(event: unknown): string {
  if (event !== null && typeof event === 'object') {
    const record = event as Record<string, unknown>;
    const wallet = record['wallet_id'] ?? record['wallet'] ?? '';
    const method = record['method'] ?? record['tx_hash'] ?? record['origin'] ?? '';
    const parts = [wallet, method].filter((part) => part !== '');
    return parts.join(' · ');
  }
  return '';
}
