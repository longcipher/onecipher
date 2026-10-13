// Wallet home: accounts + chain selector + connected sites + recent activity.

import { useEffect, useState } from 'react';
import type { PopupState } from '../../../lib/protocol';
import { activity, lock, revokeSite, switchChain } from '../api';

const CHAIN_CHOICES = [
  { chain_id: 'eip155:1', name: 'Ethereum' },
  { chain_id: 'eip155:8453', name: 'Base' },
  { chain_id: 'eip155:56', name: 'BSC' },
  { chain_id: 'eip155:42161', name: 'Arbitrum' },
  { chain_id: 'eip155:10', name: 'OP Mainnet' },
  { chain_id: 'eip155:137', name: 'Polygon' },
];

export function HomeScreen(props: {
  state: PopupState;
  onRefresh: () => Promise<void>;
  onOpenSettings: () => void;
  onError: (message: string) => void;
}) {
  const { state, onRefresh, onOpenSettings, onError } = props;
  const [tab, setTab] = useState<'accounts' | 'sites' | 'activity'>('accounts');
  const [events, setEvents] = useState<unknown[]>([]);
  const session = state.session;
  if (!session) return null;

  useEffect(() => {
    if (tab !== 'activity') return;
    void activity()
      .then(setEvents)
      .catch((cause: unknown) => onError(cause instanceof Error ? cause.message : String(cause)));
  }, [tab, onError]);

  const expiresIn = Math.max(0, session.expiresAtUnix - Math.floor(Date.now() / 1000));

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
            <span>Chain</span>
            <select
              value={state.activeChainId}
              onChange={(event) => {
                void switchChain(event.target.value)
                  .then(onRefresh)
                  .catch((cause: unknown) =>
                    onError(cause instanceof Error ? cause.message : String(cause)),
                  );
              }}
            >
              {CHAIN_CHOICES.map((chain) => (
                <option key={chain.chain_id} value={chain.chain_id}>
                  {chain.name}
                </option>
              ))}
              {state.accounts
                .filter((account) => !CHAIN_CHOICES.some((choice) => choice.chain_id === account.chain_id))
                .map((account) => (
                  <option key={account.chain_id} value={account.chain_id}>
                    {account.chain_id}
                  </option>
                ))}
            </select>
          </label>
          <ul className="accounts">
            {state.accounts.map((account) => (
              <li key={`${account.chain_id}:${account.address}`}>
                <span className="code">{shorten(account.address)}</span>
                <span className="muted">{account.chain_id}</span>
              </li>
            ))}
          </ul>
          <button
            className="ghost"
            onClick={() => {
              void lock()
                .then(onRefresh)
                .catch((cause: unknown) => onError(cause instanceof Error ? cause.message : String(cause)));
            }}
          >
            Lock
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
                  onClick={() => {
                    void revokeSite(site.origin)
                      .then(onRefresh)
                      .catch((cause: unknown) =>
                        onError(cause instanceof Error ? cause.message : String(cause)),
                      );
                  }}
                >
                  Revoke
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
    const detail = record['wallet_id'] ?? record['method'] ?? '';
    return `${String(kind)} ${String(detail)}`.trim();
  }
  return String(event);
}
