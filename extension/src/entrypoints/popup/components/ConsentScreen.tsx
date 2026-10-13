// Consent queue UI — the notification window's whole surface (design §4.8).
// Guarantees mirrored from the reference project (F14/F15):
//  - the window closes itself when the queue drains;
//  - session expiry mid-queue renders an inline unlock form and the
//    retained action is approved right after unlock;
//  - a render-race guard prevents async state refreshes from clobbering the
//    unlock form mid-interaction.

import { useCallback, useEffect, useState } from 'react';
import type {
  ConsentAssessment,
  PendingActionView,
  PopupState,
  RiskBadge,
} from '../../../lib/protocol';
import { consentBadges } from '../../../lib/consent/policy-view';
import { approveAction, declineAction, getState, unlock } from '../api';

export function ConsentScreen(props: {
  state: PopupState;
  onRefresh: () => Promise<void>;
  onError: (message: string) => void;
}) {
  const { state, onRefresh, onError } = props;
  const [busyId, setBusyId] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [unlockingFor, setUnlockingFor] = useState<string | null>(null);
  const [passphrase, setPassphrase] = useState('');
  const [wallet, setWallet] = useState('default');
  // Render-race guard (F15): a queued stateChanged refresh must not clobber
  // the one-time unlock form.
  const showingUnlock = unlockingFor !== null;

  const refresh = useCallback(async () => {
    if (showingUnlock) return;
    const next = await getState();
    if (showingUnlock) return; // refresh started before the form opened
    Object.assign(state, next);
    await onRefresh();
  }, [onRefresh, showingUnlock, state]);

  useEffect(() => {
    const interval = window.setInterval(() => {
      void refresh().catch(() => undefined);
    }, 1000);
    return () => window.clearInterval(interval);
  }, [refresh]);

  const pending = state.pendingActions;

  useEffect(() => {
    if (pending.length === 0 && !showingUnlock) {
      // Queue drained: close the notification window (F14).
      window.close();
    }
  }, [pending.length, showingUnlock]);

  const decide = useCallback(
    async (action: PendingActionView, approve: boolean) => {
      setBusyId(action.id);
      setActionError(null);
      try {
        if (approve) {
          await approveAction(action.id);
        } else {
          await declineAction(action.id);
        }
        setUnlockingFor(null);
        await onRefresh();
      } catch (cause) {
        const message = cause instanceof Error ? cause.message : String(cause);
        if (message.includes('locked')) {
          setUnlockingFor(action.id);
        } else {
          setActionError(message);
        }
      } finally {
        setBusyId(null);
      }
    },
    [onRefresh],
  );

  const submitUnlock = useCallback(async () => {
    if (unlockingFor === null) return;
    try {
      await unlock(wallet, passphrase);
      const actionId = unlockingFor;
      setUnlockingFor(null);
      setPassphrase('');
      await onRefresh();
      // Continue the approval that was waiting for the unlock (design §4.4).
      await approveAction(actionId).catch((cause: unknown) => {
        setActionError(cause instanceof Error ? cause.message : String(cause));
      });
      await onRefresh();
    } catch (cause) {
      setActionError(cause instanceof Error ? cause.message : String(cause));
    }
  }, [onRefresh, unlockingFor, passphrase, wallet]);

  return (
    <main className="app consent">
      <h1>OneCipher Wallet</h1>
      {actionError !== null && <p className="error">{actionError}</p>}
      {unlockingFor !== null ? (
        <section className="card">
          <h2>Session expired</h2>
          <p className="muted">Unlock to approve the pending request.</p>
          <label className="field">
            <span>Wallet</span>
            <input value={wallet} onChange={(event) => setWallet(event.target.value)} />
          </label>
          <label className="field">
            <span>Passphrase</span>
            <input
              type="password"
              value={passphrase}
              onChange={(event) => setPassphrase(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === 'Enter') void submitUnlock();
              }}
            />
          </label>
          <button onClick={() => void submitUnlock()}>Unlock &amp; approve</button>
          <button
            className="ghost"
            onClick={() => {
              const actionId = unlockingFor;
              setUnlockingFor(null);
              if (actionId) void declineAction(actionId).then(onRefresh);
            }}
          >
            Cancel request
          </button>
        </section>
      ) : (
        <>
          {pending.length === 0 && <p className="muted">No pending requests.</p>}
          {pending.map((action) => (
            <ActionCard
              key={action.id}
              action={action}
              busy={busyId === action.id}
              onDecide={decide}
            />
          ))}
        </>
      )}
    </main>
  );
}

/// Policy verdict + dry-run result (design §4.8/§4.9).
///
/// The badge is ADVISORY. A green badge never authorizes anything (INV-2) and
/// a red one does not bypass the user: the daemon re-evaluates at approve time
/// and that is what actually gates (INV-4).
function AssessmentBadges(props: { assessment?: ConsentAssessment | null }) {
  const { assessment } = props;
  if (!assessment) {
    return <p className="badge muted">Checking policy…</p>;
  }
  // Order matters: the worst thing on the page should be the first thing read.
  const badges: RiskBadge[] = [
    ...consentBadges(assessment.policy, assessment.simulation, assessment.tx ?? null, null),
    ...(assessment.riskBadges ?? []),
  ];
  if (badges.length === 0) {
    return <p className="badge muted">No policy or simulation data available.</p>;
  }
  return (
    <>
      {badges.map((badge, index) => (
        <p className={`badge ${badge.level}`} key={index}>
          {badge.label}
        </p>
      ))}
    </>
  );
}

function ActionCard(props: {
  action: PendingActionView;
  busy: boolean;
  onDecide: (action: PendingActionView, approve: boolean) => Promise<void>;
}) {
  const { action, busy, onDecide } = props;
  const [remaining, setRemaining] = useState(() => Math.max(0, action.expiresAt - Date.now()));
  useEffect(() => {
    const timer = window.setInterval(
      () => setRemaining(Math.max(0, action.expiresAt - Date.now())),
      500,
    );
    return () => window.clearInterval(timer);
  }, [action.expiresAt]);

  return (
    <section className="card">
      <h2>{action.view.title}</h2>
      <p className="origin">{action.origin}</p>
      <p>{action.view.summary}</p>
      <AssessmentBadges assessment={action.assessment} />
      <dl className="fields">
        {action.view.fields.map((field, index) => (
          <div className="field-row" key={index}>
            <dt>{field.label}</dt>
            <dd className={field.kind ?? 'text'}>{field.value}</dd>
          </div>
        ))}
      </dl>
      {action.view.warnings.map((warning, index) => (
        <p className="warning" key={index}>
          ⚠ {warning}
        </p>
      ))}
      <p className="muted countdown">Expires in {Math.ceil(remaining / 1000)}s</p>
      <div className="actions">
        <button className="approve" disabled={busy} onClick={() => void onDecide(action, true)}>
          Approve
        </button>
        <button className="reject" disabled={busy} onClick={() => void onDecide(action, false)}>
          Reject
        </button>
      </div>
    </section>
  );
}
