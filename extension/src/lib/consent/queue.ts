// Consent queue — the per-request human approval core (design §4.4).
//
// Guarantees (INV-2/3/4):
//  - the dApp promise never settles before an explicit decision;
//  - approve consumes the entry BEFORE awaiting anything (double clicks and
//    concurrent approvals cannot execute a request twice);
//  - at approve time the executor re-validates session/site/policy, so stale
//    or revoked approvals are rejected;
//  - TTL expiry rejects with CODE_USER_REJECTED ("Approval window expired").
//
// The queue itself is transport-agnostic: the caller injects an `Executor`
// (daemon calls) and a `Deps` (clock + notification window opener), which
// keeps this module unit-testable without a browser.

import {
  APPROVAL_TTL_MS,
  CODE_POLICY_DENIED,
  CODE_USER_REJECTED,
  rpcError,
  type ConsentAssessment,
  type ConsentKind,
  type ConsentView,
  type PendingActionView,
  type RpcErrorShape,
} from '../protocol';

export interface EnqueueInput {
  kind: ConsentKind;
  origin: string;
  ocwp: { method: string; params: Record<string, unknown> };
  view: ConsentView;
}

export interface PendingAction extends PendingActionView {
  resolve: (result: unknown) => void;
  reject: (error: RpcErrorShape) => void;
  timer: ReturnType<typeof setTimeout> | null;
}

/// Approval-time pipeline. `validate` and `assess` run AFTER the entry is
/// consumed but BEFORE `execute`, so a revoked session/site/policy can no
/// longer act on a stale approval.
export interface ConsentExecutor {
  validate(action: PendingAction): Promise<void>;
  /// Policy verdict + dry-run result. Called at enqueue time (advisory badge)
  /// and again at approve time (the check that actually gates).
  assess(action: PendingAction): Promise<ConsentAssessment>;
  execute(action: PendingAction): Promise<unknown>;
}

export interface QueueDeps {
  now(): number;
  onEnqueue(): Promise<void>;
  onDrain(): void;
  ttlMs?: number;
}

export class ConsentQueue {
  private readonly pending = new Map<string, PendingAction>();
  private nextId = 0;

  constructor(
    private readonly executor: ConsentExecutor,
    private readonly deps: QueueDeps,
  ) {}

  /// Enqueue a request and return the promise the dApp awaits.
  ///
  /// The policy verdict and simulation are computed *before* the notification
  /// window renders (design §4.8), so the user approves with the badge and
  /// dry-run result already on screen rather than discovering them afterwards.
  async enqueue(input: EnqueueInput): Promise<unknown> {
    const id = `oc-${this.deps.now()}-${++this.nextId}-${Math.random().toString(36).slice(2, 8)}`;
    const expiresAt = this.deps.now() + (this.deps.ttlMs ?? APPROVAL_TTL_MS);
    const settled = new Promise<unknown>((resolve, reject) => {
      const action: PendingAction = { id, ...input, expiresAt, resolve, reject, timer: null };
      action.timer = setTimeout(() => this.expire(id), expiresAt - this.deps.now());
      this.pending.set(id, action);
      // The notification window must open for the user to decide; if it
      // cannot, fail the request instead of leaving the promise hanging.
      void this.deps
        .onEnqueue()
        .catch((error: unknown) => {
          this.remove(id);
          reject(rpcError(CODE_USER_REJECTED, `Could not open the approval window: ${String(error)}`));
        });
    });
    void this.assess(id);
    return settled;
  }

  /// Compute the advisory policy verdict + simulation for a pending action and
  /// attach it to the snapshot the popup renders. Purely informational: it
  /// never settles the dApp promise and never authorizes anything (INV-2).
  async assess(id: string): Promise<ConsentAssessment | null> {
    const action = this.pending.get(id);
    if (!action) return null;
    let assessment: ConsentAssessment;
    try {
      assessment = await this.executor.assess(action);
    } catch {
      // A failed preview must not hide the request; the approve-time check
      // is the authoritative one.
      assessment = { policy: null, simulation: null, riskBadges: [] };
    }
    if (this.pending.get(id) === action) action.assessment = assessment;
    return assessment;
  }

  /// User approved. Single-consumption: remove first, then await.
  async approve(id: string): Promise<void> {
    const action = this.pending.get(id);
    if (!action) return; // already consumed (double click / race)
    this.remove(id);
    try {
      await this.executor.validate(action);
      // Re-run the policy check at click time. The enqueue-time badge is
      // advisory; this is the one that gates (INV-4).
      const { policy } = await this.executor.assess(action);
      if (policy && policy.decision === 'deny') {
        const reason = policy.reasons[0]?.message ?? 'denied by policy';
        action.reject(rpcError(CODE_POLICY_DENIED, reason, policy));
        return;
      }
      const result = await this.executor.execute(action);
      action.resolve(result);
    } catch (error) {
      action.reject(toRpcError(error));
    }
  }

  /// User rejected.
  decline(id: string, reason?: string): void {
    const action = this.pending.get(id);
    if (!action) return;
    this.remove(id);
    action.reject(rpcError(CODE_USER_REJECTED, reason ?? 'User rejected the request'));
  }

  /// TTL expiry — equivalent to a rejection ("Approval window expired").
  expire(id: string): void {
    this.decline(id, 'Approval window expired');
  }

  /// Snapshot for the notification UI (no resolve/reject exposure).
  list(): PendingActionView[] {
    return [...this.pending.values()].map(toView);
  }

  get(id: string): PendingActionView | undefined {
    const action = this.pending.get(id);
    return action ? toView(action) : undefined;
  }

  get size(): number {
    return this.pending.size;
  }

  private remove(id: string): void {
    const action = this.pending.get(id);
    if (action?.timer) clearTimeout(action.timer);
    this.pending.delete(id);
    if (this.pending.size === 0) this.deps.onDrain();
  }
}

/// Strip the settlement handles so a snapshot cannot be used to settle a
/// dApp promise by itself.
function toView({ resolve: _r, reject: _j, timer: _t, ...view }: PendingAction): PendingActionView {
  return view;
}

export function toRpcError(error: unknown): RpcErrorShape {
  if (error !== null && typeof error === 'object' && 'code' in error && 'message' in error) {
    return error as RpcErrorShape;
  }
  return rpcError(-32603, error instanceof Error ? error.message : String(error));
}
