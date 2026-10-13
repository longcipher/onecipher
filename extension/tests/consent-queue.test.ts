// Consent-queue invariants (design §4.4, INV-2/3/4 + F5/F6/F7).

import { describe, expect, it, vi } from 'vitest';
import { ConsentQueue, type ConsentExecutor } from '../src/lib/consent/queue';
import { rpcError, type PendingActionView } from '../src/lib/protocol';

function makeQueue(executor: Partial<ConsentExecutor> = {}) {
  const notifications: number[] = [];
  let drained = 0;
  const full: ConsentExecutor = {
    validate: async () => undefined,
    assess: async () => ({ policy: null, simulation: null }),
    execute: async () => ({ ok: true }),
    ...executor,
  };
  const queue = new ConsentQueue(full, {
    now: () => Date.now(),
    onEnqueue: async () => {
      notifications.push(Date.now());
    },
    onDrain: () => {
      drained += 1;
    },
    ttlMs: 60_000,
  });
  return { queue, notifications, drainedCount: () => drained };
}

const sample = (origin = 'https://dapp.example') => ({
  kind: 'sign_message' as const,
  origin,
  ocwp: { method: 'oc_sign_message', params: { account_id: 'eip155:1', message: 'aGVsbG8=' } },
  view: { title: 'Sign message', summary: 'Sign message text', fields: [], warnings: [] },
});

describe('ConsentQueue', () => {
  it('leaves the dApp promise unsettled until a decision (F5)', async () => {
    const { queue } = makeQueue();
    let settled = false;
    const promise = queue.enqueue(sample()).then((value) => {
      settled = true;
      return value;
    });
    await vi.waitFor(() => expect(queue.size).toBe(1));
    expect(settled).toBe(false);
    const action = queue.list()[0]!;
    await queue.approve(action.id);
    expect(await promise).toEqual({ ok: true });
    expect(settled).toBe(true);
    expect(queue.size).toBe(0);
  });

  it('attaches an advisory assessment before the user decides (design §4.8)', async () => {
    const { queue } = makeQueue({
      assess: async () => ({
        policy: {
          decision: 'allow' as const,
          reasons: [],
          matched_policy_ids: ['p1'],
        },
        simulation: { ok: false, revertReason: 'reverted' },
      }),
    });
    void queue.enqueue(sample()).catch(() => undefined);
    await vi.waitFor(() => expect(queue.size).toBe(1));
    const action = await vi.waitFor(() => {
      const current = queue.list()[0]!;
      expect(current.assessment).not.toBeUndefined();
      return current;
    });
    expect(action.assessment?.policy?.matched_policy_ids).toEqual(['p1']);
    expect(action.assessment?.simulation?.revertReason).toBe('reverted');
    queue.decline(action.id);
  });

  it('keeps the request visible when the advisory assessment fails', async () => {
    const { queue } = makeQueue({
      assess: async () => {
        throw new Error('preview unavailable');
      },
    });
    void queue.enqueue(sample()).catch(() => undefined);
    await vi.waitFor(() => expect(queue.size).toBe(1));
    const action = await vi.waitFor(() => {
      const current = queue.list()[0]!;
      expect(current.assessment).not.toBeUndefined();
      return current;
    });
    // A failed preview must not hide the request; the approve-time check is
    // the authoritative one.
    expect(action.assessment).toEqual({ policy: null, simulation: null });
    queue.decline(action.id);
  });

  it('still approves when only the enqueue-time assessment failed', async () => {
    let calls = 0;
    const { queue } = makeQueue({
      assess: async () => {
        calls += 1;
        // The daemon is reachable at enqueue time but fails at approve time.
        if (calls === 1) throw new Error('transient');
        return { policy: { decision: 'allow' as const, reasons: [], matched_policy_ids: [] }, simulation: null };
      },
    });
    const promise = queue.enqueue(sample());
    await vi.waitFor(() => expect(queue.size).toBe(1));
    await queue.approve(queue.list()[0]!.id);
    expect(await promise).toEqual({ ok: true });
  });

  it('executes exactly once under concurrent double approval (F6/INV-3)', async () => {
    let executions = 0;
    const { queue } = makeQueue({
      execute: async () => {
        executions += 1;
        await new Promise((resolve) => setTimeout(resolve, 10));
        return 'result';
      },
    });
    const promise = queue.enqueue(sample());
    await vi.waitFor(() => expect(queue.size).toBe(1));
    const action = queue.list()[0]!;
    await Promise.all([queue.approve(action.id), queue.approve(action.id)]);
    expect(await promise).toBe('result');
    expect(executions).toBe(1);
  });

  it('rejects with 4001 on decline', async () => {
    const { queue } = makeQueue();
    const promise = queue.enqueue(sample());
    await vi.waitFor(() => expect(queue.size).toBe(1));
    const action = queue.list()[0]!;
    queue.decline(action.id);
    await expect(promise).rejects.toMatchObject({ code: 4001, message: 'User rejected the request' });
    expect(queue.size).toBe(0);
  });

  it('runs validate/assess AFTER consumption so revoked approvals fail (F7/INV-4)', async () => {
    let revoked = false;
    const executed: string[] = [];
    const { queue } = makeQueue({
      validate: async () => {
        if (revoked) throw rpcError(4100, 'Origin authorization was revoked');
      },
      execute: async () => {
        executed.push('run');
        return null;
      },
    });
    const promise = queue.enqueue(sample());
    await vi.waitFor(() => expect(queue.size).toBe(1));
    const action = queue.list()[0]!;
    revoked = true;
    await expect(queue.approve(action.id).then(() => promise)).rejects.toMatchObject({ code: 4100 });
    expect(executed).toEqual([]);
  });

  it('maps a policy deny to the denial error with the verdict attached (INV-4)', async () => {
    const { queue } = makeQueue({
      assess: async () => ({
        policy: {
          decision: 'deny' as const,
          reasons: [{ code: 'policy', message: 'budget exceeded' }],
          matched_policy_ids: ['p1'],
        },
        simulation: null,
      }),
    });
    const promise = queue.enqueue(sample());
    await vi.waitFor(() => expect(queue.size).toBe(1));
    const action = queue.list()[0]!;
    await expect(queue.approve(action.id).then(() => promise)).rejects.toMatchObject({
      code: 4300,
      data: { decision: 'deny' },
    });
  });

  it('expires pending actions after the TTL', async () => {
    vi.useFakeTimers();
    try {
      const { queue } = makeQueue();
      // Attach the rejection handler before advancing the clock: the TTL
      // timer rejects the dApp promise synchronously, and an unobserved
      // rejection escapes as an unhandled error that can mask real failures.
      const promise = queue.enqueue(sample());
      const settled = expect(promise).rejects.toMatchObject({
        code: 4001,
        message: 'Approval window expired',
      });
      await vi.waitFor(() => expect(queue.size).toBe(1));
      await vi.advanceTimersByTimeAsync(61_000);
      await settled;
      expect(queue.size).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });

  it('rejects immediately when the notification window cannot open', async () => {
    const queue = new ConsentQueue(
      {
        validate: async () => undefined,
        assess: async () => ({ policy: null, simulation: null }),
        execute: async () => null,
      },
      {
        now: () => Date.now(),
        onEnqueue: async () => {
          throw new Error('no window');
        },
        onDrain: () => undefined,
      },
    );
    await expect(queue.enqueue(sample())).rejects.toMatchObject({ code: 4001 });
    expect(queue.size).toBe(0);
  });

  it('signals drain when the queue empties (window auto-close, F14)', async () => {
    const { queue, drainedCount } = makeQueue();
    const promise = queue.enqueue(sample());
    await vi.waitFor(() => expect(queue.size).toBe(1));
    const action = queue.list()[0]!;
    await queue.approve(action.id);
    await promise;
    expect(drainedCount()).toBe(1);
    // The list view never exposes resolve/reject/timer internals.
    const view: PendingActionView = queue.list()[0] ?? ({} as PendingActionView);
    expect(Object.keys(view)).not.toContain('resolve');
    expect(Object.keys(view)).not.toContain('reject');
  });
});
