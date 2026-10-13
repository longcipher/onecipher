// Risk badges (design §4.1 `policy-view.ts`, §4.8) and the EIP-6963 provider
// identity (§4.3).
//
// The three badges a user cannot derive by eye: a first-time recipient, a value
// over their own threshold, and a call to a contract they never verified. All
// advisory — INV-15 says a badge is never an authorization.

import { afterEach, describe, expect, it } from 'vitest';
import { pageUuid, providerUuid } from '../src/lib/eip6963';

afterEach(() => {
  // Keep the document-lifetime fallback from leaking between cases.
  delete (globalThis as { __oneCipherUuidFallback?: string }).__oneCipherUuidFallback;
});
import {
  consentBadges,
  normalizeAddress,
  policyBadge,
  simulationBadge,
  transactionRiskBadges,
  type RiskContext,
} from '../src/lib/consent/policy-view';
import { DEFAULT_CONFIG } from '../src/lib/storage/config';

const RECIPIENT = '0x1111111111111111111111111111111111111111';
const CONTRACT = '0x2222222222222222222222222222222222222222';

const context: RiskContext = {
  knownRecipients: [RECIPIENT.toLowerCase()],
  warnThresholdWei: DEFAULT_CONFIG.warnThresholdWei,
  verifiedContracts: [],
};

describe('policyBadge', () => {
  it('says so when the daemon could not be reached', () => {
    expect(policyBadge(null)).toEqual({
      level: 'info',
      label: 'Policy status unavailable — the daemon still enforces',
    });
  });

  it('surfaces the deny reason, not just the verdict', () => {
    const badge = policyBadge({
      decision: 'deny',
      reasons: [{ code: 'policy', message: 'budget exceeded' }],
      matched_policy_ids: ['p1'],
    });
    expect(badge.level).toBe('danger');
    expect(badge.label).toBe('Blocked by policy — budget exceeded');
  });

  it('counts matched rules when allowed', () => {
    expect(policyBadge({ decision: 'allow', reasons: [], matched_policy_ids: ['a', 'b'] })).toEqual({
      level: 'info',
      label: 'Policy allows (2 rule(s) matched)',
    });
  });
});

describe('simulationBadge', () => {
  it('omits itself when there is nothing to say', () => {
    expect(simulationBadge(null)).toBeNull();
  });

  it('treats a revert as danger and includes the reason', () => {
    expect(simulationBadge({ ok: false, revertReason: 'ERC20: bad allowance' })).toEqual({
      level: 'danger',
      label: 'Simulation reverts — ERC20: bad allowance',
    });
  });

  it('reports the gas estimate when the simulation passes', () => {
    expect(simulationBadge({ ok: true, gasUsed: '0x5208' })).toEqual({
      level: 'info',
      label: 'Simulation OK · gas ≈ 0x5208',
    });
    expect(simulationBadge({ ok: true })).toEqual({ level: 'info', label: 'Simulation OK' });
  });
});

describe('transactionRiskBadges', () => {
  it('returns nothing for a non-transaction request', () => {
    expect(transactionRiskBadges(null, context)).toEqual([]);
  });

  it('flags a first-time recipient only when value moves', () => {
    // Sending data to a new contract is routine; sending value is not.
    const valueToNew = transactionRiskBadges(
      { to: '0x9999999999999999999999999999999999999999', value: '1' },
      context,
    );
    expect(valueToNew.map((b) => b.label)).toContain('First time sending value to this recipient');

    const dataToNew = transactionRiskBadges(
      { to: '0x9999999999999999999999999999999999999999', value: '0', data: '0xdeadbeef' },
      context,
    );
    expect(dataToNew.some((b) => b.label.startsWith('First time'))).toBe(false);

    const toKnown = transactionRiskBadges({ to: RECIPIENT, value: '1' }, context);
    expect(toKnown.some((b) => b.label.startsWith('First time'))).toBe(false);
  });

  it('compares addresses case-insensitively (checksums are not identity)', () => {
    const mixed = `0xAbCdefABCDEFabcdefABCDEFabcdefABCDEFabcd`;
    const badges = transactionRiskBadges(
      { to: mixed, value: '1' },
      { ...context, knownRecipients: [mixed.toLowerCase()] },
    );
    expect(badges.some((b) => b.label.startsWith('First time'))).toBe(false);
  });

  it('flags a value above the configured threshold', () => {
    const over = transactionRiskBadges({ to: RECIPIENT, value: '2000000000000000000' }, context);
    expect(over.some((b) => b.label.includes('warn threshold'))).toBe(true);
    const under = transactionRiskBadges({ to: RECIPIENT, value: '500000000000000000' }, context);
    expect(under.some((b) => b.label.includes('warn threshold'))).toBe(false);
    // Exactly at the threshold is not "above" it.
    const at = transactionRiskBadges(
      { to: RECIPIENT, value: DEFAULT_CONFIG.warnThresholdWei },
      context,
    );
    expect(at.some((b) => b.label.includes('warn threshold'))).toBe(false);
  });

  it('handles values bigger than Number.MAX_SAFE_INTEGER', () => {
    // A 20-ETH transfer is 2e18 — string comparison would get this wrong.
    const badges = transactionRiskBadges({ to: RECIPIENT, value: '2000000000000000000' }, context);
    expect(badges.some((b) => b.label.includes('warn threshold'))).toBe(true);
  });

  it('ignores a malformed threshold instead of breaking every prompt', () => {
    const badges = transactionRiskBadges(
      { to: RECIPIENT, value: '2000000000000000000' },
      { ...context, warnThresholdWei: 'not-a-number' },
    );
    expect(badges.some((b) => b.label.includes('warn threshold'))).toBe(false);
  });

  it('flags an unverified contract for a call but not a plain transfer', () => {
    const call = transactionRiskBadges({ to: CONTRACT, value: '0', data: '0xa9059cbb' }, context);
    expect(call).toContainEqual({
      level: 'warn',
      label: 'Unverified contract — you have not marked this address as verified',
    });
    const transfer = transactionRiskBadges({ to: CONTRACT, value: '0', data: '0x' }, context);
    expect(transfer.some((b) => b.label.startsWith('Unverified'))).toBe(false);
    // A verified contract is not flagged.
    const verified = transactionRiskBadges(
      { to: CONTRACT, value: '0', data: '0xa9059cbb' },
      { ...context, verifiedContracts: [CONTRACT.toLowerCase()] },
    );
    expect(verified.some((b) => b.label.startsWith('Unverified'))).toBe(false);
  });

  it('flags contract creation', () => {
    const badges = transactionRiskBadges({ value: '0' }, context);
    expect(badges).toContainEqual({
      level: 'warn',
      label: 'Contract creation — no recipient address',
    });
  });

  it('ignores a non-quantity value rather than treating it as zero', () => {
    const badges = transactionRiskBadges({ to: '0x9999', value: 'pending' }, context);
    expect(badges.some((b) => b.label.startsWith('First time'))).toBe(false);
  });
});

describe('consentBadges', () => {
  it('sorts danger first so the worst thing is read first', () => {
    const badges = consentBadges(
      { decision: 'deny', reasons: [{ code: 'p', message: 'denied' }], matched_policy_ids: [] },
      { ok: false, revertReason: 'revert' },
      { to: '0x9999', value: '2000000000000000000' },
      context,
    );
    // Deny + revert are danger, and the unknown recipient and over-threshold
    // value are both warnings.
    expect(badges.map((b) => b.level)).toEqual(['danger', 'danger', 'warn', 'warn']);
  });

  it('composes policy, simulation and request badges', () => {
    const badges = consentBadges(
      { decision: 'allow', reasons: [], matched_policy_ids: ['p1'] },
      { ok: true, gasUsed: '0x5208' },
      { to: RECIPIENT, value: '2000000000000000000' },
      context,
    );
    // Policy (allow) + simulation (ok) + threshold warning = 3. No first-time
    // badge, because the recipient is already known.
    expect(badges).toHaveLength(3);
    expect(badges.some((b) => b.label.includes('warn threshold'))).toBe(true);
  });
});

describe('normalizeAddress', () => {
  it('lowercases and trims', () => {
    expect(normalizeAddress('  0xAbCdef ')).toBe('0xabcdef');
  });
});

describe('EIP-6963 provider identity (design §4.3)', () => {
  const published = '3f2504e0-4f89-41d3-9a0c-0305e82c3301';
  const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

  function storageWith(value: unknown = undefined) {
    const stored: Record<string, unknown> =
      value === undefined ? {} : { 'oc:eip6963:uuid': value };
    return {
      stored,
      local: {
        get: async (key: string) => (key in stored ? { [key]: stored[key] } : {}),
        set: async (patch: Record<string, unknown>) => {
          Object.assign(stored, patch);
        },
      },
    };
  }

  it('persists one uuid per install', async () => {
    const storage = storageWith();
    const first = await providerUuid(storage);
    const second = await providerUuid(storage);
    // A fresh uuid per call would hand a dApp two entries for one wallet and
    // defeat the deduplication EIP-6963 exists to provide.
    expect(second).toBe(first);
    expect(UUID_PATTERN.test(first)).toBe(true);
    expect(Object.keys(storage.stored)).toEqual(['oc:eip6963:uuid']);
  });

  it('replaces a malformed stored uuid rather than trusting it', async () => {
    const storage = storageWith('not-a-uuid');
    const uuid = await providerUuid(storage);
    expect(UUID_PATTERN.test(uuid)).toBe(true);
    expect(storage.stored['oc:eip6963:uuid']).toBe(uuid);
  });

  it('uses the uuid the content script published, not a fresh one', async () => {
    // The page realm cannot reach chrome.storage, so the content script
    // publishes the persisted uuid via `window` before injecting the provider.
    (globalThis as { __oneCipherUuid?: string }).__oneCipherUuid = published;
    try {
      expect(pageUuid()).toBe(published);
    } finally {
      delete (globalThis as { __oneCipherUuid?: string }).__oneCipherUuid;
    }
  });

  it('keeps a stable fallback for the document lifetime', () => {
    const page = pageUuid();
    expect(UUID_PATTERN.test(page)).toBe(true);
    // Re-rolled per call, a dApp would see a new identity each time.
    expect(pageUuid()).toBe(page);
  });
});
