// Policy verdict → risk badges (design §4.1 / §4.8).
//
// `policy-view.ts` is the design's named home for turning a policy verdict and
// a request into the risk badges a user reads before approving. It is a pure
// module: every input is an explicit argument, so the badge rules are unit
// testable without a browser, a daemon, or storage.
//
// A badge is never an authorization (INV-15). It exists to make a normal-looking
// request visibly abnormal, and the three badges below are exactly the ones a
// user cannot infer from the raw parameters.

import type { PolicyPreview, SimulationSummary } from '../protocol';

/// Severity of a badge. `danger` is for requests that can move funds or rights;
/// `warn` for "look at this before you click"; `info` for neutral context.
export type BadgeLevel = 'info' | 'warn' | 'danger';

export interface RiskBadge {
  level: BadgeLevel;
  label: string;
}

/// Everything the badge rules need that the request itself does not carry.
/// Sourced from `oc:config` (user-editable) and the local recipient history.
export interface RiskContext {
  /// Recipients this browser profile has previously sent value to, lowercased.
  knownRecipients: readonly string[];
  /// Wei value above which a transfer is flagged. Decimal string.
  warnThresholdWei: string;
  /// Contracts the user has explicitly marked verified, lowercased.
  verifiedContracts: readonly string[];
}

/// The policy verdict, rendered as a badge. `null` means the daemon could not
/// be reached — which is surfaced honestly rather than as an implied pass.
export function policyBadge(policy: PolicyPreview | null): RiskBadge {
  if (policy === null) {
    return { level: 'info', label: 'Policy status unavailable — the daemon still enforces' };
  }
  if (policy.decision === 'deny') {
    const reason = policy.reasons[0]?.message;
    return {
      level: 'danger',
      label: reason === undefined ? 'Blocked by policy' : `Blocked by policy — ${reason}`,
    };
  }
  const matched = policy.matched_policy_ids.length;
  return {
    level: 'info',
    label: matched === 0 ? 'Policy allows this request' : `Policy allows (${matched} rule(s) matched)`,
  };
}

/// The dry-run result, rendered as a badge. A revert is the single most
/// predictive signal that a transaction will do nothing except burn gas.
export function simulationBadge(simulation: SimulationSummary | null): RiskBadge | null {
  if (simulation === null) return null;
  if (!simulation.ok) {
    const reason = simulation.revertReason;
    return {
      level: 'danger',
      label: reason === undefined ? 'Simulation reverts' : `Simulation reverts — ${reason}`,
    };
  }
  const gas = simulation.gasUsed;
  return { level: 'info', label: gas === undefined ? 'Simulation OK' : `Simulation OK · gas ≈ ${gas}` };
}

/// Risk badges derived from the transaction parameters themselves.
///
/// These are the checks a user cannot do by eye: a 20-byte recipient looks the
/// same whether it is new or well-known, and `0x` value hides a four-figure
/// ETH transfer. All are advisory (INV-15).
export function transactionRiskBadges(
  tx: Record<string, unknown> | null,
  context: RiskContext,
): RiskBadge[] {
  if (tx === null) return [];
  const badges: RiskBadge[] = [];
  const to = typeof tx['to'] === 'string' ? tx['to'] : null;

  // First-time recipient. Only meaningful when value actually moves: sending
  // data to a new contract is routine, sending funds to a new address is not.
  const value = decimalOrNull(tx['value']);
  if (to !== null && value !== null && value > 0n) {
    const known = context.knownRecipients.includes(normalizeAddress(to));
    if (!known) {
      badges.push({
        level: 'warn',
        label: 'First time sending value to this recipient',
      });
    }
  }

  // Value above the user's own warn threshold.
  if (value !== null) {
    const threshold = parseThreshold(context.warnThresholdWei);
    if (threshold !== null && value > threshold) {
      badges.push({
        level: 'warn',
        label: `Value is above your warn threshold (${context.warnThresholdWei} wei)`,
      });
    }
  }

  // Unverified contract. A call (non-empty `data`) to an address the user has
  // not marked verified gets a badge, because the selector table alone cannot
  // tell a real `approve` from a lookalike.
  const data = typeof tx['data'] === 'string' ? tx['data'] : null;
  const isCall = data !== null && data !== '0x' && data.length > 2;
  if (to !== null && isCall && !context.verifiedContracts.includes(normalizeAddress(to))) {
    badges.push({
      level: 'warn',
      label: 'Unverified contract — you have not marked this address as verified',
    });
  }

  // Contract creation: nothing to verify yet, but worth saying out loud.
  if (to === null) {
    badges.push({ level: 'warn', label: 'Contract creation — no recipient address' });
  }
  return badges;
}

/// Compare two addresses case-insensitively. Checksums are informative, not
/// identifying, so `0xAbC…` and `0xabc…` are the same account.
export function normalizeAddress(address: string): string {
  return address.trim().toLowerCase();
}

function decimalOrNull(value: unknown): bigint | null {
  if (typeof value !== 'string' || !/^\d+$/.test(value.trim())) return null;
  try {
    return BigInt(value.trim());
  } catch {
    return null;
  }
}

/// Parse a configured warn threshold. A malformed value is ignored rather than
/// throwing — a bad config entry must not break every consent prompt.
function parseThreshold(raw: string): bigint | null {
  if (raw === undefined || raw === null) return null;
  const text = String(raw).trim();
  if (!/^\d+$/.test(text)) return null;
  try {
    return BigInt(text);
  } catch {
    return null;
  }
}

/// Every badge for one consent card, in severity order (danger first, so the
/// worst thing on the page is the first thing read).
export function consentBadges(
  policy: PolicyPreview | null,
  simulation: SimulationSummary | null,
  tx: Record<string, unknown> | null,
  context: RiskContext | null,
): RiskBadge[] {
  const badges: RiskBadge[] = [policyBadge(policy)];
  const sim = simulationBadge(simulation);
  if (sim !== null) badges.push(sim);
  if (tx !== null && context !== null) badges.push(...transactionRiskBadges(tx, context));
  const order: Record<BadgeLevel, number> = { danger: 0, warn: 1, info: 2 };
  return badges.sort((a, b) => order[a.level] - order[b.level]);
}