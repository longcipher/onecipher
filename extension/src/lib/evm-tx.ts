// EIP-1193 ⇄ OCWP transaction normalization (design §4.3 / §4.10).
//
// A dApp hands us camelCase (`chainId`, `gas`, `maxFeePerGas`, `input`,
// `authorizationList`) with hex-quantity strings; the daemon's OCWP surface
// speaks snake_case with decimal-or-hex quantities. Dropping a field in that
// hop is not a cosmetic bug: an unmapped `maxFeePerGas` lets the daemon pick
// its own fee ceiling, and an unmapped `chainId` lets the daemon sign the
// transaction for the *wallet's* active chain instead of the one the dApp
// asked for. Both are silent, and both move value.
//
// Normalization happens once, here, and the result is what the consent UI
// renders — so what the user approves is exactly what gets signed.

import { rpcError } from './protocol';

/// Normalize an EIP-1193 `chainId` (`0x1`) or CAIP-2 `eip155:1` to `eip155:1`.
///
/// The two spellings use different radices and conflating them signs for the
/// wrong chain: CAIP-2 defines `eip155:` as **decimal**, so `eip155:8453` is
/// Base while `0x8453` is a different, much larger chain id.
export function normalizeChainReference(value: string): string {
  const trimmed = value.trim();
  const invalid = (): never => {
    throw rpcError(-32602, `invalid chainId '${value}' (expected 0x-hex or eip155:<decimal>)`);
  };
  let numeric: string;
  let radix = 16;
  if (trimmed.startsWith('eip155:')) {
    numeric = trimmed.slice('eip155:'.length);
    radix = 10;
  } else if (trimmed.startsWith('0x') || trimmed.startsWith('0X')) {
    numeric = trimmed.slice(2);
  } else {
    return invalid();
  }
  const pattern = radix === 16 ? /^[0-9a-fA-F]+$/ : /^[0-9]+$/;
  if (!pattern.test(numeric)) return invalid();
  const parsed = radix === 16 ? BigInt(`0x${numeric}`) : BigInt(numeric);
  return `eip155:${parsed.toString(10)}`;
}

/// The numeric chain id from a CAIP-2 reference, for `eth_chainId` /
/// `wallet_switchEthereumChain` payloads.
export function numericChainId(chainId: string): string {
  const match = /^eip155:(\d+)$/.exec(chainId);
  if (!match?.[1]) throw rpcError(-32602, `invalid eip155 chain id '${chainId}'`);
  return match[1];
}

/// `eip155:<n>` → `0x<n>` (the EIP-1193 chainId encoding).
export function hexChainId(chainId: string): string {
  return `0x${BigInt(numericChainId(chainId)).toString(16)}`;
}

/// Convert an EIP-1193 hex/decimal quantity to a decimal string. Returns
/// `undefined` for anything that is not a quantity (e.g. `"0x"`), which the
/// caller must treat as "not provided" rather than as zero.
export function hexQuantityToDecimal(value: unknown): string | undefined {
  if (typeof value === 'number') {
    return Number.isSafeInteger(value) && value >= 0 ? String(value) : undefined;
  }
  if (typeof value !== 'string') return undefined;
  const trimmed = value.trim();
  if (/^\d+$/.test(trimmed)) return trimmed;
  if (/^0x[0-9a-fA-F]+$/.test(trimmed)) return BigInt(trimmed).toString(10);
  return undefined;
}

function read(obj: Record<string, unknown>, keys: string[]): unknown {
  for (const key of keys) {
    const value = obj[key];
    if (value !== undefined && value !== null) return value;
  }
  return undefined;
}

/// A transaction normalized for the OCWP surface.
export interface NormalizedTx {
  /// The exact object to send as `transaction`. Field names are OCWP
  /// snake_case; every value the caller set is preserved.
  transaction: Record<string, unknown>;
  /// CAIP-2 chain id the transaction will be signed on.
  chainId: string;
  /// Envelope type as sent on the wire (`0x0` / `0x2` / `0x4`), or `undefined`
  /// when the dApp did not specify one (the daemon defaults to EIP-1559).
  type: string | undefined;
  /// EIP-7702 delegation targets, surfaced as a consent warning.
  delegations: string[];
}

/// Map an EIP-1193 transaction object onto the OCWP transaction shape.
///
/// Preserves every field the dApp set — including the ones the daemon would
/// otherwise have to guess at — and derives the chain the transaction will
/// actually be signed on so the caller can bind `account_id` to it.
export function normalizeEvmTx(
  tx: Record<string, unknown>,
  fallbackChainId: string,
): NormalizedTx {
  const transaction: Record<string, unknown> = {};

  // Chain. `account_id` must follow the *transaction's* chain, not whatever
  // the wallet happens to be pointing at.
  const rawChain = read(tx, ['chainId', 'chain_id']);
  const chainId =
    typeof rawChain === 'string' && rawChain.length > 0
      ? normalizeChainReference(rawChain)
      : normalizeChainReference(fallbackChainId);

  if (tx['from'] !== undefined) transaction['from'] = tx['from'];

  const to = read(tx, ['to']);
  if (typeof to === 'string' && to.length > 0) transaction['to'] = to;

  const value = hexQuantityToDecimal(read(tx, ['value']));
  if (value !== undefined) transaction['value'] = value;

  // `input` is the EIP-1193 alias for `data`.
  const data = read(tx, ['data', 'input']);
  if (typeof data === 'string') transaction['data'] = data;

  const nonce = hexQuantityToDecimal(read(tx, ['nonce']));
  if (nonce !== undefined) transaction['nonce'] = nonce;

  // `gas` (EIP-1193) is `gas_limit` (OCWP).
  const gas = hexQuantityToDecimal(read(tx, ['gas', 'gasLimit', 'gas_limit']));
  if (gas !== undefined) transaction['gas_limit'] = gas;

  const gasPrice = hexQuantityToDecimal(read(tx, ['gasPrice', 'gas_price']));
  if (gasPrice !== undefined) transaction['gas_price'] = gasPrice;

  const maxFee = hexQuantityToDecimal(read(tx, ['maxFeePerGas', 'max_fee_per_gas']));
  if (maxFee !== undefined) transaction['max_fee_per_gas'] = maxFee;

  const maxPriorityFee = hexQuantityToDecimal(
    read(tx, ['maxPriorityFeePerGas', 'max_priority_fee_per_gas']),
  );
  if (maxPriorityFee !== undefined) transaction['max_priority_fee_per_gas'] = maxPriorityFee;

  // Envelope type: validate it here so an unsupported type is rejected before
  // a consent prompt is ever shown for something that cannot be signed.
  const rawType = read(tx, ['type']);
  let type: string | undefined;
  if (typeof rawType === 'string' && rawType.length > 0) {
    const byte = /^0x[0-9a-fA-F]+$/.test(rawType)
      ? Number.parseInt(rawType.slice(2), 16)
      : Number.NaN;
    if (!SUPPORTED_TX_TYPES.has(byte)) {
      throw rpcError(-32602, `unsupported transaction type '${rawType}'`);
    }
    type = `0x${byte.toString(16).padStart(2, '0')}`;
    transaction['type'] = type;
  }

  // EIP-7702 delegation.
  const delegations: string[] = [];
  const rawAuthList = read(tx, ['authorizationList', 'authorization_list']);
  if (Array.isArray(rawAuthList)) {
    if (type !== undefined && !type.startsWith('0x4')) {
      throw rpcError(-32602, "authorizationList requires transaction type '0x4'");
    }
    transaction['authorization_list'] = rawAuthList.map((entry) => {
      const item = requireObject(entry, 'authorizationList entry');
      const address = item['address'];
      if (typeof address !== 'string' || !/^0x[0-9a-fA-F]{40}$/.test(address)) {
        throw rpcError(-32602, "authorizationList entry needs a 20-byte 'address'");
      }
      delegations.push(address.toLowerCase());
      const mapped: Record<string, unknown> = { address };
      const entryChain = item['chainId'] ?? item['chain_id'];
      if (entryChain !== undefined && entryChain !== null) {
        const decimal = hexQuantityToDecimal(entryChain);
        if (decimal === undefined) throw rpcError(-32602, 'authorizationList[].chainId is invalid');
        mapped['chain_id'] = decimal;
      }
      const entryNonce = hexQuantityToDecimal(item['nonce']);
      if (entryNonce === undefined) throw rpcError(-32602, "authorizationList entry needs 'nonce'");
      mapped['nonce'] = entryNonce;
      // A per-entry signature would be for a different key than the one the
      // daemon holds; only the unsigned tuple is acceptable here.
      if (item['yParity'] !== undefined || item['r'] !== undefined || item['s'] !== undefined) {
        throw rpcError(-32602, 'authorizationList entries must not carry a pre-signed tuple');
      }
      return mapped;
    });
    if (delegations.length === 0) {
      throw rpcError(-32602, 'authorizationList must not be empty');
    }
    transaction['type'] = type ?? '0x04';
    type = transaction['type'] as string;
  } else if (type === '0x04') {
    throw rpcError(-32602, "EIP-7702 transactions require an 'authorizationList'");
  }

  // Carry anything else the dApp set verbatim rather than dropping it: the
  // consent view and the daemon both need to see the whole request.
  for (const [key, value_] of Object.entries(tx)) {
    if (!(key in transaction)) transaction[key] = value_;
  }

  return { transaction, chainId, type, delegations };
}

/// Envelope types the daemon can actually encode. Anything else is refused
/// rather than silently re-encoded as a different transaction.
const SUPPORTED_TX_TYPES = new Set([0x00, 0x02, 0x04]);

function requireObject(value: unknown, what: string): Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw rpcError(-32602, `${what} must be an object`);
  }
  return value as Record<string, unknown>;
}