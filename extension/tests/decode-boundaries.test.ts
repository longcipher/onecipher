// Decoder boundary coverage (design §4.8) — the cases the existing
// decode.test.ts leaves open: EIP-2930 (type-1), EIP-7702 (type-4), malformed /
// truncated RLP, the buildTransactionView raw-hex path, buildConnectView, and
// formatWei edge cases.

import { describe, expect, it } from 'vitest';
import {
  buildConnectView,
  buildTransactionView,
  decodeTransactionSummary,
  formatWei,
  hexToBytes,
  stripHexPrefix,
  isHex,
  tryDecodeUtf8,
} from '../src/lib/consent/decode';

// -- RLP encode helpers (mirror of decode.test.ts) -------------------------

function rlpEncodeBytes(bytes: number[]): number[] {
  const first = bytes[0];
  if (bytes.length === 1 && first !== undefined && first < 0x80) return bytes;
  if (bytes.length <= 55) return [0x80 + bytes.length, ...bytes];
  const lenBytes: number[] = [];
  let len = bytes.length;
  while (len > 0) {
    lenBytes.unshift(len & 0xff);
    len >>= 8;
  }
  return [0xb7 + lenBytes.length, ...lenBytes, ...bytes];
}

function rlpEncodeList(items: number[][]): number[] {
  const payload = items.flat();
  if (payload.length <= 55) return [0xc0 + payload.length, ...payload];
  const lenBytes: number[] = [];
  let len = payload.length;
  while (len > 0) {
    lenBytes.unshift(len & 0xff);
    len >>= 8;
  }
  return [0xf7 + lenBytes.length, ...lenBytes, ...payload];
}

function rlpEncodeU128(value: number): number[] {
  if (value === 0) return [0x80];
  const bytes: number[] = [];
  let rest = value;
  while (rest > 0) {
    bytes.unshift(rest & 0xff);
    rest = Math.floor(rest / 256);
  }
  return rlpEncodeBytes(bytes);
}

const to = Array.from({ length: 20 }, (_, i) => 0x22);

function hex(list: number[]): string {
  return list.map((b) => b.toString(16).padStart(2, '0')).join('');
}

// ---------------------------------------------------------------------------

describe('decodeTransactionSummary — type-1 (EIP-2930)', () => {
  it('decodes a type-1 transaction body', () => {
    // EIP-2930: [chainId, nonce, gasPrice, gasLimit, to, value, data, accessList]
    const body = rlpEncodeList([
      rlpEncodeU128(1),
      rlpEncodeU128(5),
      rlpEncodeU128(20_000_000_000),
      rlpEncodeU128(21000),
      rlpEncodeBytes(to),
      rlpEncodeU128(500),
      rlpEncodeBytes([]),
      rlpEncodeList([]), // accessList
    ]);
    const raw = hex([0x01, ...body]);
    const summary = decodeTransactionSummary(raw);
    expect(summary.type).toBe('eip2930');
    expect(summary.to).toBe(`0x${to.map((b) => b.toString(16).padStart(2, '0')).join('')}`);
    expect(summary.value).toBe('500');
    expect(summary.chainId).toBe('1');
    expect(summary.nonce).toBe('5');
    expect(summary.gasLimit).toBe('21000');
  });
});

describe('decodeTransactionSummary — type-4 (EIP-7702)', () => {
  it('decodes a type-4 transaction body', () => {
    // EIP-7702: [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, payload]
    const body = rlpEncodeList([
      rlpEncodeU128(1),
      rlpEncodeU128(10),
      rlpEncodeU128(1),
      rlpEncodeU128(2),
      rlpEncodeU128(30000),
      rlpEncodeBytes(to),
      rlpEncodeU128(0),
      rlpEncodeBytes([]),
      rlpEncodeList([]), // accessList
      rlpEncodeList([]), // authorizationList (empty for decode display)
    ]);
    const raw = hex([0x04, ...body]);
    const summary = decodeTransactionSummary(raw);
    expect(summary.type).toBe('eip7702');
    expect(summary.to).not.toBeNull();
    expect(summary.nonce).toBe('10');
  });
});

describe('decodeTransactionSummary — malformed / truncated RLP', () => {
  it('returns unknown-empty for junk bytes', () => {
    const summary = decodeTransactionSummary('0xdeadbeef');
    expect(summary.type).toBe('unknown');
    expect(summary.to).toBeNull();
  });

  it('returns empty for single type byte', () => {
    const summary = decodeTransactionSummary('0x02');
    expect(summary.type).toBe('unknown');
  });

  it('returns empty for an empty payload', () => {
    const summary = decodeTransactionSummary('');
    expect(summary.type).toBe('unknown');
    expect(summary.to).toBeNull();
  });

  it('handles RLP claiming more data than available', () => {
    // 0xf8 = long list prefix; 0x05 claims 5 bytes of list payload but only 2 follow
    const summary = decodeTransactionSummary('0x02f8050102');
    expect(summary.type).toBe('unknown');
    expect(summary.to).toBeNull();
  });

  it('handles a list that is RLP-valid but has no fields', () => {
    // An empty list is structurally valid but has no transaction fields
    const raw = hex([0x02, 0xc0]);
    const summary = decodeTransactionSummary(raw);
    // The body decodes to an empty list — to/value are null
    expect(summary.type).toBe('eip1559');
    expect(summary.to).toBeNull();
  });
});

describe('decodeTransactionSummary — selector + unlimited approve on raw path', () => {
  it('detects unlimited approve in a type-2 raw payload', () => {
    const approveData = [0x09, 0x5e, 0xa7, 0xb3, ...Array(32).fill(0), ...Array(32).fill(0xff)];
    const body = rlpEncodeList([
      rlpEncodeU128(1),
      rlpEncodeU128(0),
      rlpEncodeU128(2),
      rlpEncodeU128(3),
      rlpEncodeU128(100000),
      rlpEncodeBytes(to),
      rlpEncodeU128(0),
      rlpEncodeBytes(approveData),
      rlpEncodeList([]),
    ]);
    const raw = hex([0x02, ...body]);
    const summary = decodeTransactionSummary(raw);
    expect(summary.selectorName).toBe('approve(address,uint256)');
    expect(summary.unlimitedApprove).toBe(true);
  });
});

describe('hex helpers', () => {
  it('stripHexPrefix removes 0x and 0X', () => {
    expect(stripHexPrefix('0xABCDEF')).toBe('ABCDEF');
    expect(stripHexPrefix('0Xab')).toBe('ab');
    expect(stripHexPrefix('ff')).toBe('ff');
  });

  it('isHex validates even-length hex strings', () => {
    expect(isHex('0xabcd')).toBe(true);
    expect(isHex('ABC')).toBe(false); // odd length
    expect(isHex('0xZZ')).toBe(false);
    expect(isHex('')).toBe(true); // empty string is valid even-length hex
  });

  it('hexToBytes converts with and without prefix', () => {
    const a = hexToBytes('0x4865');
    expect(a).toEqual(new Uint8Array([0x48, 0x65]));
    const b = hexToBytes('4865');
    expect(b).toEqual(a);
  });

  it('tryDecodeUtf8 returns null for invalid sequences', () => {
    expect(tryDecodeUtf8(new Uint8Array([0xff, 0xfe, 0xfd]))).toBeNull();
  });
});

describe('formatWei edge cases', () => {
  it('passes through non-numeric input unchanged', () => {
    expect(formatWei('not-a-number')).toBe('not-a-number');
  });

  it('handles fractional values correctly', () => {
    expect(formatWei('1')).toBe('0.000000000000000001 ETH');
    expect(formatWei('1000000000000000')).toBe('0.001 ETH');
    expect(formatWei('1500000000000000000')).toBe('1.5 ETH');
  });

  it('handles large values without precision loss', () => {
    // 123456789 ETH = 123456789 * 10^18 wei
    expect(formatWei('123456789000000000000000000')).toBe('123456789 ETH');
    // A value with trailing fractional digits
    expect(formatWei('123456789000000000123456789')).toBe('123456789.000000000123456789 ETH');
  });
});

describe('buildConnectView', () => {
  it('constructs a connection view with origin and chain', () => {
    const view = buildConnectView('https://uniswap.org', 'eip155:1');
    expect(view.title).toBe('Connection request');
    expect(view.summary).toBe('Connect https://uniswap.org');
    expect(view.fields).toEqual([
      { label: 'Site', value: 'https://uniswap.org', kind: 'code' },
      { label: 'Account', value: 'eip155:1' },
    ]);
    expect(view.warnings.length).toBeGreaterThan(0);
  });
});

describe('buildTransactionView — raw hex path', () => {
  it('decodes a raw hex transaction and reports fields', () => {
    // EIP-1559 raw transaction hex
    const approveData = [0x09, 0x5e, 0xa7, 0xb3, ...Array(32).fill(0), ...Array(32).fill(0xff)];
    const body = rlpEncodeList([
      rlpEncodeU128(8453),
      rlpEncodeU128(7),
      rlpEncodeU128(1),
      rlpEncodeU128(2),
      rlpEncodeU128(100000),
      rlpEncodeBytes(to),
      rlpEncodeU128(1000),
      rlpEncodeBytes(approveData),
      rlpEncodeList([]),
    ]);
    const rawHex = hex([0x02, ...body]);
    const view = buildTransactionView('send_transaction', { raw: rawHex }, 'eip155:8453');
    expect(view.title).toBe('Send transaction');
    expect(view.fields.some((f) => f.label === 'To')).toBe(true);
    expect(view.fields.some((f) => f.label === 'Function')).toBe(true);
    expect(view.fields.some((f) => f.label === 'Nonce' && f.value === '7')).toBe(true);
    expect(view.warnings.some((w) => w.includes('UNLIMITED'))).toBe(true);
  });

  it('raises the EIP-7702 warning on a type-4 raw transaction', () => {
    const body = rlpEncodeList([
      rlpEncodeU128(1),
      rlpEncodeU128(10),
      rlpEncodeU128(1),
      rlpEncodeU128(2),
      rlpEncodeU128(30000),
      rlpEncodeBytes(to),
      rlpEncodeU128(0),
      rlpEncodeBytes([]),
      rlpEncodeList([]),
      rlpEncodeList([]),
    ]);
    const rawHex = hex([0x04, ...body]);
    const view = buildTransactionView('send_transaction', { raw: rawHex }, 'eip155:1');
    expect(view.warnings.some((w) => w.includes('EIP-7702'))).toBe(true);
  });
});

describe('buildTransactionView — structured EVM fields path', () => {
  it('shows contract creation when no to address', () => {
    const view = buildTransactionView('send_transaction', { value: '0x0' }, 'eip155:1');
    expect(view.fields.some((f) => f.label === 'To' && f.value === '(contract creation)')).toBe(true);
  });

  it('detects unlimited approve from structured data', () => {
    const data = '0x095ea7b3' + '00'.repeat(32) + 'ff'.repeat(32);
    const view = buildTransactionView('send_transaction', {
      to: '0x' + 'ab'.repeat(20),
      value: '0x0',
      data,
    }, 'eip155:1');
    expect(view.fields.some((f) => f.label === 'Function')).toBe(true);
    expect(view.warnings.some((w) => w.includes('UNLIMITED'))).toBe(true);
  });

  it('renders EIP-7700 delegations as explicit warnings', () => {
    const view = buildTransactionView('send_transaction', {
      to: '0x' + 'aa'.repeat(20),
      value: '0x1',
    }, 'eip155:1', ['0x' + 'bb'.repeat(20)]);
    expect(view.warnings.some((w) => w.includes('delegates'))).toBe(true);
    expect(view.warnings.some((w) => w.includes('0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'))).toBe(true);
  });
});
