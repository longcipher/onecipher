// Decoder tests: RLP tx summaries, message views, wei formatting, unlimited
// approve detection (design §4.8).

import { describe, expect, it } from 'vitest';
import {
  buildMessageView,
  buildTypedDataView,
  decodeTransactionSummary,
  formatWei,
  tryDecodeUtf8,
} from '../src/lib/consent/decode';

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
  // RLP-encoded quantity (mirrors oc_signer::rlp::encode_u128): zero encodes
  // as the empty string 0x80; otherwise big-endian bytes with the RLP prefix.
  if (value === 0) return [0x80];
  const bytes: number[] = [];
  let rest = value;
  while (rest > 0) {
    bytes.unshift(rest & 0xff);
    rest = Math.floor(rest / 256);
  }
  return rlpEncodeBytes(bytes);
}

const to = Array.from({ length: 20 }, (_, i) => 0x11);

describe('decodeTransactionSummary', () => {
  it('decodes a type-2 (EIP-1559) transaction built with a short list', () => {
    const body = rlpEncodeList([
      rlpEncodeU128(8453),
      rlpEncodeU128(7),
      rlpEncodeU128(1),
      rlpEncodeU128(2),
      rlpEncodeU128(21000),
      rlpEncodeBytes(to),
      rlpEncodeU128(1000),
      rlpEncodeBytes([0xde, 0xad, 0xbe, 0xef]),
      rlpEncodeList([]),
    ]);
    const raw = [0x02, ...body].map((b) => b.toString(16).padStart(2, '0')).join('');
    const summary = decodeTransactionSummary(raw);
    expect(summary.type).toBe('eip1559');
    expect(summary.to).toBe(`0x${to.map((b) => b.toString(16).padStart(2, '0')).join('')}`);
    expect(summary.value).toBe('1000');
    expect(summary.data).toBe('0xdeadbeef');
    expect(summary.chainId).toBe('8453');
  });

  it('decodes a type-2 transaction built with a LONG list (0xf8 prefix)', () => {
    const bigData = Array.from({ length: 64 }, (_, i) => i);
    const body = rlpEncodeList([
      rlpEncodeU128(8453),
      rlpEncodeU128(7),
      rlpEncodeU128(1),
      rlpEncodeU128(2),
      rlpEncodeU128(21000),
      rlpEncodeBytes(to),
      rlpEncodeU128(1000),
      rlpEncodeBytes(bigData),
      rlpEncodeList([]),
    ]);
    expect(body.length).toBeGreaterThan(55);
    const raw = [0x02, ...body].map((b) => b.toString(16).padStart(2, '0')).join('');
    const summary = decodeTransactionSummary(raw);
    expect(summary.type).toBe('eip1559');
    expect(summary.to).not.toBeNull();
    expect(summary.value).toBe('1000');
  });

  it('decodes a legacy transaction (no type byte)', () => {
    const raw = rlpEncodeList([
      rlpEncodeU128(3),
      rlpEncodeU128(20_000_000_000),
      rlpEncodeU128(21000),
      rlpEncodeBytes(to),
      rlpEncodeU128(5_000_000_000_000_000_000),
      rlpEncodeBytes([]),
    ]).map((b) => b.toString(16).padStart(2, '0')).join('');
    const summary = decodeTransactionSummary(raw);
    expect(summary.type).toBe('legacy');
    expect(summary.to).not.toBeNull();
    expect(summary.value).toBe('5000000000000000000');
  });

  it('flags unlimited approvals and returns empty for junk', () => {
    const body = rlpEncodeList([
      rlpEncodeU128(1),
      rlpEncodeU128(0),
      rlpEncodeU128(1),
      rlpEncodeU128(2),
      rlpEncodeU128(21000),
      rlpEncodeBytes(to),
      rlpEncodeU128(0),
      rlpEncodeBytes([0x09, 0x5e, 0xa7, 0xb3, ...Array(32).fill(0), ...Array(32).fill(0xff)]),
      rlpEncodeList([]),
    ]);
    const raw = [0x02, ...body].map((b) => b.toString(16).padStart(2, '0')).join('');
    const summary = decodeTransactionSummary(raw);
    expect(summary.selectorName).toBe('approve(address,uint256)');
    expect(summary.unlimitedApprove).toBe(true);
    expect(decodeTransactionSummary('0x').type).toBe('unknown');
    expect(decodeTransactionSummary('0x02ffff').to).toBeNull();
  });
});

describe('message views', () => {
  it('renders printable UTF-8 messages as text (F18 realm-safe decoding)', () => {
    const bytes = new TextEncoder().encode('Transfer 1 ETH to Bob');
    const b64 = btoa(String.fromCharCode(...bytes));
    const view = buildMessageView(b64, 'hex');
    expect(view.summary).toBe('Sign message text');
    expect(view.fields.find((field) => field.label === 'Message')?.value).toBe('Transfer 1 ETH to Bob');
  });

  it('falls back to raw hex for binary payloads with a warning', () => {
    const bytes = new Uint8Array([0x00, 0xff, 0xfe]);
    const b64 = btoa(String.fromCharCode(...bytes));
    const view = buildMessageView(b64, 'hex');
    expect(view.summary).toBe('Sign binary message');
    expect(view.warnings.length).toBeGreaterThan(0);
    expect(view.fields.some((field) => field.value === '0x00fffe')).toBe(true);
  });

  it('preserves a BOM with ignoreBOM decoding', () => {
    expect(tryDecodeUtf8(new Uint8Array([0xef, 0xbb, 0xbf, 0x41]))).toBe('\ufeffA');
  });

  it('renders EIP-712 domain and message fields', () => {
    const view = buildTypedDataView({
      domain: { name: 'Permit2', version: '1', chainId: 8453, verifyingContract: `0x${'ab'.repeat(20)}` },
      primaryType: 'PermitSingle',
      message: { owner: `0x${'cd'.repeat(20)}`, amount: '1000' },
    });
    expect(view.title).toContain('EIP-712');
    expect(view.fields.find((field) => field.label === 'Type')?.value).toBe('PermitSingle');
    expect(view.fields.find((field) => field.label === 'Domain')?.value).toBe('Permit2');
    expect(view.fields.find((field) => field.label === 'Chain')?.value).toBe('eip155:8453');
    expect(view.warnings.length).toBeGreaterThan(0);
  });
});

describe('formatWei', () => {
  it('formats wei into ETH', () => {
    expect(formatWei('1000000000000000000')).toBe('1 ETH');
    expect(formatWei('500000000000000000')).toBe('0.5 ETH');
    expect(formatWei('0')).toBe('0 ETH');
    expect(formatWei('1234567890000000000')).toBe('1.23456789 ETH');
  });
});
