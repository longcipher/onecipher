// EIP-1193 ⇄ OCWP transaction normalization. These lock the two silent,
// value-moving mistakes: dropping a fee ceiling, and signing on the wallet's
// active chain instead of the chain the dApp asked for.

import { describe, expect, it } from 'vitest';
import {
  hexChainId,
  hexQuantityToDecimal,
  normalizeChainReference,
  normalizeEvmTx,
  numericChainId,
} from '../src/lib/evm-tx';

const TO = '0x1111111111111111111111111111111111111111';

describe('normalizeChainReference', () => {
  it('reads EIP-1193 hex and CAIP-2 decimal', () => {
    expect(normalizeChainReference('0x1')).toBe('eip155:1');
    expect(normalizeChainReference('0x89')).toBe('eip155:137');
    expect(normalizeChainReference('0x2105')).toBe('eip155:8453');
    expect(normalizeChainReference('eip155:8453')).toBe('eip155:8453');
  });

  it('never collapses decimal and hex references onto the same chain', () => {
    // `eip155:8453` is Base; `0x8453` is a different, much larger chain.
    expect(normalizeChainReference('eip155:8453')).not.toBe(normalizeChainReference('0x8453'));
  });

  it('rejects ambiguous or malformed references', () => {
    expect(() => normalizeChainReference('1')).toThrow();
    expect(() => normalizeChainReference('0xzz')).toThrow();
    expect(() => normalizeChainReference('eip155:')).toThrow();
    expect(() => normalizeChainReference('eip155:0x1')).toThrow();
    expect(() => normalizeChainReference('')).toThrow();
  });
});

describe('chain id helpers', () => {
  it('converts both directions', () => {
    expect(numericChainId('eip155:8453')).toBe('8453');
    expect(hexChainId('eip155:8453')).toBe('0x2105');
    expect(hexChainId('eip155:1')).toBe('0x1');
    expect(() => numericChainId('solana:mainnet')).toThrow();
  });
});

describe('hexQuantityToDecimal', () => {
  it('accepts hex, decimal and safe numbers', () => {
    expect(hexQuantityToDecimal('0x3e8')).toBe('1000');
    expect(hexQuantityToDecimal('1000')).toBe('1000');
    expect(hexQuantityToDecimal(1000)).toBe('1000');
  });

  it('treats non-quantities as absent rather than as zero', () => {
    // `undefined` means "not provided" — folding these into `0` would let the
    // daemon fill in a value the dApp never asked for.
    expect(hexQuantityToDecimal('0x')).toBeUndefined();
    expect(hexQuantityToDecimal('')).toBeUndefined();
    expect(hexQuantityToDecimal('abc')).toBeUndefined();
    expect(hexQuantityToDecimal(-1)).toBeUndefined();
    expect(hexQuantityToDecimal(null)).toBeUndefined();
    expect(hexQuantityToDecimal({})).toBeUndefined();
  });
});

describe('normalizeEvmTx', () => {
  it('maps every camelCase field the daemon needs (D-2)', () => {
    const { transaction } = normalizeEvmTx(
      {
        to: TO,
        value: '0x3e8',
        data: '0xdeadbeef',
        nonce: '0x7',
        gas: '0x5208',
        gasPrice: '0x3b9aca00',
        maxFeePerGas: '0x77359400',
        maxPriorityFeePerGas: '0x3b9aca00',
        type: '0x2',
      },
      'eip155:1',
    );
    expect(transaction).toMatchObject({
      to: TO,
      value: '1000',
      data: '0xdeadbeef',
      nonce: '7',
      gas_limit: '21000',
      gas_price: '1000000000',
      max_fee_per_gas: '2000000000',
      max_priority_fee_per_gas: '1000000000',
      type: '0x02',
    });
  });

  it('accepts the `input` alias for `data`', () => {
    const { transaction } = normalizeEvmTx({ to: TO, input: '0xa9059cbb' }, 'eip155:1');
    expect(transaction['data']).toBe('0xa9059cbb');
  });

  it('derives the chain from the transaction, not the wallet (D-1)', () => {
    // The wallet is on Base; the dApp wants mainnet. The transaction must
    // carry mainnet so `account_id` binds to it.
    const { chainId, transaction } = normalizeEvmTx({ to: TO, chainId: '0x1' }, 'eip155:8453');
    expect(chainId).toBe('eip155:1');
    expect(transaction['chainId']).toBe('0x1');
  });

  it('falls back to the site chain only when the dApp omits one', () => {
    expect(normalizeEvmTx({ to: TO }, 'eip155:8453').chainId).toBe('eip155:8453');
  });

  it('passes unknown fields through instead of dropping them', () => {
    const { transaction } = normalizeEvmTx(
      { to: TO, accessList: [{ address: TO }], customThing: 7 },
      'eip155:1',
    );
    expect(transaction['accessList']).toEqual([{ address: TO }]);
    expect(transaction['customThing']).toBe(7);
  });

  it('omits absent fields rather than sending zero', () => {
    const { transaction } = normalizeEvmTx({ to: TO }, 'eip155:1');
    expect('value' in transaction).toBe(false);
    expect('nonce' in transaction).toBe(false);
    expect('max_fee_per_gas' in transaction).toBe(false);
  });

  it('treats a null field as absent so the daemon can still see the real one', () => {
    const { transaction } = normalizeEvmTx(
      { to: TO, gas: null, value: '0x1' } as Record<string, unknown>,
      'eip155:1',
    );
    expect(transaction['value']).toBe('1');
    expect('gas_limit' in transaction).toBe(false);
  });

  it('refuses envelope types the daemon cannot encode', () => {
    // Refusing here means the user is never asked to approve something that
    // cannot be signed as described.
    expect(() => normalizeEvmTx({ to: TO, type: '0x3' }, 'eip155:1')).toThrow();
    expect(() => normalizeEvmTx({ to: TO, type: '0x1' }, 'eip155:1')).toThrow();
    expect(() => normalizeEvmTx({ to: TO, type: 'nope' }, 'eip155:1')).toThrow();
    // Accepted: legacy and EIP-1559.
    expect(normalizeEvmTx({ to: TO, type: '0x0' }, 'eip155:1').type).toBe('0x00');
    expect(normalizeEvmTx({ to: TO, type: '0x2' }, 'eip155:1').type).toBe('0x02');
  });

  it('normalizes and validates an EIP-7702 authorization list', () => {
    const { type, delegations, transaction } = normalizeEvmTx(
      {
        to: TO,
        nonce: '0x0',
        authorizationList: [
          { chainId: '0x1', address: '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', nonce: '0x5' },
        ],
      },
      'eip155:1',
    );
    expect(type).toBe('0x04');
    expect(delegations).toEqual(['0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa']);
    expect(transaction['authorization_list']).toEqual([
      { address: '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', chain_id: '1', nonce: '5' },
    ]);
  });

  it('requires an authorizationList for a 0x4 envelope and rejects bad entries', () => {
    expect(() => normalizeEvmTx({ to: TO, type: '0x4' }, 'eip155:1')).toThrow();
    expect(() => normalizeEvmTx({ to: TO, authorizationList: [] }, 'eip155:1')).toThrow();
    expect(() =>
      normalizeEvmTx({ to: TO, authorizationList: [{ address: '0xdead' }] }, 'eip155:1'),
    ).toThrow();
    expect(() =>
      normalizeEvmTx({ to: TO, authorizationList: [{ address: TO }] }, 'eip155:1'),
    ).toThrow(/nonce/);
    // A pre-signed tuple would be for a key the daemon does not hold.
    expect(() =>
      normalizeEvmTx(
        { to: TO, authorizationList: [{ address: TO, nonce: '0x0', r: '0x1', s: '0x2' }] },
        'eip155:1',
      ),
    ).toThrow(/pre-signed/);
  });

  it('refuses an authorizationList on a non-7702 envelope', () => {
    expect(() =>
      normalizeEvmTx({ to: TO, type: '0x2', authorizationList: [{ address: TO, nonce: '0x0' }] }, 'eip155:1'),
    ).toThrow(/0x4/);
  });
});