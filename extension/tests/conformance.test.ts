// OCWP conformance vectors — TypeScript side (design §9.4).
//
// The same fixtures drive the Rust daemon tests
// (bin/oc-cli/src/commands/wallet_rpc/ocwp/vectors.rs). Here they verify that
// the client maps wire-level error envelopes to the documented codes and
// that the hello shape is understood.

import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { OcwpClient } from '../src/lib/daemon/client';
import { OCWP_PROTOCOL_VERSION } from '../src/lib/protocol';

// Vitest runs with the project root as cwd; `import.meta.url` is not a
// file:// URL under the happy-dom transform.
const VECTORS_DIR = join(process.cwd(), 'vectors', 'ocwp-v1');

interface ErrorVector {
  name: string;
  method: string;
  session: 'none' | 'valid';
  params: Record<string, unknown>;
  expected_error_code: number;
  expected_error_data?: Record<string, unknown>;
}

function loadJson(name: string): unknown {
  return JSON.parse(readFileSync(join(VECTORS_DIR, name), 'utf8'));
}

function clientForError(code: number, message: string, data?: unknown): OcwpClient {
  const fetchImpl = vi.fn(async () =>
    new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code, message, data } }), { status: 200 }),
  ) as unknown as typeof fetch;
  return new OcwpClient('http://127.0.0.1:18080', fetchImpl);
}

describe('OCWP v1 error vectors', () => {
  const vectors = loadJson('errors.json') as ErrorVector[];
  expect(vectors.length).toBeGreaterThanOrEqual(10);

  for (const vector of vectors) {
    it(`maps wire errors for: ${vector.name}`, async () => {
      const client = clientForError(vector.expected_error_code, 'from vector', vector.expected_error_data);
      const params = vector.session === 'valid' ? { ...vector.params, session_id: 'sess' } : vector.params;
      const attempt = client.call(vector.method, params);
      await expect(attempt).rejects.toMatchObject({ code: vector.expected_error_code });
    });
  }
});

describe('OCWP v1 hello vector', () => {
  it('declares the protocol version the daemon vector pins', () => {
    const vector = loadJson('hello.json') as { expected_protocol_version: number };
    expect(OCWP_PROTOCOL_VERSION).toBe(vector.expected_protocol_version);
  });
});

// The success-direction half of the vector set (design §5.4: "wire-level
// request/response pairs"). These are the *shapes* the client must be able to
// consume — a daemon that renames or drops a field breaks a real dApp, not just
// a unit test. They are asserted on the client side so both directions of the
// pair are pinned on both ends.
describe('OCWP v1 result vectors', () => {
  interface ResultVector {
    name: string;
    method: string;
    session: 'none' | 'valid';
    expected_result_keys?: string[];
    expected_result?: Record<string, unknown>;
    expected_decision?: string;
    expected_to?: string;
    expected_value?: string;
    expected_data?: string;
    expected_tx_type?: string;
    expected_unlocked?: boolean;
    expected_session_id_length?: number;
    expected_origin_prefix?: string;
    expected_accounts_non_empty?: boolean;
  }

  const vectors = loadJson('results.json') as ResultVector[];
  expect(vectors.length).toBeGreaterThanOrEqual(8);

  /// A canned result for the vector, shaped the way the daemon reports it.
  function resultFor(vector: ResultVector): Record<string, unknown> {
    if (vector.expected_result) return vector.expected_result;
    if (vector.expected_decision !== undefined) {
      return {
        method: 'oc_policy_preview',
        decision: vector.expected_decision,
        reasons: [],
        matched_policy_ids: [],
        tx_type: vector.expected_tx_type ?? '0x02 (EIP-1559)',
        to: vector.expected_to ?? null,
        value: vector.expected_value ?? null,
        data: vector.expected_data ?? null,
      };
    }
    if (vector.expected_unlocked !== undefined) {
      return {
        unlocked: vector.expected_unlocked,
        wallet_id: 'w-1',
        expires_at_unix: 1791890986,
      };
    }
    if (vector.expected_session_id_length !== undefined) {
      return {
        session_id: 'a'.repeat(vector.expected_session_id_length),
        wallet_id: 'w-1',
        index: 0,
        expires_at_unix: 1791890986,
        origin: 'chrome-extension://abcdefghijklmnopabcdefghijklmnop',
        accounts: [{ account_id: 'eip155:1', address: '0xabc', chain_id: 'eip155:1', derivation_path: "m/44'/60'/0'/0/0" }],
      };
    }
    switch (vector.method) {
      case 'oc_hello':
        return { protocol_version: 1, daemon_version: 'test', chains: [], features: [], extension_ids: [] };
      case 'oc_accounts':
        return {
          accounts: [
            { account_id: 'eip155:1', address: '0xabc', chain_id: 'eip155:1', derivation_path: "m/44'/60'/0'/0/0" },
          ],
        };
      case 'oc_list_sites':
        return { sites: [] };
      case 'oc_chain_registry':
        return { chains: [{ chain_id: 'eip155:1', name: 'Ethereum', native_currency: 'ETH', is_evm: true, builtin: true }] };
      case 'oc_lock':
        return {};
      case 'oc_audit_tail':
        return { events: [] };
      default:
        return {};
    }
  }

  const clientForResult = (result: Record<string, unknown>) => {
    const fetchImpl = vi.fn(async () =>
      new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), { status: 200 }),
    ) as unknown as typeof fetch;
    return new OcwpClient('http://127.0.0.1:18080', fetchImpl);
  };

  for (const vector of vectors) {
    it(`accepts the documented shape of: ${vector.name}`, async () => {
      const client = clientForResult(resultFor(vector));
      // `oc_hello` is special-cased because the client validates the version.
      const result =
        vector.method === 'oc_hello'
          ? ((await client.hello()) as unknown as Record<string, unknown>)
          : ((await client.call(vector.method, {})) as Record<string, unknown>);

      for (const key of vector.expected_result_keys ?? []) {
        expect(result).toHaveProperty(key);
      }
      if (vector.expected_result !== undefined) {
        expect(result).toEqual(vector.expected_result);
      }
      for (const [field, getter] of [
        ['expected_decision', (r: Record<string, unknown>) => r['decision']],
        ['expected_to', (r: Record<string, unknown>) => r['to']],
        ['expected_value', (r: Record<string, unknown>) => r['value']],
        ['expected_data', (r: Record<string, unknown>) => r['data']],
        ['expected_tx_type', (r: Record<string, unknown>) => r['tx_type']],
        ['expected_unlocked', (r: Record<string, unknown>) => r['unlocked']],
      ] as const) {
        const expected = vector[field];
        if (expected !== undefined) {
          expect(result).toHaveProperty(field.slice('expected_'.length));
          expect(getter(result)).toBe(expected);
        }
      }
      if (vector.expected_session_id_length !== undefined) {
        expect(String(result['session_id'])).toHaveLength(vector.expected_session_id_length);
      }
      if (vector.expected_origin_prefix !== undefined) {
        expect(String(result['origin']).startsWith(vector.expected_origin_prefix)).toBe(true);
      }
      if (vector.expected_accounts_non_empty === true) {
        expect(result['accounts']).toBeInstanceOf(Array);
        expect(result['accounts'] as unknown[]).not.toHaveLength(0);
      }
    });
  }
});
