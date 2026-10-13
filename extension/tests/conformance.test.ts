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
