// OcwpClient tests: loopback-only validation (INV-9) + error normalization.

import { describe, expect, it, vi } from 'vitest';
import { OcwpClient, validateLoopbackUrl } from '../src/lib/daemon/client';

describe('validateLoopbackUrl', () => {
  it('accepts loopback URLs and normalizes them', () => {
    expect(validateLoopbackUrl('http://127.0.0.1:18080')).toBe('http://127.0.0.1:18080');
    expect(validateLoopbackUrl('http://localhost:18080/')).toBe('http://localhost:18080');
    expect(validateLoopbackUrl('http://127.0.0.1')).toBe('http://127.0.0.1:80');
  });

  it('rejects non-loopback and non-http URLs', () => {
    for (const bad of [
      'https://example.com',
      'http://192.168.1.5:18080',
      'http://evil.example.com',
      'ftp://127.0.0.1',
      'not a url',
    ]) {
      expect(() => validateLoopbackUrl(bad)).toThrowError();
    }
  });
});

describe('OcwpClient.call', () => {
  function fetchOk(result: unknown): typeof fetch {
    return vi.fn(async () =>
      new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), { status: 200 }),
    ) as unknown as typeof fetch;
  }

  function fetchError(code: number, message: string, data?: unknown): typeof fetch {
    return vi.fn(async () =>
      new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, error: { code, message, data } }), { status: 200 }),
    ) as unknown as typeof fetch;
  }

  it('posts JSON-RPC envelopes and unwraps results', async () => {
    const fetchImpl = fetchOk({ unlocked: true });
    const client = new OcwpClient('http://127.0.0.1:18080', fetchImpl);
    const status = await client.sessionStatus('abc');
    expect(status).toEqual({ unlocked: true });
    const call = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0] as unknown as [
      string,
      RequestInit,
    ];
    expect(call[0]).toBe('http://127.0.0.1:18080/');
    expect(JSON.parse(String(call[1].body))).toEqual({
      jsonrpc: '2.0',
      id: 1,
      method: 'oc_session_status',
      params: { session_id: 'abc' },
    });
  });

  it('normalizes daemon errors to RpcErrorShape with data', async () => {
    const client = new OcwpClient('http://127.0.0.1:18080', fetchError(4100, 'locked', { require_passkey: true }));
    await expect(client.sessionStatus('abc')).rejects.toMatchObject({
      code: 4100,
      message: 'locked',
      data: { require_passkey: true },
    });
  });

  it('maps network failures to 4900 disconnected', async () => {
    const fetchImpl = vi.fn(async () => {
      throw new TypeError('connection refused');
    }) as unknown as typeof fetch;
    const client = new OcwpClient('http://127.0.0.1:18080', fetchImpl);
    await expect(client.hello()).rejects.toMatchObject({ code: 4900 });
  });

  it('rejects non-loopback constructor URLs before any request', () => {
    expect(() => new OcwpClient('http://evil.example.com')).toThrowError(/loopback/);
  });

  it('refuses a protocol-version mismatch (hello) and blocks every later call', async () => {
    const fetchImpl = vi.fn(async () =>
      new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result: { protocol_version: 2 } }), { status: 200 }),
    ) as unknown as typeof fetch;
    const client = new OcwpClient('http://127.0.0.1:18080', fetchImpl);
    await expect(client.hello()).rejects.toMatchObject({ code: 4200 });
    // §3.3: the mismatch must gate EVERY method, not just the handshake —
    // otherwise a later call happily speaks a dialect the daemon never
    // agreed to (D-15).
    await expect(client.sessionStatus('sess')).rejects.toMatchObject({
      code: 4200,
      data: { protocol_version: 2 },
    });
    // Nothing beyond the handshake reached the wire.
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('allows normal traffic once the version is negotiated', async () => {
    const responses = [
      { result: { protocol_version: 1, daemon_version: 'x', chains: [], features: [], extension_ids: [] } },
      { result: { unlocked: true, wallet_id: 'w', expires_at_unix: 1 } },
    ];
    let index = 0;
    const fetchImpl = vi.fn(async () =>
      new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, ...responses[index++] }), { status: 200 }),
    ) as unknown as typeof fetch;
    const client = new OcwpClient('http://127.0.0.1:18080', fetchImpl);
    await client.hello();
    await expect(client.sessionStatus('sess')).resolves.toMatchObject({ unlocked: true });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  it('refuses a protocol-version mismatch (hello)', async () => {
    const fetchImpl = vi.fn(async () =>
      new Response(
        JSON.stringify({ jsonrpc: '2.0', id: 1, result: { protocol_version: 99, daemon_version: 'x', chains: [], features: [] } }),
        { status: 200 },
      ),
    ) as unknown as typeof fetch;
    const client = new OcwpClient('http://127.0.0.1:18080', fetchImpl);
    await expect(client.hello()).rejects.toMatchObject({ code: 4200 });
  });
});
