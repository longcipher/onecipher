// Extension config hardening (design §4.6, INV-9): normalizeConfig must turn any
// untrusted input into a fully-populated, valid config, and saveConfig/loadConfig
// must never honor a non-loopback daemon URL.

import { describe, expect, it } from 'vitest';
import { DEFAULT_CONFIG, loadConfig, normalizeConfig, saveConfig, type ExtensionConfig } from '../src/lib/storage/config';

function mockStorage(area: Record<string, unknown> = {}) {
  return {
    local: {
      async get(key: string) {
        return key in area ? { [key]: area[key] } : {};
      },
      async set(value: Record<string, unknown>) {
        Object.assign(area, value);
      },
    },
    _area: area,
  };
}

describe('normalizeConfig', () => {
  it('populates every field from defaults when given undefined', () => {
    const config = normalizeConfig(undefined);
    expect(config).toEqual(DEFAULT_CONFIG);
  });

  it('preserves user-set values', () => {
    const config = normalizeConfig({
      activeChainId: 'eip155:137',
      warnThresholdWei: '500000000000000000',
      knownRecipients: ['0xabc'],
      verifiedContracts: ['0xdef'],
    });
    expect(config.activeChainId).toBe('eip155:137');
    expect(config.warnThresholdWei).toBe('500000000000000000');
    expect(config.knownRecipients).toEqual(['0xabc']);
    expect(config.verifiedContracts).toEqual(['0xdef']);
  });

  it('forces the daemon URL to the loopback default (INV-9)', () => {
    // Even if stored config somehow carries a non-loopback URL, load strips it.
    const config = normalizeConfig({ daemonUrl: 'https://evil.tld' });
    expect(config.daemonUrl).toBe(DEFAULT_CONFIG.daemonUrl);
  });

  it('rejects a malformed warnThresholdWei and falls back to default', () => {
    const config = normalizeConfig({ warnThresholdWei: 'not-a-number' });
    expect(config.warnThresholdWei).toBe(DEFAULT_CONFIG.warnThresholdWei);
  });

  it('filters non-string entries from array fields', () => {
    const config = normalizeConfig({
      knownRecipients: ['0xabc', 123, null, '0xdef'] as unknown as string[],
      verifiedContracts: [true, '0xabc'] as unknown as string[],
    });
    expect(config.knownRecipients).toEqual(['0xabc', '0xdef']);
    expect(config.verifiedContracts).toEqual(['0xabc']);
  });

  it('handles missing array fields gracefully', () => {
    const config = normalizeConfig({ knownRecipients: undefined, verifiedContracts: undefined });
    expect(config.knownRecipients).toEqual([]);
    expect(config.verifiedContracts).toEqual([]);
  });
});

describe('loadConfig (INV-9 loopback enforcement)', () => {
  it('loads and hardens a stored config', async () => {
    const area: Record<string, unknown> = {
      'oc:config': { activeChainId: 'eip155:137', warnThresholdWei: '2000' },
    };
    const storage = mockStorage(area);
    const config = await loadConfig(storage as never);
    expect(config.activeChainId).toBe('eip155:137');
    expect(config.warnThresholdWei).toBe('2000');
    // daemon URL is always the loopback default
    expect(config.daemonUrl).toBe(DEFAULT_CONFIG.daemonUrl);
  });

  it('rejects a non-loopback stored daemon URL', async () => {
    const area: Record<string, unknown> = {
      'oc:config': { daemonUrl: 'https://attacker.example' },
    };
    const storage = mockStorage(area);
    const config = await loadConfig(storage as never);
    expect(config.daemonUrl).toBe(DEFAULT_CONFIG.daemonUrl);
  });

  it('returns default config when nothing is stored', async () => {
    const storage = mockStorage();
    const config = await loadConfig(storage as never);
    expect(config).toEqual(DEFAULT_CONFIG);
  });
});

describe('saveConfig (INV-9 loopback enforcement on write)', () => {
  it('writes with a validated loopback URL', async () => {
    const area: Record<string, unknown> = {};
    const storage = mockStorage(area);
    const config: ExtensionConfig = {
      ...DEFAULT_CONFIG,
      daemonUrl: 'http://127.0.0.1:18080',
    };
    await saveConfig(storage as never, config);
    const stored = area['oc:config'] as ExtensionConfig;
    expect(stored.daemonUrl).toBe('http://127.0.0.1:18080');
  });

  it('never persists a non-loopback URL even if the config object carries one', async () => {
    const area: Record<string, unknown> = {};
    const storage = mockStorage(area);
    const config: ExtensionConfig = {
      ...DEFAULT_CONFIG,
      daemonUrl: 'https://evil.tld',
    };
    // saveConfig calls validateLoopbackUrl on write — a non-loopback URL throws
    // rather than being persisted. This is the fail-closed behavior (INV-9).
    await expect(saveConfig(storage as never, config)).rejects.toThrowError(/loopback/);
    // Nothing was persisted.
    expect(area['oc:config']).toBeUndefined();
  });
});
