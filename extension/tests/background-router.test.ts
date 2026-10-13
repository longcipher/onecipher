// Background router tests: sender authentication, fail-closed routing, the
// connect-once ≠ sign-always model (F11/INV-10), and popup command
// restrictions — with stub stores/daemon so no browser or network is needed.

import { describe, expect, it, vi } from 'vitest';
import { ConsentQueue } from '../src/lib/consent/queue';
import { OcwpClient } from '../src/lib/daemon/client';
import {
  createConsentExecutor,
  handleRuntimeMessage,
  type RouterContext,
  type RouterEnv,
  type RouterStores,
} from '../src/lib/background/router';
import { DEFAULT_CONFIG, type ExtensionConfig } from '../src/lib/storage/config';
import type {
  PendingActionView,
  PolicyPreview,
  PopupState,
  RpcErrorShape,
  SessionHandle,
} from '../src/lib/protocol';

const EXT_ID = 'abcdefghijklmnopabcdefghijklmnop';
const POPUP_URL = `chrome-extension://${EXT_ID}/popup.html`;
const WEB_ORIGIN = 'https://dapp.example';
const webSender = { id: EXT_ID, url: `${WEB_ORIGIN}/x`, origin: WEB_ORIGIN, tab: { id: 7 } };
const popupSender = { id: EXT_ID, url: POPUP_URL, origin: `chrome-extension://${EXT_ID}` };

interface Harness {
  ctx: RouterContext;
  sites: Set<string>;
  /// Per-site chain bindings (design §4.3/§4.10).
  chainsByOrigin: Map<string, string>;
  session: SessionHandle | null;
  config: ExtensionConfig;
  daemonCalls: Array<{ method: string; params: Record<string, unknown> }>;
  broadcasts: Array<{ event: string; data: unknown }>;
  notifications: number;
}

function makeHarness(
  options: {
    daemonResult?: (method: string, params: Record<string, unknown>) => unknown;
    /// Make the daemon demand a passkey step-up on the first `oc_sign_message`.
    requireStepUp?: boolean;
    policyResult?: PolicyPreview;
    simulateResult?: { ok: boolean; gas_used?: string; revert_reason?: string };
  } = {},
): Harness {
  const sites = new Set<string>([WEB_ORIGIN]);
  // Per-site chain bindings (design §4.3/§4.10). Absent = fall back to the
  // wallet default, which is what a not-yet-connected origin should see.
  const chainsByOrigin = new Map<string, string>();
  const h: Harness = {
    ctx: null as unknown as RouterContext,
    sites,
    chainsByOrigin,
    session: null,
    config: { ...DEFAULT_CONFIG, activeChainId: 'eip155:8453' },
    daemonCalls: [],
    broadcasts: [],
    notifications: 0,
  };
  const stores: RouterStores = {
    config: {
      load: async () => ({ ...h.config }),
      save: async (config) => {
        h.config = config;
      },
    },
    sites: {
      isAuthorized: async (origin) => sites.has(origin),
      chainFor: async (origin) => chainsByOrigin.get(origin) ?? null,
      setChain: async (origin, chainId) => {
        chainsByOrigin.set(origin, chainId);
      },
      upsert: async (origin, accountId, chainId) => {
        sites.add(origin);
        chainsByOrigin.set(origin, chainId);
        h.daemonCalls.push({ method: 'sites.upsert', params: { origin, accountId, chainId } });
      },
      remove: async (origin) => {
        sites.delete(origin);
        chainsByOrigin.delete(origin);
      },
      list: async () => [...sites].map((origin) => ({
        origin,
        account_id: 'eip155:1',
        chain_id: chainsByOrigin.get(origin) ?? 'eip155:1',
        connected_at: 0,
        last_seen_at: 0,
      })),
    },
    session: {
      load: async () => h.session,
      save: async (handle) => {
        h.session = handle;
      },
      clear: async () => {
        h.session = null;
      },
    },
    passkey: {
      load: async () => null,
      save: async () => undefined,
    },
  };
  const daemonStub = {
    sessionStatus: async (sessionId: string) => {
      h.daemonCalls.push({ method: 'oc_session_status', params: { session_id: sessionId } });
      return { unlocked: h.session?.sessionId === sessionId };
    },
    accounts: async (sessionId: string) => {
      h.daemonCalls.push({ method: 'oc_accounts', params: { session_id: sessionId } });
      return {
        accounts: [
          { account_id: 'eip155:1', chain_id: 'eip155:1', address: '0xaaaabbbbccccddddeeeeffff0000111122223333', derivation_path: "m/44'/60'/0'/0/0" },
          // v1 is an EVM wallet (design §1.2): a non-EVM account must never
          // surface in an `eth_*` result (D-5).
          { account_id: 'solana:mainnet', chain_id: 'solana:mainnet', address: 'SoLaNaAddreSS11111111111111111111111111111', derivation_path: "m/44'/501'/0'/0'" },
        ],
      };
    },
    connectSite: async (sessionId: string, origin: string, accountId: string, chainId: string) => {
      h.daemonCalls.push({ method: 'oc_connect_site', params: { session_id: sessionId, origin, accountId, chainId } });
    },
    rpc: async (sessionId: string, origin: string, chainId: string, method: string, params: unknown[]) => {
      h.daemonCalls.push({ method: 'oc_rpc', params: { session_id: sessionId, origin, chainId, method, params } });
      return options.daemonResult?.(method, {}) ?? '0x1';
    },
    signMessage: async (sessionId: string, accountId: string, message: string, passkey?: unknown) => {
      h.daemonCalls.push({ method: 'oc_sign_message', params: { session_id: sessionId, accountId, message, passkey } });
      if (passkey === undefined && options.requireStepUp) {
        throw { code: 4100, message: 'passkey confirmation required', data: { require_passkey: true } };
      }
      return { signature: '0xsig', public_key: '0xpk', recovery_id: 0 };
    },
    signTypedData: async (sessionId: string, accountId: string, typedData: unknown) => {
      h.daemonCalls.push({ method: 'oc_sign_typed_data', params: { session_id: sessionId, accountId, typedData } });
      return { signature: '0xtyped', public_key: '0xpk' };
    },
    signTransaction: async (sessionId: string, accountId: string, transaction: Record<string, unknown>) => {
      h.daemonCalls.push({ method: 'oc_sign_transaction', params: { session_id: sessionId, accountId, transaction } });
      return { raw_transaction: '0xsigned' };
    },
    sendTransaction: async (sessionId: string, accountId: string, transaction: Record<string, unknown>) => {
      h.daemonCalls.push({ method: 'oc_send_transaction', params: { session_id: sessionId, accountId, transaction } });
      return { tx_hash: '0xhash' };
    },
    simulate: async (sessionId: string, accountId: string, transaction: Record<string, unknown>, from: string) => {
      h.daemonCalls.push({ method: 'oc_simulate', params: { session_id: sessionId, accountId, transaction, from } });
      return options.simulateResult ?? { ok: true, gas_used: '0x5208' };
    },
    policyPreview: async (sessionId: string, request: Record<string, unknown>) => {
      h.daemonCalls.push({ method: 'oc_policy_preview', params: { session_id: sessionId, ...request } });
      return options.policyResult ?? { decision: 'allow' as const, reasons: [], matched_policy_ids: [] };
    },
    hello: async () => {
      h.daemonCalls.push({ method: 'oc_hello', params: {} });
      return { protocol_version: 1, daemon_version: 'test', chains: [], features: [], extension_ids: [] };
    },
    lock: async (sessionId: string) => {
      h.daemonCalls.push({ method: 'oc_lock', params: { session_id: sessionId } });
    },
    revokeSite: async (sessionId: string, origin: string) => {
      h.daemonCalls.push({ method: 'oc_revoke_site', params: { session_id: sessionId, origin } });
      return { revoked: true };
    },
    unlock: async (wallet: string, passphrase: string) => {
      h.daemonCalls.push({ method: 'oc_unlock', params: { wallet, passphrase } });
      return { session_id: 'sess-1', wallet_id: 'w-1', index: 0, expires_at_unix: 9999999999, accounts: [] };
    },
  };
  const env: RouterEnv = {
    broadcast: async (event, data) => {
      h.broadcasts.push({ event, data });
    },
    openNotification: async () => {
      h.notifications += 1;
    },
    closeNotification: async () => undefined,
  };
  const ctx: RouterContext = {
    extensionId: EXT_ID,
    popupUrl: POPUP_URL,
    daemon: daemonStub as unknown as OcwpClient,
    queue: null as unknown as ConsentQueue,
    stores,
    env,
    setDaemon() {
      /* test harness keeps the stub */
    },
  };
  ctx.queue = new ConsentQueue(createConsentExecutor(ctx), {
    now: () => Date.now(),
    onEnqueue: env.openNotification,
    onDrain: env.closeNotification,
  });
  h.ctx = ctx;
  return h;
}

async function providerRequest(h: Harness, method: string, params?: unknown, sender = webSender) {
  return (await handleRuntimeMessage(h.ctx, { type: 'oc:request', id: 'r1', method, params }, sender)) as {
    result?: unknown;
    error?: RpcErrorShape;
  };
}

describe('fail-closed routing (INV-7)', () => {
  it('rejects unknown envelopes and non-object messages', async () => {
    const h = makeHarness();
    await expect(handleRuntimeMessage(h.ctx, { type: 'legacy:command' }, webSender)).rejects.toMatchObject({ code: 4200 });
    await expect(handleRuntimeMessage(h.ctx, null, webSender)).resolves.toMatchObject({ error: { code: 4200 } });
  });

  it('rejects dApp requests from non-content-script senders (INV-5)', async () => {
    const h = makeHarness();
    const response = await providerRequest(h, 'eth_accounts', [], { ...webSender, id: 'other-extension' });
    expect(response.error?.code).toBe(4100);
  });
});

describe('connection model (F11/INV-10)', () => {
  it('requires consent for a first-time connection and records the site', async () => {
    const h = makeHarness();
    h.sites.delete(WEB_ORIGIN);
    h.session = { sessionId: 'sess-1', walletId: 'w-1', wallet: 'default', expiresAtUnix: 9999999999 };
    let settled = false;
    const promise = providerRequest(h, 'eth_requestAccounts').then((value) => {
      settled = true;
      return value;
    });
    await vi.waitFor(() => expect(h.ctx.queue.size).toBe(1));
    expect(settled).toBe(false);
    const action = h.ctx.queue.list()[0]!;
    expect(action.kind).toBe('connect');
    expect(action.origin).toBe(WEB_ORIGIN);
    // The site is NOT yet connected (daemon call only happens at execute time).
    expect(h.sites.has(WEB_ORIGIN)).toBe(false);
    await h.ctx.queue.approve(action.id);
    const response = await promise;
    expect(response.result).toEqual(['0xaaaabbbbccccddddeeeeffff0000111122223333']);
    expect(h.sites.has(WEB_ORIGIN)).toBe(true);
    expect(h.broadcasts.some((entry) => entry.event === 'accountsChanged')).toBe(true);
  });

  it('connects an already-authorized site without a prompt', async () => {
    const h = makeHarness();
    h.session = { sessionId: 'sess-1', walletId: 'w-1', wallet: 'default', expiresAtUnix: 9999999999 };
    const response = await providerRequest(h, 'eth_requestAccounts');
    expect(response.error).toBeUndefined();
    expect(response.result).toEqual(['0xaaaabbbbccccddddeeeeffff0000111122223333']);
    expect(h.ctx.queue.size).toBe(0);
  });

  it('every sign request requires consent, even for connected sites (INV-2/INV-10)', async () => {
    const h = makeHarness();
    h.session = { sessionId: 'sess-1', walletId: 'w-1', wallet: 'default', expiresAtUnix: 9999999999 };
    const params = ['0x48656c6c6f']; // "Hello" hex
    const promise = providerRequest(h, 'personal_sign', params);
    await vi.waitFor(() => expect(h.ctx.queue.size).toBe(1));
    expect(h.daemonCalls.some((call) => call.method === 'oc_sign_message')).toBe(false);
    const action = h.ctx.queue.list()[0]!;
    expect(action.kind).toBe('sign_message');
    await h.ctx.queue.approve(action.id);
    await promise;
    expect(h.daemonCalls.some((call) => call.method === 'oc_sign_message')).toBe(true);
  });

  it('rejects signing while locked with 4100 and never queues', async () => {
    const h = makeHarness();
    const response = await providerRequest(h, 'personal_sign', ['0x48656c6c6f']);
    expect(response.error?.code).toBe(4100);
    expect(h.ctx.queue.size).toBe(0);
  });

  it('fails a pending approval when the site is revoked mid-flight (F7)', async () => {
    const h = makeHarness();
    h.session = { sessionId: 'sess-1', walletId: 'w-1', wallet: 'default', expiresAtUnix: 9999999999 };
    const promise = providerRequest(h, 'personal_sign', ['0x48656c6c6f']);
    await vi.waitFor(() => expect(h.ctx.queue.size).toBe(1));
    const action = h.ctx.queue.list()[0]!;
    h.sites.delete(WEB_ORIGIN);
    await h.ctx.queue.approve(action.id);
    // The router resolves with an error ENVELOPE; the page-side provider
    // rejects the dApp promise when it sees `error`.
    const response = (await promise) as { error?: RpcErrorShape };
    expect(response.error).toMatchObject({ code: 4100, message: 'Origin authorization was revoked' });
  });
});

describe('local provider methods', () => {
  it('serves eth_chainId locally and honors wallet_switchEthereumChain', async () => {
    const h = makeHarness();
    const chain = await providerRequest(h, 'eth_chainId');
    expect(chain.result).toBe('0x2105'); // 8453
    await providerRequest(h, 'wallet_switchEthereumChain', [{ chainId: '0x1' }]);
    // WEB_ORIGIN is authorized, so the switch is recorded against THAT site —
    // not against the wallet-wide default (D-6).
    expect(h.chainsByOrigin.get(WEB_ORIGIN)).toBe('eip155:1');
    expect(h.config.activeChainId).toBe('eip155:8453');
    // The switching site now sees the new chain...
    expect((await providerRequest(h, 'eth_chainId')).result).toBe('0x1');
    expect(h.broadcasts.some((entry) => entry.event === 'chainChanged' && entry.data === '0x1')).toBe(true);
  });

  it('isolates chain selection per site (D-6)', async () => {
    const h = makeHarness();
    const otherOrigin = 'https://other.example';
    await providerRequest(h, 'wallet_switchEthereumChain', [{ chainId: '0x1' }], webSender);
    const otherSender = { ...webSender, url: `${otherOrigin}/x`, origin: otherOrigin, tab: { id: 9 } };
    // The second site never asked to switch, so it keeps the wallet default
    // and its own view is unaffected by the first site's switch.
    expect((await providerRequest(h, 'eth_chainId', [], otherSender)).result).toBe('0x2105');
    expect((await providerRequest(h, 'eth_chainId', [], webSender)).result).toBe('0x1');
  });

  it('records an unconnected site chain switch as the wallet default', async () => {
    const h = makeHarness();
    h.sites.delete(WEB_ORIGIN);
    await providerRequest(h, 'wallet_switchEthereumChain', [{ chainId: '0x1' }]);
    expect(h.config.activeChainId).toBe('eip155:1');
    expect(h.chainsByOrigin.has(WEB_ORIGIN)).toBe(false);
  });

  it('proxies allowlisted read methods through the daemon', async () => {
    const h = makeHarness();
    h.session = { sessionId: 'sess-1', walletId: 'w-1', wallet: 'default', expiresAtUnix: 9999999999 };
    const response = await providerRequest(h, 'eth_getBalance', ['0xabc', 'latest']);
    expect(response.result).toBe('0x1');
    expect(h.daemonCalls.some((call) => call.method === 'oc_rpc')).toBe(true);
  });

  it('rejects non-allowlisted methods with 4200', async () => {
    const h = makeHarness();
    h.session = { sessionId: 'sess-1', walletId: 'w-1', wallet: 'default', expiresAtUnix: 9999999999 };
    const response = await providerRequest(h, 'eth_sendRawTransaction', ['0xdead']);
    expect(response.error?.code).toBe(4200);
  });

  it('rejects sandboxed (opaque) origins', async () => {
    const h = makeHarness();
    const response = await providerRequest(h, 'eth_accounts', [], {
      ...webSender,
      origin: 'null',
    });
    expect(response.error?.code).toBe(4100);
  });
});

describe('provider result shapes', () => {
  it('personal_sign resolves the signature string, not a wrapper (D-4)', async () => {
    const h = makeHarness();
    h.session = { sessionId: 'sess-1', walletId: 'w-1', wallet: 'default', expiresAtUnix: 9999999999 };
    const promise = providerRequest(h, 'personal_sign', ['0x48656c6c6f']);
    await vi.waitFor(() => expect(h.ctx.queue.size).toBe(1));
    await h.ctx.queue.approve(h.ctx.queue.list()[0]!.id);
    const response = await promise;
    // EIP-1193/EIP-191: the dApp receives the signature itself. A
    // `{ publicKey, signature }` object breaks every consumer.
    expect(response.result).toBe('0xsig');
    expect(typeof response.result).toBe('string');
  });

  it('eth_signTypedData resolves the signature string', async () => {
    const h = makeHarness();
    h.session = { sessionId: 'sess-1', walletId: 'w-1', wallet: 'default', expiresAtUnix: 9999999999 };
    const typed = JSON.stringify({ primaryType: 'Mail', domain: {}, message: {} });
    const promise = providerRequest(h, 'eth_signTypedData_v4', [typed, '0xabc']);
    await vi.waitFor(() => expect(h.ctx.queue.size).toBe(1));
    await h.ctx.queue.approve(h.ctx.queue.list()[0]!.id);
    expect((await promise).result).toBe('0xtyped');
  });

  it('never exposes a non-EVM account in an eth_* result (D-5)', async () => {
    const h = makeHarness();
    h.session = { sessionId: 'sess-1', walletId: 'w-1', wallet: 'default', expiresAtUnix: 9999999999 };
    // The wallet holds an EVM and a Solana account; v1 is EVM-only (design
    // §1.2), so the Solana address must not leak into an EIP-1193 result.
    for (const method of ['eth_accounts', 'eth_requestAccounts']) {
      const response = await providerRequest(h, method);
      expect(response.result).toEqual(['0xaaaabbbbccccddddeeeeffff0000111122223333']);
    }
  });
});

describe('transaction normalization (D-1/D-2)', () => {
  async function enqueueTx(h: Harness, tx: Record<string, unknown>) {
    const promise = providerRequest(h, 'eth_sendTransaction', [tx]);
    await vi.waitFor(() => expect(h.ctx.queue.size).toBe(1));
    const action = h.ctx.queue.list()[0]!;
    await h.ctx.queue.approve(action.id);
    await promise;
    return action;
  }

  const unlocked = () => ({
    sessionId: 'sess-1',
    walletId: 'w-1',
    wallet: 'default',
    expiresAtUnix: 9999999999,
  });

  it('forwards the dApp chain and every fee field it set (D-1/D-2)', async () => {
    const h = makeHarness();
    h.session = unlocked();
    // The wallet default is Base; the dApp explicitly wants mainnet.
    const action = await enqueueTx(h, {
      chainId: '0x1',
      to: '0x1111111111111111111111111111111111111111',
      value: '0x3e8',
      nonce: '0x7',
      gas: '0x5208',
      maxFeePerGas: '0x77359400',
      maxPriorityFeePerGas: '0x3b9aca00',
      type: '0x2',
    });
    const ocwp = action.ocwp.params;
    expect(ocwp['account_id']).toBe('eip155:1');
    expect(ocwp['transaction']).toMatchObject({
      value: '1000',
      nonce: '7',
      gas_limit: '21000',
      max_fee_per_gas: '2000000000',
      max_priority_fee_per_gas: '1000000000',
      type: '0x02',
    });
    // The fee ceiling the dApp pinned is visible in what the user approves.
    const feeField = action.view.fields.find((field) => field.label === 'Max fee');
    expect(feeField?.value).toContain('ETH/gas');
  });

  it('falls back to the site chain when the dApp omits chainId', async () => {
    const h = makeHarness();
    h.session = unlocked();
    const action = await enqueueTx(h, { to: '0x1111111111111111111111111111111111111111', nonce: '0x1' });
    expect(action.ocwp.params['account_id']).toBe('eip155:8453');
  });

  it('surfaces an EIP-7702 delegation as an explicit warning', async () => {
    const h = makeHarness();
    h.session = unlocked();
    const action = await enqueueTx(h, {
      to: '0x1111111111111111111111111111111111111111',
      nonce: '0x0',
      authorizationList: [
        { chainId: '0x1', address: '0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', nonce: '0x5' },
      ],
    });
    // The entry's own `chainId` scopes the *delegation*; the transaction
    // itself stays on the site chain.
    expect(action.ocwp.params['account_id']).toBe('eip155:8453');
    const warning = action.view.warnings.find((entry) => entry.includes('delegates'));
    expect(warning).toContain('0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
  });

  it('refuses an unsupported envelope type before prompting the user', async () => {
    const h = makeHarness();
    h.session = unlocked();
    const response = await providerRequest(h, 'eth_sendTransaction', [
      { to: '0x1111111111111111111111111111111111111111', type: '0x3' },
    ]);
    expect(response.error?.code).toBe(-32602);
    expect(h.ctx.queue.size).toBe(0);
  });
});

describe('consent assessment (policy badge + simulation)', () => {
  it('assesses a pending action before the user decides (design §4.8)', async () => {
    const h = makeHarness({ simulateResult: { ok: false, revert_reason: 'ERC20: insufficient allowance' } });
    h.session = { sessionId: 'sess-1', walletId: 'w-1', wallet: 'default', expiresAtUnix: 9999999999 };
    void providerRequest(h, 'eth_sendTransaction', [
      { to: '0x1111111111111111111111111111111111111111', nonce: '0x1', value: '0x1' },
    ]);
    await vi.waitFor(() => expect(h.ctx.queue.size).toBe(1));
    const action = await vi.waitFor(() => {
      const current = h.ctx.queue.list()[0]!;
      expect(current.assessment).not.toBeUndefined();
      return current;
    });
    expect(action.assessment?.policy?.decision).toBe('allow');
    expect(action.assessment?.simulation?.ok).toBe(false);
    expect(action.assessment?.simulation?.revertReason).toBe('ERC20: insufficient allowance');
    // The preview request must carry the transaction, not an empty payload:
    // a nested-only request evaluates nothing and always allows (D-3).
    const preview = h.daemonCalls.find((call) => call.method === 'oc_policy_preview');
    expect(preview?.params['transaction']).toMatchObject({
      to: '0x1111111111111111111111111111111111111111',
    });
    expect(preview?.params['to']).toBe('0x1111111111111111111111111111111111111111');
    await h.ctx.queue.decline(action.id);
  });

  it('re-checks policy at approve time and denies with the mapped code (INV-4)', async () => {
    let allow = true;
    const h = makeHarness();
    (h.ctx.daemon as unknown as { policyPreview: unknown }).policyPreview = async (
      sessionId: string,
      request: Record<string, unknown>,
    ) => {
      h.daemonCalls.push({ method: 'oc_policy_preview', params: { session_id: sessionId, ...request } });
      return allow
        ? { decision: 'allow' as const, reasons: [], matched_policy_ids: [] }
        : {
            decision: 'deny' as const,
            reasons: [{ code: 'policy', message: 'budget exceeded' }],
            matched_policy_ids: ['p1'],
          };
    };
    h.session = { sessionId: 'sess-1', walletId: 'w-1', wallet: 'default', expiresAtUnix: 9999999999 };
    const promise = providerRequest(h, 'personal_sign', ['0x48']);
    await vi.waitFor(() => expect(h.ctx.queue.size).toBe(1));
    // The badge said "allow"; policy changed while the window was open.
    allow = false;
    await h.ctx.queue.approve(h.ctx.queue.list()[0]!.id);
    const response = (await promise) as { error?: RpcErrorShape };
    expect(response.error?.code).toBe(4300);
    expect(response.error?.data).toMatchObject({ decision: 'deny' });
  });
});

describe('passkey step-up (D-10)', () => {
  it('retries with the proof the daemon demanded', async () => {
    const h = makeHarness({ requireStepUp: true });
    // A real P-256 key: the retry actually signs the challenge, so a stub
    // "passkey" would only prove the wiring, not the flow.
    const pair = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify'],
    );
    const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
    h.ctx.stores.passkey.load = async () => ({ credentialId: 'cred-1', jwk });
    (h.ctx.daemon as unknown as { passkeyChallenge: unknown }).passkeyChallenge = async (
      sessionId: string,
      credentialId: string,
    ) => {
      h.daemonCalls.push({ method: 'oc_passkey_challenge', params: { session_id: sessionId, credentialId } });
      return { challenge_hex: 'aabb', rp_id: 'localhost', timeout_ms: 120_000 };
    };
    h.session = { sessionId: 'sess-1', walletId: 'w-1', wallet: 'default', expiresAtUnix: 9999999999 };
    const promise = providerRequest(h, 'personal_sign', ['0x48']);
    await vi.waitFor(() => expect(h.ctx.queue.size).toBe(1));
    await h.ctx.queue.approve(h.ctx.queue.list()[0]!.id);
    // The retry carries a proof rather than re-sending the same request.
    const calls = h.daemonCalls.filter((call) => call.method === 'oc_sign_message');
    expect(calls).toHaveLength(2);
    expect(calls[0]?.params['passkey']).toBeUndefined();
    expect(calls[1]?.params['passkey']).toMatchObject({
      challenge_hex: 'aabb',
      credential_id: 'cred-1',
    });
    expect((await promise).result).toBe('0xsig');
  });
});

describe('popup surface (INV-6)', () => {
  it('rejects popup commands from web senders', async () => {
    const h = makeHarness();
    await expect(
      handleRuntimeMessage(h.ctx, { type: 'popup:request', method: 'popup_getState' }, webSender),
    ).rejects.toMatchObject({ code: 4100 });
    // Mismatched origin with a popup-shaped URL (reference-project case).
    await expect(
      handleRuntimeMessage(
        h.ctx,
        { type: 'popup:request', method: 'popup_approveAction', params: { id: 'x' } },
        { ...popupSender, origin: WEB_ORIGIN, tab: { id: 1 } },
      ),
    ).rejects.toMatchObject({ code: 4100 });
  });

  it('unlock stores the session handle and getState reports it', async () => {
    const h = makeHarness();
    await handleRuntimeMessage(
      h.ctx,
      { type: 'popup:request', method: 'popup_unlock', params: { wallet: 'default', passphrase: 'pw' } },
      popupSender,
    );
    expect(h.session?.sessionId).toBe('sess-1');
    const state = (await handleRuntimeMessage(h.ctx, { type: 'popup:request', method: 'popup_getState' }, popupSender)) as PopupState;
    expect(state.daemonReachable).toBe(true);
    expect(state.session?.sessionId).toBe('sess-1');
  });

  it('approveAction on an unknown id fails without side effects', async () => {
    const h = makeHarness();
    await expect(
      handleRuntimeMessage(
        h.ctx,
        { type: 'popup:request', method: 'popup_approveAction', params: { id: 'missing' } },
        popupSender,
      ),
    ).rejects.toMatchObject({ code: 4001 });
  });

  it('declineAction resolves the dApp promise with 4001 (INV-2 path)', async () => {
    const h = makeHarness();
    h.session = { sessionId: 'sess-1', walletId: 'w-1', wallet: 'default', expiresAtUnix: 9999999999 };
    const promise = providerRequest(h, 'personal_sign', ['0x48']);
    await vi.waitFor(() => expect(h.ctx.queue.size).toBe(1));
    const action = h.ctx.queue.list()[0]!;
    await handleRuntimeMessage(
      h.ctx,
      { type: 'popup:request', method: 'popup_declineAction', params: { id: action.id } },
      popupSender,
    );
    const response = (await promise) as { error?: RpcErrorShape };
    expect(response.error).toMatchObject({ code: 4001, message: 'User rejected the request' });
  });
});
