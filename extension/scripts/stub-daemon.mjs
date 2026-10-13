// Stub OCWP daemon for end-to-end tests. Implements the subset of the
// protocol the extension exercises, with canned (non-funded, fixture-key)
// responses. It ALSO serves the fixture dApp page. NEVER use in production.

import { createServer } from 'node:http';

const EXTENSION_ORIGIN_PREFIX = 'chrome-extension://';
const FIXTURE_ADDRESS = '0xaaaabbbbccccddddeeeeffff0000111122223333';
// Deterministic 65-byte (r||s||v) fixture signature — NOT a real signature.
const FIXTURE_SIGNATURE = '0x' + '42'.repeat(65);

const state = {
  unlocked: false,
  sessionId: null,
  sites: {},
  requestLog: [],
};

function json(body, status = 200, extraHeaders = {}) {
  return { status, body: JSON.stringify(body), extraHeaders };
}

function handleOcwp(method, params) {
  state.requestLog.push({ method });
  switch (method) {
    case 'oc_hello':
      return {
        protocol_version: 1,
        daemon_version: 'stub-1.0.0',
        chains: [{ chain_id: 'eip155:8453', name: 'Base', native_currency: 'ETH', is_evm: true, builtin: true }],
        features: ['sessions', 'sites', 'policy-preview', 'rpc-proxy', 'passkey-step-up'],
        extension_ids: [],
      };
    case 'oc_unlock': {
      if (params.passphrase === 'wrong-passphrase') return { error: { code: 4100, message: 'incorrect passphrase' } };
      state.unlocked = true;
      state.sessionId = 'stub-session-1';
      return {
        session_id: state.sessionId,
        wallet_id: 'stub-wallet-1',
        index: 0,
        expires_at_unix: Math.floor(Date.now() / 1000) + 900,
        accounts: [
          {
            account_id: 'eip155:1',
            chain_id: 'eip155:1',
            address: FIXTURE_ADDRESS,
            derivation_path: "m/44'/60'/0'/0/0",
          },
        ],
      };
    }
    case 'oc_lock':
      state.unlocked = false;
      state.sessionId = null;
      return {};
    case 'oc_session_status':
      return { unlocked: state.unlocked, wallet_id: state.unlocked ? 'stub-wallet-1' : undefined };
    case 'oc_accounts':
      return {
        accounts: [
          { account_id: 'eip155:1', chain_id: 'eip155:1', address: FIXTURE_ADDRESS, derivation_path: "m/44'/60'/0'/0/0" },
        ],
      };
    case 'oc_connect_site':
      state.sites[params.origin] = { account_id: params.account_id, chain_id: params.chain_id };
      return { origin: params.origin };
    case 'oc_list_sites':
      return {
        sites: Object.entries(state.sites).map(([origin, site]) => ({
          origin,
          ...site,
          connected_at: 0,
          last_seen_at: 0,
        })),
      };
    case 'oc_revoke_site':
      delete state.sites[params.origin];
      return { revoked: true };
    case 'oc_chain_registry':
      return { chains: [] };
    case 'oc_policy_preview':
      return { decision: 'allow', reasons: [], matched_policy_ids: [] };
    case 'oc_sign_message':
      return { signature: FIXTURE_SIGNATURE, public_key: '0x' + '11'.repeat(33), recovery_id: 0 };
    case 'oc_sign_typed_data':
      return { signature: FIXTURE_SIGNATURE, public_key: '0x' + '11'.repeat(33) };
    case 'oc_sign_transaction':
      return { raw_transaction: '0x02' + 'ab'.repeat(100), recovery_id: 0 };
    case 'oc_send_transaction':
      return { tx_hash: '0x' + 'cd'.repeat(32) };
    case 'oc_rpc': {
      const canned = {
        eth_chainId: '0x2105',
        eth_blockNumber: '0x1234',
        eth_getBalance: '0xde0b6b3a7640000',
        eth_gasPrice: '0x3b9aca00',
      };
      if (params.method in canned) return { result: canned[params.method] };
      return { result: null };
    }
    case 'oc_audit_tail':
      return { events: [{ event_type: 'SignMessage', wallet_id: 'stub-wallet-1' }] };
    default:
      return { error: { code: -32601, message: `stub: method not found: ${method}` } };
  }
}

const DAPP_PAGE = `<!doctype html>
<html>
  <head><title>OneCipher fixture dApp</title></head>
  <body>
    <h1>fixture dApp</h1>
    <button id="connect">connect</button>
    <button id="sign">personal_sign</button>
    <button id="rejectme">sign to reject</button>
    <a id="payment" href="/payment-required">402</a>
    <pre id="out"></pre>
    <script>
      const out = document.getElementById('out');
      const log = (value) => { out.textContent = typeof value === 'string' ? value : JSON.stringify(value); };
      const request = (method, params) =>
        window.ethereum.request({ method, params }).then(log).catch((error) => log('ERR:' + error.code + ':' + error.message));
      document.getElementById('connect').onclick = () => request('eth_requestAccounts');
      document.getElementById('sign').onclick = () => request('personal_sign', ['0x48656c6c6f204f6e65436970686572']);
      document.getElementById('rejectme').onclick = () => request('personal_sign', ['0x72656a656374']);
    </script>
  </body>
</html>
`;

export function startStubDaemon(port = 0) {
  const server = createServer((req, res) => {
    const origin = req.headers.origin ?? '';
    const cors = origin.startsWith(EXTENSION_ORIGIN_PREFIX) ? { 'Access-Control-Allow-Origin': origin } : {};
    const respond = (payload) => {
      res.writeHead(payload.status, {
        'Content-Type': 'application/json',
        ...cors,
        ...payload.extraHeaders,
      });
      res.end(payload.body);
    };
    if (req.method === 'OPTIONS') {
      res.writeHead(204, { ...cors, 'Access-Control-Allow-Headers': 'content-type', 'Access-Control-Allow-Methods': 'POST, OPTIONS' });
      res.end();
      return;
    }
    if (req.method === 'GET' && req.url === '/dapp.html') {
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(DAPP_PAGE);
      return;
    }
    if (req.method === 'GET' && req.url === '/payment-required') {
      respond(json({ error: 'payment required' }, 402));
      return;
    }
    if (req.method === 'POST' && req.url === '/') {
      if (!origin.startsWith(EXTENSION_ORIGIN_PREFIX)) {
        respond(json({ jsonrpc: '2.0', id: null, error: { code: 4100, message: 'Origin must be a chrome-extension:// origin' } }));
        return;
      }
      let body = '';
      req.on('data', (chunk) => {
        body += chunk;
      });
      req.on('end', () => {
        try {
          const request = JSON.parse(body);
          const result = handleOcwp(request.method, request.params ?? {});
          if (result.error) {
            respond(json({ jsonrpc: '2.0', id: request.id, error: result.error }));
          } else {
            respond(json({ jsonrpc: '2.0', id: request.id, result }));
          }
        } catch (error) {
          respond(json({ jsonrpc: '2.0', id: null, error: { code: -32700, message: String(error) } }));
        }
      });
      return;
    }
    respond(json({ error: 'not found' }, 404));
  });
  return new Promise((resolve) => {
    server.listen(port, '127.0.0.1', () => {
      resolve({
        server,
        port: server.address().port,
        requestLog: state.requestLog,
        state,
      });
    });
  });
}
