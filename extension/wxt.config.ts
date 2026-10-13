import { defineConfig } from 'wxt';

// OneCipher Wallet — MV3 extension over the OneCipher daemon (OCWP).
// See docs/extension-wallet-design.md. Permission surface is minimal (§4.2):
// `storage` only, loopback-only host permissions (RPC is proxied by the daemon),
// and a single web-accessible resource (the injected EIP-1193 provider).
export default defineConfig({
  modules: ['@wxt-dev/module-react'],
  srcDir: 'src',
  manifest: {
    name: 'OneCipher Wallet',
    description:
      'Policy-gated EVM wallet. Keys stay in your OneCipher vault; every connection, signature and transaction needs explicit approval.',
    icons: {
      16: '/icon/icon-16.png',
      32: '/icon/icon-32.png',
      48: '/icon/icon-48.png',
      128: '/icon/icon-128.png',
    },
    permissions: ['storage'],
    host_permissions: ['http://127.0.0.1/*', 'http://localhost/*'],
    web_accessible_resources: [
      {
        resources: ['injected.js'],
        matches: ['http://*/*', 'https://*/*'],
      },
    ],
    // storage.session (session unlock handle) is stable since Chrome 102;
    // MV3 service-worker lifecycle is dependable from 116 on.
    minimum_chrome_version: '116',
    browser_specific_settings: {
      gecko: {
        id: 'onecipher-wallet@onecipher.io',
        strict_min_version: '128.0',
      },
    },
  },
});
