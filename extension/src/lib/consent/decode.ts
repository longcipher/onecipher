// Consent-view decoding — turn raw request params into human-readable detail
// cards (design §4.8). Display only: signing happens daemon-side, so this
// module needs no chain SDK; a minimal RLP decoder + a built-in selector
// table replaces viem/ethers.

import type { ConsentField, ConsentView } from '../protocol';
import { rpcError } from '../protocol';

// ---------------------------------------------------------------------------
// Hex / byte helpers (realm-safe; mirrors clawd-wallet F18)
// ---------------------------------------------------------------------------

export function stripHexPrefix(value: string): string {
  return value.startsWith('0x') || value.startsWith('0X') ? value.slice(2) : value;
}

export function isHex(value: string): boolean {
  return /^(0x|0X)?[0-9a-fA-F]*$/.test(value) && stripHexPrefix(value).length % 2 === 0;
}

export function hexToBytes(value: string): Uint8Array {
  const clean = stripHexPrefix(value);
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/// Decode bytes as UTF-8 for display. `ignoreBOM` keeps a leading EF BB BF so
/// re-encoded signatures match the dApp's original bytes (F18).
export function tryDecodeUtf8(bytes: Uint8Array): string | null {
  try {
    return new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  } catch {
    return null;
  }
}

/// Format a wei value (decimal string) as ETH with sensible precision.
export function formatWei(wei: string): string {
  if (!/^\d+$/.test(wei)) return wei;
  const negative = wei.startsWith('-');
  const digits = negative ? wei.slice(1) : wei;
  if (digits === '0') return '0 ETH';
  const padded = digits.padStart(19, '0');
  const whole = padded.slice(0, padded.length - 18).replace(/^0+(?=\d)/, '');
  const frac = padded.slice(-18).replace(/0+$/, '');
  const eth = frac ? `${whole}.${frac}` : whole;
  return `${negative ? '-' : ''}${eth} ETH`;
}

// ---------------------------------------------------------------------------
// Minimal RLP decoding (mirror of the Rust decoder in ocwp/handlers.rs)
// ---------------------------------------------------------------------------

type RlpItem = { bytes: Uint8Array } | { list: RlpItem[] };

function isList(item: RlpItem): item is { list: RlpItem[] } {
  return 'list' in item;
}

function rlpDecode(data: Uint8Array): { item: RlpItem; end: number } | null {
  const first = data[0];
  if (first === undefined) return null;
  if (first < 0x80) return { item: { bytes: data.slice(0, 1) }, end: 1 };
  if (first <= 0xb7) {
    const len = first - 0x80;
    if (data.length < 1 + len) return null;
    return { item: { bytes: data.slice(1, 1 + len) }, end: 1 + len };
  }
  if (first <= 0xbf) {
    const lenOfLen = first - 0xb7;
    const parsed = rlpReadLen(data, lenOfLen);
    return parsed ? { item: { bytes: data.slice(parsed.end - parsed.len, parsed.end) }, end: parsed.end } : null;
  }
  if (first <= 0xf7) {
    const len = first - 0xc0;
    if (data.length < 1 + len) return null;
    const inner = rlpDecodeList(data.slice(1, 1 + len));
    return inner ? { item: { list: inner }, end: 1 + len } : null;
  }
  const lenOfLen = first - 0xf7;
  const parsed = rlpReadLen(data, lenOfLen);
  if (!parsed) return null;
  const inner = rlpDecodeList(data.slice(parsed.end - parsed.len, parsed.end));
  return inner ? { item: { list: inner }, end: parsed.end } : null;
}

function rlpReadLen(data: Uint8Array, lenOfLen: number): { len: number; end: number } | null {
  if (lenOfLen === 0 || lenOfLen > 8 || data.length < 1 + lenOfLen) return null;
  let len = 0;
  for (let i = 1; i <= lenOfLen; i++) {
    const byte = data[i];
    if (byte === undefined) return null;
    len = len * 256 + byte;
    if (!Number.isSafeInteger(len)) return null;
  }
  if (len < 56) return null; // minimal-encoding violation
  const end = 1 + lenOfLen + len;
  if (data.length < end) return null;
  return { len, end };
}

function rlpDecodeList(data: Uint8Array): RlpItem[] | null {
  const out: RlpItem[] = [];
  let rest = data;
  while (rest.length > 0) {
    const decoded = rlpDecode(rest);
    if (!decoded) return null;
    out.push(decoded.item);
    rest = rest.slice(decoded.end);
  }
  return out;
}

function rlpBytes(item: RlpItem | undefined): Uint8Array | null {
  return item && 'bytes' in item ? item.bytes : null;
}

// ---------------------------------------------------------------------------
// Well-known function selectors (display only — informational, not security)
// ---------------------------------------------------------------------------

const SELECTORS: Record<string, string> = {
  'a9059cbb': 'transfer(address,uint256)',
  '095ea7b3': 'approve(address,uint256)',
  '23b872dd': 'transferFrom(address,address,uint256)',
  'd0e30db0': 'deposit()',
  '2e1a7d4d': 'withdraw(uint256)',
  '6e553f65': 'permit2 analogue (verify the contract!)',
  'dd62ed3e': 'allowance(address,address)',
  '70a08231': 'balanceOf(address)',
  'e8e33700': 'permit(...) (EIP-2612)',
  'b6f9de95': 'swapExactETHForTokens*',
  '38ed1739': 'swapExactTokensForTokens*',
  '18cbafe5': 'swapExactTokensForETH*',
  '7ff36ab5': 'swapExactETHForTokensSupportingFee*',
  '5c11d795': 'swapExactTokensForTokensSupportingFee*',
  '791ac947': 'swapExactTokensForETHSupportingFee*',
  'fb3bdb41': 'swapETHForExactTokens*',
  '4e71d92d': 'claim()',
  '1249c58b': 'mint(...)',
};

/// Detect `approve(spender, 2^256-1)` — the unlimited-allowance pattern.
function isUnlimitedApprove(selector: string | null, data: Uint8Array): boolean {
  if (selector !== '095ea7b3' || data.length < 4 + 32 + 32) return false;
  for (let i = 4 + 32; i < 4 + 64; i++) {
    if (data[i] !== 0xff) return false;
  }
  return true;
}

// ---------------------------------------------------------------------------
// Transaction summary (mirror of decode_tx_summary in ocwp/handlers.rs)
// ---------------------------------------------------------------------------

export interface TxSummary {
  type: 'legacy' | 'eip2930' | 'eip1559' | 'eip7702' | 'unknown';
  to: string | null;
  value: string | null;
  data: string | null;
  chainId: string | null;
  nonce: string | null;
  gasLimit: string | null;
  selectorName: string | null;
  unlimitedApprove: boolean;
}

function bytesToDecimal(bytes: Uint8Array): string {
  // Arbitrary-precision decimal via BigInt.
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value.toString(10);
}

export function decodeTransactionSummary(rawHex: string): TxSummary {
  const empty: TxSummary = {
    type: 'unknown', to: null, value: null, data: null,
    chainId: null, nonce: null, gasLimit: null, selectorName: null, unlimitedApprove: false,
  };
  let bytes: Uint8Array;
  try {
    bytes = hexToBytes(rawHex);
  } catch {
    return empty;
  }
  if (bytes.length === 0) return empty;
  const typeByte = bytes[0];
  if (typeByte === undefined) return empty;
  const typed = typeByte >= 0x01 && typeByte <= 0x04;
  const type: TxSummary['type'] =
    typeByte === 0x02 ? 'eip1559' : typeByte === 0x01 ? 'eip2930' : typeByte === 0x04 ? 'eip7702' : typed ? 'unknown' : 'legacy';
  const body = typed ? bytes.slice(1) : bytes;
  const decoded = rlpDecode(body);
  if (!decoded || !isList(decoded.item)) return empty;
  const fields = decoded.item.list;
  const indexes = type === 'eip1559' ? { to: 5, value: 6, data: 7, chain: 0, nonce: 1, gas: 4 }
    : type === 'eip2930' ? { to: 4, value: 5, data: 6, chain: 0, nonce: 1, gas: 3 }
    : type === 'eip7702' ? { to: 5, value: 6, data: 7, chain: 0, nonce: 1, gas: 4 }
    : { to: 3, value: 4, data: 5, chain: null, nonce: 0, gas: 2 };
  const toBytes = rlpBytes(fields[indexes.to]);
  const valueBytes = rlpBytes(fields[indexes.value]);
  const dataBytes = rlpBytes(fields[indexes.data]);
  const chainBytes = indexes.chain === null ? null : rlpBytes(fields[indexes.chain]);
  const nonceBytes = rlpBytes(fields[indexes.nonce]);
  const gasBytes = rlpBytes(fields[indexes.gas]);
  const selector =
    dataBytes && dataBytes.length >= 4 ? bytesToHex(dataBytes.slice(0, 4)) : null;
  return {
    type,
    to: toBytes && toBytes.length === 20 ? `0x${bytesToHex(toBytes)}` : null,
    value: valueBytes ? bytesToDecimal(valueBytes) : null,
    data: dataBytes && dataBytes.length > 0 ? `0x${bytesToHex(dataBytes)}` : null,
    chainId: chainBytes ? bytesToDecimal(chainBytes) : null,
    nonce: nonceBytes ? bytesToDecimal(nonceBytes) : null,
    gasLimit: gasBytes ? bytesToDecimal(gasBytes) : null,
    selectorName: selector ? SELECTORS[selector] ?? null : null,
    unlimitedApprove: isUnlimitedApprove(selector, dataBytes ?? new Uint8Array()),
  };
}

// ---------------------------------------------------------------------------
// Consent view builders
// ---------------------------------------------------------------------------

function truncateMiddle(value: string, head = 10, tail = 8): string {
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

export function buildMessageView(messageB64: string, encoding: string): ConsentView {
  const fields: ConsentField[] = [];
  const warnings: string[] = [];
  let summary = 'Sign a message';
  let bytes: Uint8Array;
  try {
    const binary = atob(messageB64);
    bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  } catch {
    bytes = new Uint8Array(0);
  }
  const text = tryDecodeUtf8(bytes);
  fields.push({ label: 'Length', value: `${bytes.length} bytes` });
  if (text !== null && text.length > 0 && [...text].every((ch) => ch >= ' ' || ch === '\n' || ch === '\t')) {
    fields.push({ label: 'Message', value: text });
    summary = 'Sign message text';
  } else {
    fields.push({ label: 'Raw bytes (hex)', value: `0x${bytesToHex(bytes)}`, kind: 'code' });
    warnings.push('Message is not printable UTF-8 — inspect the raw bytes before approving.');
    summary = 'Sign binary message';
  }
  if (encoding !== 'hex') {
    warnings.push(`Requested encoding is "${encoding}" — bytes are signed verbatim.`);
  }
  void truncateMiddle; // kept for address formatting in tx views
  return { title: 'Sign message', summary, fields, warnings };
}

export function buildTypedDataView(typedData: Record<string, unknown>): ConsentView {
  const fields: ConsentField[] = [];
  const warnings: string[] = [];
  const domain = (typedData['domain'] ?? {}) as Record<string, unknown>;
  const primaryType = typeof typedData['primaryType'] === 'string' ? typedData['primaryType'] : 'unknown';
  fields.push({ label: 'Type', value: String(primaryType) });
  if (typeof domain['name'] === 'string') fields.push({ label: 'Domain', value: domain['name'] });
  if (typeof domain['version'] === 'string') fields.push({ label: 'Version', value: domain['version'] });
  if (typeof domain['chainId'] === 'number') fields.push({ label: 'Chain', value: `eip155:${domain['chainId']}` });
  const verifyingContract = typeof domain['verifyingContract'] === 'string' ? domain['verifyingContract'] : null;
  if (verifyingContract) fields.push({ label: 'Verifying contract', value: verifyingContract, kind: 'code' });
  const message = typedData['message'];
  if (message !== null && typeof message === 'object') {
    for (const [key, value] of Object.entries(message as Record<string, unknown>).slice(0, 12)) {
      fields.push({
        label: key,
        value: typeof value === 'string' && value.startsWith('0x') && value.length > 24
          ? truncateMiddle(value)
          : String(value),
        kind: typeof value === 'string' && value.length > 40 ? 'code' : 'text',
      });
    }
  }
  warnings.push('Structured signatures can grant permissions (e.g. token permits). Verify the domain and contract.');
  return { title: 'Sign typed data (EIP-712)', summary: `Sign ${String(primaryType)} structure`, fields, warnings };
}

export function buildTransactionView(
  kind: 'sign_transaction' | 'send_transaction',
  tx: Record<string, unknown>,
  chainName: string,
  delegations: string[] = [],
): ConsentView {
  const fields: ConsentField[] = [];
  const warnings: string[] = [];
  let summary: string;
  if (typeof tx['raw'] === 'string') {
    const decoded = decodeTransactionSummary(tx['raw']);
    summary = kind === 'send_transaction' ? 'Approve & broadcast transaction' : 'Approve transaction';
    if (decoded.to) fields.push({ label: 'To', value: decoded.to, kind: 'code' });
    if (decoded.value) fields.push({ label: 'Value', value: formatWei(decoded.value) });
    fields.push({ label: 'Tx type', value: decoded.type });
    if (decoded.gasLimit) fields.push({ label: 'Gas limit', value: decoded.gasLimit });
    if (decoded.nonce) fields.push({ label: 'Nonce', value: decoded.nonce });
    if (decoded.selectorName) fields.push({ label: 'Function', value: decoded.selectorName });
    if (decoded.data) fields.push({ label: 'Data', value: truncateMiddle(decoded.data, 20, 10), kind: 'code' });
    if (decoded.unlimitedApprove) {
      warnings.push('UNLIMITED token approval detected — the spender can move your entire balance.');
    }
    if (decoded.type === 'eip7702') {
      warnings.push('EIP-7702 delegation: this transaction changes who can act as your account.');
    }
  } else {
    // Structured EVM fields (normalized to OCWP snake_case upstream).
    summary = kind === 'send_transaction' ? 'Approve & send transaction' : 'Sign transaction';
    const to = typeof tx['to'] === 'string' ? tx['to'] : null;
    const value = typeof tx['value'] === 'string' ? tx['value'] : '0';
    fields.push({ label: 'To', value: to ?? '(contract creation)', kind: to ? 'code' : 'warn' });
    fields.push({ label: 'Value', value: formatWei(value) });
    const data = typeof tx['data'] === 'string' ? tx['data'] : null;
    if (data && data !== '0x') {
      const selector = data.slice(2, 10);
      fields.push({ label: 'Function', value: SELECTORS[selector] ?? `selector 0x${selector}` });
      fields.push({ label: 'Data', value: truncateMiddle(data, 20, 10), kind: 'code' });
      if (isUnlimitedApprove(selector, hexToBytes(data))) {
        warnings.push('UNLIMITED token approval detected — the spender can move your entire balance.');
      }
    }
    if (typeof tx['gas_limit'] === 'string') fields.push({ label: 'Gas limit', value: tx['gas_limit'] });
    if (typeof tx['nonce'] === 'string') fields.push({ label: 'Nonce', value: tx['nonce'] });
    // Show the fee ceiling the dApp pinned: the whole point of honoring it
    // (D-2) is that the user can see what they approved.
    const maxFee = tx['max_fee_per_gas'];
    if (typeof maxFee === 'string') {
      fields.push({ label: 'Max fee', value: `${formatWei(maxFee)}/gas` });
    }
    const priority = tx['max_priority_fee_per_gas'];
    if (typeof priority === 'string') {
      fields.push({ label: 'Priority fee', value: `${formatWei(priority)}/gas` });
    }
    if (typeof tx['type'] === 'string') fields.push({ label: 'Tx type', value: tx['type'] });
  }
  fields.push({ label: 'Chain', value: chainName });
  for (const delegation of delegations) {
    // An authorization hands code-execution rights to an address; that must
    // be spelled out, not buried in a hex blob (design §4.8).
    warnings.push(`EIP-7702: this transaction delegates your account to ${delegation}.`);
  }
  return { title: kind === 'send_transaction' ? 'Send transaction' : 'Sign transaction', summary, fields, warnings };
}

export function buildConnectView(origin: string, accountId: string): ConsentView {
  return {
    title: 'Connection request',
    summary: `Connect ${origin}`,
    fields: [
      { label: 'Site', value: origin, kind: 'code' },
      { label: 'Account', value: accountId },
    ],
    warnings: ['A site connection alone grants NO signing rights — every signature still asks.'],
  };
}

/// Throw a normalized error for invalid dApp params (mirrors -32602).
export function invalidParams(message: string): never {
  throw rpcError(-32602, message);
}
