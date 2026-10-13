// Passkey step-up client (design §3.5 / §6.7).
//
// The daemon's passkey protocol (R30) verifies signatures over
// `challenge || credential_id` with a stored public key. The extension acts
// as a software authenticator: it generates an ECDSA P-256 keypair via
// WebCrypto, registers the public key with the daemon, and signs challenges
// on step-up demand.
//
// A `chrome-extension://` page cannot host a real WebAuthn relying party, so
// `navigator.credentials.get()` is not an option here (design §3.5 assumes a
// real RP; see OQ-3). The private JWK therefore lives in
// `chrome.storage.session` — never `local` — so it is wiped when the browser
// closes and never outlives the unlocked session. See storage/passkey.ts for
// the full rationale.

import { bytesToHex, hexToBytes } from './consent/decode';
import type { OcwpClient } from './daemon/client';

const ALG = { name: 'ECDSA', namedCurve: 'P-256' } as const;
const SIGN_ALG = { name: 'ECDSA', hash: 'SHA-256' } as const;

export interface PasskeyMaterial {
  credentialId: string;
  jwk: JsonWebKey;
}

/// Generate a fresh P-256 keypair + credential id.
export async function generatePasskey(): Promise<PasskeyMaterial> {
  const pair = await crypto.subtle.generateKey(ALG, true, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', pair.privateKey);
  const credentialBytes = crypto.getRandomValues(new Uint8Array(16));
  return {
    credentialId: `oc-ext-${bytesToHex(credentialBytes)}`,
    jwk: jwk as JsonWebKey,
  };
}

/// Register the software passkey with the daemon (requires an unlocked session).
export async function registerPasskey(
  daemon: OcwpClient,
  sessionId: string,
  material: PasskeyMaterial,
): Promise<void> {
  const privateKey = await crypto.subtle.importKey('jwk', material.jwk, ALG, false, ['sign']);
  // Export the public key in raw uncompressed SEC1 form (65 bytes, 0x04 || X || Y).
  const publicKeyJwk = await crypto.subtle.exportKey('jwk', await publicFromPrivate(privateKey));
  const raw = sec1FromJwk(publicKeyJwk);
  const publicKeyB64 = btoa(String.fromCharCode(...raw));
  await daemon.passkeyRegister(sessionId, material.credentialId, 'p256', publicKeyB64);
}

async function publicFromPrivate(privateKey: CryptoKey): Promise<CryptoKey> {
  // Re-derive the public key by exporting the JWK and importing only x/y.
  const jwk = (await crypto.subtle.exportKey('jwk', privateKey)) as JsonWebKey;
  const publicKeyJwk: JsonWebKey = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y, ext: true };
  return crypto.subtle.importKey('jwk', publicKeyJwk, ALG, true, ['verify']);
}

/// Convert a JWK (x/y base64url) into raw uncompressed SEC1 bytes.
function sec1FromJwk(jwk: JsonWebKey): Uint8Array {
  const x = base64UrlDecode(jwk.x ?? '');
  const y = base64UrlDecode(jwk.y ?? '');
  const out = new Uint8Array(65);
  out[0] = 0x04;
  out.set(x, 1);
  out.set(y, 33);
  return out;
}

function base64UrlDecode(value: string): Uint8Array {
  const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/// Sign `challenge || credential_id` (the OneCipher simplified protocol).
export async function signPasskeyChallenge(
  material: PasskeyMaterial,
  challengeHex: string,
): Promise<string> {
  const privateKey = await crypto.subtle.importKey('jwk', material.jwk, ALG, false, ['sign']);
  const message = new Uint8Array([...hexToBytes(challengeHex), ...new TextEncoder().encode(material.credentialId)]);
  const signature = await crypto.subtle.sign(SIGN_ALG, privateKey, message);
  return bytesToHex(new Uint8Array(signature));
}
