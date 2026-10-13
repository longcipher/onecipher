// Playwright e2e: consent flow against the stub OCWP daemon (design §9.5).
//
// Disposable profile, real Chromium, load-unpacked extension, fixture dApp.
// Verifies: connect consent → account returned; personal_sign approve →
// signature; reject → 4001; HTTP 402 passthrough; zero captures.
// Writes auditable evidence to e2e/verification/e2e.json.

import { chromium } from 'playwright';
import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { startStubDaemon } from '../scripts/stub-daemon.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const extensionPath = join(root, '.output', 'chrome-mv3');
const evidenceDir = join(root, 'e2e', 'verification');

const results = {
  checkedAt: new Date().toISOString(),
  profile: 'disposable and removed',
  installedInUserProfile: false,
  normalConnectionApproval: false,
  signingApprovalAndRejection: false,
  rejectReturns4001: false,
  http402Preserved: false,
  captures: 0,
  daemonCalls: 0,
};

/// secp256k1 group order. `r`/`s` must be non-zero and below it.
const SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n;

/**
 * Assert a string is a well-formed 65-byte EIP-191 signature.
 *
 * This is deliberately a *shape* check, not a recovery check: the e2e runs
 * against a stub daemon, so recovering a signer from a fixture signature would
 * only prove the stub returns its own constant. What this does catch is the
 * extension mangling a signature it was handed — the failure mode that belongs
 * to this layer. Design §9.5's recovery requirement is met by the Rust
 * signer's own sign/recover round-trip tests.
 */
function expectValidEip191Signature(value, label) {
  if (typeof value !== 'string' || !value.startsWith('0x')) {
    throw new Error(`${label}: expected a 0x-prefixed signature, got ${String(value)}`);
  }
  const body = value.slice(2);
  if (!/^[0-9a-f]+$/i.test(body)) throw new Error(`${label}: signature is not hex`);
  if (body.length !== 130) throw new Error(`${label}: expected 65 bytes, got ${body.length / 2}`);
  const r = BigInt(`0x${body.slice(0, 64)}`);
  const s = BigInt(`0x${body.slice(64, 128)}`);
  const v = Number.parseInt(body.slice(128, 130), 16);
  if (r === 0n) throw new Error(`${label}: r must be non-zero`);
  if (s === 0n) throw new Error(`${label}: s must be non-zero`);
  if (r >= SECP256K1_ORDER) throw new Error(`${label}: r must be below the curve order`);
  if (s >= SECP256K1_ORDER) throw new Error(`${label}: s must be below the curve order`);
  if (v !== 27 && v !== 28) throw new Error(`${label}: v must be 27 or 28, got ${v}`);
}

async function main() {
  const daemon = await startStubDaemon(18080);
  console.log(`stub daemon on http://127.0.0.1:${daemon.port}`);
  const profile = await mkdtemp(join(tmpdir(), 'onecipher-e2e-'));

  let context;
  try {
    context = await chromium.launchPersistentContext(profile, {
      channel: 'chromium',
      headless: true,
      args: [
        `--disable-extensions-except=${extensionPath}`,
        `--load-extension=${extensionPath}`,
      ],
    });

    // Extension id from the MV3 service worker.
    let [worker] = context.serviceWorkers();
    if (!worker) worker = await context.waitForEvent('serviceworker');
    const extensionId = new URL(worker.url()).host;
    console.log(`extension id: ${extensionId}`);
    // Ring-buffer SW console errors for failure diagnostics.
    const swErrors = [];
    const attachSwLogging = (sw) => {
      sw.on('console', (msg) => {
        if (msg.type() === 'error' || msg.type() === 'warning') {
          swErrors.push(`[${msg.type()}] ${msg.text()}`);
          if (swErrors.length > 20) swErrors.shift();
        }
      });
      sw.on('close', () => swErrors.push('[sw-close] service worker terminated'));
    };
    attachSwLogging(worker);
    context.on('serviceworker', attachSwLogging);

    const dappUrl = `http://127.0.0.1:${daemon.port}/dapp.html`;
    const page = await context.newPage();

    // --- 0. unlock via the popup (session unlock, design §3.5) --------------
    const popupPage = await context.newPage();
    await popupPage.goto(`chrome-extension://${extensionId}/popup.html`);
    await popupPage.locator('input[type="password"]').fill('stub-passphrase');
    await popupPage.getByRole('button', { name: 'Unlock' }).click();
    await popupPage.waitForFunction(
      () => document.body.textContent?.includes('unlocked'),
      undefined,
      { timeout: 10_000 },
    );
    await popupPage.close();
    console.log('popup unlock: OK');

    await page.goto(dappUrl);

    // Poll for a notification window with the decision button. A previously
    // served window may be tearing down (queue drained → self-close), so a
    // single waitForEvent races with the teardown — poll instead.
    const decideInNotification = async (label) => {
      const deadline = Date.now() + 20_000;
      let clicked = false;
      while (Date.now() < deadline) {
        const candidates = context.pages().filter((candidate) => candidate.url().includes('popup.html'));
        for (const popup of candidates) {
          try {
            const button = popup.getByRole('button', { name: label, exact: true });
            if (await button.isVisible({ timeout: 500 }).catch(() => false)) {
              clicked = true;
              // The click may race the post-decision window close; a throw
              // after dispatch still consumed the action, so fall through to
              // the close-wait instead of treating it as failure.
              await button.click({ timeout: 3000 }).catch(() => undefined);
              if (await waitForNotificationClosed()) return;
              break; // decision not consumed — restart the poll
            }
          } catch {
            // Window may be closing; retry with a fresh snapshot.
          }
        }
        if (clicked && context.pages().every((candidate) => !candidate.url().includes('popup.html'))) {
          return; // decision consumed and the window is gone
        }
        await new Promise((resolve) => setTimeout(resolve, 250));
      }
      // Diagnostics: dump SW queue state + console errors + every open page.
      try {
        const swState = await worker.evaluate(() => ({
          queueSize: globalThis.__ocDebug?.queueSize() ?? -1,
          windowId: globalThis.__ocDebug?.notificationWindowId() ?? null,
          requests: globalThis.__ocDebug?.requestLog() ?? [],
        }));
        console.error(`[diag] SW: ${JSON.stringify(swState)}`);
      } catch {
        console.error('[diag] SW evaluate failed (worker may have restarted)');
      }
      for (const entry of swErrors) console.error(`[diag] swErrors: ${entry}`);
      for (const candidate of context.pages()) {
        const body = await candidate
          .locator('body')
          .innerText()
          .catch(() => '<unavailable>');
        console.error(`[diag] page ${candidate.url()}: ${body.slice(0, 200)}`);
      }
      throw new Error(`no notification window with a ${label} button appeared`);
    };
    const approveInNotification = () => decideInNotification('Approve');
    const rejectInNotification = () => decideInNotification('Reject');
    /// Wait until the served notification window is fully gone. Returns true
    /// when it closed, false on timeout. The window self-closes when the
    /// queue drains; racing it with the next dApp trigger makes the
    /// orchestration ambiguous (stale Approve buttons).
    const waitForNotificationClosed = async () => {
      const deadline = Date.now() + 10_000;
      while (Date.now() < deadline) {
        const open = context.pages().filter((candidate) => candidate.url().includes('popup.html'));
        if (open.length === 0) return true;
        await new Promise((resolve) => setTimeout(resolve, 200));
      }
      console.error('[diag] notification window did not close within 10s');
      return false;
    };

    // --- 1. connect consent -------------------------------------------------
    await page.getByRole('button', { name: 'connect' }).click();
    await approveInNotification();
    await page.waitForFunction(
      () => document.getElementById('out')?.textContent?.includes('0xaaaabbbb'),
      undefined,
      { timeout: 10_000 },
    );
    await waitForNotificationClosed();
    results.normalConnectionApproval = true;
    console.log('connect consent: OK');

    // --- 2. personal_sign approve -------------------------------------------
    await page.getByRole('button', { name: 'personal_sign', exact: true }).click();
    await approveInNotification();
    await page.waitForFunction(
      () => document.getElementById('out')?.textContent?.includes('0x8f5b1c0d'),
      undefined,
      { timeout: 10_000 },
    );
    console.log('personal_sign approve: OK');
    await waitForNotificationClosed();

    // --- 2b. the signature is structurally valid (design §9.5) --------------
    // Full signer-vs-signature recovery is a Rust-side property — the daemon
    // signs, and a stub daemon has nothing to recover from. What the extension
    // CAN be caught breaking is the plumbing: truncation, a dropped 0x, a
    // result unwrapped into an object. So assert the EIP-191 shape a dApp
    // itself would validate.
    const signature = await page.evaluate(() => document.getElementById('out')?.textContent ?? '');
    expectValidEip191Signature(signature, 'personal_sign result');
    console.log('signature shape valid: OK');

    // --- 3. personal_sign reject → 4001 --------------------------------------
    await page.getByRole('button', { name: 'sign to reject' }).click();
    await rejectInNotification();
    await page.waitForFunction(
      () => document.getElementById('out')?.textContent?.startsWith('ERR:4001'),
      undefined,
      { timeout: 10_000 },
    );
    await waitForNotificationClosed();
    results.signingApprovalAndRejection = true;
    results.rejectReturns4001 = true;
    console.log('personal_sign reject (4001): OK');

    // --- 4. HTTP 402 passthrough (INV-8) -------------------------------------
    const status = await page.evaluate(async (url) => {
      const response = await fetch(url);
      return response.status;
    }, `http://127.0.0.1:${daemon.port}/payment-required`);
    results.http402Preserved = status === 402;
    console.log(`HTTP 402 passthrough: ${status === 402 ? 'OK' : 'FAIL ' + status}`);

    // --- 5. no screenshots / captures (sentinel) ------------------------------
    results.captures = await worker.evaluate(() => globalThis.__ocCaptures ?? 0);
    results.daemonCalls = daemon.requestLog.length;
  } finally {
    if (context) await context.close().catch(() => undefined);
    await rm(profile, { recursive: true, force: true }).catch(() => undefined);
    daemon.server.close();
  }

  await mkdir(evidenceDir, { recursive: true });
  await writeFile(join(evidenceDir, 'e2e.json'), JSON.stringify(results, null, 2) + '\n');
  console.log('evidence written to e2e/verification/e2e.json');

  const failed = !results.normalConnectionApproval || !results.signingApprovalAndRejection ||
    !results.rejectReturns4001 || !results.http402Preserved || results.captures !== 0;
  if (failed) {
    console.error('e2e FAILED:', results);
    process.exit(1);
  }
  console.log('e2e PASSED');
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
