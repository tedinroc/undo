// The two passkey calls, with the watch around them. Each must be started synchronously from the click that asked
// for it: iOS Safari only opens the sheet inside a user gesture, so nothing here awaits before the browser call.
import { createPasskey, getAssertion } from '/site/lib/index.mjs';
import { classifyPasskeyError, SHEET_HANG_MS, watchSheet } from './sense.mjs';

export class PasskeyFailed extends Error {
  constructor(classified, evidence) {
    super(`${classified.name}: ${classified.message}`);
    Object.assign(this, classified, { evidence });
  }
}

function watched(start, { onHang, signal = null }) {
  const watch = watchSheet(window);
  const hang = setTimeout(() => {
    if (!watch.evidence().seen) onHang?.();
  }, SHEET_HANG_MS);
  // A call the page gave up on may never settle, so its watch ends with the abort and not with an answer.
  signal?.addEventListener('abort', () => {
    clearTimeout(hang);
    watch.stop();
  }, { once: true });
  let pending;
  try {
    pending = start();
  } catch (err) {
    pending = Promise.reject(err);
  }
  return pending.then(
    (value) => {
      clearTimeout(hang);
      return { value, evidence: watch.stop() };
    },
    (err) => {
      clearTimeout(hang);
      const evidence = watch.stop();
      throw new PasskeyFailed(classifyPasskeyError(err, evidence), evidence);
    },
  );
}

/**
 * Resolves to { assertion, evidence }. `assertion` is getAssertion's: args, highS, credentialId, flags. `signal` is the
 * caller's AbortSignal: a page aborts a call only from a tap, never from a timer, because a timer cannot tell a stuck
 * call from a sheet a person is still reading, and an abort closes that sheet.
 */
export function askAssertion(ctx, { digest, credentialId = null, onHang = null, signal = null }) {
  return watched(() => getAssertion({ credentials: ctx.credentials, digest, rpId: ctx.config.rpId, credentialId, timeoutMs: 60_000, signal }), { onHang, signal })
    .then(({ value, evidence }) => ({ assertion: value, evidence }));
}

/** Resolves to { passkey, evidence }, where passkey is createPasskey's: pubkey, credentialId, flags. `signal` as above. */
export function askNewPasskey(ctx, { label, onHang = null, signal = null }) {
  return watched(() => createPasskey({ credentials: ctx.credentials, rpId: ctx.config.rpId, label, signal }), { onHang, signal })
    .then(({ value, evidence }) => ({ passkey: value, evidence }));
}
