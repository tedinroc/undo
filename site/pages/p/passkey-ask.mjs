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

function watched(start, { onHang }) {
  const watch = watchSheet(window);
  const hang = setTimeout(() => {
    if (!watch.evidence().seen) onHang?.();
  }, SHEET_HANG_MS);
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

/** Resolves to { assertion, evidence }. `assertion` is getAssertion's: args, highS, credentialId, flags. */
export function askAssertion(ctx, { digest, credentialId = null, onHang = null }) {
  return watched(() => getAssertion({ credentials: ctx.credentials, digest, rpId: ctx.config.rpId, credentialId, timeoutMs: 60_000 }), { onHang })
    .then(({ value, evidence }) => ({ assertion: value, evidence }));
}

/** Resolves to { passkey, evidence }, where passkey is createPasskey's: pubkey, credentialId, flags. */
export function askNewPasskey(ctx, { label, onHang = null }) {
  return watched(() => createPasskey({ credentials: ctx.credentials, rpId: ctx.config.rpId, label }), { onHang })
    .then(({ value, evidence }) => ({ passkey: value, evidence }));
}
