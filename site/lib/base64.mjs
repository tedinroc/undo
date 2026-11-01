// Base64 with no Buffer, so the same file runs in a page, a Worker and Node.

export function toBase64(bytes) {
  let text = '';
  for (let i = 0; i < bytes.length; i += 1) text += String.fromCharCode(bytes[i]);
  return btoa(text);
}

export function fromBase64(text) {
  const raw = atob(text);
  const out = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i += 1) out[i] = raw.charCodeAt(i);
  return out;
}

/** Unpadded, the form a WebAuthn challenge takes in clientDataJSON. */
export const toBase64Url = (bytes) => toBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

export function fromBase64Url(text) {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new Error('not base64url');
  const padded = text.replace(/-/g, '+').replace(/_/g, '/');
  return fromBase64(padded + '='.repeat((4 - (padded.length % 4)) % 4));
}

export const toArrayBuffer = (bytes) => bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
export const fromBuffer = (buffer) => (buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer));
