// Small helpers for the phone page's tests.
export const base64ToBytes = (text) => new Uint8Array(Buffer.from(text, 'base64'));
