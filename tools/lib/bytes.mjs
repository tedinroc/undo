// Byte helpers. Strict on input: a tool that accepts sloppy hex can sign the wrong thing.

export function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function fromHex(text, what = 'value') {
  if (typeof text !== 'string' || text.length % 2 !== 0 || !/^[0-9a-f]*$/.test(text)) {
    throw new Error(`${what} is not lowercase hex`);
  }
  const out = new Uint8Array(text.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function fixedHex(text, length, what) {
  const out = fromHex(text, what);
  if (out.length !== length) throw new Error(`${what} must be ${length} bytes`);
  return out;
}

export function concat(...parts) {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

export function utf8(text) {
  return new TextEncoder().encode(text);
}

export function equal(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

export function reversed(bytes) {
  return Uint8Array.from(bytes).reverse();
}

export function u32le(n) {
  if (!Number.isInteger(n) || n < 0 || n > 0xffffffff) throw new Error('not a u32');
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, true);
  return out;
}

export function u64le(n) {
  const v = BigInt(n);
  if (v < 0n || v > 0xffffffffffffffffn) throw new Error('not a u64');
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, v, true);
  return out;
}

export function u128le(n) {
  const v = BigInt(n);
  if (v < 0n || v >= 1n << 128n) throw new Error('not a u128');
  return concat(u64le(v & 0xffffffffffffffffn), u64le(v >> 64n));
}

export function toBase64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

export function fromBase64(text) {
  return new Uint8Array(Buffer.from(text, 'base64'));
}

const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58Encode(bytes) {
  const digits = [];
  for (const byte of bytes) {
    let carry = byte;
    for (let i = 0; i < digits.length; i += 1) {
      carry += digits[i] << 8;
      digits[i] = carry % 58;
      carry = Math.floor(carry / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let out = '';
  for (const byte of bytes) {
    if (byte !== 0) break;
    out += '1';
  }
  return out + digits.reverse().map((d) => B58[d]).join('');
}

export function base58Decode(text) {
  const out = [];
  for (const ch of text) {
    let carry = B58.indexOf(ch);
    if (carry < 0) throw new Error('not base58');
    for (let i = 0; i < out.length; i += 1) {
      carry += out[i] * 58;
      out[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      out.push(carry & 0xff);
      carry >>= 8;
    }
  }
  for (const ch of text) {
    if (ch !== '1') break;
    out.push(0);
  }
  return Uint8Array.from(out.reverse());
}
