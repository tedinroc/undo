// The little Borsh the contract's signed encodings use. A slice or Vec<u8> carries a u32 length;
// a fixed array does not. Mixing those up is a refused signature, not a silent bug.
import { concat, u32le, u64le, utf8 } from './bytes.mjs';

export const b = {
  raw: (bytes) => bytes,
  u8: (n) => Uint8Array.of(n),
  u32: (n) => u32le(n),
  u64: (n) => u64le(n),
  str: (text) => {
    const body = utf8(text);
    return concat(u32le(body.length), body);
  },
  bytes: (bytes) => concat(u32le(bytes.length), bytes),
  option: (value, encode) => (value === null || value === undefined ? Uint8Array.of(0) : concat(Uint8Array.of(1), encode(value))),
  vec: (items, encode) => concat(u32le(items.length), ...items.map(encode)),
};
