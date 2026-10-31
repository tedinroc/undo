//! Turning an (r, s) pair into the signature bytes a Bitcoin witness carries.
//!
//! The MPC network returns r and s as numbers, so DER is ours to get right. An EVM encoder on the
//! same path already got leading zeros wrong in an earlier prototype. Both failure classes here are
//! silent in unit tests and only fail on a node: consensus DERSIG refuses a badly padded integer,
//! and relay policy LOW_S refuses a high s.

use crate::Error;

/// The secp256k1 group order.
const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48,
    0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];
/// Half the order, rounded down. An s above this is high.
const HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4,
    0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

fn is_zero(x: &[u8; 32]) -> bool {
    x.iter().all(|b| *b == 0)
}

/// `ORDER - s`, for 0 < s < ORDER.
fn negate(s: &[u8; 32]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let d = i16::from(ORDER[i]) - i16::from(s[i]) - borrow;
        borrow = i16::from(d < 0);
        out[i] = d.rem_euclid(256) as u8;
    }
    out
}

/// A minimal DER integer: no leading zero unless the next byte's top bit needs one.
fn write_der_int(out: &mut Vec<u8>, x: &[u8; 32]) {
    let first = x.iter().position(|b| *b != 0).unwrap_or(31);
    let body = &x[first..];
    let pad = body[0] & 0x80 != 0;
    out.push(2);
    out.push((body.len() + usize::from(pad)) as u8);
    if pad {
        out.push(0);
    }
    out.extend_from_slice(body);
}

/// A signature in canonical form: strict DER, low s, with the SIGHASH_ALL byte.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DerSig {
    bytes: Vec<u8>,
    flipped: bool,
}

impl DerSig {
    /// Encodes (r, s), replacing a high s with its low form. Either form verifies against the
    /// same key and digest, and only the low one relays. r and s must be in 1..ORDER.
    pub fn from_rs(r: &[u8; 32], s: &[u8; 32]) -> Result<Self, Error> {
        if is_zero(r) || is_zero(s) || r >= &ORDER || s >= &ORDER {
            return Err(Error::BadSignature);
        }
        let flipped = s > &HALF_ORDER;
        let low = if flipped { negate(s) } else { *s };
        let mut body = Vec::with_capacity(70);
        write_der_int(&mut body, r);
        write_der_int(&mut body, &low);
        let mut bytes = Vec::with_capacity(body.len() + 3);
        bytes.push(0x30);
        bytes.push(body.len() as u8);
        bytes.extend_from_slice(&body);
        bytes.push(0x01);
        Ok(DerSig { bytes, flipped })
    }

    /// DER plus the sighash byte, as the witness item.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// True if the s given was high and got replaced.
    pub fn was_high_s(&self) -> bool {
        self.flipped
    }
}
