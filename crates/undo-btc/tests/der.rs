//! Signature encoding. The bytes come from this crate and are judged by libsecp256k1's strict
//! parser and by libbitcoinconsensus, which enforces DERSIG.

mod common;

use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::{Message, Secp256k1};
use common::*;
use undo_btc::{DerSig, Error, Sha2};

const ORDER: [u8; 32] = bitcoin::secp256k1::constants::CURVE_ORDER;

fn parts(sig: &Signature) -> ([u8; 32], [u8; 32]) {
    let c = sig.serialize_compact();
    (c[..32].try_into().unwrap(), c[32..].try_into().unwrap())
}

#[test]
fn fixed_vectors() {
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r[31] = 1;
    s[31] = 1;
    let d = DerSig::from_rs(&r, &s).unwrap();
    assert_eq!(d.as_bytes(), [0x30, 6, 2, 1, 1, 2, 1, 1, 1]);

    // A high bit needs a leading zero, or DER reads the integer as negative.
    r[31] = 0x80;
    let d = DerSig::from_rs(&r, &s).unwrap();
    assert_eq!(d.as_bytes(), [0x30, 7, 2, 2, 0, 0x80, 2, 1, 1, 1]);

    // A leading zero with no high bit after it must go.
    let mut r = [0u8; 32];
    r[30] = 0x01;
    r[31] = 0xff;
    let d = DerSig::from_rs(&r, &s).unwrap();
    assert_eq!(d.as_bytes(), [0x30, 7, 2, 2, 1, 0xff, 2, 1, 1, 1]);

    // Longest form: both 33 bytes after padding. s must stay low, so r takes the high bit and s
    // the top of the low range.
    let mut s = [0x7f; 32];
    s[0] = 0x7f;
    let r = [0xaa; 32];
    let d = DerSig::from_rs(&r, &s).unwrap();
    assert_eq!(d.as_bytes().len(), 2 + 2 + 33 + 2 + 32 + 1);
}

#[test]
fn out_of_range_values_are_refused() {
    let one = {
        let mut x = [0u8; 32];
        x[31] = 1;
        x
    };
    let zero = [0u8; 32];
    assert_eq!(DerSig::from_rs(&zero, &one), Err(Error::BadSignature));
    assert_eq!(DerSig::from_rs(&one, &zero), Err(Error::BadSignature));
    assert_eq!(DerSig::from_rs(&ORDER, &one), Err(Error::BadSignature));
    assert_eq!(DerSig::from_rs(&one, &ORDER), Err(Error::BadSignature));
    assert_eq!(DerSig::from_rs(&[0xff; 32], &one), Err(Error::BadSignature));
    assert_eq!(DerSig::from_rs(&one, &[0xff; 32]), Err(Error::BadSignature));
    let mut below = ORDER;
    below[31] -= 1;
    assert!(DerSig::from_rs(&below, &one).is_ok(), "control: order - 1 is in range");
    assert!(DerSig::from_rs(&one, &below).unwrap().was_high_s(), "control: order - 1 is high");
}

#[test]
fn high_s_boundary_is_exact() {
    let half: [u8; 32] = {
        let (mut out, mut carry) = ([0u8; 32], 0u8);
        for i in 0..32 {
            out[i] = (ORDER[i] >> 1) | (carry << 7);
            carry = ORDER[i] & 1;
        }
        out
    };
    let r = [0x11; 32];
    assert!(!DerSig::from_rs(&r, &half).unwrap().was_high_s(), "half the order is low");
    let mut above = half;
    above[31] += 1;
    let flipped = DerSig::from_rs(&r, &above).unwrap();
    assert!(flipped.was_high_s(), "one above half the order is high");
    // ORDER - (half + 1) == half, because the order is odd.
    assert_eq!(flipped.as_bytes(), DerSig::from_rs(&r, &half).unwrap().as_bytes());
}

/// Grinds real signatures until both failure shapes have appeared, so they are real signatures
/// over a real transaction and not hand-picked numbers. r is 31 bytes about 1 time in 256. s can
/// be short the same way. The nonce loop is deterministic, so this test always sees the same set.
#[test]
fn short_and_padded_integers_pass_strict_der_and_consensus() {
    let secp = Secp256k1::new();
    let v = vault(6);
    let s = v.script.as_bytes();
    let tx = one_input(2, SEQ_COSIGNED);
    let digest = tx.sighash::<Sha2>(0, s, VALUE).unwrap();
    let msg = Message::from_digest(digest);
    let u = sign(&tx, 0, s, VALUE, &v.u);

    let (mut short_r, mut short_s, mut padded_r, mut high_input, mut total) = (0, 0, 0, 0, 0);
    for n in 0u32..6_000 {
        let mut noise = [0u8; 32];
        noise[..4].copy_from_slice(&n.to_le_bytes());
        let sig = secp.sign_ecdsa_with_noncedata(&msg, &v.m.secret, &noise);
        let (r, low_s) = parts(&sig);
        let ours = DerSig::from_rs(&r, &low_s).unwrap();
        assert_eq!(&ours.as_bytes()[..ours.as_bytes().len() - 1], &sig.serialize_der()[..], "nonce {n}: ours matches libsecp256k1");
        assert!(Signature::from_der(&ours.as_bytes()[..ours.as_bytes().len() - 1]).is_ok(), "strict parse");
        assert!(!ours.was_high_s());

        total += 1;
        let interesting = r[0] == 0 || low_s[0] == 0 || (r[0] & 0x80 != 0 && n % 128 == 0);
        if r[0] == 0 {
            short_r += 1;
        }
        if low_s[0] == 0 {
            short_s += 1;
        }
        if r[0] & 0x80 != 0 {
            padded_r += 1;
        }

        // Feed the high form too: it must come back as the same low signature.
        let high = {
            let (mut out, mut borrow) = ([0u8; 32], 0i16);
            for i in (0..32).rev() {
                let d = i16::from(ORDER[i]) - i16::from(low_s[i]) - borrow;
                borrow = i16::from(d < 0);
                out[i] = d.rem_euclid(256) as u8;
            }
            out
        };
        let back = DerSig::from_rs(&r, &high).unwrap();
        assert!(back.was_high_s());
        assert_eq!(back.as_bytes(), ours.as_bytes(), "nonce {n}: high form normalizes to the same bytes");
        high_input += 1;

        if interesting {
            run_cosigned(&tx, ours.as_bytes(), &u, s, &v.spk).unwrap_or_else(|e| panic!("nonce {n}: {e}"));
        }
    }
    println!("signatures {total}: short r {short_r}, short s {short_s}, padded r {padded_r}, high-s inputs normalized {high_input}");
    assert!(short_r > 0 && short_s > 0, "the loop must really hit the short forms");
    assert!(padded_r > 0);
}

fn run_cosigned(tx: &undo_btc::Tx, m: &[u8], u: &[u8], script: &[u8], spk: &[u8]) -> Result<(), String> {
    let mut t = tx.clone();
    t.inputs[0].witness = vec![m.to_vec(), u.to_vec(), vec![1], script.to_vec()];
    consensus(&t, 0, spk, VALUE)
}

/// Negative control: this check can fail. A padded integer that strict DER refuses is refused by
/// the library too, so the passes above do mean DERSIG looked at them.
#[test]
fn bad_der_is_rejected_by_the_library() {
    let v = vault(6);
    let s = v.script.as_bytes();
    let tx = one_input(2, SEQ_COSIGNED);
    let good = sign(&tx, 0, s, VALUE, &v.m);
    let u = sign(&tx, 0, s, VALUE, &v.u);
    run_cosigned(&tx, &good, &u, s, &v.spk).expect("positive twin");

    // An extra zero byte in front of r.
    let mut bad = good.clone();
    let rlen = bad[3] as usize;
    bad[1] += 1;
    bad[3] = (rlen + 1) as u8;
    bad.insert(4, 0);
    assert!(run_cosigned(&tx, &bad, &u, s, &v.spk).is_err(), "padded r");

    // The sighash byte missing, so a DER byte is read as the type and the digest changes.
    let trimmed = &good[..good.len() - 1];
    assert!(run_cosigned(&tx, trimmed, &u, s, &v.spk).is_err(), "no sighash byte");

    // A different sighash type on otherwise valid DER changes the digest.
    let mut other_type = good.clone();
    *other_type.last_mut().unwrap() = 0x81;
    assert!(run_cosigned(&tx, &other_type, &u, s, &v.spk).is_err(), "sighash byte changed");
}
