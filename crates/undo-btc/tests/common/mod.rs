//! Shared by the test files. Keys are derived from labels at run time, for local checks only
//! `[test-only]`. Anyone reading this repo can derive them, so they must never hold value.
#![allow(dead_code)]

use bitcoin::consensus::validation::verify_script;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use undo_btc::{Csv, DerSig, OutPoint, PubKey, Sha2, Sha256, Tx, TxOut, Txid, WitnessScript};

pub const VALUE: u64 = 100_000;
pub const SEQ_COSIGNED: u32 = 0xffff_fffd;

pub struct Key {
    pub secret: SecretKey,
    pub public: PubKey,
}

pub fn key(label: &str) -> Key {
    let digest = Sha2::sha256(format!("undo-test-only:{label}").as_bytes());
    let secret = SecretKey::from_slice(&digest).unwrap();
    let public = PubKey::from_slice(&secret.public_key(&Secp256k1::signing_only()).serialize()).unwrap();
    Key { secret, public }
}

pub struct Vault {
    pub u: Key,
    pub m: Key,
    pub e: Key,
    pub script: WitnessScript,
    pub spk: Vec<u8>,
}

pub fn vault(csv: u32) -> Vault {
    let (u, m, e) = (key("user"), key("mpc"), key("cold"));
    let script = WitnessScript::new(u.public, m.public, e.public, Csv::new(csv).unwrap()).unwrap();
    let spk = script.script_pubkey::<Sha2>();
    Vault { u, m, e, script, spk }
}

pub fn outpoint(n: u8) -> OutPoint {
    OutPoint { txid: Txid([n; 32]), vout: u32::from(n) }
}

/// A P2WSH output nobody involved here controls.
pub fn destination() -> Vec<u8> {
    let mut spk = vec![0x00, 0x20];
    spk.extend_from_slice(&[0x99; 32]);
    spk
}

pub fn pay_out(value: u64) -> Vec<TxOut> {
    vec![TxOut { value, script_pubkey: destination() }]
}

/// One input, with a chosen version and sequence, so tests can break either on purpose.
pub fn one_input(version: u32, sequence: u32) -> Tx {
    let mut tx = Tx::cosigned(&[outpoint(1)], pay_out(VALUE - 1_000));
    tx.version = version;
    tx.inputs[0].sequence = sequence;
    tx
}

/// A real signature by `key` over this crate's digest of this exact transaction.
pub fn sign(tx: &Tx, index: usize, script: &[u8], value: u64, key: &Key) -> Vec<u8> {
    sign_der(tx, index, script, value, key).as_bytes().to_vec()
}

pub fn sign_der(tx: &Tx, index: usize, script: &[u8], value: u64, key: &Key) -> DerSig {
    let digest = tx.sighash::<Sha2>(index, script, value).unwrap();
    let compact = Secp256k1::signing_only().sign_ecdsa(&Message::from_digest(digest), &key.secret).serialize_compact();
    DerSig::from_rs(compact[..32].try_into().unwrap(), compact[32..].try_into().unwrap()).unwrap()
}

/// One input against libbitcoinconsensus 25.1 under P2SH, DERSIG, NULLDUMMY, CLTV, CSV and
/// WITNESS. This is the independent judge in these tests.
///
/// What it cannot see, so what a pass here does not mean:
/// - Relay policy: MINIMALIF, MINIMALDATA, LOW_S, standardness, dust, fee rate. Regtest covers it.
/// - BIP-68 age: CSV compares the operand with this input's nSequence, and nothing compares
///   nSequence with how old the coin is, because the library has no chain. Regtest covers it.
/// - That the coin exists, or that outputs do not exceed inputs.
pub fn consensus(tx: &Tx, index: usize, spk: &[u8], value: u64) -> Result<(), String> {
    verify_script(bitcoin::Script::from_bytes(spk), index, bitcoin::Amount::from_sat(value), &tx.serialize())
        .map_err(|e| format!("{e:?}"))
}

/// Rewrites a low-s DER signature to its high-s form, by hand, so it can test the node's rule.
pub fn high_s_form(der_with_type: &[u8]) -> Vec<u8> {
    let sig = bitcoin::secp256k1::ecdsa::Signature::from_der(&der_with_type[..der_with_type.len() - 1]).unwrap();
    let compact = sig.serialize_compact();
    let order = bitcoin::secp256k1::constants::CURVE_ORDER;
    let (mut hs, mut borrow) = ([0u8; 32], 0i16);
    for i in (0..32).rev() {
        let d = i16::from(order[i]) - i16::from(compact[32 + i]) - borrow;
        borrow = i16::from(d < 0);
        hs[i] = d.rem_euclid(256) as u8;
    }
    let int = |x: &[u8]| {
        let mut y = x.to_vec();
        while y.len() > 1 && y[0] == 0 && y[1] < 0x80 {
            y.remove(0);
        }
        if y[0] >= 0x80 {
            y.insert(0, 0);
        }
        let mut o = vec![2, y.len() as u8];
        o.extend(y);
        o
    };
    let (r, s) = (int(&compact[..32]), int(&hs));
    let mut der = vec![0x30, (r.len() + s.len()) as u8];
    der.extend(r);
    der.extend(s);
    der.push(1);
    der
}
