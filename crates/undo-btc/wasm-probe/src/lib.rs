//! Exports the crate's main paths from a wasm cdylib, so that `scripts/check-wasm-identity.sh`
//! scans the code and panic strings a contract would really link. It is only ever scanned, never
//! run, so it has a stand-in hash where a contract would pass the host function.
//!
//! This is its own workspace on purpose. Cargo builds dev-dependencies for examples, and the
//! crate's dev-dependencies have C code that does not compile for wasm.

use undo_btc::{Csv, DerSig, OutPoint, PubKey, Sha256, Tx, TxOut, Txid, WitnessScript};

struct NotAHash;

impl Sha256 for NotAHash {
    fn sha256(data: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in data.iter().enumerate() {
            out[i % 32] ^= *b;
        }
        out
    }
}

fn read(ptr: *const u8, len: usize) -> &'static [u8] {
    // Sound only under the host's promise, which is fine for a binary nobody runs.
    unsafe { core::slice::from_raw_parts(ptr, len) }
}

/// Parses a script, builds a co-signed spend and hashes it. Returns the first byte of the digest.
#[no_mangle]
pub extern "C" fn probe_cosigned(script: *const u8, script_len: usize, value: u64) -> u32 {
    let Ok(parsed) = WitnessScript::parse(read(script, script_len)) else { return 256 };
    let previous = OutPoint { txid: Txid([7; 32]), vout: 0 };
    let out = TxOut { value: value - 1, script_pubkey: parsed.script_pubkey::<NotAHash>() };
    let tx = Tx::cosigned(&[previous], vec![out]);
    match tx.sighash::<NotAHash>(0, parsed.as_bytes(), value) {
        Ok(digest) => u32::from(digest[0]),
        Err(_) => 257,
    }
}

/// Builds a script from parts and assembles an escape witness.
#[no_mangle]
pub extern "C" fn probe_escape(keys: *const u8, csv: u32, r: *const u8, s: *const u8) -> usize {
    let keys = read(keys, 99);
    let (Ok(u), Ok(m), Ok(e), Ok(csv)) =
        (PubKey::from_slice(&keys[..33]), PubKey::from_slice(&keys[33..66]), PubKey::from_slice(&keys[66..]), Csv::new(csv))
    else {
        return 0;
    };
    let Ok(script) = WitnessScript::new(u, m, e, csv) else { return 0 };
    let (Ok(r), Ok(s)) = (read(r, 32).try_into(), read(s, 32).try_into()) else { return 0 };
    let Ok(sig) = DerSig::from_rs(r, s) else { return 0 };
    let mut tx = Tx::escape(&[OutPoint { txid: Txid([7; 32]), vout: 0 }], csv, Vec::new());
    if tx.set_escape_witness(0, &sig, &script).is_err() {
        return 0;
    }
    tx.serialize().len() + tx.vsize()
}
