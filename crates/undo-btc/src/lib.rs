//! Bitcoin side of Undo.
//!
//! Coins sit in a P2WSH with two branches, fixed at vault creation:
//!
//! ```text
//! OP_IF
//!   <K_u> OP_CHECKSIGVERIFY <K_m> OP_CHECKSIG
//! OP_ELSE
//!   <csv> OP_CHECKSEQUENCEVERIFY OP_DROP <K_e> OP_CHECKSIG
//! OP_ENDIF
//! ```
//!
//! The first branch needs the user key and the MPC key. The second lets the cold key leave alone
//! once a coin is `csv` blocks old.
//!
//! The default build has no dependencies and reads no clock, chain or key. It builds bytes and
//! digests. Signing belongs to the caller, or to [`recovery`] under the `tools` feature.

#![forbid(unsafe_code)]

pub mod address;
pub mod hash;
#[cfg(feature = "tools")]
pub mod recovery;
pub mod script;
pub mod sig;
pub mod tx;

pub use address::Network;
pub use hash::Sha256;
#[cfg(feature = "sha2")]
pub use hash::Sha2;
pub use script::{Csv, PubKey, WitnessScript};
pub use sig::DerSig;
pub use tx::{OutPoint, Tx, TxIn, TxOut, Txid};

/// Why a value was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The CSV value is outside 1..=65535. Anything else lets the cold key spend with no wait.
    CsvOutOfRange,
    /// A public key is not 33 bytes with a 02 or 03 prefix.
    BadPubKey,
    /// Two of `K_u`, `K_m`, `K_e` are the same key, which collapses the script's guarantees.
    DuplicateKey,
    /// The bytes are not exactly the script this crate builds.
    BadScript,
    /// A signature's r or s is zero or not below the curve order.
    BadSignature,
    /// An input index is past the end of the transaction.
    InputIndex,
    /// The transaction does not have the shape this witness needs.
    BadShape,
    /// Text is not lowercase hex of the expected length.
    BadHex,
    /// The network name is not one this crate knows.
    BadNetwork,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Error::CsvOutOfRange => "csv must be a block count in 1..=65535",
            Error::BadPubKey => "public key must be 33 compressed bytes",
            Error::DuplicateKey => "K_u, K_m and K_e must all be different keys",
            Error::BadScript => "not an Undo witness script",
            Error::BadSignature => "signature r or s is out of range",
            Error::InputIndex => "input index out of range",
            Error::BadShape => "transaction has the wrong shape for this witness",
            Error::BadHex => "not lowercase hex of the expected length",
            Error::BadNetwork => "unknown network name",
        })
    }
}

impl std::error::Error for Error {}

/// Lowercase hex.
pub fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}

/// Strict lowercase hex. Uppercase is refused so that one script has exactly one text form.
pub fn hex_decode(text: &str) -> Result<Vec<u8>, Error> {
    fn nibble(c: u8) -> Result<u8, Error> {
        match c {
            b'0'..=b'9' => Ok(c - b'0'),
            b'a'..=b'f' => Ok(c - b'a' + 10),
            _ => Err(Error::BadHex),
        }
    }
    let (pairs, rest) = text.as_bytes().as_chunks::<2>();
    if !rest.is_empty() {
        return Err(Error::BadHex);
    }
    pairs.iter().map(|[hi, lo]| Ok(nibble(*hi)? << 4 | nibble(*lo)?)).collect()
}
