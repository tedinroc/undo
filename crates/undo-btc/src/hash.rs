//! SHA-256 supplied by the caller.
//!
//! A contract passes the host function, which costs less gas than wasm code and keeps the hash
//! out of the binary. Everything else can use [`Sha2`] under the `sha2` feature.

/// One SHA-256 implementation.
pub trait Sha256 {
    /// SHA-256 of `data`.
    fn sha256(data: &[u8]) -> [u8; 32];

    /// SHA-256 of SHA-256 of `data`, as Bitcoin signs and names transactions.
    fn sha256d(data: &[u8]) -> [u8; 32] {
        Self::sha256(&Self::sha256(data))
    }
}

/// [`Sha256`] from the `sha2` crate.
#[cfg(feature = "sha2")]
#[derive(Clone, Copy, Debug)]
pub struct Sha2;

#[cfg(feature = "sha2")]
impl Sha256 for Sha2 {
    fn sha256(data: &[u8]) -> [u8; 32] {
        use sha2::Digest;
        sha2::Sha256::digest(data).into()
    }
}
