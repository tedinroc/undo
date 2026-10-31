//! The witness script, its CSV operand and its P2WSH output script.

use crate::hash::Sha256;
use crate::Error;

const OP_0: u8 = 0x00;
const OP_PUSH_33: u8 = 0x21;
const OP_1: u8 = 0x51;
const OP_16: u8 = 0x60;
const OP_IF: u8 = 0x63;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_DROP: u8 = 0x75;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKSIGVERIFY: u8 = 0xad;
const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;
const OP_PUSH_32: u8 = 0x20;

/// A compressed secp256k1 public key.
///
/// This checks length and prefix only, because the default build has no curve code. Whether the
/// point is on the curve is proved by the proof of possession at vault creation, and for `K_e` by
/// the recovery file, which derives it from the secret. A wrong point in `K_e` would mean no
/// escape, so the recovery file's dry run has to pass before a deposit address is shown.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PubKey([u8; 33]);

impl PubKey {
    /// Refuses anything but 33 bytes starting 02 or 03. Uncompressed keys in witness scripts are
    /// non-standard, so coins sent to one could not be relayed.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        let key: [u8; 33] = bytes.try_into().map_err(|_| Error::BadPubKey)?;
        match key[0] {
            2 | 3 => Ok(PubKey(key)),
            _ => Err(Error::BadPubKey),
        }
    }

    /// The 33 bytes.
    pub fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }
}

/// A block-based relative timelock, 1..=65535.
///
/// The range is the whole safety of the escape branch. `operand_abuse_is_why_the_range_exists` in
/// the tests runs each case below:
/// - 0 is satisfied by any sequence, so `K_e` spends with no wait.
/// - Bit 31 (BIP-112's disable flag) turns the opcode into a no-op, with the same result.
/// - Above 65535, CSV and BIP-68 ignore the extra bits, so 65536 acts as 0, and 65542 reads as a
///   long wait while the chain enforces 6 blocks.
/// - Bit 22 (the time flag) makes it time-based, which this product never promises.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Csv(u16);

impl Csv {
    /// The only way to make a [`Csv`] from a number.
    pub fn new(blocks: u32) -> Result<Self, Error> {
        match u16::try_from(blocks) {
            Ok(v) if v >= 1 => Ok(Csv(v)),
            _ => Err(Error::CsvOutOfRange),
        }
    }

    /// The value in blocks.
    pub fn blocks(self) -> u32 {
        u32::from(self.0)
    }

    /// The `nSequence` an escape input carries. Equal to the block count, so bits 22 and 31 are
    /// clear and BIP-68 enforces the age on chain.
    pub fn sequence(self) -> u32 {
        u32::from(self.0)
    }

    /// The minimal script push: `OP_1`..`OP_16` for 1..=16, otherwise a minimal CScriptNum.
    /// MINIMALDATA is a policy rule, so a non-minimal push passes consensus and then fails to
    /// relay, which would leave an escape that no node forwards. A trailing 00 is needed when the
    /// top bit of the last byte is set, or the number would read as negative.
    fn push_into(self, out: &mut Vec<u8>) {
        let v = self.0;
        match v {
            1..=16 => out.push(OP_1 + (v as u8 - 1)),
            17..=127 => out.extend_from_slice(&[1, v as u8]),
            128..=255 => out.extend_from_slice(&[2, v as u8, 0]),
            256..=32767 => out.extend_from_slice(&[2, v as u8, (v >> 8) as u8]),
            _ => out.extend_from_slice(&[3, v as u8, (v >> 8) as u8, 0]),
        }
    }

    /// Reads a push from the front of `bytes`. Returns the value and the bytes consumed. This does
    /// not judge the encoding: [`WitnessScript::parse`] rebuilds the whole script and compares, and
    /// that refuses every non-minimal or negative form.
    fn read_push(bytes: &[u8]) -> Result<(Self, usize), Error> {
        let first = *bytes.first().ok_or(Error::BadScript)?;
        let (value, used) = match first {
            OP_1..=OP_16 => (u32::from(first - OP_1) + 1, 1),
            1..=3 => {
                let len = first as usize;
                let body = bytes.get(1..1 + len).ok_or(Error::BadScript)?;
                let value = body.iter().enumerate().fold(0u32, |v, (i, b)| v | u32::from(*b) << (8 * i));
                (value, 1 + len)
            }
            _ => return Err(Error::BadScript),
        };
        Ok((Csv::new(value).map_err(|_| Error::BadScript)?, used))
    }
}

/// The exact script for one vault. It can only be built from checked parts, or parsed from bytes
/// that rebuild to themselves.
///
/// Length is 110 bytes plus the CSV push: 111 for csv 1..=16, 112 for 17..=127, 113 for
/// 128..=32767 and 114 for 32768..=65535.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct WitnessScript {
    k_u: PubKey,
    k_m: PubKey,
    k_e: PubKey,
    csv: Csv,
    bytes: Vec<u8>,
}

impl WitnessScript {
    /// Builds the script. All three keys must differ:
    /// - `K_u == K_m` lets MPC alone spend through the first branch.
    /// - `K_m == K_e` lets MPC alone spend through the second branch.
    /// - `K_u == K_e` lets the spend key use the second branch.
    ///
    /// This cannot tell whether `K_m` really is the MPC key. The contract checks that against the
    /// signer at creation.
    pub fn new(k_u: PubKey, k_m: PubKey, k_e: PubKey, csv: Csv) -> Result<Self, Error> {
        if k_u == k_m || k_u == k_e || k_m == k_e {
            return Err(Error::DuplicateKey);
        }
        let mut bytes = Vec::with_capacity(114);
        bytes.push(OP_IF);
        bytes.push(OP_PUSH_33);
        bytes.extend_from_slice(k_u.as_bytes());
        bytes.push(OP_CHECKSIGVERIFY);
        bytes.push(OP_PUSH_33);
        bytes.extend_from_slice(k_m.as_bytes());
        bytes.push(OP_CHECKSIG);
        bytes.push(OP_ELSE);
        csv.push_into(&mut bytes);
        bytes.push(OP_CHECKSEQUENCEVERIFY);
        bytes.push(OP_DROP);
        bytes.push(OP_PUSH_33);
        bytes.extend_from_slice(k_e.as_bytes());
        bytes.push(OP_CHECKSIG);
        bytes.push(OP_ENDIF);
        Ok(WitnessScript { k_u, k_m, k_e, csv, bytes })
    }

    /// Parses script bytes, for example from a recovery file. It reads the fields and then
    /// requires that building from them gives the same bytes, so there is one accepted encoding
    /// per vault and nothing here has to reason about opcodes twice.
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        let bad = |_| Error::BadScript;
        let k_u = PubKey::from_slice(bytes.get(2..35).ok_or(Error::BadScript)?).map_err(bad)?;
        let k_m = PubKey::from_slice(bytes.get(37..70).ok_or(Error::BadScript)?).map_err(bad)?;
        let (csv, used) = Csv::read_push(bytes.get(72..).ok_or(Error::BadScript)?)?;
        let start = 72 + used + 3;
        let k_e = PubKey::from_slice(bytes.get(start..start + 33).ok_or(Error::BadScript)?).map_err(bad)?;
        let built = WitnessScript::new(k_u, k_m, k_e, csv)?;
        if built.bytes != bytes {
            return Err(Error::BadScript);
        }
        Ok(built)
    }

    /// The script bytes, the last item of every witness.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The user key.
    pub fn k_u(&self) -> &PubKey {
        &self.k_u
    }

    /// The MPC key.
    pub fn k_m(&self) -> &PubKey {
        &self.k_m
    }

    /// The cold key.
    pub fn k_e(&self) -> &PubKey {
        &self.k_e
    }

    /// The timelock.
    pub fn csv(&self) -> Csv {
        self.csv
    }

    /// The witness program, SHA-256 of the script.
    pub fn program<H: Sha256>(&self) -> [u8; 32] {
        H::sha256(&self.bytes)
    }

    /// The output script coins are sent to: `OP_0 <32 bytes>`.
    pub fn script_pubkey<H: Sha256>(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(34);
        out.push(OP_0);
        out.push(OP_PUSH_32);
        out.extend_from_slice(&self.program::<H>());
        out
    }
}
