//! Transactions: building, serializing, BIP-143 digests and witness assembly.

use crate::hash::Sha256;
use crate::script::{Csv, WitnessScript};
use crate::sig::DerSig;
use crate::Error;

/// `nSequence` on a co-signed input: signals replacement, no relative lock. Spec section 4.1.
pub const SEQUENCE_COSIGNED: u32 = 0xffff_fffd;
/// SIGHASH_ALL, the only type signed here. A co-signer that signed anything else could have its
/// signature moved onto outputs the contract never saw.
pub const SIGHASH_ALL: u32 = 1;

/// A transaction id in internal byte order, the reverse of what explorers show.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Txid(pub [u8; 32]);

impl Txid {
    /// From the hex an explorer or RPC shows. Reversing here means only this one place has to
    /// know about display order.
    pub fn from_display_hex(text: &str) -> Result<Self, Error> {
        let mut raw: [u8; 32] = crate::hex_decode(text)?.try_into().map_err(|_| Error::BadHex)?;
        raw.reverse();
        Ok(Txid(raw))
    }

    /// The hex an explorer or RPC shows.
    pub fn to_display_hex(self) -> String {
        let mut raw = self.0;
        raw.reverse();
        crate::hex_encode(&raw)
    }
}

/// A coin's location.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct OutPoint {
    /// The transaction that created it.
    pub txid: Txid,
    /// Its output index there.
    pub vout: u32,
}

/// An input.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TxIn {
    /// The coin being spent.
    pub previous: OutPoint,
    /// `nSequence`.
    pub sequence: u32,
    /// Witness items, bottom of the stack first.
    pub witness: Vec<Vec<u8>>,
}

/// An output.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TxOut {
    /// Value in sats.
    pub value: u64,
    /// The locking script.
    pub script_pubkey: Vec<u8>,
}

/// A transaction. `script_sig` is always empty, because every coin here is native segwit.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Tx {
    /// nVersion. Must be 2 for CSV to pass.
    pub version: u32,
    /// nLockTime.
    pub lock_time: u32,
    /// Inputs.
    pub inputs: Vec<TxIn>,
    /// Outputs.
    pub outputs: Vec<TxOut>,
}

/// The three hashes BIP-143 shares across every input, so signing n inputs costs O(n) hashes.
#[derive(Clone, Copy, Debug)]
struct Shared {
    prevouts: [u8; 32],
    sequences: [u8; 32],
    outputs: [u8; 32],
}

fn write_compact_size(out: &mut Vec<u8>, n: usize) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&(n as u64).to_le_bytes());
        }
    }
}

fn write_outpoint(out: &mut Vec<u8>, p: &OutPoint) {
    out.extend_from_slice(&p.txid.0);
    out.extend_from_slice(&p.vout.to_le_bytes());
}

fn write_output(out: &mut Vec<u8>, o: &TxOut) {
    out.extend_from_slice(&o.value.to_le_bytes());
    write_compact_size(out, o.script_pubkey.len());
    out.extend_from_slice(&o.script_pubkey);
}

impl Tx {
    /// A co-signed spend: version 2, locktime 0, replaceable.
    pub fn cosigned(inputs: &[OutPoint], outputs: Vec<TxOut>) -> Self {
        Self::shaped(inputs, SEQUENCE_COSIGNED, outputs)
    }

    /// An escape: version 2, locktime 0, `nSequence = csv` on every input.
    pub fn escape(inputs: &[OutPoint], csv: Csv, outputs: Vec<TxOut>) -> Self {
        Self::shaped(inputs, csv.sequence(), outputs)
    }

    fn shaped(inputs: &[OutPoint], sequence: u32, outputs: Vec<TxOut>) -> Self {
        Tx {
            version: 2,
            lock_time: 0,
            inputs: inputs.iter().map(|p| TxIn { previous: *p, sequence, witness: Vec::new() }).collect(),
            outputs,
        }
    }

    fn shared<H: Sha256>(&self) -> Shared {
        let mut prevouts = Vec::with_capacity(self.inputs.len() * 36);
        let mut sequences = Vec::with_capacity(self.inputs.len() * 4);
        for i in &self.inputs {
            write_outpoint(&mut prevouts, &i.previous);
            sequences.extend_from_slice(&i.sequence.to_le_bytes());
        }
        let mut outputs = Vec::new();
        for o in &self.outputs {
            write_output(&mut outputs, o);
        }
        Shared { prevouts: H::sha256d(&prevouts), sequences: H::sha256d(&sequences), outputs: H::sha256d(&outputs) }
    }

    fn preimage(&self, shared: &Shared, index: usize, script: &[u8], value: u64) -> Result<Vec<u8>, Error> {
        let input = self.inputs.get(index).ok_or(Error::InputIndex)?;
        let mut p = Vec::with_capacity(156 + script.len() + 3);
        p.extend_from_slice(&self.version.to_le_bytes());
        p.extend_from_slice(&shared.prevouts);
        p.extend_from_slice(&shared.sequences);
        write_outpoint(&mut p, &input.previous);
        // The script code is the whole witness script. It holds no OP_CODESEPARATOR.
        write_compact_size(&mut p, script.len());
        p.extend_from_slice(script);
        p.extend_from_slice(&value.to_le_bytes());
        p.extend_from_slice(&input.sequence.to_le_bytes());
        p.extend_from_slice(&shared.outputs);
        p.extend_from_slice(&self.lock_time.to_le_bytes());
        p.extend_from_slice(&SIGHASH_ALL.to_le_bytes());
        Ok(p)
    }

    /// The BIP-143 digest for one input under SIGHASH_ALL.
    ///
    /// This commits to the value of this input only, and not to the other inputs' values. So
    /// signatures from separate signing sessions over the same inputs can be combined into one
    /// valid transaction with a much larger real fee. The fix is the pin rules in spec section
    /// 4.1, which the contract owns, and nothing in this function closes that.
    pub fn sighash<H: Sha256>(&self, index: usize, script: &[u8], value: u64) -> Result<[u8; 32], Error> {
        Ok(H::sha256d(&self.preimage(&self.shared::<H>(), index, script, value)?))
    }

    /// The digest for every input, with the shared hashes computed once. `values` gives each
    /// input's value in order and must have one entry per input.
    pub fn sighashes<H: Sha256>(&self, script: &[u8], values: &[u64]) -> Result<Vec<[u8; 32]>, Error> {
        if values.len() != self.inputs.len() {
            return Err(Error::InputIndex);
        }
        let shared = self.shared::<H>();
        values
            .iter()
            .enumerate()
            .map(|(i, v)| Ok(H::sha256d(&self.preimage(&shared, i, script, *v)?)))
            .collect()
    }

    /// Puts the co-signed witness on an input: `sig_m sig_u 01 script`. `K_u` is checked first,
    /// because it is the top signature on the stack.
    pub fn set_cosigned_witness(&mut self, index: usize, sig_m: &DerSig, sig_u: &DerSig, script: &WitnessScript) -> Result<(), Error> {
        let input = self.inputs.get_mut(index).ok_or(Error::InputIndex)?;
        input.witness = vec![sig_m.as_bytes().to_vec(), sig_u.as_bytes().to_vec(), vec![1], script.as_bytes().to_vec()];
        Ok(())
    }

    /// Puts the escape witness on an input: `sig_e "" script`. Refuses an input the script would
    /// reject anyway, so a caller finds out here and not from a node.
    pub fn set_escape_witness(&mut self, index: usize, sig_e: &DerSig, script: &WitnessScript) -> Result<(), Error> {
        if self.version != 2 {
            return Err(Error::BadShape);
        }
        let input = self.inputs.get_mut(index).ok_or(Error::InputIndex)?;
        if input.sequence != script.csv().sequence() {
            return Err(Error::BadShape);
        }
        input.witness = vec![sig_e.as_bytes().to_vec(), Vec::new(), script.as_bytes().to_vec()];
        Ok(())
    }

    /// Without witness data: the bytes a txid hashes.
    pub fn serialize_stripped(&self) -> Vec<u8> {
        self.write(false)
    }

    /// The full network form. Uses the segwit marker only if some input has a witness.
    pub fn serialize(&self) -> Vec<u8> {
        self.write(self.inputs.iter().any(|i| !i.witness.is_empty()))
    }

    fn write(&self, witness: bool) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.version.to_le_bytes());
        if witness {
            out.extend_from_slice(&[0, 1]);
        }
        write_compact_size(&mut out, self.inputs.len());
        for i in &self.inputs {
            write_outpoint(&mut out, &i.previous);
            out.push(0); // empty script_sig
            out.extend_from_slice(&i.sequence.to_le_bytes());
        }
        write_compact_size(&mut out, self.outputs.len());
        for o in &self.outputs {
            write_output(&mut out, o);
        }
        if witness {
            for i in &self.inputs {
                write_compact_size(&mut out, i.witness.len());
                for item in &i.witness {
                    write_compact_size(&mut out, item.len());
                    out.extend_from_slice(item);
                }
            }
        }
        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out
    }

    /// The transaction id.
    pub fn txid<H: Sha256>(&self) -> Txid {
        Txid(H::sha256d(&self.serialize_stripped()))
    }

    /// Weight units: 3 x stripped size + full size.
    pub fn weight(&self) -> usize {
        self.serialize_stripped().len() * 3 + self.serialize().len()
    }

    /// Virtual bytes, rounded up.
    pub fn vsize(&self) -> usize {
        self.weight().div_ceil(4)
    }
}
