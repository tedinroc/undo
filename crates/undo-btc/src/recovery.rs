//! The recovery file, and the escape it makes possible with no NEAR.
//!
//! Every escape witness needs the whole script, which holds `K_u` and `K_m`, and neither can be
//! fetched once NEAR is gone. So a bare cold key cannot spend. The file carries everything.
//!
//! The file is one JSON object:
//!
//! ```text
//! format          "undo-recovery-v1"
//! network         mainnet | mutinynet | signet | testnet4 | regtest
//! vault_id        label, 1 to 128 of A-Z a-z 0-9 . _ -. Not checked against anything here.
//! csv             number, 1..=65535, equal to the operand in the script
//! witness_script  lowercase hex, exactly the script this crate builds
//! address         the P2WSH address of that script on that network
//! cold_key        lowercase hex, 32-byte secret of K_e
//! checksum        lowercase hex, SHA-256 of the checksum text below
//! ```
//!
//! The checksum text is each field after `format` on its own line, in that order, after the line
//! `undo-recovery-v1`, with a final newline. JSON layout does not affect it, so a tool in any
//! language can check it. It catches a damaged or mistyped file. It authenticates nothing: anyone
//! who can edit the file can recompute it.
//!
//! The file holds a secret. Nothing here prints `cold_key`, and errors never quote file text.

use bitcoin::consensus::validation::verify_script;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};

use crate::address::{p2wsh_address, Network};
use crate::hash::{Sha2, Sha256};
use crate::script::{PubKey, WitnessScript};
use crate::sig::DerSig;
use crate::tx::{OutPoint, Tx, TxOut, Txid};

const FORMAT: &str = "undo-recovery-v1";
/// Below this, an output is dust at the default relay fee on any script type.
const DUST_LIMIT: u64 = 546;

/// Why a recovery file or an escape was refused. No variant carries text from the file.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecoveryError {
    /// Not JSON, or a field is missing, unknown or of the wrong type.
    Malformed,
    /// `format` is not one this code reads.
    UnknownFormat,
    /// The file changed after it was written.
    Checksum,
    /// `network` is not known.
    Network,
    /// `vault_id` is empty, too long or has other characters.
    VaultId,
    /// `witness_script` is not the Undo script.
    Script,
    /// `csv` differs from the operand in the script.
    CsvMismatch,
    /// `address` is not this script's address on this network.
    AddressMismatch,
    /// `cold_key` is not a valid secret.
    ColdKey,
    /// `cold_key` is not the key named in the script's escape branch.
    ColdKeyMismatch,
    /// No coins were given, or their values overflow.
    NoCoins,
    /// The fee is more than the coins, or leaves dust.
    Fee,
    /// The destination is empty, or an `OP_RETURN` that would burn the coins.
    Destination,
    /// The consensus library refused the escape this file builds.
    DryRunRefused,
    /// A negative control passed, so the dry run proves nothing. Treat the file as unusable.
    DryRunControl,
}

impl core::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            RecoveryError::Malformed => "not a valid recovery file",
            RecoveryError::UnknownFormat => "unknown recovery file format",
            RecoveryError::Checksum => "checksum does not match, the file is damaged",
            RecoveryError::Network => "unknown network",
            RecoveryError::VaultId => "bad vault id",
            RecoveryError::Script => "witness script is not an Undo script",
            RecoveryError::CsvMismatch => "csv does not match the script",
            RecoveryError::AddressMismatch => "address does not match the script and network",
            RecoveryError::ColdKey => "cold key is not a valid secret",
            RecoveryError::ColdKeyMismatch => "cold key is not the one in the script",
            RecoveryError::NoCoins => "no coins to spend, or their values overflow",
            RecoveryError::Fee => "fee leaves too little to send",
            RecoveryError::Destination => "destination would burn the coins",
            RecoveryError::DryRunRefused => "the consensus library refused this file's escape",
            RecoveryError::DryRunControl => "a dry-run control passed that must fail",
        })
    }
}

impl std::error::Error for RecoveryError {}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Wire {
    format: String,
    network: String,
    vault_id: String,
    csv: u32,
    witness_script: String,
    address: String,
    cold_key: String,
    checksum: String,
}

impl Wire {
    fn checksum_text(&self) -> String {
        format!(
            "{FORMAT}\n{}\n{}\n{}\n{}\n{}\n{}\n",
            self.network, self.vault_id, self.csv, self.witness_script, self.address, self.cold_key
        )
    }
}

/// A checked recovery file. Holding one means every field agrees with every other.
#[derive(Clone)]
pub struct RecoveryFile {
    network: Network,
    vault_id: String,
    script: WitnessScript,
    cold_key: SecretKey,
}

/// Never prints the secret.
impl core::fmt::Debug for RecoveryFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecoveryFile")
            .field("network", &self.network)
            .field("vault_id", &self.vault_id)
            .field("csv", &self.script.csv().blocks())
            .field("cold_key", &"<hidden>")
            .finish()
    }
}

/// A coin to escape with.
#[derive(Clone, Copy, Debug)]
pub struct Coin {
    /// Where it is.
    pub outpoint: OutPoint,
    /// Its real value. BIP-143 signs this, so a wrong value gives a signature consensus refuses.
    pub value: u64,
}

/// What a dry run established. It builds and checks one escape and broadcasts nothing.
///
/// Checked with libbitcoinconsensus, which sees one input's script and nothing else. It cannot
/// check that a coin exists or how old it is, so BIP-68 age, relay policy, fee and dust all stay
/// unchecked. A pass means this file can produce a witness the script accepts.
#[derive(Clone, Debug)]
pub struct DryRun {
    /// The txid of the transaction built, which spends a made-up coin.
    pub txid: String,
    /// Its size.
    pub vsize: usize,
    /// The timelock.
    pub csv: u32,
    /// The script length.
    pub script_len: usize,
    /// The vault address.
    pub address: String,
    /// The network.
    pub network: Network,
}

impl RecoveryFile {
    /// Makes a file from its parts. Refuses a cold key the script does not name.
    pub fn new(network: Network, vault_id: &str, script: WitnessScript, cold_key: &[u8; 32]) -> Result<Self, RecoveryError> {
        check_vault_id(vault_id)?;
        let cold_key = SecretKey::from_slice(cold_key).map_err(|_| RecoveryError::ColdKey)?;
        check_cold_key(&cold_key, script.k_e())?;
        Ok(RecoveryFile { network, vault_id: vault_id.to_owned(), script, cold_key })
    }

    /// Reads a file and checks that every field agrees with every other. The checksum comes first,
    /// so damage is reported as damage and not as whatever field it happened to hit.
    pub fn parse(text: &str) -> Result<Self, RecoveryError> {
        let wire: Wire = serde_json::from_str(text).map_err(|_| RecoveryError::Malformed)?;
        if wire.format != FORMAT {
            return Err(RecoveryError::UnknownFormat);
        }
        if crate::hex_encode(&Sha2::sha256(wire.checksum_text().as_bytes())) != wire.checksum {
            return Err(RecoveryError::Checksum);
        }
        let network = Network::from_name(&wire.network).map_err(|_| RecoveryError::Network)?;
        check_vault_id(&wire.vault_id)?;
        let script_bytes = crate::hex_decode(&wire.witness_script).map_err(|_| RecoveryError::Script)?;
        let script = WitnessScript::parse(&script_bytes).map_err(|_| RecoveryError::Script)?;
        if script.csv().blocks() != wire.csv {
            return Err(RecoveryError::CsvMismatch);
        }
        if p2wsh_address(network, &script.program::<Sha2>()) != wire.address {
            return Err(RecoveryError::AddressMismatch);
        }
        let cold: [u8; 32] = crate::hex_decode(&wire.cold_key)
            .map_err(|_| RecoveryError::ColdKey)?
            .try_into()
            .map_err(|_| RecoveryError::ColdKey)?;
        let cold_key = SecretKey::from_slice(&cold).map_err(|_| RecoveryError::ColdKey)?;
        check_cold_key(&cold_key, script.k_e())?;
        Ok(RecoveryFile { network, vault_id: wire.vault_id, script, cold_key })
    }

    /// The file's text.
    pub fn to_json(&self) -> String {
        let mut wire = Wire {
            format: FORMAT.to_owned(),
            network: self.network.name().to_owned(),
            vault_id: self.vault_id.clone(),
            csv: self.script.csv().blocks(),
            witness_script: crate::hex_encode(self.script.as_bytes()),
            address: self.address(),
            cold_key: crate::hex_encode(&self.cold_key.secret_bytes()),
            checksum: String::new(),
        };
        wire.checksum = crate::hex_encode(&Sha2::sha256(wire.checksum_text().as_bytes()));
        serde_json::to_string_pretty(&wire).expect("a struct of strings and a number serializes")
    }

    /// The vault's script.
    pub fn script(&self) -> &WitnessScript {
        &self.script
    }

    /// The vault's network.
    pub fn network(&self) -> Network {
        self.network
    }

    /// The vault's id, as written in the file.
    pub fn vault_id(&self) -> &str {
        &self.vault_id
    }

    /// The vault's address.
    pub fn address(&self) -> String {
        p2wsh_address(self.network, &self.script.program::<Sha2>())
    }

    /// Builds a complete signed escape, ready to broadcast. It sends everything but `fee` to
    /// `destination`. A coin younger than CSV gives a transaction nodes refuse as not final; it
    /// cannot leave early, and the signature stays good for when it can.
    pub fn build_escape(&self, coins: &[Coin], destination: &[u8], fee: u64) -> Result<Tx, RecoveryError> {
        if destination.is_empty() || destination[0] == 0x6a {
            return Err(RecoveryError::Destination);
        }
        if coins.is_empty() {
            return Err(RecoveryError::NoCoins);
        }
        let total = coins.iter().try_fold(0u64, |t, c| t.checked_add(c.value)).ok_or(RecoveryError::NoCoins)?;
        let send = total.checked_sub(fee).filter(|v| *v >= DUST_LIMIT).ok_or(RecoveryError::Fee)?;
        let outpoints: Vec<OutPoint> = coins.iter().map(|c| c.outpoint).collect();
        let outputs = vec![TxOut { value: send, script_pubkey: destination.to_vec() }];
        let mut tx = Tx::escape(&outpoints, self.script.csv(), outputs);
        let values: Vec<u64> = coins.iter().map(|c| c.value).collect();
        let sigs = sign_all(&tx, self.script.as_bytes(), &values, &self.cold_key);
        for (i, sig) in sigs.iter().enumerate() {
            tx.set_escape_witness(i, sig, &self.script).expect("Tx::escape sets version 2 and nSequence = csv");
        }
        Ok(tx)
    }
}

/// Reads a file and proves it can escape, against the consensus library, on a made-up coin.
pub fn dry_run_escape(text: &str) -> Result<DryRun, RecoveryError> {
    dry_run_with(text, consensus_accepts)
}

/// [`dry_run_escape`] with the judge as a parameter, which is how the tests show that its two
/// controls can fire. A broken judge is the one thing the real run could not otherwise notice.
///
/// There are two controls, so that a broken check cannot pass as a good file. The same key one
/// block below CSV must be refused, and a different key at CSV must be refused.
pub fn dry_run_with(text: &str, accepts: impl Fn(&Tx, usize, &[u8], u64) -> bool) -> Result<DryRun, RecoveryError> {
    let file = RecoveryFile::parse(text)?;
    let script = file.script().clone();
    let spk = script.script_pubkey::<Sha2>();
    let coin = Coin {
        outpoint: OutPoint { txid: Txid(Sha2::sha256(b"undo recovery dry run: this coin does not exist")), vout: 0 },
        value: 100_000,
    };

    let tx = file.build_escape(&[coin], &spk, 1_000)?;
    if !accepts(&tx, 0, &spk, coin.value) {
        return Err(RecoveryError::DryRunRefused);
    }

    // Control 1: signed correctly for nSequence = csv - 1. The opcode must refuse.
    let mut early = tx.clone();
    early.inputs[0].sequence = script.csv().sequence() - 1;
    let sig = sign_all(&early, script.as_bytes(), &[coin.value], &file.cold_key).remove(0);
    early.inputs[0].witness = vec![sig.as_bytes().to_vec(), Vec::new(), script.as_bytes().to_vec()];
    if accepts(&early, 0, &spk, coin.value) {
        return Err(RecoveryError::DryRunControl);
    }

    // Control 2: a different key signing the same digest. The signature check must refuse.
    let other = SecretKey::from_slice(&Sha2::sha256(&file.cold_key.secret_bytes())).map_err(|_| RecoveryError::DryRunControl)?;
    let sig = sign_all(&tx, script.as_bytes(), &[coin.value], &other).remove(0);
    let mut wrong = tx.clone();
    wrong.inputs[0].witness = vec![sig.as_bytes().to_vec(), Vec::new(), script.as_bytes().to_vec()];
    if accepts(&wrong, 0, &spk, coin.value) {
        return Err(RecoveryError::DryRunControl);
    }

    Ok(DryRun {
        txid: tx.txid::<Sha2>().to_display_hex(),
        vsize: tx.vsize(),
        csv: script.csv().blocks(),
        script_len: script.as_bytes().len(),
        address: file.address(),
        network: file.network(),
    })
}

fn check_vault_id(id: &str) -> Result<(), RecoveryError> {
    let allowed = |c: u8| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-');
    if id.is_empty() || id.len() > 128 || !id.bytes().all(allowed) {
        return Err(RecoveryError::VaultId);
    }
    Ok(())
}

fn check_cold_key(secret: &SecretKey, named: &PubKey) -> Result<(), RecoveryError> {
    let derived = secret.public_key(&Secp256k1::signing_only()).serialize();
    if &derived != named.as_bytes() {
        return Err(RecoveryError::ColdKeyMismatch);
    }
    Ok(())
}

/// RFC 6979 signatures, so the same file builds the same bytes.
fn sign_all(tx: &Tx, script: &[u8], values: &[u64], key: &SecretKey) -> Vec<DerSig> {
    let secp = Secp256k1::signing_only();
    tx.sighashes::<Sha2>(script, values)
        .expect("callers pass one value per input")
        .iter()
        .map(|digest| {
            let compact = secp.sign_ecdsa(&Message::from_digest(*digest), key).serialize_compact();
            let r: [u8; 32] = compact[..32].try_into().expect("compact form is 64 bytes");
            let s: [u8; 32] = compact[32..].try_into().expect("compact form is 64 bytes");
            DerSig::from_rs(&r, &s).expect("libsecp256k1 returns r and s in range")
        })
        .collect()
}

/// One input's script under the library's full flag set: P2SH, DERSIG, NULLDUMMY, CLTV, CSV and
/// WITNESS. The library takes no chain, so this cannot see a coin's age.
fn consensus_accepts(tx: &Tx, index: usize, spk: &[u8], value: u64) -> bool {
    verify_script(bitcoin::Script::from_bytes(spk), index, bitcoin::Amount::from_sat(value), &tx.serialize()).is_ok()
}
