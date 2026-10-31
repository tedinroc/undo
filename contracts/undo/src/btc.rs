//! Bitcoin bytes for one vault, from `undo-btc` with the host's SHA-256.

use near_sdk::env;
use undo_btc::{Csv, DerSig, OutPoint, PubKey, Sha256, Tx, TxOut, Txid, WitnessScript};
use undo_core::{Input, Outputs, Request, Vault};

pub struct HostSha;

impl Sha256 for HostSha {
    fn sha256(data: &[u8]) -> [u8; 32] {
        env::sha256_array(data)
    }
}

pub fn witness_script(k_u: &[u8], k_m: &[u8], k_e: &[u8], csv: u32) -> Result<WitnessScript, undo_btc::Error> {
    WitnessScript::new(PubKey::from_slice(k_u)?, PubKey::from_slice(k_m)?, PubKey::from_slice(k_e)?, Csv::new(csv)?)
}

/// The contract builds the script itself, so it cannot be anything but this shape.
pub fn script_of(vault: &Vault) -> WitnessScript {
    witness_script(&vault.k_u, &vault.k_m, &vault.k_e_leaf, vault.csv_blocks)
        .unwrap_or_else(|_| env::panic_str("stored keys do not build a script"))
}

/// One destination, then any change to the vault's own script.
pub fn tx_of(vault_spk: &[u8], inputs: &[Input], outputs: &Outputs) -> Tx {
    let outpoints: Vec<OutPoint> = inputs
        .iter()
        .map(|i| OutPoint { txid: Txid(i.outpoint.txid), vout: i.outpoint.vout })
        .collect();
    let mut out = vec![TxOut { value: outputs.dest_value, script_pubkey: outputs.dest_script.clone() }];
    if let Some(change) = outputs.change_value {
        out.push(TxOut { value: change, script_pubkey: vault_spk.to_vec() });
    }
    Tx::cosigned(&outpoints, out)
}

pub fn sighashes(script: &WitnessScript, vault_spk: &[u8], inputs: &[Input], outputs: &Outputs) -> Vec<[u8; 32]> {
    let values: Vec<u64> = inputs.iter().map(|i| i.value).collect();
    tx_of(vault_spk, inputs, outputs)
        .sighashes::<HostSha>(script.as_bytes(), &values)
        .unwrap_or_else(|_| env::panic_str("cannot compute sighash"))
}

/// The id the request's transaction will have. A segwit txid leaves the witness out, so this is fixed
/// from the moment the request exists, signed or not.
pub fn txid_of(vault_spk: &[u8], request: &Request) -> [u8; 32] {
    tx_of(vault_spk, &request.inputs, &request.outputs).txid::<HostSha>().0
}

/// The complete witness transaction, once every input has both signatures.
pub fn final_tx(vault: &Vault, request: &Request) -> Option<Vec<u8>> {
    let script = script_of(vault);
    let mut tx = tx_of(&vault.vault_spk, &request.inputs, &request.outputs);
    for index in 0..request.inputs.len() {
        let sig_m = der(request.sigs.get(index)?.as_ref()?)?;
        let sig_u = der(request.half_sigs.get(index)?)?;
        tx.set_cosigned_witness(index, &sig_m, &sig_u, &script).ok()?;
    }
    Some(tx.serialize())
}

fn der(rs: &[u8]) -> Option<DerSig> {
    let r: &[u8; 32] = rs.get(..32)?.try_into().ok()?;
    let s: &[u8; 32] = rs.get(32..64)?.try_into().ok()?;
    DerSig::from_rs(r, s).ok()
}

/// True when r and s are in range, so `final_tx` can encode them.
pub fn encodable(rs: &[u8]) -> bool {
    der(rs).is_some()
}
