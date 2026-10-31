//! JSON shapes of the contract's methods. State lives in `undo-core` types, encoded with Borsh.

use near_sdk::serde::{Deserialize, Deserializer, Serialize, Serializer};
use near_sdk::{env, near};
use undo_core::{Fixed, Input, Outpoint, Outputs, Policy, Request, RequestKind, RequestStatus, Tier};

/// Bytes as lowercase hex in JSON.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HexBytes(pub Vec<u8>);

impl Serialize for HexBytes {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for HexBytes {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        hex::decode(text).map(HexBytes).map_err(near_sdk::serde::de::Error::custom)
    }
}

impl HexBytes {
    pub fn fixed<const N: usize>(&self, what: &str) -> [u8; N] {
        self.0
            .as_slice()
            .try_into()
            .unwrap_or_else(|_| env::panic_str(&format!("{what} must be {N} bytes")))
    }
}

/// `txid` is in the order block explorers display.
#[derive(Clone, Debug)]
#[near(serializers = [json])]
pub struct Utxo {
    pub txid: HexBytes,
    pub vout: u32,
    pub value: u64,
}

impl Utxo {
    pub fn outpoint(&self) -> Outpoint {
        outpoint(&self.txid, self.vout)
    }

    pub fn input(&self) -> Input {
        Input { outpoint: self.outpoint(), value: self.value }
    }

    pub fn from_input(input: &Input) -> Self {
        let mut txid = input.outpoint.txid;
        txid.reverse();
        Utxo { txid: HexBytes(txid.to_vec()), vout: input.outpoint.vout, value: input.value }
    }
}

/// The ledger holds the internal byte order, the same order the sighash commits to.
pub fn outpoint(display_txid: &HexBytes, vout: u32) -> Outpoint {
    let mut txid: [u8; 32] = display_txid.fixed("txid");
    txid.reverse();
    Outpoint { txid, vout }
}

#[derive(Clone, Copy, Debug)]
#[near(serializers = [json])]
pub struct PolicyArgs {
    pub t_known_ms: u64,
    pub t_new_ms: u64,
    pub t_new_unguarded_ms: u64,
    pub hold_ms: u64,
    pub t_stuck_ms: u64,
    pub fee_cap_tx: u64,
    pub fee_budget_24h: u64,
    pub outflow_cap_24h: u64,
}

impl From<PolicyArgs> for Policy {
    fn from(p: PolicyArgs) -> Self {
        Policy {
            t_known_ms: p.t_known_ms,
            t_new_ms: p.t_new_ms,
            t_new_unguarded_ms: p.t_new_unguarded_ms,
            hold_ms: p.hold_ms,
            t_stuck_ms: p.t_stuck_ms,
            fee_cap_tx: p.fee_cap_tx,
            fee_budget_24h: p.fee_budget_24h,
            outflow_cap_24h: p.outflow_cap_24h,
        }
    }
}

impl From<Policy> for PolicyArgs {
    fn from(p: Policy) -> Self {
        PolicyArgs {
            t_known_ms: p.t_known_ms,
            t_new_ms: p.t_new_ms,
            t_new_unguarded_ms: p.t_new_unguarded_ms,
            hold_ms: p.hold_ms,
            t_stuck_ms: p.t_stuck_ms,
            fee_cap_tx: p.fee_cap_tx,
            fee_budget_24h: p.fee_budget_24h,
            outflow_cap_24h: p.outflow_cap_24h,
        }
    }
}

/// One WebAuthn assertion. `client_data_json` stays bytes, because its hash is what got signed.
#[derive(Clone, Debug)]
#[near(serializers = [json])]
pub struct WebAuthn {
    pub authenticator_data: HexBytes,
    pub client_data_json: HexBytes,
    /// r || s. Either S form verifies.
    pub signature: HexBytes,
}

#[derive(Clone, Debug)]
#[near(serializers = [json])]
pub enum CancelAuth {
    Passkey(WebAuthn),
    /// r || s || v from the cold key's intent key.
    Cold(HexBytes),
}

#[near(serializers = [json])]
pub struct PasskeyArgs {
    pub pubkey: HexBytes,
    pub rp_id_hash: HexBytes,
}

/// Everything `create_vault` needs. `vault_id` and the script are computed by the contract.
#[near(serializers = [json])]
pub struct CreateArgs {
    pub k_s: HexBytes,
    pub k_u: HexBytes,
    pub k_m: HexBytes,
    pub k_e_leaf: HexBytes,
    pub k_e_intent: HexBytes,
    pub passkey: PasskeyArgs,
    pub guard: Option<near_sdk::AccountId>,
    pub csv: u32,
    /// `None` takes the instance's deployed values.
    pub policy: Option<PolicyArgs>,
    pub expires_at: u64,
    /// ed25519 by `K_s`, over the creation digest.
    pub pop_s: HexBytes,
    /// r || s || v by `K_u`.
    pub pop_u: HexBytes,
    /// r || s || v by the cold key's intent key.
    pub pop_e: HexBytes,
    /// r || s || v by the Bitcoin escape key, over `leaf_pop_digest`. So the key in the script is one
    /// the creator holds, and a point on the curve. This is the only thing that key signs on NEAR.
    pub pop_leaf: HexBytes,
    pub pop_p: WebAuthn,
}

#[near(serializers = [json])]
pub struct InstanceView {
    pub preset: Preset,
    pub signer: near_sdk::AccountId,
    pub domain_id: u64,
    pub sign_tgas: u64,
    pub callback_tgas: u64,
    pub derive_tgas: u64,
    pub operator: near_sdk::AccountId,
    pub restrict_create: bool,
    pub origins: Vec<String>,
    pub network: String,
    pub policy: PolicyArgs,
    pub t_recover_ms: u64,
    pub expiry_window_ms: u64,
    pub bump_wait_ms: u64,
    pub block_ms: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[near(serializers = [borsh, json])]
pub enum Preset {
    TestCoin,
    MainnetProof,
}

impl Preset {
    pub fn fixed(self) -> Fixed {
        match self {
            Preset::TestCoin => Fixed::test_coin(),
            Preset::MainnetProof => Fixed::mainnet_proof(),
        }
    }
}

#[near(serializers = [json])]
pub struct VaultView {
    pub id: HexBytes,
    pub active: bool,
    pub k_s: HexBytes,
    pub k_s_suspended: bool,
    pub k_u: HexBytes,
    pub k_m: HexBytes,
    pub k_e_leaf: HexBytes,
    pub k_e_intent: HexBytes,
    pub passkey: HexBytes,
    pub rp_id_hash: HexBytes,
    pub backup_eligible: bool,
    pub backup_state: bool,
    pub guard: Option<near_sdk::AccountId>,
    pub csv: u32,
    pub script_pubkey: HexBytes,
    pub address: String,
    pub policy: PolicyArgs,
    pub spend_epoch: u64,
    pub frozen_until: Option<u64>,
    pub spend_nonce: u64,
    pub passkey_nonce: u64,
    pub cold_nonce: u64,
    pub pending: Vec<u64>,
    pub grants: Vec<u64>,
    pub recover_cancels: u8,
    pub recovery_ready_at: Option<u64>,
    pub storage_credit: near_sdk::json_types::U128,
    pub row_bytes: u64,
    pub reserved_bytes: u64,
}

#[near(serializers = [json])]
pub struct RequestView {
    pub id: u64,
    pub kind: String,
    pub status: String,
    pub epoch: u64,
    pub inputs: Vec<Utxo>,
    pub to: HexBytes,
    pub amount: u64,
    pub change: Option<u64>,
    pub tier: String,
    pub fee: u64,
    pub proposed_at: u64,
    pub base_unlock: u64,
    pub unlock: u64,
    pub expires_at: u64,
    pub first_execute_at: Option<u64>,
    pub attempt: u32,
    pub in_flight: u32,
    pub sigs: Vec<Option<HexBytes>>,
}

impl RequestView {
    pub fn of(r: &Request) -> Self {
        let Outputs { dest_script, dest_value, change_value } = &r.outputs;
        RequestView {
            id: r.id,
            kind: match r.kind {
                RequestKind::Normal => "Normal",
                RequestKind::Bump { .. } => "Bump",
                RequestKind::Reclaim => "Reclaim",
            }
            .to_string(),
            status: match r.status {
                RequestStatus::Pending => "Pending",
                RequestStatus::Signing => "Signing",
                RequestStatus::Signed => "Signed",
            }
            .to_string(),
            epoch: r.epoch,
            inputs: r.inputs.iter().map(Utxo::from_input).collect(),
            to: HexBytes(dest_script.clone()),
            amount: *dest_value,
            change: *change_value,
            tier: tier_name(r.tier).to_string(),
            fee: r.fee,
            proposed_at: r.proposed_at,
            base_unlock: r.base_unlock,
            unlock: r.unlock,
            expires_at: r.expires_at,
            first_execute_at: r.first_execute_at,
            attempt: r.attempt,
            in_flight: r.in_flight.len() as u32,
            sigs: r.sigs.iter().map(|s| s.clone().map(HexBytes)).collect(),
        }
    }
}

pub fn tier_name(tier: Tier) -> &'static str {
    match tier {
        Tier::SelfSpend => "SelfSpend",
        Tier::Known => "Known",
        Tier::New => "New",
    }
}

#[near(serializers = [json])]
pub struct CheckView {
    pub tier: String,
    pub delay_ms: u64,
    pub fee: u64,
    pub unguarded: bool,
}

#[near(serializers = [json])]
pub struct OutpointView {
    pub state: String,
    pub request: Option<u64>,
    pub pinned_value: Option<u64>,
    /// Set on a coin this vault's own signed transaction paid back to itself.
    pub born_at: Option<u64>,
}

/// Same wire shape as the live signer's `SignatureResponse::Secp256k1`. Other fields are ignored.
#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct AffinePoint {
    pub affine_point: HexBytes,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct Scalar {
    pub scalar: HexBytes,
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct SignerResponse {
    pub scheme: String,
    pub big_r: AffinePoint,
    pub s: Scalar,
    pub recovery_id: u8,
}
