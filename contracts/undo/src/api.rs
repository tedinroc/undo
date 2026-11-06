//! JSON shapes of the contract's methods. State lives in `undo-core` types, encoded with Borsh.

use near_sdk::serde::{Deserialize, Deserializer, Serialize, Serializer};
use near_sdk::{env, near};
use undo_core::{Fixed, Input, Outpoint, Outputs, Policy, Request, RequestKind, RequestStatus, Snapshot, Tier, UpgradeRules};

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
    pub block_ms: u64,
    pub csv_min: u32,
    pub csv_max: u32,
    pub t_upgrade_ms: u64,
    pub upgrade_expiry_ms: u64,
    /// How long an owner has to notice an upgrade and still be out before it lands.
    pub reaction_window_ms: u64,
    pub pending_upgrade: Option<UpgradeView>,
    /// All vaults' credit, plus what their reservations paid for.
    pub vault_funds: near_sdk::json_types::U128,
    /// What the balance holds beyond storage and `vault_funds`, which is all new code may spend.
    pub free_balance: near_sdk::json_types::U128,
    /// The running code's size, high by the account's overhead until the first upgrade.
    pub code_bytes: u64,
    pub operator_passkey: HexBytes,
    pub guard_model: String,
    pub model_signers: Vec<ModelSignerView>,
}

#[near(serializers = [json])]
pub struct UpgradeView {
    pub code_hash: HexBytes,
    pub proposed_at: u64,
    pub unlock_at: u64,
    pub expires_at: u64,
}

#[near(serializers = [json])]
pub struct ModelSignerView {
    pub model: String,
    pub signer: HexBytes,
}

/// Plain language for a person with curl. `ok` is false when a line calls for attention.
#[near(serializers = [json])]
pub struct StatusView {
    pub ok: bool,
    pub lines: Vec<String>,
}

/// Vaults whose distinct passkey completed a cancel or a spend, with a team test set taken out and
/// listed. Nothing here can rule out one person holding many passkeys.
#[near(serializers = [json])]
pub struct StatsView {
    pub vaults_created: u64,
    pub vaults_active: u64,
    pub passkeys_completed: u64,
    pub excluded_passkeys: Vec<HexBytes>,
    pub excluded_that_completed: u64,
    pub counted: u64,
}

#[near(serializers = [json])]
pub struct GrantView {
    pub id: u64,
    pub kind: String,
    pub begun_at: u64,
    pub ready_at: u64,
}

#[near(serializers = [json])]
pub struct SnapshotView {
    pub destination_seen_hours_ago: Option<u32>,
    pub amount_sats: u64,
    pub inputs_sats: u64,
    pub share_bps: u16,
    pub proposals_24h: u8,
    pub cancels_30d: u8,
    pub hours_since_last_spend: Option<u32>,
    pub vault_age_hours: u32,
    pub spend_key_age_hours: u32,
    pub utc_hour: u8,
    pub memo: Option<String>,
}

impl SnapshotView {
    fn of(s: &Snapshot) -> Self {
        SnapshotView {
            destination_seen_hours_ago: s.destination_seen_hours_ago,
            amount_sats: s.amount_sats,
            inputs_sats: s.inputs_sats,
            share_bps: s.share_bps,
            proposals_24h: s.proposals_24h,
            cancels_30d: s.cancels_30d,
            hours_since_last_spend: s.hours_since_last_spend,
            vault_age_hours: s.vault_age_hours,
            spend_key_age_hours: s.spend_key_age_hours,
            utc_hour: s.utc_hour,
            memo: s.memo.clone(),
        }
    }
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

    pub fn upgrade(self) -> UpgradeRules {
        match self {
            Preset::TestCoin => UpgradeRules::test_coin(),
            Preset::MainnetProof => UpgradeRules::mainnet_proof(),
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
    pub guard_online: bool,
    pub last_heartbeat: Option<u64>,
    pub created_at: u64,
    pub known: Vec<HexBytes>,
    pub fee_used_24h: u64,
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
    pub grant_list: Vec<GrantView>,
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
    pub assessed: bool,
    pub assess_hold: bool,
    pub assess_reason: String,
    pub hold_used: bool,
    pub hold_active: bool,
    pub snapshot: SnapshotView,
}

impl RequestView {
    pub fn of(r: &Request) -> Self {
        let Outputs { dest_script, dest_value, change_value } = &r.outputs;
        RequestView {
            id: r.id,
            kind: match r.kind {
                RequestKind::Normal => "Normal",
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
            assessed: r.assessed,
            assess_hold: r.assess_hold,
            assess_reason: r.assess_reason.name().to_string(),
            hold_used: r.hold_used,
            hold_active: r.hold_active,
            snapshot: SnapshotView::of(&r.snapshot),
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

/// The parts of a chat completion this contract reads. Other fields are ignored, because the provider
/// adds them, and the signature already covers every byte.
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct ChatCompletion {
    pub choices: Vec<ChatChoice>,
}

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct ChatChoice {
    pub message: ChatMessage,
}

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde")]
pub struct ChatMessage {
    pub content: String,
}

/// What the model is told to answer with, and nothing else.
#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde", deny_unknown_fields)]
pub struct GuardAnswer {
    pub hold: bool,
    pub reason: String,
}
