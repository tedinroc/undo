use crate::types::{HalfSig, Input, MpcSig, Ms, Outputs, RequestId, Sats};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub enum Tier {
    SelfSpend,
    Known,
    New,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub enum RequestKind {
    Normal,
    /// Same inputs and declared values as `predecessor`, higher fee, no new delay.
    Bump { predecessor: RequestId },
    /// One outpoint back to the vault's own script. May re-declare the value.
    Reclaim,
}

/// Only live states exist. A cancelled, expired, invalidated, superseded or pruned request is
/// deleted, so a late callback finds nothing to write to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub enum RequestStatus {
    Pending,
    Signing,
    Signed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct Request {
    pub id: RequestId,
    pub kind: RequestKind,
    pub status: RequestStatus,
    pub epoch: u64,
    pub inputs: Vec<Input>,
    pub half_sigs: Vec<HalfSig>,
    pub outputs: Outputs,
    pub tier: Tier,
    pub fee: Sats,
    /// Part of `fee` already charged by the request this one replaced. Only one of them can
    /// confirm, so a bump charges the difference.
    pub fee_prepaid: Sats,
    /// Set by `K_p` for one named self-spend.
    pub fee_override: Option<Sats>,
    pub proposed_at: Ms,
    /// Earliest possible unlock. No method moves it.
    pub base_unlock: Ms,
    /// `base_unlock`, plus `hold_ms` while a hold stands.
    pub unlock: Ms,
    pub expires_at: Ms,
    pub assessed: bool,
    pub hold_used: bool,
    pub hold_active: bool,
    pub first_execute_at: Option<Ms>,
    pub attempt: u32,
    pub in_flight: Vec<usize>,
    pub last_attempt_height: u64,
    /// When the last signature landed. `prune_signed` counts from here.
    pub signed_at: Option<Ms>,
    pub sigs: Vec<Option<MpcSig>>,
}

impl Request {
    pub fn is_self_spend(&self) -> bool {
        self.tier == Tier::SelfSpend
    }

    /// Which outputs of this request's transaction pay the vault's own script: the destination, if
    /// this is a self-spend, comes first, and any change comes after it. Each is a new coin with age
    /// zero.
    pub fn vault_vouts(&self) -> Vec<u32> {
        let mut vouts = Vec::new();
        if self.is_self_spend() {
            vouts.push(0);
        }
        if self.outputs.change_value.is_some() {
            vouts.push(1);
        }
        vouts
    }

    pub fn missing_inputs(&self) -> Vec<usize> {
        (0..self.sigs.len()).filter(|i| self.sigs[*i].is_none()).collect()
    }
}
