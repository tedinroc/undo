//! The upgrade queue: a public wait, longer than any withdrawal, before new code can land, and an
//! approved upgrade that runs out. The shell checks who is asking and does the deploying.

use crate::error::Error;
use crate::policy::{Bounds, DAY, HOUR, MINUTE};
use crate::types::Ms;

/// `T_upgrade`, how long an approved upgrade stays approved, and the reaction window it must leave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UpgradeRules {
    pub t_upgrade_ms: Ms,
    pub expiry_ms: Ms,
    pub min_reaction_ms: Ms,
}

impl UpgradeRules {
    pub fn test_coin() -> UpgradeRules {
        UpgradeRules { t_upgrade_ms: HOUR, expiry_ms: HOUR, min_reaction_ms: 30 * MINUTE }
    }

    pub fn mainnet_proof() -> UpgradeRules {
        UpgradeRules { t_upgrade_ms: 14 * DAY, expiry_ms: 3 * DAY, min_reaction_ms: 7 * DAY }
    }

    /// What is left of `T_upgrade` after the longest withdrawal this instance allows: how long an owner
    /// has to notice and still be out before new code lands. `Bounds` holds every vault's delays under
    /// these maxima, at creation and at every `set_policy`.
    pub fn reaction_window_ms(&self, bounds: &Bounds) -> Ms {
        self.t_upgrade_ms.saturating_sub(bounds.longest_withdrawal_ms())
    }

    pub fn holds(&self, bounds: &Bounds) -> bool {
        self.reaction_window_ms(bounds) >= self.min_reaction_ms
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct PendingUpgrade {
    pub code_hash: [u8; 32],
    pub proposed_at: Ms,
    pub unlock_at: Ms,
    pub expires_at: Ms,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct UpgradeQueue {
    pub pending: Option<PendingUpgrade>,
}

impl UpgradeQueue {
    /// Holds one at a time. A cancel or an expiry means a new full `T_upgrade`, so a second proposal
    /// cannot inherit the first one's clock.
    pub fn propose(&mut self, code_hash: [u8; 32], rules: &UpgradeRules, now: Ms) -> Result<PendingUpgrade, Error> {
        if self.pending.is_some_and(|p| now <= p.expires_at) {
            return Err(Error::UpgradeInProgress);
        }
        let unlock_at = now.saturating_add(rules.t_upgrade_ms);
        let pending = PendingUpgrade {
            code_hash,
            proposed_at: now,
            unlock_at,
            expires_at: unlock_at.saturating_add(rules.expiry_ms),
        };
        self.pending = Some(pending);
        Ok(pending)
    }

    pub fn cancel(&mut self) -> Result<PendingUpgrade, Error> {
        self.pending.take().ok_or(Error::NoUpgrade)
    }

    /// Anyone, with code matching the hash, once it unlocks and before it runs out. The approval is
    /// used up by the attempt, so code that fails to deploy needs a new full `T_upgrade`.
    pub fn take_for_apply(&mut self, code_hash: [u8; 32], now: Ms) -> Result<PendingUpgrade, Error> {
        let pending = self.pending.ok_or(Error::NoUpgrade)?;
        if code_hash != pending.code_hash {
            return Err(Error::UpgradeHashMismatch);
        }
        if now < pending.unlock_at {
            return Err(Error::UpgradeNotReady { ready_at: pending.unlock_at });
        }
        if now > pending.expires_at {
            return Err(Error::UpgradeExpired);
        }
        self.pending = None;
        Ok(pending)
    }
}
