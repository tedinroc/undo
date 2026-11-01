//! Delays, caps and the bounds that hold them. Values come from the spec's delay table.

use crate::types::{Ms, Sats};

pub const MINUTE: Ms = 60_000;
pub const HOUR: Ms = 60 * MINUTE;
pub const DAY: Ms = 24 * HOUR;

pub const MAX_INPUTS: usize = 16;
pub const MAX_PENDING: usize = 3;
/// `K_p` may cancel a recovery this many times between successful recoveries.
pub const RECOVERY_CANCEL_CAP: u8 = 2;
/// A guard counts as offline once its heartbeat is older than this: four missed 5 min beats.
pub const HEARTBEAT_STALE_MS: Ms = 20 * MINUTE;
/// NEAR blocks before a lost callback stops holding `in_flight`.
pub const RETRY_AFTER_BLOCKS: u64 = 250;
/// Bound on pending passkey grants, so `freeze` and the phone page stay bounded.
pub const MAX_GRANTS: usize = 8;
/// Bound on known destinations. They sit in the row, which `on_signed` reads with fixed gas, so a stolen
/// passkey adding one per `T_new` must not be able to grow it without limit.
pub const MAX_KNOWN: usize = 32;
/// Lowest accepted fee rate in sat/vB, on the estimate from counts.
pub const MIN_FEE_RATE: Sats = 1;
/// A named self-spend override may go up to 1/20 of the value it moves.
pub const FEE_OVERRIDE_DIVISOR: Sats = 20;

/// What `K_p` can change, within [`Bounds`]. `T_recover` is deliberately not here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct Policy {
    pub t_known_ms: Ms,
    pub t_new_ms: Ms,
    pub t_new_unguarded_ms: Ms,
    pub hold_ms: Ms,
    pub t_stuck_ms: Ms,
    pub fee_cap_tx: Sats,
    pub fee_budget_24h: Sats,
    pub outflow_cap_24h: Sats,
}

impl Policy {
    pub fn test_coin(outflow_cap_24h: Sats) -> Policy {
        Policy {
            t_known_ms: MINUTE,
            t_new_ms: 5 * MINUTE,
            t_new_unguarded_ms: 10 * MINUTE,
            hold_ms: 5 * MINUTE,
            t_stuck_ms: 10 * MINUTE,
            fee_cap_tx: 1_000,
            fee_budget_24h: 5_000,
            outflow_cap_24h,
        }
    }

    pub fn mainnet_proof(outflow_cap_24h: Sats) -> Policy {
        Policy {
            t_known_ms: 5 * MINUTE,
            t_new_ms: 10 * MINUTE,
            t_new_unguarded_ms: 20 * MINUTE,
            hold_ms: 20 * MINUTE,
            t_stuck_ms: HOUR,
            fee_cap_tx: 1_000,
            fee_budget_24h: 3_000,
            outflow_cap_24h,
        }
    }

    /// True when `self` gives `K_s` more reach than `old` in any field, so it must wait as a grant.
    pub fn loosens(&self, old: &Policy) -> bool {
        self.t_known_ms < old.t_known_ms
            || self.t_new_ms < old.t_new_ms
            || self.t_new_unguarded_ms < old.t_new_unguarded_ms
            || self.hold_ms < old.hold_ms
            || self.t_stuck_ms < old.t_stuck_ms
            || self.fee_cap_tx > old.fee_cap_tx
            || self.fee_budget_24h > old.fee_budget_24h
            || self.outflow_cap_24h > old.outflow_cap_24h
    }
}

/// Fixed at creation. No key can change these.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct Fixed {
    pub t_recover_ms: Ms,
    pub expiry_window_ms: Ms,
    /// Bitcoin block interval of the network, used to turn CSV blocks into the longest freeze.
    pub block_ms: Ms,
    /// CSV blocks a vault on this instance may choose.
    pub csv_min: u32,
    pub csv_max: u32,
}

impl Fixed {
    /// Mutinynet, 30-second blocks.
    pub fn test_coin() -> Fixed {
        Fixed {
            t_recover_ms: 15 * MINUTE,
            expiry_window_ms: HOUR,
            block_ms: 30_000,
            // Six is the delay table's value. A day of Mutinynet blocks is far more than a test coin
            // needs, and keeps the longest freeze to a day.
            csv_min: 6,
            csv_max: 2_880,
        }
    }

    /// Bitcoin mainnet, 10-minute blocks.
    pub fn mainnet_proof() -> Fixed {
        Fixed {
            t_recover_ms: HOUR,
            expiry_window_ms: DAY,
            block_ms: 10 * MINUTE,
            // From the proof vault's six to the documented default's six months.
            csv_min: 6,
            csv_max: 26_280,
        }
    }
}

/// Instance limits on [`Policy`]. Maxima keep `T_upgrade` longer than any withdrawal. Floors on the
/// fee caps keep an exit possible.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct Bounds {
    pub min: Policy,
    pub max: Policy,
}

impl Bounds {
    /// Delay maxima equal the deployed values, because the upgrade arithmetic (26 min of a 1 h
    /// `T_upgrade`) assumes them. Delays therefore cannot move on this instance. Fee floors are
    /// this crate's choice: the spec requires a floor and names no number.
    pub fn test_coin(outflow_cap_24h: Sats) -> Bounds {
        let deployed = Policy::test_coin(outflow_cap_24h);
        Bounds {
            min: Policy { fee_cap_tx: 500, fee_budget_24h: 1_000, outflow_cap_24h: 0, ..deployed },
            max: deployed,
        }
    }

    /// Delay floors are the proof vault's values. Delay maxima are the documented-default column,
    /// which the upgrade arithmetic uses (48 h + 24 h + 24 h + 1 h). Fee floors as in `test_coin`.
    pub fn mainnet(outflow_cap_24h: Sats) -> Bounds {
        let deployed = Policy::mainnet_proof(outflow_cap_24h);
        Bounds {
            min: Policy { fee_cap_tx: 500, fee_budget_24h: 1_000, outflow_cap_24h: 0, ..deployed },
            max: Policy {
                t_known_ms: HOUR,
                t_new_ms: 24 * HOUR,
                t_new_unguarded_ms: 48 * HOUR,
                hold_ms: 24 * HOUR,
                t_stuck_ms: 24 * HOUR,
                ..deployed
            },
        }
    }

    /// The longest a withdrawal can take here: unguarded new-destination delay, one hold, a stuck wait
    /// and a known-destination delay.
    pub fn longest_withdrawal_ms(&self) -> Ms {
        let m = &self.max;
        m.t_new_unguarded_ms
            .saturating_add(m.hold_ms)
            .saturating_add(m.t_stuck_ms)
            .saturating_add(m.t_known_ms)
    }

    pub fn allows(&self, p: &Policy) -> bool {
        let within = |v, lo, hi| v >= lo && v <= hi;
        let (lo, hi) = (&self.min, &self.max);
        within(p.t_known_ms, lo.t_known_ms, hi.t_known_ms)
            && within(p.t_new_ms, lo.t_new_ms, hi.t_new_ms)
            && within(p.t_new_unguarded_ms, lo.t_new_unguarded_ms, hi.t_new_unguarded_ms)
            && within(p.hold_ms, lo.hold_ms, hi.hold_ms)
            && within(p.t_stuck_ms, lo.t_stuck_ms, hi.t_stuck_ms)
            && within(p.fee_cap_tx, lo.fee_cap_tx, hi.fee_cap_tx)
            && within(p.fee_budget_24h, lo.fee_budget_24h, hi.fee_budget_24h)
            && within(p.outflow_cap_24h, lo.outflow_cap_24h, hi.outflow_cap_24h)
            && p.t_known_ms <= p.t_new_ms
            && p.t_new_ms <= p.t_new_unguarded_ms
            && p.fee_cap_tx <= p.fee_budget_24h
    }
}
