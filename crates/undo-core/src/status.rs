//! A vault's state in plain language, for anyone reading the chain with one curl line. Downtime reads
//! as a designed state, because it is one. Each line names what still works.

use crate::policy::{DAY, HEARTBEAT_STALE_MS, HOUR, MINUTE, RECOVERY_CANCEL_CAP};
use crate::request::RequestStatus;
use crate::types::Ms;
use crate::vault::{GrantKind, Vault};

/// `2026-11-01 08:15 UTC`. Days to a civil date, after Howard Hinnant's algorithm.
pub fn utc_text(ms: Ms) -> String {
    let minutes = ms / 60_000;
    let (hour, minute) = ((minutes / 60) % 24, minutes % 60);
    let z = (ms / 86_400_000) as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02} UTC")
}

/// `48 h`, `10 min`, `1 h 30 s`, `10 min 1.5 s`: exact, with no rounding.
pub fn span_text(ms: Ms) -> String {
    let (hours, minutes, rest) = (ms / HOUR, (ms % HOUR) / MINUTE, ms % MINUTE);
    let mut parts = Vec::new();
    if hours > 0 {
        parts.push(format!("{hours} h"));
    }
    if minutes > 0 {
        parts.push(format!("{minutes} min"));
    }
    if rest > 0 || parts.is_empty() {
        let fraction = format!("{:03}", rest % 1_000);
        let fraction = fraction.trim_end_matches('0');
        parts.push(if fraction.is_empty() { format!("{} s", rest / 1_000) } else { format!("{}.{fraction} s", rest / 1_000) });
    }
    parts.join(" ")
}

impl GrantKind {
    pub fn describe(&self) -> &'static str {
        match self {
            GrantKind::RotateSpend { .. } => "install a new spend key",
            GrantKind::AddDestination { .. } => "add a known destination",
            GrantKind::LoosenPolicy { .. } => "loosen the policy",
            GrantKind::SetGuard { guard: Some(_) } => "replace the guard",
            GrantKind::SetGuard { guard: None } => "remove the guard",
        }
    }
}

impl Vault {
    /// What this vault's state means right now, one fact per line, the attention-worthy ones first. The
    /// first return is false when any line calls for attention. Reads whatever pending requests the
    /// caller has loaded.
    pub fn status_lines(&self, now: Ms) -> (bool, Vec<String>) {
        let mut attention = Vec::new();
        let mut calm = Vec::new();
        if !self.active {
            attention.push("not active: the signer has not confirmed K_m, so nothing can be proposed".to_string());
        }
        if self.is_frozen(now) {
            let until = utc_text(self.frozen_until.unwrap_or(now));
            // The freeze bumped the epoch, so every pending request is dead, and nothing can be proposed until
            // it ends. Cancel is the one passkey action left, and it has nothing to act on.
            attention.push(format!("frozen until {until} by the cold key: no proposals, reclaims or execute, and no passkey action except cancel, which has nothing to stop because the freeze ended every pending request. Only the cold key can lift it early, and the cold-key exit is unaffected"));
        }
        // Execute refuses a retry for a request that pays out from a day after its first execute, sooner for
        // one executed before an upgrade, and leaves reclaim, which the spend key signs, as the way out.
        let retry = format!("a self-spend with no time limit and one that pays out for at most {} after its first execute", span_text(DAY));
        if self.k_s_suspended {
            // Execute is the point of no return, so a rotation cannot speak for a request past it. A veto,
            // a freeze or a finished recovery takes the waiting key away and leaves this one suspended.
            let waiting = self.grants.iter().any(|g| matches!(g.kind, GrantKind::RotateSpend { .. }));
            let next = if waiting { "a new key lands after its wait unless the cold key vetoes it" } else { "no new key is waiting, so the passkey has to rotate again" };
            attention.push(format!("spend key suspended: requests not yet executed are dead. One already executed can still ask the signer for its missing signatures, {retry}, after which its coins come back by reclaim with a new key: {next}"));
        }
        if self.last_spend_at != 0 {
            // A rotation that began or landed after this spend may be the owner reacting too late. The
            // contract cannot tell a thief's spend from the owner's, so an ordinary one stays calm.
            let before_rotation = self.k_s_suspended || (self.k_s_since > self.created_at && self.last_spend_at <= self.k_s_since);
            let line = format!("last spend reached signing at {}", utc_text(self.last_spend_at));
            if before_rotation && now.saturating_sub(self.last_spend_at) < DAY {
                attention.push(format!("{line}, before the spend key was rotated: its signature cannot be taken back, so check it on Bitcoin"));
            } else {
                calm.push(line);
            }
        }
        // Only said when it is true: a freeze, a suspended key and an inactive vault move nothing.
        let movable = if self.active && !self.is_frozen(now) && !self.k_s_suspended { ", funds movable" } else { "" };
        // The bounds allow the two delays to be equal, or far apart, so the line names both.
        let (guarded, unguarded) = (self.policy.t_new_ms, self.policy.t_new_unguarded_ms);
        let slow = if unguarded == guarded {
            format!("new-destination delay {}, the same as with a guard online", span_text(unguarded))
        } else {
            format!("new-destination delay {} instead of {}", span_text(unguarded), span_text(guarded))
        };
        match (&self.guard, self.last_heartbeat) {
            (None, _) => calm.push(format!("no guard: {slow}{movable}")),
            (Some(_), Some(beat)) if now.saturating_sub(beat) <= HEARTBEAT_STALE_MS => {
                calm.push(format!("guard online, last heartbeat {}", utc_text(beat)));
            }
            (Some(_), Some(beat)) => attention.push(format!("guard offline since {}: {slow}{movable}", utc_text(beat))),
            (Some(_), None) => attention.push(format!("guard offline, no heartbeat yet: {slow}{movable}")),
        }
        if self.sign_failed_at != 0 {
            // Reclaim takes the self-spend slot, so its coins come back one per `T_new`, and only once a
            // suspended key has been replaced.
            let reclaim = if self.k_s_suspended { "with a new key".to_string() } else { format!("at most one per {}", span_text(self.policy.t_new_ms)) };
            attention.push(format!(
                "the signer's last answer failed at {}: a request still signing can retry, {retry}, after which its coins come back by reclaim, {reclaim}, and a coin {} blocks old can leave by the cold-key exit",
                utc_text(self.sign_failed_at),
                self.csv_blocks,
            ));
        }
        for grant in &self.grants {
            attention.push(format!("passkey grant {} waiting until {}: {}. The cold key can veto it", grant.id, utc_text(grant.ready_at), grant.kind.describe()));
        }
        if let Some(recovery) = &self.recovery {
            // `recover_cancel` is a passkey action, so a freeze refuses it.
            let held = if self.is_frozen(now) { " but cannot use them while the vault is frozen" } else { "" };
            attention.push(format!(
                "passkey recovery lands at {}. The current passkey has {} of {RECOVERY_CANCEL_CAP} cancels left{held}",
                utc_text(recovery.ready_at),
                RECOVERY_CANCEL_CAP.saturating_sub(self.recover_cancels),
            ));
        }
        let budget_used = self.fee_used_24h(now);
        let budget_left = self.policy.fee_budget_24h.saturating_sub(budget_used);
        if budget_left < self.policy.fee_cap_tx {
            attention.push(format!(
                "24 h fee budget used, {budget_used} of {} sats: a fee above {budget_left} sats waits until it rolls off, within {} h, or until a rotation lands",
                self.policy.fee_budget_24h,
                DAY / crate::policy::HOUR,
            ));
        }
        let live: Vec<Ms> = self
            .pending
            .iter()
            .filter(|id| self.is_live(**id, now))
            .filter_map(|id| self.requests.get(id))
            .filter(|r| r.status == RequestStatus::Pending)
            .map(|r| r.unlock)
            .collect();
        if let Some(next) = live.iter().min() {
            calm.push(format!("{} pending, next unlock {}", live.len(), utc_text(*next)));
        }
        calm.push(format!("cold-key exit: a coin {} blocks old can leave with the recovery file and no NEAR", self.csv_blocks));
        let ok = attention.is_empty();
        attention.append(&mut calm);
        (ok, attention)
    }
}
