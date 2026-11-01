//! A vault's state in plain language, for anyone reading the chain with one curl line. Downtime reads
//! as a designed state, because it is one. Each line names what still works.

use crate::policy::{DAY, HEARTBEAT_STALE_MS, RECOVERY_CANCEL_CAP};
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
            attention.push(format!("frozen until {until} by the cold key: no proposals, no execute, no passkey grants, cold-key exit unaffected"));
        }
        if self.k_s_suspended {
            attention.push("spend key suspended: every older request is dead, and a new key lands after its wait unless the cold key vetoes it".to_string());
        }
        match (&self.guard, self.last_heartbeat) {
            (None, _) => calm.push("no guard: new-destination delay doubled, funds movable".to_string()),
            (Some(_), Some(beat)) if now.saturating_sub(beat) <= HEARTBEAT_STALE_MS => {
                calm.push(format!("guard online, last heartbeat {}", utc_text(beat)));
            }
            (Some(_), Some(beat)) => attention.push(format!("guard offline since {}: new-destination delay doubled, funds movable", utc_text(beat))),
            (Some(_), None) => attention.push("guard offline, no heartbeat yet: new-destination delay doubled, funds movable".to_string()),
        }
        if self.sign_failed_at != 0 {
            attention.push(format!(
                "signing unavailable since {}: the signer's last answer failed, retry is open, and a coin {} blocks old can leave by the cold-key exit",
                utc_text(self.sign_failed_at),
                self.csv_blocks,
            ));
        }
        for grant in &self.grants {
            attention.push(format!("passkey grant {} waiting until {}: {}. The cold key can veto it", grant.id, utc_text(grant.ready_at), grant.kind.describe()));
        }
        if let Some(recovery) = &self.recovery {
            attention.push(format!(
                "passkey recovery lands at {}. The current passkey has {} of {RECOVERY_CANCEL_CAP} cancels left",
                utc_text(recovery.ready_at),
                RECOVERY_CANCEL_CAP.saturating_sub(self.recover_cancels),
            ));
        }
        let budget_used = self.fee_used_24h(now);
        if budget_used >= self.policy.fee_budget_24h {
            attention.push(format!(
                "24 h fee budget used, {budget_used} of {} sats: spends wait until it rolls off, within {} h, or until a rotation lands",
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
