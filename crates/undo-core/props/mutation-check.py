#!/usr/bin/env python3
"""Breaks undo-core one rule at a time, in a temporary copy, and expects a test to notice.

Run with the toolchain environment set. The source tree is not touched. Each entry is a name, then
(file, old text, new text) edits. `fee model only` also removes the harness's direct assertion on
the pin rule, to show that the real-fee property catches the attack on its own.
"""
import os, re, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
CRATE = os.path.dirname(HERE)
V = "src/vault.rs"
W = "props/tests/common/world.rs"
P = "src/policy.rs"
T = "src/types.rs"
G = "src/guard.rs"
S = "src/status.rs"
U = "src/upgrade.rs"
PIN_RULE = ("inputs.len() > 1 && self.pinned_value(&input.outpoint).is_some()", "false")

MUTANTS = [
    ("rule 2 off: pinned outpoint may enter a multi-input request", [(V, *PIN_RULE)]),
    ("rule 2 off, fee model only", [
        (V, *PIN_RULE),
        (W, 'assert!(!self.pins.contains_key(o), "a pinned outpoint entered a multi-input request");', ""),
    ]),
    ("pin overwritten at each execute", [(V, "entry.pinned_value.get_or_insert(input.value);", "entry.pinned_value = Some(input.value);")]),
    ("pin dropped when an outpoint is freed", [(V, "if entry.pinned_value.is_some() || entry.born_at.is_some() {\n            entry.state = OutpointState::Free;", "if entry.born_at.is_some() {\n            entry.state = OutpointState::Free;")]),
    ("execute ignores unlock", [(V, "if now < request.unlock {", "if false {")]),
    ("execute waits past the unlock", [(V, "if now < request.unlock {", "if now <= request.unlock {")]),
    ("clear_hold goes below base", [(V, "request.unlock = request.base_unlock;\n        request.expires_at", "request.unlock = request.base_unlock.saturating_sub(1_000);\n        request.expires_at")]),
    ("hold adds nothing", [(V, "request.unlock = request.base_unlock.saturating_add(hold_ms);", "")]),
    ("old epoch still executes", [
        (V, "(request.epoch != self.spend_epoch || now > request.expires_at)", "(now > request.expires_at)"),
        (V, "if request.epoch != self.spend_epoch {", "if false {"),
    ]),
    ("expired request still executes", [(V, "(request.epoch != self.spend_epoch || now > request.expires_at)", "(request.epoch != self.spend_epoch)")]),
    ("expiry race lost at the exact block", [(V, "|| now > request.expires_at)", "|| now >= request.expires_at)")]),
    ("freeze does not block execute", [(V, "self.require_not_frozen(now)?;\n        if max_inputs == 0", "if max_inputs == 0")]),
    ("freeze does not bump the epoch", [(V, "self.csv_period_ms())));\n        self.bump_epoch();", "self.csv_period_ms())));")]),
    ("freeze keeps pending grants", [(V, "self.bump_epoch();\n        self.grants.clear();", "self.bump_epoch();")]),
    ("freeze may outlast CSV", [(V, "self.frozen_until = Some(until.min(now.saturating_add(self.csv_period_ms())));", "self.frozen_until = Some(until);")]),
    ("passkey can recover_cancel during a freeze", [(V, "self.sweep(now);\n        self.require_not_frozen(now)?;\n        self.auth_passkey(caller, intent, now)?;\n        if self.recovery.is_none()", "self.sweep(now);\n        self.auth_passkey(caller, intent, now)?;\n        if self.recovery.is_none()")]),
    ("recovery cap removed", [(V, "if self.recover_cancels >= RECOVERY_CANCEL_CAP {", "if false {")]),
    ("recovery does not reset the count", [(V, "self.recover_cancels = 0;\n        self.grants.clear();", "self.grants.clear();")]),
    ("recovery keeps old grants", [(V, "self.recover_cancels = 0;\n        self.grants.clear();", "self.recover_cancels = 0;")]),
    ("recovery ignores T_recover", [(V, "if now < recovery.ready_at {", "if false {")]),
    ("grant lands early", [(V, "if now < ready_at {\n            return Err(Error::GrantNotReady { ready_at });", "if false {\n            return Err(Error::GrantNotReady { ready_at });")]),
    ("loosening applies at once", [(V, "if policy.loosens(&self.policy) {", "if false {")]),
    ("tightening keeps a waiting loosening", [(V, "self.policy = policy;\n        self.grants.retain(|g| !matches!(g.kind, GrantKind::LoosenPolicy { .. }));", "self.policy = policy;")]),
    ("fee cap unchecked at execute", [(V, "if request.fee > cap {", "if false {")]),
    ("fee budget unchecked", [(V, "used.saturating_add(charge) > self.policy.fee_budget_24h", "false")]),
    ("fee override not limited to a twentieth", [(V, "if cap > limit {", "if false {")]),
    ("fee override allowed on any tier", [(V, "if !request.is_self_spend() {", "if false {")]),
    ("self-spend slot never checked", [(V, "if now < free_at {", "if false {")]),
    ("a spend with change needs no slot", [(V, "outputs.dest_script == self.vault_spk || outputs.change_value.is_some()", "outputs.dest_script == self.vault_spk")]),
    ("the fee window is never trimmed", [(V, "self.fee_window.retain(|(at, _)| now < at.saturating_add(DAY));\n", "")]),
    ("prune ignores the window", [(V, "if now < ready_at {\n            return Err(Error::PruneTooSoon { ready_at });", "if false {\n            return Err(Error::PruneTooSoon { ready_at });")]),
    ("prune takes a request not yet signed", [(V, "if request.status != RequestStatus::Signed {\n            return Err(Error::NotSigned);\n        }\n        let signed_at = request.signed_at.ok_or(Error::NotSigned)?;", "let signed_at = request.signed_at.unwrap_or(0);")]),
    ("prune window counts from nothing", [(V, "request.signed_at = Some(now);", "request.signed_at = Some(0);")]),
    ("slot refund ignores the holder", [(V, "if self.slot.holder == Some(id) {\n            self.slot.last_at", "if true {\n            self.slot.last_at")]),
    ("slot not refunded on cancel", [(V, "self.refund_slot(id);\n        self.kill_pending(id);", "self.kill_pending(id);")]),
    ("reclaim ignores T_stuck", [(V, "if now < ready_at {\n            return Err(Error::NotStuck { ready_at });", "if false {\n            return Err(Error::NotStuck { ready_at });")]),
    ("reclaim does not supersede", [(V, "self.supersede(owner);", "let _ = owner;")]),
    ("reclaim at no delay", [(V, "let base_unlock = now.saturating_add(self.policy.t_known_ms);\n        self.require_chain_wait(&[Input { outpoint, value }], base_unlock)?;", "let base_unlock = now;\n        self.require_chain_wait(&[Input { outpoint, value }], base_unlock)?;")]),
    ("any script counts as known", [(V, "self.known.contains(&outputs.dest_script)\n", "true\n")]),
    ("outflow cap ignored", [(V, "<= self.policy.outflow_cap_24h", "<= Sats::MAX")]),
    ("outflow not released on kill", [(V, "self.outflow_window.retain(|e| e.request != id);\n", "")]),
    ("stale guard counts as online", [(V, "<= HEARTBEAT_STALE_MS", "<= 10 * HEARTBEAT_STALE_MS")]),
    ("second hold allowed", [(V, "if request.hold_used {\n            return Err(Error::HoldAlreadyUsed);\n        }", "")]),
    ("stale attempt accepted", [(V, "if attempt != request.attempt {", "if false {")]),
    ("digest not compared", [(V, "if payload != recomputed {", "if false {")]),
    ("csv unbounded", [(V, "args.csv_blocks > 65_535", "false")]),
    ("keys may repeat", [(V, "if keys[i + 1..].iter().any(|b| a == b) {", "if false {")]),
    ("wrong K_m activates", [(V, "if signer_key != self.k_m.as_slice() {", "if false {")]),
    ("rotation does not suspend K_s", [(V, "self.k_s_suspended = true;", "")]),
    ("removal leaves pending requests", [(V, "for id in doomed {\n            self.refund_slot(id);\n            self.kill_pending(id);\n        }", "let _ = doomed;")]),
    ("removal keeps the slot a killed spend held", [(V, "for id in doomed {\n            self.refund_slot(id);\n", "for id in doomed {\n")]),
    ("nonces not checked", [(V, "if intent.nonce != expected {", "if false {")]),
    ("pending cap off at propose", [(V, "if self.pending.len() >= MAX_PENDING {\n            return Err(Error::PendingCap);\n        }\n\n        let unguarded", "let unguarded")]),
    ("an inactive vault works", [(V, "self.require_active()?;", "")]),
    ("chain: a repeat of the same transaction moves the birth time", [(V, "self.ledger.entry(child).or_insert(LedgerEntry {\n                state: OutpointState::Free,\n                pinned_value: None,\n                signing_since: None,\n                born_at: Some(now),\n            });", "self.ledger.insert(child, LedgerEntry {\n                state: OutpointState::Free,\n                pinned_value: None,\n                signing_since: None,\n                born_at: Some(now),\n            });")]),
    ("reclaim needs no slot", [(V, "self.require_slot_free(now)?;\n        let base_unlock = now.saturating_add(self.policy.t_known_ms);\n        self.require_chain_wait(&[Input { outpoint, value }], base_unlock)?;", "let base_unlock = now.saturating_add(self.policy.t_known_ms);\n        self.require_chain_wait(&[Input { outpoint, value }], base_unlock)?;")]),
    ("reclaim takes no slot", [(V, "self.take_slot(id, now);\n        Ok(self.proposed(id))\n    }\n\n    // ---------------------------------------------------------------- open methods", "let _ = id;\n        Ok(self.proposed(id))\n    }\n\n    // ---------------------------------------------------------------- open methods")]),
    ("chain: propose does not wait", [(V, "self.require_chain_wait(inputs, now.saturating_add(delay_ms))?;", "")]),
    ("chain: reclaim does not wait", [(V, "self.require_chain_wait(&[Input { outpoint, value }], base_unlock)?;", "")]),
    ("chain: built backwards allowed", [(V, "return Err(Error::ChainOutOfOrder(*child));", "continue;")]),
    ("chain: only a signed child blocks the parent", [(V, "e.state != OutpointState::Free || e.pinned_value.is_some()", "e.pinned_value.is_some()")]),
    ("chain: a cancelled child still blocks the parent", [(V, "e.state != OutpointState::Free || e.pinned_value.is_some()", "true")]),
    ("chain: a cancel forgets the birth time", [(V, "if entry.pinned_value.is_some() || entry.born_at.is_some() {", "if entry.pinned_value.is_some() {")]),
    ("chain: the wait is the whole CSV", [(V, "self.csv_period_ms().saturating_mul(3) / 4", "self.csv_period_ms()")]),
    ("chain: the wait is half the CSV", [(V, "self.csv_period_ms().saturating_mul(3) / 4", "self.csv_period_ms() / 2")]),
    ("chain: no birth time recorded", [(V, "born_at: Some(now),", "born_at: None,")]),
    ("chain: a spend with no restart waits too", [(V, "if self.restarts_csv(outputs) {\n            self.require_slot_free(now)?;\n            self.require_chain_wait(inputs, now.saturating_add(delay_ms))?;\n        }", "self.require_chain_wait(inputs, now.saturating_add(delay_ms))?;\n        if self.restarts_csv(outputs) {\n            self.require_slot_free(now)?;\n        }")]),
    ("chain: change is not a coin of the vault", [("src/request.rs", "if self.outputs.change_value.is_some() {\n            vouts.push(1);", "if false {\n            vouts.push(1);")]),
    ("chain: change at the wrong index", [("src/request.rs", "vouts.push(1);", "vouts.push(0);")]),
    ("chain: a self-spend's output is not a coin of the vault", [("src/request.rs", "if self.is_self_spend() {\n            vouts.push(0);", "if false {\n            vouts.push(0);")]),
    # The review of 10/31: each of these lived through the whole suite then.
    ("a rotation keeps the fee window", [(V, "self.fee_window.clear();\n", "")]),
    ("raise_fee_cap ignores a freeze", [(V, "self.require_not_frozen(now)?;\n        self.auth_passkey(caller, intent, now)?;\n        let request = self.requests.get_mut(&id).ok_or(Error::RequestNotFound)?;\n        if request.status != RequestStatus::Pending {\n            return Err(Error::NotPending);\n        }\n        if !request.is_self_spend()", "self.auth_passkey(caller, intent, now)?;\n        let request = self.requests.get_mut(&id).ok_or(Error::RequestNotFound)?;\n        if request.status != RequestStatus::Pending {\n            return Err(Error::NotPending);\n        }\n        if !request.is_self_spend()")]),
    ("cancel ignores its expiry", [(V, "if now > expires_at {\n            return Err(Error::IntentExpired);\n        }", "")]),
    ("recover_begin overwrites a running recovery", [(V, "if self.recovery.is_some() {\n            return Err(Error::RecoveryInProgress);\n        }", "")]),
    ("reclaim has no fee ceiling", [(V, "self.check_fee_ceiling(Tier::SelfSpend, fee, &outputs)?;\n", "")]),
    ("reclaim ignores the pending cap", [(V, "if self.pending.len() >= MAX_PENDING {\n            return Err(Error::PendingCap);\n        }\n\n        self.supersede(owner);", "self.supersede(owner);")]),
    ("reclaim dust check off", [(V, "if dest_value < dust_limit(ScriptKind::P2wsh) {\n            return Err(Error::DustOutput);\n        }\n        let floor", "let floor")]),
    ("reclaim value check off", [(V, "if value == 0 || value > MAX_MONEY {\n            return Err(Error::BadValue);\n        }\n        let dest_value", "let dest_value")]),
    ("a freeze may end now", [(V, "if until <= now {\n            return Err(Error::FreezeAlreadyOver);\n        }\n", "")]),
    ("sweep keeps old outflow", [(V, "let pending = &self.pending;\n        self.outflow_window.retain(|e| e.counts(pending, now));\n", "")]),
    ("retry window is one block", [(P, "RETRY_AFTER_BLOCKS: u64 = 250;", "RETRY_AFTER_BLOCKS: u64 = 1;")]),
    ("bounds: the fee cap may pass the budget", [(P, "            && p.fee_cap_tx <= p.fee_budget_24h\n", "")]),
    ("loosens ignores t_known", [(P, "self.t_known_ms < old.t_known_ms\n            || ", "")]),
    ("loosens ignores t_new", [(P, "            || self.t_new_ms < old.t_new_ms\n", "")]),
    ("loosens ignores t_new_unguarded", [(P, "            || self.t_new_unguarded_ms < old.t_new_unguarded_ms\n", "")]),
    ("loosens ignores hold", [(P, "            || self.hold_ms < old.hold_ms\n", "")]),
    ("loosens ignores t_stuck", [(P, "            || self.t_stuck_ms < old.t_stuck_ms\n", "")]),
    ("loosens ignores the fee cap", [(P, "            || self.fee_cap_tx > old.fee_cap_tx\n", "")]),
    ("loosens ignores the fee budget", [(P, "            || self.fee_budget_24h > old.fee_budget_24h\n", "")]),
    ("loosens ignores outflow", [(P, "            || self.outflow_cap_24h > old.outflow_cap_24h\n", "")]),
    ("max money off", [(T, "MAX_MONEY: Sats = 2_100_000_000_000_000;", "MAX_MONEY: Sats = 9_000_000_000_000_000_000;")]),
    ("csv ignores the instance's floor", [(V, "args.csv_blocks < args.fixed.csv_min || ", "")]),
    ("csv ignores the instance's ceiling", [(V, " || args.csv_blocks > args.fixed.csv_max", "")]),
    ("test coin csv ceiling is the whole range", [(P, "csv_max: 2_880,", "csv_max: 65_535,")]),
    ("proof vault csv ceiling is the whole range", [(P, "csv_max: 26_280,", "csv_max: 65_535,")]),
    # Section 11, the rules that came with the last methods.
    ("a rotation can hit the grant cap", [(V, "if !rotation && self.grants.len() >= MAX_GRANTS {", "if self.grants.len() >= MAX_GRANTS {")]),
    ("known destinations are unbounded", [(V, "if self.known.len() + waiting >= MAX_KNOWN {", "if false {")]),
    ("a waiting add does not count", [(V, "self.known.len() + waiting >= MAX_KNOWN", "self.known.len() >= MAX_KNOWN")]),
    ("max known is larger", [(P, "MAX_KNOWN: usize = 32;", "MAX_KNOWN: usize = 64;")]),
    ("a memo is never checked", [(V, "if args.memo.as_deref().is_some_and(|m| !memo_ok(m)) {", "if false {")]),
    ("a memo may be any length", [(G, "memo.len() <= MEMO_MAX && ", "")]),
    ("a memo may hold anything", [(G, " && memo.bytes().all(|b| (0x20..=0x7e).contains(&b))", "")]),
    ("quotes go into the prompt raw", [(G, r"""            '"' => out.push_str("\\\""),""" + "\n", "")]),
    ("backslashes go into the prompt raw", [(G, """            '\\\\' => out.push_str("\\\\\\\\"),\n""", "")]),
    ("the prompt streams", [(G, '\\"stream\\":false', '\\"stream\\":true')]),
    ("the prompt has a temperature", [(G, '\\"temperature\\":0', '\\"temperature\\":1')]),
    ("the prompt leaves out the request id", [(G, 'request.id,\n', '0,\n')]),
    ("the prompt leaves out the vault", [(G, 'json_string(vault_hex),\n', 'json_string(""),\n')]),
    ("the prompt leaves out the contract", [(G, 'json_string(contract),\n', 'json_string(""),\n')]),
    ("snapshot: proposals not counted", [(V, "self.proposals.push(now);\n        if plan.tier != Tier::SelfSpend {", "if plan.tier != Tier::SelfSpend {")]),
    ("snapshot: cancels not counted", [(V, "self.cancels.push(now);\n", "")]),
    ("snapshot: destination not noted", [(V, "self.destinations.note(&args.outputs.dest_script, now);\n", "")]),
    ("snapshot: a ring forgets its window", [(V, "now.saturating_sub(**at) < window", "true")]),
    ("snapshot: last spend not recorded", [(V, "self.last_spend_at = now;\n", "")]),
    ("snapshot: key age ignores a rotation", [(V, "self.k_s_since = now;\n", "")]),
    ("snapshot: cancels window is a day", [(V, "self.cancels.count_within(30 * DAY, now)", "self.cancels.count_within(DAY, now)")]),
    ("snapshot: proposals window is a month", [(V, "self.proposals.count_within(DAY, now)", "self.proposals.count_within(30 * DAY, now)")]),
    ("snapshot: share is of the wrong thing", [(V, "u128::from(outputs.dest_value) * 10_000", "u128::from(outputs.total()) * 10_000")]),
    ("snapshot: memo dropped", [(V, "            memo,\n        }\n    }\n\n    /// The panic button", "            memo: None,\n        }\n    }\n\n    /// The panic button")]),
    ("assess records no hold", [(V, "request.assess_hold = hold;\n", "")]),
    ("assess records no reason", [(V, "request.assess_reason = reason;\n", "")]),
    ("assess sets no flag", [(V, "request.assessed = true;\n", "")]),
    ("a reason outside the list passes", [(G, ".map(|(r, _)| *r)", ".map(|(r, _)| *r).or(Some(Reason::Other))")]),
    ("status: a failed answer goes unrecorded", [(V, "self.sign_failed_at = now;\n", "")]),
    ("status: a good answer does not clear it", [(V, "self.sign_failed_at = 0;\n", "")]),
    ("status: stale guard reads online", [(S, "if now.saturating_sub(beat) <= HEARTBEAT_STALE_MS", "if true")]),
    ("status: waiting grants are hidden", [(S, "for grant in &self.grants {", "for grant in self.grants.iter().take(0) {")]),
    ("status: a used budget is hidden", [(S, "if budget_left < self.policy.fee_cap_tx {", "if false {")]),
    # The fifth review. What the page and a person read, and the rules that had no test.
    ("status: the budget line waits until it is all gone", [(S, "if budget_left < self.policy.fee_cap_tx {", "if budget_left == 0 {")]),
    ("status: says a key lands when none is waiting", [(S, 'let next = if waiting {', 'let next = if true {')]),
    ("status: says no key is waiting when one is", [(S, 'let next = if waiting {', 'let next = if false {')]),
    ("status: any grant reads as a key waiting", [(S, "let waiting = self.grants.iter().any(|g| matches!(g.kind, GrantKind::RotateSpend { .. }));", "let waiting = !self.grants.is_empty();")]),
    ("status: funds movable while frozen", [(S, "if self.active && !self.is_frozen(now) && !self.k_s_suspended {", "if self.active && !self.k_s_suspended {")]),
    ("status: funds movable while suspended", [(S, "if self.active && !self.is_frozen(now) && !self.k_s_suspended {", "if self.active && !self.is_frozen(now) {")]),
    ("status: funds movable while inactive", [(S, "if self.active && !self.is_frozen(now) && !self.k_s_suspended {", "if !self.is_frozen(now) && !self.k_s_suspended {")]),
    ("status: the last spend is hidden", [(S, "if self.last_spend_at != 0 {", "if false {")]),
    ("status: a spend during a suspension reads calm", [(S, "let before_rotation = self.k_s_suspended || (", "let before_rotation = (")]),
    ("status: a spend before a landing reads calm", [(S, "let before_rotation = self.k_s_suspended || (self.k_s_since > self.created_at && self.last_spend_at <= self.k_s_since);", "let before_rotation = self.k_s_suspended;")]),
    ("status: every spend calls for attention", [(S, "(self.k_s_since > self.created_at && self.last_spend_at <= self.k_s_since)", "(self.k_s_since > self.created_at)")]),
    ("status: the owner's first spend calls for attention", [(S, "(self.k_s_since > self.created_at && self.last_spend_at <= self.k_s_since)", "(self.last_spend_at <= self.k_s_since || self.k_s_since == self.created_at)")]),
    ("status: the warning outlasts its day", [(S, "now.saturating_sub(self.last_spend_at) < DAY", "now.saturating_sub(self.last_spend_at) <= DAY")]),
    ("status: frozen reads forever", [(S, "if self.is_frozen(now) {", "if self.frozen_until.is_some() {")]),
    ("status: pending count includes dead", [(S, ".filter(|id| self.is_live(**id, now))\n", "")]),
    ("check_propose ignores a suspended key", [(V, "if scratch.k_s_suspended {\n            return Err(Error::SpendKeySuspended);\n        }\n", "")]),
    ("a rotation counts no cancels", [(V, "for _ in self.live_pending(now) {\n            self.cancels.push(now);\n        }\n", "")]),
    ("a rotation counts one cancel, however many it stopped", [(V, "for _ in self.live_pending(now) {\n            self.cancels.push(now);\n        }\n", "if !self.live_pending(now).is_empty() {\n            self.cancels.push(now);\n        }\n")]),
    ("bounds: test fee floor gone", [(P, "fee_cap_tx: 500,\n                fee_budget_24h: 1_000,\n", "fee_cap_tx: 0,\n                fee_budget_24h: 0,\n")]),
    ("bounds: test known floor gone", [(P, "t_known_ms: 30_000,", "t_known_ms: 0,")]),
    ("bounds: test new floor gone", [(P, "t_new_ms: MINUTE,\n                t_new_unguarded_ms: MINUTE,", "t_new_ms: 0,\n                t_new_unguarded_ms: MINUTE,")]),
    ("bounds: new may exceed unguarded", [(P, "&& p.t_new_ms <= p.t_new_unguarded_ms\n", "\n")]),
    ("template p2tr accepts another version", [(T, "[0x51, 0x20, rest @ ..] if rest.len() == 32 => Some(ScriptKind::P2tr),", "[_, 0x20, rest @ ..] if rest.len() == 32 => Some(ScriptKind::P2tr),")]),
    ("reclaim pays no rate floor", [(V, "let floor = estimate_vsize(1, &outputs).saturating_mul(MIN_FEE_RATE);\n        if fee < floor {\n            return Err(Error::FeeRateTooLow { fee, floor });\n        }\n", "")]),
    ("nine grants fit", [(P, "MAX_GRANTS: usize = 8;", "MAX_GRANTS: usize = 9;")]),
    ("recover_cancel with none running burns the cap", [(V, "if self.recovery.is_none() {\n            return Err(Error::NoRecovery);\n        }\n", "")]),
    ("upgrade: two at once", [(U, "if self.pending.is_some_and(|p| now <= p.expires_at) {", "if false {")]),
    ("upgrade: hash not compared", [(U, "if code_hash != pending.code_hash {", "if false {")]),
    ("upgrade: lands early", [(U, "if now < pending.unlock_at {", "if false {")]),
    ("upgrade: never runs out", [(U, "if now > pending.expires_at {", "if false {")]),
    ("upgrade: runs out at its last moment", [(U, "if now > pending.expires_at {", "if now >= pending.expires_at {")]),
    ("upgrade: the approval can be used twice", [(U, "self.pending = None;\n        Ok(pending)", "Ok(pending)")]),
    ("upgrade: no expiry added", [(U, "unlock_at.saturating_add(rules.expiry_ms)", "unlock_at")]),
    ("upgrade: test coin T_upgrade is short", [(U, "t_upgrade_ms: HOUR, expiry_ms: HOUR", "t_upgrade_ms: 10 * MINUTE, expiry_ms: HOUR")]),
    ("upgrade: proof vault T_upgrade is short", [(U, "t_upgrade_ms: 14 * DAY", "t_upgrade_ms: 1 * DAY")]),
    ("upgrade: holds always", [(U, "self.reaction_window_ms(bounds) >= self.min_reaction_ms", "true")]),
    ("longest withdrawal leaves out the hold", [(P, ".saturating_add(m.hold_ms)\n", "\n")]),
    # Round 5, the authorization audit: the outflow window and what status says.
    ("outflow: a pending request's reservation ages out", [(V, "pending.contains(&self.request) || now < self.at.saturating_add(DAY)", "now < self.at.saturating_add(DAY)")]),
    ("outflow: an entry never leaves", [(V, "pending.contains(&self.request) || now < self.at.saturating_add(DAY)", "pending.contains(&self.request) || now == now")]),
    ("outflow: the cap reads entries past their day", [(V, ".filter(|e| e.counts(&self.pending, now))", ".filter(|_| true)")]),
    ("outflow: execute does not move the entry", [(V, "let attempt = request.attempt;\n        self.stamp_outflow(id, now);\n", "let attempt = request.attempt;\n")]),
    ("outflow: the last signature does not move the entry", [(V, "            self.stamp_outflow(id, now);\n        }\n        SignedOutcome::Stored", "        }\n        SignedOutcome::Stored")]),
    ("outflow: a stamp moves every entry", [(V, "for entry in self.outflow_window.iter_mut().filter(|e| e.request == id) {", "let _ = id;\n        for entry in self.outflow_window.iter_mut() {")]),
    ("outflow: retries never close", [(V, "if now >= closed_at {", "if false {")]),
    ("outflow: retries close a moment late", [(V, "if now >= closed_at {", "if now > closed_at {")]),
    ("outflow: self-spend retries close too", [(V, "if request.tier != Tier::SelfSpend {\n                    let mut closed_at", "if true {\n                    let mut closed_at")]),
    ("outflow: retries close a day after propose", [(V, "request.first_execute_at.unwrap_or(now)", "Some(request.proposed_at).unwrap_or(now)")]),
    # Round 5, the confirmation's new problems: an entry an earlier build left, and the two lines that
    # promised retries the window refuses.
    ("outflow: a retry runs once an earlier build's entry has left", [(V, "if now < closed_at && !self.outflow_window.iter().any(|e| e.request == id) {", "if false {")]),
    ("outflow: an entry that left early reads as closing now", [(V, "closed_at = request.proposed_at.saturating_add(DAY).min(now);", "closed_at = now;")]),
    ("status: the retry window names another length", [(S, "for at most {} after its first execute\", span_text(DAY))", "for at most {} after its first execute\", span_text(2 * DAY))")]),
    ("status: the suspended line says an executed request keeps signing", [(S, "requests not yet executed are dead. One already executed can still ask the signer for its missing signatures, {retry}, after which its coins come back by reclaim with a new key: {next}", "requests not yet executed are dead, one already executed keeps signing, and {next}")]),
    ("status: the signer line says any request can retry", [(S, "a request still signing can retry, {retry}, after which its coins come back by reclaim, {reclaim}, and a coin", "a request still signing can retry, and a coin")]),
    ("status: the signer line offers reclaim to a suspended key", [(S, "let reclaim = if self.k_s_suspended {", "let reclaim = if false {")]),
    ("status: reclaims spaced by the unguarded delay", [(S, 'format!("at most one per {}", span_text(self.policy.t_new_ms))', 'format!("at most one per {}", span_text(self.policy.t_new_unguarded_ms))')]),
    ("status: the delays the wrong way round", [(S, 'format!("new-destination delay {} instead of {}", span_text(unguarded), span_text(guarded))', 'format!("new-destination delay {} instead of {}", span_text(guarded), span_text(unguarded))')]),
    ("status: equal delays read as a slowdown", [(S, "if unguarded == guarded {", "if false {")]),
    ("status: a duration drops its seconds", [(S, "if rest > 0 || parts.is_empty() {", "if parts.is_empty() {")]),
    ("status: the recovery line ignores a freeze", [(S, "let held = if self.is_frozen(now) {", "let held = if false {")]),
    ("status: the freeze line names grants only", [(S, "no passkey action except cancel, which has nothing to stop because the freeze ended every pending request", "no passkey grants")]),
]

ROOT = """[workspace]
resolver = "2"
members = ["crates/undo-core"]
[workspace.package]
version = "0.0.1"
edition = "2021"
license = "MIT"
authors = ["mutant"]
publish = false
"""

def main():
    only = sys.argv[1] if len(sys.argv) > 1 else None
    tmp = tempfile.mkdtemp(prefix="undo-core-mutants-")
    crate = os.path.join(tmp, "crates", "undo-core")
    os.makedirs(os.path.join(crate, "props"))
    with open(os.path.join(tmp, "Cargo.toml"), "w") as f:
        f.write(ROOT)
    shutil.copy(os.path.join(CRATE, "Cargo.toml"), crate)
    shutil.copytree(os.path.join(CRATE, "src"), os.path.join(crate, "src"))
    for name in ("Cargo.toml", "Cargo.lock"):
        shutil.copy(os.path.join(HERE, name), os.path.join(crate, "props"))
    for name in ("src", "tests"):
        shutil.copytree(os.path.join(HERE, name), os.path.join(crate, "props", name))
    env = dict(os.environ, PROPTEST_CASES="2000", RUST_BACKTRACE="0")
    # A control first. A suite that is already red would read every mutant as killed.
    tests = ["cargo", "test", "--no-fail-fast", "--test", "scenarios", "--test", "round5", "--test", "no_unlock_before_base", "--test", "no_fee_combination", "--test", "chain_bound"]
    baseline = subprocess.run(tests, cwd=os.path.join(crate, "props"), env=env, capture_output=True, text=True)
    if baseline.returncode != 0:
        print("BASELINE FAILED: the unmutated suite is not green, so no mutant result means anything")
        print((baseline.stdout + baseline.stderr)[-2000:])
        shutil.rmtree(tmp, ignore_errors=True)
        return 2
    print("baseline green", flush=True)
    survived, broken = [], []
    for name, edits in MUTANTS:
        if only and only not in name:
            continue
        originals = {}
        applied = True
        for rel, old, new in edits:
            path = os.path.join(crate, rel)
            text = open(path).read()
            originals.setdefault(path, text)
            if old not in text:
                applied = False
                break
            with open(path, "w") as f:
                f.write(text.replace(old, new))
        killers = []
        reason = ""
        if applied:
            run = subprocess.run(tests, cwd=os.path.join(crate, "props"), env=env, capture_output=True, text=True)
            output = run.stdout + run.stderr
            if "could not compile" in output:
                applied = False
                reason = "does not compile"
            elif run.returncode != 0 and "--test " not in output:
                # A run that never reached the tests proves nothing, so it must not read as survived.
                applied = False
                reason = "cargo did not run the tests"
            killers = sorted(set(re.findall(r"`--test (\w+)`", output)))
            hit = re.search(r'Fail\(Reason\("([^"]{0,70})', output)
            if hit:
                reason = hit.group(1)
        for path, text in originals.items():
            with open(path, "w") as f:
                f.write(text)
        if not applied:
            broken.append(name)
            print(f"NOT APPLIED  {name}  {reason}", flush=True)
        elif killers:
            print(f"KILLED       {name}  by {', '.join(killers)}  {reason}", flush=True)
        else:
            survived.append(name)
            print(f"SURVIVED     {name}", flush=True)
    shutil.rmtree(tmp, ignore_errors=True)
    print(f"\nsurvived: {len(survived)}, not applied: {len(broken)}")
    return 1 if survived or broken else 0

if __name__ == "__main__":
    sys.exit(main())
