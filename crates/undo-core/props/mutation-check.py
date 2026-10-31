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
    ("clear_hold goes below base", [(V, "request.unlock = request.base_unlock;\n        request.expires_at", "request.unlock = request.base_unlock.saturating_sub(1_000);\n        request.expires_at")]),
    ("hold adds nothing", [(V, "request.unlock = request.base_unlock.saturating_add(hold_ms);", "")]),
    ("bump takes a fresh base", [(V, "            now,\n            old.base_unlock,\n", "            now,\n            now,\n")]),
    ("bump ignores its wait", [(V, "if now < ready_at {\n            return Err(Error::BumpTooSoon { ready_at });", "if false {\n            return Err(Error::BumpTooSoon { ready_at });")]),
    ("bump charges the whole fee", [(V, "let charge = request.fee.saturating_sub(request.fee_prepaid);", "let charge = request.fee;")]),
    ("old epoch still executes", [
        (V, "(request.epoch != self.spend_epoch || now > request.expires_at)", "(now > request.expires_at)"),
        (V, "if request.epoch != self.spend_epoch {", "if false {"),
    ]),
    ("expired request still executes", [(V, "(request.epoch != self.spend_epoch || now > request.expires_at)", "(request.epoch != self.spend_epoch)")]),
    ("expiry race lost at the exact block", [(V, "|| now > request.expires_at)", "|| now >= request.expires_at)")]),
    ("freeze does not block execute", [(V, "self.require_not_frozen(now)?;\n        if max_inputs == 0", "if max_inputs == 0")]),
    ("freeze does not bump the epoch", [(V, "self.frozen_until = Some(until);\n        self.bump_epoch();", "self.frozen_until = Some(until);")]),
    ("freeze keeps pending grants", [(V, "self.bump_epoch();\n        self.grants.clear();", "self.bump_epoch();")]),
    ("freeze may outlast CSV", [(V, "if until > max_until || until <= now {", "if until <= now {")]),
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
    ("bump keeps the old request", [(V, "self.requests.remove(&old_id);\n", "")]),
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
            run = subprocess.run(
                ["cargo", "test", "--no-fail-fast", "--test", "scenarios", "--test", "no_unlock_before_base", "--test", "no_fee_combination", "--test", "chain_bound"],
                cwd=os.path.join(crate, "props"), env=env, capture_output=True, text=True)
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
