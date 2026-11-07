//! Round 5, the authorization audit's contract findings. Each test here failed on the build before it.
//!
//! C1: a known destination's 24 h cap counted from propose time, while a request stays executable until
//! its expiry, a day after unlock on the proof preset. So two full caps could reach signing within
//! `T_known` of each other. Outflow now counts while its request is pending, and for a day after the
//! last time execute asked the signer for it or its last signature landed. From a day after a paying
//! request's first execute, execute asks the signer for nothing more for it, so nothing is asked for
//! outside a window that a later proposal was checked against.
//!
//! C2: the guard line said "doubled" whatever the vault's policy was. C3: the freeze line named only
//! grants as blocked, and the recovery line counted cancels a freeze does not let the passkey use.
//!
//! The confirmation's new problems, at the end: two status lines still promised retries the window
//! refuses, and a request executed before an upgrade could retry after its propose-time entry had left.

mod common;

use common::*;
use undo_core::*;

const FEE: Sats = 1_000;

/// Adds `dest` through the passkey grant and lands it.
fn known(h: &mut H, dest: &[u8]) {
    let grant = h.add_dest(dest).unwrap();
    h.advance(h.v.policy.t_new_ms);
    h.apply(grant).unwrap();
}

fn tier_of(h: &H, coin: Outpoint, dest: &[u8], amount: Sats) -> Tier {
    let inputs = [Input { outpoint: coin, value: amount + FEE }];
    let outputs = Outputs { dest_script: dest.to_vec(), dest_value: amount, change_value: None };
    h.v.check_propose(&inputs, &outputs, h.now).unwrap().tier
}

fn text_of(h: &H) -> String {
    h.v.status_lines(h.now).1.join("\n")
}

fn vault_with(policy: Policy, fixed: Fixed, bounds: Bounds) -> H {
    let mut v = Vault::create(create_args(policy, fixed, bounds, p2wsh(0x77))).unwrap();
    v.activate(&k_m()).unwrap();
    H::new(v)
}

// ------------------------------------------------------------------ C1: outflow window

/// The audit's mainnet case. R1 takes the whole cap and is still pending a day later, because the
/// proof preset's expiry window is a day. Before the fix its reservation dropped out at propose + 24 h
/// and R2 read Known, so both signed five minutes apart.
#[test]
fn a_pending_request_holds_its_outflow_for_as_long_as_it_lives() {
    let mut h = H::mainnet();
    let dest = p2wpkh(0x55);
    known(&mut h, &dest);
    let cap = h.v.policy.outflow_cap_24h;
    let r1 = h.propose(&[(op(1), cap + FEE)], &dest, cap, None).unwrap();
    assert_eq!(r1.tier, Tier::Known);
    assert_eq!(r1.expires_at, r1.base_unlock + DAY, "the proof preset keeps it a day past unlock");

    h.advance(DAY);
    assert!(h.v.is_live(r1.id, h.now), "R1 is neither cancelled nor expired");
    assert_eq!(h.v.outflow_used_24h(h.now), cap, "so its reservation stands");
    assert_eq!(tier_of(&h, op(2), &dest, cap), Tier::New, "check_propose says the same as propose");
    let r2 = h.propose(&[(op(2), cap + FEE)], &dest, cap, None).unwrap();
    assert_eq!(r2.tier, Tier::New, "a second cap waits T_new while the first is reserved");
    assert_eq!(r2.base_unlock, h.now + h.v.policy.t_new_unguarded_ms);
    h.cancel(r2.id).unwrap();
    assert_eq!(h.v.outflow_used_24h(h.now), cap, "the cancel released R2 only");

    // R1 signs at its last live moment. Its outflow counts for a day from there.
    h.advance(r1.expires_at - h.now);
    h.execute_all_signed(r1.id);
    let signed = h.now;
    h.advance(DAY - 1);
    assert_eq!(tier_of(&h, op(3), &dest, cap), Tier::New, "one millisecond short of a day after the signature");
    h.advance(1);
    assert_eq!(tier_of(&h, op(3), &dest, cap), Tier::Known, "a day after it");
    assert_eq!(h.now, signed + DAY);
}

/// The audit's test-coin case: the expiry window is 1 h, so R1 signs at T0 + 61 min and a second cap
/// read Known at T0 + 24 h, two caps 23 h apart.
#[test]
fn an_executed_request_counts_for_a_day_from_its_signature_on_test_coins() {
    let mut h = H::test_coin();
    let dest = p2wpkh(0x56);
    known(&mut h, &dest);
    let cap = h.v.policy.outflow_cap_24h;
    let r1 = h.propose(&[(op(1), cap + FEE)], &dest, cap, None).unwrap();
    assert_eq!(r1.tier, Tier::Known);
    let t0 = h.now;
    h.advance(r1.expires_at - h.now);
    h.execute_all_signed(r1.id);
    let signed = h.now;
    assert_eq!(signed, t0 + h.v.policy.t_known_ms + h.v.fixed.expiry_window_ms);

    h.advance(t0 + DAY - h.now);
    let r2 = h.propose(&[(op(2), cap + FEE)], &dest, cap, None).unwrap();
    assert_eq!(r2.tier, Tier::New, "R1 signed 23 h ago, inside the day");
    h.cancel(r2.id).unwrap();
    h.advance(signed + DAY - 1 - h.now);
    assert_eq!(tier_of(&h, op(3), &dest, cap), Tier::New);
    h.advance(1);
    assert_eq!(tier_of(&h, op(3), &dest, cap), Tier::Known);
}

/// The reviewer's extension: a guard hold adds `hold_ms` to a request's expiry, and the mainnet bounds
/// allow a 24 h hold. Before the fix one held R1 gave three caps at once.
#[test]
fn a_hold_cannot_stretch_the_cap() {
    let mut h = H::mainnet();
    let dest = p2wpkh(0x57);
    known(&mut h, &dest);
    let longer = Policy { hold_ms: 24 * HOUR, ..h.v.policy };
    assert_eq!(h.set_policy(longer).unwrap(), PolicyOutcome::Applied, "a longer hold is a tightening");
    let cap = h.v.policy.outflow_cap_24h;
    let r1 = h.propose(&[(op(1), cap + FEE)], &dest, cap, None).unwrap();
    h.assess(r1.id, true).unwrap();
    let held = h.v.requests[&r1.id].clone();
    assert_eq!(held.expires_at, r1.expires_at + 24 * HOUR);

    h.advance(DAY);
    let r2 = h.propose(&[(op(2), cap + FEE)], &dest, cap, None).unwrap();
    assert_eq!(r2.tier, Tier::New);
    h.advance(DAY);
    assert!(h.v.is_live(r1.id, h.now));
    let r3 = h.propose(&[(op(3), cap + FEE)], &dest, cap, None).unwrap();
    assert_eq!(r3.tier, Tier::New);
    assert_eq!(h.v.outflow_used_24h(h.now), 3 * cap, "all three reserved, and only R1 had the Known wait");
}

/// The code-trace claim: the documented default keeps a request seven days past unlock, so the pending
/// cap of three, not the outflow cap, bounded what could sign at once. Not a deployed preset.
#[test]
fn a_week_long_expiry_cannot_queue_three_caps() {
    let fixed = Fixed { expiry_window_ms: 7 * DAY, ..Fixed::mainnet_proof() };
    let mut h = vault_with(Policy::mainnet_proof(OUTFLOW_CAP), fixed, Bounds::mainnet(OUTFLOW_CAP));
    let dest = p2wpkh(0x58);
    known(&mut h, &dest);
    let cap = h.v.policy.outflow_cap_24h;
    let mut tiers = vec![];
    for i in 1..=MAX_PENDING as u8 {
        tiers.push(h.propose(&[(op(i), cap + FEE)], &dest, cap, None).unwrap());
        h.advance(DAY);
    }
    assert_eq!(tiers.iter().map(|p| p.tier).collect::<Vec<_>>(), vec![Tier::Known, Tier::New, Tier::New]);
    assert!(tiers.iter().all(|p| h.v.is_live(p.id, h.now)), "all three still pending");
}

/// Execute is the point of no return, and a request can take its signatures in several calls. Each one
/// moves the outflow's time to now. Execute asks for none for a request that pays out from a day after
/// its first execute, so a half-signed spend cannot finish inside the window of a request proposed after
/// its entry left.
#[test]
fn a_half_signed_spend_counts_from_its_last_signature_request_and_closes_a_day_after_its_first() {
    let mut h = H::test_coin();
    let dest = p2wpkh(0x59);
    known(&mut h, &dest);
    let cap = h.v.policy.outflow_cap_24h;
    let r1 = h.propose(&[(op(1), cap), (op(2), FEE)], &dest, cap, None).unwrap();
    assert_eq!(r1.tier, Tier::Known);
    h.advance(r1.base_unlock - h.now);
    let first = h.execute(r1.id, 1).unwrap();
    h.sign_batch(r1.id, &first);
    let opened = h.now;

    // The window is still open one millisecond before a day: a retry signs, and its time counts.
    let mut late = h.clone();
    late.advance(DAY - 1);
    assert_eq!(tier_of(&late, op(3), &dest, cap), Tier::New, "the first execute still counts");
    let rest = late.execute(r1.id, 1).unwrap();
    assert_eq!(rest.indices, vec![1]);
    let asked = late.now;
    late.advance(DAY - 1);
    assert_eq!(tier_of(&late, op(3), &dest, cap), Tier::New, "a day from the retry, not from the first execute");
    late.sign_batch(r1.id, &rest);
    assert_eq!(late.v.requests[&r1.id].status, RequestStatus::Signed);
    late.advance(DAY - 1);
    assert_eq!(tier_of(&late, op(3), &dest, cap), Tier::New, "a day from the last signature, which landed later");
    late.advance(1);
    assert_eq!(tier_of(&late, op(3), &dest, cap), Tier::Known);
    assert!(late.now > asked + DAY);

    // At a day the window has closed. The entry has gone, a full cap reads Known, and R1 cannot finish.
    h.advance(DAY);
    let refused = h.execute(r1.id, 1).unwrap_err();
    assert_eq!(format!("{refused:?}"), format!("RetryWindowClosed {{ closed_at: {} }}", opened + DAY));
    assert_eq!(tier_of(&h, op(3), &dest, cap), Tier::Known);
    let r2 = h.propose(&[(op(3), cap + FEE)], &dest, cap, None).unwrap();
    h.advance(r2.base_unlock - h.now);
    h.execute_all_signed(r2.id);
    assert!(h.execute(r1.id, 16).is_err(), "still closed after R2 signs");
    assert_eq!(h.v.requests[&r1.id].sigs.iter().filter(|s| s.is_some()).count(), 1, "R1 stays half signed");
    // Reclaim is still the way out for the half-signed coin.
    h.advance(h.v.policy.t_new_ms);
    h.reclaim(op(1), cap, FEE).unwrap();
}

/// A signature answer can land well after its execute. The day counts from the answer that completes
/// the request, so a slow signer cannot bring the window forward.
#[test]
fn the_window_counts_from_the_last_signature_to_land() {
    let mut h = H::test_coin();
    let dest = p2wpkh(0x5a);
    known(&mut h, &dest);
    let cap = h.v.policy.outflow_cap_24h;
    let r1 = h.propose(&[(op(1), cap + FEE)], &dest, cap, None).unwrap();
    h.advance(r1.base_unlock - h.now);
    let batch = h.execute(r1.id, 1).unwrap();
    h.advance(HOUR);
    h.sign_batch(r1.id, &batch);
    let landed = h.now;
    assert_eq!(h.v.requests[&r1.id].signed_at, Some(landed));
    h.advance(DAY - 1);
    assert_eq!(tier_of(&h, op(2), &dest, cap), Tier::New, "a day from the answer, not from execute");
    h.advance(1);
    assert_eq!(tier_of(&h, op(2), &dest, cap), Tier::Known);
}

/// Each request's entry moves alone. A spend at noon does not keep one from midnight in the window.
#[test]
fn an_execute_moves_only_its_own_entry() {
    let mut h = H::test_coin();
    let dest = p2wpkh(0x5b);
    known(&mut h, &dest);
    let half = h.v.policy.outflow_cap_24h / 2;
    let a = h.propose(&[(op(1), half + FEE)], &dest, half, None).unwrap();
    h.advance(a.base_unlock - h.now);
    h.execute_all_signed(a.id);
    let a_signed = h.now;
    h.advance(12 * HOUR);
    let b = h.propose(&[(op(2), half + FEE)], &dest, half, None).unwrap();
    assert_eq!(b.tier, Tier::Known, "two halves fit");
    h.advance(b.base_unlock - h.now);
    h.execute_all_signed(b.id);
    h.advance(a_signed + DAY - h.now);
    assert_eq!(h.v.outflow_used_24h(h.now), half, "only the noon spend is left");
    assert_eq!(tier_of(&h, op(3), &dest, half), Tier::Known);
}

/// Self-spends carry no outflow, so their retries are not closed. A reclaim is one.
#[test]
fn a_self_spend_can_still_retry_after_a_day() {
    let mut h = H::test_coin();
    let r = h.self_spend(&[(op(1), COIN_5), (op(2), COIN_5)], FEE).unwrap();
    h.advance(r.base_unlock - h.now);
    let first = h.execute(r.id, 1).unwrap();
    h.sign_batch(r.id, &first);
    h.advance(2 * DAY);
    let rest = h.execute(r.id, 1).unwrap();
    h.sign_batch(r.id, &rest);
    assert_eq!(h.v.requests[&r.id].status, RequestStatus::Signed);
}

const COIN_5: Sats = 500_000;

/// Deleting a request does not delete what it may already have signed. A reclaim supersedes a Signed
/// request, and `prune_signed` deletes one after the expiry window. Its outflow still counts for the
/// rest of its day, and only a pending request's reservation goes with it.
#[test]
fn a_superseded_or_pruned_spend_still_counts_for_its_day() {
    let mut h = H::test_coin();
    let dest = p2wpkh(0x5c);
    known(&mut h, &dest);
    let cap = h.v.policy.outflow_cap_24h;
    let r1 = h.propose(&[(op(1), cap + FEE)], &dest, cap, None).unwrap();
    h.advance(r1.base_unlock - h.now);
    h.execute_all_signed(r1.id);
    let signed = h.now;

    let mut pruned = h.clone();
    pruned.advance(pruned.v.fixed.expiry_window_ms);
    let now = pruned.now;
    pruned.v.prune_signed(r1.id, now).unwrap();
    assert!(!pruned.v.requests.contains_key(&r1.id));
    assert_eq!(pruned.v.outflow_used_24h(pruned.now), cap);
    assert_eq!(tier_of(&pruned, op(2), &dest, cap), Tier::New);
    pruned.advance(signed + DAY - pruned.now);
    assert_eq!(tier_of(&pruned, op(2), &dest, cap), Tier::Known);

    h.advance(h.v.policy.t_stuck_ms);
    h.reclaim(op(1), cap + FEE, FEE).unwrap();
    assert!(!h.v.requests.contains_key(&r1.id), "superseded");
    assert_eq!(h.v.outflow_used_24h(h.now), cap, "a reclaim moves nothing out and releases nothing");
    h.advance(signed + DAY - 1 - h.now);
    assert_eq!(tier_of(&h, op(2), &dest, cap), Tier::New);
    h.advance(1);
    assert_eq!(tier_of(&h, op(2), &dest, cap), Tier::Known);
}

/// A rotation and a freeze kill pending requests, which releases their reservations. A request past its
/// first execute, inside its retry window, keeps signing through both, so its outflow keeps counting.
#[test]
fn a_rotation_or_freeze_releases_pending_outflow_and_keeps_what_is_signing() {
    let mut h = H::test_coin();
    let dest = p2wpkh(0x5d);
    known(&mut h, &dest);
    let half = h.v.policy.outflow_cap_24h / 2;
    let signing = h.propose(&[(op(1), half + FEE)], &dest, half, None).unwrap();
    h.advance(signing.base_unlock - h.now);
    h.execute(signing.id, 1).unwrap();
    h.propose(&[(op(2), half + FEE)], &dest, half, None).unwrap();
    assert_eq!(h.v.outflow_used_24h(h.now), 2 * half);

    let mut frozen = h.clone();
    let until = frozen.now + frozen.v.csv_period_ms();
    frozen.freeze(until).unwrap();
    frozen.advance(until - frozen.now);
    assert_eq!(tier_of(&frozen, op(3), &dest, half), Tier::Known, "the frozen pending one is gone, the signing one stays");
    assert_eq!(tier_of(&frozen, op(3), &dest, half + 1), Tier::New);

    h.rotate(SPEND_2).unwrap();
    h.advance(h.v.policy.t_known_ms);
    h.apply(h.v.grants[0].id).unwrap();
    assert_eq!(h.v.outflow_used_24h(h.now), half, "swept by the landing");
    assert_eq!(h.v.outflow_window_entries(), 1);
}

// ------------------------------------------------------------------ C2: what a dead guard does

/// The guard line prints the delays the vault really has. Equal delays are allowed, and so are other
/// ratios than two, so "doubled" was false for some vaults.
#[test]
fn the_guard_line_names_the_real_delays() {
    let mut h = H::test_coin();
    assert!(text_of(&h).contains("guard offline, no heartbeat yet: new-destination delay 10 min instead of 5 min, funds movable"), "{}", text_of(&h));
    h.heartbeat().unwrap();
    let beat = h.now;
    h.advance(HEARTBEAT_STALE_MS + 1);
    assert!(text_of(&h).contains(&format!("guard offline since {}: new-destination delay 10 min instead of 5 min, funds movable", utc_text(beat))));
    h.v.guard = None;
    assert!(text_of(&h).contains("no guard: new-destination delay 10 min instead of 5 min, funds movable"));

    // The audit's case: the bounds allow the same delay with and without a guard.
    let equal = Policy { t_new_unguarded_ms: 5 * MINUTE, ..Policy::test_coin(OUTFLOW_CAP) };
    let h = vault_with(equal, Fixed::test_coin(), Bounds::test_coin(OUTFLOW_CAP));
    assert_eq!(h.v.delay_now(h.now), h.v.policy.t_new_ms, "nothing slowed down");
    let text = text_of(&h);
    assert!(text.contains("guard offline, no heartbeat yet: new-destination delay 5 min, the same as with a guard online, funds movable"), "{text}");
    assert!(!text.contains("doubled"));

    // Ten times on test coins, and the proof preset's widest.
    let tenfold = Policy { t_known_ms: 30_000, t_new_ms: MINUTE, ..Policy::test_coin(OUTFLOW_CAP) };
    let h = vault_with(tenfold, Fixed::test_coin(), Bounds::test_coin(OUTFLOW_CAP));
    assert!(text_of(&h).contains("new-destination delay 10 min instead of 1 min"), "{}", text_of(&h));
    let widest = Policy { t_new_ms: 24 * HOUR, t_new_unguarded_ms: 48 * HOUR, ..Policy::mainnet_proof(OUTFLOW_CAP) };
    let h = vault_with(widest, Fixed::mainnet_proof(), Bounds::mainnet(OUTFLOW_CAP));
    assert!(text_of(&h).contains("new-destination delay 48 h instead of 24 h"), "{}", text_of(&h));
    let odd = Policy { t_new_ms: 10 * MINUTE + 1_500, t_new_unguarded_ms: HOUR + 30 * 1_000, ..Policy::mainnet_proof(OUTFLOW_CAP) };
    let h = vault_with(odd, Fixed::mainnet_proof(), Bounds::mainnet(OUTFLOW_CAP));
    assert!(text_of(&h).contains("new-destination delay 1 h 30 s instead of 10 min 1.5 s"), "{}", text_of(&h));
}

// ------------------------------------------------------------------ C3: what a freeze blocks

const FROZEN_LINE: &str = "by the cold key: no proposals, reclaims or execute, and no passkey action except cancel, which has nothing to stop because the freeze ended every pending request. Only the cold key can lift it early, and the cold-key exit is unaffected";

/// The line says what the rules do. Every passkey action but cancel is refused, and cancel finds
/// nothing, because the freeze killed every pending request and nothing new can be proposed.
#[test]
fn the_freeze_line_says_exactly_what_is_blocked() {
    let mut h = H::test_coin();
    let dest = p2wpkh(0x5e);
    known(&mut h, &dest);
    let r = h.propose(&[(op(1), COIN_5)], &dest, COIN_5 - FEE, None).unwrap();
    let until = h.now + h.v.csv_period_ms();
    h.freeze(until).unwrap();
    let text = text_of(&h);
    assert!(text.contains(&format!("frozen until {} {FROZEN_LINE}", utc_text(until))), "{text}");

    let frozen = Error::Frozen { until };
    let tighter = Policy { fee_budget_24h: h.v.policy.fee_budget_24h - 1, ..h.v.policy };
    assert_eq!(h.set_policy(tighter).unwrap_err(), frozen, "even a tightening");
    assert_eq!(h.remove_dest(&dest).unwrap_err(), frozen, "even a removal");
    assert_eq!(h.rotate(SPEND_2).unwrap_err(), frozen);
    assert_eq!(h.raise_fee_cap(r.id, 100).unwrap_err(), frozen);
    assert_eq!(h.clear_hold(r.id).unwrap_err(), frozen);
    assert_eq!(h.recover_cancel().unwrap_err(), frozen);
    assert_eq!(h.propose(&[(op(2), COIN_5)], &dest, COIN_5 - FEE, None).unwrap_err(), frozen);
    assert_eq!(h.reclaim(op(1), COIN_5, FEE).unwrap_err(), frozen);
    assert_eq!(h.execute(r.id, 16).unwrap_err(), frozen);
    assert_eq!(h.cancel(r.id).unwrap_err(), Error::RequestNotFound, "cancel runs, and finds nothing");
    assert!(h.v.live_pending(h.now).is_empty());
    h.unfreeze().unwrap();
    assert!(!text_of(&h).contains("frozen until"));
}

/// While frozen the passkey cannot cancel a recovery, so the recovery line says so.
#[test]
fn the_recovery_line_says_a_freeze_holds_the_passkeys_cancels() {
    let mut h = H::test_coin();
    h.recover_begin(passkey(0x41)).unwrap();
    assert!(text_of(&h).contains("The current passkey has 2 of 2 cancels left"));
    assert!(!text_of(&h).contains("while the vault is frozen"));
    let until = h.now + h.v.csv_period_ms();
    h.freeze(until).unwrap();
    assert!(text_of(&h).contains("The current passkey has 2 of 2 cancels left but cannot use them while the vault is frozen"), "{}", text_of(&h));
    assert_eq!(h.recover_cancel().unwrap_err(), Error::Frozen { until });
    h.advance(until - h.now);
    assert!(!text_of(&h).contains("while the vault is frozen"), "the freeze lapsed");
    h.recover_cancel().unwrap();
}

// ------------------------------------------------------------------ the confirmation's new problems

const SPEND_3: [u8; 32] = [0x13; 32];

/// What both status lines now say execute still asks the signer for.
const RETRY: &str = "a self-spend with no time limit and one that pays out for at most 24 h after its first execute";

fn line_starting(h: &H, start: &str) -> String {
    h.v.status_lines(h.now).1.into_iter().find(|l| l.starts_with(start)).unwrap_or_default()
}

fn signer_line(failed: Ms, csv: u32, reclaim: &str) -> String {
    format!("the signer's last answer failed at {}: a request still signing can retry, {RETRY}, after which its coins come back by reclaim, {reclaim}, and a coin {csv} blocks old can leave by the cold-key exit", utc_text(failed))
}

/// The reviewer's first repro: a mainnet two-input withdrawal whose signer answers fail, then 25 h. The
/// line said a request still signing can retry while execute refused it. It now names the window and the
/// way out, and each part holds: a self-spend from the same outage still retries, the withdrawal does
/// not, and reclaim brings its coins back one per `T_new`.
#[test]
fn the_signer_line_names_the_retry_window_and_reclaim() {
    let mut h = H::mainnet();
    let dest = p2wpkh(0x63);
    let own = h.self_spend(&[(op(3), COIN_5)], FEE).unwrap();
    let r = h.propose(&[(op(1), 600_000), (op(2), 600_000)], &dest, 1_199_000, None).unwrap();
    h.advance(r.base_unlock - h.now);
    let first = h.now;
    for id in [own.id, r.id] {
        let batch = h.execute(id, MAX_INPUTS).unwrap();
        for i in &batch.indices {
            assert_eq!(h.v.on_signed(id, batch.attempt, *i, [7; 32], [7; 32], None, h.now), SignedOutcome::Failed);
        }
    }
    let (failed, csv) = (h.now, h.v.csv_blocks);
    assert_eq!(line_starting(&h, "the signer's"), signer_line(failed, csv, "at most one per 10 min"));

    h.advance(25 * HOUR);
    assert_eq!(line_starting(&h, "the signer's"), signer_line(failed, csv, "at most one per 10 min"));
    assert_eq!(h.execute(r.id, MAX_INPUTS).unwrap_err(), Error::RetryWindowClosed { closed_at: first + DAY });
    let again = h.execute(own.id, MAX_INPUTS).unwrap();
    h.sign_batch(own.id, &again);
    assert_eq!(h.v.requests[&own.id].status, RequestStatus::Signed, "a self-spend has no time limit");
    h.reclaim(op(1), 600_000, 500).unwrap();
    let free_at = h.now + h.v.policy.t_new_ms;
    assert_eq!(h.reclaim(op(2), 600_000, 500).unwrap_err(), Error::SelfSpendSlotUsed { free_at });
    h.advance(h.v.policy.t_new_ms);
    h.reclaim(op(2), 600_000, 500).unwrap();
}

/// The second repro: a rotation, a cold-key veto, then 25 h. The line said an executed request keeps
/// signing while execute refused it. Reclaim is signed by the spend key, so while this one is suspended
/// the way out waits for a new key, and both lines say so.
#[test]
fn the_suspended_key_line_names_the_retry_window_and_reclaim_with_a_new_key() {
    let mut h = H::mainnet();
    let dest = p2wpkh(0x64);
    let r = h.propose(&[(op(1), 600_000), (op(2), 600_000)], &dest, 1_199_000, None).unwrap();
    h.advance(r.base_unlock - h.now);
    let first = h.now;
    let batch = h.execute(r.id, MAX_INPUTS).unwrap();
    assert_eq!(h.v.on_signed(r.id, batch.attempt, 0, [7; 32], [7; 32], Some(vec![0xbb]), h.now), SignedOutcome::Stored { complete: false });
    assert_eq!(h.v.on_signed(r.id, batch.attempt, 1, [7; 32], [7; 32], None, h.now), SignedOutcome::Failed);
    let (failed, csv) = (h.now, h.v.csv_blocks);
    let grant = h.rotate(SPEND_2).unwrap();
    h.veto(grant).unwrap();
    h.advance(25 * HOUR);

    let suspended = format!("spend key suspended: requests not yet executed are dead. One already executed can still ask the signer for its missing signatures, {RETRY}, after which its coins come back by reclaim with a new key: no new key is waiting, so the passkey has to rotate again");
    assert_eq!(line_starting(&h, "spend key suspended"), suspended);
    assert_eq!(line_starting(&h, "the signer's"), signer_line(failed, csv, "with a new key"));
    assert_eq!(h.execute(r.id, MAX_INPUTS).unwrap_err(), Error::RetryWindowClosed { closed_at: first + DAY });
    assert_eq!(h.reclaim(op(2), 600_000, 500).unwrap_err(), Error::SpendKeySuspended);

    let grant = h.rotate(SPEND_3).unwrap();
    assert!(line_starting(&h, "spend key suspended").ends_with("by reclaim with a new key: a new key lands after its wait unless the cold key vetoes it"));
    h.advance(h.v.policy.t_known_ms);
    h.apply(grant).unwrap();
    assert_eq!(line_starting(&h, "spend key suspended"), "");
    assert_eq!(line_starting(&h, "the signer's"), signer_line(failed, csv, "at most one per 10 min"));
    h.reclaim(op(2), 600_000, 500).unwrap();
}

/// The close stops execute asking, not answers landing. An answer to a retry made just before the close
/// lands after it and completes the request, and its outflow then counts for a day from that landing.
#[test]
fn an_answer_asked_for_before_the_close_lands_after_it_and_counts_from_there() {
    let mut h = H::mainnet();
    let dest = p2wpkh(0x65);
    known(&mut h, &dest);
    let cap = h.v.policy.outflow_cap_24h;
    let r = h.propose(&[(op(1), cap / 2 + FEE), (op(2), cap - cap / 2)], &dest, cap, None).unwrap();
    h.advance(r.base_unlock - h.now);
    let first = h.now;
    let batch = h.execute(r.id, 1).unwrap();
    h.sign_batch(r.id, &batch);
    h.advance(DAY - 1);
    let last = h.execute(r.id, MAX_INPUTS).unwrap();
    h.advance(3_000);
    h.sign_batch(r.id, &last);
    let landed = h.now;
    assert!(landed > first + DAY);
    assert_eq!(h.v.requests[&r.id].status, RequestStatus::Signed);
    h.advance(DAY - 1);
    assert_eq!(tier_of(&h, op(3), &dest, cap), Tier::New, "a day from the landing, which came after the close");
    h.advance(1);
    assert_eq!(tier_of(&h, op(3), &dest, cap), Tier::Known);
}

/// The row as a build before round 5 left it: the same bytes, except that this request's outflow entry
/// still has its propose time, which that build never moved. Requests and ledger entries are stored
/// outside the row, so they come through as they are, as they do in the contract.
fn as_an_earlier_build_left_it(v: &Vault, id: RequestId) -> Vault {
    let r = &v.requests[&id];
    let entry = |at: Ms| [at.to_le_bytes(), r.outputs.dest_value.to_le_bytes(), id.to_le_bytes()].concat();
    let (stamped, proposed) = (entry(r.first_execute_at.unwrap()), entry(r.proposed_at));
    let mut row = borsh::to_vec(v).unwrap();
    let found: Vec<usize> = (0..=row.len() - stamped.len()).filter(|i| row[*i..*i + stamped.len()] == stamped[..]).collect();
    assert_eq!(found.len(), 1, "the entry is in the row once");
    row[found[0]..found[0] + proposed.len()].copy_from_slice(&proposed);
    let mut old: Vault = borsh::from_slice(&row).unwrap();
    old.requests = v.requests.clone();
    old.ledger = v.ledger.clone();
    old
}

/// SPEC 22's upgrade case. A build before round 5 timed an executed request's entry at propose, and an
/// upgrade keeps the row as that build wrote it. Once that entry left, a day after propose, the request
/// could still retry until a day after its first execute, while a second full cap read Known: two caps
/// inside a day. A retry with no entry left is now refused. One made before the entry leaves moves it,
/// as any retry does.
#[test]
fn a_request_executed_before_an_upgrade_stops_retrying_when_its_entry_leaves() {
    let mut h = H::mainnet();
    let dest = p2wpkh(0x66);
    known(&mut h, &dest);
    let cap = h.v.policy.outflow_cap_24h;
    let half = cap / 2;
    let r1 = h.propose(&[(op(1), half + FEE), (op(2), cap - half)], &dest, cap, None).unwrap();
    assert_eq!(r1.tier, Tier::Known);
    let proposed = h.now;
    // Executed half a day after its unlock, which the proof preset's day of expiry allows.
    h.advance(r1.base_unlock + 12 * HOUR - h.now);
    let batch = h.execute(r1.id, 1).unwrap();
    h.sign_batch(r1.id, &batch);
    let first = h.now;
    h.v = as_an_earlier_build_left_it(&h.v, r1.id);
    assert_eq!(h.v.outflow_used_24h(h.now), cap, "the earlier build's entry still counts");

    let mut early = h.clone();
    early.advance(proposed + DAY - 1 - early.now);
    let rest = early.execute(r1.id, 1).unwrap();
    early.sign_batch(r1.id, &rest);
    let landed = early.now;
    early.advance(DAY - 1);
    assert_eq!(tier_of(&early, op(3), &dest, cap), Tier::New, "a retry before it left moved it");
    early.advance(1);
    assert_eq!(early.now, landed + DAY);
    assert_eq!(tier_of(&early, op(3), &dest, cap), Tier::Known);

    h.advance(proposed + DAY - h.now);
    assert!(h.now + 12 * HOUR <= first + DAY, "half a day before the usual close");
    assert_eq!(tier_of(&h, op(3), &dest, cap), Tier::Known, "the entry has left");
    let r2 = h.propose(&[(op(3), cap + FEE)], &dest, cap, None).unwrap();
    assert_eq!(r2.tier, Tier::Known);
    let closed = Error::RetryWindowClosed { closed_at: proposed + DAY };
    assert_eq!(h.execute(r1.id, MAX_INPUTS).unwrap_err(), closed);
    h.advance(r2.base_unlock - h.now);
    h.execute_all_signed(r2.id);
    assert_eq!(h.execute(r1.id, MAX_INPUTS).unwrap_err(), closed, "still closed when R2 has signed");
    assert_eq!(h.v.requests[&r1.id].sigs.iter().filter(|s| s.is_some()).count(), 1, "R1 stays half signed");
    h.reclaim(op(2), cap - half, FEE).unwrap();
}
