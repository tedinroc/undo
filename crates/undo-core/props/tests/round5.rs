//! Round 5, the authorization audit's contract findings. Each test here failed on the build before it.
//!
//! C1: a known destination's 24 h cap counted from propose time, while a request stays executable until
//! its expiry, a day after unlock on the proof preset. So two full caps could reach signing within
//! `T_known` of each other. Outflow now counts while its request is pending, and for a day after the
//! last time execute asked the signer for it or its last signature landed. A request that pays out
//! takes no more signatures a day after its first execute, so nothing signs outside a window that a
//! later proposal was checked against.

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
/// moves the outflow's time to now. A request that pays out takes none a day after its first execute,
/// so a half-signed spend cannot finish inside the window of a request proposed after its entry left.
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
/// first execute keeps signing through both, so its outflow keeps counting.
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
