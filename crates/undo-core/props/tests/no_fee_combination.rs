//! C09, model half. For generated action sequences, every transaction the recorded signing sessions
//! could assemble is either invalid or pays a real fee within the cap its sessions passed. The model
//! of what BIP-143 lets combine is checked against libbitcoinconsensus in `consensus.rs`.

mod common;

use common::world::{coin, sequence, valid_combinations, Session, World, REALS};
use common::*;
use proptest::test_runner::{Config, TestRunner};
use std::cell::Cell;
use std::collections::BTreeMap;
use undo_core::*;

fn cases(default: u32) -> u32 {
    std::env::var("PROPTEST_CASES").ok().and_then(|c| c.parse().ok()).unwrap_or(default)
}

#[test]
fn no_fee_combination() {
    let touching_pairs = Cell::new(0usize);
    let refused = Cell::new(0usize);
    let multi = Cell::new(0usize);
    let mut runner = TestRunner::new(Config { cases: cases(2_000), failure_persistence: None, ..Config::default() });
    runner
        .run(&sequence(), |actions| {
            let mut world = World::new(p2wsh(0x77));
            for action in &actions {
                world.step(action);
            }
            for (real_fee, cap) in valid_combinations(&world.sessions, &world.reals) {
                assert!(real_fee <= cap, "real fee {real_fee} over cap {cap}: {:#?}", world.sessions);
            }
            let s = &world.sessions;
            for i in 0..s.len() {
                for j in i + 1..s.len() {
                    if s[i].prevouts.iter().any(|o| s[j].prevouts.contains(o)) {
                        touching_pairs.set(touching_pairs.get() + 1);
                    }
                }
            }
            refused.set(refused.get() + world.coverage.pinned_multi_refused);
            multi.set(multi.get() + world.coverage.multi_sessions);
            Ok(())
        })
        .unwrap();
    println!(
        "coverage: session pairs touching an outpoint={} pinned multi-input refusals={} multi-input sessions={}",
        touching_pairs.get(),
        refused.get(),
        multi.get()
    );
    assert!(touching_pairs.get() > 200, "the property never saw two sessions over one outpoint");
    assert!(refused.get() > 100, "the property never reached the pin rule");
    assert!(multi.get() > 100, "the property never signed a multi-input request");
}

/// The model must actually see the attack. Feed it the two sessions directly, with no state machine:
/// it reports the 999,500-sat fee the attack review measured.
#[test]
fn the_model_detects_the_attack_when_given_both_sessions() {
    let (a, b) = (coin(0), coin(1));
    assert_eq!((REALS[0], REALS[1]), (1_000_000, 1_000_000));
    let reals: BTreeMap<Outpoint, Sats> = [(a, REALS[0]), (b, REALS[1])].into_iter().collect();
    let outputs = Outputs { dest_script: p2wsh(0x77), dest_value: 1_000_500, change_value: None };
    let session = |declared: [Sats; 2]| Session {
        request: 0,
        prevouts: vec![a, b],
        declared: declared.to_vec(),
        outputs: outputs.clone(),
        signed: [0usize, 1].into_iter().collect(),
        allowed_fee: 1_000,
    };
    let one = session([1_000_000, 1_500]);
    let two = session([1_500, 1_000_000]);
    assert!(valid_combinations(std::slice::from_ref(&one), &reals).is_empty(), "alone it is invalid");
    assert!(valid_combinations(std::slice::from_ref(&two), &reals).is_empty(), "alone it is invalid");
    assert_eq!(valid_combinations(&[one, two], &reals), vec![(999_500, 1_000)]);
}
