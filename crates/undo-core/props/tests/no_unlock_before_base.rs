//! C01. No request gets an MPC signature before its base unlock. Property-tested over generated role
//! and method sequences, not exhaustive. Scope: the contract. The cold key's Bitcoin leaf is outside
//! it, and that is the one exit that skips the wait.

mod common;

use common::world::{sequence, Coverage, World};
use common::*;
use proptest::test_runner::{Config, TestRunner};
use std::cell::RefCell;

fn cases(default: u32) -> u32 {
    std::env::var("PROPTEST_CASES").ok().and_then(|c| c.parse().ok()).unwrap_or(default)
}

fn add(total: &mut Coverage, c: Coverage) {
    total.accepted += c.accepted;
    total.refused += c.refused;
    total.executes += c.executes;
    total.executed_with_hold_cleared += c.executed_with_hold_cleared;
    total.reclaims += c.reclaims;
    total.bumps += c.bumps;
    total.grants_applied += c.grants_applied;
    total.freezes += c.freezes;
    total.rotations += c.rotations;
    total.early_execute_refused += c.early_execute_refused;
}

#[test]
fn no_unlock_before_base() {
    let total = RefCell::new(Coverage::default());
    let mut runner = TestRunner::new(Config { cases: cases(2_000), failure_persistence: None, ..Config::default() });
    runner
        .run(&sequence(), |actions| {
            let mut world = World::new(p2wsh(0x77));
            for action in &actions {
                world.step(action);
            }
            add(&mut total.borrow_mut(), world.coverage);
            Ok(())
        })
        .unwrap();
    let total = total.into_inner();
    println!("coverage: {total:?}");
    // A property that never reaches these states would pass while proving nothing.
    assert!(total.executes > 500, "{total:?}");
    assert!(total.early_execute_refused > 100, "{total:?}");
    assert!(total.reclaims > 50, "{total:?}");
    assert!(total.bumps > 5, "{total:?}");
    assert!(total.grants_applied > 50, "{total:?}");
    assert!(total.freezes > 50, "{total:?}");
    assert!(total.rotations > 50, "{total:?}");
}
