//! A signed chain of restarts cannot grow faster than the chain wait, whatever order a thief signs it
//! in. Property-tested over generated sequences, not exhaustive.
//!
//! The chain is one fixed line of self-spends: link g spends the coin link g-1 pays back to the vault.
//! So a test can name a link before its parent has gone out, which is how the backwards attack works.

mod common;

use common::*;
use proptest::prelude::*;
use proptest::test_runner::{Config, TestRunner};
use std::cell::RefCell;
use std::collections::BTreeMap;
use undo_core::*;

const VALUE: Sats = 1_000_000;
const FEE: Sats = 200;
const LINKS: usize = 8;

#[derive(Clone, Copy, Debug)]
enum Step {
    Advance(Ms),
    Propose(usize),
    Execute(usize),
    Cancel(usize),
    Reclaim(usize),
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        4 => prop_oneof![Just(MINUTE), Just(5 * MINUTE), Just(10 * MINUTE), Just(45 * MINUTE), Just(HOUR)].prop_map(Step::Advance),
        5 => (0..LINKS).prop_map(Step::Propose),
        5 => (0..LINKS).prop_map(Step::Execute),
        1 => (0..LINKS).prop_map(Step::Cancel),
        1 => (0..LINKS).prop_map(Step::Reclaim),
    ]
}

/// A thief walking the line forward, or from the far end, with noise.
fn walk() -> impl Strategy<Value = Vec<Step>> {
    let noise = proptest::collection::vec(step(), 1..120);
    let forward = (1u64..6).prop_map(|gap| {
        let mut out = Vec::new();
        for g in 0..LINKS {
            out.extend([Step::Propose(g), Step::Advance(5 * MINUTE), Step::Execute(g), Step::Advance(gap * 10 * MINUTE)]);
        }
        out
    });
    // Each child proposed before its parent goes out, so it has no birth time to wait for.
    let overlapped = Just({
        let mut out = Vec::new();
        for g in 0..LINKS - 1 {
            out.extend([Step::Propose(g), Step::Advance(10 * MINUTE), Step::Propose(g + 1), Step::Execute(g), Step::Advance(5 * MINUTE), Step::Execute(g + 1), Step::Advance(45 * MINUTE), Step::Execute(g + 1)]);
        }
        out
    });
    let backward = Just({
        let mut out = Vec::new();
        for g in (0..LINKS).rev() {
            out.extend([Step::Propose(g), Step::Advance(5 * MINUTE), Step::Execute(g), Step::Advance(10 * MINUTE)]);
        }
        out
    });
    prop_oneof![2 => noise, 1 => forward, 1 => backward, 1 => overlapped]
}

/// Link g as the contract would see it.
fn links(spk: &[u8]) -> Vec<(Input, Outputs)> {
    let mut coin = op(1);
    let mut value = VALUE;
    let mut out = Vec::new();
    for _ in 0..LINKS {
        let input = Input { outpoint: coin, value };
        let outputs = Outputs { dest_script: spk.to_vec(), dest_value: value - FEE, change_value: None };
        // What txid_of hashes, without needing a request to exist.
        let probe = probe_request(input, &outputs);
        coin = Outpoint { txid: txid_of(&probe), vout: 0 };
        value -= FEE;
        out.push((input, outputs));
    }
    out
}

fn probe_request(input: Input, outputs: &Outputs) -> Request {
    let mut h = H::test_coin();
    h.v.vault_spk = outputs.dest_script.clone();
    let args = ProposeArgs { inputs: vec![input], outputs: outputs.clone(), half_sigs: vec![vec![0xaa; 65]], memo: None };
    let (caller, intent) = (h.spend_caller(), h.sp());
    let id = h.v.propose(&caller, intent, args, h.now).unwrap().id;
    h.v.requests[&id].clone()
}

#[derive(Default)]
struct Coverage {
    longest: usize,
    too_young_at_propose: usize,
    out_of_order: usize,
    signed: usize,
}

fn run(mut h: H, steps: &[Step], cover: &mut Coverage) {
    let wait = h.v.chain_wait_ms();
    let start = h.now;
    let line = links(&h.v.vault_spk.clone());
    let mut requests: BTreeMap<usize, RequestId> = BTreeMap::new();
    // When each link first went out. A reclaim is an alternative to a link, at the same depth.
    let mut out_at: BTreeMap<usize, Ms> = BTreeMap::new();
    for step in steps {
        match *step {
            Step::Advance(ms) => h.advance(ms),
            Step::Propose(g) => {
                let (input, outputs) = line[g].clone();
                match h.propose(&[(input.outpoint, input.value)], &outputs.dest_script, outputs.dest_value, None) {
                    Ok(p) => {
                        requests.insert(g, p.id);
                    }
                    Err(Error::ChainTooYoung { .. }) => cover.too_young_at_propose += 1,
                    Err(_) => {}
                }
            }
            Step::Execute(g) => {
                let Some(id) = requests.get(&g).copied() else { continue };
                let first = h.v.requests.get(&id).is_some_and(|r| r.status == RequestStatus::Pending);
                match h.execute(id, 16) {
                    Ok(batch) => {
                        h.sign_batch(id, &batch);
                        cover.signed += 1;
                        if first {
                            out_at.entry(g).or_insert(h.now);
                        }
                    }
                    Err(Error::ChainOutOfOrder(_)) => cover.out_of_order += 1,
                    Err(_) => {}
                }
            }
            Step::Cancel(g) => {
                if let Some(id) = requests.get(&g).copied() {
                    let _ = h.cancel(id);
                }
            }
            Step::Reclaim(g) => {
                let (input, _) = line[g];
                if let Ok(p) = h.reclaim(input.outpoint, input.value, FEE) {
                    // Same inputs and outputs as link g, so the same link by a second route.
                    requests.insert(g, p.id);
                }
            }
        }
        // The property, after every step, from the outside: no link went out before its parent, or
        // inside the wait after it.
        for (g, at) in &out_at {
            if *g == 0 {
                continue;
            }
            if let Some(parent) = out_at.get(&(g - 1)) {
                assert!(parent + wait <= *at, "link {g} went out at {at}, parent at {parent}, wait {wait}");
            }
        }
        let mut length = 0;
        while out_at.contains_key(&length) {
            length += 1;
        }
        // Its consequence for a whole chain: links are spaced, so time bounds how many there are.
        if length > 0 {
            assert!(length as u64 <= 1 + (h.now - start) / wait, "{length} links after {} ms, wait {wait}", h.now - start);
        }
        cover.longest = cover.longest.max(length);
    }
}

fn check(make: fn() -> H, want_longest: usize) {
    let cover = RefCell::new(Coverage::default());
    let cases = std::env::var("PROPTEST_CASES").ok().and_then(|c| c.parse().ok()).unwrap_or(1_000);
    let mut runner = TestRunner::new(Config { cases, failure_persistence: None, ..Config::default() });
    runner
        .run(&walk(), |steps| {
            run(make(), &steps, &mut cover.borrow_mut());
            Ok(())
        })
        .unwrap();
    let c = cover.into_inner();
    println!("coverage: longest={} too_young_at_propose={} out_of_order={} signed={}", c.longest, c.too_young_at_propose, c.out_of_order, c.signed);
    // A property that never reaches these states would pass while proving nothing.
    assert!(c.longest >= want_longest, "longest {}", c.longest);
    assert!(c.signed > 200, "signed {}", c.signed);
    assert!(c.too_young_at_propose > 50, "too_young_at_propose {}", c.too_young_at_propose);
    assert!(c.out_of_order > 20, "out_of_order {}", c.out_of_order);
}

#[test]
fn no_signed_chain_outruns_the_wait_on_the_proof_vault() {
    check(H::mainnet, 4);
}
