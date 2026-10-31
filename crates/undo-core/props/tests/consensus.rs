//! C09, consensus half. [test-only] keys, derived from labels at run time and never holding value.
//! Real ECDSA signatures over real BIP-143 digests, judged by libbitcoinconsensus on the spec's
//! two-branch script. Proves signature and script validity only, not mempool policy or maturity.

mod common;

use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::script::Builder;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use bitcoin::sighash::SighashCache;
use bitcoin::{
    absolute, transaction, Amount, EcdsaSighashType, OutPoint, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Txid, Witness,
};
use common::world::{coin, sequence, Session, World, FALSE_VALUE};
use common::*;
use proptest::test_runner::{Config, TestRunner};
use std::cell::Cell;
use std::collections::BTreeMap;
use undo_core::*;

struct Key {
    sk: SecretKey,
    pk: bitcoin::PublicKey,
}

fn key(label: &str) -> Key {
    let secp = Secp256k1::new();
    let digest = sha256::Hash::hash(format!("[test-only] {label}").as_bytes());
    let sk = SecretKey::from_slice(digest.as_byte_array()).unwrap();
    Key { sk, pk: bitcoin::PublicKey::new(PublicKey::from_secret_key(&secp, &sk)) }
}

/// Spec 1.2: `K_u` and `K_m`, or `K_e` alone after CSV.
fn witness_script(u: &Key, m: &Key, e: &Key, csv: i64) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_IF)
        .push_key(&u.pk)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_key(&m.pk)
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ELSE)
        .push_int(csv)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_key(&e.pk)
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ENDIF)
        .into_script()
}

struct Keys {
    u: Key,
    m: Key,
    script: ScriptBuf,
    spk: ScriptBuf,
}

fn keys() -> Keys {
    let (u, m, e) = (key("k_u"), key("k_m"), key("k_e"));
    let script = witness_script(&u, &m, &e, 6);
    let spk = script.to_p2wsh();
    Keys { u, m, script, spk }
}

fn outpoint(o: &Outpoint) -> OutPoint {
    OutPoint { txid: Txid::from_byte_array(o.txid), vout: o.vout }
}

/// Version 2, locktime 0, `nSequence = 0xfffffffd`, as the spec fixes them.
fn unsigned_tx(prevouts: &[Outpoint], outputs: &Outputs, vault_spk: &ScriptBuf) -> Transaction {
    let mut output = vec![TxOut {
        value: Amount::from_sat(outputs.dest_value),
        script_pubkey: ScriptBuf::from_bytes(outputs.dest_script.clone()),
    }];
    if let Some(change) = outputs.change_value {
        output.push(TxOut { value: Amount::from_sat(change), script_pubkey: vault_spk.clone() });
    }
    Transaction {
        version: transaction::Version(2),
        lock_time: absolute::LockTime::ZERO,
        input: prevouts
            .iter()
            .map(|o| TxIn {
                previous_output: outpoint(o),
                script_sig: ScriptBuf::new(),
                sequence: Sequence(0xffff_fffd),
                witness: Witness::new(),
            })
            .collect(),
        output,
    }
}

/// Witness for one input, signed with the value this session was told. `sig_m sig_u 01 script`.
fn signed_input(k: &Keys, tx: &Transaction, index: usize, declared: Sats) -> Witness {
    let secp = Secp256k1::new();
    let digest = SighashCache::new(tx)
        .p2wsh_signature_hash(index, &k.script, Amount::from_sat(declared), EcdsaSighashType::All)
        .unwrap();
    let message = Message::from_digest(digest.to_byte_array());
    let der = |sk: &SecretKey| {
        let mut sig = secp.sign_ecdsa(&message, sk).serialize_der().to_vec();
        sig.push(0x01);
        sig
    };
    let mut witness = Witness::new();
    witness.push(der(&k.m.sk));
    witness.push(der(&k.u.sk));
    witness.push([1u8]);
    witness.push(k.script.as_bytes());
    witness
}

fn consensus_valid(tx: &Transaction, reals: &BTreeMap<Outpoint, Sats>, spk: &ScriptBuf) -> bool {
    let lookup = |o: &OutPoint| {
        reals
            .iter()
            .find(|(real, _)| outpoint(real) == *o)
            .map(|(_, value)| TxOut { value: Amount::from_sat(*value), script_pubkey: spk.clone() })
    };
    tx.verify(lookup).is_ok()
}

fn self_spend_outputs(spk: &ScriptBuf, value: Sats) -> Outputs {
    Outputs { dest_script: spk.as_bytes().to_vec(), dest_value: value, change_value: None }
}

/// Control: on the current two-branch script, with no state machine in the way, the attack works.
/// Each session alone is invalid and the combination pays 999,500 sats at a declared fee of 1,000.
#[test]
fn fee_swap_control_is_valid_when_a_signer_produces_both_sessions() {
    let k = keys();
    let (a, b) = (coin(0), coin(1));
    let reals: BTreeMap<Outpoint, Sats> = [(a, 1_000_000), (b, 1_000_000)].into_iter().collect();
    let (d1, d2) = ([1_000_000u64, 1_500u64], [1_500u64, 1_000_000u64]);
    let fee = 1_000;
    let outputs = self_spend_outputs(&k.spk, d1[0] + d1[1] - fee);
    assert_eq!(outputs.dest_value, d2[0] + d2[1] - fee, "same output in both sessions");
    let tx = unsigned_tx(&[a, b], &outputs, &k.spk);

    let with = |w0: Witness, w1: Witness| {
        let mut t = tx.clone();
        t.input[0].witness = w0;
        t.input[1].witness = w1;
        t
    };
    let session_one = with(signed_input(&k, &tx, 0, d1[0]), signed_input(&k, &tx, 1, d1[1]));
    let session_two = with(signed_input(&k, &tx, 0, d2[0]), signed_input(&k, &tx, 1, d2[1]));
    assert!(!consensus_valid(&session_one, &reals, &k.spk), "session one alone");
    assert!(!consensus_valid(&session_two, &reals, &k.spk), "session two alone");

    let combined = with(signed_input(&k, &tx, 0, d1[0]), signed_input(&k, &tx, 1, d2[1]));
    assert!(consensus_valid(&combined, &reals, &k.spk), "the combination is the attack");
    let real_fee = 2_000_000 - outputs.dest_value;
    assert_eq!(real_fee, 999_500);
    println!("control: combined tx valid, real fee {real_fee} sat at a declared fee of {fee}");
}

/// What undo-core leaves an attacker with: session one plus a single-input reclaim. The reclaim's
/// signature cannot join session one's transaction, because `hashPrevouts` covers its one input.
#[test]
fn fee_swap_single_input_reclaim_cannot_combine_with_the_first_session() {
    let k = keys();
    let (a, b) = (coin(0), coin(1));
    let reals: BTreeMap<Outpoint, Sats> = [(a, 1_000_000), (b, 1_000_000)].into_iter().collect();
    let first_outputs = self_spend_outputs(&k.spk, 1_000_500);
    let first = unsigned_tx(&[a, b], &first_outputs, &k.spk);

    // The reclaim of B, with its true value, under every output that could help the attacker: its
    // own, and session one's.
    for output_value in [999_000u64, 1_000_500] {
        let single = unsigned_tx(&[b], &self_spend_outputs(&k.spk, output_value), &k.spk);
        let reclaim_witness = signed_input(&k, &single, 0, 1_000_000);
        let mut combined = first.clone();
        combined.input[0].witness = signed_input(&k, &first, 0, 1_000_000);
        combined.input[1].witness = reclaim_witness;
        assert!(!consensus_valid(&combined, &reals, &k.spk));
    }
}

/// The state machine and consensus together: the same request sequence the attack needs, with real
/// signatures from every session it allows, combined every way, never pays over the cap.
#[test]
fn fee_swap_through_undo_core_never_yields_a_valid_overpayment() {
    let k = keys();
    let mut world = World::new(k.spk.as_bytes().to_vec());
    let (a, b) = (coin(0), coin(1));
    let fee = 1_000;
    let false_value = FALSE_VALUE;
    let drive = |h: &mut H| {
        let first = h.self_spend(&[(a, 1_000_000), (b, false_value)], fee).unwrap();
        h.advance(h.v.policy.t_known_ms);
        h.execute_all_signed(first.id);
        h.advance(h.v.policy.t_stuck_ms);
        let r_a = h.reclaim(a, false_value, fee).unwrap();
        h.cancel(r_a.id).unwrap();
        let r_b = h.reclaim(b, 1_000_000, fee).unwrap();
        h.cancel(r_b.id).unwrap();
        assert_eq!(
            h.self_spend(&[(a, false_value), (b, 1_000_000)], fee).unwrap_err(),
            Error::PinnedInMultiInput(a)
        );
        first
    };
    let first = drive(&mut world.h);
    let session = Session {
        request: first.id,
        prevouts: vec![a, b],
        declared: vec![1_000_000, false_value],
        outputs: self_spend_outputs(&k.spk, 1_000_000 + false_value - fee),
        signed: [0usize, 1].into_iter().collect(),
        allowed_fee: 1_000,
    };
    assert!(common::world::valid_combinations(&[session], &world.reals).is_empty());
}

/// Rule 6 of the spec: signatures combined across every pair of sessions touching an outpoint. Every
/// combination is judged by consensus, and that verdict must equal the model's. A valid one must pay
/// within the cap. Pairs include a session with itself, which covers each session alone.
#[test]
fn no_fee_combination_all_pairs_under_consensus() {
    let k = keys();
    let checked = Cell::new(0usize);
    let valid = Cell::new(0usize);
    let cases = std::env::var("PROPTEST_CONSENSUS_CASES").ok().and_then(|c| c.parse().ok()).unwrap_or(300);
    let mut runner = TestRunner::new(Config { cases, failure_persistence: None, ..Config::default() });
    runner
        .run(&sequence(), |actions| {
            let mut world = World::new(k.spk.as_bytes().to_vec());
            for action in &actions {
                world.step(action);
            }
            let sessions = &world.sessions;
            for s in sessions {
                for t in sessions {
                    if !s.prevouts.iter().any(|o| t.prevouts.contains(o)) {
                        continue;
                    }
                    check_pair(&k, s, t, &world.reals, &checked, &valid);
                }
            }
            Ok(())
        })
        .unwrap();
    println!("consensus: {} combinations judged, {} valid", checked.get(), valid.get());
    assert!(checked.get() > 1_000, "the test barely ran: {}", checked.get());
    assert!(valid.get() > 50, "no valid combination was ever seen, so the check proved little");
}

fn check_pair(
    k: &Keys,
    s: &Session,
    t: &Session,
    reals: &BTreeMap<Outpoint, Sats>,
    checked: &Cell<usize>,
    valid: &Cell<usize>,
) {
    let base = unsigned_tx(&s.prevouts, &s.outputs, &k.spk);
    let t_tx = unsigned_tx(&t.prevouts, &t.outputs, &k.spk);
    let same_shape = s.prevouts == t.prevouts && s.outputs == t.outputs;
    // For each input of s's transaction: s's own signature, or t's signature over the same outpoint.
    let n = s.prevouts.len();
    for mask in 0u32..(1 << n) {
        let mut tx = base.clone();
        let mut model_valid = true;
        let mut usable = true;
        for i in 0..n {
            let real = reals[&s.prevouts[i]];
            if mask & (1 << i) == 0 {
                if !s.signed.contains(&i) {
                    usable = false;
                    break;
                }
                tx.input[i].witness = signed_input(k, &base, i, s.declared[i]);
                model_valid &= s.declared[i] == real;
            } else {
                let Some(j) = t.prevouts.iter().position(|o| *o == s.prevouts[i]) else {
                    usable = false;
                    break;
                };
                if !t.signed.contains(&j) {
                    usable = false;
                    break;
                }
                tx.input[i].witness = signed_input(k, &t_tx, j, t.declared[j]);
                // A signature from another session is good here only if that session signed this
                // same shape, at the same index, with the true value.
                model_valid &= same_shape && t.declared[j] == real;
            }
        }
        if !usable {
            continue;
        }
        let total: Sats = s.prevouts.iter().map(|o| reals[o]).sum();
        let out = s.outputs.total();
        model_valid &= total >= out;
        let verdict = consensus_valid(&tx, reals, &k.spk);
        checked.set(checked.get() + 1);
        assert_eq!(verdict, model_valid, "model and consensus disagree: {s:#?} {t:#?} mask {mask}");
        if verdict {
            valid.set(valid.get() + 1);
            let real_fee = total - out;
            let cap = s.allowed_fee.max(t.allowed_fee);
            assert!(real_fee <= cap, "real fee {real_fee} over cap {cap}: {s:#?} {t:#?}");
        }
    }
}
