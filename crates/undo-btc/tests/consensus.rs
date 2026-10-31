//! The two-branch script under libbitcoinconsensus, through this crate's own sighash and witness
//! code. Scope and blind spots are on `common::consensus`. Every negative here is a well-formed
//! signature over the right digest, so a rejection is about who signed and when, and each one has
//! a positive twin in this file that passes.

mod common;

use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::script::Builder;
use common::*;
use undo_btc::{Csv, Error, PubKey, Sha2, Tx, TxOut, WitnessScript};

const ONE: &[u8] = &[1];
const EMPTY: &[u8] = &[];

/// Puts `items` and the script on input 0, then asks the library.
fn run(mut tx: Tx, items: &[&[u8]], script: &[u8], spk: &[u8]) -> Result<(), String> {
    let mut witness: Vec<Vec<u8>> = items.iter().map(|i| i.to_vec()).collect();
    witness.push(script.to_vec());
    tx.inputs[0].witness = witness;
    consensus(&tx, 0, spk, VALUE)
}

fn expect_rejected(name: &str, result: Result<(), String>) {
    println!("{name}: rejected={}", result.is_err());
    assert!(result.is_err(), "{name} must be rejected");
}

// ---------------------------------------------------------------- positive controls

#[test]
fn cosigned_spend_passes_through_the_crate_api() {
    let v = vault(6);
    let mut tx = one_input(2, SEQ_COSIGNED);
    let (m, u) = (sign_der(&tx, 0, v.script.as_bytes(), VALUE, &v.m), sign_der(&tx, 0, v.script.as_bytes(), VALUE, &v.u));
    tx.set_cosigned_witness(0, &m, &u, &v.script).unwrap();
    consensus(&tx, 0, &v.spk, VALUE).unwrap();
}

#[test]
fn cosigned_spend_with_three_inputs_and_change_passes() {
    let v = vault(6);
    let values = [40_000u64, 50_000, 60_000];
    let outs = vec![
        TxOut { value: 100_000, script_pubkey: destination() },
        TxOut { value: 49_000, script_pubkey: v.spk.clone() },
    ];
    let mut tx = Tx::cosigned(&[outpoint(1), outpoint(2), outpoint(3)], outs);
    let digests = tx.sighashes::<Sha2>(v.script.as_bytes(), &values).unwrap();
    for (i, value) in values.into_iter().enumerate() {
        assert_eq!(digests[i], tx.sighash::<Sha2>(i, v.script.as_bytes(), value).unwrap());
        let (m, u) = (sign_der(&tx, i, v.script.as_bytes(), value, &v.m), sign_der(&tx, i, v.script.as_bytes(), value, &v.u));
        tx.set_cosigned_witness(i, &m, &u, &v.script).unwrap();
    }
    for (i, value) in values.into_iter().enumerate() {
        consensus(&tx, i, &v.spk, value).unwrap();
    }
}

#[test]
fn escape_passes_at_csv_and_above() {
    let v = vault(6);
    let mut tx = Tx::escape(&[outpoint(1)], Csv::new(6).unwrap(), pay_out(VALUE - 1_000));
    let e = sign_der(&tx, 0, v.script.as_bytes(), VALUE, &v.e);
    tx.set_escape_witness(0, &e, &v.script).unwrap();
    consensus(&tx, 0, &v.spk, VALUE).unwrap();

    // A larger block count also satisfies the opcode, and only ever waits longer.
    for seq in [7u32, 65_535] {
        let tx = one_input(2, seq);
        let e = sign(&tx, 0, v.script.as_bytes(), VALUE, &v.e);
        run(tx, &[&e, EMPTY], v.script.as_bytes(), &v.spk).unwrap();
    }
}

#[test]
fn escape_at_every_push_size_boundary() {
    for csv in [1u32, 2, 16, 17, 127, 128, 255, 256, 32_767, 32_768, 65_534, 65_535] {
        let v = vault(csv);
        let at = one_input(2, csv);
        let sig = sign(&at, 0, v.script.as_bytes(), VALUE, &v.e);
        run(at, &[&sig, EMPTY], v.script.as_bytes(), &v.spk).unwrap_or_else(|e| panic!("csv {csv} at csv: {e}"));

        let below = one_input(2, csv - 1);
        let sig = sign(&below, 0, v.script.as_bytes(), VALUE, &v.e);
        expect_rejected(&format!("csv {csv} at csv-1"), run(below, &[&sig, EMPTY], v.script.as_bytes(), &v.spk));
    }
}

#[test]
fn escape_at_csv_over_the_whole_range_sampled() {
    // Every 251st value, because signing all 65,535 adds nothing the boundaries do not.
    for csv in (1u32..=65_535).step_by(251) {
        let v = vault(csv);
        let at = one_input(2, csv);
        let sig = sign(&at, 0, v.script.as_bytes(), VALUE, &v.e);
        run(at, &[&sig, EMPTY], v.script.as_bytes(), &v.spk).unwrap_or_else(|e| panic!("csv {csv}: {e}"));
    }
}

// ---------------------------------------------------------------- the five named negatives

#[test]
fn mpc_alone_cannot_spend() {
    let v = vault(6);
    let s = v.script.as_bytes();

    let tx = one_input(2, SEQ_COSIGNED);
    let m = sign(&tx, 0, s, VALUE, &v.m);
    expect_rejected("MPC in both slots of the co-sign branch", run(tx.clone(), &[&m, &m, ONE], s, &v.spk));
    expect_rejected("MPC with an empty K_u slot", run(tx.clone(), &[&m, EMPTY, ONE], s, &v.spk));
    expect_rejected("MPC with K_u slot missing", run(tx, &[&m, ONE], s, &v.spk));

    let tx = one_input(2, 6);
    let m = sign(&tx, 0, s, VALUE, &v.m);
    expect_rejected("MPC in the escape branch, seq = csv", run(tx, &[&m, EMPTY], s, &v.spk));
}

#[test]
fn k_u_alone_cannot_spend() {
    let v = vault(6);
    let s = v.script.as_bytes();
    let tx = one_input(2, SEQ_COSIGNED);
    let u = sign(&tx, 0, s, VALUE, &v.u);
    expect_rejected("K_u in both slots", run(tx.clone(), &[&u, &u, ONE], s, &v.spk));
    expect_rejected("K_u with an empty K_m slot", run(tx.clone(), &[EMPTY, &u, ONE], s, &v.spk));
    expect_rejected("K_u with K_m slot missing", run(tx, &[&u, ONE], s, &v.spk));
}

#[test]
fn k_u_after_csv_cannot_escape() {
    let v = vault(6);
    let s = v.script.as_bytes();
    for seq in [6u32, 7, 65_535] {
        let tx = one_input(2, seq);
        let u = sign(&tx, 0, s, VALUE, &v.u);
        expect_rejected(&format!("K_u in the escape branch, seq {seq}"), run(tx, &[&u, EMPTY], s, &v.spk));
    }
}

#[test]
fn k_e_before_csv_cannot_escape() {
    let v = vault(6);
    let s = v.script.as_bytes();
    for seq in 0u32..6 {
        let tx = one_input(2, seq);
        let e = sign(&tx, 0, s, VALUE, &v.e);
        expect_rejected(&format!("K_e at seq {seq}, csv 6"), run(tx, &[&e, EMPTY], s, &v.spk));
    }
    // Bit 31 turns off the relative lock for the input, and CSV must then fail.
    for seq in [SEQ_COSIGNED, 0xffff_ffff, 0x8000_0006] {
        let tx = one_input(2, seq);
        let e = sign(&tx, 0, s, VALUE, &v.e);
        expect_rejected(&format!("K_e at disabled seq {seq:#x}"), run(tx, &[&e, EMPTY], s, &v.spk));
    }
    // Bit 22 makes the sequence time-based, a different unit from the block-based operand.
    let tx = one_input(2, (1 << 22) | 6);
    let e = sign(&tx, 0, s, VALUE, &v.e);
    expect_rejected("K_e with a time-based sequence", run(tx, &[&e, EMPTY], s, &v.spk));
    // Version 1 has no relative locks at all.
    let tx = one_input(1, 6);
    let e = sign(&tx, 0, s, VALUE, &v.e);
    expect_rejected("K_e in a version 1 transaction", run(tx, &[&e, EMPTY], s, &v.spk));
}

#[test]
fn k_e_has_no_path_through_the_cosign_branch() {
    let v = vault(6);
    let s = v.script.as_bytes();
    let tx = one_input(2, SEQ_COSIGNED);
    let (e, u, m) = (sign(&tx, 0, s, VALUE, &v.e), sign(&tx, 0, s, VALUE, &v.u), sign(&tx, 0, s, VALUE, &v.m));
    expect_rejected("K_e twice", run(tx.clone(), &[&e, &e, ONE], s, &v.spk));
    expect_rejected("K_m + K_e in K_u's slot", run(tx.clone(), &[&m, &e, ONE], s, &v.spk));
    expect_rejected("K_e in K_m's slot + K_u", run(tx, &[&e, &u, ONE], s, &v.spk));
}

// ---------------------------------------------------------------- operand abuse

#[test]
fn builder_refuses_every_abusive_csv() {
    for bad in [0u32, 65_536, 1 << 22, (1 << 22) | 1, 1 << 31, (1 << 31) | 6, u32::MAX] {
        assert_eq!(Csv::new(bad), Err(Error::CsvOutOfRange), "csv {bad:#x}");
    }
    assert!(Csv::new(1).is_ok());
    assert!(Csv::new(65_535).is_ok());
}

/// A hostile script with any operand, built with rust-bitcoin since this crate refuses to.
fn hostile_script(v: &Vault, operand: Option<i64>, raw_push: Option<&[u8]>) -> Vec<u8> {
    let pk = |k: &PubKey| bitcoin::PublicKey::from_slice(k.as_bytes()).unwrap();
    let mut b = Builder::new()
        .push_opcode(OP_IF)
        .push_key(&pk(&v.u.public))
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_key(&pk(&v.m.public))
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ELSE);
    if let Some(n) = operand {
        b = b.push_int(n);
    }
    let mut bytes = b.into_script().into_bytes();
    if let Some(raw) = raw_push {
        bytes.extend_from_slice(raw);
    }
    let tail = Builder::new()
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_key(&pk(&v.e.public))
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ENDIF)
        .into_script();
    bytes.extend_from_slice(tail.as_bytes());
    bytes
}

fn p2wsh(script: &[u8]) -> Vec<u8> {
    bitcoin::Script::from_bytes(script).to_p2wsh().into_bytes()
}

/// Negative controls for the bound itself. Each operand below, if it reached a script, lets `K_e`
/// spend with no wait. Asserting that they pass here shows the refusal above protects something.
#[test]
fn operand_abuse_is_why_the_range_exists() {
    let v = vault(6);
    let cases: [(&str, i64, u32, u32); 5] = [
        ("csv=0, v2, seq=0", 0, 2, 0),
        ("csv=bit31, v1, seq=ffffffff", 0x8000_0000, 1, 0xffff_ffff),
        ("csv=bit31, v2, seq=0", 0x8000_0000, 2, 0),
        ("csv=65536 acts as 0, v2, seq=0", 65_536, 2, 0),
        ("csv=65542 acts as 6, v2, seq=6", 65_542, 2, 6),
    ];
    for (name, operand, version, seq) in cases {
        let script = hostile_script(&v, Some(operand), None);
        assert!(WitnessScript::parse(&script).is_err(), "{name}: parser must refuse");
        let tx = one_input(version, seq);
        let e = sign(&tx, 0, &script, VALUE, &v.e);
        let got = run(tx, &[&e, EMPTY], &script, &p2wsh(&script));
        println!("{name}: K_e alone accepted with no wait = {}", got.is_ok());
        assert!(got.is_ok(), "{name}: expected the library to accept, which is the danger: {got:?}");
    }

    // Time-type: the library accepts because the sequence is the same type. On a chain this waits
    // 512 seconds rather than blocks, which is not what the vault promised.
    let script = hostile_script(&v, Some((1 << 22) | 1), None);
    assert!(WitnessScript::parse(&script).is_err());
    let tx = one_input(2, (1 << 22) | 1);
    let e = sign(&tx, 0, &script, VALUE, &v.e);
    run(tx, &[&e, EMPTY], &script, &p2wsh(&script)).unwrap();

    // A negative operand is refused by the opcode itself, so the coins would be stuck, not stolen.
    let script = hostile_script(&v, Some(-1), None);
    assert!(WitnessScript::parse(&script).is_err());
    let tx = one_input(2, 0);
    let e = sign(&tx, 0, &script, VALUE, &v.e);
    expect_rejected("csv=-1", run(tx, &[&e, EMPTY], &script, &p2wsh(&script)));
}

#[test]
fn parser_refuses_every_noncanonical_operand() {
    let v = vault(6);
    let hostile: [(&str, &[u8]); 13] = [
        ("OP_0", &[0x00]),
        ("OP_1NEGATE", &[0x4f]),
        ("6 as a one-byte push", &[1, 6]),
        ("16 as a one-byte push", &[1, 16]),
        ("0 as a one-byte push", &[1, 0]),
        ("negative zero", &[1, 0x80]),
        ("-1 as a one-byte push", &[1, 0x81]),
        ("6 padded to two bytes", &[2, 6, 0]),
        ("127 padded to two bytes", &[2, 127, 0]),
        ("32767 padded to three bytes", &[3, 0xff, 0x7f, 0]),
        ("65536", &[3, 0, 0, 1]),
        ("time-type, bit 22 set", &[3, 1, 0, 0x40]),
        ("bit 31, five bytes", &[5, 0, 0, 0, 0x80, 0]),
    ];
    for (name, push) in hostile {
        let script = hostile_script(&v, None, Some(push));
        assert_eq!(WitnessScript::parse(&script), Err(Error::BadScript), "{name}");
    }
    // The parser's refusal of non-minimal 6 is not just tidiness. The library accepts that form,
    // and only relay policy refuses it. See `library_blind_spots` and the regtest test.
    assert!(WitnessScript::parse(&hostile_script(&v, Some(6), None)).is_ok(), "control: the same helper with 6 parses");
}

#[test]
fn every_single_byte_change_to_the_script_is_refused_or_changes_a_key_or_csv() {
    let v = vault(300);
    let good = v.script.as_bytes().to_vec();
    let mut parsed_ok = 0usize;
    for i in 0..good.len() {
        for delta in 1..=255u8 {
            let mut bad = good.clone();
            bad[i] ^= delta;
            if let Ok(s) = WitnessScript::parse(&bad) {
                parsed_ok += 1;
                let changed_key = s.k_u() != v.script.k_u() || s.k_m() != v.script.k_m() || s.k_e() != v.script.k_e();
                let changed_csv = s.csv() != v.script.csv();
                assert!(changed_key || changed_csv, "byte {i} delta {delta} parsed with nothing changed");
            }
        }
    }
    println!("byte changes that still parse as a script for other keys or another csv: {parsed_ok}");
    for truncated in 0..good.len() {
        assert!(WitnessScript::parse(&good[..truncated]).is_err(), "truncated to {truncated}");
    }
    let mut longer = good.clone();
    longer.push(0x61);
    assert!(WitnessScript::parse(&longer).is_err(), "trailing OP_NOP");
}

#[test]
fn colliding_keys_are_refused_and_this_is_why() {
    let v = vault(6);
    let csv = Csv::new(6).unwrap();
    let (u, m, e) = (v.u.public, v.m.public, v.e.public);
    for (a, b, c) in [(m, m, e), (u, m, u), (u, m, m), (u, u, u)] {
        assert_eq!(WitnessScript::new(a, b, c, csv), Err(Error::DuplicateKey));
    }

    // K_u == K_m, built by hand: MPC alone spends through the first branch.
    let pk = |k: &PubKey| bitcoin::PublicKey::from_slice(k.as_bytes()).unwrap();
    let hand = |ku: &PubKey, km: &PubKey, ke: &PubKey| {
        Builder::new()
            .push_opcode(OP_IF)
            .push_key(&pk(ku))
            .push_opcode(OP_CHECKSIGVERIFY)
            .push_key(&pk(km))
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ELSE)
            .push_int(6)
            .push_opcode(OP_CSV)
            .push_opcode(OP_DROP)
            .push_key(&pk(ke))
            .push_opcode(OP_CHECKSIG)
            .push_opcode(OP_ENDIF)
            .into_script()
            .into_bytes()
    };
    let collapsed = hand(&m, &m, &e);
    assert_eq!(WitnessScript::parse(&collapsed), Err(Error::DuplicateKey));
    let tx = one_input(2, SEQ_COSIGNED);
    let sig = sign(&tx, 0, &collapsed, VALUE, &v.m);
    run(tx, &[&sig, &sig, ONE], &collapsed, &p2wsh(&collapsed)).expect("K_u == K_m lets MPC alone spend");

    // K_m == K_e: MPC alone spends through the second branch.
    let collapsed = hand(&u, &m, &m);
    assert_eq!(WitnessScript::parse(&collapsed), Err(Error::DuplicateKey));
    let tx = one_input(2, 6);
    let sig = sign(&tx, 0, &collapsed, VALUE, &v.m);
    run(tx, &[&sig, EMPTY], &collapsed, &p2wsh(&collapsed)).expect("K_m == K_e lets MPC alone spend after CSV");

    // K_u == K_e: the spend key has an escape leaf.
    let collapsed = hand(&u, &m, &u);
    assert_eq!(WitnessScript::parse(&collapsed), Err(Error::DuplicateKey));
    let tx = one_input(2, 6);
    let sig = sign(&tx, 0, &collapsed, VALUE, &v.u);
    run(tx, &[&sig, EMPTY], &collapsed, &p2wsh(&collapsed)).expect("K_u == K_e gives the spend key an escape");
}

#[test]
fn bad_public_keys_are_refused() {
    assert_eq!(PubKey::from_slice(&[2; 32]), Err(Error::BadPubKey));
    assert_eq!(PubKey::from_slice(&[4; 33]), Err(Error::BadPubKey));
    assert_eq!(PubKey::from_slice(&[0; 33]), Err(Error::BadPubKey));
    let mut uncompressed = [0x11; 65];
    uncompressed[0] = 4;
    assert_eq!(PubKey::from_slice(&uncompressed), Err(Error::BadPubKey));
}

// ---------------------------------------------------------------- witness and digest controls

#[test]
fn witness_shape_matters() {
    let v = vault(6);
    let s = v.script.as_bytes();

    let tx = one_input(2, SEQ_COSIGNED);
    let (m, u) = (sign(&tx, 0, s, VALUE, &v.m), sign(&tx, 0, s, VALUE, &v.u));
    run(tx.clone(), &[&m, &u, ONE], s, &v.spk).expect("positive twin");
    expect_rejected("signatures swapped", run(tx.clone(), &[&u, &m, ONE], s, &v.spk));
    expect_rejected("selector picks the wrong branch", run(tx.clone(), &[&m, &u, EMPTY], s, &v.spk));
    expect_rejected("extra item under the signatures", run(tx.clone(), &[ONE, &m, &u, ONE], s, &v.spk));
    expect_rejected("witness has no script", {
        let mut t = tx.clone();
        t.inputs[0].witness = vec![m.clone(), u.clone(), vec![1]];
        consensus(&t, 0, &v.spk, VALUE)
    });

    let other = vault(7);
    expect_rejected("another vault's script", run(tx.clone(), &[&m, &u, ONE], other.script.as_bytes(), &v.spk));

    let tx = one_input(2, 6);
    let e = sign(&tx, 0, s, VALUE, &v.e);
    run(tx.clone(), &[&e, EMPTY], s, &v.spk).expect("positive twin");
    expect_rejected("escape with the co-sign selector", run(tx, &[&e, ONE], s, &v.spk));
}

#[test]
fn digest_commits_to_what_it_should() {
    let v = vault(6);
    let s = v.script.as_bytes();
    let base = one_input(2, SEQ_COSIGNED);
    let (m, u) = (sign(&base, 0, s, VALUE, &v.m), sign(&base, 0, s, VALUE, &v.u));
    run(base.clone(), &[&m, &u, ONE], s, &v.spk).expect("positive twin");

    let mut t = base.clone();
    t.outputs[0].value -= 1;
    expect_rejected("output value changed after signing", run(t, &[&m, &u, ONE], s, &v.spk));

    let mut t = base.clone();
    t.outputs[0].script_pubkey[5] ^= 1;
    expect_rejected("output script changed after signing", run(t, &[&m, &u, ONE], s, &v.spk));

    let mut t = base.clone();
    t.lock_time = 1;
    expect_rejected("locktime changed after signing", run(t, &[&m, &u, ONE], s, &v.spk));

    let mut t = base.clone();
    t.inputs[0].sequence = SEQ_COSIGNED - 1;
    expect_rejected("sequence changed after signing", run(t, &[&m, &u, ONE], s, &v.spk));

    let mut t = base.clone();
    t.inputs[0].previous.vout += 1;
    expect_rejected("input changed after signing", run(t, &[&m, &u, ONE], s, &v.spk));

    // A false declared value gives a signature that fails against the real value.
    let (fm, fu) = (sign(&base, 0, s, VALUE - 1, &v.m), sign(&base, 0, s, VALUE - 1, &v.u));
    expect_rejected("signed for a false input value", run(base.clone(), &[&fm, &fu, ONE], s, &v.spk));
    // One honest half is not enough either.
    expect_rejected("K_m honest, K_u false value", run(base, &[&m, &fu, ONE], s, &v.spk));
}

#[test]
fn signature_does_not_move_between_inputs() {
    let v = vault(6);
    let s = v.script.as_bytes();
    let mut tx = Tx::cosigned(&[outpoint(1), outpoint(2)], pay_out(2 * VALUE - 1_000));
    let (m0, u0) = (sign_der(&tx, 0, s, VALUE, &v.m), sign_der(&tx, 0, s, VALUE, &v.u));
    tx.set_cosigned_witness(0, &m0, &u0, &v.script).unwrap();
    tx.set_cosigned_witness(1, &m0, &u0, &v.script).unwrap();
    consensus(&tx, 0, &v.spk, VALUE).unwrap();
    assert!(consensus(&tx, 1, &v.spk, VALUE).is_err(), "input 0's signatures on input 1");
}

#[test]
fn crate_api_refuses_an_escape_it_knows_is_invalid() {
    let v = vault(6);
    let sig = sign_der(&one_input(2, 6), 0, v.script.as_bytes(), VALUE, &v.e);
    assert_eq!(one_input(2, 5).set_escape_witness(0, &sig, &v.script), Err(Error::BadShape));
    assert_eq!(one_input(1, 6).set_escape_witness(0, &sig, &v.script), Err(Error::BadShape));
    assert_eq!(one_input(2, 6).set_escape_witness(1, &sig, &v.script), Err(Error::InputIndex));
    assert_eq!(one_input(2, 6).set_cosigned_witness(1, &sig, &sig, &v.script), Err(Error::InputIndex));
    assert_eq!(one_input(2, 6).sighash::<Sha2>(1, v.script.as_bytes(), VALUE), Err(Error::InputIndex));
    assert_eq!(one_input(2, 6).sighashes::<Sha2>(v.script.as_bytes(), &[1, 2]), Err(Error::InputIndex));
}

// ---------------------------------------------------------------- what the library cannot do

/// Each of these passes the library and would fail on a real node. Asserting the pass records the
/// limit, so that nobody reads `[consensus-lib]` as more than it is. `tests/regtest.rs` runs the
/// same five against bitcoind and asserts the node refuses each.
#[test]
fn library_blind_spots() {
    let v = vault(6);
    let s = v.script.as_bytes();

    // MINIMALIF, a policy rule: selector 02 instead of 01.
    let tx = one_input(2, SEQ_COSIGNED);
    let (m, u) = (sign(&tx, 0, s, VALUE, &v.m), sign(&tx, 0, s, VALUE, &v.u));
    run(tx, &[&m, &u, &[2]], s, &v.spk).expect("library cannot see MINIMALIF");

    // LOW_S, a policy rule: the high-s form of a valid signature.
    let tx = one_input(2, SEQ_COSIGNED);
    let high = high_s_form(&sign(&tx, 0, s, VALUE, &v.m));
    let u = sign(&tx, 0, s, VALUE, &v.u);
    run(tx, &[&high, &u, ONE], s, &v.spk).expect("library cannot see LOW_S");

    // MINIMALDATA, a policy rule: csv 6 pushed as 01 06.
    let script = hostile_script(&v, None, Some(&[1, 6]));
    let tx = one_input(2, 6);
    let e = sign(&tx, 0, &script, VALUE, &v.e);
    run(tx, &[&e, EMPTY], &script, &p2wsh(&script)).expect("library cannot see MINIMALDATA");

    // BIP-68, a consensus rule the library has no chain for: a coin of unknown age, even one
    // mined in the previous block, passes with seq = csv.
    let tx = one_input(2, 6);
    let e = sign(&tx, 0, s, VALUE, &v.e);
    run(tx, &[&e, EMPTY], s, &v.spk).expect("library cannot see coin age");

    // Value sums, also consensus: outputs above the input's value pass, because the library sees
    // one input's script and nothing else.
    let mut tx = Tx::cosigned(&[outpoint(1)], pay_out(VALUE * 2));
    let (m, u) = (sign_der(&tx, 0, s, VALUE, &v.m), sign_der(&tx, 0, s, VALUE, &v.u));
    tx.set_cosigned_witness(0, &m, &u, &v.script).unwrap();
    consensus(&tx, 0, &v.spk, VALUE).expect("library cannot see value sums");
}

// ---------------------------------------------------------------- agreement with rust-bitcoin

#[test]
fn csv_encoding_matches_rust_bitcoin_for_every_value() {
    let v = vault(1);
    let mut lengths = [0usize; 4];
    for csv in 1u32..=65_535 {
        let ours = WitnessScript::new(v.u.public, v.m.public, v.e.public, Csv::new(csv).unwrap()).unwrap();
        let theirs = hostile_script(&v, Some(i64::from(csv)), None);
        assert_eq!(ours.as_bytes(), &theirs[..], "csv {csv}");
        assert_eq!(WitnessScript::parse(&theirs).unwrap().csv().blocks(), csv);
        lengths[ours.as_bytes().len() - 111] += 1;
    }
    println!("script length counts over 1..=65535: 111:{} 112:{} 113:{} 114:{}", lengths[0], lengths[1], lengths[2], lengths[3]);
    assert_eq!(lengths, [16, 111, 32_640, 32_768]);
}

#[test]
fn script_pubkey_and_address_match_rust_bitcoin() {
    use bitcoin::{Address, Network as BN};
    use undo_btc::address::p2wsh_address;
    use undo_btc::Network;
    for csv in [1u32, 6, 300, 65_535] {
        let v = vault(csv);
        let script = bitcoin::Script::from_bytes(v.script.as_bytes());
        assert_eq!(v.spk, script.to_p2wsh().into_bytes());
        let program = v.script.program::<Sha2>();
        for (ours, theirs) in [
            (Network::Mainnet, BN::Bitcoin),
            (Network::Mutinynet, BN::Signet),
            (Network::Signet, BN::Signet),
            (Network::Testnet4, BN::Testnet4),
            (Network::Regtest, BN::Regtest),
        ] {
            assert_eq!(p2wsh_address(ours, &program), Address::p2wsh(script, theirs).to_string());
        }
    }
}

#[test]
fn network_names_round_trip() {
    use undo_btc::Network;
    for n in [Network::Mainnet, Network::Mutinynet, Network::Signet, Network::Testnet4, Network::Regtest] {
        assert_eq!(Network::from_name(n.name()), Ok(n));
    }
    assert_eq!(Network::from_name("testnet3"), Err(Error::BadNetwork));
}

#[test]
fn digest_serialization_txid_and_size_match_rust_bitcoin() {
    use bitcoin::consensus::encode::{deserialize, serialize};
    use bitcoin::hashes::Hash;
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};

    let v = vault(6);
    let s = v.script.as_bytes();
    let values = [40_000u64, 50_000, 60_000];
    let outs = vec![
        TxOut { value: 100_000, script_pubkey: destination() },
        TxOut { value: 49_000, script_pubkey: v.spk.clone() },
    ];
    for mut tx in [
        Tx::cosigned(&[outpoint(1), outpoint(2), outpoint(3)], outs.clone()),
        Tx::escape(&[outpoint(1), outpoint(2), outpoint(3)], Csv::new(6).unwrap(), outs),
    ] {
        let theirs: bitcoin::Transaction = deserialize(&tx.serialize()).unwrap();
        for (i, value) in values.into_iter().enumerate() {
            let digest = SighashCache::new(&theirs)
                .p2wsh_signature_hash(i, bitcoin::Script::from_bytes(s), bitcoin::Amount::from_sat(value), EcdsaSighashType::All)
                .unwrap();
            assert_eq!(tx.sighash::<Sha2>(i, s, value).unwrap(), digest.to_byte_array(), "input {i}");
        }
        for (i, value) in values.into_iter().enumerate() {
            let (a, b) = (sign_der(&tx, i, s, value, &v.m), sign_der(&tx, i, s, value, &v.u));
            tx.set_cosigned_witness(i, &a, &b, &v.script).unwrap();
        }
        let theirs: bitcoin::Transaction = deserialize(&tx.serialize()).unwrap();
        assert_eq!(serialize(&theirs), tx.serialize(), "full serialization");
        assert_eq!(tx.txid::<Sha2>().0, theirs.compute_txid().to_byte_array(), "txid");
        assert_eq!(tx.txid::<Sha2>().to_display_hex(), theirs.compute_txid().to_string(), "display order");
        assert_eq!(tx.weight(), theirs.weight().to_wu() as usize);
        assert_eq!(tx.vsize(), theirs.vsize());
    }
}

#[test]
fn compact_size_above_one_byte_matches_rust_bitcoin() {
    use bitcoin::consensus::encode::{deserialize, serialize};
    // 300 inputs and a 300-byte output script both cross the 0xfd boundary.
    let inputs: Vec<_> = (0..300u32).map(|i| undo_btc::OutPoint { txid: undo_btc::Txid([1; 32]), vout: i }).collect();
    let tx = Tx::cosigned(&inputs, vec![TxOut { value: 1, script_pubkey: vec![0x51; 300] }]);
    let theirs: bitcoin::Transaction = deserialize(&tx.serialize()).unwrap();
    assert_eq!(serialize(&theirs), tx.serialize());
    assert_eq!(theirs.input.len(), 300);
}

#[test]
fn compact_size_at_each_exact_boundary_matches_rust_bitcoin() {
    use bitcoin::consensus::encode::{deserialize, serialize};
    for len in [0usize, 252, 253, 254, 255, 256, 65_535, 65_536] {
        let tx = Tx::cosigned(&[outpoint(1)], vec![TxOut { value: 1, script_pubkey: vec![0x51; len] }]);
        let theirs: bitcoin::Transaction = deserialize(&tx.serialize()).unwrap_or_else(|e| panic!("len {len}: {e}"));
        assert_eq!(theirs.output[0].script_pubkey.len(), len);
        assert_eq!(serialize(&theirs), tx.serialize(), "len {len}");
    }
}

#[test]
fn transaction_shapes_are_what_the_spec_says() {
    let outs = pay_out(1_000);
    let c = Tx::cosigned(&[outpoint(1), outpoint(2)], outs.clone());
    assert_eq!((c.version, c.lock_time), (2, 0));
    assert!(c.inputs.iter().all(|i| i.sequence == 0xffff_fffd && i.witness.is_empty()));
    let e = Tx::escape(&[outpoint(1), outpoint(2)], Csv::new(300).unwrap(), outs);
    assert_eq!((e.version, e.lock_time), (2, 0));
    assert!(e.inputs.iter().all(|i| i.sequence == 300 && i.witness.is_empty()));
    // No witness anywhere means no segwit marker, and the stripped form is what a txid hashes.
    assert_eq!(c.serialize(), c.serialize_stripped());
    assert_eq!(Csv::new(65_535).unwrap().sequence(), 0xffff);
    assert_eq!(Csv::new(65_535).unwrap().blocks(), 65_535);
}

#[test]
fn txid_display_order_is_reversed_and_strict() {
    let text = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    let id = undo_btc::Txid::from_display_hex(text).unwrap();
    assert_eq!(id.0[0], 0x1f);
    assert_eq!(id.0[31], 0x00);
    assert_eq!(id.to_display_hex(), text);
    assert_eq!(undo_btc::Txid::from_display_hex(&text.to_uppercase()), Err(Error::BadHex));
    assert_eq!(undo_btc::Txid::from_display_hex(&text[2..]), Err(Error::BadHex));
    assert_eq!(undo_btc::Txid::from_display_hex("0"), Err(Error::BadHex));
}

#[test]
fn measured_sizes() {
    // Spec 1.2 estimated about 107 vB per co-signed input and about 191 vB for 1-in, 2-out, which
    // holds for a P2WPKH destination. A P2WSH or P2TR destination is 12 vB larger.
    let v = vault(6);
    let s = v.script.as_bytes();
    let change = TxOut { value: 49_000, script_pubkey: v.spk.clone() };
    let mut p2wpkh = vec![0x00, 0x14];
    p2wpkh.extend_from_slice(&[0x99; 20]);
    let spend = |inputs: &[undo_btc::OutPoint], dest: Vec<u8>| {
        let outs = vec![TxOut { value: 50_000, script_pubkey: dest }, change.clone()];
        let mut tx = Tx::cosigned(inputs, outs);
        for i in 0..inputs.len() {
            let (m, u) = (sign_der(&tx, i, s, VALUE, &v.m), sign_der(&tx, i, s, VALUE, &v.u));
            tx.set_cosigned_witness(i, &m, &u, &v.script).unwrap();
        }
        tx.vsize()
    };
    let one_wpkh = spend(&[outpoint(1)], p2wpkh.clone());
    let one_wsh = spend(&[outpoint(1)], destination());
    let per_input = spend(&[outpoint(1), outpoint(2)], p2wpkh) - one_wpkh;

    let mut esc = Tx::escape(&[outpoint(1)], Csv::new(6).unwrap(), pay_out(VALUE - 500));
    let e = sign_der(&esc, 0, s, VALUE, &v.e);
    esc.set_escape_witness(0, &e, &v.script).unwrap();

    println!(
        "co-signed 1-in 2-out: {one_wpkh} vB to P2WPKH, {one_wsh} vB to P2WSH; each further input {per_input} vB; escape 1-in 1-out to P2WSH: {} vB",
        esc.vsize()
    );
    assert!((185..=195).contains(&one_wpkh), "{one_wpkh}");
    assert_eq!(one_wsh, one_wpkh + 12);
    assert!((104..=108).contains(&per_input), "{per_input}");
}
