//! Attack review, script level. Each test names its finding in tests/REGRESSION-MAP.md.
//! These run under libbitcoinconsensus with no node. A test whose name ends in `_valid` is a control:
//! it shows the attack really is valid to Bitcoin, so whatever stops it has to be somewhere else.

use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::script::{Builder, PushBytesBuf};
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message, PublicKey as SPk, Secp256k1, SecretKey};
use bitcoin::sighash::SighashCache;
use bitcoin::*;
use sandbox_tests::test_key;
use undo_btc::{Csv, DerSig, PubKey, Sha2, WitnessScript};

struct K {
    sk: SecretKey,
    pk: bitcoin::PublicKey,
}

fn key(label: &str) -> K {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&test_key(label)).unwrap();
    K { sk, pk: bitcoin::PublicKey::new(SPk::from_secret_key(&secp, &sk)) }
}

fn pk(k: &K) -> PubKey {
    PubKey::from_slice(&k.pk.to_bytes()).unwrap()
}

/// Hand-built, with no range check, for showing what the checks are for.
fn raw_script(u: &K, e: &K, m: &K, csv: i64) -> ScriptBuf {
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

/// The repo's script, checked against the hand-built one.
fn ws(u: &K, e: &K, m: &K, csv: u32) -> ScriptBuf {
    let built = WitnessScript::new(pk(u), pk(m), pk(e), Csv::new(csv).unwrap()).unwrap();
    let script = ScriptBuf::from_bytes(built.as_bytes().to_vec());
    assert_eq!(script, raw_script(u, e, m, csv as i64));
    assert_eq!(built.script_pubkey::<Sha2>(), script.to_p2wsh().to_bytes());
    script
}

fn op(i: u8) -> OutPoint {
    OutPoint { txid: Txid::from_byte_array([i; 32]), vout: i as u32 }
}

fn tx(inputs: usize, out: &[(u64, ScriptBuf)], seq: u32, ver: i32) -> Transaction {
    Transaction {
        version: transaction::Version(ver),
        lock_time: absolute::LockTime::ZERO,
        input: (0..inputs)
            .map(|i| TxIn { previous_output: op(i as u8 + 1), script_sig: ScriptBuf::new(), sequence: Sequence(seq), witness: Witness::new() })
            .collect(),
        output: out.iter().map(|(v, s)| TxOut { value: Amount::from_sat(*v), script_pubkey: s.clone() }).collect(),
    }
}

/// DER + SIGHASH_ALL over the BIP-143 digest, using the value the signer was told.
fn sign(t: &Transaction, i: usize, script: &ScriptBuf, declared: u64, k: &K) -> Vec<u8> {
    let d = SighashCache::new(t).p2wsh_signature_hash(i, script, Amount::from_sat(declared), EcdsaSighashType::All).unwrap();
    let sig = Secp256k1::new().sign_ecdsa(&Message::from_digest(d.to_byte_array()), &k.sk);
    let mut der = sig.serialize_der().to_vec();
    der.push(0x01);
    der
}

fn check(t: &Transaction, spk: &ScriptBuf, reals: &[u64]) -> Result<(), String> {
    t.verify(|o| {
        (0..reals.len())
            .find(|i| op(*i as u8 + 1) == *o)
            .map(|i| TxOut { value: Amount::from_sat(reals[i]), script_pubkey: spk.clone() })
    })
    .map_err(|e| format!("{e:?}"))
}

fn wit(items: &[&[u8]]) -> Witness {
    let mut w = Witness::new();
    for i in items {
        w.push(i);
    }
    w
}

const ONE: &[u8] = &[1];
const NIL: &[u8] = &[];
const COSIGNED: u32 = 0xfffffffd;

fn dest() -> ScriptBuf {
    ScriptBuf::new_p2wsh(&WScriptHash::from_byte_array([9; 32]))
}

/// The two branches do what the drawing says, and the old lost-laptop branch is gone.
#[test]
fn f4_two_branches_behave_as_drawn() {
    let (u, e, m) = (key("u"), key("e"), key("m"));
    let s = ws(&u, &e, &m, 6);
    let spk = s.to_p2wsh();
    let v = 100_000u64;
    let run = |name: &str, seq: u32, stack: &dyn Fn(&Transaction) -> Vec<Vec<u8>>, want: bool| {
        let mut t = tx(1, &[(v - 1000, dest())], seq, 2);
        let st = stack(&t);
        let mut refs: Vec<&[u8]> = st.iter().map(|x| x.as_slice()).collect();
        refs.push(s.as_bytes());
        t.input[0].witness = wit(&refs);
        assert_eq!(check(&t, &spk, &[v]).is_ok(), want, "{name}");
    };
    run("normal sig_m sig_u 01", COSIGNED, &|t| vec![sign(t, 0, &s, v, &m), sign(t, 0, &s, v, &u), vec![1]], true);
    run("escape sig_e '' seq=6", 6, &|t| vec![sign(t, 0, &s, v, &e), vec![]], true);
    run("escape seq=5 too low", 5, &|t| vec![sign(t, 0, &s, v, &e), vec![]], false);
    run("MPC alone in normal branch", COSIGNED, &|t| vec![sign(t, 0, &s, v, &m), sign(t, 0, &s, v, &m), vec![1]], false);
    run("MPC alone in escape branch", 6, &|t| vec![sign(t, 0, &s, v, &m), vec![]], false);
    run("K_u alone in escape branch after CSV", 6, &|t| vec![sign(t, 0, &s, v, &u), vec![]], false);
    run("K_u twice", COSIGNED, &|t| vec![sign(t, 0, &s, v, &u), sign(t, 0, &s, v, &u), vec![1]], false);
    // Finding 4's young-coin path needed K_e in the co-sign branch. It has no such slot now.
    run("K_e with K_m in the co-sign branch", COSIGNED, &|t| vec![sign(t, 0, &s, v, &m), sign(t, 0, &s, v, &e), vec![1]], false);
    run("K_e half-signature replayed in the escape leaf", COSIGNED, &|t| vec![sign(t, 0, &s, v, &e), vec![]], false);
}

/// BIP-143 commits only to the value of the input being signed. Bitcoin itself accepts this.
#[test]
fn f0_fee_swap_two_sessions_valid() {
    let (u, e, m) = (key("u"), key("e"), key("m"));
    let s = ws(&u, &e, &m, 2016);
    let spk = s.to_p2wsh();
    let real = [1_000_000u64, 1_000_000u64];
    let (d1, d2) = ([1_000_000u64, 1_500u64], [1_500u64, 1_000_000u64]);
    let fee = 1_000u64;
    let o = d1[0] + d1[1] - fee;
    assert_eq!(o, d2[0] + d2[1] - fee, "same outputs in both requests");
    let mut t = tx(2, &[(o, spk.clone())], COSIGNED, 2);
    let full = |t: &Transaction, i: usize, d: &[u64; 2]| wit(&[&sign(t, i, &s, d[i], &m), &sign(t, i, &s, d[i], &u), ONE, s.as_bytes()]);
    let mut r1 = t.clone();
    r1.input[0].witness = full(&t, 0, &d1);
    r1.input[1].witness = full(&t, 1, &d1);
    let mut r2 = t.clone();
    r2.input[0].witness = full(&t, 0, &d2);
    r2.input[1].witness = full(&t, 1, &d2);
    assert!(check(&r1, &spk, &real).is_err() && check(&r2, &spk, &real).is_err(), "each session alone is invalid");
    let (w0, w1) = (full(&t, 0, &d1), full(&t, 1, &d2));
    t.input[0].witness = w0;
    t.input[1].witness = w1;
    check(&t, &spk, &real).expect("the combination is valid to Bitcoin");
    assert_eq!(real[0] + real[1] - o, 999_500, "real fee at a declared fee of 1,000");
    let _ = serialize(&t);
}

/// k sessions over balanced subsets: real fee about (k-1)/k of the coins.
#[test]
fn f0_fee_swap_many_inputs_valid() {
    let (u, e, m) = (key("u"), key("e"), key("m"));
    let s = ws(&u, &e, &m, 2016);
    let spk = s.to_p2wsh();
    let (n, each) = (16usize, 500_000u64);
    let real = vec![each; n];
    for k in [2usize, 4, 8] {
        let group = n / k;
        let o = each * group as u64 + (n - group) as u64 * 600 - 1000;
        let mut t = tx(n, &[(o, spk.clone())], COSIGNED, 2);
        let base = t.clone();
        for i in 0..n {
            t.input[i].witness = wit(&[&sign(&base, i, &s, each, &m), &sign(&base, i, &s, each, &u), ONE, s.as_bytes()]);
        }
        check(&t, &spk, &real).expect("valid to Bitcoin");
        let burned = (each * n as u64 - o) * 100 / (each * n as u64);
        assert!(burned as usize + 1 >= 100 * (k - 1) / k - 1, "{k} sessions burn about (k-1)/k, got {burned}%");
    }
}

/// One big coin plus attacker dust: the burn is bounded by the smaller side.
#[test]
fn f0_fee_swap_big_coin_plus_dust_valid() {
    let (u, e, m) = (key("u"), key("e"), key("m"));
    let s = ws(&u, &e, &m, 2016);
    let spk = s.to_p2wsh();
    let real = [50_000u64, 1_000u64];
    let fee = 3_000u64;
    let o = real[0] + 1 - fee;
    let mut t = tx(2, &[(o, spk.clone())], COSIGNED, 2);
    let b = t.clone();
    t.input[0].witness = wit(&[&sign(&b, 0, &s, real[0], &m), &sign(&b, 0, &s, real[0], &u), ONE, s.as_bytes()]);
    t.input[1].witness = wit(&[&sign(&b, 1, &s, real[1], &m), &sign(&b, 1, &s, real[1], &u), ONE, s.as_bytes()]);
    check(&t, &spk, &real).expect("valid to Bitcoin");
}

/// Each abusive operand lets K_e spend with no wait, so the crate refuses to build one.
#[test]
fn f15_csv_operand_abuse() {
    let (u, e, m) = (key("u"), key("e"), key("m"));
    let v = 100_000u64;
    for (name, csv, ver, seq, library_accepts) in [
        ("csv=0 v2 seq=0", 0i64, 2, 0u32, true),
        ("csv=bit31 v1 seq=ffffffff", 0x8000_0000i64, 1, 0xffff_ffff, true),
        ("csv=bit31 v2 seq=0", 0x8000_0000i64, 2, 0, true),
        ("csv=time-type v2 seq same", (1i64 << 22) | 1, 2, (1u32 << 22) | 1, true),
        ("csv=-1 v2 seq=0", -1i64, 2, 0, false),
    ] {
        let s = raw_script(&u, &e, &m, csv);
        let spk = s.to_p2wsh();
        let mut t = tx(1, &[(v - 1000, dest())], seq, ver);
        let sig = sign(&t, 0, &s, v, &e);
        t.input[0].witness = wit(&[&sig, NIL, s.as_bytes()]);
        assert_eq!(check(&t, &spk, &[v]).is_ok(), library_accepts, "{name}");
        assert!(u32::try_from(csv).map_or(true, |c| Csv::new(c).is_err()), "{name} must not build");
    }
}

/// What the consensus library cannot see, and that this repo's bytes are not in that gap.
#[test]
fn f15_consensus_lib_blind_spots() {
    let (u, e, m) = (key("u"), key("e"), key("m"));
    let v = 100_000u64;
    let s = ws(&u, &e, &m, 6);
    let spk = s.to_p2wsh();

    // MINIMALIF: selector 0x02 instead of 0x01. The library accepts it, relay would not.
    let mut t = tx(1, &[(v - 1000, dest())], COSIGNED, 2);
    let (a, b) = (sign(&t, 0, &s, v, &m), sign(&t, 0, &s, v, &u));
    t.input[0].witness = wit(&[&a, &b, &[2], s.as_bytes()]);
    assert!(check(&t, &spk, &[v]).is_ok(), "library does not check MINIMALIF");

    // LOW_S: the library accepts high S. DerSig never emits it.
    let mut t = tx(1, &[(v - 1000, dest())], COSIGNED, 2);
    let d = SighashCache::new(&t).p2wsh_signature_hash(0, &s, Amount::from_sat(v), EcdsaSighashType::All).unwrap();
    let compact = Secp256k1::new().sign_ecdsa(&Message::from_digest(d.to_byte_array()), &m.sk).serialize_compact();
    let order = bitcoin::secp256k1::constants::CURVE_ORDER;
    let mut hs = [0u8; 32];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let x = order[i] as i16 - compact[32 + i] as i16 - borrow;
        borrow = (x < 0) as i16;
        hs[i] = x.rem_euclid(256) as u8;
    }
    let der_int = |x: &[u8]| {
        let mut y = x.to_vec();
        while y.len() > 1 && y[0] == 0 && y[1] < 0x80 {
            y.remove(0);
        }
        if y[0] >= 0x80 {
            y.insert(0, 0);
        }
        let mut o = vec![2, y.len() as u8];
        o.extend(y);
        o
    };
    let (r_, s_) = (der_int(&compact[..32]), der_int(&hs));
    let mut der = vec![0x30, (r_.len() + s_.len()) as u8];
    der.extend(r_);
    der.extend(s_);
    der.push(1);
    let b = sign(&t, 0, &s, v, &u);
    t.input[0].witness = wit(&[&der, &b, ONE, s.as_bytes()]);
    assert!(check(&t, &spk, &[v]).is_ok(), "library does not check LOW_S");
    let r: [u8; 32] = compact[..32].try_into().unwrap();
    let low = DerSig::from_rs(&r, &hs).unwrap();
    assert!(low.was_high_s(), "the crate saw a high S");
    assert_eq!(low.as_bytes().last(), Some(&1));
    assert_ne!(low.as_bytes(), der.as_slice(), "the crate encodes the low form");

    // MINIMALDATA: 6 pushed as 01 06 rather than OP_6. The crate's script uses OP_6.
    let mut pb = PushBytesBuf::new();
    pb.push(6).unwrap();
    let nm = Builder::new()
        .push_opcode(OP_IF)
        .push_key(&u.pk)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_key(&m.pk)
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ELSE)
        .push_slice(&pb)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_key(&e.pk)
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ENDIF)
        .into_script();
    let spk2 = nm.to_p2wsh();
    let mut t = tx(1, &[(v - 1000, dest())], 6, 2);
    let a = sign(&t, 0, &nm, v, &e);
    t.input[0].witness = wit(&[&a, NIL, nm.as_bytes()]);
    assert!(check(&t, &spk2, &[v]).is_ok(), "library does not check MINIMALDATA");
    assert_ne!(nm, s, "the crate's script is the minimal one");
    assert!(WitnessScript::parse(nm.as_bytes()).is_err(), "and it refuses this encoding");

    // BIP-68: the library has no chain, so a coin of unknown age passes. Age is a regtest claim.
    let mut t = tx(1, &[(v - 1000, dest())], 6, 2);
    let a = sign(&t, 0, &s, v, &e);
    t.input[0].witness = wit(&[&a, NIL, s.as_bytes()]);
    assert!(check(&t, &spk, &[v]).is_ok(), "library does not check coin age");
}

/// Keys that collapse the 2-of-2 are valid to Bitcoin, so the crate refuses to build them. The
/// contract's refusal is `f1_create_vault_refuses_foreign_or_junk` in review_contract.rs.
#[test]
fn f1_key_collisions_valid_but_cannot_be_built() {
    let (u, e, m) = (key("u"), key("e"), key("m"));
    let v = 100_000u64;
    let csv = Csv::new(6).unwrap();

    let s = raw_script(&m, &e, &m, 6);
    let spk = s.to_p2wsh();
    let mut t = tx(1, &[(v - 1000, dest())], COSIGNED, 2);
    let a = sign(&t, 0, &s, v, &m);
    t.input[0].witness = wit(&[&a, &a, ONE, s.as_bytes()]);
    assert!(check(&t, &spk, &[v]).is_ok(), "K_u == K_m: MPC alone spends");
    assert_eq!(WitnessScript::new(pk(&m), pk(&m), pk(&e), csv), Err(undo_btc::Error::DuplicateKey));
    assert_eq!(WitnessScript::new(pk(&u), pk(&m), pk(&m), csv), Err(undo_btc::Error::DuplicateKey));
    assert_eq!(WitnessScript::new(pk(&u), pk(&m), pk(&u), csv), Err(undo_btc::Error::DuplicateKey));

    // An attacker's K_m: a spend with no NEAR at all. Only the signer callback can catch this one.
    let att = key("attacker");
    let s = raw_script(&u, &e, &att, 6);
    let spk = s.to_p2wsh();
    let mut t = tx(1, &[(v - 1000, dest())], COSIGNED, 2);
    let (a, b) = (sign(&t, 0, &s, v, &att), sign(&t, 0, &s, v, &u));
    t.input[0].witness = wit(&[&a, &b, ONE, s.as_bytes()]);
    assert!(check(&t, &spk, &[v]).is_ok(), "K_m substituted at creation");
}
