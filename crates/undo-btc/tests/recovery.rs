//! The recovery file: it round-trips, refuses every disagreement, never prints the secret, and
//! its dry run escapes from the file alone. No test here has a chain, so coin age is not covered.
//! `tests/regtest.rs` spends a real regtest coin from this same file.

mod common;

use common::*;
use std::process::Command;
use undo_btc::recovery::{dry_run_escape, dry_run_with, Coin, RecoveryError, RecoveryFile};
use undo_btc::{hex_encode, Csv, Network, Sha2, Sha256, WitnessScript};

fn file(csv: u32) -> (RecoveryFile, Vault) {
    let v = vault(csv);
    let f = RecoveryFile::new(Network::Mutinynet, "vault-test-1", v.script.clone(), &v.e.secret.secret_bytes()).unwrap();
    (f, v)
}

fn json_of(f: &RecoveryFile) -> serde_json::Value {
    serde_json::from_str(&f.to_json()).unwrap()
}

/// Sets one field and writes a matching checksum, as an attacker or a buggy tool could.
fn edited(f: &RecoveryFile, field: &str, value: serde_json::Value) -> String {
    let mut j = json_of(f);
    j[field] = value;
    rechecksum(&mut j);
    j.to_string()
}

fn rechecksum(j: &mut serde_json::Value) {
    let line = |k: &str| match &j[k] {
        serde_json::Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    let text = format!(
        "undo-recovery-v1\n{}\n{}\n{}\n{}\n{}\n{}\n",
        line("network"),
        line("vault_id"),
        line("csv"),
        line("witness_script"),
        line("address"),
        line("cold_key")
    );
    j["checksum"] = hex_encode(&Sha2::sha256(text.as_bytes())).into();
}

fn refused(text: &str) -> RecoveryError {
    RecoveryFile::parse(text).unwrap_err()
}

#[test]
fn round_trip() {
    let (f, v) = file(6);
    let text = f.to_json();
    let back = RecoveryFile::parse(&text).unwrap();
    assert_eq!(back.script(), &v.script);
    assert_eq!(back.network(), Network::Mutinynet);
    assert_eq!(back.vault_id(), "vault-test-1");
    assert_eq!(back.to_json(), text, "writing is stable");
    assert!(f.address().starts_with("tb1q"));
}

#[test]
fn layout_does_not_affect_the_checksum() {
    let (f, _) = file(6);
    let compact = json_of(&f).to_string();
    assert_ne!(compact, f.to_json());
    RecoveryFile::parse(&compact).unwrap();
}

#[test]
fn checksum_catches_damage_to_any_field() {
    let (f, _) = file(6);
    let j = json_of(&f);
    for field in ["network", "vault_id", "witness_script", "address", "cold_key"] {
        let mut d = j.clone();
        let s = d[field].as_str().unwrap().to_owned();
        let changed = if s.ends_with('0') { format!("{}1", &s[..s.len() - 1]) } else { format!("{}0", &s[..s.len() - 1]) };
        d[field] = changed.into();
        assert_eq!(refused(&d.to_string()), RecoveryError::Checksum, "{field}");
    }
    let mut d = j.clone();
    d["csv"] = 7.into();
    assert_eq!(refused(&d.to_string()), RecoveryError::Checksum, "csv");
    let mut d = j.clone();
    d["checksum"] = "00".into();
    assert_eq!(refused(&d.to_string()), RecoveryError::Checksum, "checksum");
    let mut d = j;
    d["checksum"] = d["checksum"].as_str().unwrap().to_uppercase().into();
    assert_eq!(refused(&d.to_string()), RecoveryError::Checksum, "uppercase checksum");
}

/// With a good checksum, each disagreement still has to be caught by its own check.
#[test]
fn fields_must_agree_even_with_a_valid_checksum() {
    let (f, _) = file(6);
    let other = vault(7);
    let other_key = key("someone else");

    assert_eq!(refused(&edited(&f, "network", "testnet3".into())), RecoveryError::Network);
    assert_eq!(refused(&edited(&f, "network", "mainnet".into())), RecoveryError::AddressMismatch);
    assert_eq!(refused(&edited(&f, "vault_id", "".into())), RecoveryError::VaultId);
    assert_eq!(refused(&edited(&f, "vault_id", "no spaces".into())), RecoveryError::VaultId);
    assert_eq!(refused(&edited(&f, "vault_id", "a".repeat(129).into())), RecoveryError::VaultId);
    assert_eq!(refused(&edited(&f, "csv", 7.into())), RecoveryError::CsvMismatch);
    assert_eq!(refused(&edited(&f, "witness_script", "00".into())), RecoveryError::Script);
    assert_eq!(refused(&edited(&f, "witness_script", "not hex".into())), RecoveryError::Script);
    assert_eq!(
        refused(&edited(&f, "witness_script", hex_encode(other.script.as_bytes()).into())),
        RecoveryError::CsvMismatch
    );
    assert_eq!(refused(&edited(&f, "address", "tb1qxyz".into())), RecoveryError::AddressMismatch);
    assert_eq!(refused(&edited(&f, "cold_key", "00".into())), RecoveryError::ColdKey);
    assert_eq!(refused(&edited(&f, "cold_key", "00".repeat(32).into())), RecoveryError::ColdKey);
    assert_eq!(refused(&edited(&f, "cold_key", "ff".repeat(32).into())), RecoveryError::ColdKey, "above the curve order");
    assert_eq!(
        refused(&edited(&f, "cold_key", hex_encode(&other_key.secret.secret_bytes()).into())),
        RecoveryError::ColdKeyMismatch
    );
    // The file for a script with a non-minimal operand: consensus would accept it and relay would not.
    let script_hex = hex_encode(f.script().as_bytes()).replace("56b275", "0106b275");
    assert_ne!(script_hex, hex_encode(f.script().as_bytes()), "the edit applied");
    assert_eq!(refused(&edited(&f, "witness_script", script_hex.into())), RecoveryError::Script);
}

#[test]
fn shape_is_strict() {
    let (f, _) = file(6);
    assert_eq!(refused("not json"), RecoveryError::Malformed);
    assert_eq!(refused("{}"), RecoveryError::Malformed);

    let mut j = json_of(&f);
    j["extra"] = 1.into();
    assert_eq!(refused(&j.to_string()), RecoveryError::Malformed, "unknown field");

    let mut j = json_of(&f);
    j.as_object_mut().unwrap().remove("address");
    assert_eq!(refused(&j.to_string()), RecoveryError::Malformed, "missing field");

    let mut j = json_of(&f);
    j["csv"] = "6".into();
    assert_eq!(refused(&j.to_string()), RecoveryError::Malformed, "csv as text");

    let mut j = json_of(&f);
    j["format"] = "undo-recovery-v2".into();
    assert_eq!(refused(&j.to_string()), RecoveryError::UnknownFormat);
}

#[test]
fn new_refuses_a_key_the_script_does_not_name() {
    let v = vault(6);
    assert_eq!(
        RecoveryFile::new(Network::Regtest, "v", v.script.clone(), &v.u.secret.secret_bytes()).unwrap_err(),
        RecoveryError::ColdKeyMismatch
    );
    assert_eq!(RecoveryFile::new(Network::Regtest, "v", v.script.clone(), &[0; 32]).unwrap_err(), RecoveryError::ColdKey);
    assert_eq!(RecoveryFile::new(Network::Regtest, "", v.script, &v.e.secret.secret_bytes()).unwrap_err(), RecoveryError::VaultId);
}

#[test]
fn secret_never_appears_in_debug_or_errors() {
    let (f, v) = file(6);
    let secret = hex_encode(&v.e.secret.secret_bytes());
    assert!(!format!("{f:?}").contains(&secret));
    assert!(f.to_json().contains(&secret), "control: the file itself does hold it");
    for bad in [
        f.to_json().replace("mutinynet", "x"),
        edited(&f, "cold_key", (secret.clone() + "zz").into()),
        edited(&f, "cold_key", 5.into()),
        f.to_json().replace(&format!("\"{secret}\""), &format!("[\"{secret}\"]")),
    ] {
        let e = RecoveryFile::parse(&bad).unwrap_err();
        assert!(!format!("{e} {e:?}").contains(&secret));
    }
}

// ---------------------------------------------------------------- escape and dry run

#[test]
fn dry_run_passes_at_push_size_boundaries() {
    for csv in [1u32, 16, 17, 127, 128, 32_767, 32_768, 65_535] {
        let (f, _) = file(csv);
        let r = dry_run_escape(&f.to_json()).unwrap_or_else(|e| panic!("csv {csv}: {e}"));
        assert_eq!(r.csv, csv);
        assert_eq!(r.address, f.address());
        println!("csv {csv}: script {} bytes, escape {} vB", r.script_len, r.vsize);
    }
}

#[test]
fn dry_run_refuses_what_parse_refuses() {
    let (f, _) = file(6);
    assert_eq!(dry_run_escape("{}").unwrap_err(), RecoveryError::Malformed);
    assert_eq!(dry_run_escape(&f.to_json().replace("mutinynet", "signet")).unwrap_err(), RecoveryError::Checksum);
}

/// The dry run's own controls. Each judge below is wrong in one specific way, and the dry run has
/// to notice that exact way. The real judge never behaves like this, so nothing else exercises them.
#[test]
fn dry_run_controls_fire_on_a_broken_judge() {
    let (f, _) = file(6);
    let text = f.to_json();
    let real = |tx: &undo_btc::Tx, i: usize, spk: &[u8], value: u64| consensus(tx, i, spk, value).is_ok();

    dry_run_with(&text, real).expect("control: the real judge passes");

    assert_eq!(dry_run_with(&text, |_, _, _, _| false).unwrap_err(), RecoveryError::DryRunRefused, "refuses everything");
    assert_eq!(dry_run_with(&text, |_, _, _, _| true).unwrap_err(), RecoveryError::DryRunControl, "accepts everything");

    // Cannot see the timelock: passes a too-early sequence, real on everything else.
    let blind_to_csv = |tx: &undo_btc::Tx, i: usize, spk: &[u8], value: u64| tx.inputs[i].sequence == 5 || real(tx, i, spk, value);
    assert_eq!(dry_run_with(&text, blind_to_csv).unwrap_err(), RecoveryError::DryRunControl, "blind to the timelock");

    // Cannot see the signer: passes any signature at seq = csv, real on everything else.
    let blind_to_key = |tx: &undo_btc::Tx, i: usize, spk: &[u8], value: u64| tx.inputs[i].sequence == 6 || real(tx, i, spk, value);
    assert_eq!(dry_run_with(&text, blind_to_key).unwrap_err(), RecoveryError::DryRunControl, "blind to the key");
}

#[test]
fn built_escape_passes_the_library_from_the_file_alone() {
    let (f, v) = file(6);
    let parsed = RecoveryFile::parse(&f.to_json()).unwrap();
    let coins = [Coin { outpoint: outpoint(1), value: 30_000 }, Coin { outpoint: outpoint(2), value: 70_000 }];
    let tx = parsed.build_escape(&coins, &destination(), 1_000).unwrap();
    assert_eq!(tx.version, 2);
    assert_eq!(tx.lock_time, 0);
    assert_eq!(tx.outputs[0].value, 99_000);
    for (i, c) in coins.iter().enumerate() {
        assert_eq!(tx.inputs[i].sequence, 6);
        assert_eq!(tx.inputs[i].witness.len(), 3);
        assert!(tx.inputs[i].witness[1].is_empty());
        consensus(&tx, i, &v.spk, c.value).unwrap();
    }
    // A wrong declared value gives a signature consensus refuses, which is the whole protection
    // against a lying UTXO API.
    let lied = [Coin { outpoint: outpoint(1), value: 30_001 }];
    let tx = parsed.build_escape(&lied, &destination(), 1_000).unwrap();
    assert!(consensus(&tx, 0, &v.spk, 30_000).is_err());
    // Control: signed for the real value, the same input passes.
    let honest = [Coin { outpoint: outpoint(1), value: 30_000 }];
    let tx = parsed.build_escape(&honest, &destination(), 1_000).unwrap();
    consensus(&tx, 0, &v.spk, 30_000).unwrap();
}

#[test]
fn escape_builder_refuses_what_would_lose_or_fail() {
    let (f, _) = file(Csv::new(6).unwrap().blocks());
    let coin = [Coin { outpoint: outpoint(1), value: 10_000 }];
    let dest = destination();
    assert_eq!(f.build_escape(&[], &dest, 1).unwrap_err(), RecoveryError::NoCoins);
    assert_eq!(f.build_escape(&coin, &[], 1).unwrap_err(), RecoveryError::Destination);
    assert_eq!(f.build_escape(&coin, &[0x6a, 0x01, 0x00], 1).unwrap_err(), RecoveryError::Destination);
    assert_eq!(f.build_escape(&coin, &dest, 10_001).unwrap_err(), RecoveryError::Fee);
    assert_eq!(f.build_escape(&coin, &dest, 10_000 - 545).unwrap_err(), RecoveryError::Fee, "dust");
    assert!(f.build_escape(&coin, &dest, 10_000 - 546).is_ok(), "control: exactly at the limit");
    let huge = [Coin { outpoint: outpoint(1), value: u64::MAX }, Coin { outpoint: outpoint(2), value: 1 }];
    assert_eq!(f.build_escape(&huge, &dest, 1).unwrap_err(), RecoveryError::NoCoins);
}

#[test]
fn escape_is_deterministic() {
    let (f, _) = file(6);
    let coin = [Coin { outpoint: outpoint(1), value: 10_000 }];
    let a = f.build_escape(&coin, &destination(), 500).unwrap();
    let b = f.build_escape(&coin, &destination(), 500).unwrap();
    assert_eq!(a.serialize(), b.serialize());
}

#[test]
fn script_parsed_from_file_is_the_same_as_built() {
    let (f, v) = file(300);
    let back = WitnessScript::parse(RecoveryFile::parse(&f.to_json()).unwrap().script().as_bytes()).unwrap();
    assert_eq!(back, v.script);
}

// ---------------------------------------------------------------- the binary

#[test]
fn binary_reports_and_exits_correctly_and_prints_no_secret() {
    let (f, v) = file(6);
    let secret = hex_encode(&v.e.secret.secret_bytes());
    let dir = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"));
    let exe = env!("CARGO_BIN_EXE_recovery-dry-run");

    let good = dir.join("recovery-good.json");
    std::fs::write(&good, f.to_json()).unwrap();
    let out = Command::new(exe).arg(&good).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    println!("{text}");
    assert!(out.status.success());
    assert!(text.contains("PASS C18 [consensus-lib]"));
    assert!(text.contains("NOT CHECKED"));
    assert!(!text.contains(&secret));

    let bad = dir.join("recovery-bad.json");
    std::fs::write(&bad, f.to_json().replace("mutinynet", "signet")).unwrap();
    let out = Command::new(exe).arg(&bad).output().unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(out.status.code(), Some(1));
    assert!(text.contains("FAIL C18"));
    assert!(!text.contains(&secret));

    assert_eq!(Command::new(exe).output().unwrap().status.code(), Some(2));
    assert_eq!(Command::new(exe).arg(dir.join("no-such-file")).output().unwrap().status.code(), Some(1));

    std::fs::remove_file(good).unwrap();
    std::fs::remove_file(bad).unwrap();
}
