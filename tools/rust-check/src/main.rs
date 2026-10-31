//! Referee for the Node tools. Everything a tool computes is computed again here with other code, so
//! a disagreement fails a test instead of passing unnoticed:
//!
//!   make-recovery NETWORK LABEL CSV VAULT_ID     a recovery file from undo-btc, keys hashed from LABEL
//!   escape FILE COINS_JSON DEST_HEX FEE          undo-btc's escape transaction, as hex
//!   verify TX_HEX SPK_HEX VALUE[,VALUE...]       libbitcoinconsensus on every input
//!   dry-run FILE                                 undo-btc's recovery-file check
//!   cold-digest CONTRACT VAULT METHOD ARG EXPIRES NONCE
//!                                                the intent digest, encoded with the borsh crate
//!   cold-check DIGEST RSV COLD_SECRET            recovers the signer and names the key it matches
//!   intent-key COLD_SECRET                       the derived intent public key, with the hkdf crate
//!   leaf-pop-digest CREATE_DIGEST                what the escape key signs at creation
//!
//! Test keys only: every secret here comes from a public label, or from a throwaway test file.

use borsh::BorshSerialize;
use hkdf::Hkdf;
use k256::ecdsa::{RecoveryId, Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use undo_btc::recovery::{dry_run_escape, Coin, RecoveryFile};
use undo_btc::{Csv, Network, OutPoint, PubKey, Txid, WitnessScript};

fn sha(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn label_secret(label: &str, role: &str) -> [u8; 32] {
    sha(format!("undo-test-only:{label}:{role}").as_bytes())
}

fn public(secret: &[u8; 32]) -> Vec<u8> {
    SigningKey::from_bytes(secret.into()).unwrap().verifying_key().to_encoded_point(true).as_bytes().to_vec()
}

fn pubkey(secret: &[u8; 32]) -> PubKey {
    PubKey::from_slice(&public(secret)).unwrap()
}

fn make_recovery(a: &[String]) {
    let network = Network::from_name(&a[0]).unwrap();
    let label = &a[1];
    let csv: u32 = a[2].parse().unwrap();
    let cold = label_secret(label, "k_e");
    let script = WitnessScript::new(
        pubkey(&label_secret(label, "k_u")),
        pubkey(&label_secret(label, "k_m")),
        pubkey(&cold),
        Csv::new(csv).unwrap(),
    )
    .unwrap();
    println!("{}", RecoveryFile::new(network, &a[3], script, &cold).unwrap().to_json());
}

fn escape(a: &[String]) {
    let text = std::fs::read_to_string(&a[0]).unwrap();
    let file = RecoveryFile::parse(&text).unwrap();
    let list: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(&a[1]).unwrap()).unwrap();
    let coins: Vec<Coin> = list
        .as_array()
        .unwrap()
        .iter()
        .map(|c| Coin {
            outpoint: OutPoint { txid: Txid::from_display_hex(c["txid"].as_str().unwrap()).unwrap(), vout: c["vout"].as_u64().unwrap() as u32 },
            value: c["value"].as_u64().unwrap(),
        })
        .collect();
    let tx = file.build_escape(&coins, &hex::decode(&a[2]).unwrap(), a[3].parse().unwrap()).unwrap();
    println!("{}", hex::encode(tx.serialize()));
}

fn verify(a: &[String]) {
    let tx = hex::decode(&a[0]).unwrap();
    let spk = hex::decode(&a[1]).unwrap();
    let mut failed = 0;
    for (index, value) in a[2].split(',').enumerate() {
        let amount = bitcoin::Amount::from_sat(value.parse().unwrap());
        if let Err(e) = bitcoin::consensus::validation::verify_script(bitcoin::Script::from_bytes(&spk), index, amount, &tx) {
            println!("input {index}: refused: {e}");
            failed += 1;
        }
    }
    if failed > 0 {
        std::process::exit(1);
    }
    println!("consensus ok");
}

fn dry_run(a: &[String]) {
    match dry_run_escape(&std::fs::read_to_string(&a[0]).unwrap()) {
        Ok(r) => println!("ok {} {} {}", r.network.name(), r.csv, r.vsize),
        Err(e) => {
            println!("refused {e:?}");
            std::process::exit(1);
        }
    }
}

#[derive(BorshSerialize)]
struct Intent<'a> {
    tag: &'a str,
    contract: &'a str,
    vault: &'a [u8; 32],
    method: &'a str,
    args_hash: [u8; 32],
    expires_at: u64,
    nonce: Option<u64>,
}

fn cold_digest(a: &[String]) {
    let vault: [u8; 32] = hex::decode(&a[1]).unwrap().try_into().unwrap();
    let args = match a[2].as_str() {
        "unfreeze" => Vec::new(),
        _ => borsh::to_vec(&a[3].parse::<u64>().unwrap()).unwrap(),
    };
    let nonce = if a[5] == "none" { None } else { Some(a[5].parse().unwrap()) };
    let intent = Intent { tag: "undo-cold-v1", contract: &a[0], vault: &vault, method: &a[2], args_hash: sha(&args), expires_at: a[4].parse().unwrap(), nonce };
    println!("{}", hex::encode(sha(&borsh::to_vec(&intent).unwrap())));
}

fn intent_secret(cold: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    Hkdf::<Sha256>::new(Some(b"undo-key-v1"), cold).expand(b"undo-k_e-intent-secp256k1-v1", &mut out).unwrap();
    out
}

fn cold_check(a: &[String]) {
    let digest = hex::decode(&a[0]).unwrap();
    let rsv = hex::decode(&a[1]).unwrap();
    let cold: [u8; 32] = hex::decode(&a[2]).unwrap().try_into().unwrap();
    let sig = Signature::from_slice(&rsv[..64]).unwrap();
    let key = VerifyingKey::recover_from_prehash(&digest, &sig, RecoveryId::from_byte(rsv[64]).unwrap()).unwrap();
    let got = key.to_encoded_point(true).as_bytes().to_vec();
    if got == public(&intent_secret(&cold)) {
        println!("signed by intent key");
    } else if got == public(&cold) {
        println!("signed by LEAF key");
        std::process::exit(1);
    } else {
        println!("signed by another key");
        std::process::exit(1);
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some((command, rest)) = args.split_first() else {
        eprintln!("usage: see the file header");
        std::process::exit(2);
    };
    match command.as_str() {
        "make-recovery" => make_recovery(rest),
        "escape" => escape(rest),
        "verify" => verify(rest),
        "dry-run" => dry_run(rest),
        "cold-digest" => cold_digest(rest),
        "cold-check" => cold_check(rest),
        "leaf-pop-digest" => {
            let mut preimage = b"undo-leaf-pop-v1".to_vec();
            preimage.extend(hex::decode(&rest[0]).unwrap());
            println!("{}", hex::encode(sha(&preimage)));
        }
        "intent-key" => {
            let cold = hex::decode(&rest[0]).unwrap();
            println!("{}", hex::encode(public(&intent_secret(&cold))));
        }
        _ => {
            eprintln!("usage: see the file header");
            std::process::exit(2);
        }
    }
}
