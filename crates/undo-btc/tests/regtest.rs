//! The two-branch script on a real node: bitcoind on regtest, local, with no peers and no wallet.
//!
//! This covers what libbitcoinconsensus cannot: BIP-68 age on a chain, relay policy, and that the
//! transactions really get mined. `K_m` here is a local test key standing in for the MPC network.
//! Nothing here touches NEAR, testnet or mainnet.
//!
//! Two questions are asked of every transaction, because the answers differ:
//! - `mempool`: `testmempoolaccept`, which applies standard relay policy and consensus.
//! - `block`: `generateblock` with `submit=false`, which applies consensus only and moves nothing.
//!
//! Standard policy has to be asked for. Regtest defaults to `-acceptnonstdtxn=1`, so the node is
//! started with `-acceptnonstdtxn=0`, and `standard_policy_is_on` proves that it took effect.
//!
//! Run with:
//!
//!     scripts/fetch-bitcoind.sh
//!     cargo test -p undo-btc --test regtest -- --ignored --nocapture
//!
//! `UNDO_BITCOIN_BIN` overrides the directory holding `bitcoind` and `bitcoin-cli`.

mod common;

use bitcoin::secp256k1::{Message, Secp256k1};
use common::*;
use serde_json::{json, Value};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use undo_btc::address::p2wsh_address;
use undo_btc::recovery::{Coin, RecoveryFile};
use undo_btc::{hex_encode, DerSig, Network, OutPoint, Sha2, Sha256, Tx, TxOut, Txid};

const ONE: &[u8] = &[1];
const EMPTY: &[u8] = &[];
const FEE: u64 = 1_000;

struct Node {
    child: Child,
    bin: PathBuf,
    datadir: PathBuf,
    rpc_port: u16,
}

impl Node {
    fn start() -> Self {
        let bin = std::env::var_os("UNDO_BITCOIN_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(".tools/bitcoin-32.1/bin"));
        assert!(bin.join("bitcoind").exists(), "no bitcoind: run scripts/fetch-bitcoind.sh or set UNDO_BITCOIN_BIN");

        // Tests run side by side, and two nodes on one datadir leave the second unable to start.
        static NEXT: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let datadir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("regtest-{}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&datadir);
        std::fs::create_dir_all(&datadir).unwrap();
        let rpc_port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();

        let child = Command::new(bin.join("bitcoind"))
            .args([
                "-regtest",
                "-server=1",
                "-listen=0",
                "-dnsseed=0",
                "-fixedseeds=0",
                "-discover=0",
                "-disablewallet=1",
                "-acceptnonstdtxn=0",
                "-printtoconsole=0",
                "-dbcache=8",
                "-par=1",
            ])
            .arg(format!("-datadir={}", datadir.display()))
            .arg(format!("-rpcport={rpc_port}"))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let node = Node { child, bin, datadir, rpc_port };
        node.raw(&["-rpcwait", "-rpcwaittimeout=60", "getblockcount"]).expect("bitcoind did not start");
        node
    }

    fn raw(&self, args: &[&str]) -> Result<String, String> {
        let out = Command::new(self.bin.join("bitcoin-cli"))
            .arg("-regtest")
            .arg(format!("-datadir={}", self.datadir.display()))
            .arg(format!("-rpcport={}", self.rpc_port))
            .args(args)
            .output()
            .unwrap();
        if out.status.success() {
            Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
        } else {
            Err(String::from_utf8_lossy(&out.stderr).trim().to_owned())
        }
    }

    fn rpc(&self, args: &[&str]) -> String {
        self.raw(args).unwrap_or_else(|e| panic!("{args:?}: {e}"))
    }

    fn rpc_json(&self, args: &[&str]) -> Value {
        serde_json::from_str(&self.rpc(args)).unwrap()
    }

    fn height(&self) -> u64 {
        self.rpc("getblockcount".split(' ').collect::<Vec<_>>().as_slice()).parse().unwrap()
    }

    /// Mines to an address and returns the coinbase coin of each block that pays `spk`.
    fn mine_to(&self, count: u32, address: &str, spk: &[u8]) -> Vec<Coin> {
        let hashes = self.rpc_json(&["generatetoaddress", &count.to_string(), address]);
        let spk_hex = hex_encode(spk);
        hashes
            .as_array()
            .unwrap()
            .iter()
            .map(|h| {
                let block = self.rpc_json(&["getblock", h.as_str().unwrap(), "2"]);
                let coinbase = &block["tx"][0];
                let vout = coinbase["vout"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|o| o["scriptPubKey"]["hex"] == spk_hex.as_str())
                    .expect("coinbase pays the address");
                Coin {
                    outpoint: OutPoint {
                        txid: Txid::from_display_hex(coinbase["txid"].as_str().unwrap()).unwrap(),
                        vout: vout["n"].as_u64().unwrap() as u32,
                    },
                    value: sats(&vout["value"]),
                }
            })
            .collect()
    }

    /// Standard relay policy plus consensus. `Ok(vsize)`, or `Err(reason)` as the node words it.
    fn mempool(&self, tx: &Tx) -> Result<u64, String> {
        let list = json!([hex_encode(&tx.serialize())]).to_string();
        let result = &self.rpc_json(&["testmempoolaccept", &list])[0];
        if result["allowed"].as_bool().unwrap() {
            assert_eq!(result["txid"], tx.txid::<Sha2>().to_display_hex().as_str(), "the node computes the same txid");
            Ok(result["vsize"].as_u64().unwrap())
        } else {
            Err(result["reject-reason"].as_str().unwrap_or("").to_owned())
        }
    }

    /// Consensus only, in a block that is built, validated and thrown away.
    fn block(&self, tx: &Tx) -> Result<(), String> {
        let list = json!([hex_encode(&tx.serialize())]).to_string();
        let burn = burn_address();
        self.raw(&["generateblock", &burn, &list, "false"]).map(|_| ())
    }

    fn send(&self, tx: &Tx) {
        let txid = self.rpc(&["sendrawtransaction", &hex_encode(&tx.serialize())]);
        assert_eq!(txid, tx.txid::<Sha2>().to_display_hex());
    }

    fn generate(&self, count: u32) {
        self.rpc(&["generatetoaddress", &count.to_string(), &burn_address()]);
    }

    fn confirmations(&self, tx: &Tx, vout: u32) -> Option<u64> {
        let got = self.rpc(&["gettxout", &tx.txid::<Sha2>().to_display_hex(), &vout.to_string()]);
        if got.is_empty() {
            return None;
        }
        serde_json::from_str::<Value>(&got).unwrap()["confirmations"].as_u64()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.raw(&["stop"]);
        for _ in 0..100 {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.datadir);
    }
}

fn sats(value: &Value) -> u64 {
    (value.as_f64().unwrap() * 1e8).round() as u64
}

fn burn_address() -> String {
    p2wsh_address(Network::Regtest, &[0x99; 32])
}

fn address_of(script: &[u8]) -> String {
    p2wsh_address(Network::Regtest, &Sha2::sha256(script))
}

fn p2wsh_of(script: &[u8]) -> Vec<u8> {
    let mut spk = vec![0x00, 0x20];
    spk.extend_from_slice(&Sha2::sha256(script));
    spk
}

/// A transaction on `coin` with a chosen version and sequence, paying everything but the fee to
/// the burn output.
fn on_coin(coin: Coin, version: u32, sequence: u32) -> Tx {
    let mut tx = Tx::cosigned(&[coin.outpoint], pay_out(coin.value - FEE));
    tx.version = version;
    tx.inputs[0].sequence = sequence;
    tx
}

fn witnessed(mut tx: Tx, items: &[&[u8]], script: &[u8]) -> Tx {
    let mut w: Vec<Vec<u8>> = items.iter().map(|i| i.to_vec()).collect();
    w.push(script.to_vec());
    tx.inputs[0].witness = w;
    tx
}

/// Refused by both questions, and the mempool's reason has to name the expected rule.
fn assert_consensus_refuses(node: &Node, name: &str, tx: &Tx, reason: &str) {
    let mem = node.mempool(tx).expect_err(name);
    let blk = node.block(tx).expect_err(name);
    println!("REFUSED {name}\n  mempool: {mem}\n  block:   {blk}");
    assert!(mem.contains(reason), "{name}: mempool said {mem}, expected {reason}");
}

/// Accepted by the block question and refused by the mempool: consensus valid, policy refused.
fn assert_policy_only(node: &Node, name: &str, tx: &Tx, reason: &str) {
    let mem = node.mempool(tx).expect_err(name);
    node.block(tx).unwrap_or_else(|e| panic!("{name}: block refused too: {e}"));
    println!("POLICY ONLY {name}\n  mempool: {mem}\n  block:   valid");
    assert!(mem.contains(reason), "{name}: mempool said {mem}, expected {reason}");
}

#[test]
#[ignore = "needs bitcoind: run scripts/fetch-bitcoind.sh, then --test regtest -- --ignored"]
fn two_branch_script_on_regtest() {
    let node = Node::start();
    println!("node: {}", node.rpc(&["getnetworkinfo"]).lines().find(|l| l.contains("subversion")).unwrap().trim());
    assert_eq!(node.rpc_json(&["getnetworkinfo"])["connections"], 0, "no peers");

    // ------------------------------------------------------------ setup
    let v = vault(6);
    let script = v.script.as_bytes();
    let file = RecoveryFile::new(Network::Regtest, "regtest-vault", v.script.clone(), &v.e.secret.secret_bytes()).unwrap();
    let recovery_text = file.to_json();
    drop(file);
    // From here on, escapes use only what the file holds.
    let from_file = RecoveryFile::parse(&recovery_text).unwrap();
    assert!(from_file.address().starts_with("bcrt1q"));

    let coins = node.mine_to(10, &from_file.address(), &v.spk);

    // A vault whose CSV push is non-minimal, which this crate refuses to build.
    let nonminimal: Vec<u8> = {
        let hex = hex_encode(script).replace("56b275", "0106b275");
        assert_ne!(hex, hex_encode(script));
        undo_btc::hex_decode(&hex).unwrap()
    };
    let nonminimal_coin = node.mine_to(1, &address_of(&nonminimal), &p2wsh_of(&nonminimal))[0];

    // One coin for each CSV push size that a short regtest chain can reach.
    let boundary: Vec<(u32, Vault, Coin)> = [1u32, 2, 16, 17, 127, 128, 255, 256]
        .into_iter()
        .map(|csv| {
            let b = vault(csv);
            let coin = node.mine_to(1, &address_of(b.script.as_bytes()), &b.spk)[0];
            (csv, b, coin)
        })
        .collect();

    // Past coinbase maturity and past the largest CSV above.
    node.generate(300);
    println!("mined to height {}", node.height());

    // ------------------------------------------------------------ the node really applies policy
    standard_policy_is_on(&node, coins[9]);

    // ------------------------------------------------------------ positive controls
    let coin = coins[0];
    let tx = on_coin(coin, 2, SEQ_COSIGNED);
    let (m, u) = (sign(&tx, 0, script, coin.value, &v.m), sign(&tx, 0, script, coin.value, &v.u));
    let good = witnessed(tx, &[&m, &u, ONE], script);
    println!("co-signed on an old coin: mempool {:?}, block {:?}", node.mempool(&good), node.block(&good));
    node.mempool(&good).expect("co-signed spend passes policy");
    node.block(&good).expect("co-signed spend passes consensus");

    let old_escape = from_file.build_escape(&[coin], &destination(), FEE).unwrap();
    println!("escape on an old coin: mempool {:?}, block {:?}", node.mempool(&old_escape), node.block(&old_escape));
    node.mempool(&old_escape).expect("escape on an old coin passes policy");
    node.block(&old_escape).expect("escape on an old coin passes consensus");

    // ------------------------------------------------------------ the five named negatives
    let script_fail = "script-verify-flag";

    let t = on_coin(coin, 2, SEQ_COSIGNED);
    let m = sign(&t, 0, script, coin.value, &v.m);
    assert_consensus_refuses(&node, "MPC alone, both slots", &witnessed(t.clone(), &[&m, &m, ONE], script), script_fail);
    assert_consensus_refuses(&node, "MPC alone, empty K_u slot", &witnessed(t, &[&m, EMPTY, ONE], script), script_fail);
    let t = on_coin(coin, 2, 6);
    let m = sign(&t, 0, script, coin.value, &v.m);
    assert_consensus_refuses(&node, "MPC alone, escape branch", &witnessed(t, &[&m, EMPTY], script), script_fail);

    let t = on_coin(coin, 2, SEQ_COSIGNED);
    let u = sign(&t, 0, script, coin.value, &v.u);
    assert_consensus_refuses(&node, "K_u alone, both slots", &witnessed(t.clone(), &[&u, &u, ONE], script), script_fail);
    assert_consensus_refuses(&node, "K_u alone, empty K_m slot", &witnessed(t, &[EMPTY, &u, ONE], script), script_fail);

    let t = on_coin(coin, 2, 6);
    let u = sign(&t, 0, script, coin.value, &v.u);
    assert_consensus_refuses(&node, "K_u after CSV, coin 300+ blocks old", &witnessed(t, &[&u, EMPTY], script), script_fail);

    let t = on_coin(coin, 2, 5);
    let e = sign(&t, 0, script, coin.value, &v.e);
    assert_consensus_refuses(&node, "K_e with seq below CSV", &witnessed(t, &[&e, EMPTY], script), script_fail);
    let t = on_coin(coin, 2, SEQ_COSIGNED);
    let e = sign(&t, 0, script, coin.value, &v.e);
    assert_consensus_refuses(&node, "K_e with the disable bit set", &witnessed(t.clone(), &[&e, EMPTY], script), script_fail);
    assert_consensus_refuses(&node, "K_e in the co-sign branch", &witnessed(t, &[&e, &e, ONE], script), script_fail);
    let t = on_coin(coin, 1, 6);
    let e = sign(&t, 0, script, coin.value, &v.e);
    assert_consensus_refuses(&node, "K_e in a version 1 tx", &witnessed(t, &[&e, EMPTY], script), script_fail);

    let t = on_coin(coin, 2, SEQ_COSIGNED);
    let (m, u) = (sign(&t, 0, script, coin.value, &v.m), sign(&t, 0, script, coin.value, &v.u));
    assert_consensus_refuses(&node, "signatures swapped", &witnessed(t, &[&u, &m, ONE], script), script_fail);

    // Outputs above inputs: the library cannot see this one, the node can.
    let mut t = on_coin(coin, 2, SEQ_COSIGNED);
    t.outputs[0].value = coin.value + 1;
    let (m, u) = (sign(&t, 0, script, coin.value, &v.m), sign(&t, 0, script, coin.value, &v.u));
    assert_consensus_refuses(&node, "outputs above inputs", &witnessed(t, &[&m, &u, ONE], script), "bad-txns-in-belowout");

    // ------------------------------------------------------------ passes the library, fails policy
    let t = on_coin(coin, 2, SEQ_COSIGNED);
    let (m, u) = (sign(&t, 0, script, coin.value, &v.m), sign(&t, 0, script, coin.value, &v.u));
    assert_policy_only(&node, "MINIMALIF: selector 02", &witnessed(t.clone(), &[&m, &u, &[2]], script), script_fail);
    assert_policy_only(&node, "LOW_S: high-s K_m signature", &witnessed(t.clone(), &[&high_s_form(&m), &u, ONE], script), script_fail);
    assert_policy_only(&node, "LOW_S: high-s K_u signature", &witnessed(t, &[&m, &high_s_form(&u), ONE], script), script_fail);

    let t = on_coin(nonminimal_coin, 2, 6);
    let e = sign(&t, 0, &nonminimal, nonminimal_coin.value, &v.e);
    assert_policy_only(&node, "MINIMALDATA: csv pushed as 01 06", &witnessed(t, &[&e, EMPTY], &nonminimal), script_fail);

    // ------------------------------------------------------------ co-signed spend, really mined
    let coin = coins[1];
    let dest_value = 1_000_000u64;
    let outs = vec![
        TxOut { value: dest_value, script_pubkey: destination() },
        TxOut { value: coin.value - dest_value - FEE, script_pubkey: v.spk.clone() },
    ];
    let mut spend = Tx::cosigned(&[coin.outpoint], outs);
    let (m, u) = (sign_der(&spend, 0, script, coin.value, &v.m), sign_der(&spend, 0, script, coin.value, &v.u));
    spend.set_cosigned_witness(0, &m, &u, &v.script).unwrap();
    let node_vsize = node.mempool(&spend).unwrap();
    println!("co-signed 1-in 2-out: node vsize {node_vsize}, crate vsize {}", spend.vsize());
    assert_eq!(node_vsize as usize, spend.vsize(), "the crate's size agrees with the node");
    node.send(&spend);
    node.generate(1);
    assert_eq!(node.confirmations(&spend, 0), Some(1), "mined");
    println!("MINED co-signed spend {}", spend.txid::<Sha2>().to_display_hex());

    // ------------------------------------------------------------ BIP-68: real age on a real chain
    // The change output of that spend is a coin with 1 confirmation.
    let young = Coin {
        outpoint: OutPoint { txid: spend.txid::<Sha2>(), vout: 1 },
        value: coin.value - dest_value - FEE,
    };
    let escape = from_file.build_escape(&[young], &destination(), FEE).unwrap();
    for confirmations in 1..6u64 {
        assert_eq!(node.confirmations(&spend, 1), Some(confirmations));
        assert_consensus_refuses(
            &node,
            &format!("K_e at seq = CSV on a coin with {confirmations} of 6 confirmations"),
            &escape,
            "non-BIP68-final",
        );
        // The library says yes here. That gap is what this block of the test exists to cover.
        consensus(&escape, 0, &v.spk, young.value).expect("library has no chain, so it accepts");
        assert!(node.raw(&["sendrawtransaction", &hex_encode(&escape.serialize())]).is_err(), "not broadcastable yet");
        node.generate(1);
    }
    assert_eq!(node.confirmations(&spend, 1), Some(6));
    let vsize = node.mempool(&escape).expect("at 6 confirmations the same bytes are accepted");
    node.block(&escape).expect("and valid in a block");
    println!("escape at 6 of 6 confirmations: accepted, node vsize {vsize}, crate vsize {}", escape.vsize());
    assert_eq!(vsize as usize, escape.vsize());
    node.send(&escape);
    node.generate(1);
    assert_eq!(node.confirmations(&escape, 0), Some(1), "mined");
    assert_eq!(node.confirmations(&spend, 1), None, "the vault coin is gone");
    println!("MINED escape from the recovery file alone {}", escape.txid::<Sha2>().to_display_hex());

    // A coin still in the mempool has no age at all.
    let coin = coins[2];
    let outs = vec![TxOut { value: coin.value - FEE, script_pubkey: v.spk.clone() }];
    let mut self_spend = Tx::cosigned(&[coin.outpoint], outs);
    let (m, u) = (sign_der(&self_spend, 0, script, coin.value, &v.m), sign_der(&self_spend, 0, script, coin.value, &v.u));
    self_spend.set_cosigned_witness(0, &m, &u, &v.script).unwrap();
    node.send(&self_spend);
    let unconfirmed = Coin { outpoint: OutPoint { txid: self_spend.txid::<Sha2>(), vout: 0 }, value: coin.value - FEE };
    let early = from_file.build_escape(&[unconfirmed], &destination(), FEE).unwrap();
    let reason = node.mempool(&early).expect_err("unconfirmed parent");
    println!("REFUSED escape on an unconfirmed coin\n  mempool: {reason}");
    assert!(reason.contains("non-BIP68-final"), "{reason}");
    node.generate(1);

    // A self-spend restarts the CSV clock, which spec 1.3 and the self-spend slot rely on: the
    // coin that was old enough a moment ago is now a young coin.
    let restarted = from_file.build_escape(&[unconfirmed], &destination(), FEE).unwrap();
    assert_consensus_refuses(&node, "K_e after a self-spend restarted the clock", &restarted, "non-BIP68-final");

    // ------------------------------------------------------------ several inputs
    let (a, b) = (coins[3], coins[4]);
    let outs = vec![TxOut { value: a.value + b.value - 2 * FEE, script_pubkey: destination() }];
    let mut multi = Tx::cosigned(&[a.outpoint, b.outpoint], outs);
    for (i, c) in [a, b].iter().enumerate() {
        let (m, u) = (sign_der(&multi, i, script, c.value, &v.m), sign_der(&multi, i, script, c.value, &v.u));
        multi.set_cosigned_witness(i, &m, &u, &v.script).unwrap();
    }
    assert_eq!(node.mempool(&multi).unwrap() as usize, multi.vsize());
    node.send(&multi);

    let (c, d) = (coins[5], coins[6]);
    let multi_escape = from_file.build_escape(&[c, d], &destination(), 2 * FEE).unwrap();
    assert_eq!(node.mempool(&multi_escape).unwrap() as usize, multi_escape.vsize());
    node.send(&multi_escape);
    node.generate(1);
    assert_eq!(node.confirmations(&multi, 0), Some(1));
    assert_eq!(node.confirmations(&multi_escape, 0), Some(1));
    println!("MINED co-signed 2 inputs and escape 2 inputs");

    // ------------------------------------------------------------ DER edge cases on a real node
    let coin = coins[7];
    let t = on_coin(coin, 2, SEQ_COSIGNED);
    let digest = t.sighash::<Sha2>(0, script, coin.value).unwrap();
    let u_sig = sign(&t, 0, script, coin.value, &v.u);
    let secp = Secp256k1::new();
    let (mut short_r, mut short_s) = (None, None);
    for n in 0u32..6_000 {
        let mut noise = [0u8; 32];
        noise[..4].copy_from_slice(&n.to_le_bytes());
        let c = secp.sign_ecdsa_with_noncedata(&Message::from_digest(digest), &v.m.secret, &noise).serialize_compact();
        if c[0] == 0 && short_r.is_none() {
            short_r = Some(c);
        }
        if c[32] == 0 && short_s.is_none() {
            short_s = Some(c);
        }
        if short_r.is_some() && short_s.is_some() {
            break;
        }
    }
    for (name, c) in [("short r", short_r.unwrap()), ("short s", short_s.unwrap())] {
        let der = DerSig::from_rs(c[..32].try_into().unwrap(), c[32..].try_into().unwrap()).unwrap();
        let tx = witnessed(t.clone(), &[der.as_bytes(), &u_sig, ONE], script);
        let got = node.mempool(&tx);
        println!("{name} K_m signature, {} witness bytes: mempool {got:?}", der.as_bytes().len());
        got.unwrap_or_else(|e| panic!("{name}: {e}"));
        node.block(&tx).unwrap();
    }

    // ------------------------------------------------------------ every reachable push size
    node.generate(1);
    for (csv, b, coin) in &boundary {
        let f = RecoveryFile::new(Network::Regtest, "boundary", b.script.clone(), &b.e.secret.secret_bytes()).unwrap();
        let tx = f.build_escape(&[*coin], &destination(), FEE).unwrap();
        let got = node.mempool(&tx);
        println!("csv {csv}: script {} bytes, escape mempool {got:?}", b.script.as_bytes().len());
        assert_eq!(got.expect("standard") as usize, tx.vsize());
        node.send(&tx);

        // Control: one sequence below is refused, by CSV itself.
        let low = on_coin(*coin, 2, csv - 1);
        let e = sign(&low, 0, b.script.as_bytes(), coin.value, &b.e);
        let low = witnessed(low, &[&e, EMPTY], b.script.as_bytes());
        assert!(node.block(&low).is_err(), "csv {csv} at seq csv-1");
    }
    node.generate(1);
    assert_eq!(node.rpc_json(&["getmempoolinfo"])["size"], 0, "everything sent was mined");
    println!("final height {}", node.height());
}

/// Controls for the node itself. If `-acceptnonstdtxn=0` were not in force, the policy assertions
/// in this file could not be trusted, in either direction.
fn standard_policy_is_on(node: &Node, coin: Coin) {
    let v = vault(6);
    let script = v.script.as_bytes();
    let mut t = on_coin(coin, 2, SEQ_COSIGNED);
    t.outputs[0].script_pubkey = vec![0x51, 0x51, 0x93]; // a bare script no standard template has
    let (m, u) = (sign(&t, 0, script, coin.value, &v.m), sign(&t, 0, script, coin.value, &v.u));
    let tx = witnessed(t, &[&m, &u, ONE], script);
    let reason = node.mempool(&tx).expect_err("non-standard output");
    println!("control, non-standard output: mempool {reason}");
    assert!(reason.contains("scriptpubkey"), "{reason}");
    node.block(&tx).expect("the same transaction is valid by consensus");
}

/// The cold-key exit against a thief's held links, on a node. The escape and a link spend the same
/// coin, so this is a replacement race, and the node judges it by absolute fee: the replacement has to
/// beat the sum of everything it evicts, with stacked children counted. So an escape's fee has to be
/// sized against the links a thief may hold, not by rate alone. `tools/escape.mjs` says this when it
/// prints a transaction.
#[test]
#[ignore = "needs bitcoind: see the file header"]
fn the_escape_is_a_fee_race_against_held_links() {
    let node = Node::start();
    let v = vault(6);
    let script = v.script.as_bytes();
    let file = RecoveryFile::new(Network::Regtest, "race", v.script.clone(), &v.e.secret.secret_bytes()).unwrap();
    let coins = node.mine_to(6, &file.address(), &v.spk);
    node.generate(120);
    let link = |coin: Coin, fee: u64| {
        let outs = vec![TxOut { value: coin.value - fee, script_pubkey: v.spk.clone() }];
        let mut tx = Tx::cosigned(&[coin.outpoint], outs);
        let (m, u) = (sign_der(&tx, 0, script, coin.value, &v.m), sign_der(&tx, 0, script, coin.value, &v.u));
        tx.set_cosigned_witness(0, &m, &u, &v.script).unwrap();
        tx
    };
    let child_of = |tx: &Tx, coin: Coin, fee: u64| Coin { outpoint: OutPoint { txid: tx.txid::<Sha2>(), vout: 0 }, value: coin.value - fee };
    let send = |tx: &Tx| node.raw(&["sendrawtransaction", &hex_encode(&tx.serialize())]);
    let in_pool = |tx: &Tx| node.raw(&["getmempoolentry", &tx.txid::<Sha2>().to_display_hex()]).is_ok();

    // The owner escapes first with a small fee. A held link that pays more takes its place, and once
    // that link is mined the escape is void and the coin's age starts over.
    let escape = file.build_escape(&[coins[0]], &destination(), 500).unwrap();
    send(&escape).unwrap();
    let held = link(coins[0], 1_000);
    send(&held).unwrap();
    assert!(!in_pool(&escape) && in_pool(&held), "the higher absolute fee won");
    node.generate(1);
    let restarted = child_of(&held, coins[0], 1_000);
    let again = file.build_escape(&[restarted], &destination(), 500).unwrap();
    assert!(node.mempool(&again).unwrap_err().contains("non-BIP68-final"), "the new coin is young");

    // The thief goes first. An equal fee does not replace it, and a higher one does.
    let held = link(coins[1], 1_000);
    send(&held).unwrap();
    let equal = file.build_escape(&[coins[1]], &destination(), 1_000).unwrap();
    assert!(send(&equal).is_err(), "an equal fee does not replace");
    let higher = file.build_escape(&[coins[1]], &destination(), 1_200).unwrap();
    send(&higher).unwrap();
    assert!(in_pool(&higher) && !in_pool(&held));
    node.generate(1);
    assert_eq!(node.confirmations(&higher, 0), Some(1), "the owner is out");

    // A stacked chain in the mempool: the escape has to beat the sum of all three.
    let l1 = link(coins[2], 1_000);
    let c1 = child_of(&l1, coins[2], 1_000);
    let l2 = link(c1, 1_000);
    let c2 = child_of(&l2, c1, 1_000);
    let l3 = link(c2, 1_000);
    for tx in [&l1, &l2, &l3] {
        send(tx).unwrap();
    }
    let short = file.build_escape(&[coins[2]], &destination(), 2_500).unwrap();
    assert!(send(&short).is_err(), "2,500 sats does not beat 3,000 of stacked fees, at any rate");
    let enough = file.build_escape(&[coins[2]], &destination(), 3_500).unwrap();
    send(&enough).unwrap();
    assert!(in_pool(&enough) && !in_pool(&l1) && !in_pool(&l3));

    // Links mined in one block restart the coin once: the last one is as old as the block.
    let l1 = link(coins[3], 500);
    let c1 = child_of(&l1, coins[3], 500);
    let l2 = link(c1, 500);
    send(&l1).unwrap();
    send(&l2).unwrap();
    node.generate(1);
    let last = child_of(&l2, c1, 500);
    let exit = file.build_escape(&[last], &destination(), 500).unwrap();
    assert!(node.mempool(&exit).unwrap_err().contains("non-BIP68-final"));
    node.generate(4);
    assert!(node.mempool(&exit).unwrap_err().contains("non-BIP68-final"), "at five confirmations");
    node.generate(1);
    node.mempool(&exit).expect("at six confirmations");
}
