//! Shared harness: sandbox setup, an independent copy of every signed encoding, a stand-in MPC node,
//! and Bitcoin checks with a real library. Nothing here calls contract code to compute what the
//! contract should compute, so a disagreement shows up as a refused call.

use anyhow::{anyhow, Result};
use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::script::Builder;
use bitcoin::hashes::Hash;
use bitcoin::sighash::SighashCache;
use bitcoin::{absolute, transaction, Amount, EcdsaSighashType, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use borsh::BorshSerialize;
use ed25519_dalek::{Signer as _, SigningKey as EdKey};
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::PrimeField;
use k256::{NonZeroScalar, Scalar, U256};
use near_gas::NearGas;
use near_token::NearToken;
use near_workspaces::network::Sandbox;
use near_workspaces::result::ExecutionFinalResult;
use near_workspaces::{Account, Contract, Worker};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sha3::Sha3_256;

pub const TWEAK_PREFIX: &str = "near-mpc-recovery v0.1.0 epsilon derivation:";
pub const MAX_GAS_TGAS: u64 = 1000;
pub const SIGN_TGAS: u64 = 30;
pub const CALLBACK_TGAS: u64 = 10;
pub const DERIVE_TGAS: u64 = 30;
pub const ORIGIN: &str = "https://app.example";
pub const RP_ID: &str = "app.example";
pub const OUTFLOW_CAP: u64 = 1_000_000;
pub const MINUTE_MS: u64 = 60_000;

pub fn wasm(name: &str) -> Vec<u8> {
    let dir = std::env::var("UNDO_WASM_DIR").expect("set UNDO_WASM_DIR, scripts/protocol-check.sh does");
    std::fs::read(format!("{dir}/{name}.wasm")).expect("run scripts/build.sh first")
}

/// Test-only keys, derived at run time so no key material is committed.
pub fn test_key(label: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"undo-test-only:");
    h.update(label.as_bytes());
    h.finalize().into()
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub fn gas(tgas: u64) -> NearGas {
    NearGas::from_tgas(tgas)
}

pub fn tgas(g: u64) -> f64 {
    g as f64 / 1e12
}

pub fn derive_tweak(predecessor: &str, path: &str) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(format!("{TWEAK_PREFIX}{predecessor},{path}"));
    h.finalize().into()
}

fn tweak_scalar(tweak: &[u8; 32]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(tweak.into())
}

/// Same arithmetic as the live signer: root + tweak.
pub fn derived_signing_key(secret: &[u8; 32], tweak: &[u8; 32]) -> SigningKey {
    let base = Scalar::from_repr((*secret).into()).unwrap();
    SigningKey::from(NonZeroScalar::new(base + tweak_scalar(tweak)).unwrap())
}

pub fn compressed(key: &SigningKey) -> Vec<u8> {
    key.verifying_key().to_encoded_point(true).as_bytes().to_vec()
}

/// What a node would submit. `high_s` deliberately returns the malleated form.
pub fn node_response(secret: &[u8; 32], tweak: &[u8; 32], payload: &[u8; 32], high_s: bool) -> Value {
    let key = derived_signing_key(secret, tweak);
    let (sig, recid) = key.sign_prehash_recoverable(payload).unwrap();
    let bytes = sig.to_bytes();
    let mut s: [u8; 32] = bytes[32..].try_into().unwrap();
    let mut v = recid.to_byte();
    if high_s {
        let negated = -<Scalar as Reduce<U256>>::reduce_bytes((&s).into());
        s = negated.to_repr().into();
        v ^= 1;
    }
    let mut big_r = vec![2 + recid.is_y_odd() as u8];
    big_r.extend_from_slice(&bytes[..32]);
    json!({
        "scheme": "Secp256k1",
        "big_r": {"affine_point": hex::encode(big_r)},
        "s": {"scalar": hex::encode(s)},
        "recovery_id": v,
    })
}

/// r || s || v from a secp256k1 key over a prehash.
pub fn secp_sign(key: &SigningKey, digest: &[u8; 32]) -> Vec<u8> {
    let (sig, recid) = key.sign_prehash_recoverable(digest).unwrap();
    let mut out = sig.to_bytes().to_vec();
    out.push(recid.to_byte());
    out
}

// ---------------------------------------------------------------- the same encodings, written again

#[derive(BorshSerialize)]
struct IntentBytes<'a> {
    tag: &'a str,
    contract: &'a str,
    vault: &'a [u8; 32],
    method: &'a str,
    args_hash: [u8; 32],
    expires_at: u64,
    nonce: Option<u64>,
}

pub fn intent_digest<A: BorshSerialize>(tag: &str, contract: &str, vault: &[u8; 32], method: &str, args: &A, expires_at: u64, nonce: Option<u64>) -> [u8; 32] {
    let bytes = IntentBytes { tag, contract, vault, method, args_hash: sha256(&borsh::to_vec(args).unwrap()), expires_at, nonce };
    sha256(&borsh::to_vec(&bytes).unwrap())
}

/// What the escape key signs at creation. Tagged, so it cannot be a sighash.
pub fn leaf_pop_digest(create_digest: &[u8; 32]) -> [u8; 32] {
    let mut preimage = b"undo-leaf-pop-v1".to_vec();
    preimage.extend_from_slice(create_digest);
    sha256(&preimage)
}

/// The script, built by rust-bitcoin and not by this repo's crates.
pub fn witness_script(k_u: &[u8], k_m: &[u8], k_e: &[u8], csv: i64) -> ScriptBuf {
    let key = |k: &[u8]| bitcoin::PublicKey::from_slice(k).unwrap();
    Builder::new()
        .push_opcode(OP_IF)
        .push_key(&key(k_u))
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_key(&key(k_m))
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ELSE)
        .push_int(csv)
        .push_opcode(OP_CSV)
        .push_opcode(OP_DROP)
        .push_key(&key(k_e))
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ENDIF)
        .into_script()
}

/// A coin, with its txid as block explorers display it.
#[derive(Clone, Debug)]
pub struct Coin {
    pub txid: [u8; 32],
    pub vout: u32,
    pub value: u64,
}

impl Coin {
    pub fn internal(&self) -> [u8; 32] {
        let mut t = self.txid;
        t.reverse();
        t
    }

    pub fn outpoint(&self) -> OutPoint {
        OutPoint { txid: Txid::from_byte_array(self.internal()), vout: self.vout }
    }

    pub fn with_value(&self, value: u64) -> Coin {
        Coin { value, ..self.clone() }
    }

    pub fn json(&self) -> Value {
        json!({"txid": hex::encode(self.txid), "vout": self.vout, "value": self.value})
    }
}

pub fn coins(label: &str, n: usize, value: u64) -> Vec<Coin> {
    (0..n).map(|i| Coin { txid: test_key(&format!("{label}-txid-{i}")), vout: i as u32, value }).collect()
}

pub fn coins_json(c: &[Coin]) -> Value {
    Value::Array(c.iter().map(Coin::json).collect())
}

/// Co-signed shape: version 2, locktime 0, replaceable. One destination, then change to the vault.
pub fn unsigned_tx(inputs: &[Coin], to: &[u8], amount: u64, change: Option<(u64, &ScriptBuf)>) -> Transaction {
    let mut output = vec![TxOut { value: Amount::from_sat(amount), script_pubkey: ScriptBuf::from_bytes(to.to_vec()) }];
    if let Some((value, spk)) = change {
        output.push(TxOut { value: Amount::from_sat(value), script_pubkey: spk.clone() });
    }
    Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: inputs
            .iter()
            .map(|c| TxIn { previous_output: c.outpoint(), script_sig: ScriptBuf::new(), sequence: Sequence(0xffff_fffd), witness: Witness::new() })
            .collect(),
        output,
    }
}

pub fn sighash(tx: &Transaction, index: usize, script: &ScriptBuf, declared: u64) -> [u8; 32] {
    SighashCache::new(tx)
        .p2wsh_signature_hash(index, script, Amount::from_sat(declared), EcdsaSighashType::All)
        .unwrap()
        .to_byte_array()
}

pub fn p2wpkh(label: &str) -> Vec<u8> {
    let mut script = vec![0x00, 0x14];
    script.extend_from_slice(&test_key(label)[..20]);
    script
}

// ---------------------------------------------------------------- webauthn

/// How to bend one assertion. The default is what a real phone sends.
#[derive(Clone, Debug)]
pub struct Bend {
    pub flags: u8,
    pub kind: &'static str,
    pub origin: &'static str,
    pub cross_origin: Option<bool>,
    pub rp_id: &'static str,
    pub wrong_challenge: bool,
    pub high_s: bool,
}

impl Default for Bend {
    fn default() -> Self {
        Bend { flags: 0x05, kind: "webauthn.get", origin: ORIGIN, cross_origin: None, rp_id: RP_ID, wrong_challenge: false, high_s: false }
    }
}

fn base64url(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    bytes
        .chunks(3)
        .flat_map(|c| {
            let n = (u32::from(c[0]) << 16) | (u32::from(*c.get(1).unwrap_or(&0)) << 8) | u32::from(*c.get(2).unwrap_or(&0));
            (0..=c.len()).map(move |i| A[((n >> (18 - 6 * i)) & 63) as usize] as char).collect::<Vec<_>>()
        })
        .collect()
}

/// A software authenticator, labelled as one in every claim that rests on it.
pub fn assertion(key: &p256::ecdsa::SigningKey, digest: &[u8; 32], bend: &Bend) -> Value {
    let mut auth = sha256(bend.rp_id.as_bytes()).to_vec();
    auth.push(bend.flags);
    auth.extend_from_slice(&1u32.to_be_bytes());
    let challenge = if bend.wrong_challenge { base64url(&[7u8; 32]) } else { base64url(digest) };
    let cross = match bend.cross_origin {
        Some(v) => format!(r#","crossOrigin":{v}"#),
        None => String::new(),
    };
    let client = format!(r#"{{"type":"{}","challenge":"{challenge}","origin":"{}"{cross}}}"#, bend.kind, bend.origin);
    let mut signed = auth.clone();
    signed.extend_from_slice(&sha256(client.as_bytes()));
    let sig: p256::ecdsa::Signature = key.sign_prehash(&sha256(&signed)).unwrap();
    let low = sig.normalize_s().unwrap_or(sig);
    let sig = if bend.high_s {
        let (r, s) = low.split_scalars();
        p256::ecdsa::Signature::from_scalars(*r, -*s).unwrap()
    } else {
        low
    };
    json!({
        "authenticator_data": hex::encode(auth),
        "client_data_json": hex::encode(client.as_bytes()),
        "signature": hex::encode(sig.to_bytes()),
    })
}

// ---------------------------------------------------------------- vaults

pub struct Vault {
    pub id: [u8; 32],
    pub k_s: EdKey,
    pub k_u: SigningKey,
    pub k_e_leaf: SigningKey,
    pub k_e_intent: SigningKey,
    pub passkey: p256::ecdsa::SigningKey,
    pub k_m: SigningKey,
    pub csv: u32,
    pub script: ScriptBuf,
    pub spk: ScriptBuf,
    pub spend_nonce: u64,
    pub passkey_nonce: u64,
}

impl Vault {
    pub fn hex(&self) -> String {
        hex::encode(self.id)
    }
}

pub struct Keys {
    pub k_s: EdKey,
    pub k_u: SigningKey,
    pub k_e_leaf: SigningKey,
    pub k_e_intent: SigningKey,
    pub passkey: p256::ecdsa::SigningKey,
}

pub fn secp(label: &str) -> SigningKey {
    SigningKey::from_bytes((&test_key(label)).into()).unwrap()
}

pub fn keys(label: &str) -> Keys {
    Keys {
        k_s: EdKey::from_bytes(&test_key(&format!("{label}-k_s"))),
        k_u: secp(&format!("{label}-k_u")),
        k_e_leaf: secp(&format!("{label}-k_e_leaf")),
        k_e_intent: secp(&format!("{label}-k_e_intent")),
        passkey: p256::ecdsa::SigningKey::from_bytes((&test_key(&format!("{label}-k_p"))).into()).unwrap(),
    }
}

pub fn p256_compressed(key: &p256::ecdsa::SigningKey) -> Vec<u8> {
    key.verifying_key().to_encoded_point(true).as_bytes().to_vec()
}

#[derive(Clone, Debug)]
pub struct Options {
    pub preset: &'static str,
    pub restrict_create: bool,
    pub mode: &'static str,
    pub callback_tgas: u64,
    pub origins: &'static [&'static str],
}

impl Default for Options {
    fn default() -> Self {
        Options { preset: "TestCoin", restrict_create: false, mode: "Yield", callback_tgas: CALLBACK_TGAS, origins: &[ORIGIN] }
    }
}

pub struct Harness {
    pub worker: Worker<Sandbox>,
    pub undo: Contract,
    pub mock: Contract,
    pub relayer: Account,
    pub secret: [u8; 32],
    pub operator_key: p256::ecdsa::SigningKey,
}

/// The operator passkey every test instance uses, as `new` takes it. A label, not a secret.
pub fn operator_key() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_bytes((&test_key("operator-passkey")).into()).unwrap()
}

pub fn operator_passkey_args() -> Value {
    json!({"pubkey": hex::encode(p256_compressed(&operator_key())), "rp_id_hash": hex::encode(sha256(RP_ID.as_bytes()))})
}

/// What create_vault is signed over. Tests change one field to show it is load-bearing.
pub struct CreateCall {
    pub k_m: Vec<u8>,
    pub csv: u32,
    pub policy: Option<[u64; 8]>,
    pub guard: Option<String>,
    pub expires_at: u64,
    pub deposit_milli: u128,
}

impl Harness {
    pub async fn new() -> Result<Self> {
        Self::with(Options::default()).await
    }

    pub async fn with(o: Options) -> Result<Self> {
        // UNDO_EXTERNAL_RPC and UNDO_EXTERNAL_HOME point at a node started by hand, for example one
        // whose genesis is pinned to an older protocol version.
        let worker = match (std::env::var("UNDO_EXTERNAL_RPC"), std::env::var("UNDO_EXTERNAL_HOME")) {
            (Ok(rpc), Ok(home)) => {
                near_workspaces::sandbox()
                    .rpc_addr(&rpc)
                    .validator_key(near_workspaces::network::ValidatorKey::HomeDir(home.into()))
                    .await?
            }
            _ => near_workspaces::sandbox().await?,
        };
        let secret = test_key("mock-root");
        let mock = worker.dev_deploy(&wasm("mock_signer")).await?;
        mock.call("new").args_json(json!({"secret_hex": hex::encode(secret), "mode": o.mode})).transact().await?.into_result()?;
        let undo = worker.dev_deploy(&wasm("undo_vault")).await?;
        let relayer = worker.dev_create_account().await?;
        undo.call("new")
            .args_json(json!({
                "preset": o.preset, "operator": relayer.id(), "restrict_create": o.restrict_create || o.preset == "MainnetProof",
                "signer": mock.id(), "domain_id": 0, "sign_tgas": SIGN_TGAS, "callback_tgas": o.callback_tgas,
                "derive_tgas": DERIVE_TGAS, "network": if o.preset == "MainnetProof" { "mainnet" } else { "mutinynet" },
                "origins": o.origins, "outflow_cap_24h": OUTFLOW_CAP, "operator_passkey": operator_passkey_args(),
            }))
            .transact()
            .await?
            .into_result()?;
        Ok(Self { worker, undo, mock, relayer, secret, operator_key: operator_key() })
    }

    pub fn contract(&self) -> &str {
        self.undo.id().as_str()
    }

    pub fn vault_id(&self, k: &Keys, csv: u32) -> [u8; 32] {
        let k_s = k.k_s.verifying_key().to_bytes();
        let bytes = (
            "undo-vault-id-v1",
            self.contract(),
            k_s,
            compressed(&k.k_u),
            compressed(&k.k_e_leaf),
            compressed(&k.k_e_intent),
            p256_compressed(&k.passkey),
            csv,
        );
        sha256(&borsh::to_vec(&bytes).unwrap())
    }

    pub fn mpc_key(&self, id: &[u8; 32]) -> SigningKey {
        derived_signing_key(&self.secret, &derive_tweak(self.contract(), &format!("undo/{}", hex::encode(id))))
    }

    /// Default arguments for a vault that should activate.
    pub fn create_call(&self, k: &Keys, csv: u32) -> CreateCall {
        CreateCall { k_m: compressed(&self.mpc_key(&self.vault_id(k, csv))), csv, policy: None, guard: None, expires_at: u64::MAX / 2, deposit_milli: 100 }
    }

    /// The deployed values for this instance, in the contract's own encoding order.
    pub async fn deployed_policy(&self) -> Result<[u64; 8]> {
        let v: Value = self.undo.view("instance").args_json(json!({})).await?.json()?;
        let p = &v["policy"];
        let f = |n: &str| p[n].as_u64().unwrap();
        Ok([f("t_known_ms"), f("t_new_ms"), f("t_new_unguarded_ms"), f("hold_ms"), f("t_stuck_ms"), f("fee_cap_tx"), f("fee_budget_24h"), f("outflow_cap_24h")])
    }

    pub async fn create_args(&self, k: &Keys, c: &CreateCall) -> Result<Value> {
        let id = self.vault_id(k, c.csv);
        let rp_id_hash = sha256(RP_ID.as_bytes());
        let policy = match c.policy {
            Some(p) => p,
            None => self.deployed_policy().await?,
        };
        let digest = sha256(
            &borsh::to_vec(&("undo-create-v1", self.contract(), id, c.k_m.clone(), rp_id_hash, c.guard.clone(), policy, c.expires_at)).unwrap(),
        );
        let policy_json = c.policy.map(|p| {
            json!({"t_known_ms": p[0], "t_new_ms": p[1], "t_new_unguarded_ms": p[2], "hold_ms": p[3], "t_stuck_ms": p[4], "fee_cap_tx": p[5], "fee_budget_24h": p[6], "outflow_cap_24h": p[7]})
        });
        Ok(json!({"args": {
            "k_s": hex::encode(k.k_s.verifying_key().to_bytes()),
            "k_u": hex::encode(compressed(&k.k_u)),
            "k_m": hex::encode(&c.k_m),
            "k_e_leaf": hex::encode(compressed(&k.k_e_leaf)),
            "k_e_intent": hex::encode(compressed(&k.k_e_intent)),
            "passkey": {"pubkey": hex::encode(p256_compressed(&k.passkey)), "rp_id_hash": hex::encode(rp_id_hash)},
            "guard": c.guard,
            "csv": c.csv,
            "policy": policy_json,
            "expires_at": c.expires_at,
            "pop_s": hex::encode(k.k_s.sign(&digest).to_bytes()),
            "pop_u": hex::encode(secp_sign(&k.k_u, &digest)),
            "pop_e": hex::encode(secp_sign(&k.k_e_intent, &digest)),
            "pop_leaf": hex::encode(secp_sign(&k.k_e_leaf, &leaf_pop_digest(&digest))),
            "pop_p": assertion(&k.passkey, &digest, &Bend::default()),
        }}))
    }

    pub async fn create_raw(&self, args: Value, deposit_milli: u128) -> Result<ExecutionFinalResult> {
        Ok(self
            .relayer
            .call(self.undo.id(), "create_vault")
            .args_json(args)
            .deposit(NearToken::from_millinear(deposit_milli))
            .gas(gas(300))
            .transact()
            .await?)
    }

    pub async fn create_vault(&self, label: &str) -> Result<Vault> {
        self.create_vault_csv(label, 6).await
    }

    pub async fn create_vault_csv(&self, label: &str, csv: u32) -> Result<Vault> {
        let k = keys(label);
        let call = self.create_call(&k, csv);
        let args = self.create_args(&k, &call).await?;
        self.create_raw(args, call.deposit_milli).await?.into_result()?;
        let id = self.vault_id(&k, csv);
        let k_m = self.mpc_key(&id);
        let script = witness_script(&compressed(&k.k_u), &compressed(&k_m), &compressed(&k.k_e_leaf), csv as i64);
        let spk = script.to_p2wsh();
        Ok(Vault {
            id,
            k_s: k.k_s,
            k_u: k.k_u,
            k_e_leaf: k.k_e_leaf,
            k_e_intent: k.k_e_intent,
            passkey: k.passkey,
            k_m,
            csv,
            script,
            spk,
            spend_nonce: 0,
            passkey_nonce: 0,
        })
    }

    /// A vault with the exact deposit its creation costs, read from the refusal, so its credit is zero.
    pub async fn create_vault_no_credit(&self, label: &str, csv: u32) -> Result<Vault> {
        let k = keys(label);
        let call = self.create_call(&k, csv);
        let args = self.create_args(&k, &call).await?;
        let res = self.relayer.call(self.undo.id(), "create_vault").args_json(args.clone()).deposit(NearToken::from_yoctonear(1)).gas(gas(300)).transact().await?;
        let need = yocto_after(&err_text(&res), "attach at least ");
        self.relayer.call(self.undo.id(), "create_vault").args_json(args).deposit(NearToken::from_yoctonear(need)).gas(gas(300)).transact().await?.into_result()?;
        let id = self.vault_id(&k, csv);
        let k_m = self.mpc_key(&id);
        let script = witness_script(&compressed(&k.k_u), &compressed(&k_m), &compressed(&k.k_e_leaf), csv as i64);
        let spk = script.to_p2wsh();
        Ok(Vault { id, k_s: k.k_s, k_u: k.k_u, k_e_leaf: k.k_e_leaf, k_e_intent: k.k_e_intent, passkey: k.passkey, k_m, csv, script, spk, spend_nonce: 0, passkey_nonce: 0 })
    }

    /// Proposes with exactly the credit it costs, read from the refusal, so the credit lands on zero.
    /// Returns the request and what it paid in.
    pub async fn propose_exact(&self, v: &mut Vault, inputs: &[Coin], to: &[u8], amount: u64, change: Option<u64>) -> Result<(u64, u128)> {
        let args = self.propose_args(v, inputs, to, amount, change, v.spend_nonce);
        let res = self.propose_raw(args.clone()).await?;
        let need = yocto_after(&err_text(&res), "need ");
        self.relayer.call(self.undo.id(), "deposit_storage").args_json(json!({"vault": v.hex()})).deposit(NearToken::from_yoctonear(need)).transact().await?.into_result()?;
        let res = self.propose_raw(args).await?;
        res.clone().into_result()?;
        v.spend_nonce += 1;
        Ok((res.json::<u64>()?, need))
    }

    // ------------------------------------------------------------ intents

    pub fn spend_digest<A: BorshSerialize>(&self, v: &Vault, method: &str, args: &A, expires_at: u64, nonce: u64) -> [u8; 32] {
        intent_digest("undo-spend-v1", self.contract(), &v.id, method, args, expires_at, Some(nonce))
    }

    pub fn passkey_digest<A: BorshSerialize>(&self, v: &Vault, method: &str, args: &A, expires_at: u64, nonce: Option<u64>) -> [u8; 32] {
        intent_digest("undo-passkey-v1", self.contract(), &v.id, method, args, expires_at, nonce)
    }

    pub fn propose_args(&self, v: &Vault, inputs: &[Coin], to: &[u8], amount: u64, change: Option<u64>, nonce: u64) -> Value {
        self.propose_args_memo(v, inputs, to, amount, change, nonce, None)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn propose_args_memo(&self, v: &Vault, inputs: &[Coin], to: &[u8], amount: u64, change: Option<u64>, nonce: u64, memo: Option<String>) -> Value {
        let tx = unsigned_tx(inputs, to, amount, change.map(|c| (c, &v.spk)));
        let half: Vec<String> = inputs
            .iter()
            .enumerate()
            .map(|(i, c)| hex::encode(secp_sign(&v.k_u, &sighash(&tx, i, &v.script, c.value))))
            .collect();
        let expires_at = u64::MAX / 2;
        let spend: Vec<([u8; 32], u32, u64)> = inputs.iter().map(|c| (c.internal(), c.vout, c.value)).collect();
        let digest = self.spend_digest(v, "propose_btc", &(spend, to.to_vec(), amount, change, memo.clone()), expires_at, nonce);
        json!({
            "vault": v.hex(), "inputs": coins_json(inputs), "to": hex::encode(to), "amount": amount, "change": change,
            "half_sigs": half, "nonce": nonce, "expires_at": expires_at, "memo": memo,
            "spend_sig": hex::encode(v.k_s.sign(&digest).to_bytes()),
        })
    }

    pub async fn propose_raw(&self, args: Value) -> Result<ExecutionFinalResult> {
        Ok(self.relayer.call(self.undo.id(), "propose_btc").args_json(args).gas(gas(300)).transact().await?)
    }

    /// Proposes as the owner. Returns the request id.
    pub async fn propose(&self, v: &mut Vault, inputs: &[Coin], to: &[u8], amount: u64, change: Option<u64>) -> Result<u64> {
        let args = self.propose_args(v, inputs, to, amount, change, v.spend_nonce);
        let res = self.propose_raw(args).await?;
        res.clone().into_result()?;
        v.spend_nonce += 1;
        Ok(res.json::<u64>()?)
    }

    /// One whole coin to a new address, at a fee of 500 sats. No change, so it needs no self-spend slot
    /// and a test can hold several at once. A spend with change goes through `propose` by name.
    pub async fn propose_simple(&self, v: &mut Vault, coin: &Coin) -> Result<u64> {
        let to = p2wpkh("destination");
        self.propose(v, std::slice::from_ref(coin), &to, coin.value - 500, None).await
    }

    pub fn reclaim_args(&self, v: &Vault, coin: &Coin, fee: u64, nonce: u64) -> Value {
        let spk = v.spk.to_bytes();
        let tx = unsigned_tx(std::slice::from_ref(coin), &spk, coin.value - fee, None);
        let half = secp_sign(&v.k_u, &sighash(&tx, 0, &v.script, coin.value));
        let expires_at = u64::MAX / 2;
        let spend: Vec<([u8; 32], u32, u64)> = vec![(coin.internal(), coin.vout, coin.value)];
        let digest = self.spend_digest(v, "reclaim", &(spend, fee), expires_at, nonce);
        json!({
            "vault": v.hex(), "utxo": coin.json(), "fee": fee, "half_sig": hex::encode(half),
            "nonce": nonce, "expires_at": expires_at, "spend_sig": hex::encode(v.k_s.sign(&digest).to_bytes()),
        })
    }

    pub async fn reclaim(&self, v: &mut Vault, coin: &Coin, fee: u64) -> Result<u64> {
        let args = self.reclaim_args(v, coin, fee, v.spend_nonce);
        let res = self.relayer.call(self.undo.id(), "reclaim").args_json(args).gas(gas(300)).transact().await?;
        res.clone().into_result()?;
        v.spend_nonce += 1;
        Ok(res.json::<u64>()?)
    }

    pub async fn cancel_passkey(&self, v: &Vault, request: u64) -> Result<ExecutionFinalResult> {
        self.cancel_bent(v, request, u64::MAX / 2, &Bend::default()).await
    }

    pub async fn cancel_bent(&self, v: &Vault, request: u64, expires_at: u64, bend: &Bend) -> Result<ExecutionFinalResult> {
        let digest = self.passkey_digest(v, "cancel", &request, expires_at, None);
        let auth = json!({"Passkey": assertion(&v.passkey, &digest, bend)});
        Ok(self
            .relayer
            .call(self.undo.id(), "cancel")
            .args_json(json!({"vault": v.hex(), "request": request, "expires_at": expires_at, "auth": auth}))
            .gas(gas(100))
            .transact()
            .await?)
    }

    pub fn cold_cancel_args(&self, v: &Vault, key: &SigningKey, request: u64) -> Value {
        let expires_at = u64::MAX / 2;
        let digest = intent_digest("undo-cold-v1", self.contract(), &v.id, "cancel", &request, expires_at, None);
        json!({"vault": v.hex(), "request": request, "expires_at": expires_at, "auth": {"Cold": hex::encode(secp_sign(key, &digest))}})
    }

    pub async fn rotate(&self, v: &mut Vault, new_k_s: &[u8; 32]) -> Result<u64> {
        let expires_at = u64::MAX / 2;
        let digest = self.passkey_digest(v, "cancel_all_and_rotate", new_k_s, expires_at, Some(v.passkey_nonce));
        let res = self
            .relayer
            .call(self.undo.id(), "cancel_all_and_rotate")
            .args_json(json!({
                "vault": v.hex(), "new_k_s": hex::encode(new_k_s), "nonce": v.passkey_nonce, "expires_at": expires_at,
                "assertion": assertion(&v.passkey, &digest, &Bend::default()),
            }))
            .gas(gas(100))
            .transact()
            .await?;
        res.clone().into_result()?;
        v.passkey_nonce += 1;
        Ok(res.json::<u64>()?)
    }

    pub async fn raise_fee_cap(&self, v: &mut Vault, request: u64, cap: u64) -> Result<()> {
        let expires_at = u64::MAX / 2;
        let digest = self.passkey_digest(v, "raise_fee_cap", &(request, cap), expires_at, Some(v.passkey_nonce));
        self.relayer
            .call(self.undo.id(), "raise_fee_cap")
            .args_json(json!({
                "vault": v.hex(), "request": request, "cap": cap, "nonce": v.passkey_nonce, "expires_at": expires_at,
                "assertion": assertion(&v.passkey, &digest, &Bend::default()),
            }))
            .gas(gas(100))
            .transact()
            .await?
            .into_result()?;
        v.passkey_nonce += 1;
        Ok(())
    }

    /// A passkey-signed call with every field in the caller's hands, so a test can bend one. `args` are
    /// the bytes the assertion commits to, and `call` is the method's own JSON.
    #[allow(clippy::too_many_arguments)]
    pub async fn passkey_call<A: BorshSerialize>(&self, v: &Vault, key: &p256::ecdsa::SigningKey, method: &str, args: &A, mut call: Value, nonce: u64, expires_at: u64) -> Result<ExecutionFinalResult> {
        let digest = self.passkey_digest(v, method, args, expires_at, Some(nonce));
        call["vault"] = json!(v.hex());
        call["nonce"] = json!(nonce);
        call["expires_at"] = json!(expires_at);
        call["assertion"] = assertion(key, &digest, &Bend::default());
        Ok(self.relayer.call(self.undo.id(), method).args_json(call).gas(gas(100)).transact().await?)
    }

    /// A cold-key call, the same way.
    #[allow(clippy::too_many_arguments)]
    pub async fn cold_call<A: BorshSerialize>(&self, v: &Vault, key: &SigningKey, method: &str, args: &A, mut call: Value, nonce: u64, expires_at: u64) -> Result<ExecutionFinalResult> {
        let digest = intent_digest("undo-cold-v1", self.contract(), &v.id, method, args, expires_at, Some(nonce));
        call["vault"] = json!(v.hex());
        call["nonce"] = json!(nonce);
        call["expires_at"] = json!(expires_at);
        call["signature"] = json!(hex::encode(secp_sign(key, &digest)));
        Ok(self.relayer.call(self.undo.id(), method).args_json(call).gas(gas(100)).transact().await?)
    }

    pub async fn nonce_of(&self, v: &Vault, which: &str) -> Result<u64> {
        Ok(self.vault_view(v).await?[which].as_u64().unwrap())
    }

    /// Everything `recover_begin` needs, with the new passkey signing the same digest as the cold key.
    #[allow(clippy::too_many_arguments)]
    pub async fn recover_begin_with(&self, v: &Vault, cold: &SigningKey, new_key: &p256::ecdsa::SigningKey, pop_key: &p256::ecdsa::SigningKey, nonce: u64, expires_at: u64) -> Result<ExecutionFinalResult> {
        let rp_id_hash = sha256(RP_ID.as_bytes());
        let args = (p256_compressed(new_key), rp_id_hash);
        let digest = intent_digest("undo-cold-v1", self.contract(), &v.id, "recover_begin", &args, expires_at, Some(nonce));
        let call = json!({
            "new_passkey": {"pubkey": hex::encode(p256_compressed(new_key)), "rp_id_hash": hex::encode(rp_id_hash)},
            "pop_p": assertion(pop_key, &digest, &Bend::default()),
        });
        self.cold_call(v, cold, "recover_begin", &args, call, nonce, expires_at).await
    }

    pub async fn prune(&self, v: &Vault, id: u64) -> Result<ExecutionFinalResult> {
        Ok(self.relayer.call(self.undo.id(), "prune_signed").args_json(json!({"vault": v.hex(), "request": id})).gas(gas(100)).transact().await?)
    }

    // ------------------------------------------------------------ views

    pub async fn vault_view(&self, v: &Vault) -> Result<Value> {
        Ok(self.undo.view("vault").args_json(json!({"vault": v.hex()})).await?.json()?)
    }

    pub async fn credit(&self, v: &Vault) -> Result<u128> {
        Ok(self.vault_view(v).await?["storage_credit"].as_str().unwrap().parse()?)
    }

    pub async fn request(&self, v: &Vault, id: u64) -> Result<Value> {
        Ok(self.undo.view("request").args_json(json!({"vault": v.hex(), "request": id})).await?.json()?)
    }

    /// The page's rule, in one place. A rotation or a freeze moves the epoch at once and a Pending request
    /// stays in the row until the next state change sweeps it, so reading only its status would let the
    /// clock run on. One that has reached Signing keeps going whatever the epoch says. Gone reads as
    /// cancelled, for a request last read as Pending: a pruned Signed one is gone too, and a page knows
    /// which it last saw.
    pub async fn reads_cancelled(&self, v: &Vault, id: u64) -> Result<bool> {
        let r = self.request(v, id).await?;
        Ok(r.is_null() || (r["status"] == "Pending" && r["epoch"] != self.vault_view(v).await?["spend_epoch"]))
    }

    pub async fn status(&self, v: &Vault, id: u64) -> Result<String> {
        Ok(self.request(v, id).await?["status"].as_str().unwrap_or("deleted").to_string())
    }

    pub async fn outpoint(&self, v: &Vault, c: &Coin) -> Result<Value> {
        Ok(self.undo.view("outpoint").args_json(json!({"vault": v.hex(), "txid": hex::encode(c.txid), "vout": c.vout})).await?.json()?)
    }

    pub async fn payloads(&self, v: &Vault, id: u64) -> Result<Vec<[u8; 32]>> {
        let list: Vec<String> = self.undo.view("payloads").args_json(json!({"vault": v.hex(), "request": id})).await?.json()?;
        Ok(list.iter().map(|p| hex::decode(p).unwrap().try_into().unwrap()).collect())
    }

    pub async fn final_tx(&self, v: &Vault, id: u64) -> Result<Option<Transaction>> {
        let raw: Option<String> = self.undo.view("final_tx").args_json(json!({"vault": v.hex(), "request": id})).await?.json()?;
        Ok(raw.map(|h| bitcoin::consensus::deserialize(&hex::decode(h).unwrap()).unwrap()))
    }

    // ------------------------------------------------------------ time

    pub async fn now_ms(&self) -> Result<u64> {
        Ok(self.worker.view_block().await?.timestamp() / 1_000_000)
    }

    pub async fn height(&self) -> Result<u64> {
        Ok(self.worker.view_block().await?.height())
    }

    /// Moves the sandbox clock to at least `target_ms`. Fast-forward advances block time by an
    /// average block interval per block, so this looks at the clock and not at a block count.
    pub async fn advance_to(&self, target_ms: u64) -> Result<()> {
        for _ in 0..40 {
            let now = self.now_ms().await?;
            if now >= target_ms {
                return Ok(());
            }
            let blocks = (target_ms - now) / 500 + 5;
            self.worker.fast_forward(blocks.min(5_000)).await?;
        }
        Err(anyhow!("clock never reached the target"))
    }

    pub async fn wait_unlock(&self, v: &Vault, id: u64) -> Result<()> {
        let unlock = self.request(v, id).await?["unlock"].as_u64().unwrap();
        self.advance_to(unlock + 1).await
    }

    // ------------------------------------------------------------ signer

    pub async fn wait_pending(&self, n: usize) -> Result<Vec<Value>> {
        for _ in 0..300 {
            let pending: Vec<Value> = self.mock.view("pending").args_json(json!({})).await?.json()?;
            if pending.len() >= n {
                return Ok(pending);
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
        Err(anyhow!("signer never saw {n} pending requests"))
    }

    /// Plays the MPC node for every queued request.
    pub async fn respond_all(&self, n: usize, high_s: bool) -> Result<()> {
        for request in self.wait_pending(n).await? {
            self.respond_one(&request, high_s).await?.into_result()?;
        }
        Ok(())
    }

    pub async fn respond_one(&self, request: &Value, high_s: bool) -> Result<ExecutionFinalResult> {
        let tweak: [u8; 32] = hex::decode(request["tweak"].as_str().unwrap())?.try_into().unwrap();
        let payload: [u8; 32] = hex::decode(request["payload"]["Ecdsa"].as_str().unwrap())?.try_into().unwrap();
        let response = node_response(&self.secret, &tweak, &payload, high_s);
        Ok(self
            .relayer
            .call(self.mock.id(), "respond")
            .args_json(json!({"request": request, "response": response}))
            .gas(gas(100))
            .transact()
            .await?)
    }

    pub fn execute_call(&self, v: &Vault, id: u64, max_inputs: Option<u32>) -> near_workspaces::operations::CallTransaction {
        self.relayer
            .call(self.undo.id(), "execute")
            .args_json(json!({"vault": v.hex(), "request": id, "max_inputs": max_inputs}))
            .gas(gas(MAX_GAS_TGAS))
    }

    /// Runs execute with the signer in Yield mode, answering like a node, and returns the result.
    pub async fn execute_and_respond(&self, v: &Vault, id: u64, n: usize, high_s: bool) -> Result<ExecutionFinalResult> {
        self.execute_with(self.execute_call(v, id, None), n, high_s).await
    }

    pub async fn execute_with(&self, call: near_workspaces::operations::CallTransaction, n: usize, high_s: bool) -> Result<ExecutionFinalResult> {
        let task = tokio::spawn(async move { call.transact().await });
        self.respond_all(n, high_s).await?;
        Ok(task.await??)
    }

    /// For a call that may be refused before it reaches the signer. A transaction waiting on the
    /// signer blocks, and the client resends one that blocks too long, so this answers as soon as
    /// the signer has the requests, and returns early when the call ends first.
    pub async fn execute_racing(&self, call: near_workspaces::operations::CallTransaction, n: usize) -> Result<std::result::Result<ExecutionFinalResult, String>> {
        let mut task = tokio::spawn(async move { call.transact().await });
        let done = tokio::select! {
            done = &mut task => done?,
            queued = self.wait_pending(n) => {
                for q in queued? {
                    self.respond_one(&q, false).await?.into_result()?;
                }
                task.await?
            }
        };
        Ok(done.map_err(|e| format!("{e:?}")))
    }

    /// A consensus verdict on the contract's own `final_tx`.
    pub async fn verified_final_tx(&self, v: &Vault, id: u64, real: &[Coin]) -> Result<Transaction> {
        let tx = self.final_tx(v, id).await?.ok_or_else(|| anyhow!("final_tx returned nothing"))?;
        consensus_verify(&tx, &spent_outputs(real, &v.spk))?;
        Ok(tx)
    }
}

/// Runs libbitcoinconsensus over every input against the given previous outputs.
pub fn consensus_verify(tx: &Transaction, spent: &[(OutPoint, TxOut)]) -> Result<()> {
    tx.verify(|op| spent.iter().find(|(o, _)| o == op).map(|(_, t)| t.clone()))
        .map_err(|e| anyhow!("consensus rejected: {e:?}"))
}

pub fn spent_outputs(coins: &[Coin], spk: &ScriptBuf) -> Vec<(OutPoint, TxOut)> {
    coins
        .iter()
        .map(|c| (c.outpoint(), TxOut { value: Amount::from_sat(c.value), script_pubkey: spk.clone() }))
        .collect()
}

/// The digits after `marker` in a refusal.
pub fn yocto_after(text: &str, marker: &str) -> u128 {
    let at = text.find(marker).unwrap_or_else(|| panic!("no {marker:?} in {text}")) + marker.len();
    text[at..].chars().take_while(char::is_ascii_digit).collect::<String>().parse().unwrap()
}

/// A coin a signed transaction pays out at `vout`, named as an explorer would name it.
pub fn output_coin(tx: &Transaction, vout: u32) -> Coin {
    let mut txid = tx.compute_txid().to_byte_array();
    txid.reverse();
    Coin { txid, vout, value: tx.output[vout as usize].value.to_sat() }
}

/// Failure text of a transaction, panics and all.
pub fn err_text(res: &ExecutionFinalResult) -> String {
    res.failures().iter().map(|f| format!("{:?}", (*f).clone().into_result().err())).collect::<Vec<_>>().join(" | ")
}

pub fn assert_refused(res: &ExecutionFinalResult, needle: &str) {
    assert!(res.is_failure(), "expected refusal containing {needle:?}, but it succeeded");
    let text = err_text(res);
    assert!(text.contains(needle), "expected refusal containing {needle:?}, got {text}");
}

pub fn own_gas(res: &ExecutionFinalResult, executor: &str, needle: Option<&str>) -> Vec<u64> {
    res.receipt_outcomes()
        .iter()
        .filter(|o| o.executor_id.as_str() == executor)
        .filter(|o| needle.is_none_or(|n| o.logs.iter().any(|l| l.contains(n))))
        .map(|o| o.gas_burnt.as_gas())
        .collect()
}
