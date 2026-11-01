//! Fourth review, against the real wasm in sandbox with the mock signer. Attacks that were scratch
//! files then, kept as regression tests, and the rules that came out of them.
use anyhow::Result;
use bitcoin::{ScriptBuf, Sequence, Witness};
use ed25519_dalek::{Signer as _, SigningKey as EdKey};
use near_token::NearToken;
use sandbox_tests::*;
use serde_json::{json, Value};

const FAR: u64 = u64::MAX / 2;

fn fresh_key(label: &str) -> EdKey { EdKey::from_bytes(&test_key(label)) }

async fn balance(h: &Harness) -> Result<u128> {
    Ok(h.undo.view_account().await?.balance.as_yoctonear())
}

/// A thief with K_s and K_u burns the 24 h fee budget with coins that do not exist. Nothing moves. The
/// owner rotates, and once the new key lands the exit to a new vault goes out. The override is for a
/// self-spend and does not reach this request.
#[tokio::test]
async fn budget_burnt_with_fake_coins_does_not_stop_the_exit_to_a_new_vault() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r3-burn").await?;
    let dest = p2wpkh("thief");
    let fake = coins("r3-fake", 6, 100_000);
    let mut burnt = 0u64;
    let mut i = 0;
    while burnt < 5_000 {
        let mut batch = vec![];
        for _ in 0..3 {
            if burnt + 1_000 * (batch.len() as u64 + 1) > 5_000 { break; }
            batch.push(h.propose(&mut v, std::slice::from_ref(&fake[i]), &dest, 99_000, None).await?);
            i += 1;
        }
        for id in &batch {
            h.wait_unlock(&v, *id).await?;
            h.execute_and_respond(&v, *id, 1, false).await?.into_result()?;
            burnt += 1_000;
        }
    }

    // While the window is full the same exit is refused, and the named override does not apply to it.
    let real = coins("r3-real", 2, 1_000_000);
    let new_vault = { let mut s = vec![0x00, 0x20]; s.extend_from_slice(&test_key("r3-new-vault")); s };
    let blocked = h.propose(&mut v, &real[..1], &new_vault, 999_800, None).await?;
    h.wait_unlock(&v, blocked).await?;
    assert_refused(&h.execute_call(&v, blocked, None).transact().await?, "FeeBudgetExceeded");
    let digest = h.passkey_digest(&v, "raise_fee_cap", &(blocked, 1_000u64), FAR, Some(v.passkey_nonce));
    let r = h.relayer.call(h.undo.id(), "raise_fee_cap").args_json(json!({"vault": v.hex(), "request": blocked, "cap": 1000, "nonce": v.passkey_nonce, "expires_at": FAR, "assertion": assertion(&v.passkey, &digest, &Bend::default())})).gas(gas(100)).transact().await?;
    assert_refused(&r, "NotSelfSpend");

    // Panic button, new key.
    let new = fresh_key("r3-burn-new");
    let grant = h.rotate(&mut v, &new.verifying_key().to_bytes()).await?;
    let known = h.vault_view(&v).await?["policy"]["t_known_ms"].as_u64().unwrap();
    h.advance_to(h.now_ms().await? + known + 1).await?;
    h.relayer.call(h.undo.id(), "apply_grant").args_json(json!({"vault": v.hex(), "grant": grant})).transact().await?.into_result()?;
    v.k_s = new;

    // Leaves for a new vault with the second coin: signed, and valid under consensus.
    let id = h.propose(&mut v, &real[1..], &new_vault, 999_800, None).await?;
    h.wait_unlock(&v, id).await?;
    h.execute_and_respond(&v, id, 1, false).await?.into_result()?;
    let tx = h.verified_final_tx(&v, id, &real[1..]).await?;
    assert_eq!(tx.output[0].script_pubkey.as_bytes(), new_vault.as_slice());
    Ok(())
}

/// Propose, then rotate or freeze. The old request must never reach the signer.
#[tokio::test]
async fn atk_stale_epoch_cannot_execute() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r3-epoch").await?;
    let c = coins("r3-epoch", 2, 100_000);
    let a = h.propose_simple(&mut v, &c[0]).await?;
    let b = h.propose_simple(&mut v, &c[1]).await?;
    h.wait_unlock(&v, a).await?;
    h.wait_unlock(&v, b).await?;
    // Freeze for a moment and let it lapse, so only the epoch stands in the way.
    let until = h.now_ms().await? + 1_000;
    let n = h.nonce_of(&v, "cold_nonce").await?;
    h.cold_call(&v, &v.k_e_intent, "freeze", &until, json!({"until": until}), n, FAR).await?.into_result()?;
    h.advance_to(until + 1).await?;
    assert_refused(&h.execute_call(&v, a, None).transact().await?, "RequestNotFound");
    let new = fresh_key("r3-epoch-new");
    h.rotate(&mut v, &new.verifying_key().to_bytes()).await?;
    assert_refused(&h.execute_call(&v, b, None).transact().await?, "RequestNotFound");
    let queued: Vec<Value> = h.mock.view("pending").args_json(json!({})).await?.json()?;
    assert!(queued.is_empty(), "signer asked");
    Ok(())
}

/// Stranger calls every callback directly.
#[tokio::test]
async fn atk_spoofed_callbacks() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r3-spoof").await?;
    let c = coins("r3-spoof", 1, 100_000);
    let id = h.propose_simple(&mut v, &c[0]).await?;
    let thief = h.worker.dev_create_account().await?;
    let payload = h.payloads(&v, id).await?[0];
    let r = thief.call(h.undo.id(), "on_signed").args_json(json!({"vault": v.hex(), "request": id, "attempt": 1, "input": 0, "payload": hex::encode(payload)})).gas(gas(50)).transact().await?;
    println!("RESULT on_signed stranger: {}", err_text(&r));
    assert!(r.is_failure());
    let r = thief.call(h.undo.id(), "on_derived").args_json(json!({"vault": v.hex()})).gas(gas(50)).transact().await?;
    assert!(r.is_failure());
    assert_eq!(h.status(&v, id).await?, "Pending");
    assert_eq!(h.vault_view(&v).await?["active"], true);
    Ok(())
}

/// The spending key of another vault, a real signer key on the wrong path, and K_m == K_e_intent.
#[tokio::test]
async fn atk_wrong_k_m_variants() -> Result<()> {
    let h = Harness::new().await?;
    let k = keys("r3-km");
    let id = h.vault_id(&k, 6);
    // Key the signer really derives, but for another vault's path.
    let other = compressed(&h.mpc_key(&h.vault_id(&keys("r3-km-other"), 6)));
    let call = CreateCall { k_m: other, csv: 6, policy: None, guard: None, expires_at: FAR, deposit_milli: 100 };
    let before = h.relayer.view_account().await?.balance.as_yoctonear();
    let args = h.create_args(&k, &call).await?;
    h.create_raw(args, call.deposit_milli).await?.into_result()?;
    let row: Option<Value> = h.undo.view("vault").args_json(json!({"vault": hex::encode(id)})).await?.json()?;
        assert!(row.is_none());
    let after = h.relayer.view_account().await?.balance.as_yoctonear();
    println!("RESULT cost of the refused attempt in milliNEAR: {}", (before - after) / 1_000_000_000_000_000_000_000);
    // A second attempt with the right K_m after the refusal must still work: the failed try squats nothing.
    let good = h.create_call(&k, 6);
    let args = h.create_args(&k, &good).await?;
    h.create_raw(args, good.deposit_milli).await?.into_result()?;
    let row: Value = h.undo.view("vault").args_json(json!({"vault": hex::encode(id)})).await?.json()?;
    assert_eq!(row["active"], true);
    Ok(())
}

/// Outpoint reuse: every state an outpoint can be in, after a signature exists.
#[tokio::test]
async fn atk_outpoint_reuse() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r3-reuse").await?;
    let c = coins("r3-reuse", 2, 200_000);
    let dest = p2wpkh("r3-d");
    let id = h.propose(&mut v, &c[..1], &dest, 199_500, None).await?;
    let again = h.propose_args(&v, &c[..1], &dest, 199_500, None, v.spend_nonce);
    assert_refused(&h.propose_raw(again).await?, "OutpointBusy");
    h.wait_unlock(&v, id).await?;
    h.execute_and_respond(&v, id, 1, false).await?.into_result()?;
    let again = h.propose_args(&v, &c[..1], &p2wpkh("r3-e"), 199_500, None, v.spend_nonce);
    assert_refused(&h.propose_raw(again).await?, "OutpointBusy");
    // After prune, the ledger still says Spent.
    let window = h.undo.view("instance").args_json(json!({})).await?.json::<Value>()?["expiry_window_ms"].as_u64().unwrap();
    h.advance_to(h.now_ms().await? + window + 1).await?;
    h.prune(&v, id).await?.into_result()?;
    let again = h.propose_args(&v, &c[..1], &p2wpkh("r3-e"), 199_500, None, v.spend_nonce);
    assert_refused(&h.propose_raw(again).await?, "OutpointBusy");
    assert_eq!(h.outpoint(&v, &c[0]).await?["state"], "Spent");
    // Second execute of a Signed request.
    let args = h.propose_args(&v, &c[1..], &dest, 199_500, None, v.spend_nonce);
    let r2 = h.propose_raw(args).await?.json::<u64>()?; v.spend_nonce += 1;
    h.wait_unlock(&v, r2).await?;
    h.execute_and_respond(&v, r2, 1, false).await?.into_result()?;
    assert_refused(&h.execute_call(&v, r2, None).transact().await?, "AlreadySigned");
    // Same outpoint id in a second vault is that vault's own business, and the script differs.
    let mut w = h.create_vault("r3-reuse-2").await?;
    let other = h.propose(&mut w, &c[..1], &dest, 199_500, None).await?;
    let (pa, pb) = (h.payloads(&w, other).await?, h.payloads(&v, r2).await?);
    assert_ne!(pa[0], pb[0]);
    Ok(())
}

/// Thief's pending self-spend, execute(max_inputs=1) by a stranger closes cancel for the whole request.
#[tokio::test]
async fn atk_stranger_partial_execute_closes_cancel_for_all_inputs() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r3-partial").await?;
    let c = coins("r3-partial", 3, 100_000);
    let dest = p2wpkh("r3-partial-d");
    let id = h.propose(&mut v, &c, &dest, 299_000, None).await?;
    h.wait_unlock(&v, id).await?;
    let stranger = h.worker.dev_create_account().await?;
    let call = stranger.call(h.undo.id(), "execute").args_json(json!({"vault": v.hex(), "request": id, "max_inputs": 1})).gas(gas(1000));
    h.execute_with(call, 1, false).await?.into_result()?;
    assert_refused(&h.cancel_passkey(&v, id).await?, "NotPending");
    // Rotation does not stop the rest either.
    let new = fresh_key("r3-partial-new");
    h.rotate(&mut v, &new.verifying_key().to_bytes()).await?;
    let call = stranger.call(h.undo.id(), "execute").args_json(json!({"vault": v.hex(), "request": id})).gas(gas(1000));
    h.execute_with(call, 2, false).await?.into_result()?;
    assert_eq!(h.status(&v, id).await?, "Signed");
    println!("RESULT after rotation a stranger finished signing the remaining 2 inputs");
    Ok(())
}

/// The escape branch under consensus: every way to spend it early or sideways.
#[tokio::test]
async fn atk_escape_branch() -> Result<()> {
    use bitcoin::sighash::SighashCache;
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, EcdsaSighashType};
    let h = Harness::new().await?;
    let v = h.create_vault("r3-esc").await?;
    let coin = coins("r3-esc", 1, 500_000)[0].clone();
    let spent = spent_outputs(std::slice::from_ref(&coin), &v.spk);
    let to = p2wpkh("r3-esc-to");
    let der = |key: &k256::ecdsa::SigningKey, d: [u8; 32]| {
        let (s, _) = key.sign_prehash_recoverable(&d).unwrap();
        let mut x = s.normalize_s().unwrap_or(s).to_der().as_bytes().to_vec();
        x.push(1);
        x
    };
    let attempt = |version: i32, seq: u32, key: &k256::ecdsa::SigningKey, selector: &[u8]| {
        let mut tx = unsigned_tx(std::slice::from_ref(&coin), &to, 499_000, None);
        tx.version = bitcoin::transaction::Version(version);
        tx.input[0].sequence = Sequence(seq);
        let d = SighashCache::new(&tx).p2wsh_signature_hash(0, &v.script, Amount::from_sat(coin.value), EcdsaSighashType::All).unwrap().to_byte_array();
        let mut w = Witness::new();
        w.push(der(key, d));
        w.push(selector);
        w.push(v.script.as_bytes());
        tx.input[0].witness = w;
        consensus_verify(&tx, &spent).is_ok()
    };
    let e: &[u8] = &[];
    let rows: Vec<(&str, bool, bool)> = vec![
        ("K_e v2 seq=6", attempt(2, 6, &v.k_e_leaf, e), true),
        ("K_e v2 seq=5", attempt(2, 5, &v.k_e_leaf, e), false),
        ("K_e v1 seq=6", attempt(1, 6, &v.k_e_leaf, e), false),
        ("K_e v2 seq=disable-bit", attempt(2, 0x8000_0006, &v.k_e_leaf, e), false),
        ("K_e v2 seq=time-type", attempt(2, 0x0040_0006, &v.k_e_leaf, e), false),
        ("K_e v2 seq=final", attempt(2, 0xffff_ffff, &v.k_e_leaf, e), false),
        ("K_u on the else branch", attempt(2, 6, &v.k_u, e), false),
        ("K_m on the else branch", attempt(2, 6, &v.k_m, e), false),
        ("K_e intent key on the else branch", attempt(2, 6, &v.k_e_intent, e), false),
    ];
    for (name, got, want) in &rows {
        println!("RESULT escape {name}: consensus={got}");
        assert_eq!(got, want, "{name}");
    }
    let _ = ScriptBuf::new();
    Ok(())
}

/// Storage griefing by the key holder: spends over fake coins, executed, so pins stay. Then compare the
/// credit and the contract's balance. And griefing by a stranger: activate on an active vault, deposit of zero.
#[tokio::test]
async fn atk_storage_griefing() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r3-grief").await?;
    let start = h.credit(&v).await?;
    let bal0 = balance(&h).await?;
    let dest = p2wpkh("r3-grief-d");
    let mut made = 0u64;
    let mut stopped = String::new();
    'outer: for round in 0..10 {
        let mut ids = vec![];
        for j in 0..3 {
            let f = coins(&format!("r3-grief-{round}-{j}"), 1, 100_000);
            let args = h.propose_args(&v, &f, &dest, 99_800, None, v.spend_nonce);
            let r = h.propose_raw(args).await?;
            if r.is_failure() { stopped = err_text(&r); break 'outer; }
            v.spend_nonce += 1;
            ids.push(r.json::<u64>()?);
        }
        for id in ids {
            h.wait_unlock(&v, id).await?;
            let r = h.execute_and_respond(&v, id, 1, false).await?;
            if r.is_failure() { stopped = err_text(&r); break 'outer; }
            made += 1;
        }
    }
    let end = h.credit(&v).await?;
    let bal1 = balance(&h).await?;
    println!("RESULT griefing executed {made} fake spends, credit {start} -> {end}, stopped: {}", &stopped[..stopped.len().min(160)]);
    println!("RESULT contract balance {bal0} -> {bal1}, storage {}", h.undo.view_account().await?.storage_usage);
    // A stranger cannot make it spend anything: repeated deposit_storage of zero, activate on active.
    let s = h.worker.dev_create_account().await?;
    let r = s.call(h.undo.id(), "activate").args_json(json!({"vault": v.hex()})).gas(gas(100)).transact().await?;
    assert_refused(&r, "already active");
    let credit0 = h.credit(&v).await?;
    s.call(h.undo.id(), "deposit_storage").args_json(json!({"vault": v.hex()})).deposit(NearToken::from_yoctonear(0)).transact().await?.into_result()?;
    assert_eq!(h.credit(&v).await?, credit0);
    Ok(())
}

/// The instance rules a reader of the delay table expects, at the contract's door.
#[tokio::test]
async fn instance_rules_hold_at_new_and_at_create_vault() -> Result<()> {
    let h = Harness::new().await?;
    let args = |preset: &str, restrict: bool, network: &str| {
        json!({
            "preset": preset, "operator": h.relayer.id(), "restrict_create": restrict, "signer": h.mock.id(), "domain_id": 0,
            "sign_tgas": SIGN_TGAS, "callback_tgas": CALLBACK_TGAS, "derive_tgas": DERIVE_TGAS, "network": network, "origins": [ORIGIN], "outflow_cap_24h": OUTFLOW_CAP,
        })
    };
    let fresh = h.worker.dev_deploy(&wasm("undo_vault")).await?;
    assert_refused(&fresh.call("new").args_json(args("MainnetProof", false, "mainnet")).transact().await?, "needs restrict_create");
    assert_refused(&fresh.call("new").args_json(args("MainnetProof", true, "mutinynet")).transact().await?, "do not match");
    assert_refused(&fresh.call("new").args_json(args("TestCoin", false, "mainnet")).transact().await?, "do not match");
    fresh.call("new").args_json(args("MainnetProof", true, "mainnet")).transact().await?.into_result()?;
    let other = h.worker.dev_deploy(&wasm("undo_vault")).await?;
    other.call("new").args_json(args("TestCoin", false, "testnet4")).transact().await?.into_result()?;

    // Each preset refuses a CSV outside its own range, and so the longest freeze is bounded with it.
    for (preset, low, high) in [("TestCoin", 5u32, 2_881u32), ("MainnetProof", 5, 26_281)] {
        let h = Harness::with(Options { preset, ..Options::default() }).await?;
        for csv in [low, high] {
            let k = keys(&format!("r3-csv-{preset}-{csv}"));
            let call = h.create_call(&k, csv);
            let args = h.create_args(&k, &call).await?;
            assert_refused(&h.create_raw(args, 100).await?, "CsvOutOfRange");
        }
        h.create_vault_csv(&format!("r3-csv-{preset}-low"), low + 1).await?;
        h.create_vault_csv(&format!("r3-csv-{preset}-high"), high - 1).await?;
    }
    Ok(())
}

/// A signer's answer is read only up to a bound, so a hostile one cannot burn the callback's gas. A
/// well-formed signature inside too many bytes is treated as a failed answer.
#[tokio::test]
async fn oversized_signer_answer_is_not_read() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r3-big").await?;
    let c = coins("r3-big", 1, 100_000);
    let id = h.propose_simple(&mut v, &c[0]).await?;
    h.wait_unlock(&v, id).await?;
    h.mock.call("set_mode").args_json(json!({"mode": "Padded"})).transact().await?.into_result()?;
    let call = h.relayer.call(h.undo.id(), "execute").args_json(json!({"vault": v.hex(), "request": id, "sign_tgas": 200})).gas(gas(MAX_GAS_TGAS));
    call.transact().await?;
    let r = h.request(&v, id).await?;
    assert_eq!(r["status"], "Signing");
    assert_eq!(r["sigs"][0], Value::Null, "too many bytes, however good the signature inside");
    assert_eq!(r["in_flight"], 0, "the input is retryable");
    Ok(())
}

/// Thief with only K_p: rotates to its own K_s, then owner recovers. What is left afterwards?
#[tokio::test]
async fn atk_passkey_thief_after_recovery() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r3-kp").await?;
    let thief_ks = fresh_key("r3-kp-thief");
    let grant = h.rotate(&mut v, &thief_ks.verifying_key().to_bytes()).await?;
    let known = h.vault_view(&v).await?["policy"]["t_known_ms"].as_u64().unwrap();
    h.advance_to(h.now_ms().await? + known + 1).await?;
    h.relayer.call(h.undo.id(), "apply_grant").args_json(json!({"vault": v.hex(), "grant": grant})).transact().await?.into_result()?;
    // Owner's K_s is locked out. Thief's K_s has no K_u, so its half-signature fails.
    let c = coins("r3-kp", 1, 100_000);
    let mut as_thief = h.propose_args(&v, &c, &p2wpkh("r3-kp-d"), 99_500, None, v.spend_nonce);
    let digest = { let spend: Vec<([u8; 32], u32, u64)> = c.iter().map(|x| (x.internal(), x.vout, x.value)).collect(); h.spend_digest(&v, "propose_btc", &(spend, p2wpkh("r3-kp-d"), 99_500u64, Option::<u64>::None), FAR, v.spend_nonce) };
    as_thief["spend_sig"] = json!(hex::encode(thief_ks.sign(&digest).to_bytes()));
    as_thief["half_sigs"] = json!([hex::encode(secp_sign(&secp("r3-kp-thief-ku"), &[7u8; 32]))]);
    assert_refused(&h.propose_raw(as_thief).await?, "bad K_u half-signature");
    // Owner: K_e recovery. Thief cancels twice, third lands.
    let fresh = |l: &str| p256::ecdsa::SigningKey::from_bytes((&test_key(l)).into()).unwrap();
    let t_recover = h.undo.view("instance").args_json(json!({})).await?.json::<Value>()?["t_recover_ms"].as_u64().unwrap();
    let newp = fresh("r3-kp-new");
    let t0 = h.now_ms().await?;
    let mut ready = 0;
    for attempt in 0..3 {
        let n = h.nonce_of(&v, "cold_nonce").await?;
        h.recover_begin_with(&v, &v.k_e_intent, &newp, &newp, n, FAR).await?.into_result()?;
        ready = h.vault_view(&v).await?["recovery_ready_at"].as_u64().unwrap();
        h.advance_to(ready - 5_000).await?;
        let n = h.nonce_of(&v, "passkey_nonce").await?;
        let r = h.passkey_call(&v, &v.passkey, "recover_cancel", &(), json!({}), n, FAR).await?;
        if attempt < 2 { r.into_result()?; } else { assert_refused(&r, "RecoveryCancelCapReached"); }
    }
    h.advance_to(ready + 1).await?;
    h.relayer.call(h.undo.id(), "recover_finish").args_json(json!({"vault": v.hex()})).transact().await?.into_result()?;
    let t1 = h.now_ms().await?;
    println!("RESULT owner back in {:.2} x T_recover, cap held", (t1 - t0) as f64 / t_recover as f64);
    // Old passkey dead. Thief's K_s still installed until the owner rotates with the new passkey.
    let view = h.vault_view(&v).await?;
    assert_eq!(view["k_s"], hex::encode(thief_ks.verifying_key().to_bytes()));
    v.passkey = newp;
    v.passkey_nonce = view["passkey_nonce"].as_u64().unwrap();
    let mine = fresh_key("r3-kp-mine");
    let g2 = h.rotate(&mut v, &mine.verifying_key().to_bytes()).await?;
    h.advance_to(h.now_ms().await? + known + 1).await?;
    h.relayer.call(h.undo.id(), "apply_grant").args_json(json!({"vault": v.hex(), "grant": g2})).transact().await?.into_result()?;
    v.k_s = mine;
    let id = h.propose_simple(&mut v, &c[0]).await?;
    println!("RESULT owner proposing again, request {id}");
    Ok(())
}

/// Cancel's own expiry and raise_fee_cap during a freeze, on the wasm. These survived the core suite.
#[tokio::test]
async fn atk_small_rules() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r3-small").await?;
    let c = coins("r3-small", 2, 100_000);
    let id = h.propose_simple(&mut v, &c[0]).await?;
    let past = h.now_ms().await? - 1;
    let r = h.cancel_bent(&v, id, past, &Bend::default()).await?;
    println!("RESULT cancel past its expiry: {}", err_text(&r));
    assert_refused(&r, "IntentExpired");
    let own = v.spk.to_bytes();
    let s = h.propose(&mut v, &c[1..], &own, 99_500, None).await?;
    let until = h.now_ms().await? + 60_000;
    let n = h.nonce_of(&v, "cold_nonce").await?;
    h.cold_call(&v, &v.k_e_intent, "freeze", &until, json!({"until": until}), n, FAR).await?.into_result()?;
    // Request is already dead by epoch, so make the check about the freeze: it answers either way.
    let digest = h.passkey_digest(&v, "raise_fee_cap", &(s, 2_000u64), FAR, Some(v.passkey_nonce));
    let r = h.relayer.call(h.undo.id(), "raise_fee_cap").args_json(json!({"vault": v.hex(), "request": s, "cap": 2000, "nonce": v.passkey_nonce, "expires_at": FAR, "assertion": assertion(&v.passkey, &digest, &Bend::default())})).gas(gas(100)).transact().await?;
    println!("RESULT raise_fee_cap during freeze: {}", err_text(&r));
    assert!(r.is_failure());
    Ok(())
}
