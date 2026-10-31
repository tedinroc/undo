//! The contract shell on the two crates, with the mock signer. Behaviour the attack review did not
//! name goes here. The review's own attacks are in the review_* files.

use anyhow::Result;
use near_token::NearToken;
use sandbox_tests::*;
use serde_json::json;
use std::str::FromStr;

/// The contract's script, program and address all equal what rust-bitcoin builds from the same keys,
/// and the row plus reservation is paid for exactly.
#[tokio::test]
async fn create_vault_matches_rust_bitcoin_and_accounts_every_byte() -> Result<()> {
    let h = Harness::new().await?;
    let usage = h.undo.view_account().await?.storage_usage;
    let v = h.create_vault("view").await?;
    let view = h.vault_view(&v).await?;
    assert_eq!(view["active"], true);
    assert_eq!(view["id"], v.hex());
    let script: String = h.undo.view("script").args_json(json!({"vault": v.hex()})).await?.json()?;
    assert_eq!(script, hex::encode(v.script.as_bytes()));
    assert_eq!(view["script_pubkey"], hex::encode(v.spk.as_bytes()));
    let address = bitcoin::Address::from_str(view["address"].as_str().unwrap())?.assume_checked();
    assert_eq!(address.script_pubkey(), v.spk);
    assert!(view["address"].as_str().unwrap().starts_with("tb1"));

    let grown = h.undo.view_account().await?.storage_usage - usage;
    let reserved = view["reserved_bytes"].as_u64().unwrap();
    let paid = NearToken::from_millinear(100).as_yoctonear() - h.credit(&v).await?;
    assert_eq!(paid, (grown + reserved) as u128 * 10_000_000_000_000_000_000u128);
    println!("MEASURE vault row={} entry={grown} reserved={reserved}", view["row_bytes"]);

    let again = h.relayer.call(h.undo.id(), "activate").args_json(json!({"vault": v.hex()})).gas(gas(100)).transact().await?;
    assert_refused(&again, "already active");
    Ok(())
}

/// A creation intent has an expiry, like every other intent.
#[tokio::test]
async fn creation_intent_expires() -> Result<()> {
    let h = Harness::new().await?;
    let k = keys("expired");
    let mut call = h.create_call(&k, 6);
    call.expires_at = 1;
    let args = h.create_args(&k, &call).await?;
    assert_refused(&h.create_raw(args, 100).await?, "creation intent expired");
    Ok(())
}

/// An answer from any other key is not stored, whoever delivers it, and the input stays retryable.
#[tokio::test]
async fn wrong_signer_answer_is_not_stored() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("wrong-signer").await?;
    let coin = coins("wrong-signer", 1, 100_000);
    let id = h.propose_simple(&mut v, &coin[0]).await?;
    h.wait_unlock(&v, id).await?;
    let call = h.execute_call(&v, id, None);
    let task = tokio::spawn(async move { call.transact().await });
    let queued = h.wait_pending(1).await?;
    let tweak: [u8; 32] = hex::decode(queued[0]["tweak"].as_str().unwrap())?.try_into().unwrap();
    let payload: [u8; 32] = hex::decode(queued[0]["payload"]["Ecdsa"].as_str().unwrap())?.try_into().unwrap();
    let wrong = node_response(&test_key("another-root"), &tweak, &payload, false);
    h.relayer.call(h.mock.id(), "respond").args_json(json!({"request": queued[0], "response": wrong})).gas(gas(100)).transact().await?.into_result()?;
    let _ = task.await??;
    let r = h.request(&v, id).await?;
    assert_eq!(r["status"], "Signing");
    assert_eq!(r["sigs"][0], serde_json::Value::Null);
    assert_eq!(r["in_flight"], 0);

    h.execute_and_respond(&v, id, 1, false).await?.into_result()?;
    h.verified_final_tx(&v, id, &coin).await?;
    Ok(())
}

/// Only the operator creates vaults on a restricted instance.
#[tokio::test]
async fn restricted_instance_refuses_strangers() -> Result<()> {
    let h = Harness::with(Options { preset: "MainnetProof", restrict_create: true, ..Options::default() }).await?;
    let k = keys("restricted");
    let call = h.create_call(&k, 6);
    let args = h.create_args(&k, &call).await?;
    let stranger = h.worker.dev_create_account().await?;
    let res = stranger.call(h.undo.id(), "create_vault").args_json(args.clone()).deposit(NearToken::from_millinear(100)).gas(gas(300)).transact().await?;
    assert_refused(&res, "only the operator");
    h.create_raw(args, 100).await?.into_result()?;
    let view: serde_json::Value = h.undo.view("instance").args_json(json!({})).await?.json()?;
    assert_eq!(view["policy"]["t_new_unguarded_ms"], 20 * MINUTE_MS);
    assert_eq!(view["t_recover_ms"], 60 * MINUTE_MS);
    Ok(())
}

/// Refused before unlock, and the signer is never called. Self-spends take T_known, anything else
/// takes the unguarded delay here because this vault has no guard.
#[tokio::test]
async fn early_execute_refused_and_tiers_are_as_stated() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("tiers").await?;
    let coin = coins("early", 2, 100_000);
    let to = p2wpkh("destination");

    let check: serde_json::Value = h.undo.view("check_propose").args_json(json!({"vault": v.hex(), "inputs": coins_json(&coin[..1]), "to": hex::encode(&to), "amount": 50_000, "change": 49_500})).await?.json()?;
    assert_eq!(check["tier"], "New");
    assert_eq!(check["delay_ms"], 10 * MINUTE_MS);
    assert_eq!(check["fee"], 500);
    assert_eq!(check["unguarded"], true);

    let id = h.propose_simple(&mut v, &coin[0]).await?;
    assert_refused(&h.execute_call(&v, id, None).transact().await?, "NotUnlocked");
    let pending: Vec<serde_json::Value> = h.mock.view("pending").args_json(json!({})).await?.json()?;
    assert!(pending.is_empty(), "the signer was not called");

    let spk = v.spk.to_bytes();
    let own = h.propose(&mut v, &coin[1..], &spk, 99_500, None).await?;
    let r = h.request(&v, own).await?;
    assert_eq!(r["tier"], "SelfSpend");
    let wait = r["base_unlock"].as_u64().unwrap() - r["proposed_at"].as_u64().unwrap();
    assert_eq!(wait, MINUTE_MS);
    Ok(())
}

/// The same signature twice, on another vault, and with the wrong key.
#[tokio::test]
async fn spend_signatures_cannot_be_replayed() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("replay").await?;
    let other = h.create_vault("replay-other").await?;
    let coin = coins("replay", 3, 100_000);
    let to = p2wpkh("destination");

    let args = h.propose_args(&v, &coin[..1], &to, 50_000, Some(49_500), 0);
    h.propose_raw(args.clone()).await?.into_result()?;
    v.spend_nonce = 1;
    assert_refused(&h.propose_raw(args.clone()).await?, "BadNonce");

    let mut elsewhere = args;
    elsewhere["vault"] = json!(other.hex());
    assert_refused(&h.propose_raw(elsewhere).await?, "bad K_s");
    Ok(())
}

/// The half-signature is checked per input against the digest of this exact request.
#[tokio::test]
async fn half_signatures_are_checked() -> Result<()> {
    let h = Harness::new().await?;
    let v = h.create_vault("half").await?;
    let coin = coins("half", 1, 100_000);
    let to = p2wpkh("destination");
    let good = h.propose_args(&v, &coin, &to, 50_000, Some(49_500), 0);

    let mut wrong_key = good.clone();
    wrong_key["half_sigs"] = json!([hex::encode(secp_sign(&secp("stranger"), &sighash(&unsigned_tx(&coin, &to, 50_000, Some((49_500, &v.spk))), 0, &v.script, 100_000)))]);
    assert_refused(&h.propose_raw(wrong_key).await?, "bad K_u half-signature");

    // A half-signature over another declared value, the shape of a fee-swap session.
    let tx = unsigned_tx(&coin, &to, 50_000, Some((49_500, &v.spk)));
    let mut other_value = good.clone();
    other_value["half_sigs"] = json!([hex::encode(secp_sign(&v.k_u, &sighash(&tx, 0, &v.script, 90_000)))]);
    assert_refused(&h.propose_raw(other_value).await?, "bad K_u half-signature");

    let mut none = good;
    none["half_sigs"] = json!([]);
    assert_refused(&h.propose_raw(none).await?, "HalfSigCount");
    Ok(())
}

/// A high-S answer verifies, and `final_tx` carries the low form, which is all that relays.
#[tokio::test]
async fn high_s_from_signer_is_normalized() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("high-s").await?;
    let coin = coins("high-s", 1, 100_000);
    let id = h.propose_simple(&mut v, &coin[0]).await?;
    h.wait_unlock(&v, id).await?;
    h.execute_and_respond(&v, id, 1, true).await?.into_result()?;
    let tx = h.verified_final_tx(&v, id, &coin).await?;
    let der = tx.input[0].witness.nth(0).unwrap();
    let sig = bitcoin::secp256k1::ecdsa::Signature::from_der(&der[..der.len() - 1])?;
    let mut low = sig;
    low.normalize_s();
    assert_eq!(sig, low);
    Ok(())
}

/// `max_inputs` splits a spend across transactions. The first call already closes cancel for all of it.
#[tokio::test]
async fn split_execute_and_partial_cancel() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("split").await?;
    let real = coins("split", 3, 100_000);
    let to = p2wpkh("destination");
    let id = h.propose(&mut v, &real, &to, 200_000, Some(99_000)).await?;
    h.wait_unlock(&v, id).await?;

    h.execute_with(h.execute_call(&v, id, Some(1)), 1, false).await?.into_result()?;
    assert_eq!(h.status(&v, id).await?, "Signing");
    assert_refused(&h.cancel_passkey(&v, id).await?, "NotPending");
    assert!(h.final_tx(&v, id).await?.is_none());
    for coin in &real {
        assert_eq!(h.outpoint(&v, coin).await?["pinned_value"], 100_000, "every declared input pins at first execute");
    }

    h.execute_with(h.execute_call(&v, id, Some(5)), 2, false).await?.into_result()?;
    assert_eq!(h.status(&v, id).await?, "Signed");
    h.verified_final_tx(&v, id, &real).await?;
    assert_refused(&h.execute_call(&v, id, None).transact().await?, "AlreadySigned");
    Ok(())
}

/// The signer times out after 200 blocks. The coins stay held, retry signs only what is missing, and
/// the late answer finds nothing.
#[tokio::test]
async fn signer_timeout_keeps_coins_and_retry_signs_the_rest() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("timeout").await?;
    let real = coins("timeout", 2, 100_000);
    let to = p2wpkh("destination");
    let id = h.propose(&mut v, &real, &to, 150_000, Some(49_000)).await?;
    h.wait_unlock(&v, id).await?;
    h.execute_with(h.execute_call(&v, id, Some(1)), 1, false).await?.into_result()?;

    let call = h.execute_call(&v, id, Some(1));
    let task = tokio::spawn(async move { call.transact().await });
    let queued = h.wait_pending(1).await?;
    assert_refused(&h.execute_call(&v, id, Some(1)).transact().await?, "InFlight");

    h.worker.fast_forward(210).await?;
    let _ = task.await??;
    for _ in 0..100 {
        if h.request(&v, id).await?["in_flight"] == 0 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert_eq!(h.request(&v, id).await?["in_flight"], 0, "the timeout reached on_signed");
    assert_eq!(h.status(&v, id).await?, "Signing");
    assert_eq!(h.outpoint(&v, &real[1]).await?["state"], "Signing", "the coin stays held, a signature may exist");
    assert!(h.respond_one(&queued[0], false).await?.is_failure(), "the signer has forgotten it");

    h.execute_with(h.execute_call(&v, id, None), 1, false).await?.into_result()?;
    assert_eq!(h.status(&v, id).await?, "Signed");
    h.verified_final_tx(&v, id, &real).await?;
    Ok(())
}

/// A callback that runs out of gas leaves the slot in flight, and execute can run again after 250
/// blocks. The transaction still reports success, so clients must read request state.
#[tokio::test]
async fn lost_callback_is_recoverable() -> Result<()> {
    let h = Harness::with(Options { callback_tgas: 1, ..Options::default() }).await?;
    let mut v = h.create_vault("lost").await?;
    let coin = coins("lost", 1, 100_000);
    let id = h.propose_simple(&mut v, &coin[0]).await?;
    h.wait_unlock(&v, id).await?;
    let _ = h.execute_and_respond(&v, id, 1, false).await?;
    assert_eq!(h.status(&v, id).await?, "Signing");
    assert_eq!(h.request(&v, id).await?["in_flight"], 1);
    assert_refused(&h.execute_call(&v, id, None).transact().await?, "InFlight");

    h.worker.fast_forward(260).await?;
    let call = h.execute_call(&v, id, None);
    let res = h.execute_with(call, 1, false).await?;
    assert!(res.logs().iter().any(|l| l.contains("undo:executing")), "{:?}", res.logs());
    assert_eq!(h.request(&v, id).await?["attempt"], 2);
    Ok(())
}

/// The cold key cancels with its intent key. The leaf key and strangers cannot.
#[tokio::test]
async fn cold_key_cancel() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("cold").await?;
    let coin = coins("cold", 1, 100_000);
    let id = h.propose_simple(&mut v, &coin[0]).await?;
    let call = |args| h.relayer.call(h.undo.id(), "cancel").args_json(args).gas(gas(100)).transact();
    assert_refused(&call(h.cold_cancel_args(&v, &v.k_e_leaf, id)).await?, "bad K_e");
    assert_refused(&call(h.cold_cancel_args(&v, &secp("stranger"), id)).await?, "bad K_e");
    call(h.cold_cancel_args(&v, &v.k_e_intent, id)).await?.into_result()?;
    assert_eq!(h.status(&v, id).await?, "deleted");
    Ok(())
}

/// After rotation the new key proposes, with the nonce where it was, and the old key is refused.
#[tokio::test]
async fn rotation_installs_the_new_key_after_the_wait() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("rotate").await?;
    let new_key = ed25519_dalek::SigningKey::from_bytes(&test_key("rotated-k-s"));
    let grant = h.rotate(&mut v, &new_key.verifying_key().to_bytes()).await?;
    let apply = |grant: u64| h.relayer.call(h.undo.id(), "apply_grant").args_json(json!({"vault": v.hex(), "grant": grant})).transact();
    assert_refused(&apply(grant).await?, "GrantNotReady");
    let t_known = h.vault_view(&v).await?["policy"]["t_known_ms"].as_u64().unwrap();
    h.advance_to(h.now_ms().await? + t_known + 1).await?;
    apply(grant).await?.into_result()?;
    let view = h.vault_view(&v).await?;
    assert_eq!(view["k_s_suspended"], false);
    assert_eq!(view["k_s"], hex::encode(new_key.verifying_key().to_bytes()));

    let coin = coins("rotate", 1, 100_000);
    let to = p2wpkh("destination");
    let old = h.propose_args(&v, &coin, &to, 50_000, Some(49_500), 0);
    assert_refused(&h.propose_raw(old).await?, "bad K_s");
    v.k_s = new_key;
    h.propose(&mut v, &coin, &to, 50_000, Some(49_500)).await?;
    Ok(())
}

/// Rotation must work with nothing in the credit: it is the panic button. A griefer who spends the
/// credit first cannot stop it.
#[tokio::test]
async fn rotation_needs_no_credit() -> Result<()> {
    let h = Harness::new().await?;
    let k = keys("no-credit");
    let call = h.create_call(&k, 6);
    let args = h.create_args(&k, &call).await?;
    let res = h.relayer.call(h.undo.id(), "create_vault").args_json(args.clone()).deposit(NearToken::from_yoctonear(1)).gas(gas(300)).transact().await?;
    let text = err_text(&res);
    let at = text.find("attach at least ").unwrap() + "attach at least ".len();
    let need: u128 = text[at..].chars().take_while(char::is_ascii_digit).collect::<String>().parse()?;
    h.relayer.call(h.undo.id(), "create_vault").args_json(args).deposit(NearToken::from_yoctonear(need)).gas(gas(300)).transact().await?.into_result()?;
    let id = h.vault_id(&k, 6);
    let k_m = h.mpc_key(&id);
    let script = witness_script(&compressed(&k.k_u), &compressed(&k_m), &compressed(&k.k_e_leaf), 6);
    let spk = script.to_p2wsh();
    let mut v = Vault { id, k_s: k.k_s, k_u: k.k_u, k_e_leaf: k.k_e_leaf, k_e_intent: k.k_e_intent, passkey: k.passkey, k_m, csv: 6, script, spk, spend_nonce: 0, passkey_nonce: 0 };
    assert_eq!(h.credit(&v).await?, 0);

    // Propose with no credit is refused, and anyone can top up.
    let coin = coins("no-credit", 1, 100_000);
    let args = h.propose_args(&v, &coin, &p2wpkh("destination"), 50_000, Some(49_500), 0);
    assert_refused(&h.propose_raw(args).await?, "storage credit short");

    h.rotate(&mut v, &test_key("rotated")).await?;
    assert_eq!(h.vault_view(&v).await?["spend_epoch"], 1);
    assert_eq!(h.credit(&v).await?, 0);

    let stranger = h.worker.dev_create_account().await?;
    stranger.call(h.undo.id(), "deposit_storage").args_json(json!({"vault": v.hex()})).deposit(NearToken::from_millinear(1)).transact().await?.into_result()?;
    assert_eq!(h.credit(&v).await?, NearToken::from_millinear(1).as_yoctonear());
    Ok(())
}

/// Template check, dust, fee cap and the 24 h budget charged at execute.
#[tokio::test]
async fn fee_and_destination_rules() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("fees").await?;
    let coin = coins("fees", 8, 100_000);
    let propose = |to: Vec<u8>, amount: u64, change: Option<u64>, nonce: u64| h.propose_raw(h.propose_args(&v, &coin[..1], &to, amount, change, nonce));

    assert_refused(&propose(vec![0x6a, 0x01, 0x00], 50_000, Some(49_500), 0).await?, "BadDestination");
    let mut p2pkh = vec![0x76, 0xa9, 0x14];
    p2pkh.extend_from_slice(&[1u8; 20]);
    p2pkh.extend_from_slice(&[0x88, 0xac]);
    assert_refused(&propose(p2pkh, 50_000, Some(49_500), 0).await?, "BadDestination");
    let to = p2wpkh("destination");
    assert_refused(&propose(to.clone(), 100, Some(99_400), 0).await?, "DustOutput");
    assert_refused(&propose(to.clone(), 50_000, Some(49_990), 0).await?, "FeeRateTooLow");
    assert_refused(&propose(to.clone(), 50_000, Some(48_000), 0).await?, "FeeOverCap");
    assert_refused(&propose(to.clone(), 50_000, Some(50_000), 0).await?, "FeeRateTooLow");
    assert_refused(&propose(to.clone(), 200_000, None, 0).await?, "OutputsExceedInputs");

    // Fake proposals do not charge the budget. Executed ones do. The test-coin budget is 5,000 sats.
    let mut last = 0;
    for c in &coin[..5] {
        last = h.propose(&mut v, std::slice::from_ref(c), &to, 50_000, Some(49_000)).await?;
        h.wait_unlock(&v, last).await?;
        h.execute_with(h.execute_call(&v, last, None), 1, false).await?.into_result()?;
    }
    assert_eq!(h.status(&v, last).await?, "Signed");
    let id = h.propose(&mut v, &coin[5..6], &to, 50_000, Some(49_000)).await?;
    h.wait_unlock(&v, id).await?;
    assert_refused(&h.execute_call(&v, id, None).transact().await?, "FeeBudgetExceeded");
    Ok(())
}

/// The wasm carries no route to read Bitcoin through MPC, and stays on low-level promises. The grep
/// itself lives in scripts/check-wasm.sh. This asserts the call shape the mock has to accept.
#[tokio::test]
async fn execute_asks_the_signer_for_exactly_the_contract_digests() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("digests").await?;
    let real = coins("digests", 3, 100_000);
    let to = p2wpkh("destination");
    let id = h.propose(&mut v, &real, &to, 200_000, Some(99_000)).await?;
    let tx = unsigned_tx(&real, &to, 200_000, Some((99_000, &v.spk)));
    let expected: Vec<[u8; 32]> = (0..3).map(|i| sighash(&tx, i, &v.script, 100_000)).collect();
    assert_eq!(h.payloads(&v, id).await?, expected);
    h.wait_unlock(&v, id).await?;
    let call = h.execute_call(&v, id, None);
    let task = tokio::spawn(async move { call.transact().await });
    let queued = h.wait_pending(3).await?;
    let tweak = hex::encode(derive_tweak(h.contract(), &format!("undo/{}", v.hex())));
    for q in &queued {
        assert_eq!(q["tweak"], tweak, "the path is this vault's");
        let payload: [u8; 32] = hex::decode(q["payload"]["Ecdsa"].as_str().unwrap())?.try_into().unwrap();
        assert!(expected.contains(&payload));
        assert_eq!(q["domain_id"], 0);
    }
    for q in &queued {
        h.respond_one(q, false).await?.into_result()?;
    }
    let _ = task.await??;
    h.verified_final_tx(&v, id, &real).await?;
    Ok(())
}
