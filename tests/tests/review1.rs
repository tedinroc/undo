//! Second review, against the real wasm in sandbox with the mock signer. Each test closes a finding
//! that ran as a working attack on the earlier code, or removes a mutant that survived the suite.

use anyhow::Result;
use near_token::NearToken;
use sandbox_tests::*;
use serde_json::{json, Value};

const FAR: u64 = u64::MAX / 2;
const SPENT: u64 = 1;

fn stranger_passkey() -> p256::ecdsa::SigningKey {
    p256::ecdsa::SigningKey::from_bytes((&test_key("stranger-passkey")).into()).unwrap()
}

fn stranger_cold() -> k256::ecdsa::SigningKey {
    secp("stranger-cold")
}

async fn create_with_raw_leaf(h: &Harness, k: &Keys, leaf: Vec<u8>, sign: impl Fn(&[u8; 32]) -> Vec<u8>) -> Result<(near_workspaces::result::ExecutionFinalResult, [u8; 32])> {
    use ed25519_dalek::Signer;
    let k_s = k.k_s.verifying_key().to_bytes();
    let id = sha256(&borsh::to_vec(&("undo-vault-id-v1", h.contract(), k_s, compressed(&k.k_u), leaf.clone(), compressed(&k.k_e_intent), p256_compressed(&k.passkey), 6u32)).unwrap());
    let k_m = compressed(&h.mpc_key(&id));
    let rp = sha256(RP_ID.as_bytes());
    let policy = h.deployed_policy().await?;
    let digest = sha256(&borsh::to_vec(&("undo-create-v1", h.contract(), id, k_m.clone(), rp, Option::<String>::None, policy, FAR)).unwrap());
    let args = json!({"args": {
        "k_s": hex::encode(k_s), "k_u": hex::encode(compressed(&k.k_u)), "k_m": hex::encode(&k_m),
        "k_e_leaf": hex::encode(&leaf), "k_e_intent": hex::encode(compressed(&k.k_e_intent)),
        "passkey": {"pubkey": hex::encode(p256_compressed(&k.passkey)), "rp_id_hash": hex::encode(rp)},
        "guard": null, "csv": 6, "policy": null, "expires_at": FAR,
        "pop_s": hex::encode(k.k_s.sign(&digest).to_bytes()), "pop_u": hex::encode(secp_sign(&k.k_u, &digest)),
        "pop_e": hex::encode(secp_sign(&k.k_e_intent, &digest)), "pop_leaf": hex::encode(sign(&digest)),
        "pop_p": assertion(&k.passkey, &digest, &Bend::default()),
    }});
    Ok((h.create_raw(args, 100).await?, id))
}

async fn no_row(h: &Harness, id: &[u8; 32]) -> Result<()> {
    let view: Option<Value> = h.undo.view("vault").args_json(json!({"vault": hex::encode(id)})).await?.json()?;
    assert!(view.is_none(), "no vault may exist");
    Ok(())
}

/// A vault whose script names a key the creator cannot sign with has no exit that skips NEAR, or an
/// exit that belongs to someone else. A changed page could register either. Neither activates now.
#[tokio::test]
async fn escape_key_needs_proof_of_possession() -> Result<()> {
    let h = Harness::new().await?;

    // Control: the leaf key signs the tagged digest, and the vault activates.
    let k = keys("r1-leaf-good");
    let leaf_key = k.k_e_leaf.clone();
    let (res, id) = create_with_raw_leaf(&h, &k, compressed(&leaf_key), |d| secp_sign(&leaf_key, &leaf_pop_digest(d))).await?;
    res.into_result()?;
    let view: Value = h.undo.view("vault").args_json(json!({"vault": hex::encode(id)})).await?.json()?;
    assert_eq!(view["active"], true);

    // A foreign key, an attacker's, with the proof made by the key the creator really holds.
    let k = keys("r1-leaf-foreign");
    let attacker = compressed(&secp("attacker-leaf"));
    let own = k.k_e_leaf.clone();
    let (res, id) = create_with_raw_leaf(&h, &k, attacker.clone(), |d| secp_sign(&own, &leaf_pop_digest(d))).await?;
    assert_refused(&res, "bad K_e leaf");
    no_row(&h, &id).await?;

    // The same, with the intent key's proof reused in the leaf slot: the old code's only check.
    let k = keys("r1-leaf-foreign-2");
    let intent = k.k_e_intent.clone();
    let (res, _) = create_with_raw_leaf(&h, &k, attacker, |d| secp_sign(&intent, d)).await?;
    assert_refused(&res, "bad K_e leaf");

    // Off-curve: x above the field prime, so no such point and no secret key exist.
    let k = keys("r1-leaf-off-curve");
    let mut off = vec![2u8];
    off.extend([0xffu8; 32]);
    let any = k.k_e_leaf.clone();
    let (res, id) = create_with_raw_leaf(&h, &k, off, |d| secp_sign(&any, &leaf_pop_digest(d))).await?;
    assert_refused(&res, "bad K_e leaf");
    no_row(&h, &id).await?;

    // Off-curve the other way: x inside the field, with no y on the curve.
    let mut no_y = Vec::new();
    for x in 1u8..=50 {
        let mut candidate = vec![2u8];
        candidate.extend([0u8; 31]);
        candidate.push(x);
        if k256::PublicKey::from_sec1_bytes(&candidate).is_err() {
            no_y = candidate;
            break;
        }
    }
    assert!(!no_y.is_empty(), "the search found an x with no point");
    let k = keys("r1-leaf-no-y");
    let any = k.k_e_leaf.clone();
    let (res, _) = create_with_raw_leaf(&h, &k, no_y, |d| secp_sign(&any, &leaf_pop_digest(d))).await?;
    assert_refused(&res, "bad K_e leaf");

    // The domain tag is load-bearing: the right key over the untagged digest is refused.
    let k = keys("r1-leaf-untagged");
    let leaf_key = k.k_e_leaf.clone();
    let (res, _) = create_with_raw_leaf(&h, &k, compressed(&leaf_key), |d| secp_sign(&leaf_key, d)).await?;
    assert_refused(&res, "bad K_e leaf");
    Ok(())
}

// ---------------------------------------------------------------- the panic button's auth

/// Anyone who could pass this could suspend `K_s` and install their own.
#[tokio::test]
async fn rotate_needs_the_passkey_the_args_the_nonce_and_time() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r1-rotate").await?;
    let good = test_key("r1-new-k-s");
    let other = test_key("r1-other-k-s");
    let call = |key: [u8; 32]| json!({"new_k_s": hex::encode(key)});
    let method = "cancel_all_and_rotate";

    assert_refused(&h.passkey_call(&v, &stranger_passkey(), method, &good, call(good), 0, FAR).await?, "webauthn: bad signature");
    // The assertion names another key, so the digest differs.
    let digest = h.passkey_digest(&v, method, &good, FAR, Some(0));
    let bent = h.relayer.call(h.undo.id(), method).args_json(json!({"vault": v.hex(), "new_k_s": hex::encode(other), "nonce": 0, "expires_at": FAR, "assertion": assertion(&v.passkey, &digest, &Bend::default())})).gas(gas(100)).transact().await?;
    assert_refused(&bent, "webauthn: wrong challenge");
    assert_refused(&h.passkey_call(&v, &v.passkey, method, &good, call(good), 0, SPENT).await?, "IntentExpired");
    assert_refused(&h.passkey_call(&v, &v.passkey, method, &good, call(good), 5, FAR).await?, "BadNonce");

    let view = h.vault_view(&v).await?;
    assert_eq!(view["spend_epoch"], 0, "nothing landed");
    assert_eq!(view["k_s_suspended"], false);
    assert_eq!(view["grants"], json!([]));

    // Control, then a replay of the same signed call.
    h.rotate(&mut v, &good).await?;
    assert_eq!(h.vault_view(&v).await?["spend_epoch"], 1);
    assert_refused(&h.passkey_call(&v, &v.passkey, method, &good, call(good), 0, FAR).await?, "BadNonce");
    Ok(())
}

#[tokio::test]
async fn raise_fee_cap_needs_the_passkey_the_args_the_nonce_and_time() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r1-fee").await?;
    let real = coins("r1-fee", 16, 100_000);
    let to = v.spk.to_bytes();
    let id = h.propose(&mut v, &real, &to, 1_598_000, None).await?;
    h.wait_unlock(&v, id).await?;
    let call = |request: u64, cap: u64| json!({"request": request, "cap": cap});
    let method = "raise_fee_cap";

    assert_refused(&h.passkey_call(&v, &stranger_passkey(), method, &(id, 2_000u64), call(id, 2_000), 0, FAR).await?, "webauthn: bad signature");
    // An assertion for one cap does not carry another.
    let digest = h.passkey_digest(&v, method, &(id, 1_500u64), FAR, Some(0));
    let bent = h.relayer.call(h.undo.id(), method).args_json(json!({"vault": v.hex(), "request": id, "cap": 2_000, "nonce": 0, "expires_at": FAR, "assertion": assertion(&v.passkey, &digest, &Bend::default())})).gas(gas(100)).transact().await?;
    assert_refused(&bent, "webauthn: wrong challenge");
    assert_refused(&h.passkey_call(&v, &v.passkey, method, &(id, 2_000u64), call(id, 2_000), 0, SPENT).await?, "IntentExpired");
    assert_refused(&h.passkey_call(&v, &v.passkey, method, &(id, 2_000u64), call(id, 2_000), 3, FAR).await?, "BadNonce");

    assert_refused(&h.execute_call(&v, id, None).transact().await?, "FeeOverCap");
    h.raise_fee_cap(&mut v, id, 2_000).await?;
    assert_refused(&h.passkey_call(&v, &v.passkey, method, &(id, 2_000u64), call(id, 2_000), 0, FAR).await?, "BadNonce");
    Ok(())
}

/// A reclaim replaces the request holding a coin and spends the self-spend slot, so it must take the
/// spend key, this exact coin and fee, and a live nonce.
#[tokio::test]
async fn reclaim_needs_the_spend_key_the_args_the_nonce_and_time() -> Result<()> {
    use ed25519_dalek::Signer;
    let h = Harness::new().await?;
    let mut v = h.create_vault("r1-reclaim").await?;
    let real = coins("r1-reclaim", 1, 100_000);
    let lie = [real[0].with_value(90_000)];
    let to = v.spk.to_bytes();
    let id = h.propose(&mut v, &lie, &to, 89_500, None).await?;
    h.wait_unlock(&v, id).await?;
    h.execute_and_respond(&v, id, 1, false).await?.into_result()?;
    let t_stuck = h.vault_view(&v).await?["policy"]["t_stuck_ms"].as_u64().unwrap();
    h.advance_to(h.now_ms().await? + t_stuck + 1).await?;
    let send = |args: Value| h.relayer.call(h.undo.id(), "reclaim").args_json(args).gas(gas(100)).transact();
    let nonce = v.spend_nonce;

    // A stranger's K_s, over the right bytes, with a valid half-signature.
    let mut bad = h.reclaim_args(&v, &real[0], 500, nonce);
    let spend: Vec<([u8; 32], u32, u64)> = vec![(real[0].internal(), real[0].vout, real[0].value)];
    let digest = h.spend_digest(&v, "reclaim", &(spend.clone(), 500u64), FAR, nonce);
    let stranger = ed25519_dalek::SigningKey::from_bytes(&test_key("stranger-k-s"));
    bad["spend_sig"] = json!(hex::encode(stranger.sign(&digest).to_bytes()));
    assert_refused(&send(bad).await?, "bad K_s");

    // A signature for one fee does not carry another. The half-signature matches the fee sent.
    let mut bent = h.reclaim_args(&v, &real[0], 900, nonce);
    bent["spend_sig"] = json!(hex::encode(v.k_s.sign(&digest).to_bytes()));
    assert_refused(&send(bent).await?, "bad K_s");

    // Stale nonce and past expiry, each correctly signed.
    let stale = h.reclaim_args(&v, &real[0], 500, nonce + 3);
    assert_refused(&send(stale).await?, "BadNonce");
    let mut late = h.reclaim_args(&v, &real[0], 500, nonce);
    let digest = h.spend_digest(&v, "reclaim", &(spend, 500u64), SPENT, nonce);
    late["expires_at"] = json!(SPENT);
    late["spend_sig"] = json!(hex::encode(v.k_s.sign(&digest).to_bytes()));
    assert_refused(&send(late).await?, "IntentExpired");

    assert_eq!(h.status(&v, id).await?, "Signed", "nothing was replaced");
    let replay = h.reclaim_args(&v, &real[0], 500, nonce);
    h.reclaim(&mut v, &real[0], 500).await?;
    assert_refused(&send(replay).await?, "BadNonce");
    Ok(())
}

// ---------------------------------------------------------------- a second on_derived

/// A racing `activate` can deliver a second callback after the first activated the vault. It must not
/// be taken for a refusal, which deletes the vault and refunds its deposit.
#[tokio::test]
async fn second_on_derived_leaves_an_active_vault_alone() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r1-derived").await?;
    let coin = coins("r1-derived", 1, 100_000);
    let request = h.propose_simple(&mut v, &coin[0]).await?;
    let (usage, credit) = (h.undo.view_account().await?.storage_usage, h.credit(&v).await?);

    // Delivered as the contract itself, so it passes #[private], with no promise result at all: what
    // a refusal looks like.
    let late = h.undo.as_account().call(h.undo.id(), "on_derived").args_json(json!({"vault": v.hex()})).gas(gas(100)).transact().await?;
    late.into_result()?;

    let view = h.vault_view(&v).await?;
    assert_eq!(view["active"], true);
    assert_eq!(h.status(&v, request).await?, "Pending");
    assert_eq!(h.undo.view_account().await?.storage_usage, usage);
    assert_eq!(h.credit(&v).await?, credit, "nothing was refunded");

    // A stranger cannot deliver it at all.
    let outsider = h.relayer.call(h.undo.id(), "on_derived").args_json(json!({"vault": v.hex()})).gas(gas(100)).transact().await?;
    assert!(outsider.is_failure());
    Ok(())
}

/// The same through the real path. A batch runs `create_vault` and then `activate` in one receipt, so
/// `activate` sees the vault Inactive and asks the signer a second time. Two real callbacks arrive,
/// and the second finds the vault already active.
#[tokio::test]
async fn racing_activate_delivers_two_callbacks_and_keeps_the_vault() -> Result<()> {
    use near_workspaces::operations::Function;
    let h = Harness::new().await?;
    let k = keys("r1-race");
    let call = h.create_call(&k, 6);
    let args = h.create_args(&k, &call).await?;
    let id = hex::encode(h.vault_id(&k, 6));
    let res = h
        .relayer
        .batch(h.undo.id())
        .call(Function::new("create_vault").args_json(args).deposit(NearToken::from_millinear(100)).gas(gas(150)))
        .call(Function::new("activate").args_json(json!({"vault": id})).gas(gas(150)))
        .transact()
        .await?;
    let callbacks = res.receipt_outcomes().iter().filter(|o| o.executor_id.as_str() == h.undo.id().as_str() && o.logs.iter().any(|l| l.contains("undo:active"))).count();
    res.clone().into_result()?;
    assert_eq!(own_gas(&res, h.mock.id().as_str(), None).len(), 2, "the signer was asked twice");
    assert_eq!(callbacks, 1, "the first activates, and the second does nothing");
    assert!(res.logs().iter().all(|l| !l.contains("undo:refused")), "{:?}", res.logs());
    let view: Value = h.undo.view("vault").args_json(json!({"vault": id})).await?.json()?;
    assert_eq!(view["active"], true);
    Ok(())
}

// ---------------------------------------------------------------- the slot, at the contract's door

/// A 294-sat spend with the rest as change restarts CSV as a self-spend does, so it needs the slot.
#[tokio::test]
async fn slot_covers_spends_with_change_on_the_wasm() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r1-slot").await?;
    let real = coins("r1-slot", 3, 100_000);
    let to = p2wpkh("destination");
    let own = v.spk.to_bytes();

    let first = h.propose(&mut v, &real[..1], &own, 99_500, None).await?;
    let dust = h.propose_args(&v, &real[1..2], &to, 294, Some(99_000), v.spend_nonce);
    assert_refused(&h.propose_raw(dust).await?, "SelfSpendSlotUsed");
    let check = h.undo.view("check_propose").args_json(json!({"vault": v.hex(), "inputs": coins_json(&real[1..2]), "to": hex::encode(&to), "amount": 294, "change": 99_000})).await;
    assert!(format!("{check:?}").contains("SelfSpendSlotUsed"), "the free view agrees: {check:?}");

    // A cancel gives the slot back, and now the dust spend holds it against a self-spend.
    h.cancel_passkey(&v, first).await?.into_result()?;
    let spend = h.propose(&mut v, &real[1..2], &to, 294, Some(99_000)).await?;
    assert_eq!(h.request(&v, spend).await?["tier"], "New");
    let own_args = h.propose_args(&v, &real[2..], &own, 99_500, None, v.spend_nonce);
    assert_refused(&h.propose_raw(own_args).await?, "SelfSpendSlotUsed");

    // A spend with no change leaves no new coin, and needs no slot.
    h.propose(&mut v, &real[2..], &to, 99_500, None).await?;
    Ok(())
}

// ---------------------------------------------------------------- pruning

/// A signed request can leave after the window. Its bytes go back to the credit, the transaction stays
/// readable in the log, and the coin keeps everything it needs.
#[tokio::test]
async fn prune_returns_the_bytes_and_keeps_the_transaction() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r1-prune").await?;
    let real = coins("r1-prune", 2, 100_000);
    let to = p2wpkh("destination");
    let id = h.propose(&mut v, &real, &to, 150_000, Some(49_000)).await?;
    assert_refused(&h.prune(&v, id).await?, "NotSigned");
    h.wait_unlock(&v, id).await?;
    h.execute_and_respond(&v, id, 2, false).await?.into_result()?;
    assert_eq!(h.status(&v, id).await?, "Signed");
    let tx = h.verified_final_tx(&v, id, &real).await?;
    assert_refused(&h.prune(&v, id).await?, "PruneTooSoon");

    let window = h.undo.view("instance").args_json(json!({})).await?.json::<Value>()?["expiry_window_ms"].as_u64().unwrap();
    h.advance_to(h.now_ms().await? + window + 1).await?;
    let (usage, credit) = (h.undo.view_account().await?.storage_usage, h.credit(&v).await?);

    // Anyone may call it.
    let stranger = h.worker.dev_create_account().await?;
    let res = stranger.call(h.undo.id(), "prune_signed").args_json(json!({"vault": v.hex(), "request": id})).gas(gas(100)).transact().await?;
    let logs: Vec<String> = res.logs().iter().map(|l| l.to_string()).collect();
    res.into_result()?;

    let line = logs.iter().find(|l| l.contains("undo:pruned")).expect("a pruned line");
    let hex_tx = line.split("tx=").nth(1).expect("the transaction");
    let logged: bitcoin::Transaction = bitcoin::consensus::deserialize(&hex::decode(hex_tx)?)?;
    assert_eq!(logged, tx, "the log carries the same transaction");
    consensus_verify(&logged, &spent_outputs(&real, &v.spk))?;

    let freed = usage - h.undo.view_account().await?.storage_usage;
    assert!(freed > 0, "the row's entry is gone");
    assert_eq!(h.credit(&v).await? - credit, freed as u128 * 10_000_000_000_000_000_000u128, "every byte came back, no more");
    assert_eq!(h.status(&v, id).await?, "deleted");
    assert!(h.final_tx(&v, id).await?.is_none());
    println!("MEASURE pruned request inputs=2 freed_bytes={freed}");

    // The coin keeps its ledger entry and pin, so it stays out of new requests and can be reclaimed.
    let point = h.outpoint(&v, &real[0]).await?;
    assert_eq!(point["state"], "Spent");
    assert_eq!(point["pinned_value"], 100_000);
    let args = h.propose_args(&v, &real[..1], &to, 50_000, None, v.spend_nonce);
    assert_refused(&h.propose_raw(args).await?, "OutpointBusy");
    assert_refused(&h.prune(&v, id).await?, "RequestNotFound");
    let t_stuck = h.vault_view(&v).await?["policy"]["t_stuck_ms"].as_u64().unwrap();
    h.advance_to(h.now_ms().await? + t_stuck + 1).await?;
    let r = h.reclaim(&mut v, &real[0], 500).await?;
    h.wait_unlock(&v, r).await?;
    h.execute_and_respond(&v, r, 1, false).await?.into_result()?;
    h.verified_final_tx(&v, r, &real[..1]).await?;
    Ok(())
}

/// The pin outlives a prune: a multi-input session over the same coins stays shut.
#[tokio::test]
async fn pins_survive_in_their_own_storage_entries() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r1-pins").await?;
    let real = coins("r1-pins", 2, 100_000);
    let own = v.spk.to_bytes();
    let id = h.propose(&mut v, &real[..1], &own, 99_500, None).await?;
    h.cancel_passkey(&v, id).await?.into_result()?;
    assert_eq!(h.outpoint(&v, &real[0]).await?["pinned_value"], Value::Null, "cancelled before execute: no pin");

    let id = h.propose(&mut v, &real[..1], &own, 99_500, None).await?;
    h.wait_unlock(&v, id).await?;
    h.execute_and_respond(&v, id, 1, false).await?.into_result()?;
    let window = h.undo.view("instance").args_json(json!({})).await?.json::<Value>()?["expiry_window_ms"].as_u64().unwrap();
    h.advance_to(h.now_ms().await? + window + 1).await?;
    h.prune(&v, id).await?.into_result()?;
    let r = h.reclaim(&mut v, &real[0], 500).await?;
    h.cancel_passkey(&v, r).await?.into_result()?;
    assert_eq!(h.outpoint(&v, &real[0]).await?["state"], "Free");
    assert_eq!(h.outpoint(&v, &real[0]).await?["pinned_value"], 100_000);
    let t_new = h.vault_view(&v).await?["policy"]["t_new_ms"].as_u64().unwrap();
    h.advance_to(h.now_ms().await? + t_new + 1).await?;
    let args = h.propose_args(&v, &real, &own, 199_000, None, v.spend_nonce);
    assert_refused(&h.propose_raw(args).await?, "PinnedInMultiInput");
    Ok(())
}

/// A dead request frees its coin even when the call that sweeps it names another coin, because the
/// coin's ledger entry is in its own storage entry and must be loaded for the sweep.
#[tokio::test]
async fn dead_requests_free_coins_the_sweeping_call_does_not_name() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r1-dead").await?;
    let coin = coins("r1-dead", 2, 100_000);
    let to = p2wpkh("destination");
    let dead = h.propose(&mut v, &coin[..1], &to, 99_500, None).await?;
    let expires = h.request(&v, dead).await?["expires_at"].as_u64().unwrap();
    h.advance_to(expires + 1).await?;
    h.propose(&mut v, &coin[1..], &to, 99_500, None).await?;
    assert_eq!(h.status(&v, dead).await?, "deleted", "the other proposal swept it");
    h.propose(&mut v, &coin[..1], &to, 99_500, None).await?;
    assert_eq!(h.outpoint(&v, &coin[0]).await?["state"], "Pending", "the coin was free again");
    Ok(())
}

// ---------------------------------------------------------------- the cold key

/// The cold key's methods must work with nothing in the credit, like the panic button: a griefer who
/// spends the credit first cannot stop them, and their bytes were paid for at creation.
#[tokio::test]
async fn cold_methods_need_no_credit() -> Result<()> {
    let h = Harness::new().await?;
    let k = keys("r1-no-credit");
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
    let v = Vault { id, k_s: k.k_s, k_u: k.k_u, k_e_leaf: k.k_e_leaf, k_e_intent: k.k_e_intent, passkey: k.passkey, k_m, csv: 6, script, spk, spend_nonce: 0, passkey_nonce: 0 };
    assert_eq!(h.credit(&v).await?, 0);
    let cold = v.k_e_intent.clone();
    let owner = p256::ecdsa::SigningKey::from_bytes((&test_key("r1-no-credit-new")).into()).unwrap();
    let no_short = |res: &near_workspaces::result::ExecutionFinalResult| res.logs().iter().all(|l| !l.contains("credit_short"));

    let begun = h.recover_begin_with(&v, &cold, &owner, &owner, 0, FAR).await?;
    assert!(no_short(&begun), "the recovery's bytes were reserved: {:?}", begun.logs());
    begun.into_result()?;
    let until = h.now_ms().await? + 60_000;
    let frozen = h.cold_call(&v, &cold, "freeze", &until, json!({"until": until}), 1, FAR).await?;
    assert!(no_short(&frozen), "the freeze's bytes were reserved: {:?}", frozen.logs());
    frozen.into_result()?;
    assert_eq!(h.credit(&v).await?, 0);
    Ok(())
}

/// One signature blocks everything but cancel, kills pending requests and grants, and only `K_e` lifts it.
#[tokio::test]
async fn freeze_and_unfreeze_on_the_wasm() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r1-freeze").await?;
    let coin = coins("r1-freeze", 2, 100_000);
    let pending = h.propose_simple(&mut v, &coin[0]).await?;
    let grant = h.rotate(&mut v, &test_key("r1-freeze-new")).await?;
    let view = h.vault_view(&v).await?;
    assert_eq!(view["grants"], json!([grant]));
    let cold = v.k_e_intent.clone();
    let now = h.now_ms().await?;
    let until = now + 60_000;
    let call = json!({"until": until});

    // Refused: wrong key, the leaf key, changed args, a stale nonce, past expiry, too long.
    assert_refused(&h.cold_call(&v, &stranger_cold(), "freeze", &until, call.clone(), 0, FAR).await?, "bad K_e");
    assert_refused(&h.cold_call(&v, &v.k_e_leaf, "freeze", &until, call.clone(), 0, FAR).await?, "bad K_e");
    let later = until + 1;
    assert_refused(&h.cold_call(&v, &cold, "freeze", &later, call.clone(), 0, FAR).await?, "bad K_e");
    assert_refused(&h.cold_call(&v, &cold, "freeze", &until, call.clone(), 2, FAR).await?, "BadNonce");
    assert_refused(&h.cold_call(&v, &cold, "freeze", &until, call.clone(), 0, SPENT).await?, "IntentExpired");
    let too_long = now + 6 * 30_000 + 120_000;
    assert_refused(&h.cold_call(&v, &cold, "freeze", &too_long, json!({"until": too_long}), 0, FAR).await?, "FreezeTooLong");
    assert_eq!(h.vault_view(&v).await?["frozen_until"], Value::Null, "nothing landed");

    h.cold_call(&v, &cold, "freeze", &until, call.clone(), 0, FAR).await?.into_result()?;
    let view = h.vault_view(&v).await?;
    assert_eq!(view["frozen_until"], until);
    assert_eq!(view["grants"], json!([]), "grants die with the freeze");
    assert_eq!(view["spend_epoch"], 2, "rotation bumped it once and the freeze again");
    assert_eq!(view["cold_nonce"], 1);
    assert_refused(&h.cold_call(&v, &cold, "freeze", &until, call, 0, FAR).await?, "BadNonce");

    // Blocked: propose, execute, passkey grants and the override.
    let args = h.propose_args(&v, &coin[1..], &p2wpkh("destination"), 50_000, None, v.spend_nonce);
    assert_refused(&h.propose_raw(args).await?, "Frozen");
    assert_refused(&h.execute_call(&v, pending, None).transact().await?, "Frozen");
    let again = test_key("r1-freeze-again");
    let nonce = h.nonce_of(&v, "passkey_nonce").await?;
    assert_refused(&h.passkey_call(&v, &v.passkey, "cancel_all_and_rotate", &again, json!({"new_k_s": hex::encode(again)}), nonce, FAR).await?, "Frozen");
    let apply = h.relayer.call(h.undo.id(), "apply_grant").args_json(json!({"vault": v.hex(), "grant": grant})).transact().await?;
    assert_refused(&apply, "Frozen");

    // Only K_e lifts it. A passkey has no such method, and a stranger's signature fails.
    assert_refused(&h.cold_call(&v, &stranger_cold(), "unfreeze", &(), json!({}), 1, FAR).await?, "bad K_e");
    assert_refused(&h.cold_call(&v, &v.k_e_leaf, "unfreeze", &(), json!({}), 1, FAR).await?, "bad K_e");
    assert_refused(&h.cold_call(&v, &cold, "unfreeze", &(), json!({}), 4, FAR).await?, "BadNonce");
    assert_refused(&h.cold_call(&v, &cold, "unfreeze", &(), json!({}), 1, SPENT).await?, "IntentExpired");
    h.cold_call(&v, &cold, "unfreeze", &(), json!({}), 1, FAR).await?.into_result()?;
    assert_eq!(h.vault_view(&v).await?["frozen_until"], Value::Null);
    assert_refused(&h.cold_call(&v, &cold, "unfreeze", &(), json!({}), 2, FAR).await?, "NotFrozen");

    // The request the freeze killed stays dead.
    assert_refused(&h.execute_call(&v, pending, None).transact().await?, "RequestNotFound");
    assert_eq!(h.outpoint(&v, &coin[0]).await?["state"], "Free");
    Ok(())
}

/// `K_e` stops a grant still waiting, so a stolen passkey cannot install its own spend key.
#[tokio::test]
async fn veto_grant_on_the_wasm() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r1-veto").await?;
    let grant = h.rotate(&mut v, &test_key("r1-veto-thief")).await?;
    let cold = v.k_e_intent.clone();
    let call = json!({"grant": grant});

    assert_refused(&h.cold_call(&v, &stranger_cold(), "veto_grant", &grant, call.clone(), 0, FAR).await?, "bad K_e");
    assert_refused(&h.cold_call(&v, &v.k_e_leaf, "veto_grant", &grant, call.clone(), 0, FAR).await?, "bad K_e");
    let other = grant + 1;
    assert_refused(&h.cold_call(&v, &cold, "veto_grant", &other, call.clone(), 0, FAR).await?, "bad K_e");
    assert_refused(&h.cold_call(&v, &cold, "veto_grant", &grant, call.clone(), 3, FAR).await?, "BadNonce");
    assert_refused(&h.cold_call(&v, &cold, "veto_grant", &grant, call.clone(), 0, SPENT).await?, "IntentExpired");
    assert_eq!(h.vault_view(&v).await?["grants"], json!([grant]));

    h.cold_call(&v, &cold, "veto_grant", &grant, call.clone(), 0, FAR).await?.into_result()?;
    assert_eq!(h.vault_view(&v).await?["grants"], json!([]));
    assert_refused(&h.cold_call(&v, &cold, "veto_grant", &grant, call, 1, FAR).await?, "GrantNotFound");

    let t_known = h.vault_view(&v).await?["policy"]["t_known_ms"].as_u64().unwrap();
    h.advance_to(h.now_ms().await? + t_known + 1).await?;
    let apply = h.relayer.call(h.undo.id(), "apply_grant").args_json(json!({"vault": v.hex(), "grant": grant})).transact().await?;
    assert_refused(&apply, "GrantNotFound");
    assert_eq!(h.vault_view(&v).await?["k_s_suspended"], true, "the thief's key never landed");
    Ok(())
}

// ---------------------------------------------------------------- recovery, at the deployed constants

/// SPEC 1.5: the current passkey may cancel a recovery at most twice between successful recoveries,
/// so the owner is back within 3 x T_recover. Runs each instance's real constants, with the thief
/// cancelling as late as this clock allows.
async fn recovery_cap_at(preset: &'static str, t_recover: u64) -> Result<()> {
    let h = Harness::with(Options { preset, ..Options::default() }).await?;
    let instance: Value = h.undo.view("instance").args_json(json!({})).await?.json()?;
    assert_eq!(instance["t_recover_ms"], t_recover, "this test is about the deployed constant");
    let v = h.create_vault(&format!("r1-recover-{preset}")).await?;
    let cold = v.k_e_intent.clone();
    let owner = p256::ecdsa::SigningKey::from_bytes((&test_key(&format!("r1-new-passkey-{preset}"))).into()).unwrap();
    let start = h.now_ms().await?;

    let mut cold_nonce = 0;
    for attempt in 0..2 {
        h.recover_begin_with(&v, &cold, &owner, &owner, cold_nonce, FAR).await?.into_result()?;
        cold_nonce += 1;
        let ready = h.vault_view(&v).await?["recovery_ready_at"].as_u64().unwrap();
        // The thief waits for almost the whole of it.
        h.advance_to(ready - t_recover / 10).await?;
        assert_refused(&h.relayer.call(h.undo.id(), "recover_finish").args_json(json!({"vault": v.hex()})).transact().await?, "RecoveryNotReady");
        let nonce = h.nonce_of(&v, "passkey_nonce").await?;
        h.passkey_call(&v, &v.passkey, "recover_cancel", &(), json!({}), nonce, FAR).await?.into_result()?;
        let view = h.vault_view(&v).await?;
        assert_eq!(view["recover_cancels"], attempt + 1);
        assert_eq!(view["recovery_ready_at"], Value::Null);
    }

    h.recover_begin_with(&v, &cold, &owner, &owner, cold_nonce, FAR).await?.into_result()?;
    let ready = h.vault_view(&v).await?["recovery_ready_at"].as_u64().unwrap();
    let nonce = h.nonce_of(&v, "passkey_nonce").await?;
    assert_refused(&h.passkey_call(&v, &v.passkey, "recover_cancel", &(), json!({}), nonce, FAR).await?, "RecoveryCancelCapReached");

    h.advance_to(ready + 1).await?;
    h.relayer.call(h.undo.id(), "recover_finish").args_json(json!({"vault": v.hex()})).transact().await?.into_result()?;
    let finished = h.now_ms().await?;
    assert!(ready - start <= 3 * t_recover, "the owner is back within 3 x T_recover: {}", ready - start);
    println!("MEASURE recovery {preset} landed {} ms after the first begin, {} x T_recover", finished - start, (finished - start) as f64 / t_recover as f64);

    let view = h.vault_view(&v).await?;
    assert_eq!(view["passkey"], hex::encode(p256_compressed(&owner)));
    assert_eq!(view["recover_cancels"], 0, "the count resets only on success");

    // The old passkey has lost its power, and the new one holds it.
    let stolen = test_key("r1-after-recovery");
    let nonce = view["passkey_nonce"].as_u64().unwrap();
    assert_refused(&h.passkey_call(&v, &v.passkey, "cancel_all_and_rotate", &stolen, json!({"new_k_s": hex::encode(stolen)}), nonce, FAR).await?, "webauthn: bad signature");
    h.passkey_call(&v, &owner, "cancel_all_and_rotate", &stolen, json!({"new_k_s": hex::encode(stolen)}), nonce, FAR).await?.into_result()?;
    Ok(())
}

#[tokio::test]
async fn recovery_cap_on_the_test_coin_constants() -> Result<()> {
    recovery_cap_at("TestCoin", 15 * MINUTE_MS).await
}

#[tokio::test]
async fn recovery_cap_on_the_mainnet_proof_constants() -> Result<()> {
    recovery_cap_at("MainnetProof", 60 * MINUTE_MS).await
}

#[tokio::test]
async fn recovery_needs_the_cold_key_a_real_new_passkey_and_the_passkey_to_cancel() -> Result<()> {
    let h = Harness::new().await?;
    let v = h.create_vault("r1-recover-auth").await?;
    let cold = v.k_e_intent.clone();
    let owner = p256::ecdsa::SigningKey::from_bytes((&test_key("r1-recover-auth-new")).into()).unwrap();

    assert_refused(&h.recover_begin_with(&v, &stranger_cold(), &owner, &owner, 0, FAR).await?, "bad K_e");
    assert_refused(&h.recover_begin_with(&v, &v.k_e_leaf, &owner, &owner, 0, FAR).await?, "bad K_e");
    assert_refused(&h.recover_begin_with(&v, &cold, &owner, &stranger_passkey(), 0, FAR).await?, "webauthn: bad signature");
    assert_refused(&h.recover_begin_with(&v, &cold, &owner, &owner, 2, FAR).await?, "BadNonce");
    assert_refused(&h.recover_begin_with(&v, &cold, &owner, &owner, 0, SPENT).await?, "IntentExpired");

    // Off-curve new passkey: nobody can sign for it, so it cannot lock the owner out later.
    let rp_id_hash = sha256(RP_ID.as_bytes());
    let junk = vec![0xffu8; 33];
    let args = (junk.clone(), rp_id_hash);
    let digest = intent_digest("undo-cold-v1", h.contract(), &v.id, "recover_begin", &args, FAR, Some(0));
    let call = json!({"new_passkey": {"pubkey": hex::encode(&junk), "rp_id_hash": hex::encode(rp_id_hash)}, "pop_p": assertion(&owner, &digest, &Bend::default())});
    assert!(h.cold_call(&v, &cold, "recover_begin", &args, call, 0, FAR).await?.is_failure());
    assert_eq!(h.vault_view(&v).await?["recovery_ready_at"], Value::Null, "nothing landed");

    h.recover_begin_with(&v, &cold, &owner, &owner, 0, FAR).await?.into_result()?;
    assert_refused(&h.recover_begin_with(&v, &cold, &owner, &owner, 1, FAR).await?, "RecoveryInProgress");

    // Cancel takes the current passkey, a live nonce and time.
    assert_refused(&h.passkey_call(&v, &stranger_passkey(), "recover_cancel", &(), json!({}), 0, FAR).await?, "webauthn: bad signature");
    assert_refused(&h.passkey_call(&v, &owner, "recover_cancel", &(), json!({}), 0, FAR).await?, "webauthn: bad signature");
    assert_refused(&h.passkey_call(&v, &v.passkey, "recover_cancel", &(), json!({}), 4, FAR).await?, "BadNonce");
    assert_refused(&h.passkey_call(&v, &v.passkey, "recover_cancel", &(), json!({}), 0, SPENT).await?, "IntentExpired");
    Ok(())
}
