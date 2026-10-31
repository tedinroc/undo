//! Attack review, against the real wasm in sandbox with the mock signer. Each test names its finding
//! in tests/REGRESSION-MAP.md. The review ran these against an earlier prototype, where most succeeded
//! as attacks. Here each is expected to be refused.

use anyhow::Result;
use near_token::NearToken;
use sandbox_tests::*;
use serde_json::json;

fn yocto_in(text: &str, marker: &str) -> u128 {
    let at = text.find(marker).unwrap_or_else(|| panic!("no {marker:?} in {text}")) + marker.len();
    text[at..].chars().take_while(char::is_ascii_digit).collect::<String>().parse().unwrap()
}

/// Two sessions over the same coins, with each input declared true in one of them. Signatures from
/// the two would make a valid transaction with a real fee of 999,500 sats at a declared 1,000.
#[tokio::test]
async fn f0_contract_digests_do_not_compose() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("f0").await?;
    let real = coins("swap", 2, 1_000_000);
    let declared = [real[0].clone(), real[1].with_value(1_500)];
    let to = v.spk.to_bytes();
    let id = h.propose(&mut v, &declared, &to, 1_000_500, None).await?;
    assert_eq!(h.request(&v, id).await?["tier"], "SelfSpend");
    let first = h.payloads(&v, id).await?;
    h.wait_unlock(&v, id).await?;
    h.execute_and_respond(&v, id, 2, false).await?.into_result()?;
    assert_eq!(h.status(&v, id).await?, "Signed");
    assert_eq!(h.outpoint(&v, &real[0]).await?["pinned_value"], 1_000_000);
    assert_eq!(h.outpoint(&v, &real[1]).await?["pinned_value"], 1_500);

    // The second session: other input true. Refused while the coins are held.
    let swapped = [real[0].with_value(1_500), real[1].clone()];
    let args = h.propose_args(&v, &swapped, &to, 1_000_500, None, v.spend_nonce);
    assert_refused(&h.propose_raw(args).await?, "OutpointBusy");

    // Free both coins through reclaim and cancel. The pins stay, so a multi-input session stays shut.
    let t_stuck = h.vault_view(&v).await?["policy"]["t_stuck_ms"].as_u64().unwrap();
    let t_new = h.vault_view(&v).await?["policy"]["t_new_ms"].as_u64().unwrap();
    h.advance_to(h.now_ms().await? + t_stuck + 1).await?;
    for coin in &real {
        let r = h.reclaim(&mut v, coin, 500).await?;
        h.cancel_passkey(&v, r).await?.into_result()?;
    }
    assert_eq!(h.outpoint(&v, &real[0]).await?["state"], "Free");
    assert_eq!(h.outpoint(&v, &real[0]).await?["pinned_value"], 1_000_000, "a pin outlives everything");
    let args = h.propose_args(&v, &swapped, &to, 1_000_500, None, v.spend_nonce);
    assert_refused(&h.propose_raw(args).await?, "PinnedInMultiInput");

    // Re-declaring is allowed only alone. That signature has its own hashPrevouts, so it cannot join
    // the first session.
    h.advance_to(h.now_ms().await? + t_new + 1).await?;
    let r = h.propose(&mut v, &real[1..], &to, 999_500, None).await?;
    h.wait_unlock(&v, r).await?;
    h.execute_and_respond(&v, r, 1, false).await?.into_result()?;
    let alone = h.verified_final_tx(&v, r, &real[1..]).await?;
    let spent = spent_outputs(&real, &v.spk);
    let sign_m = |d: &[u8; 32]| {
        let (s, _) = v.k_m.sign_prehash_recoverable(d).unwrap();
        let mut der = s.normalize_s().unwrap_or(s).to_der().as_bytes().to_vec();
        der.push(1);
        der
    };
    let base = unsigned_tx(&declared, &to, 1_000_500, None);
    let half = |index: usize, value: u64| {
        let (s, _) = v.k_u.sign_prehash_recoverable(&sighash(&base, index, &v.script, value)).unwrap();
        let mut der = s.normalize_s().unwrap_or(s).to_der().as_bytes().to_vec();
        der.push(1);
        der
    };
    let build = |sig_b: Vec<u8>, half_b: Vec<u8>| {
        let mut tx = base.clone();
        for (i, (sig, half)) in [(sign_m(&first[0]), half(0, 1_000_000)), (sig_b, half_b)].into_iter().enumerate() {
            let mut w = bitcoin::Witness::new();
            w.push(&sig);
            w.push(&half);
            w.push([1u8]);
            w.push(v.script.as_bytes());
            tx.input[i].witness = w;
        }
        tx
    };
    let alone_m = alone.input[0].witness.nth(0).unwrap().to_vec();
    let alone_u = alone.input[0].witness.nth(1).unwrap().to_vec();
    assert!(consensus_verify(&build(alone_m, alone_u), &spent).is_err(), "the reclaim's signature cannot join");

    // Control: had the contract signed the second session, this is exactly what would be valid.
    let what_it_refused = sighash(&base, 1, &v.script, 1_000_000);
    let attack = build(sign_m(&what_it_refused), half(1, 1_000_000));
    consensus_verify(&attack, &spent)?;
    Ok(())
}

/// A false amount used to hold the coin forever, because a useless signature
/// looks like any other. Now the owner gets it back by `reclaim`, with a fresh half-signature.
#[tokio::test]
async fn f0_false_amount_no_longer_freezes_a_coin() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("f0-freeze").await?;
    let real = coins("pin", 1, 100_000);
    let lie = [real[0].with_value(90_000)];
    let to = v.spk.to_bytes();
    let id = h.propose(&mut v, &lie, &to, 89_500, None).await?;
    h.wait_unlock(&v, id).await?;
    h.execute_and_respond(&v, id, 1, false).await?.into_result()?;
    let useless = h.final_tx(&v, id).await?.unwrap();
    assert!(consensus_verify(&useless, &spent_outputs(&real, &v.spk)).is_err(), "signed over a false value");

    // Held: no honest proposal, and no reclaim until T_stuck.
    let args = h.propose_args(&v, &real, &to, 98_000, None, v.spend_nonce);
    assert_refused(&h.propose_raw(args).await?, "OutpointBusy");
    let early = h.reclaim_args(&v, &real[0], 500, v.spend_nonce);
    let res = h.relayer.call(h.undo.id(), "reclaim").args_json(early).gas(gas(100)).transact().await?;
    assert_refused(&res, "NotStuck");

    let view = h.vault_view(&v).await?;
    let t_stuck = view["policy"]["t_stuck_ms"].as_u64().unwrap();
    h.advance_to(h.now_ms().await? + t_stuck + 1).await?;
    let r = h.reclaim(&mut v, &real[0], 500).await?;
    assert_eq!(h.status(&v, id).await?, "deleted", "the old request is superseded");
    h.wait_unlock(&v, r).await?;
    h.execute_and_respond(&v, r, 1, false).await?.into_result()?;
    h.verified_final_tx(&v, r, &real).await?;
    Ok(())
}

/// A cancel deletes the request and returns its bytes. The earlier prototype kept 183 bytes per cycle forever.
#[tokio::test]
async fn f5_cancel_cycle_keeps_no_storage() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("f5-cycle").await?;
    let real = coins("repin", 1, 100_000);
    let to = v.spk.to_bytes();
    let usage = h.undo.view_account().await?.storage_usage;
    let credit = h.credit(&v).await?;
    let mut last = 0;
    for _ in 0..5 {
        last = h.propose(&mut v, &real, &to, 99_500, None).await?;
        assert!(h.credit(&v).await? < credit, "a pending request is paid for");
        h.cancel_passkey(&v, last).await?.into_result()?;
        assert_eq!(h.undo.view_account().await?.storage_usage, usage, "bytes are gone");
        assert_eq!(h.credit(&v).await?, credit, "and paid back");
    }
    assert_eq!(h.status(&v, last).await?, "deleted");
    Ok(())
}

/// One passkey call kills every pending request, and fake outpoints give three decoys at most.
#[tokio::test]
async fn f5_thief_requests_die_with_rotation_and_decoys_are_capped() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("f5-epoch").await?;
    let fake = coins("decoy", 4, 100_000);
    let mut ids = Vec::new();
    for c in &fake[..3] {
        ids.push(h.propose_simple(&mut v, c).await?);
    }
    let args = h.propose_args(&v, &fake[3..], &p2wpkh("destination"), 50_000, Some(49_500), v.spend_nonce);
    assert_refused(&h.propose_raw(args).await?, "PendingCap");
    let unlock = h.request(&v, ids[2]).await?["unlock"].as_u64().unwrap();

    let grant = h.rotate(&mut v, &test_key("new-k-s")).await?;
    let view = h.vault_view(&v).await?;
    assert_eq!(view["spend_epoch"], 1);
    assert_eq!(view["k_s_suspended"], true);

    h.advance_to(unlock + 1).await?;
    for id in &ids {
        let res = h.execute_call(&v, *id, None).transact().await?;
        assert_refused(&res, "RequestNotFound");
    }
    let args = h.propose_args(&v, &fake[..1], &p2wpkh("destination"), 50_000, Some(49_500), v.spend_nonce);
    assert_refused(&h.propose_raw(args).await?, "SpendKeySuspended");
    assert_eq!(h.outpoint(&v, &fake[0]).await?["state"], "Free", "old requests free their coins when next touched");

    // Anyone applies the grant after the wait, and the old key is then refused.
    h.relayer.call(h.undo.id(), "apply_grant").args_json(json!({"vault": v.hex(), "grant": grant})).transact().await?.into_result()?;
    let args = h.propose_args(&v, &fake[..1], &p2wpkh("destination"), 50_000, Some(49_500), v.spend_nonce);
    assert_refused(&h.propose_raw(args).await?, "bad K_s signature");
    Ok(())
}

/// The earlier prototype took an attacker's K_m and delay u64::MAX. An off-curve or foreign recovery
/// key is in `review1: escape_key_needs_proof_of_possession`.
#[tokio::test]
async fn f1_create_vault_refuses_foreign_or_junk() -> Result<()> {
    let h = Harness::new().await?;
    let usage = h.undo.view_account().await?.storage_usage;

    // An attacker's K_m passes every proof, because it is not signed by anyone the attacker lacks.
    let k = keys("f1-attacker-km");
    let mut call = h.create_call(&k, 6);
    call.k_m = compressed(&secp("attacker-mpc"));
    let before = h.relayer.view_account().await?.balance;
    let args = h.create_args(&k, &call).await?;
    let res = h.create_raw(args, 100).await?;
    assert!(res.logs().iter().any(|l| l.contains("undo:refused")), "{:?}", res.logs());
    let id = hex::encode(h.vault_id(&k, 6));
    let view: Option<serde_json::Value> = h.undo.view("vault").args_json(json!({"vault": id})).await?.json()?;
    assert!(view.is_none(), "a wrong K_m never activates, and leaves no row");
    assert_eq!(h.undo.view_account().await?.storage_usage, usage, "no bytes left behind");
    let spent = before.as_yoctonear() - h.relayer.view_account().await?.balance.as_yoctonear();
    assert!(spent < NearToken::from_millinear(10).as_yoctonear(), "the deposit came back: spent {spent}");

    // Keys that collapse the script.
    let mut same = keys("f1-collide");
    same.k_e_leaf = same.k_u.clone();
    let call = h.create_call(&same, 6);
    let args = h.create_args(&same, &call).await?;
    assert_refused(&h.create_raw(args, 100).await?, "DuplicateKey");
    let k = keys("f1-collide-km");
    let mut call = h.create_call(&k, 6);
    call.k_m = compressed(&k.k_u);
    let args = h.create_args(&k, &call).await?;
    assert_refused(&h.create_raw(args, 100).await?, "DuplicateKey");

    // An uncompressed key.
    let k = keys("f1-uncompressed");
    let mut call = h.create_call(&k, 6);
    call.k_m = vec![4; 65];
    let args = h.create_args(&k, &call).await?;
    assert_refused(&h.create_raw(args, 100).await?, "BadPubKey");

    // A junk passkey cannot prove possession.
    let k = keys("f1-junk-passkey");
    let call = h.create_call(&k, 6);
    let mut args = h.create_args(&k, &call).await?;
    args["args"]["passkey"]["pubkey"] = json!(hex::encode([0xffu8; 33]));
    assert!(h.create_raw(args, 100).await?.is_failure());

    // Each proof of possession is required. A stranger's signature in any slot fails.
    let k = keys("f1-pop");
    let call = h.create_call(&k, 6);
    let good = h.create_args(&k, &call).await?;
    let stranger = secp("stranger");
    let junk = hex::encode(secp_sign(&stranger, &[9u8; 32]));
    for (field, needle) in [("pop_u", "bad K_u"), ("pop_e", "bad K_e"), ("pop_leaf", "bad K_e leaf")] {
        let mut bad = good.clone();
        bad["args"][field] = json!(junk);
        assert_refused(&h.create_raw(bad, 100).await?, needle);
    }
    let mut bad = good.clone();
    bad["args"]["pop_s"] = json!(hex::encode([7u8; 64]));
    assert_refused(&h.create_raw(bad, 100).await?, "bad K_s");
    let mut bad = good.clone();
    let mut sig = hex::decode(good["args"]["pop_p"]["signature"].as_str().unwrap())?;
    sig[40] ^= 1;
    bad["args"]["pop_p"]["signature"] = json!(hex::encode(sig));
    assert_refused(&h.create_raw(bad, 100).await?, "webauthn: bad signature");
    let mut bad = good.clone();
    bad["args"]["policy"] = serde_json::to_value(POLICY_OTHER)?;
    assert!(h.create_raw(bad, 100).await?.is_failure(), "proofs bind the policy");

    // Delays beyond the instance's bounds.
    let k = keys("f1-policy");
    let mut call = h.create_call(&k, 6);
    let mut p = h.deployed_policy().await?;
    p[0] = u64::MAX;
    call.policy = Some(p);
    let args = h.create_args(&k, &call).await?;
    assert_refused(&h.create_raw(args, 100).await?, "PolicyOutOfBounds");

    // The signer answering junk does not activate anything either.
    let g = Harness::with(Options { mode: "Garbage", ..Options::default() }).await?;
    let k = keys("f1-garbage");
    let call = g.create_call(&k, 6);
    let args = g.create_args(&k, &call).await?;
    let res = g.create_raw(args, 100).await?;
    assert!(res.logs().iter().any(|l| l.contains("undo:refused")), "{:?}", res.logs());
    Ok(())
}

const POLICY_OTHER: Policy = Policy { t_known_ms: 60_000, t_new_ms: 300_000, t_new_unguarded_ms: 600_000, hold_ms: 300_000, t_stuck_ms: 600_000, fee_cap_tx: 500, fee_budget_24h: 5_000, outflow_cap_24h: OUTFLOW_CAP };

#[derive(serde::Serialize)]
struct Policy {
    t_known_ms: u64,
    t_new_ms: u64,
    t_new_unguarded_ms: u64,
    hold_ms: u64,
    t_stuck_ms: u64,
    fee_cap_tx: u64,
    fee_budget_24h: u64,
    outflow_cap_24h: u64,
}

/// The csv bound, at the contract's door.
#[tokio::test]
async fn f15_create_vault_refuses_csv_abuse() -> Result<()> {
    let h = Harness::new().await?;
    for csv in [0u32, 65_536, 65_542, 1 << 22, (1 << 22) | 1, 1 << 31, (1 << 31) + 6, u32::MAX] {
        let k = keys(&format!("f15-{csv}"));
        let call = h.create_call(&k, csv);
        let args = h.create_args(&k, &call).await?;
        assert_refused(&h.create_raw(args, 100).await?, "CsvOutOfRange");
    }
    for csv in [1u32, 65_535] {
        h.create_vault_csv(&format!("f15-ok-{csv}"), csv).await?;
    }
    Ok(())
}

/// The id is a hash of the keys, not a name, and creating it needs proofs from those same keys.
#[tokio::test]
async fn f22_vault_id_cannot_be_squatted() -> Result<()> {
    let h = Harness::new().await?;
    let k = keys("f22");
    let call = h.create_call(&k, 6);
    let args = h.create_args(&k, &call).await?;

    // A front-runner cannot use the owner's keys with its own K_s: the id changes and the proofs fail.
    let mut front = args.clone();
    front["args"]["k_s"] = json!(hex::encode(keys("f22-thief").k_s.verifying_key().to_bytes()));
    assert_refused(&h.create_raw(front, 100).await?, "bad K_s");

    let res = h.create_raw(args.clone(), 100).await?;
    res.clone().into_result()?;
    assert_eq!(res.json::<String>()?, hex::encode(h.vault_id(&k, 6)), "the contract and the harness agree");
    assert_refused(&h.create_raw(args, 100).await?, "vault exists");
    Ok(())
}

/// The callback must store a signature with the credit at zero and no spare balance. The review
/// drained a contract to this floor: `on_signed` died with LackBalanceForState while the transaction
/// reported success.
async fn floor_run(keep_reserved: bool) -> Result<(String, bool)> {
    let h = Harness::new().await?;
    let k = keys("f11");
    let call = h.create_call(&k, 6);
    let args = h.create_args(&k, &call).await?;
    // Exact deposits: read each price from the refusal, so the credit lands on zero.
    let res = h.relayer.call(h.undo.id(), "create_vault").args_json(args.clone()).deposit(NearToken::from_yoctonear(1)).gas(gas(300)).transact().await?;
    let need = yocto_in(&err_text(&res), "attach at least ");
    h.relayer
        .call(h.undo.id(), "create_vault")
        .args_json(args)
        .deposit(NearToken::from_yoctonear(need))
        .gas(gas(300))
        .transact()
        .await?
        .into_result()?;
    let id = h.vault_id(&k, 6);
    let k_m = h.mpc_key(&id);
    let script = witness_script(&compressed(&k.k_u), &compressed(&k_m), &compressed(&k.k_e_leaf), 6);
    let spk = script.to_p2wsh();
    let mut v = Vault { id, k_s: k.k_s, k_u: k.k_u, k_e_leaf: k.k_e_leaf, k_e_intent: k.k_e_intent, passkey: k.passkey, k_m, csv: 6, script, spk, spend_nonce: 0, passkey_nonce: 0 };
    assert_eq!(h.credit(&v).await?, 0, "creation left no credit");

    let coin = coins("floor", 1, 100_000);
    let args = h.propose_args(&v, &coin, &p2wpkh("destination"), 50_000, Some(49_500), 0);
    let res = h.propose_raw(args.clone()).await?;
    let need = yocto_in(&err_text(&res), "need ");
    h.relayer
        .call(h.undo.id(), "deposit_storage")
        .args_json(json!({"vault": v.hex()}))
        .deposit(NearToken::from_yoctonear(need))
        .transact()
        .await?
        .into_result()?;
    let res = h.propose_raw(args).await?;
    res.clone().into_result()?;
    let request = res.json::<u64>()?;
    v.spend_nonce = 1;
    assert_eq!(h.credit(&v).await?, 0, "the proposal spent all of it");
    h.wait_unlock(&v, request).await?;

    // Move out everything the vault's accounting does not cover. One small transfer first, to learn
    // what a transfer costs the contract's own account.
    let sink = h.worker.dev_create_account().await?;
    let byte = 10_000_000_000_000_000_000u128;
    let free = |a: &near_workspaces::types::AccountDetails| a.balance.as_yoctonear() - a.storage_usage as u128 * byte;
    let a = h.undo.view_account().await?;
    h.undo.as_account().transfer_near(sink.id(), NearToken::from_yoctonear(1)).await?.into_result()?;
    let b = h.undo.view_account().await?;
    let cost = free(&a) - free(&b);
    let reserved = h.vault_view(&v).await?["reserved_bytes"].as_u64().unwrap() as u128 * byte;
    let keep = if keep_reserved { reserved } else { 0 };
    h.undo.as_account().transfer_near(sink.id(), NearToken::from_yoctonear(free(&b) - keep - cost)).await?.into_result()?;
    let left = free(&h.undo.view_account().await?);
    assert!(left >= keep && left < keep + byte * 100, "the balance is at the floor: {left} vs {keep}");

    let res = h.execute_racing(h.execute_call(&v, request, None), 1).await?.map_err(anyhow::Error::msg)?;
    let logs = res.logs().join(" ");
    assert!(!logs.contains("undo:credit_short"), "{logs}");
    Ok((err_text(&res), h.status(&v, request).await? == "Signed"))
}

#[tokio::test]
async fn f11_on_signed_stores_with_zero_credit_at_the_floor() -> Result<()> {
    let (text, signed) = floor_run(true).await?;
    assert!(signed, "the signature was stored: {text}");
    Ok(())
}

/// Control: with nothing kept, the same steps do fail on storage, so the test above is at the floor.
#[tokio::test]
async fn f11_control_without_the_reservation_fails_on_storage() -> Result<()> {
    let (text, signed) = floor_run(false).await?;
    assert!(text.contains("LackBalanceForState"), "expected a storage failure, got {text}");
    assert!(!signed);
    Ok(())
}

/// A stale attempt is dropped. A payload that is not the digest of current state is dropped. Outsiders
/// cannot call the callback. A real answer after the slot was dropped does not store, and retry works.
#[tokio::test]
async fn f8_callback_checks_attempt_and_digest() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("f8").await?;
    let coin = coins("callback", 1, 100_000);
    let id = h.propose_simple(&mut v, &coin[0]).await?;
    h.wait_unlock(&v, id).await?;
    let digest = h.payloads(&v, id).await?[0];

    let call = h.execute_call(&v, id, None);
    let task = tokio::spawn(async move { call.transact().await });
    let pending = h.wait_pending(1).await?;

    let outsider = h.relayer.call(h.undo.id(), "on_signed").args_json(json!({"vault": v.hex(), "request": id, "attempt": 1, "input": 0, "payload": hex::encode(digest)})).transact().await?;
    assert!(outsider.is_failure(), "only the contract calls its own callback");

    let self_call = |attempt: u32, payload: [u8; 32]| {
        h.undo.as_account().call(h.undo.id(), "on_signed").args_json(json!({"vault": v.hex(), "request": id, "attempt": attempt, "input": 0, "payload": hex::encode(payload)})).gas(gas(100)).transact()
    };
    let stale = self_call(0, digest).await?;
    assert!(stale.logs().iter().any(|l| l.contains("DroppedStaleAttempt")), "{:?}", stale.logs());
    assert_eq!(h.request(&v, id).await?["in_flight"], 1, "a stale attempt changes nothing");

    let wrong = self_call(1, [9u8; 32]).await?;
    assert!(wrong.logs().iter().any(|l| l.contains("DroppedDigestMismatch")), "{:?}", wrong.logs());
    assert_eq!(h.request(&v, id).await?["sigs"][0], serde_json::Value::Null);

    // The real answer arrives for a slot no longer in flight.
    h.respond_one(&pending[0], false).await?.into_result()?;
    let _ = task.await??;
    assert_eq!(h.status(&v, id).await?, "Signing");
    assert_eq!(h.request(&v, id).await?["sigs"][0], serde_json::Value::Null);

    // Retry signs under a new attempt, and the old attempt number is dead.
    h.execute_and_respond(&v, id, 1, false).await?.into_result()?;
    assert_eq!(h.status(&v, id).await?, "Signed");
    assert_eq!(h.request(&v, id).await?["attempt"], 2);
    h.verified_final_tx(&v, id, &coin).await?;
    Ok(())
}

/// `reclaim` needs a fresh half-signature over its own digest. A passkey alone has no Bitcoin key.
#[tokio::test]
async fn f8_reclaim_needs_fresh_half_signature() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("f8-reclaim").await?;
    let coin = coins("fresh", 1, 100_000);
    let id = h.propose_simple(&mut v, &coin[0]).await?;
    h.wait_unlock(&v, id).await?;
    h.execute_and_respond(&v, id, 1, false).await?.into_result()?;
    let t_stuck = h.vault_view(&v).await?["policy"]["t_stuck_ms"].as_u64().unwrap();
    h.advance_to(h.now_ms().await? + t_stuck + 1).await?;

    let mut args = h.reclaim_args(&v, &coin[0], 500, v.spend_nonce);
    args["half_sig"] = json!(hex::encode(secp_sign(&v.k_u, &[1u8; 32])));
    let res = h.relayer.call(h.undo.id(), "reclaim").args_json(args).gas(gas(100)).transact().await?;
    assert_refused(&res, "bad K_u half-signature");
    Ok(())
}

/// A rise in the signer's requirement needs no upgrade: a caller may supply more sign gas and a
/// capped deposit. Junk answers leave the request retryable.
#[tokio::test]
async fn f13_execute_takes_caller_gas_and_survives_a_junk_signer() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("f13").await?;
    let coin = coins("outage", 2, 100_000);
    let id = h.propose_simple(&mut v, &coin[0]).await?;
    h.wait_unlock(&v, id).await?;

    let call = |sign: u64, yocto: u128| {
        h.relayer
            .call(h.undo.id(), "execute")
            .args_json(json!({"vault": v.hex(), "request": id, "sign_tgas": sign}))
            .deposit(NearToken::from_yoctonear(yocto))
            .gas(gas(MAX_GAS_TGAS))
    };
    assert_refused(&call(SIGN_TGAS - 1, 0).transact().await?, "sign gas out of range");
    assert_refused(&call(301, 0).transact().await?, "sign gas out of range");
    assert_refused(&call(SIGN_TGAS, NearToken::from_near(1).as_yoctonear()).transact().await?, "deposit per sign above the cap");

    h.mock.call("set_mode").args_json(json!({"mode": "Garbage"})).transact().await?.into_result()?;
    let _ = call(SIGN_TGAS, 0).transact().await?;
    assert_eq!(h.status(&v, id).await?, "Signing");
    assert_eq!(h.request(&v, id).await?["in_flight"], 0, "a junk answer does not strand the slot");

    h.mock.call("set_mode").args_json(json!({"mode": "Yield"})).transact().await?.into_result()?;
    h.execute_with(call(SIGN_TGAS + 10, 2), 1, false).await?.into_result()?;
    assert_eq!(h.status(&v, id).await?, "Signed");
    h.verified_final_tx(&v, id, &coin[..1]).await?;
    Ok(())
}

/// An exit that needs more than the fee cap: 16 inputs. The passkey lifts the cap for that one
/// self-spend, up to 1/20 of what it moves.
#[tokio::test]
async fn f14_sixteen_input_exit_through_the_named_override() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("f14").await?;
    let real = coins("exit", 16, 100_000);
    let to = v.spk.to_bytes();
    let id = h.propose(&mut v, &real, &to, 1_598_000, None).await?;
    h.wait_unlock(&v, id).await?;
    assert_refused(&h.execute_call(&v, id, None).transact().await?, "FeeOverCap");

    let digest = h.passkey_digest(&v, "raise_fee_cap", &(id, 100_000u64), u64::MAX / 2, Some(v.passkey_nonce));
    let too_high = h
        .relayer
        .call(h.undo.id(), "raise_fee_cap")
        .args_json(json!({"vault": v.hex(), "request": id, "cap": 100_000, "nonce": v.passkey_nonce, "expires_at": u64::MAX / 2, "assertion": assertion(&v.passkey, &digest, &Bend::default())}))
        .gas(gas(100))
        .transact()
        .await?;
    assert_refused(&too_high, "OverrideTooHigh");

    h.raise_fee_cap(&mut v, id, 2_000).await?;
    h.execute_and_respond(&v, id, 16, false).await?.into_result()?;
    assert_eq!(h.status(&v, id).await?, "Signed");
    h.verified_final_tx(&v, id, &real).await?;
    Ok(())
}

/// WebAuthn rules, each one bent in turn. Software authenticator: a real phone is a later gate.
#[tokio::test]
async fn f17_webauthn_fixtures() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("f17").await?;
    let coin = coins("webauthn", 1, 100_000);
    let id = h.propose_simple(&mut v, &coin[0]).await?;
    let far = u64::MAX / 2;
    for (bend, needle) in [
        (Bend { flags: 0x01, ..Bend::default() }, "user not verified"),
        (Bend { flags: 0x04, ..Bend::default() }, "user not present"),
        (Bend { kind: "webauthn.create", ..Bend::default() }, "wrong type"),
        (Bend { origin: "https://evil.example", ..Bend::default() }, "origin not allowed"),
        (Bend { cross_origin: Some(true), ..Bend::default() }, "cross origin"),
        (Bend { rp_id: "evil.example", ..Bend::default() }, "wrong rp id"),
        (Bend { wrong_challenge: true, ..Bend::default() }, "wrong challenge"),
    ] {
        assert_refused(&h.cancel_bent(&v, id, far, &bend).await?, needle);
    }
    assert_eq!(h.status(&v, id).await?, "Pending");

    // Everything right except the key, and then except the signature bytes.
    let digest = h.passkey_digest(&v, "cancel", &id, far, None);
    let stranger = p256::ecdsa::SigningKey::from_bytes((&test_key("stranger-passkey")).into()).unwrap();
    let cancel = |assert: serde_json::Value| {
        h.relayer.call(h.undo.id(), "cancel").args_json(json!({"vault": v.hex(), "request": id, "expires_at": far, "auth": {"Passkey": assert}})).gas(gas(100)).transact()
    };
    assert_refused(&cancel(assertion(&stranger, &digest, &Bend::default())).await?, "webauthn: bad signature");
    let mut flipped = assertion(&v.passkey, &digest, &Bend::default());
    let mut sig = hex::decode(flipped["signature"].as_str().unwrap())?;
    sig[40] ^= 1;
    flipped["signature"] = json!(hex::encode(sig));
    assert_refused(&cancel(flipped).await?, "webauthn: bad signature");

    // An expired intent, signed correctly.
    assert_refused(&h.cancel_bent(&v, id, 1, &Bend::default()).await?, "IntentExpired");

    // crossOrigin false is fine, and so is high S, which real authenticators often emit.
    h.cancel_bent(&v, id, far, &Bend { cross_origin: Some(false), high_s: true, ..Bend::default() }).await?.into_result()?;
    assert_eq!(h.status(&v, id).await?, "deleted");

    // No nonce on cancel: a replay finds nothing to cancel, and that is all it can do.
    assert_refused(&h.cancel_passkey(&v, id).await?, "RequestNotFound");

    // The passkey's backup flags are read from its assertion at creation.
    let view = h.vault_view(&v).await?;
    assert_eq!(view["backup_eligible"], false);
    assert_eq!(view["backup_state"], false);
    let k = keys("f17-synced");
    let call = h.create_call(&k, 6);
    let mut args = h.create_args(&k, &call).await?;
    // A synced passkey sets BE and BS. The digest does not change, so re-sign the same creation.
    let id2 = h.vault_id(&k, 6);
    let rp = sha256(RP_ID.as_bytes());
    let digest = sha256(&borsh::to_vec(&("undo-create-v1", h.contract(), id2, call.k_m.clone(), rp, Option::<String>::None, h.deployed_policy().await?, call.expires_at)).unwrap());
    args["args"]["pop_p"] = assertion(&k.passkey, &digest, &Bend { flags: 0x1d, ..Bend::default() });
    h.create_raw(args, 100).await?.into_result()?;
    let view: serde_json::Value = h.undo.view("vault").args_json(json!({"vault": hex::encode(id2)})).await?.json()?;
    assert_eq!(view["backup_eligible"], true);
    assert_eq!(view["backup_state"], true);
    Ok(())
}

/// A request that nobody executes dies, frees its coin, and cannot be executed late.
#[tokio::test]
async fn f18_request_expires() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("f18").await?;
    let coin = coins("expiry", 1, 100_000);
    let id = h.propose_simple(&mut v, &coin[0]).await?;
    let expires = h.request(&v, id).await?["expires_at"].as_u64().unwrap();
    h.advance_to(expires + 1).await?;
    assert_refused(&h.execute_call(&v, id, None).transact().await?, "RequestNotFound");
    h.propose_simple(&mut v, &coin[0]).await?;
    assert_eq!(h.outpoint(&v, &coin[0]).await?["state"], "Pending", "the coin was free again");
    Ok(())
}
