//! Gas and storage of the real wasm, on whatever node the environment names. Prints `MEASURE` lines.
//! scripts/protocol-check.sh --measure writes them to a file per protocol version. Tgas burnt, with
//! the mock signer. The live signer's own gas is a later gate.

use anyhow::Result;
use near_workspaces::result::ExecutionFinalResult;
use sandbox_tests::*;
use serde_json::json;

fn line(name: &str, res: &ExecutionFinalResult, contract: &str, needle: Option<&str>) {
    let own = own_gas(res, contract, needle);
    let max = own.iter().copied().max().unwrap_or(0);
    println!("MEASURE gas {name} method_max={:.2}T tx_total={:.2}T", tgas(max), tgas(res.total_gas_burnt.as_gas()));
}

fn callback_max(res: &ExecutionFinalResult, contract: &str) -> f64 {
    tgas(own_gas(res, contract, Some("undo:signed")).into_iter().max().unwrap_or(0))
}

#[tokio::test]
async fn gas_and_storage() -> Result<()> {
    let h = Harness::new().await?;
    let c = h.undo.id().to_string();
    let info = h.undo.view_account().await?;
    println!("MEASURE contract storage_usage={} bytes", info.storage_usage);

    // create_vault: own receipt, the signer's view in the mock, and the callback.
    let k = keys("measure-create");
    let call = h.create_call(&k, 6);
    let args = h.create_args(&k, &call).await?;
    let res = h.create_raw(args, 100).await?;
    res.clone().into_result()?;
    line("create_vault", &res, &c, Some("undo:created"));
    println!("MEASURE gas on_derived method_max={:.2}T", tgas(own_gas(&res, &c, Some("undo:active")).into_iter().max().unwrap_or(0)));
    println!("MEASURE gas mock_derived_public_key {:.2}T", tgas(own_gas(&res, h.mock.id().as_str(), None).into_iter().max().unwrap_or(0)));

    for inputs in [1usize, 3, 8, 16] {
        let mut v = h.create_vault(&format!("measure-{inputs}")).await?;
        let real = coins(&format!("measure-{inputs}"), inputs, 100_000);
        let to = v.spk.to_bytes();
        let fee = if inputs == 16 { 2_000 } else { 950 };
        let args = h.propose_args(&v, &real, &to, inputs as u64 * 100_000 - fee, None, 0);
        let res = h.propose_raw(args).await?;
        res.clone().into_result()?;
        let id = res.clone().json::<u64>()?;
        v.spend_nonce = 1;
        line(&format!("propose_btc inputs={inputs}"), &res, &c, Some("undo:proposed"));
        let view = h.vault_view(&v).await?;
        println!("MEASURE storage request inputs={inputs} row_bytes={} reserved_bytes={}", view["row_bytes"], view["reserved_bytes"]);

        h.wait_unlock(&v, id).await?;
        if fee > 1_000 {
            h.raise_fee_cap(&mut v, id, fee).await?;
        }
        let res = h.execute_and_respond(&v, id, inputs, false).await?;
        res.clone().into_result()?;
        assert_eq!(h.status(&v, id).await?, "Signed");
        h.verified_final_tx(&v, id, &real).await?;
        line(&format!("execute inputs={inputs}"), &res, &c, Some("undo:executing"));
        println!("MEASURE gas on_signed inputs={inputs} max={:.2}T", callback_max(&res, &c));
        let view = h.vault_view(&v).await?;
        println!("MEASURE storage signed inputs={inputs} row_bytes={} reserved_bytes={}", view["row_bytes"], view["reserved_bytes"]);
    }

    // Smallest prepaid gas: the contract refuses below it with a message, and it is enough above it.
    for inputs in [1usize, 3, 8, 16] {
        let mut v = h.create_vault(&format!("measure-prepaid-{inputs}")).await?;
        let real = coins(&format!("prepaid-{inputs}"), inputs, 100_000);
        let fee = if inputs == 16 { 2_000 } else { 950 };
        let to = v.spk.to_bytes();
        let id = h.propose(&mut v, &real, &to, inputs as u64 * 100_000 - fee, None).await?;
        h.wait_unlock(&v, id).await?;
        if fee > 1_000 {
            h.raise_fee_cap(&mut v, id, fee).await?;
        }
        let base = inputs as u64 * (SIGN_TGAS + CALLBACK_TGAS);
        let mut floor = None;
        for extra in (2u64..=60).step_by(2) {
            let call = h.relayer.call(h.undo.id(), "execute").args_json(json!({"vault": v.hex(), "request": id})).gas(gas(base + extra));
            if let Ok(res) = h.execute_racing(call, inputs).await? {
                if res.is_success() && h.status(&v, id).await? == "Signed" {
                    floor = Some(base + extra);
                    break;
                }
            }
        }
        println!("MEASURE prepaid execute inputs={inputs} attach_at_least={floor:?}T sign={SIGN_TGAS}T callback={CALLBACK_TGAS}T");
        assert_eq!(h.status(&v, id).await?, "Signed");
    }

    // Passkey, cold key, rotation, reclaim, top-up.
    let mut v = h.create_vault("measure-rest").await?;
    let coin = coins("rest", 3, 100_000);
    let id = h.propose_simple(&mut v, &coin[0]).await?;
    let res = h.cancel_passkey(&v, id).await?;
    res.clone().into_result()?;
    line("cancel passkey", &res, &c, Some("undo:cancelled"));
    let id = h.propose_simple(&mut v, &coin[0]).await?;
    let res = h.relayer.call(h.undo.id(), "cancel").args_json(h.cold_cancel_args(&v, &v.k_e_intent, id)).gas(gas(100)).transact().await?;
    res.clone().into_result()?;
    line("cancel cold", &res, &c, Some("undo:cancelled"));

    let res = h.relayer.call(h.undo.id(), "deposit_storage").args_json(json!({"vault": v.hex()})).deposit(near_token::NearToken::from_millinear(1)).transact().await?;
    res.clone().into_result()?;
    println!("MEASURE gas deposit_storage tx_total={:.2}T", tgas(res.total_gas_burnt.as_gas()));

    let id = h.propose_simple(&mut v, &coin[1]).await?;
    h.wait_unlock(&v, id).await?;
    h.execute_and_respond(&v, id, 1, false).await?.into_result()?;
    let t_stuck = h.vault_view(&v).await?["policy"]["t_stuck_ms"].as_u64().unwrap();
    h.advance_to(h.now_ms().await? + t_stuck + 1).await?;
    let args = h.reclaim_args(&v, &coin[1], 500, v.spend_nonce);
    let res = h.relayer.call(h.undo.id(), "reclaim").args_json(args).gas(gas(100)).transact().await?;
    res.clone().into_result()?;
    v.spend_nonce += 1;
    line("reclaim", &res, &c, Some("undo:proposed"));

    let expires_at = u64::MAX / 2;
    let new_key = test_key("measure-rotate");
    let digest = h.passkey_digest(&v, "cancel_all_and_rotate", &new_key, expires_at, Some(v.passkey_nonce));
    let res = h
        .relayer
        .call(h.undo.id(), "cancel_all_and_rotate")
        .args_json(json!({"vault": v.hex(), "new_k_s": hex::encode(new_key), "nonce": v.passkey_nonce, "expires_at": expires_at, "assertion": assertion(&v.passkey, &digest, &Bend::default())}))
        .gas(gas(100))
        .transact()
        .await?;
    res.clone().into_result()?;
    line("cancel_all_and_rotate", &res, &c, Some("undo:rotating"));
    let grant = res.clone().json::<u64>()?;
    v.passkey_nonce += 1;

    // The cold key's methods, recovery, and pruning.
    let cold = v.k_e_intent.clone();
    let res = h.cold_call(&v, &cold, "veto_grant", &grant, json!({"grant": grant}), 0, expires_at).await?;
    res.clone().into_result()?;
    line("veto_grant", &res, &c, Some("undo:vetoed"));
    let until = h.now_ms().await? + 60_000;
    let res = h.cold_call(&v, &cold, "freeze", &until, json!({"until": until}), 1, expires_at).await?;
    res.clone().into_result()?;
    line("freeze", &res, &c, Some("undo:frozen"));
    let res = h.cold_call(&v, &cold, "unfreeze", &(), json!({}), 2, expires_at).await?;
    res.clone().into_result()?;
    line("unfreeze", &res, &c, Some("undo:unfrozen"));
    let owner = p256::ecdsa::SigningKey::from_bytes((&test_key("measure-new-passkey")).into()).unwrap();
    let res = h.recover_begin_with(&v, &cold, &owner, &owner, 3, expires_at).await?;
    res.clone().into_result()?;
    line("recover_begin", &res, &c, Some("undo:recovery_begun"));
    let res = h.passkey_call(&v, &v.passkey, "recover_cancel", &(), json!({}), v.passkey_nonce, expires_at).await?;
    res.clone().into_result()?;
    line("recover_cancel", &res, &c, Some("undo:recovery_cancelled"));
    h.recover_begin_with(&v, &cold, &owner, &owner, 4, expires_at).await?.into_result()?;
    let ready = h.vault_view(&v).await?["recovery_ready_at"].as_u64().unwrap();
    h.advance_to(ready + 1).await?;
    let res = h.relayer.call(h.undo.id(), "recover_finish").args_json(json!({"vault": v.hex()})).gas(gas(100)).transact().await?;
    res.clone().into_result()?;
    line("recover_finish", &res, &c, Some("undo:recovered"));

    let mut v = h.create_vault("measure-prune").await?;
    let coin = coins("prune", 1, 100_000);
    let id = h.propose_simple(&mut v, &coin[0]).await?;
    h.wait_unlock(&v, id).await?;
    h.execute_and_respond(&v, id, 1, false).await?.into_result()?;
    let window: serde_json::Value = h.undo.view("instance").args_json(json!({})).await?.json()?;
    h.advance_to(h.now_ms().await? + window["expiry_window_ms"].as_u64().unwrap() + 1).await?;
    let res = h.prune(&v, id).await?;
    res.clone().into_result()?;
    line("prune_signed", &res, &c, Some("undo:pruned"));
    Ok(())
}

/// Pins never leave, but each has its own storage entry, so what a call costs should not grow with
/// them. The budget limits how fast fake executes can add them, and this measures the cost at that
/// limit.
#[tokio::test]
async fn gas_with_a_grown_row() -> Result<()> {
    let h = Harness::new().await?;
    let c = h.undo.id().to_string();
    let mut v = h.create_vault("measure-grown").await?;
    h.relayer.call(h.undo.id(), "deposit_storage").args_json(json!({"vault": v.hex()})).deposit(near_token::NearToken::from_near(1)).transact().await?.into_result()?;
    let to = p2wpkh("destination");
    let mut pins = 0;
    for round in 0..5 {
        let real = coins(&format!("grown-{round}"), 8, 100_000);
        let id = h.propose(&mut v, &real, &to, 799_050, None).await?;
        h.wait_unlock(&v, id).await?;
        let res = h.execute_and_respond(&v, id, 8, false).await?;
        res.clone().into_result()?;
        pins += 8;
        let view = h.vault_view(&v).await?;
        println!("MEASURE grown pins={pins} row_bytes={} on_signed_max={:.2}T", view["row_bytes"], callback_max(&res, &c));
    }
    let coin = coins("grown-more", 1, 100_000);
    let args = h.propose_args(&v, &coin, &to, 50_000, Some(49_500), v.spend_nonce);
    let res = h.propose_raw(args).await?;
    res.clone().into_result()?;
    line(&format!("propose_btc inputs=1 pins={pins}"), &res, &c, Some("undo:proposed"));
    let id = res.clone().json::<u64>()?;
    let res = h.cancel_passkey(&v, id).await?;
    res.clone().into_result()?;
    line(&format!("cancel passkey pins={pins}"), &res, &c, Some("undo:cancelled"));
    Ok(())
}

/// What a griefed panic button costs. A thief fills the queue with the largest requests the rules
/// allow, each carrying half-signatures, so every owner method has them to load. These sizes are what
/// the relay's owner key has to attach.
#[tokio::test]
async fn gas_of_owner_methods_on_a_griefed_queue() -> Result<()> {
    let h = Harness::new().await?;
    let burn = |r: &ExecutionFinalResult| tgas(r.total_gas_burnt.as_gas());
    let mut v = h.create_vault("griefed").await?;
    h.relayer.call(h.undo.id(), "deposit_storage").args_json(json!({"vault": v.hex()})).deposit(near_token::NearToken::from_near(2)).transact().await?.into_result()?;
    let dest = p2wpkh("griefed-d");
    // The fee cap refuses a new-address spend past 8 inputs at the rate floor. A self-spend may carry
    // 16, up to a twentieth at propose, and the slot lets one through. The others are the largest that
    // pass.
    let own = v.spk.to_bytes();
    let big = coins("griefed-a", 16, 1_000_000);
    h.propose(&mut v, &big, &own, 16_000_000 - 2_000, None).await?;
    for label in ["griefed-b", "griefed-c"] {
        h.propose(&mut v, &coins(label, 8, 1_000_000), &dest, 8_000_000 - 1_000, None).await?;
    }
    let queue = h.vault_view(&v).await?["pending"].as_array().unwrap().clone();
    assert_eq!(queue.len(), 3);
    let third = queue[2].as_u64().unwrap();

    let r = h.cancel_passkey(&v, third).await?;
    println!("MEASURE griefed cancel_passkey tx={:.2}T", burn(&r));
    r.into_result()?;
    h.propose(&mut v, &coins("griefed-d", 8, 1_000_000), &dest, 8_000_000 - 1_000, None).await?;
    let third = h.vault_view(&v).await?["pending"].as_array().unwrap()[2].as_u64().unwrap();
    let args = h.cold_cancel_args(&v, &v.k_e_intent, third);
    let r = h.relayer.call(h.undo.id(), "cancel").args_json(args).gas(gas(100)).transact().await?;
    println!("MEASURE griefed cancel_cold tx={:.2}T", burn(&r));
    r.into_result()?;
    h.propose(&mut v, &coins("griefed-e", 8, 1_000_000), &dest, 8_000_000 - 1_000, None).await?;

    let expires_at = u64::MAX / 2;
    let new = test_key("griefed-new");
    let digest = h.passkey_digest(&v, "cancel_all_and_rotate", &new, expires_at, Some(v.passkey_nonce));
    let r = h.relayer.call(h.undo.id(), "cancel_all_and_rotate")
        .args_json(json!({"vault": v.hex(), "new_k_s": hex::encode(new), "nonce": v.passkey_nonce, "expires_at": expires_at, "assertion": assertion(&v.passkey, &digest, &Bend::default())}))
        .gas(gas(100)).transact().await?;
    println!("MEASURE griefed cancel_all_and_rotate tx={:.2}T", burn(&r));
    r.into_result()?;

    // The first state change after that sweeps the dead queue: 32 outpoints freed in one call.
    let until = h.now_ms().await? + 60_000;
    let n = h.nonce_of(&v, "cold_nonce").await?;
    let r = h.cold_call(&v, &v.k_e_intent, "freeze", &until, json!({"until": until}), n, expires_at).await?;
    println!("MEASURE griefed freeze_sweeping_three tx={:.2}T", burn(&r));
    r.into_result()?;
    Ok(())
}
