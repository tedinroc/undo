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
        if inputs == 16 {
            // A reclaim that supersedes a Signed request logs its transaction, and this is the largest.
            let t_stuck = view["policy"]["t_stuck_ms"].as_u64().unwrap();
            h.advance_to(h.now_ms().await? + t_stuck + 1).await?;
            let args = h.reclaim_args(&v, &real[0], 500, v.spend_nonce);
            let res = h.relayer.call(h.undo.id(), "reclaim").args_json(args).gas(gas(100)).transact().await?;
            res.clone().into_result()?;
            line("reclaim superseding_signed_inputs=16", &res, &c, Some("undo:superseded"));
        }
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

/// The section 11 methods, in the shape their sandbox tests use them.
#[tokio::test]
async fn gas_of_the_last_methods() -> Result<()> {
    use ed25519_dalek::{Signer as _, SigningKey};
    let h = Harness::new().await?;
    let c = h.undo.id().to_string();
    let far = u64::MAX / 2;
    let guard = h.worker.dev_create_account().await?;
    let model = SigningKey::from_bytes(&test_key("measure-model"));
    h.relayer.call(h.undo.id(), "add_model_signer").args_json(json!({"model": "Qwen/Qwen3.8-27B", "signer": hex::encode(model.verifying_key().to_bytes())})).transact().await?.into_result()?;
    let k = keys("measure-surface");
    let mut call = h.create_call(&k, 6);
    call.guard = Some(guard.id().to_string());
    let args = h.create_args(&k, &call).await?;
    h.create_raw(args, 100).await?.into_result()?;
    let id = h.vault_id(&k, 6);
    let k_m = h.mpc_key(&id);
    let script = witness_script(&compressed(&k.k_u), &compressed(&k_m), &compressed(&k.k_e_leaf), 6);
    let spk = script.to_p2wsh();
    let mut v = Vault { id, k_s: k.k_s, k_u: k.k_u, k_e_leaf: k.k_e_leaf, k_e_intent: k.k_e_intent, passkey: k.passkey, k_m, csv: 6, script, spk, spend_nonce: 0, passkey_nonce: 0 };

    let res = guard.call(h.undo.id(), "heartbeat").args_json(json!({"vault": v.hex()})).gas(gas(30)).transact().await?;
    res.clone().into_result()?;
    line("heartbeat", &res, &c, None);

    let dest = p2wpkh("measure-dest");
    let pk = |nonce: u64| nonce;
    let n = h.nonce_of(&v, "passkey_nonce").await?;
    let res = h.passkey_call(&v, &v.passkey, "add_destination", &dest, json!({"script": hex::encode(&dest)}), pk(n), far).await?;
    res.clone().into_result()?;
    line("add_destination", &res, &c, None);
    let res = h.passkey_call(&v, &v.passkey, "remove_destination", &dest, json!({"script": hex::encode(&dest)}), pk(n + 1), far).await?;
    res.clone().into_result()?;
    line("remove_destination", &res, &c, None);
    let policy = h.deployed_policy().await?;
    let mut tighter = policy;
    tighter[5] -= 1;
    let call_policy = json!({"t_known_ms": tighter[0], "t_new_ms": tighter[1], "t_new_unguarded_ms": tighter[2], "hold_ms": tighter[3], "t_stuck_ms": tighter[4], "fee_cap_tx": tighter[5], "fee_budget_24h": tighter[6], "outflow_cap_24h": tighter[7]});
    let res = h.passkey_call(&v, &v.passkey, "set_policy", &tighter, json!({"policy": call_policy}), pk(n + 2), far).await?;
    res.clone().into_result()?;
    line("set_policy", &res, &c, None);
    let g = Some(guard.id().to_string());
    let res = h.passkey_call(&v, &v.passkey, "set_guard", &g, json!({"guard": g}), pk(n + 3), far).await?;
    res.clone().into_result()?;
    line("set_guard", &res, &c, None);

    let coin = coins("measure-surface", 1, 100_000);
    let request = h.propose_simple(&mut v, &coin[0]).await?;
    let body: String = h.undo.view("guard_prompt").args_json(json!({"vault": v.hex(), "request": request})).await?.json()?;
    println!("MEASURE size guard_prompt bytes={}", body.len());
    let content = serde_json::to_string(r#"{"hold":true,"reason":"memo_mismatch"}"#)?;
    let response = format!(r#"{{"id":"chatcmpl-1","object":"chat.completion","model":"Qwen/Qwen3.8-27B","choices":[{{"index":0,"message":{{"role":"assistant","content":{content}}},"finish_reason":"stop"}}],"usage":{{"prompt_tokens":318,"completion_tokens":15,"total_tokens":333}}}}"#);
    let text = format!("Qwen/Qwen3.8-27B:{}:{}", hex::encode(sha256(body.as_bytes())), hex::encode(sha256(response.as_bytes())));
    let sig = model.sign(text.as_bytes()).to_bytes();
    let res = guard.call(h.undo.id(), "assess").args_json(json!({"vault": v.hex(), "request": request, "response_bytes": hex::encode(&response), "signature": hex::encode(sig)})).gas(gas(100)).transact().await?;
    res.clone().into_result()?;
    line("assess", &res, &c, None);
    let res = h.passkey_call(&v, &v.passkey, "clear_hold", &request, json!({"request": request}), pk(n + 4), far).await?;
    res.clone().into_result()?;
    line("clear_hold", &res, &c, None);

    // The largest answer `assess` will read, so a guard's allowance can be sized from it.
    let second = h.propose_simple(&mut v, &coins("measure-surface-2", 1, 100_000)[0]).await?;
    let body: String = h.undo.view("guard_prompt").args_json(json!({"vault": v.hex(), "request": second})).await?.json()?;
    let padding = " ".repeat(16_384 - response.len());
    let padded = format!("{response}{padding}");
    let text = format!("Qwen/Qwen3.8-27B:{}:{}", hex::encode(sha256(body.as_bytes())), hex::encode(sha256(padded.as_bytes())));
    let sig = model.sign(text.as_bytes()).to_bytes();
    let res = guard.call(h.undo.id(), "assess").args_json(json!({"vault": v.hex(), "request": second, "response_bytes": hex::encode(&padded), "signature": hex::encode(sig)})).gas(gas(100)).transact().await?;
    res.clone().into_result()?;
    line("assess_16kb_answer", &res, &c, None);

    let view = h.vault_view(&v).await?;
    println!("MEASURE storage surface row_bytes={} reserved_bytes={}", view["row_bytes"], view["reserved_bytes"]);

    // What the page's relay must attach at least, and what a fresh vault's row holds.
    let k = keys("measure-fresh");
    let call = h.create_call(&k, 6);
    let args = h.create_args(&k, &call).await?;
    let refused = h.relayer.call(h.undo.id(), "create_vault").args_json(args).deposit(near_token::NearToken::from_yoctonear(1)).gas(gas(300)).transact().await?;
    let need = yocto_after(&err_text(&refused), "attach at least ");
    let fresh = h.create_vault_no_credit("measure-fresh", 6).await?;
    let view = h.vault_view(&fresh).await?;
    println!("MEASURE storage empty_vault row_bytes={} reserved_bytes={} deposit_needed_near={:.5}", view["row_bytes"], view["reserved_bytes"], need as f64 / 1e24);

    // The upgrade queue. The code travels as the call's raw input, and it is a contract's size.
    let mut code = wasm("undo_vault");
    code.extend_from_slice(&[0, 2, 1, b'x']);
    let res = h.relayer.call(h.undo.id(), "upgrade_propose").args_json(json!({"code_hash": hex::encode(sha256(&code))})).transact().await?;
    res.clone().into_result()?;
    line("upgrade_propose", &res, &c, None);
    let instance: serde_json::Value = h.undo.view("instance").args_json(json!({})).await?.json()?;
    h.advance_to(instance["pending_upgrade"]["unlock_at"].as_u64().unwrap()).await?;
    let res = h.relayer.call(h.undo.id(), "upgrade_apply").args(code).gas(gas(300)).transact().await?;
    res.clone().into_result()?;
    line("upgrade_apply", &res, &c, None);
    Ok(())
}

/// What the relay attaches to every `K_p` and `K_e` method, from the griefed rows below. It is
/// `OWNER_ATTACH_TGAS` in `tools/lib/vault-client.mjs` too. Prepaid gas is held against the relay, and
/// unused gas comes back, so this only has to clear the worst case, not match the usual one.
const OWNER_ATTACH_TGAS: u64 = 30;
/// What the docs tell a guard to attach to `assess`.
const ASSESS_ATTACH_TGAS: u64 = 20;

async fn rotate_at_owner_attach(h: &Harness, v: &Vault, label: &str) -> Result<(ExecutionFinalResult, ed25519_dalek::SigningKey)> {
    let expires_at = u64::MAX / 2;
    let new = ed25519_dalek::SigningKey::from_bytes(&test_key(label));
    let key = new.verifying_key().to_bytes();
    let n = h.nonce_of(v, "passkey_nonce").await?;
    let digest = h.passkey_digest(v, "cancel_all_and_rotate", &key, expires_at, Some(n));
    let r = h.relayer.call(h.undo.id(), "cancel_all_and_rotate")
        .args_json(json!({"vault": v.hex(), "new_k_s": hex::encode(key), "nonce": n, "expires_at": expires_at, "assertion": assertion(&v.passkey, &digest, &Bend::default())}))
        .gas(gas(OWNER_ATTACH_TGAS))
        .transact()
        .await?;
    Ok((r, new))
}

/// One griefed row: what it burnt, at exactly what a relay attaches.
fn griefed(name: &str, r: ExecutionFinalResult) -> Result<()> {
    let burnt = tgas(r.total_gas_burnt.as_gas());
    println!("MEASURE griefed {name} tx={burnt:.2}T");
    assert!(burnt < OWNER_ATTACH_TGAS as f64, "{name}: {burnt}");
    r.into_result()?;
    Ok(())
}

/// The worst row the rules allow: 32 known destinations of the longest script, a full list of grants with
/// the longest account names, and the 24 h windows full at the rate floor. Thief here has K_s, K_u and K_p.
/// A request's outflow counts for a day after its last signature request, and a paying request's retries
/// close a day after its first execute, so the outflow window can hold two days of spends. A landing
/// rotation clears the fee window and not the outflow window, so one gets the row to that size inside one
/// sandbox day.
async fn worst_row(h: &Harness, label: &str, guard: &str) -> Result<Vault> {
    let k = keys(label);
    let mut call = h.create_call(&k, 6);
    call.guard = Some(guard.to_string());
    let args = h.create_args(&k, &call).await?;
    h.create_raw(args, 100).await?.into_result()?;
    let id = h.vault_id(&k, 6);
    let k_m = h.mpc_key(&id);
    let script = witness_script(&compressed(&k.k_u), &compressed(&k_m), &compressed(&k.k_e_leaf), 6);
    let spk = script.to_p2wsh();
    let mut v = Vault { id, k_s: k.k_s, k_u: k.k_u, k_e_leaf: k.k_e_leaf, k_e_intent: k.k_e_intent, passkey: k.passkey, k_m, csv: 6, script, spk, spend_nonce: 0, passkey_nonce: 0 };
    h.relayer.call(h.undo.id(), "deposit_storage").args_json(json!({"vault": v.hex()})).deposit(near_token::NearToken::from_near(5)).transact().await?.into_result()?;

    let expires_at = u64::MAX / 2;
    let t_new = h.vault_view(&v).await?["policy"]["t_new_ms"].as_u64().unwrap();
    let mut known = None;
    for i in 0..32 {
        let mut script = vec![0x00, 0x20];
        script.extend_from_slice(&test_key(&format!("{label}-known-{i}")));
        let r = h.passkey_call(&v, &v.passkey, "add_destination", &script, json!({"script": hex::encode(&script)}), v.passkey_nonce, expires_at).await?;
        let grant = r.into_result()?.json::<u64>()?;
        v.passkey_nonce += 1;
        known.get_or_insert(script);
        if i % 8 == 7 {
            h.advance_to(h.now_ms().await? + t_new + 1).await?;
            for g in grant - 7..=grant {
                h.relayer.call(h.undo.id(), "apply_grant").args_json(json!({"vault": v.hex(), "grant": g})).transact().await?.into_result()?;
            }
        }
    }
    for i in 0..8u8 {
        let name = Some(format!("{}", (b'a' + i) as char).repeat(64));
        h.passkey_call(&v, &v.passkey, "set_guard", &name, json!({"guard": name}), v.passkey_nonce, expires_at).await?.into_result()?;
        v.passkey_nonce += 1;
    }
    let known = known.unwrap();
    for day in 0..2 {
        if day == 1 {
            let (r, new) = rotate_at_owner_attach(h, &v, &format!("{label}-second-day")).await?;
            r.into_result()?;
            v.passkey_nonce += 1;
            let grant = h.vault_view(&v).await?["grants"].as_array().unwrap().last().unwrap().as_u64().unwrap();
            let t_known = h.vault_view(&v).await?["policy"]["t_known_ms"].as_u64().unwrap();
            h.advance_to(h.now_ms().await? + t_known + 1).await?;
            h.relayer.call(h.undo.id(), "apply_grant").args_json(json!({"vault": v.hex(), "grant": grant})).gas(gas(OWNER_ATTACH_TGAS)).transact().await?.into_result()?;
            v.k_s = new;
        }
        let c = coins(&format!("{label}-win-{day}"), 31, 5_000);
        for chunk in c.chunks(3) {
            let mut ids = vec![];
            for coin in chunk {
                ids.push(h.propose(&mut v, std::slice::from_ref(coin), &known, 5_000 - 161, None).await?);
            }
            for id in ids {
                h.wait_unlock(&v, id).await?;
                h.execute_and_respond(&v, id, 1, false).await?.into_result()?;
            }
        }
    }
    let view = h.vault_view(&v).await?;
    println!("MEASURE griefed row row_bytes={} known={} grants={} fee_used={}", view["row_bytes"], view["known"].as_array().unwrap().len(), view["grants"].as_array().unwrap().len(), view["fee_used_24h"]);
    Ok(v)
}

/// The largest queue the rules allow. The slot lets one self-spend through per `T_new`, and a self-spend stays
/// pending for over an hour, so three of 16 inputs can wait at once, each with the longest memo.
async fn big_queue(h: &Harness, v: &mut Vault, label: &str) -> Result<Vec<u64>> {
    let t_new = h.vault_view(v).await?["policy"]["t_new_ms"].as_u64().unwrap();
    let own = v.spk.to_bytes();
    let mut ids = vec![];
    for i in 0..3 {
        h.advance_to(h.now_ms().await? + t_new + 1).await?;
        let c = coins(&format!("{label}-q{i}"), 16, 1_000_000);
        let args = h.propose_args_memo(v, &c, &own, 16_000_000 - 2_000, None, v.spend_nonce, Some("\"".repeat(140)));
        let r = h.propose_raw(args).await?;
        ids.push(r.into_result()?.json::<u64>()?);
        v.spend_nonce += 1;
    }
    Ok(ids)
}

/// What a griefed panic button costs, on the worst row and the largest queue. These sizes are what the
/// relay's owner key has to attach, and the callback's fixed gas has to clear.
#[tokio::test]
async fn gas_of_owner_methods_on_the_worst_row_and_queue() -> Result<()> {
    let h = Harness::new().await?;
    let guard = h.worker.dev_create_account().await?;
    let mut v = worst_row(&h, "griefed", guard.id().as_str()).await?;
    let own = v.spk.to_bytes();
    let expires_at = u64::MAX / 2;

    // on_signed first, on the biggest request, while the row is at its largest.
    let t_new = h.vault_view(&v).await?["policy"]["t_new_ms"].as_u64().unwrap();
    h.advance_to(h.now_ms().await? + t_new + 1).await?;
    let args = h.propose_args_memo(&v, &coins("griefed-big", 16, 1_000_000), &own, 16_000_000 - 2_000, None, v.spend_nonce, Some("\"".repeat(140)));
    let r = h.propose_raw(args).await?;
    let id = r.into_result()?.json::<u64>()?;
    v.spend_nonce += 1;
    h.raise_fee_cap(&mut v, id, 2_000).await?;
    h.wait_unlock(&v, id).await?;
    let r = h.execute_and_respond(&v, id, 16, false).await?;
    r.clone().into_result()?;
    let c = h.contract().to_string();
    let most = own_gas(&r, &c, Some("undo:signed")).into_iter().max().unwrap_or(0);
    println!("MEASURE griefed on_signed_16_inputs own={:.2}T", tgas(most));
    assert!(tgas(most) < CALLBACK_TGAS as f64);
    assert_eq!(h.status(&v, id).await?, "Signed");

    let queue = big_queue(&h, &mut v, "griefed").await?;
    let digest = h.passkey_digest(&v, "cancel", &queue[2], expires_at, None);
    let auth = json!({"Passkey": assertion(&v.passkey, &digest, &Bend::default())});
    griefed("cancel_passkey", h.relayer.call(h.undo.id(), "cancel").args_json(json!({"vault": v.hex(), "request": queue[2], "expires_at": expires_at, "auth": auth})).gas(gas(OWNER_ATTACH_TGAS)).transact().await?)?;
    h.advance_to(h.now_ms().await? + t_new + 1).await?;
    let again = h.propose(&mut v, &coins("griefed-again", 16, 1_000_000), &own, 16_000_000 - 2_000, None).await?;
    let args = h.cold_cancel_args(&v, &v.k_e_intent, again);
    griefed("cancel_cold", h.relayer.call(h.undo.id(), "cancel").args_json(args).gas(gas(OWNER_ATTACH_TGAS)).transact().await?)?;
    h.advance_to(h.now_ms().await? + t_new + 1).await?;
    h.propose(&mut v, &coins("griefed-again2", 16, 1_000_000), &own, 16_000_000 - 2_000, None).await?;

    let (r, _) = rotate_at_owner_attach(&h, &v, "griefed-new").await?;
    griefed("cancel_all_and_rotate", r)?;
    let (r, _) = rotate_at_owner_attach(&h, &v, "griefed-newer").await?;
    griefed("cancel_all_and_rotate_sweeping_three", r)?;
    let view = h.vault_view(&v).await?;
    println!("MEASURE griefed row_after_sweep row_bytes={} grants={}", view["row_bytes"], view["grants"].as_array().unwrap().len());
    Ok(())
}

/// The other calls that can land on a dead queue: whichever comes first sweeps it. `apply_grant` and
/// `recover_finish` are neither a passkey's nor a cold key's, and the rotation's landing goes through one.
#[tokio::test]
async fn gas_of_the_landing_and_the_cold_key_on_the_largest_dead_queue() -> Result<()> {
    let h = Harness::new().await?;
    let guard = h.worker.dev_create_account().await?;
    let mut v = worst_row(&h, "landing", guard.id().as_str()).await?;
    let expires_at = u64::MAX / 2;
    big_queue(&h, &mut v, "landing-a").await?;
    rotate_at_owner_attach(&h, &v, "landing-n1").await?.0.into_result()?;
    let newest_grant = |view: &serde_json::Value| view["grants"].as_array().unwrap().last().unwrap().as_u64().unwrap();

    // The cold key's recovery is the first state change.
    let phone = p256::ecdsa::SigningKey::from_bytes((&test_key("landing-phone")).into()).unwrap();
    let rp = sha256(RP_ID.as_bytes());
    let args = (p256_compressed(&phone), rp);
    let n = h.nonce_of(&v, "cold_nonce").await?;
    let digest = intent_digest("undo-cold-v1", h.contract(), &v.id, "recover_begin", &args, expires_at, Some(n));
    let call = json!({
        "vault": v.hex(), "nonce": n, "expires_at": expires_at,
        "new_passkey": {"pubkey": hex::encode(p256_compressed(&phone)), "rp_id_hash": hex::encode(rp)},
        "pop_p": assertion(&phone, &digest, &Bend::default()),
        "signature": hex::encode(secp_sign(&v.k_e_intent, &digest)),
    });
    griefed("recover_begin_sweeping_three", h.relayer.call(h.undo.id(), "recover_begin").args_json(call).gas(gas(OWNER_ATTACH_TGAS)).transact().await?)?;
    let n = h.nonce_of(&v, "passkey_nonce").await?;
    h.passkey_call(&v, &v.passkey, "recover_cancel", &(), json!({}), n, expires_at).await?.into_result()?;

    // The rotation lands, the next queue dies, and `apply_grant` is what sweeps it.
    let known = h.vault_view(&v).await?["policy"]["t_known_ms"].as_u64().unwrap();
    let grant = newest_grant(&h.vault_view(&v).await?);
    h.advance_to(h.now_ms().await? + known + 1).await?;
    h.relayer.call(h.undo.id(), "apply_grant").args_json(json!({"vault": v.hex(), "grant": grant})).gas(gas(OWNER_ATTACH_TGAS)).transact().await?.into_result()?;
    v.k_s = ed25519_dalek::SigningKey::from_bytes(&test_key("landing-n1"));
    big_queue(&h, &mut v, "landing-b").await?;
    let (_, new) = rotate_at_owner_attach(&h, &v, "landing-n2").await?;
    let grant = newest_grant(&h.vault_view(&v).await?);
    h.advance_to(h.now_ms().await? + known + 1).await?;
    griefed("apply_grant_sweeping_three", h.relayer.call(h.undo.id(), "apply_grant").args_json(json!({"vault": v.hex(), "grant": grant})).gas(gas(OWNER_ATTACH_TGAS)).transact().await?)?;
    v.k_s = new;

    big_queue(&h, &mut v, "landing-c").await?;
    rotate_at_owner_attach(&h, &v, "landing-n3").await?.0.into_result()?;
    let until = h.now_ms().await? + 60_000;
    let n = h.nonce_of(&v, "cold_nonce").await?;
    griefed("freeze_sweeping_three", h.cold_call(&v, &v.k_e_intent, "freeze", &until, json!({"until": until}), n, expires_at).await?)?;
    Ok(())
}

/// The doc says 20 Tgas clears the largest `assess`. A thief can time two big requests to die just before the
/// guard calls, so `assess` is the call that sweeps them, on the largest answer it reads, with eight signers.
#[tokio::test]
async fn gas_of_assess_on_a_dead_queue() -> Result<()> {
    use ed25519_dalek::Signer as _;
    let h = Harness::new().await?;
    let guard = h.worker.dev_create_account().await?;
    let mut v = worst_row(&h, "assess", guard.id().as_str()).await?;
    let model_name = "Qwen/Qwen3.8-27B";
    for i in 0..7 {
        let decoy = ed25519_dalek::SigningKey::from_bytes(&test_key(&format!("decoy-{i}")));
        h.relayer.call(h.undo.id(), "add_model_signer").args_json(json!({"model": model_name, "signer": hex::encode(decoy.verifying_key().to_bytes())})).transact().await?.into_result()?;
    }
    let model = ed25519_dalek::SigningKey::from_bytes(&test_key("assess-model"));
    h.relayer.call(h.undo.id(), "add_model_signer").args_json(json!({"model": model_name, "signer": hex::encode(model.verifying_key().to_bytes())})).transact().await?.into_result()?;

    let vault = v.hex();
    let beat = || guard.call(h.undo.id(), "heartbeat").args_json(json!({"vault": vault})).gas(gas(10)).transact();
    h.advance_to(h.now_ms().await? + 301_000).await?;
    beat().await?.into_result()?;
    let own = v.spk.to_bytes();
    let t0 = h.now_ms().await?;
    let a = h.propose(&mut v, &coins("assess-a", 16, 1_000_000), &own, 16_000_000 - 2_000, None).await?;
    let b = h.propose(&mut v, &coins("assess-b", 8, 1_000_000), &p2wpkh("assess-thief"), 8_000_000 - 950, None).await?;
    let (ax, bx) = (h.request(&v, a).await?["expires_at"].as_u64().unwrap(), h.request(&v, b).await?["expires_at"].as_u64().unwrap());
    for minutes in [19, 38, 57] {
        h.advance_to(t0 + minutes * MINUTE_MS).await?;
        beat().await?.into_result()?;
    }
    // The real request goes in just before both die, and is still waiting when they have.
    h.advance_to(ax - 20_000).await?;
    let r = h.propose_simple(&mut v, &coins("assess-r", 1, 1_000_000)[0]).await?;
    h.advance_to(bx + 1).await?;

    let body: String = h.undo.view("guard_prompt").args_json(json!({"vault": v.hex(), "request": r})).await?.json()?;
    let content = serde_json::to_string(r#"{"hold":true,"reason":"memo_mismatch"}"#)?;
    let small = format!(r#"{{"id":"chatcmpl-1","object":"chat.completion","model":"{model_name}","choices":[{{"index":0,"message":{{"role":"assistant","content":{content}}},"finish_reason":"stop"}}],"usage":{{"prompt_tokens":318,"completion_tokens":15,"total_tokens":333}}}}"#);
    let padded = format!("{small}{}", " ".repeat(16_384 - small.len()));
    let text = format!("{model_name}:{}:{}", hex::encode(sha256(body.as_bytes())), hex::encode(sha256(padded.as_bytes())));
    let sig = model.sign(text.as_bytes()).to_bytes();
    let r = guard.call(h.undo.id(), "assess").args_json(json!({"vault": v.hex(), "request": r, "response_bytes": hex::encode(&padded), "signature": hex::encode(sig)})).gas(gas(ASSESS_ATTACH_TGAS)).transact().await?;
    let burnt = tgas(r.total_gas_burnt.as_gas());
    println!("MEASURE griefed assess_sweeping_two_16kb_eight_signers tx={burnt:.2}T");
    assert!(burnt < ASSESS_ATTACH_TGAS as f64);
    r.into_result()?;
    Ok(())
}
