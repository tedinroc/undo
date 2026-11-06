//! The fifth review, owner and spec lenses: attacks on the panic path, on an upgrade's bill, and on what
//! the contract says about itself. Real wasm, sandbox, mock signer. Where a test pins a limit that stays,
//! its comment says so and SPEC section 20 names it.

use anyhow::Result;
use ed25519_dalek::{Signer as _, SigningKey as EdKey};
use near_token::NearToken;
use near_workspaces::result::ExecutionFinalResult;
use sandbox_tests::*;
use serde_json::{json, Value};

const FAR: u64 = u64::MAX / 2;
const MODEL: &str = "Qwen/Qwen3.8-27B";
/// Yocto per byte, as the sandbox and both live networks read it.
const COST: u128 = 10_000_000_000_000_000_000;

fn ed(label: &str) -> EdKey {
    EdKey::from_bytes(&test_key(label))
}

fn p2wsh(label: &str) -> Vec<u8> {
    let mut s = vec![0x00, 0x20];
    s.extend_from_slice(&test_key(label));
    s
}

async fn pk_call<A: borsh::BorshSerialize>(h: &Harness, v: &Vault, method: &str, args: &A, call: Value) -> Result<ExecutionFinalResult> {
    let nonce = h.nonce_of(v, "passkey_nonce").await?;
    h.passkey_call(v, &v.passkey, method, args, call, nonce, FAR).await
}

async fn cold<A: borsh::BorshSerialize>(h: &Harness, v: &Vault, method: &str, args: &A, call: Value) -> Result<ExecutionFinalResult> {
    let nonce = h.nonce_of(v, "cold_nonce").await?;
    h.cold_call(v, &v.k_e_intent, method, args, call, nonce, FAR).await
}

async fn apply(h: &Harness, v: &Vault, grant: u64) -> Result<ExecutionFinalResult> {
    Ok(h.relayer.call(h.undo.id(), "apply_grant").args_json(json!({"vault": v.hex(), "grant": grant})).gas(gas(50)).transact().await?)
}

async fn top_up(h: &Harness, v: &Vault, milli: u128) -> Result<()> {
    h.relayer.call(h.undo.id(), "deposit_storage").args_json(json!({"vault": v.hex()})).deposit(NearToken::from_millinear(milli)).transact().await?.into_result()?;
    Ok(())
}

async fn status(h: &Harness, v: &Vault) -> Result<(bool, String)> {
    let view: Value = h.undo.view("status").args_json(json!({"vault": v.hex()})).await?.json()?;
    let lines: Vec<String> = view["lines"].as_array().unwrap().iter().map(|l| l.as_str().unwrap().to_string()).collect();
    Ok((view["ok"].as_bool().unwrap(), lines.join("\n")))
}

async fn instance(h: &Harness) -> Result<Value> {
    Ok(h.undo.view("instance").args_json(json!({})).await?.json()?)
}

fn yocto(value: &Value) -> u128 {
    value.as_str().unwrap().parse().unwrap()
}

fn vault_of(h: &Harness, k: Keys, csv: u32) -> Vault {
    let id = h.vault_id(&k, csv);
    let k_m = h.mpc_key(&id);
    let script = witness_script(&compressed(&k.k_u), &compressed(&k_m), &compressed(&k.k_e_leaf), csv as i64);
    let spk = script.to_p2wsh();
    Vault { id, k_s: k.k_s, k_u: k.k_u, k_e_leaf: k.k_e_leaf, k_e_intent: k.k_e_intent, passkey: k.passkey, k_m, csv, script, spk, spend_nonce: 0, passkey_nonce: 0 }
}

async fn recover_finish(h: &Harness, v: &Vault) -> Result<()> {
    let ready = h.vault_view(v).await?["recovery_ready_at"].as_u64().unwrap();
    h.advance_to(ready + 1).await?;
    h.relayer.call(h.undo.id(), "recover_finish").args_json(json!({"vault": v.hex()})).gas(gas(30)).transact().await?.into_result()?;
    Ok(())
}

// ---------------------------------------------------------------- a dead domain

const BACKUP_ORIGIN: &str = "https://backup.example";
const BACKUP_RP: &str = "backup.example";

async fn recover_from(h: &Harness, v: &Vault, phone: &p256::ecdsa::SigningKey, bend: &Bend) -> Result<ExecutionFinalResult> {
    let rp = sha256(bend.rp_id.as_bytes());
    let args = (p256_compressed(phone), rp);
    let n = h.nonce_of(v, "cold_nonce").await?;
    let digest = intent_digest("undo-cold-v1", h.contract(), &v.id, "recover_begin", &args, FAR, Some(n));
    let call = json!({
        "new_passkey": {"pubkey": hex::encode(p256_compressed(phone)), "rp_id_hash": hex::encode(rp)},
        "pop_p": assertion(phone, &digest, bend),
    });
    h.cold_call(v, &v.k_e_intent, "recover_begin", &args, call, n, FAR).await
}

/// SPEC 1.5. A passkey is bound to its domain, so when the domain dies the way back runs through a second
/// origin named at `new`. A browser on it sends its own origin and rp id, and both must pass.
#[tokio::test]
async fn a_second_origin_named_at_new_recovers_a_dead_domain() -> Result<()> {
    let h = Harness::with(Options { origins: &[ORIGIN, BACKUP_ORIGIN], ..Options::default() }).await?;
    let mut v = h.create_vault("r4-domain").await?;
    let phone = p256::ecdsa::SigningKey::from_bytes((&test_key("r4-domain-phone")).into()).unwrap();
    let browser = Bend { origin: BACKUP_ORIGIN, rp_id: BACKUP_RP, ..Bend::default() };

    // A domain nobody named stays refused, on the same instance.
    let elsewhere = Bend { origin: "https://new.example", rp_id: "new.example", ..Bend::default() };
    assert_refused(&recover_from(&h, &v, &phone, &elsewhere).await?, "origin not allowed");

    recover_from(&h, &v, &phone, &browser).await?.into_result()?;
    recover_finish(&h, &v).await?;
    v.passkey = phone;
    assert!(status(&h, &v).await?.1.contains(&format!("passkeys work from {ORIGIN}, {BACKUP_ORIGIN}")));

    // The cancel button works again, with the phone's real assertion from the new domain.
    let id = h.propose_simple(&mut v, &coins("r4-domain", 1, 100_000)[0]).await?;
    h.cancel_bent(&v, id, FAR, &browser).await?.into_result()?;
    Ok(())
}

/// The limit that stays on an instance with one origin: nothing but an upgrade helps the passkey, and the
/// cold key can still stop things. `status` says so.
#[tokio::test]
async fn with_one_origin_a_dead_domain_leaves_the_cold_key() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r4-one").await?;
    let phone = p256::ecdsa::SigningKey::from_bytes((&test_key("r4-one-phone")).into()).unwrap();
    let browser = Bend { origin: "https://new.example", rp_id: "new.example", ..Bend::default() };
    assert_refused(&recover_from(&h, &v, &phone, &browser).await?, "origin not allowed");
    assert!(status(&h, &v).await?.1.contains("A passkey on any other domain needs an upgrade first"));

    let id = h.propose_simple(&mut v, &coins("r4-one", 1, 100_000)[0]).await?;
    let args = h.cold_cancel_args(&v, &v.k_e_intent, id);
    h.relayer.call(h.undo.id(), "cancel").args_json(args).gas(gas(30)).transact().await?.into_result()?;
    Ok(())
}

// ---------------------------------------------------------------- an upgrade's bill

/// Takes the contract's balance down to what vaults have paid in, plus a sliver, as it is once a deploy
/// buffer is used up.
async fn trim_the_buffer(h: &Harness) -> Result<()> {
    let a = h.undo.view_account().await?;
    let keep = a.storage_usage as u128 * COST + yocto(&instance(h).await?["vault_funds"]) + 2_000_000_000_000_000_000_000u128;
    let surplus = a.balance.as_yoctonear() - keep;
    h.undo.as_account().transfer_near(h.relayer.id(), NearToken::from_yoctonear(surplus)).await?.into_result()?;
    Ok(())
}

/// Code with a custom section of `pad` bytes, so it does the same and stores larger.
fn larger_code(pad: usize) -> Vec<u8> {
    let mut code = wasm("undo_vault");
    let body = 2 + pad;
    let mut leb = vec![];
    let mut n = body;
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n == 0 {
            leb.push(byte);
            break;
        }
        leb.push(byte | 0x80);
    }
    code.push(0);
    code.extend(leb);
    code.push(1);
    code.push(b'x');
    code.extend(std::iter::repeat_n(0u8, pad));
    code
}

async fn rotate_at_relay_gas(h: &Harness, v: &mut Vault, key: &[u8; 32]) -> Result<ExecutionFinalResult> {
    let digest = h.passkey_digest(v, "cancel_all_and_rotate", key, FAR, Some(v.passkey_nonce));
    let r = h.relayer.call(h.undo.id(), "cancel_all_and_rotate")
        .args_json(json!({"vault": v.hex(), "new_k_s": hex::encode(key), "nonce": v.passkey_nonce, "expires_at": FAR, "assertion": assertion(&v.passkey, &digest, &Bend::default())}))
        .gas(gas(30)).transact().await?;
    if r.is_success() {
        v.passkey_nonce += 1;
    }
    Ok(r)
}

/// New code's bytes come out of the contract's balance, and what vaults have paid in sits in that balance.
/// Larger code that would spend it stops the panic button with `LackBalanceForState`, so it is refused, the
/// approval stands, and a plain transfer from anyone lets it through.
#[tokio::test]
async fn an_upgrade_that_would_spend_what_vaults_paid_in_is_refused() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r4-up").await?;
    h.propose_simple(&mut v, &coins("r4-up", 1, 100_000)[0]).await?;
    trim_the_buffer(&h).await?;

    let view = instance(&h).await?;
    let free = yocto(&view["free_balance"]) / COST;
    assert!(free > 0 && free < 1_000, "the buffer is trimmed: {free} bytes free");
    assert!(status(&h, &v).await?.1.contains(&format!("{free} bytes free beyond what vaults have paid in")));
    let target = view["code_bytes"].as_u64().unwrap() as usize + free as usize + 500;
    let code = larger_code(target - wasm("undo_vault").len());

    let proposed = h.relayer.call(h.undo.id(), "upgrade_propose").args_json(json!({"code_hash": hex::encode(sha256(&code))})).transact().await?;
    // Near what the view said, not equal: each call's gas reward lands in the balance.
    let logged = proposed.logs().iter().find_map(|l| l.split("free_bytes=").nth(1)?.parse::<u128>().ok()).expect("the log names what is free");
    assert!(logged.abs_diff(free) < 100, "{logged} against {free}");
    proposed.into_result()?;
    h.advance_to(instance(&h).await?["pending_upgrade"]["unlock_at"].as_u64().unwrap()).await?;

    let refused = h.relayer.call(h.undo.id(), "upgrade_apply").args(code.clone()).gas(gas(300)).transact().await?;
    assert_refused(&refused, "the new code would spend what vaults have paid in");
    let after = instance(&h).await?;
    assert!(after["pending_upgrade"].is_object(), "a refusal here does not use up the approval");
    assert_eq!(after["code_bytes"], view["code_bytes"]);

    // The panic button still works, because nothing was spent.
    rotate_at_relay_gas(&h, &mut v, &test_key("r4-up-new")).await?.into_result()?;

    // Anyone can repair it.
    let funds = instance(&h).await?["vault_funds"].clone();
    h.relayer.transfer_near(h.undo.id(), NearToken::from_millinear(10)).await?.into_result()?;
    h.relayer.call(h.undo.id(), "upgrade_apply").args(code.clone()).gas(gas(300)).transact().await?.into_result()?;
    let landed = instance(&h).await?;
    assert_eq!(landed["code_bytes"], code.len() as u64, "migrate records the real size");
    assert!(landed["pending_upgrade"].is_null());
    assert_eq!(landed["vault_funds"], funds, "what vaults paid in is still theirs");
    rotate_at_relay_gas(&h, &mut v, &test_key("r4-up-newer")).await?.into_result()?;
    Ok(())
}

/// The check that holds when `upgrade_apply` could not see it: its size for the old code is an estimate.
/// Called straight as the contract itself, on a balance already short.
#[tokio::test]
async fn migrate_refuses_when_what_vaults_paid_in_is_gone() -> Result<()> {
    let h = Harness::new().await?;
    let v = h.create_vault("r4-mig").await?;
    let me = h.undo.as_account();
    me.call(h.undo.id(), "migrate").args_json(json!({"code_bytes": 7})).transact().await?.into_result()?;
    assert_eq!(instance(&h).await?["code_bytes"], 7);

    let a = h.undo.view_account().await?;
    let funds = yocto(&instance(&h).await?["vault_funds"]);
    let surplus = a.balance.as_yoctonear() - (a.storage_usage as u128 * COST + funds / 2);
    me.transfer_near(h.relayer.id(), NearToken::from_yoctonear(surplus)).await?.into_result()?;

    let (ok, text) = status(&h, &v).await?;
    assert!(!ok, "{text}");
    assert!(text.contains("yoctoNEAR short of what vaults have paid in"), "{text}");
    assert_eq!(instance(&h).await?["free_balance"], "0");
    assert_refused(&me.call(h.undo.id(), "migrate").args_json(json!({"code_bytes": 8})).transact().await?, "spends what vaults have paid in");
    assert_eq!(instance(&h).await?["code_bytes"], 7, "nothing landed");
    Ok(())
}

async fn paid_in(h: &Harness, v: &Vault) -> Result<u128> {
    let view = h.vault_view(v).await?;
    Ok(yocto(&view["storage_credit"]) + view["reserved_bytes"].as_u64().unwrap() as u128 * COST)
}

async fn funds_match(h: &Harness, vaults: &[&Vault], what: &str) -> Result<()> {
    let mut sum = 0;
    for v in vaults {
        sum += paid_in(h, v).await?;
    }
    assert_eq!(yocto(&instance(h).await?["vault_funds"]), sum, "{what}");
    Ok(())
}

/// The running total is worth nothing unless it follows every way a vault's money moves.
#[tokio::test]
async fn vault_funds_follows_every_vault() -> Result<()> {
    let h = Harness::new().await?;
    funds_match(&h, &[], "nothing yet").await?;
    let mut a = h.create_vault("r4-funds-a").await?;
    funds_match(&h, &[&a], "creation").await?;
    let mut b = h.create_vault("r4-funds-b").await?;
    funds_match(&h, &[&a, &b], "a second vault adds").await?;

    top_up(&h, &a, 3).await?;
    funds_match(&h, &[&a, &b], "a top-up").await?;

    let c = coins("r4-funds", 3, 100_000);
    let id = h.propose_simple(&mut a, &c[0]).await?;
    funds_match(&h, &[&a, &b], "a proposal").await?;
    h.wait_unlock(&a, id).await?;
    h.execute_and_respond(&a, id, 1, false).await?.into_result()?;
    funds_match(&h, &[&a, &b], "execute and the callback").await?;

    let id2 = h.propose_simple(&mut a, &c[1]).await?;
    h.cancel_passkey(&a, id2).await?.into_result()?;
    funds_match(&h, &[&a, &b], "a cancel").await?;

    let expiry = instance(&h).await?["expiry_window_ms"].as_u64().unwrap();
    h.advance_to(h.now_ms().await? + expiry + 1).await?;
    h.prune(&a, id).await?.into_result()?;
    funds_match(&h, &[&a, &b], "a prune").await?;

    h.propose_simple(&mut b, &c[2]).await?;
    rotate_at_relay_gas(&h, &mut b, &test_key("r4-funds-new")).await?.into_result()?;
    funds_match(&h, &[&a, &b], "a rotation").await?;

    // A refused vault takes its deposit home and leaves the total where it was.
    let k = keys("r4-funds-refused");
    let mut call = h.create_call(&k, 6);
    call.k_m = compressed(&secp("r4-funds-not-km"));
    let args = h.create_args(&k, &call).await?;
    h.create_raw(args, 100).await?.into_result()?;
    funds_match(&h, &[&a, &b], "a refused vault").await?;
    Ok(())
}

// ---------------------------------------------------------------- what status says

/// The thief executes, the owner taps a beat later, and the signature lands anyway. Neither `status` nor the
/// page's rule may read that as stopped.
#[tokio::test]
async fn a_rotation_after_execute_does_not_read_as_cancelled() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r4-late").await?;
    let c = coins("r4-late", 1, 100_000);
    let id = h.propose(&mut v, &c[..1], &p2wpkh("r4-thief"), 99_000, None).await?;
    h.wait_unlock(&v, id).await?;
    let call = h.execute_call(&v, id, None);
    let task = tokio::spawn(async move { call.transact().await });
    let queued = h.wait_pending(1).await?;

    h.rotate(&mut v, &ed("r4-late-new").verifying_key().to_bytes()).await?;
    let (ok, text) = status(&h, &v).await?;
    assert!(!ok);
    assert!(text.contains("requests not yet executed are dead, one already executed keeps signing"), "{text}");
    assert!(!text.contains("every older request is dead"), "{text}");
    assert!(text.contains("before the spend key was rotated"), "{text}");
    assert_eq!(h.request(&v, id).await?["status"], "Signing");
    assert!(!h.reads_cancelled(&v, id).await?, "the epochs differ, and it is past stopping");

    h.respond_one(&queued[0], false).await?.into_result()?;
    let _ = task.await?;
    assert_eq!(h.request(&v, id).await?["status"], "Signed");
    h.verified_final_tx(&v, id, &c[..1]).await?;
    assert!(!h.reads_cancelled(&v, id).await?);
    assert!(status(&h, &v).await?.1.contains("before the spend key was rotated"));

    // A split execute is the same: a stranger signs the rest after the rotation.
    let mut v = h.create_vault("r4-split").await?;
    let c = coins("r4-split", 2, 100_000);
    let id = h.propose(&mut v, &c[..2], &p2wpkh("r4-t2"), 199_000, None).await?;
    h.wait_unlock(&v, id).await?;
    h.execute_with(h.execute_call(&v, id, Some(1)), 1, false).await?.into_result()?;
    h.rotate(&mut v, &ed("r4-split-new").verifying_key().to_bytes()).await?;
    assert!(!h.reads_cancelled(&v, id).await?);
    assert!(status(&h, &v).await?.1.contains("one already executed keeps signing"));
    h.execute_with(h.execute_call(&v, id, None), 1, false).await?.into_result()?;
    assert_eq!(h.request(&v, id).await?["status"], "Signed");
    Ok(())
}

/// After a veto, a freeze or a recovery there is no new key coming. `status` must not tell the owner to wait.
#[tokio::test]
async fn status_says_when_no_new_key_is_coming() -> Result<()> {
    let h = Harness::new().await?;
    for (label, how) in [("r4-st-veto", "veto"), ("r4-st-freeze", "freeze"), ("r4-st-recover", "recover")] {
        let mut v = h.create_vault(label).await?;
        let grant = h.rotate(&mut v, &test_key(&format!("{label}-n"))).await?;
        assert!(status(&h, &v).await?.1.contains("a new key lands after its wait"));
        match how {
            "veto" => cold(&h, &v, "veto_grant", &grant, json!({"grant": grant})).await?.into_result()?,
            "freeze" => {
                let until = h.now_ms().await? + 2_000;
                let r = cold(&h, &v, "freeze", &until, json!({"until": until})).await?.into_result()?;
                h.advance_to(until + 1).await?;
                r
            }
            _ => {
                let phone = p256::ecdsa::SigningKey::from_bytes((&test_key(&format!("{label}-p"))).into()).unwrap();
                let r = h.recover_begin_with(&v, &v.k_e_intent, &phone, &phone, 0, FAR).await?.into_result()?;
                recover_finish(&h, &v).await?;
                r
            }
        };
        let view = h.vault_view(&v).await?;
        assert_eq!((view["k_s_suspended"].as_bool(), view["grants"].as_array().map(Vec::len)), (Some(true), Some(0)));
        let text = status(&h, &v).await?.1;
        assert!(text.contains("no new key is waiting, so the passkey has to rotate again"), "{how}: {text}");
        assert!(!text.contains("a new key lands after its wait"), "{how}: {text}");
        assert_refused(&apply(&h, &v, grant).await?, "GrantNotFound");
    }
    Ok(())
}

/// A vault with a guard reads `funds movable` only when a proposal could go through.
#[tokio::test]
async fn status_says_funds_movable_only_when_they_are() -> Result<()> {
    let h = Harness::new().await?;
    let guard = h.worker.dev_create_account().await?;
    let k = keys("r4-mov");
    let mut call = h.create_call(&k, 6);
    call.guard = Some(guard.id().to_string());
    let args = h.create_args(&k, &call).await?;
    h.create_raw(args, call.deposit_milli).await?.into_result()?;
    let mut v = vault_of(&h, k, 6);
    assert!(status(&h, &v).await?.1.contains("delay doubled, funds movable"));
    h.rotate(&mut v, &ed("r4-mov-new").verifying_key().to_bytes()).await?;
    let until = h.now_ms().await? + 60_000;
    cold(&h, &v, "freeze", &until, json!({"until": until})).await?.into_result()?;
    let text = status(&h, &v).await?.1;
    assert!(text.contains("frozen until") && text.contains("delay doubled") && !text.contains("funds movable"), "{text}");
    Ok(())
}

/// The budget line, the view it rests on, and the refusal it warns about.
#[tokio::test]
async fn status_warns_before_the_budget_refuses_a_spend() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r4-budget").await?;
    let fake = coins("r4-bfake", 5, 100_000);
    for chunk in fake.chunks(3) {
        let mut ids = vec![];
        for coin in chunk {
            ids.push(h.propose(&mut v, std::slice::from_ref(coin), &p2wpkh("r4-b"), 99_100, None).await?);
        }
        for id in ids {
            h.wait_unlock(&v, id).await?;
            h.execute_and_respond(&v, id, 1, false).await?.into_result()?;
        }
    }
    assert_eq!(h.vault_view(&v).await?["fee_used_24h"], 4_500, "the view reads the window");
    let real = coins("r4-breal", 1, 1_000_000);
    let id = h.propose(&mut v, &real, &p2wpkh("r4-new-vault"), 999_000, None).await?;
    h.wait_unlock(&v, id).await?;
    let (ok, text) = status(&h, &v).await?;
    assert!(!ok && text.contains("24 h fee budget used, 4500 of 5000 sats: a fee above 500 sats waits"), "{text}");
    assert_refused(&h.execute_call(&v, id, None).transact().await?, "FeeBudgetExceeded");
    Ok(())
}

/// With nothing left to retry and a healthy signer, the line must not say retry is open.
#[tokio::test]
async fn the_signer_line_promises_no_retry() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r4-stale-sign").await?;
    let c = coins("r4-stale-sign", 1, 100_000);
    let id = h.propose_simple(&mut v, &c[0]).await?;
    h.wait_unlock(&v, id).await?;
    h.mock.call("set_mode").args_json(json!({"mode": "Garbage"})).transact().await?.into_result()?;
    let _ = h.execute_call(&v, id, None).transact().await?;
    h.mock.call("set_mode").args_json(json!({"mode": "Yield"})).transact().await?.into_result()?;
    let stuck = h.vault_view(&v).await?["policy"]["t_stuck_ms"].as_u64().unwrap();
    h.advance_to(h.now_ms().await? + stuck + 1).await?;
    let new = h.reclaim(&mut v, &c[0], 500).await?;
    h.cancel_passkey(&v, new).await?.into_result()?;
    assert!(h.request(&v, id).await?.is_null());
    let text = status(&h, &v).await?.1;
    assert!(text.contains("the signer's last answer failed at"), "{text}");
    assert!(text.contains("a request still signing can retry"), "{text}");
    assert!(!text.contains("retry is open") && !text.contains("signing unavailable"), "{text}");
    Ok(())
}

/// The credit line's two figures come from a proposal's real bill, read here from its refusal.
#[tokio::test]
async fn the_credit_line_matches_what_a_proposal_costs() -> Result<()> {
    let h = Harness::new().await?;
    let near = |y: u128| y as f64 / 1e24;
    let v = h.create_vault_no_credit("r4-credit", 6).await?;
    let (ok, text) = status(&h, &v).await?;
    assert!(!ok, "no credit: {text}");
    assert!(text.contains("storage credit low, 0.000 NEAR: a one-input proposal takes about 0.006 and a 16-input one about 0.057"), "{text}");

    let needed = |r: &ExecutionFinalResult| yocto_after(&err_text(r), "need ");
    let one = coins("r4-credit-1", 1, 100_000);
    let refused = h.propose_raw(h.propose_args(&v, &one, &p2wpkh("d"), 99_000, None, 0)).await?;
    let need_one = needed(&refused);
    assert!((0.006..0.007).contains(&near(need_one)), "one input needs {}", near(need_one));
    let big = coins("r4-credit-16", 16, 100_000);
    let to = v.spk.to_bytes();
    let refused = h.propose_raw(h.propose_args(&v, &big, &to, 1_598_000, None, 0)).await?;
    let need_big = needed(&refused);
    assert!((0.054..0.060).contains(&near(need_big)), "16 inputs need {}", near(need_big));

    // Between the two a line says so, and nothing calls for attention: a small proposal still lands.
    top_up(&h, &v, 11).await?;
    let (ok, text) = status(&h, &v).await?;
    assert!(ok, "{text}");
    assert!(text.contains("storage credit 0.011 NEAR"), "{text}");
    assert_refused(&h.propose_raw(h.propose_args(&v, &big, &to, 1_598_000, None, 0)).await?, "storage credit short");
    h.propose_raw(h.propose_args(&v, &one, &p2wpkh("d"), 99_000, None, 0)).await?.into_result()?;
    Ok(())
}

#[tokio::test]
async fn check_propose_refuses_a_suspended_key() -> Result<()> {
    let h = Harness::new().await?;
    let v = h.create_vault("r4-check").await?;
    let c = coins("r4-check", 1, 100_000);
    let to = p2wpkh("r4-ct");
    let ask = || h.undo.view("check_propose").args_json(json!({"vault": v.hex(), "inputs": coins_json(&c), "to": hex::encode(&to), "amount": 99_000u64, "change": null}));
    assert_eq!(ask().await?.json::<Value>()?["tier"], "New");
    pk_call(&h, &v, "cancel_all_and_rotate", &test_key("r4-check-new"), json!({"new_k_s": hex::encode(test_key("r4-check-new"))})).await?.into_result()?;
    let refused = ask().await;
    assert!(format!("{refused:?}").contains("SpendKeySuspended"), "{refused:?}");
    Ok(())
}

// ---------------------------------------------------------------- the film's cancel

/// SPEC 6 counts passkeys that completed a cancel, and the page's Cancel is this method. It writes the count
/// from what the row reserved, so it needs no credit, and the model's snapshot sees it.
#[tokio::test]
async fn the_films_cancel_counts_and_the_model_can_read_it() -> Result<()> {
    let h = Harness::new().await?;
    let stats = || async { h.undo.view("stats").args_json(json!({})).await?.json::<Value>() };

    // Nothing stopped, nothing counted.
    let mut idle = h.create_vault("r4-count-idle").await?;
    h.rotate(&mut idle, &test_key("r4-count-idle-new")).await?;
    assert_eq!(stats().await?["passkeys_completed"], 0);

    let mut v = h.create_vault_no_credit("r4-count", 6).await?;
    let c = coins("r4-count", 2, 100_000);
    let args = h.propose_args(&v, &c[..1], &p2wpkh("destination"), 99_000, None, 0);
    let refused = h.propose_raw(args.clone()).await?;
    h.relayer.call(h.undo.id(), "deposit_storage").args_json(json!({"vault": v.hex()})).deposit(NearToken::from_yoctonear(yocto_after(&err_text(&refused), "need "))).transact().await?.into_result()?;
    let r = h.propose_raw(args).await?;
    r.clone().into_result()?;
    v.spend_nonce += 1;
    assert_eq!(h.credit(&v).await?, 0, "the credit is spent");

    let new = ed("r4-count-new");
    let key = new.verifying_key().to_bytes();
    let rotated = rotate_at_relay_gas(&h, &mut v, &key).await?;
    assert!(rotated.logs().iter().all(|l| !l.contains("credit_short")), "{:?}", rotated.logs());
    let grant = rotated.into_result()?.json::<u64>()?;
    let s = stats().await?;
    assert_eq!((s["passkeys_completed"].as_u64(), s["counted"].as_u64()), (Some(1), Some(1)));

    // The same vault pressing again on a dead queue counts nothing new.
    let again = rotate_at_relay_gas(&h, &mut v, &key).await?;
    assert_eq!(again.into_result()?.json::<u64>()? , grant + 1);
    assert_eq!(stats().await?["passkeys_completed"], 1);

    let known = h.vault_view(&v).await?["policy"]["t_known_ms"].as_u64().unwrap();
    h.advance_to(h.now_ms().await? + known + 1).await?;
    apply(&h, &v, grant + 1).await?.into_result()?;
    v.k_s = new;
    top_up(&h, &v, 50).await?;
    let next = h.propose_simple(&mut v, &c[1]).await?;
    assert_eq!(h.request(&v, next).await?["snapshot"]["cancels_30d"], 1);
    Ok(())
}

// ---------------------------------------------------------------- the copy's sentence

/// DEMO-FIRST says the wait is set per vault. It is, within the instance's range.
#[tokio::test]
async fn a_test_coin_vault_can_set_its_own_wait() -> Result<()> {
    let h = Harness::new().await?;
    let base = h.deployed_policy().await?;
    let mut chosen = base;
    (chosen[0], chosen[1], chosen[2]) = (30_000, 60_000, 120_000);
    let k = keys("r4-wait");
    let mut call = h.create_call(&k, 6);
    call.policy = Some(chosen);
    let args = h.create_args(&k, &call).await?;
    h.create_raw(args, call.deposit_milli).await?.into_result()?;
    let mut v = vault_of(&h, k, 6);
    let policy = h.vault_view(&v).await?["policy"].clone();
    assert_eq!((policy["t_known_ms"].as_u64(), policy["t_new_ms"].as_u64(), policy["t_new_unguarded_ms"].as_u64()), (Some(30_000), Some(60_000), Some(120_000)));

    // The request really waits what this vault set: no guard here, so the unguarded figure.
    let id = h.propose(&mut v, &coins("r4-wait", 1, 100_000), &p2wpkh("r4-w"), 99_000, None).await?;
    let r = h.request(&v, id).await?;
    assert_eq!(r["base_unlock"].as_u64().unwrap() - r["proposed_at"].as_u64().unwrap(), 120_000);

    // One millisecond outside the range at either end is refused.
    for (field, value) in [(0usize, 29_999), (0, base[0] + 1), (1, 59_999), (1, base[1] + 1), (2, 59_999), (2, base[2] + 1), (3, base[3] - 1), (4, base[4] - 1)] {
        let k = keys(&format!("r4-wait-{field}-{value}"));
        let mut call = h.create_call(&k, 6);
        let mut p = base;
        (p[0], p[1]) = (30_000, 60_000);
        p[field] = value;
        call.policy = Some(p);
        let args = h.create_args(&k, &call).await?;
        assert_refused(&h.create_raw(args, call.deposit_milli).await?, "PolicyOutOfBounds");
    }
    assert_eq!(instance(&h).await?["reaction_window_ms"], 34 * MINUTE_MS, "the maxima did not move");
    Ok(())
}

// ---------------------------------------------------------------- the freeze tool's clock

/// `tools/freeze.mjs` signs offline. Its clock ahead of the chain, or a slow relay, must not cost another
/// signature in a crisis: a later `until` is cut to the CSV period from when it lands.
#[tokio::test]
async fn a_late_or_long_freeze_lands_and_is_cut_to_the_csv_period() -> Result<()> {
    let h = Harness::new().await?;
    let v = h.create_vault("r4-skew").await?;
    let csv_ms = 6 * 30_000u64;
    for skew in [5_000u64, 30_000, 120_000, 365 * 24 * 60 * MINUTE_MS] {
        let until = h.now_ms().await? + skew + csv_ms;
        let r = cold(&h, &v, "freeze", &until, json!({"until": until})).await?;
        let log = r.logs().iter().find(|l| l.contains("undo:frozen")).map(|l| l.to_string()).unwrap();
        r.into_result()?;
        let landed = h.vault_view(&v).await?["frozen_until"].as_u64().unwrap();
        assert!(landed <= h.now_ms().await? + csv_ms && landed < until, "skew {skew}: {landed}");
        assert_eq!(log, format!("undo:frozen until={landed}"), "the log says what landed");
        let unfrozen = cold(&h, &v, "unfreeze", &(), json!({})).await?;
        unfrozen.into_result()?;
    }
    // One that has already run out says so, and kills nothing.
    let until = h.now_ms().await? - 1;
    let before = h.vault_view(&v).await?["spend_epoch"].clone();
    assert_refused(&cold(&h, &v, "freeze", &until, json!({"until": until})).await?, "FreezeAlreadyOver");
    assert_eq!(h.vault_view(&v).await?["spend_epoch"], before);
    Ok(())
}

// ---------------------------------------------------------------- limits that stay

/// A spend-key thief who waits out `T_new` can spend a coin's only signature at a false value. A direct exit
/// then says busy, and `reclaim` takes the slot, one per `T_new`. The owner's short way, with the passkey:
/// reclaim then cancel, which refunds the slot and leaves the coin free, then whole-coin exits. SPEC 5 states
/// the reaction window per coin because of this.
#[tokio::test]
async fn poisoned_coins_leave_by_reclaim_then_cancel() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r4-poison").await?;
    top_up(&h, &v, 1_000).await?;
    let p = h.vault_view(&v).await?["policy"].clone();
    let (t_known, t_stuck) = (p["t_known_ms"].as_u64().unwrap(), p["t_stuck_ms"].as_u64().unwrap());
    let real = coins("r4-poison", 8, 1_000_000);
    let declared: Vec<Coin> = real.iter().map(|c| c.with_value(40_000)).collect();
    let a = h.propose(&mut v, &declared, &p2wpkh("r4-poison-thief"), 8 * 40_000 - 950, None).await?;
    h.wait_unlock(&v, a).await?;
    h.execute_and_respond(&v, a, 8, false).await?.into_result()?;
    let tx = h.final_tx(&v, a).await?.unwrap();
    assert!(consensus_verify(&tx, &spent_outputs(&real, &v.spk)).is_err(), "signed at a false value, useless on Bitcoin");

    let began = h.now_ms().await?;
    let new = ed("r4-poison-new");
    let grant = h.rotate(&mut v, &new.verifying_key().to_bytes()).await?;
    h.advance_to(began + t_known + 1).await?;
    apply(&h, &v, grant).await?.into_result()?;
    v.k_s = new;
    let out = p2wsh("r4-poison-out");
    assert_refused(&h.propose_raw(h.propose_args(&v, &real[..1], &out, 999_000, None, v.spend_nonce)).await?, "OutpointBusy");
    h.advance_to(began + t_stuck + 1).await?;

    // The slot allows one reclaim per T_new, and a cancel gives it back.
    let first = h.reclaim(&mut v, &real[0], 170).await?;
    assert_refused(&h.relayer.call(h.undo.id(), "reclaim").args_json(h.reclaim_args(&v, &real[1], 170, v.spend_nonce)).gas(gas(300)).transact().await?, "SelfSpendSlotUsed");
    h.cancel_passkey(&v, first).await?.into_result()?;
    for coin in &real[1..] {
        let id = h.reclaim(&mut v, coin, 170).await?;
        h.cancel_passkey(&v, id).await?.into_result()?;
    }
    for chunk in real.chunks(3) {
        let mut ids = vec![];
        for coin in chunk {
            ids.push(h.propose(&mut v, std::slice::from_ref(coin), &out, coin.value - 170, None).await?);
        }
        for id in &ids {
            h.wait_unlock(&v, *id).await?;
        }
        for (id, coin) in ids.iter().zip(chunk) {
            h.execute_and_respond(&v, *id, 1, false).await?.into_result()?;
            h.verified_final_tx(&v, *id, std::slice::from_ref(coin)).await?;
        }
    }
    println!("MEASURE poisoned eight coins out {} min after the owner reacted", (h.now_ms().await? - began) / MINUTE_MS);
    Ok(())
}

/// Pins a limit SPEC 1.3 states. A passkey thief tightens at once, within bounds. The cold key gets the owner
/// back within three tries, and the delays stay at the maxima until a loosening waits out the raised `T_new`.
/// No coin moves.
#[tokio::test]
async fn a_passkey_thief_leaves_the_mainnet_delays_at_their_maxima() -> Result<()> {
    let h = Harness::with(Options { preset: "MainnetProof", restrict_create: true, ..Options::default() }).await?;
    let mut v = h.create_vault("r4-tight").await?;
    let hour = 60 * MINUTE_MS;
    let policy = |p: [u64; 8]| json!({"policy": {"t_known_ms": p[0], "t_new_ms": p[1], "t_new_unguarded_ms": p[2], "hold_ms": p[3], "t_stuck_ms": p[4], "fee_cap_tx": p[5], "fee_budget_24h": p[6], "outflow_cap_24h": p[7]}});
    let tight = [hour, 24 * hour, 48 * hour, 24 * hour, 24 * hour, 500u64, 1_000u64, 0u64];
    let r = pk_call(&h, &v, "set_policy", &tight, policy(tight)).await?;
    assert_eq!(r.into_result()?.json::<Option<u64>>()?, None, "a tightening lands at once");

    let phone = p256::ecdsa::SigningKey::from_bytes((&test_key("r4-tight-phone")).into()).unwrap();
    let t0 = h.now_ms().await?;
    let mut n = 0;
    for _ in 0..2 {
        h.recover_begin_with(&v, &v.k_e_intent, &phone, &phone, n, FAR).await?.into_result()?;
        n += 1;
        let ready = h.vault_view(&v).await?["recovery_ready_at"].as_u64().unwrap();
        h.advance_to(ready - 60_000).await?;
        pk_call(&h, &v, "recover_cancel", &(), json!({})).await?.into_result()?;
    }
    h.recover_begin_with(&v, &v.k_e_intent, &phone, &phone, n, FAR).await?.into_result()?;
    recover_finish(&h, &v).await?;
    v.passkey = phone;
    assert!(h.now_ms().await? - t0 <= 3 * hour, "SPEC 1.3");

    let dest = p2wsh("r4-tight-new-vault");
    let coin = coins("r4-tight", 1, 1_000_000);
    let check: Value = h.undo.view("check_propose").args_json(json!({"vault": v.hex(), "inputs": coins_json(&coin), "to": hex::encode(&dest), "amount": 999_500, "change": null})).await?.json()?;
    assert_eq!(check["delay_ms"], 48 * hour, "what the owner has after recovery, against 20 min in the delay table");
    let deployed = [5 * MINUTE_MS, 10 * MINUTE_MS, 20 * MINUTE_MS, 20 * MINUTE_MS, hour, 1_000u64, 3_000u64, OUTFLOW_CAP];
    let r = pk_call(&h, &v, "set_policy", &deployed, policy(deployed)).await?;
    let grant = r.into_result()?.json::<Option<u64>>()?.unwrap();
    let list = h.vault_view(&v).await?["grant_list"].clone();
    let ready = list.as_array().unwrap().iter().find(|g| g["id"].as_u64() == Some(grant)).unwrap()["ready_at"].as_u64().unwrap();
    assert!(ready > h.now_ms().await? + 23 * hour, "the loosening waits the raised T_new");
    Ok(())
}

/// A limit the page has to handle. Creation proofs bind no sender, so a stranger can land a `create_vault`
/// first with the least deposit. The owner's own call then answers `vault exists` and keeps its deposit. A
/// top-up from anyone, then a beat, gives the vault the film expects.
#[tokio::test]
async fn a_stranger_can_land_someone_elses_create_vault_and_a_top_up_repairs_it() -> Result<()> {
    let h = Harness::new().await?;
    let guard = h.worker.dev_create_account().await?;
    let k = keys("r4-front");
    let mut call = h.create_call(&k, 6);
    call.guard = Some(guard.id().to_string());
    let args = h.create_args(&k, &call).await?;

    let griefer = h.worker.dev_create_account().await?;
    let short = griefer.call(h.undo.id(), "create_vault").args_json(args.clone()).deposit(NearToken::from_yoctonear(1)).gas(gas(300)).transact().await?;
    let least = yocto_after(&err_text(&short), "attach at least ");
    griefer.call(h.undo.id(), "create_vault").args_json(args.clone()).deposit(NearToken::from_yoctonear(least)).gas(gas(300)).transact().await?.into_result()?;

    assert_refused(&h.relayer.call(h.undo.id(), "create_vault").args_json(args).deposit(NearToken::from_millinear(100)).gas(gas(300)).transact().await?, "vault exists");
    let v = vault_of(&h, k, 6);
    assert_eq!(h.vault_view(&v).await?["storage_credit"], "0");
    assert_refused(&guard.call(h.undo.id(), "heartbeat").args_json(json!({"vault": v.hex()})).gas(gas(10)).transact().await?, "storage credit short");
    assert_eq!(h.undo.view("delay_now").args_json(json!({"vault": v.hex()})).await?.json::<u64>()?, 10 * MINUTE_MS);

    top_up(&h, &v, 100).await?;
    guard.call(h.undo.id(), "heartbeat").args_json(json!({"vault": v.hex()})).gas(gas(10)).transact().await?.into_result()?;
    assert_eq!(h.undo.view("delay_now").args_json(json!({"vault": v.hex()})).await?.json::<u64>()?, 5 * MINUTE_MS);
    Ok(())
}

/// A limit that stays, with its way out. A thief who guesses the owner's next self-paying transaction signs
/// its child first, and that parent can then never go out. One passkey cancel frees the coin, and a whole-coin
/// exit restarts nothing, so it needs no chain order.
#[tokio::test]
async fn a_pinned_child_blocks_one_exact_reclaim_and_cancel_is_the_way_out() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r4-child").await?;
    top_up(&h, &v, 1_000).await?;
    let real = coins("r4-child", 1, 1_000_000);
    let dest = p2wpkh("r4-child-thief");
    let declared = real[0].with_value(40_000);
    let id = h.propose(&mut v, std::slice::from_ref(&declared), &dest, 39_500, None).await?;
    h.wait_unlock(&v, id).await?;
    h.execute_and_respond(&v, id, 1, false).await?.into_result()?;

    let spk = v.spk.to_bytes();
    let parent = unsigned_tx(std::slice::from_ref(&real[0]), &spk, 1_000_000 - 200, None);
    let child = output_coin(&parent, 0);
    let c = h.propose(&mut v, std::slice::from_ref(&child), &dest, child.value - 500, None).await?;
    h.wait_unlock(&v, c).await?;
    h.execute_and_respond(&v, c, 1, false).await?.into_result()?;

    let new = ed("r4-child-new");
    let grant = h.rotate(&mut v, &new.verifying_key().to_bytes()).await?;
    let stuck = h.vault_view(&v).await?["policy"]["t_stuck_ms"].as_u64().unwrap();
    h.advance_to(h.now_ms().await? + stuck + 1).await?;
    apply(&h, &v, grant).await?.into_result()?;
    v.k_s = new;
    let reclaimed = h.reclaim(&mut v, &real[0], 200).await?;
    h.wait_unlock(&v, reclaimed).await?;
    assert_refused(&h.execute_call(&v, reclaimed, None).transact().await?, "ChainOutOfOrder");

    h.cancel_passkey(&v, reclaimed).await?.into_result()?;
    let exit = h.propose(&mut v, &real, &p2wsh("r4-child-out"), 999_800, None).await?;
    h.wait_unlock(&v, exit).await?;
    h.execute_and_respond(&v, exit, 1, false).await?.into_result()?;
    h.verified_final_tx(&v, exit, &real).await?;
    Ok(())
}

// ---------------------------------------------------------------- stated rules with no test

#[tokio::test]
async fn the_model_signer_list_holds_eight() -> Result<()> {
    let h = Harness::new().await?;
    let add = |i: u8| {
        let key = ed(&format!("r4-signer-{i}")).verifying_key().to_bytes();
        h.relayer.call(h.undo.id(), "add_model_signer").args_json(json!({"model": MODEL, "signer": hex::encode(key)})).transact()
    };
    for i in 0..8 {
        add(i).await?.into_result()?;
    }
    assert_refused(&add(8).await?, "too many model signers");
    Ok(())
}

#[tokio::test]
async fn the_excluded_list_holds_thirty_two() -> Result<()> {
    let h = Harness::new().await?;
    let exclude = |i: u8| h.relayer.call(h.undo.id(), "stats_exclude").args_json(json!({"passkey": hex::encode([i; 33])})).transact();
    for i in 0..32 {
        exclude(i).await?.into_result()?;
    }
    assert_refused(&exclude(32).await?, "too many excluded passkeys");
    Ok(())
}

/// The spec reads the first choice. A guard that could pick from several would choose its answer inside
/// what the model signed.
#[tokio::test]
async fn assess_reads_the_first_choice() -> Result<()> {
    let h = Harness::new().await?;
    let guard = h.worker.dev_create_account().await?;
    let model = ed("r4-choice-model");
    h.relayer.call(h.undo.id(), "add_model_signer").args_json(json!({"model": MODEL, "signer": hex::encode(model.verifying_key().to_bytes())})).transact().await?.into_result()?;
    let k = keys("r4-choice");
    let mut call = h.create_call(&k, 6);
    call.guard = Some(guard.id().to_string());
    let args = h.create_args(&k, &call).await?;
    h.create_raw(args, call.deposit_milli).await?.into_result()?;
    let mut v = vault_of(&h, k, 6);
    let id = h.propose_simple(&mut v, &coins("r4-choice", 1, 100_000)[0]).await?;

    let body: String = h.undo.view("guard_prompt").args_json(json!({"vault": v.hex(), "request": id})).await?.json()?;
    let content = |text: &str| serde_json::to_string(text).unwrap();
    let response = format!(
        r#"{{"choices":[{{"message":{{"content":{}}}}},{{"message":{{"content":{}}}}}]}}"#,
        content(r#"{"hold":false,"reason":"none"}"#),
        content(r#"{"hold":true,"reason":"other"}"#),
    );
    let text = format!("{MODEL}:{}:{}", hex::encode(sha256(body.as_bytes())), hex::encode(sha256(response.as_bytes())));
    let sig = model.sign(text.as_bytes()).to_bytes();
    guard.call(h.undo.id(), "assess").args_json(json!({"vault": v.hex(), "request": id, "response_bytes": hex::encode(&response), "signature": hex::encode(sig)})).gas(gas(30)).transact().await?.into_result()?;
    let r = h.request(&v, id).await?;
    assert_eq!((r["hold_active"].as_bool(), r["assess_reason"].as_str()), (Some(false), Some("none")));
    Ok(())
}

/// What a passkey assertion binds. The harness writes the same digest as the contract, so each of these has
/// to be a digest for something else: one passkey on two vaults, another contract's name, the cold key's tag,
/// another expiry. A rule dropped from both the contract and the harness shows up here and nowhere else.
#[tokio::test]
async fn a_passkey_assertion_binds_its_vault_contract_tag_and_expiry() -> Result<()> {
    let h = Harness::new().await?;
    let mut a = h.create_vault("r4-xv-a").await?;
    let mut kb = keys("r4-xv-b");
    kb.passkey = a.passkey.clone();
    let call = h.create_call(&kb, 6);
    let args = h.create_args(&kb, &call).await?;
    h.create_raw(args, call.deposit_milli).await?.into_result()?;
    let mut b = vault_of(&h, kb, 6);
    let ra = h.propose_simple(&mut a, &coins("r4-xv-ca", 1, 100_000)[0]).await?;
    let rb = h.propose_simple(&mut b, &coins("r4-xv-cb", 1, 100_000)[0]).await?;
    assert_eq!(ra, rb, "the same request number on both");

    let send = |digest: [u8; 32], expires_at: u64| {
        let auth = json!({"Passkey": assertion(&b.passkey, &digest, &Bend::default())});
        h.relayer.call(h.undo.id(), "cancel").args_json(json!({"vault": b.hex(), "request": rb, "expires_at": expires_at, "auth": auth})).gas(gas(30)).transact()
    };
    let for_a = h.passkey_digest(&a, "cancel", &ra, FAR, None);
    assert_refused(&send(for_a, FAR).await?, "webauthn: wrong challenge");
    let other_contract = intent_digest("undo-passkey-v1", "other.test", &b.id, "cancel", &rb, FAR, None);
    assert_refused(&send(other_contract, FAR).await?, "webauthn: wrong challenge");
    let cold_tag = intent_digest("undo-cold-v1", h.contract(), &b.id, "cancel", &rb, FAR, None);
    assert_refused(&send(cold_tag, FAR).await?, "webauthn: wrong challenge");
    let other_expiry = h.passkey_digest(&b, "cancel", &rb, FAR - 1, None);
    assert_refused(&send(other_expiry, FAR).await?, "webauthn: wrong challenge");

    // Control: the right one lands, so none of those failed for some other reason.
    send(h.passkey_digest(&b, "cancel", &rb, FAR, None), FAR).await?.into_result()?;
    Ok(())
}
