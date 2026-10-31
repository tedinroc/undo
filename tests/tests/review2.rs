//! Third review, against the real wasm in sandbox with the mock signer. Pre-signed chains of CSV
//! restarts, the reservation rules, and tests for mutants that survived the earlier files.

use anyhow::Result;
use near_token::NearToken;
use near_workspaces::result::ExecutionFinalResult;
use sandbox_tests::*;
use serde_json::{json, Value};

const FAR: u64 = u64::MAX / 2;
const BYTE: u128 = 10_000_000_000_000_000_000;

fn no_short(res: &ExecutionFinalResult) -> bool {
    res.logs().iter().all(|l| !l.contains("credit_short"))
}

// ---------------------------------------------------------------- the chain rule

async fn t_known(h: &Harness, v: &Vault) -> Result<u64> {
    Ok(h.vault_view(v).await?["policy"]["t_known_ms"].as_u64().unwrap())
}

async fn t_new(h: &Harness, v: &Vault) -> Result<u64> {
    Ok(h.vault_view(v).await?["policy"]["t_new_ms"].as_u64().unwrap())
}

/// Signs a whole-coin self-spend through the contract and returns the real transaction.
async fn self_spend(h: &Harness, v: &mut Vault, coin: &Coin, fee: u64) -> Result<(u64, bitcoin::Transaction)> {
    let own = v.spk.to_bytes();
    let id = h.propose(v, std::slice::from_ref(coin), &own, coin.value - fee, None).await?;
    h.wait_unlock(v, id).await?;
    h.execute_and_respond(v, id, 1, false).await?.into_result()?;
    let tx = h.verified_final_tx(v, id, std::slice::from_ref(coin)).await?;
    Ok((id, tx))
}

/// A real chain, each link spending the coin the last one pays back, with txids from rust-bitcoin
/// and every link valid to libbitcoinconsensus. The contract's own txid has to match, or it would
/// never recognise the coin as young. Each preset's tighter rule sets the pace.
async fn chain_walk(preset: &'static str, wait_ms: u64, spacing_ms: u64) -> Result<()> {
    let h = Harness::with(Options { preset, ..Options::default() }).await?;
    let mut v = h.create_vault(&format!("r2-chain-{preset}")).await?;
    let known = t_known(&h, &v).await?;
    let mut coin = coins(&format!("r2-chain-{preset}"), 1, 1_000_000)[0].clone();
    let mut last_propose = 0;
    for link in 0..3 {
        let before = h.now_ms().await?;
        let (_, tx) = self_spend(&h, &mut v, &coin, 500).await?;
        if link > 0 {
            assert!(before >= last_propose + spacing_ms - known, "this walk did not outrun the rules");
        }
        last_propose = before;
        let child = output_coin(&tx, 0);
        let view = h.outpoint(&v, &child).await?;
        let born = view["born_at"].as_u64().expect("the contract named the same coin rust-bitcoin did");
        assert_eq!(view["state"], "Free");
        assert_eq!(view["pinned_value"], Value::Null);

        let own = v.spk.to_bytes();
        let args = h.propose_args(&v, std::slice::from_ref(&child), &own, child.value - 500, None, v.spend_nonce);
        // Inside T_new the slot refuses, on either preset.
        assert_refused(&h.propose_raw(args).await?, "SelfSpendSlotUsed");

        // Past the slot, the chain wait refuses if it has not run out yet, and the free view agrees.
        h.advance_to(before + t_new(&h, &v).await? + 1).await?;
        let args = h.propose_args(&v, std::slice::from_ref(&child), &own, child.value - 500, None, v.spend_nonce);
        let now = h.now_ms().await?;
        if now + known < born + wait_ms {
            assert_refused(&h.propose_raw(args).await?, "ChainTooYoung");
            let check = h.undo.view("check_propose").args_json(json!({"vault": v.hex(), "inputs": coins_json(std::slice::from_ref(&child)), "to": hex::encode(&own), "amount": child.value - 500, "change": null})).await;
            assert!(format!("{check:?}").contains("ChainTooYoung"), "{check:?}");
            h.advance_to(born + wait_ms).await?;
        }
        coin = child;
    }
    println!("MEASURE chain wasm preset={preset} chain_wait_ms={wait_ms} spacing_ms={spacing_ms} links=3 all valid to consensus");
    Ok(())
}

#[tokio::test]
async fn chain_on_the_proof_vault_waits_for_the_chain_rule() -> Result<()> {
    chain_walk("MainnetProof", 45 * MINUTE_MS, 45 * MINUTE_MS).await
}

#[tokio::test]
async fn chain_on_test_coins_waits_for_the_slot() -> Result<()> {
    chain_walk("TestCoin", 135_000, 5 * MINUTE_MS).await
}

/// A spend's change is the vault's coin at index 1, and the destination at index 0 is not.
#[tokio::test]
async fn change_is_born_at_its_own_index_on_the_wasm() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r2-change").await?;
    let real = coins("r2-change", 1, 100_000);
    let to = p2wpkh("destination");
    let id = h.propose(&mut v, &real, &to, 50_000, Some(49_500)).await?;
    h.wait_unlock(&v, id).await?;
    h.execute_and_respond(&v, id, 1, false).await?.into_result()?;
    let tx = h.verified_final_tx(&v, id, &real).await?;
    assert!(h.outpoint(&v, &output_coin(&tx, 1)).await?["born_at"].is_u64());
    assert_eq!(h.outpoint(&v, &output_coin(&tx, 0)).await?["born_at"], Value::Null);
    Ok(())
}

/// The chain from the far end. The child is signed against a txid the thief worked out in advance,
/// so the contract has no birth time for it, and its parent then cannot go out.
#[tokio::test]
async fn a_chain_built_backwards_stops_at_its_parent_on_the_wasm() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r2-backwards").await?;
    let coin = coins("r2-backwards", 1, 1_000_000);
    let own = v.spk.to_bytes();
    let parent_tx = unsigned_tx(&coin, &own, 999_500, None);
    let predicted = output_coin(&parent_tx, 0);

    // Signing the child first works, because nothing says yet that this coin is the vault's own.
    let child = h.propose(&mut v, std::slice::from_ref(&predicted), &own, 999_000, None).await?;
    h.wait_unlock(&v, child).await?;
    h.execute_and_respond(&v, child, 1, false).await?.into_result()?;

    let wait = t_new(&h, &v).await?;
    h.advance_to(h.now_ms().await? + wait + 1).await?;
    let parent = h.propose(&mut v, &coin, &own, 999_500, None).await?;
    h.wait_unlock(&v, parent).await?;
    assert_refused(&h.execute_call(&v, parent, None).transact().await?, "ChainOutOfOrder");
    assert_eq!(h.status(&v, parent).await?, "Pending", "nothing was signed, and it can still be cancelled");
    let queued: Vec<Value> = h.mock.view("pending").args_json(json!({})).await?.json()?;
    assert!(queued.is_empty(), "the signer was never asked");
    h.cancel_passkey(&v, parent).await?.into_result()?;
    Ok(())
}

/// A reclaim is a restart too, so a young coin waits, after `T_stuck` and past it.
#[tokio::test]
async fn reclaim_of_a_young_coin_waits_on_the_wasm() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault_csv("r2-reclaim", 144).await?;
    let coin = coins("r2-reclaim", 1, 1_000_000);
    let (_, tx) = self_spend(&h, &mut v, &coin[0], 500).await?;
    let young = output_coin(&tx, 0);
    let born = h.outpoint(&v, &young).await?["born_at"].as_u64().unwrap();

    let out = h.propose_simple(&mut v, &young).await?;
    h.wait_unlock(&v, out).await?;
    h.execute_and_respond(&v, out, 1, false).await?.into_result()?;
    let stuck = h.vault_view(&v).await?["policy"]["t_stuck_ms"].as_u64().unwrap();
    h.advance_to(h.now_ms().await? + stuck + 1).await?;

    let wait = 144 * 30_000 * 3 / 4;
    assert!(h.now_ms().await? < born + wait);
    let args = h.reclaim_args(&v, &young, 500, v.spend_nonce);
    let res = h.relayer.call(h.undo.id(), "reclaim").args_json(args).gas(gas(100)).transact().await?;
    assert_refused(&res, "ChainTooYoung");
    h.advance_to(born + wait).await?;
    h.reclaim(&mut v, &young, 500).await?;
    Ok(())
}

// ---------------------------------------------------------------- the reservation rules

/// Every yocto paid in is either in the credit or paying for bytes held or reserved. If the contract
/// ever pays, the credit cannot go below zero and this sum comes up short.
async fn assert_books(h: &Harness, v: &Vault, base_usage: u64, paid: u128) -> Result<()> {
    let view = h.vault_view(v).await?;
    let held = h.undo.view_account().await?.storage_usage - base_usage;
    let reserved = view["reserved_bytes"].as_u64().unwrap();
    let credit: u128 = view["storage_credit"].as_str().unwrap().parse()?;
    assert_eq!(credit + (held + reserved) as u128 * BYTE, paid, "held {held}, reserved {reserved}, credit {credit}");
    Ok(())
}

/// What a vault costs to create, measured from the refusal the same way the helper does.
async fn created_cost(h: &Harness, v: &Vault, base_usage: u64) -> Result<u128> {
    let view = h.vault_view(v).await?;
    let held = h.undo.view_account().await?.storage_usage - base_usage;
    Ok((held + view["reserved_bytes"].as_u64().unwrap()) as u128 * BYTE)
}

/// The finding: `fee_override` grew a request by 8 bytes with the credit at zero, and the contract
/// paid for them. An exit must not need new credit, so those bytes are reserved at propose, and the
/// reservation has to come down when they are used.
#[tokio::test]
async fn raise_fee_cap_at_zero_credit_leaks_nothing() -> Result<()> {
    let h = Harness::new().await?;
    let base = h.undo.view_account().await?.storage_usage;
    let mut v = h.create_vault_no_credit("r2-override", 6).await?;
    let mut paid = created_cost(&h, &v, base).await?;
    let coin = coins("r2-override", 1, 100_000);
    let own = v.spk.to_bytes();
    let (id, need) = h.propose_exact(&mut v, &coin, &own, 98_000, None).await?;
    paid += need;
    assert_eq!(h.credit(&v).await?, 0);
    assert_books(&h, &v, base, paid).await?;
    let reserved = h.vault_view(&v).await?["reserved_bytes"].as_u64().unwrap();

    let nonce = v.passkey_nonce;
    let res = h.passkey_call(&v, &v.passkey, "raise_fee_cap", &(id, 2_000u64), json!({"request": id, "cap": 2_000}), nonce, FAR).await?;
    assert!(no_short(&res), "those bytes were reserved: {:?}", res.logs());
    res.into_result()?;
    v.passkey_nonce += 1;
    assert_eq!(h.credit(&v).await?, 0, "and they cost nothing new");
    assert_eq!(h.vault_view(&v).await?["reserved_bytes"].as_u64().unwrap(), reserved - 8, "the reservation came down");
    assert_books(&h, &v, base, paid).await?;

    // A second raise changes nothing in size.
    let nonce = v.passkey_nonce;
    let res = h.passkey_call(&v, &v.passkey, "raise_fee_cap", &(id, 3_000u64), json!({"request": id, "cap": 3_000}), nonce, FAR).await?;
    assert!(no_short(&res), "{:?}", res.logs());
    res.into_result()?;
    assert_eq!(h.credit(&v).await?, 0);
    assert_books(&h, &v, base, paid).await?;

    h.wait_unlock(&v, id).await?;
    let res = h.execute_and_respond(&v, id, 1, false).await?;
    assert!(no_short(&res), "{:?}", res.logs());
    res.into_result()?;
    assert_eq!(h.status(&v, id).await?, "Signed");
    assert_books(&h, &v, base, paid).await?;
    // Only the in-flight entry, the pending entry and the slot's holder were more than the growth.
    assert_eq!(h.credit(&v).await?, (8 + 8 + 8) as u128 * BYTE, "the reservation was exact");
    Ok(())
}

/// Execute, a partial answer, a failed answer, a retry and the last signature, with the credit at
/// zero from propose on. Nothing may ask for credit, and what comes back at the end must be exactly
/// the bytes that were only ever transient. A reservation constant too small shows as `credit_short`,
/// and one too large shows in the last line.
#[tokio::test]
async fn a_request_lives_on_its_reservation_and_the_reservation_is_exact() -> Result<()> {
    let h = Harness::new().await?;
    let base = h.undo.view_account().await?.storage_usage;
    let mut v = h.create_vault_no_credit("r2-life", 6).await?;
    let mut paid = created_cost(&h, &v, base).await?;
    let idle = h.vault_view(&v).await?["reserved_bytes"].as_u64().unwrap();
    let real = coins("r2-life", 2, 100_000);
    let own = v.spk.to_bytes();
    // Two inputs, and both outputs pay back to the vault, so two coins are born.
    let (id, need) = h.propose_exact(&mut v, &real, &own, 100_000, Some(99_000)).await?;
    paid += need;
    assert_eq!(h.credit(&v).await?, 0);
    h.wait_unlock(&v, id).await?;

    let res = h.execute_with(h.execute_call(&v, id, Some(1)), 1, false).await?;
    assert!(no_short(&res), "first execute and answer: {:?}", res.logs());
    res.into_result()?;
    assert_eq!(h.status(&v, id).await?, "Signing");
    assert_books(&h, &v, base, paid).await?;
    // What the next steps need stays reserved, because a spend key could use up anything freed. Only
    // this comes free: the pending entry, the slot's holder, the override, and one in-flight entry.
    assert_eq!(h.credit(&v).await?, (8 + 8 + 8 + 8) as u128 * BYTE, "the rest stays reserved");

    h.mock.call("set_mode").args_json(json!({"mode": "Garbage"})).transact().await?.into_result()?;
    let res = h.execute_call(&v, id, Some(1)).transact().await?;
    assert!(no_short(&res), "a failed answer: {:?}", res.logs());
    assert_eq!(h.request(&v, id).await?["in_flight"], 0);
    assert_books(&h, &v, base, paid).await?;
    assert_eq!(h.credit(&v).await?, (8 + 8 + 8 + 8) as u128 * BYTE, "a failed answer costs nothing");

    h.mock.call("set_mode").args_json(json!({"mode": "Yield"})).transact().await?.into_result()?;
    let res = h.execute_with(h.execute_call(&v, id, Some(1)), 1, false).await?;
    assert!(no_short(&res), "the retry and last answer: {:?}", res.logs());
    res.into_result()?;
    assert_eq!(h.status(&v, id).await?, "Signed");
    assert_books(&h, &v, base, paid).await?;
    h.verified_final_tx(&v, id, &real).await?;

    assert_eq!(h.vault_view(&v).await?["reserved_bytes"].as_u64().unwrap(), idle, "only the vault's own reservation is left");
    // Transient or unused: an in-flight entry per input, the pending entry, the slot's holder, and the
    // override nobody asked for.
    assert_eq!(h.credit(&v).await?, (2 * 8 + 8 + 8 + 8) as u128 * BYTE, "the reservation was exact");

    // A prune gives back the request and leaves the books right.
    let window = h.undo.view("instance").args_json(json!({})).await?.json::<Value>()?["expiry_window_ms"].as_u64().unwrap();
    h.advance_to(h.now_ms().await? + window + 1).await?;
    h.prune(&v, id).await?.into_result()?;
    assert_books(&h, &v, base, paid).await?;
    Ok(())
}

/// The panic button and every cold-key method, with the credit at zero. Each costs exactly nothing:
/// a constant too small asks for credit, and one too large would pay some back.
#[tokio::test]
async fn panic_button_and_cold_key_cost_exactly_nothing_at_zero_credit() -> Result<()> {
    let h = Harness::new().await?;
    let base = h.undo.view_account().await?.storage_usage;
    let v = h.create_vault_no_credit("r2-panic", 6).await?;
    let paid = created_cost(&h, &v, base).await?;
    let cold = v.k_e_intent.clone();
    let owner = p256::ecdsa::SigningKey::from_bytes((&test_key("r2-panic-new")).into()).unwrap();
    assert_eq!(h.credit(&v).await?, 0);

    macro_rules! step {
        ($what:literal, $res:expr) => {{
            let res = $res;
            assert!(no_short(&res), "{}: {:?}", $what, res.logs());
            res.into_result()?;
            assert_eq!(h.credit(&v).await?, 0, $what);
            assert_books(&h, &v, base, paid).await?;
        }};
    }
    let rotate = |key: [u8; 32], nonce: u64| {
        let (h, v) = (&h, &v);
        async move { h.passkey_call(v, &v.passkey, "cancel_all_and_rotate", &key, json!({"new_k_s": hex::encode(key)}), nonce, FAR).await }
    };

    step!("rotate", rotate(test_key("r2-k-1"), 0).await?);
    step!("rotate again, replacing the wait", rotate(test_key("r2-k-2"), 1).await?);
    let grant = h.vault_view(&v).await?["grants"][0].as_u64().unwrap();
    step!("veto", h.cold_call(&v, &cold, "veto_grant", &grant, json!({"grant": grant}), 0, FAR).await?);
    step!("rotate after a veto", rotate(test_key("r2-k-3"), 2).await?);
    let grant = h.vault_view(&v).await?["grants"][0].as_u64().unwrap();
    let wait = t_known(&h, &v).await?;
    h.advance_to(h.now_ms().await? + wait + 1).await?;
    step!("apply the rotation", h.relayer.call(h.undo.id(), "apply_grant").args_json(json!({"vault": v.hex(), "grant": grant})).transact().await?);

    let until = h.now_ms().await? + 60_000;
    step!("freeze", h.cold_call(&v, &cold, "freeze", &until, json!({"until": until}), 1, FAR).await?);
    let later = until + 1_000;
    step!("renew the freeze", h.cold_call(&v, &cold, "freeze", &later, json!({"until": later}), 2, FAR).await?);
    step!("unfreeze", h.cold_call(&v, &cold, "unfreeze", &(), json!({}), 3, FAR).await?);

    step!("recover_begin", h.recover_begin_with(&v, &cold, &owner, &owner, 4, FAR).await?);
    step!("recover_cancel", h.passkey_call(&v, &v.passkey, "recover_cancel", &(), json!({}), 3, FAR).await?);
    step!("recover_begin again", h.recover_begin_with(&v, &cold, &owner, &owner, 5, FAR).await?);
    let ready = h.vault_view(&v).await?["recovery_ready_at"].as_u64().unwrap();
    h.advance_to(ready + 1).await?;
    step!("recover_finish", h.relayer.call(h.undo.id(), "recover_finish").args_json(json!({"vault": v.hex()})).transact().await?);
    Ok(())
}

/// A reclaim grows state on a spend key's say-so, so it is refused when the credit cannot pay.
#[tokio::test]
async fn reclaim_is_refused_when_the_credit_cannot_pay() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault_no_credit("r2-reclaim-credit", 6).await?;
    let real = coins("r2-reclaim-credit", 1, 100_000);
    let to = p2wpkh("destination");
    let (id, _) = h.propose_exact(&mut v, &real, &to, 99_500, None).await?;
    h.wait_unlock(&v, id).await?;
    h.execute_and_respond(&v, id, 1, false).await?.into_result()?;
    let stuck = h.vault_view(&v).await?["policy"]["t_stuck_ms"].as_u64().unwrap();
    h.advance_to(h.now_ms().await? + stuck + 1).await?;

    let args = h.reclaim_args(&v, &real[0], 500, v.spend_nonce);
    let res = h.relayer.call(h.undo.id(), "reclaim").args_json(args).gas(gas(100)).transact().await?;
    assert_refused(&res, "storage credit short");
    assert_eq!(h.status(&v, id).await?, "Signed", "nothing was replaced");
    h.relayer.call(h.undo.id(), "deposit_storage").args_json(json!({"vault": v.hex()})).deposit(NearToken::from_millinear(10)).transact().await?.into_result()?;
    h.reclaim(&mut v, &real[0], 500).await?;
    Ok(())
}

// ---------------------------------------------------------------- creation

/// A relay holds proofs for one set of choices and tries to land another. Each field is bound.
#[tokio::test]
async fn creation_proofs_bind_every_choice() -> Result<()> {
    let h = Harness::new().await?;
    let k = keys("r2-bind");
    let call = h.create_call(&k, 6);
    let good = h.create_args(&k, &call).await?;
    let stranger = h.worker.dev_create_account().await?;
    let bent: [(&str, Value); 4] = [
        ("k_m", json!(hex::encode(compressed(&secp("r2-other-km"))))),
        ("expires_at", json!(FAR + 1)),
        ("guard", json!(stranger.id())),
        ("policy", json!({"t_known_ms": 60_000, "t_new_ms": 300_000, "t_new_unguarded_ms": 600_000, "hold_ms": 300_000, "t_stuck_ms": 600_000, "fee_cap_tx": 500, "fee_budget_24h": 5_000, "outflow_cap_24h": OUTFLOW_CAP})),
    ];
    for (field, value) in bent {
        let mut args = good.clone();
        args["args"][field] = value;
        assert_refused(&h.create_raw(args, 100).await?, "bad K_s");
    }
    let mut args = good.clone();
    args["args"]["passkey"]["rp_id_hash"] = json!(hex::encode(sha256(b"evil.example")));
    assert_refused(&h.create_raw(args, 100).await?, "bad K_s");
    let mut args = good.clone();
    args["args"]["csv"] = json!(7);
    assert_refused(&h.create_raw(args, 100).await?, "bad K_s");
    h.create_raw(good, 100).await?.into_result()?;
    Ok(())
}

/// What the proofs bind is also what the vault gets.
#[tokio::test]
async fn a_chosen_policy_and_guard_are_what_the_vault_keeps() -> Result<()> {
    let h = Harness::new().await?;
    let k = keys("r2-chosen");
    let mut call = h.create_call(&k, 6);
    let mut policy = h.deployed_policy().await?;
    policy[5] = 700;
    call.policy = Some(policy);
    let guard = h.worker.dev_create_account().await?;
    call.guard = Some(guard.id().to_string());
    let args = h.create_args(&k, &call).await?;
    h.create_raw(args, 100).await?.into_result()?;
    let view: Value = h.undo.view("vault").args_json(json!({"vault": hex::encode(h.vault_id(&k, 6))})).await?.json()?;
    assert_eq!(view["policy"]["fee_cap_tx"], 700);
    assert_eq!(view["guard"], guard.id().as_str());
    Ok(())
}

/// A wrong `K_m` is refused and everything comes back, down to the yocto.
#[tokio::test]
async fn a_refused_vault_returns_the_whole_deposit() -> Result<()> {
    let h = Harness::new().await?;
    let k = keys("r2-refund");
    let mut call = h.create_call(&k, 6);
    call.k_m = compressed(&secp("r2-attacker"));
    let args = h.create_args(&k, &call).await?;
    let res = h.create_raw(args, 100).await?;
    let line = res.logs().iter().find(|l| l.contains("undo:refused")).map(|l| l.to_string()).expect("a refused line");
    assert_eq!(yocto_after(&line, "refund="), NearToken::from_millinear(100).as_yoctonear(), "{line}");
    Ok(())
}

/// A vault is Inactive until the signer has answered, so nothing can propose in the same receipt.
#[tokio::test]
async fn an_inactive_vault_refuses_a_proposal() -> Result<()> {
    use near_workspaces::operations::Function;
    let h = Harness::new().await?;
    let k = keys("r2-inactive");
    let call = h.create_call(&k, 6);
    let create = h.create_args(&k, &call).await?;
    let id = h.vault_id(&k, 6);
    let k_m = h.mpc_key(&id);
    let script = witness_script(&compressed(&k.k_u), &compressed(&k_m), &compressed(&k.k_e_leaf), 6);
    let spk = script.to_p2wsh();
    let v = Vault { id, k_s: k.k_s, k_u: k.k_u, k_e_leaf: k.k_e_leaf, k_e_intent: k.k_e_intent, passkey: k.passkey, k_m, csv: 6, script, spk, spend_nonce: 0, passkey_nonce: 0 };
    let real = coins("r2-inactive", 1, 100_000);
    let propose = h.propose_args(&v, &real, &p2wpkh("destination"), 99_500, None, 0);
    let res = h
        .relayer
        .batch(h.undo.id())
        .call(Function::new("create_vault").args_json(create).deposit(NearToken::from_millinear(100)).gas(gas(150)))
        .call(Function::new("propose_btc").args_json(propose).gas(gas(150)))
        .transact()
        .await?;
    assert_refused(&res, "Inactive");
    Ok(())
}

/// Nobody else can initialise a fresh deployment, it cannot be initialised twice, and it refuses a
/// network it has no address format for.
#[tokio::test]
async fn only_the_account_itself_initialises_the_contract() -> Result<()> {
    let h = Harness::new().await?;
    let fresh = h.worker.dev_deploy(&wasm("undo_vault")).await?;
    let args = |network: &str| {
        json!({
            "preset": "TestCoin", "operator": h.relayer.id(), "restrict_create": false, "signer": h.mock.id(), "domain_id": 0,
            "sign_tgas": SIGN_TGAS, "callback_tgas": CALLBACK_TGAS, "derive_tgas": DERIVE_TGAS, "network": network, "origins": [ORIGIN], "outflow_cap_24h": OUTFLOW_CAP,
        })
    };
    let outsider = h.relayer.call(fresh.id(), "new").args_json(args("mutinynet")).transact().await?;
    assert!(outsider.is_failure(), "a stranger could have named its own signer");
    assert_refused(&fresh.call("new").args_json(args("no-such-net")).transact().await?, "unknown network");
    fresh.call("new").args_json(args("mutinynet")).transact().await?.into_result()?;
    assert!(fresh.call("new").args_json(args("mutinynet")).transact().await?.is_failure(), "no second init");
    Ok(())
}

// ---------------------------------------------------------------- execute and the signer

/// Too little gas is refused with a message and nothing changes, because a sign call with no callback
/// gas would lose its signature.
#[tokio::test]
async fn too_little_gas_is_refused_before_anything_changes() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r2-gas").await?;
    let real = coins("r2-gas", 1, 100_000);
    let id = h.propose_simple(&mut v, &real[0]).await?;
    h.wait_unlock(&v, id).await?;
    let res = h.relayer.call(h.undo.id(), "execute").args_json(json!({"vault": v.hex(), "request": id})).gas(gas(40)).transact().await?;
    assert_refused(&res, "attach at least 43 Tgas");
    assert_eq!(h.status(&v, id).await?, "Pending", "cancel is still open");
    assert_eq!(h.outpoint(&v, &real[0]).await?["pinned_value"], Value::Null);

    let k = keys("r2-gas-create");
    let call = h.create_call(&k, 6);
    let args = h.create_args(&k, &call).await?;
    let res = h.relayer.call(h.undo.id(), "create_vault").args_json(args).deposit(NearToken::from_millinear(100)).gas(gas(40)).transact().await?;
    assert_refused(&res, "attach at least 43 Tgas");
    Ok(())
}

/// The deposit cap is per sign, so a larger spend may carry a larger deposit, and the contract's own
/// balance pays only the 1 yocto the docs promise.
#[tokio::test]
async fn the_sign_deposit_is_split_across_inputs() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r2-deposit").await?;
    let real = coins("r2-deposit", 3, 100_000);
    let to = p2wpkh("destination");
    let id = h.propose(&mut v, &real, &to, 299_000, None).await?;
    h.wait_unlock(&v, id).await?;
    let call = |yocto: u128| h.relayer.call(h.undo.id(), "execute").args_json(json!({"vault": v.hex(), "request": id})).deposit(NearToken::from_yoctonear(yocto)).gas(gas(MAX_GAS_TGAS));
    let cent = NearToken::from_millinear(10).as_yoctonear();
    assert_refused(&call(3 * cent + 3).transact().await?, "deposit per sign above the cap");
    h.execute_with(call(3 * cent), 3, false).await?.into_result()?;
    assert_eq!(h.status(&v, id).await?, "Signed");
    Ok(())
}

/// Answers from a broken or hostile signer. None may panic the callback, which would strand the slot,
/// and none may store. The right answer still lands afterwards.
#[tokio::test]
async fn malformed_signer_answers_are_dropped_and_the_input_stays_retryable() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r2-answers").await?;
    let real = coins("r2-answers", 1, 100_000);
    let id = h.propose_simple(&mut v, &real[0]).await?;
    h.wait_unlock(&v, id).await?;
    let bends: [(&str, fn(&mut Value)); 5] = [
        ("wrong scheme", |r| r["scheme"] = json!("Ed25519")),
        ("short big_r", |r| r["big_r"]["affine_point"] = json!("02aa")),
        ("short s", |r| r["s"]["scalar"] = json!("aa")),
        ("wrong recovery id", |r| {
            let id = r["recovery_id"].as_u64().unwrap();
            r["recovery_id"] = json!(id ^ 1);
        }),
        ("recovery id out of range", |r| r["recovery_id"] = json!(9)),
    ];
    for (what, bend) in bends {
        let call = h.execute_call(&v, id, None);
        let task = tokio::spawn(async move { call.transact().await });
        let queued = h.wait_pending(1).await?;
        let tweak: [u8; 32] = hex::decode(queued[0]["tweak"].as_str().unwrap())?.try_into().unwrap();
        let payload: [u8; 32] = hex::decode(queued[0]["payload"]["Ecdsa"].as_str().unwrap())?.try_into().unwrap();
        let mut answer = node_response(&h.secret, &tweak, &payload, false);
        bend(&mut answer);
        h.relayer.call(h.mock.id(), "respond").args_json(json!({"request": queued[0], "response": answer})).gas(gas(100)).transact().await?.into_result()?;
        let _ = task.await??;
        let r = h.request(&v, id).await?;
        assert_eq!(r["sigs"][0], Value::Null, "{what} was stored");
        assert_eq!(r["in_flight"], 0, "{what} stranded the slot");
    }
    h.execute_and_respond(&v, id, 1, false).await?.into_result()?;
    h.verified_final_tx(&v, id, &real).await?;
    Ok(())
}

/// The callback, delivered oddly by the contract itself. It drops these without a panic.
#[tokio::test]
async fn on_signed_drops_what_it_cannot_place() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r2-odd").await?;
    let real = coins("r2-odd", 1, 100_000);
    let id = h.propose_simple(&mut v, &real[0]).await?;
    let digest = hex::encode(h.payloads(&v, id).await?[0]);
    let deliver = |vault: String, request: u64, input: u32| {
        h.undo.as_account().call(h.undo.id(), "on_signed").args_json(json!({"vault": vault, "request": request, "attempt": 0, "input": input, "payload": digest.clone()})).gas(gas(100)).transact()
    };
    let res = deliver(hex::encode([0u8; 32]), id, 0).await?;
    assert!(res.logs().iter().any(|l| l.contains("unknown_vault")), "{:?}", res.logs());
    res.into_result()?;
    let res = deliver(v.hex(), id, 99).await?;
    assert!(res.logs().iter().any(|l| l.contains("DroppedNotInFlight")), "{:?}", res.logs());
    res.into_result()?;
    let res = deliver(v.hex(), id + 7, 0).await?;
    assert!(res.logs().iter().any(|l| l.contains("DroppedUnknownRequest")), "{:?}", res.logs());
    res.into_result()?;
    assert_eq!(h.status(&v, id).await?, "Pending");
    Ok(())
}

// ---------------------------------------------------------------- views and small refusals

/// `check_propose` is the free way to learn what a proposal would meet. It must read the same ledger
/// the real call reads, and it says who is held.
#[tokio::test]
async fn the_free_views_read_the_same_state_the_calls_do() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r2-views").await?;
    let real = coins("r2-views", 2, 100_000);
    let to = p2wpkh("destination");
    let id = h.propose_simple(&mut v, &real[0]).await?;
    let check = h.undo.view("check_propose").args_json(json!({"vault": v.hex(), "inputs": coins_json(&real[..1]), "to": hex::encode(&to), "amount": 99_500, "change": null})).await;
    assert!(format!("{check:?}").contains("OutpointBusy"), "{check:?}");
    h.wait_unlock(&v, id).await?;
    h.execute_and_respond(&v, id, 1, false).await?.into_result()?;
    let check = h.undo.view("check_propose").args_json(json!({"vault": v.hex(), "inputs": coins_json(&real), "to": hex::encode(&to), "amount": 199_000, "change": null})).await;
    assert!(format!("{check:?}").contains("OutpointBusy"), "a spent coin stays out of the view too: {check:?}");

    // No guard here, so the unguarded delay is the delay.
    let delay: u64 = h.undo.view("delay_now").args_json(json!({"vault": v.hex()})).await?.json()?;
    assert_eq!(delay, 10 * MINUTE_MS);

    // An override needs a request still Pending, and a signed one says so.
    let nonce = v.passkey_nonce;
    let res = h.passkey_call(&v, &v.passkey, "raise_fee_cap", &(id, 1_000u64), json!({"request": id, "cap": 1_000}), nonce, FAR).await?;
    assert_refused(&res, "NotPending");
    Ok(())
}

/// WebAuthn input that is not even shaped right is refused with a reason, not a trap.
#[tokio::test]
async fn malformed_webauthn_is_refused_with_a_reason() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r2-webauthn").await?;
    let real = coins("r2-webauthn", 1, 100_000);
    let id = h.propose_simple(&mut v, &real[0]).await?;
    let digest = h.passkey_digest(&v, "cancel", &id, FAR, None);
    let send = |assert: Value| h.relayer.call(h.undo.id(), "cancel").args_json(json!({"vault": v.hex(), "request": id, "expires_at": FAR, "auth": {"Passkey": assert}})).gas(gas(100)).transact();

    let mut short = assertion(&v.passkey, &digest, &Bend::default());
    short["authenticator_data"] = json!(hex::encode([1u8; 36]));
    assert_refused(&send(short).await?, "short authenticator data");
    let mut bad = assertion(&v.passkey, &digest, &Bend::default());
    bad["client_data_json"] = json!(hex::encode(b"not json"));
    assert_refused(&send(bad).await?, "bad client data");
    assert_eq!(h.status(&v, id).await?, "Pending");
    Ok(())
}
