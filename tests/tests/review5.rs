//! Round 5, the authorization audit's contract findings, on the real wasm with the mock signer. Each
//! test here failed on the build before it. The first one runs the sandbox clock a little over a day:
//! under a minute on the nodes `scripts/protocol-check.sh` starts, and about 50 minutes on the sandbox
//! near-workspaces starts by itself.

use anyhow::Result;
use sandbox_tests::*;
use serde_json::{json, Value};

const FAR: u64 = u64::MAX / 2;
const DAY_MS: u64 = 24 * 60 * MINUTE_MS;

/// Moves the clock to at least `target` without overshooting it by more than a block: the sandbox's time
/// per block is measured, and each step covers at most nine tenths of what is left. `advance_to` gives
/// up short of a day, and a long jump would pass a request's expiry.
async fn approach(h: &Harness, target: u64) -> Result<u64> {
    let t1 = h.now_ms().await?;
    h.worker.fast_forward(20).await?;
    let per_block = ((h.now_ms().await? - t1) / 20).max(1);
    loop {
        let now = h.now_ms().await?;
        if now >= target {
            return Ok(now);
        }
        let left = target - now;
        let blocks = if left <= 3 * per_block { 1 } else { (left * 9 / 10 / per_block).clamp(1, 5_000) };
        h.worker.fast_forward(blocks).await?;
    }
}

/// The tier `check_propose` gives `amount` from this coin, at a fee of 1,000 sats.
async fn tier_of(h: &Harness, v: &Vault, coin: &Coin, to: &[u8], amount: u64) -> Result<String> {
    let coin = coin.with_value(amount + 1_000);
    let c: Value = h
        .undo
        .view("check_propose")
        .args_json(json!({"vault": v.hex(), "inputs": coins_json(std::slice::from_ref(&coin)), "to": hex::encode(to), "amount": amount, "change": null}))
        .await?
        .json()?;
    Ok(c["tier"].as_str().unwrap_or_default().to_string())
}

async fn status_lines(h: &Harness, vault: &str) -> Result<Vec<String>> {
    let view: Value = h.undo.view("status").args_json(json!({"vault": vault})).await?.json()?;
    Ok(view["lines"].as_array().unwrap().iter().map(|l| l.as_str().unwrap().to_string()).collect())
}

/// C1 on the proof preset, where a request lives a day past its unlock. Before the fix R1's reservation
/// left at propose + 24 h while R1 was still pending, and a second full cap read Known: two caps signed
/// five minutes apart. Now R1 holds its outflow while pending and for a day after it signs, and a half
/// signed request that pays out cannot take signatures a day after its first execute.
#[tokio::test]
async fn outflow_counts_until_a_day_after_signing_on_the_wasm() -> Result<()> {
    let h = Harness::with(Options { preset: "MainnetProof", restrict_create: true, ..Options::default() }).await?;
    let mut v = h.create_vault("r5-outflow").await?;
    let cap = h.vault_view(&v).await?["policy"]["outflow_cap_24h"].as_u64().unwrap();
    let dest = p2wpkh("r5-known");
    let n = h.nonce_of(&v, "passkey_nonce").await?;
    let grant: u64 = h.passkey_call(&v, &v.passkey, "add_destination", &dest, json!({"script": hex::encode(&dest)}), n, FAR).await?.into_result()?.json()?;
    let ready = h.vault_view(&v).await?["grant_list"][0]["ready_at"].as_u64().unwrap();
    approach(&h, ready + 1).await?;
    h.relayer.call(h.undo.id(), "apply_grant").args_json(json!({"vault": v.hex(), "grant": grant})).gas(gas(50)).transact().await?.into_result()?;

    // R3 first: two coins to an address the vault does not know, so New. Then R1 takes the rest of the
    // cap to the known destination.
    let small = coins("r5-small", 2, 20_000);
    let r3 = h.propose(&mut v, &small, &p2wpkh("r5-elsewhere"), 39_000, None).await?;
    assert_eq!(h.request(&v, r3).await?["tier"], "New");
    let big = coins("r5-big", 3, cap - 38_000);
    let r1 = h.propose(&mut v, &big[..1], &dest, cap - 39_000, None).await?;
    let first = h.request(&v, r1).await?;
    assert_eq!(first["tier"], "Known", "with R3 it is exactly the cap");
    let t0 = first["proposed_at"].as_u64().unwrap();
    let r1_expires = first["expires_at"].as_u64().unwrap();
    assert_eq!(tier_of(&h, &v, &big[1], &dest, 1_000).await?, "New", "control: the cap is used");

    // R3 takes one of its two signatures.
    h.wait_unlock(&v, r3).await?;
    h.execute_with(h.execute_call(&v, r3, Some(1)), 1, false).await?.into_result()?;
    let opened = h.request(&v, r3).await?["first_execute_at"].as_u64().unwrap();

    // A day after R1's propose, R1 is still pending, so a second full cap waits T_new.
    let landed = approach(&h, t0 + DAY_MS + 1).await?;
    assert!(landed < r1_expires, "inside R1's life: now {landed}, expires {r1_expires}");
    assert_eq!(h.status(&v, r1).await?, "Pending");
    assert_eq!(tier_of(&h, &v, &big[1], &dest, cap - 39_000).await?, "New", "R1's reservation stands");
    let r2 = h.propose(&mut v, &big[1..2], &dest, cap - 39_000, None).await?;
    assert_eq!(h.request(&v, r2).await?["tier"], "New");
    h.cancel_passkey(&v, r2).await?.into_result()?;

    // R1 signs at the end of its life. Its outflow counts from there, R3's from its execute.
    h.execute_and_respond(&v, r1, 1, false).await?.into_result()?;
    let signed = h.now_ms().await?;
    h.verified_final_tx(&v, r1, &big[..1]).await?;
    assert_eq!(tier_of(&h, &v, &big[1], &dest, 1_000).await?, "New");

    // R3 cannot take its second signature a day after its first execute.
    approach(&h, opened + DAY_MS).await?;
    let retry = h.execute_call(&v, r3, Some(1)).transact().await?;
    assert_refused(&retry, "RetryWindowClosed");
    assert_eq!(h.status(&v, r3).await?, "Signing");
    // R3's entry has left with its day. R1's stays until a day after it signed.
    assert_eq!(tier_of(&h, &v, &big[1], &dest, 39_000).await?, "Known");
    assert_eq!(tier_of(&h, &v, &big[1], &dest, 39_001).await?, "New");
    let now = h.now_ms().await?;
    assert!(now < signed + DAY_MS);
    println!(
        "R5 outflow: cap {cap} sats. R1 pending at propose + {} min read as reserved, R1 counted from its signature, R3's retry refused {} min after its first execute",
        (landed - t0) / MINUTE_MS,
        (now - opened) / MINUTE_MS
    );
    Ok(())
}

/// C2 and C3 on the wasm: the status view prints what the core says, so the real delays and the whole
/// freeze rule reach a curl line.
#[tokio::test]
async fn status_prints_the_real_delays_and_the_freeze_rule() -> Result<()> {
    let h = Harness::new().await?;
    let k = keys("r5-equal");
    let mut call = h.create_call(&k, 6);
    let mut p = h.deployed_policy().await?;
    p[2] = p[1];
    call.policy = Some(p);
    let args = h.create_args(&k, &call).await?;
    h.create_raw(args, call.deposit_milli).await?.into_result()?;
    let equal = hex::encode(h.vault_id(&k, 6));
    let delay: u64 = h.undo.view("delay_now").args_json(json!({"vault": equal})).await?.json()?;
    assert_eq!(delay, p[1], "the unguarded delay is the guarded one");
    let lines = status_lines(&h, &equal).await?;
    println!("R5 status, equal delays: {lines:?}");
    assert!(lines.iter().any(|l| l == "no guard: new-destination delay 5 min, the same as with a guard online, funds movable"), "{lines:?}");
    assert!(!lines.iter().any(|l| l.contains("doubled")));

    let v = h.create_vault("r5-freeze").await?;
    let lines = status_lines(&h, &v.hex()).await?;
    assert!(lines.iter().any(|l| l == "no guard: new-destination delay 10 min instead of 5 min, funds movable"), "{lines:?}");
    let until = h.now_ms().await? + 60_000;
    let n = h.nonce_of(&v, "cold_nonce").await?;
    h.cold_call(&v, &v.k_e_intent, "freeze", &until, json!({"until": until}), n, FAR).await?.into_result()?;
    let lines = status_lines(&h, &v.hex()).await?;
    println!("R5 status, frozen: {lines:?}");
    assert!(lines.iter().any(|l| l.starts_with("frozen until ") && l.ends_with(" by the cold key: no proposals, reclaims or execute, and no passkey action except cancel, which has nothing to stop because the freeze ended every pending request. Only the cold key can lift it early, and the cold-key exit is unaffected")), "{lines:?}");
    Ok(())
}

/// C4. A reclaim after `T_stuck` supersedes a Signed request inside its expiry window, and the request
/// goes at once. Before the fix nothing logged its transaction, which may still be valid on Bitcoin, so
/// the contract's copy was gone. Now the reclaim logs it as `prune_signed` does. Sixteen inputs, so the
/// largest transaction there is has to fit the log: a self-spend, since only one with the passkey's fee
/// override can pay the rate floor for sixteen inputs.
#[tokio::test]
async fn reclaim_logs_the_signed_transaction_it_supersedes() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("r5-reclaim-signed").await?;
    let real = coins("r5-reclaim-signed", 16, 100_000);
    let own = v.spk.to_bytes();
    let id = h.propose(&mut v, &real, &own, 1_600_000 - 2_000, None).await?;
    h.raise_fee_cap(&mut v, id, 2_000).await?;
    h.wait_unlock(&v, id).await?;
    h.execute_and_respond(&v, id, 16, false).await?.into_result()?;
    assert_eq!(h.status(&v, id).await?, "Signed");
    let tx = h.verified_final_tx(&v, id, &real).await?;
    let hex_tx = hex::encode(bitcoin::consensus::serialize(&tx));
    let signed_at = h.now_ms().await?;

    let t_stuck = h.vault_view(&v).await?["policy"]["t_stuck_ms"].as_u64().unwrap();
    let window = h.undo.view("instance").args_json(json!({})).await?.json::<Value>()?["expiry_window_ms"].as_u64().unwrap();
    assert!(t_stuck < window);
    h.advance_to(signed_at + t_stuck + 1).await?;
    assert_refused(&h.prune(&v, id).await?, "PruneTooSoon");

    let args = h.reclaim_args(&v, &real[0], 500, v.spend_nonce);
    let res = h.relayer.call(h.undo.id(), "reclaim").args_json(args).gas(gas(300)).transact().await?;
    let burnt = tgas(res.total_gas_burnt.as_gas());
    let logs: Vec<String> = res.logs().iter().map(|l| l.to_string()).collect();
    res.into_result()?;
    v.spend_nonce += 1;
    let line = format!("undo:superseded request={id} tx={hex_tx}");
    assert!(logs.contains(&line), "the log holds the whole transaction: {:?}", logs.iter().map(|l| &l[..l.len().min(80)]).collect::<Vec<_>>());
    let logged: bitcoin::Transaction = bitcoin::consensus::deserialize(&hex::decode(&hex_tx)?)?;
    consensus_verify(&logged, &spent_outputs(&real, &v.spk))?;
    assert_eq!(h.status(&v, id).await?, "deleted", "the supersede itself is unchanged");
    assert!(h.final_tx(&v, id).await?.is_none());
    println!("R5 reclaim: 16-input Signed request {id} superseded {} s after signing, its {} byte transaction in the log, reclaim {burnt:.2} Tgas", (h.now_ms().await? - signed_at) / 1_000, hex_tx.len() / 2);
    Ok(())
}
