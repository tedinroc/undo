//! A vault with a long history must keep working. The earlier code held every signed request in one
//! row, so `on_signed` passed its fixed 10 Tgas at spend 141, the signature was produced and dropped,
//! and retry failed the same way. Real wasm, real completed self-spends.

use anyhow::Result;
use near_token::NearToken;
use sandbox_tests::*;
use serde_json::json;

/// Past the old limit. `UNDO_GROWTH_ROUNDS` changes it.
const DEFAULT_ROUNDS: usize = 150;

#[tokio::test]
async fn history_does_not_weigh_on_the_callback() -> Result<()> {
    let h = Harness::new().await?;
    let c = h.undo.id().to_string();
    let mut v = h.create_vault("r1-grow").await?;
    h.relayer.call(h.undo.id(), "deposit_storage").args_json(json!({"vault": v.hex()})).deposit(NearToken::from_near(5)).transact().await?.into_result()?;
    let to = v.spk.to_bytes();
    let rounds: usize = std::env::var("UNDO_GROWTH_ROUNDS").ok().and_then(|s| s.parse().ok()).unwrap_or(DEFAULT_ROUNDS);
    let credit_start = h.credit(&v).await?;
    let t_new = h.vault_view(&v).await?["policy"]["t_new_ms"].as_u64().unwrap();
    let mut first_callback = 0.0;
    let mut worst_callback: f64 = 0.0;
    let mut ids = Vec::new();

    for n in 0..rounds {
        let coin = coins(&format!("r1-grow-{n}"), 1, 100_000);
        let id = h.propose(&mut v, &coin, &to, 99_800, None).await?;
        // The named override lifts the 24 h budget, so this needs no day-long clock jump.
        h.raise_fee_cap(&mut v, id, 200).await?;
        h.wait_unlock(&v, id).await?;
        let res = h.execute_and_respond(&v, id, 1, false).await?;
        let callback = tgas(own_gas(&res, &c, Some("undo:signed")).into_iter().max().unwrap_or(0));
        assert_eq!(h.status(&v, id).await?, "Signed", "spend {} lost its signature: {}", n + 1, err_text(&res));
        if n == 0 {
            first_callback = callback;
        }
        worst_callback = worst_callback.max(callback);
        ids.push(id);
        if (n + 1) % 25 == 0 {
            let view = h.vault_view(&v).await?;
            println!("MEASURE growth spends={} row_bytes={} on_signed={callback:.2}T credit_spent_near={:.4}", n + 1, view["row_bytes"], (credit_start - h.credit(&v).await?) as f64 / 1e24);
        }
        h.advance_to(h.now_ms().await? + t_new + 1).await?;
    }

    // The last real transaction from the end of the run still verifies, and the first is still here.
    let last = coins(&format!("r1-grow-{}", rounds - 1), 1, 100_000);
    h.verified_final_tx(&v, ids[rounds - 1], &last).await?;
    let first = coins("r1-grow-0", 1, 100_000);
    h.verified_final_tx(&v, ids[0], &first).await?;
    println!("MEASURE growth on_signed first={first_callback:.2}T worst={worst_callback:.2}T over {rounds} spends");
    assert!(worst_callback < 5.0, "under half the 10 Tgas callback attach after {rounds} spends: {worst_callback:.2}");
    assert!(worst_callback - first_callback < 1.0, "the callback stays flat: {first_callback:.2} to {worst_callback:.2}");

    // Pruning every request gives back all but the pins.
    let spent_before = credit_start - h.credit(&v).await?;
    let window = h.undo.view("instance").args_json(json!({})).await?.json::<serde_json::Value>()?["expiry_window_ms"].as_u64().unwrap();
    h.advance_to(h.now_ms().await? + window + 1).await?;
    for id in &ids {
        h.prune(&v, *id).await?.into_result()?;
    }
    let spent_after = credit_start - h.credit(&v).await?;
    let per_spend_before = spent_before as f64 / rounds as f64 / 1e24;
    let per_spend_after = spent_after as f64 / rounds as f64 / 1e24;
    println!("MEASURE growth credit per spend before prune {per_spend_before:.5} NEAR, after {per_spend_after:.5} NEAR");
    assert!(spent_after < spent_before / 2, "most of the credit comes back");
    Ok(())
}
