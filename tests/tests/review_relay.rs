//! Attack review, relay keys. Failing calls burn a shared function-call key's allowance, and that is
//! NEAR's behaviour, not this contract's. So the design has no public key, and cancels go through a
//! separate key. These tests keep the measurement and show the separation. See tests/REGRESSION-MAP.md.

use anyhow::Result;
use near_token::NearToken;
use near_workspaces::types::{AccessKey, AccessKeyPermission, KeyType, SecretKey};
use near_workspaces::Account;
use sandbox_tests::*;
use serde_json::json;

async fn allowance(a: &Account, k: &SecretKey) -> u128 {
    match a.view_access_key(&k.public_key()).await.unwrap().permission {
        AccessKeyPermission::FunctionCall(f) => f.allowance.map(|x| x.as_yoctonear()).unwrap_or(0),
        _ => 0,
    }
}

/// Failing calls cost the sponsor allowance for free, and a small allowance then refuses even a real
/// cancel. A separate owner key is not touched by any of it.
#[tokio::test]
async fn f10_griefed_general_key_cannot_stop_a_cancel_on_the_owner_key() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("f10").await?;
    let coin = coins("relay", 1, 100_000);
    let id = h.propose_simple(&mut v, &coin[0]).await?;
    let sponsor = h.worker.dev_create_account().await?;

    let general = SecretKey::from_seed(KeyType::ED25519, "test-only general relay key");
    let owner = SecretKey::from_seed(KeyType::ED25519, "test-only owner relay key");
    let small = SecretKey::from_seed(KeyType::ED25519, "test-only small relay key");
    sponsor.batch(sponsor.id()).add_key(general.public_key(), AccessKey::function_call_access(h.undo.id(), &["execute", "propose_btc"], Some(NearToken::from_millinear(250)))).transact().await?.into_result()?;
    sponsor.batch(sponsor.id()).add_key(owner.public_key(), AccessKey::function_call_access(h.undo.id(), &["cancel"], Some(NearToken::from_millinear(250)))).transact().await?.into_result()?;
    sponsor.batch(sponsor.id()).add_key(small.public_key(), AccessKey::function_call_access(h.undo.id(), &["cancel"], Some(NearToken::from_millinear(10)))).transact().await?.into_result()?;
    let griefer = Account::from_secret_key(sponsor.id().clone(), general.clone(), &h.worker);

    let before = allowance(&sponsor, &general).await;
    let mut burned = 0;
    for _ in 0..40 {
        let _ = griefer.call(h.undo.id(), "execute").args_json(json!({"vault": v.hex(), "request": 999_999})).gas(gas(30)).transact().await?;
        burned += 1;
    }
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;
    let after = allowance(&sponsor, &general).await;
    assert!(after < before, "failing calls cost allowance");
    println!("MEASURE relay failing_calls={burned} allowance_spent={} yocto after refunds", before - after);

    // A real cancel at 30 Tgas does not fit in a small allowance, which is why a shared key was griefable.
    let far = u64::MAX / 2;
    let digest = h.passkey_digest(&v, "cancel", &id, far, None);
    let args = json!({"vault": v.hex(), "request": id, "expires_at": far, "auth": {"Passkey": assertion(&v.passkey, &digest, &Bend::default())}});
    let too_small = Account::from_secret_key(sponsor.id().clone(), small, &h.worker);
    let refused = too_small.call(h.undo.id(), "cancel").args_json(args.clone()).gas(gas(30)).transact().await;
    assert!(format!("{:?}", refused.err()).contains("NotEnoughAllowance"));

    // The griefed key has no cancel method at all, and the owner key still cancels at 30 Tgas.
    let owner_account = Account::from_secret_key(sponsor.id().clone(), owner, &h.worker);
    owner_account.call(h.undo.id(), "cancel").args_json(args).gas(gas(30)).transact().await?.into_result()?;
    assert_eq!(h.status(&v, id).await?, "deleted");
    Ok(())
}

/// What one failing call spends against allowance, at several prepaid values.
#[tokio::test]
async fn f10_measure_failing_call_cost_by_prepaid_gas() -> Result<()> {
    let h = Harness::new().await?;
    let v = h.create_vault("f10-measure").await?;
    let sponsor = h.worker.dev_create_account().await?;
    let key = SecretKey::from_seed(KeyType::ED25519, "test-only sponsor key");
    sponsor.batch(sponsor.id()).add_key(key.public_key(), AccessKey::function_call_access(h.undo.id(), &["execute"], Some(NearToken::from_millinear(250)))).transact().await?.into_result()?;
    let k = Account::from_secret_key(sponsor.id().clone(), key.clone(), &h.worker);
    // Reserved up front, in full, and given back by the refund receipt once the call ends.
    for t in [30u64, 100, 200] {
        let a = allowance(&sponsor, &key).await;
        let _ = k.call(h.undo.id(), "execute").args_json(json!({"vault": v.hex(), "request": 999_999})).gas(gas(t)).transact().await?;
        let reserved = a.saturating_sub(allowance(&sponsor, &key).await);
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        let net = a.saturating_sub(allowance(&sponsor, &key).await);
        println!("MEASURE failing_call prepaid={t}T allowance_held_at_result={reserved} allowance_spent_after_refund={net}");
        assert!(net <= reserved);
    }
    let refused = k.call(h.undo.id(), "execute").args_json(json!({"vault": v.hex(), "request": 999_999})).gas(gas(1000)).transact().await;
    assert!(format!("{:?}", refused.err()).contains("NotEnoughAllowance"), "prepaid gas larger than the allowance is refused");
    Ok(())
}
