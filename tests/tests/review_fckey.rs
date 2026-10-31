//! Attack review, function-call keys. A function-call key cannot attach a deposit, so an agent's key
//! has to spend the vault's prepaid credit. See tests/REGRESSION-MAP.md.

use anyhow::Result;
use near_token::NearToken;
use near_workspaces::types::{AccessKey, KeyType, SecretKey};
use near_workspaces::Account;
use sandbox_tests::*;
use serde_json::json;

/// Room for `execute`'s own work on top of the sign and callback gas. scripts/protocol-check.sh
/// --measure finds the real floor.
const EXECUTE_OWN_TGAS: u64 = 30;

#[tokio::test]
async fn f19_function_call_key_proposes_against_credit() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("f19").await?;
    let real = coins("fc", 8, 100_000);
    let to = p2wpkh("destination");
    let sponsor = h.worker.dev_create_account().await?;
    let sk = SecretKey::from_seed(KeyType::ED25519, "test-only agent key");
    sponsor
        .batch(sponsor.id())
        .add_key(sk.public_key(), AccessKey::function_call_access(h.undo.id(), &["execute", "propose_btc"], Some(NearToken::from_near(2))))
        .transact()
        .await?
        .into_result()?;
    let k = Account::from_secret_key(sponsor.id().clone(), sk, &h.worker);

    let args = h.propose_args(&v, &real, &to, 799_050, None, 0);
    let refused = k.call(h.undo.id(), "propose_btc").args_json(args.clone()).deposit(NearToken::from_millinear(100)).gas(gas(30)).transact().await;
    let text = format!("{:?}", refused.as_ref().err());
    assert!(refused.is_err() && text.contains("DepositWithFunctionCall"), "protocol refuses a deposit through this key: {text}");

    let credit = h.credit(&v).await?;
    let res = k.call(h.undo.id(), "propose_btc").args_json(args).gas(gas(30)).transact().await?;
    res.clone().into_result()?;
    let id = res.json::<u64>()?;
    v.spend_nonce = 1;
    assert!(h.credit(&v).await? < credit, "the proposal was paid from credit");

    // The agent cannot cancel: the key has no such method, and the method wants a passkey anyway.
    let far = u64::MAX / 2;
    let digest = h.passkey_digest(&v, "cancel", &id, far, None);
    let no_method = k.call(h.undo.id(), "cancel").args_json(json!({"vault": v.hex(), "request": id, "expires_at": far, "auth": {"Passkey": assertion(&v.passkey, &digest, &Bend::default())}})).transact().await;
    assert!(format!("{:?}", no_method.err()).contains("MethodNameMismatch"));

    // Execute at 8 inputs, with no deposit, through the same key.
    h.wait_unlock(&v, id).await?;
    let prepaid = 8 * (SIGN_TGAS + CALLBACK_TGAS) + EXECUTE_OWN_TGAS;
    let call = k.call(h.undo.id(), "execute").args_json(json!({"vault": v.hex(), "request": id})).gas(gas(prepaid));
    h.execute_with(call, 8, false).await?.into_result()?;
    assert_eq!(h.status(&v, id).await?, "Signed");
    h.verified_final_tx(&v, id, &real).await?;
    Ok(())
}

/// Prepaid gas is reserved against allowance. This finds the smallest allowance that runs execute at
/// 1 and 8 inputs, so an agent's key can be sized from a number.
#[tokio::test]
async fn f19_measure_allowance_needed_for_execute() -> Result<()> {
    for inputs in [1usize, 8] {
        let prepaid = inputs as u64 * (SIGN_TGAS + CALLBACK_TGAS) + EXECUTE_OWN_TGAS;
        let mut smallest = None;
        for milli in [10u128, 25, 50, 100, 250, 500, 1000, 2000] {
            let h = Harness::new().await?;
            let mut v = h.create_vault(&format!("f19-{inputs}-{milli}")).await?;
            let real = coins("fc", inputs, 100_000);
            let id = h.propose(&mut v, &real, &p2wpkh("destination"), inputs as u64 * 100_000 - 950, None).await?;
            h.wait_unlock(&v, id).await?;
            let sponsor = h.worker.dev_create_account().await?;
            let sk = SecretKey::from_seed(KeyType::ED25519, "test-only agent key");
            sponsor
                .batch(sponsor.id())
                .add_key(sk.public_key(), AccessKey::function_call_access(h.undo.id(), &["execute"], Some(NearToken::from_millinear(milli))))
                .transact()
                .await?
                .into_result()?;
            let k = Account::from_secret_key(sponsor.id().clone(), sk, &h.worker);
            let call = k.call(h.undo.id(), "execute").args_json(json!({"vault": v.hex(), "request": id})).gas(gas(prepaid));
            match h.execute_racing(call, inputs).await? {
                Ok(r) => {
                    r.into_result()?;
                    assert_eq!(h.status(&v, id).await?, "Signed");
                    smallest = Some(milli);
                    break;
                }
                Err(e) => assert!(e.contains("NotEnoughAllowance"), "{e}"),
            }
        }
        let smallest = smallest.expect("some allowance must run it");
        println!("MEASURE allowance inputs={inputs} prepaid={prepaid}T smallest_tried_that_runs={smallest} milliNEAR");
    }
    Ok(())
}
