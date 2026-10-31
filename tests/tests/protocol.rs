//! Runs the built wasm on a node pinned to one protocol version, which UNDO_PROTOCOL names.
//! scripts/protocol-check.sh starts the node and sets the environment. Mock signer only:
//! nothing here touches a live signer.

use anyhow::Result;
use sandbox_tests::*;

/// Same wasm files: a spend signed through the mock passes libbitcoinconsensus on the two-branch
/// script, and a tampered copy does not.
#[tokio::test]
async fn signed_spend_passes_consensus() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("protocol-alice").await?;
    let coin = coins("spend", 1, 100_000);
    let id = h.propose_simple(&mut v, &coin[0]).await?;
    h.wait_unlock(&v, id).await?;
    h.execute_and_respond(&v, id, 1, false).await?.into_result()?;
    assert_eq!(h.status(&v, id).await?, "Signed");

    let tx = h.verified_final_tx(&v, id, &coin).await?;
    let spent = spent_outputs(&coin, &v.spk);
    let mut tampered = tx.clone();
    tampered.output[0].value = bitcoin::Amount::from_sat(tampered.output[0].value.to_sat() - 1);
    assert!(consensus_verify(&tampered, &spent).is_err(), "a changed output must fail");
    Ok(())
}

/// `p256_verify` and low-level promises both run: a wrong request id is refused, a right one cancels.
#[tokio::test]
async fn p256_cancel_runs() -> Result<()> {
    let h = Harness::new().await?;
    let mut v = h.create_vault("protocol-bob").await?;
    let coin = coins("cancel", 1, 100_000);
    let id = h.propose_simple(&mut v, &coin[0]).await?;

    let refused = h
        .relayer
        .call(h.undo.id(), "cancel")
        .args_json({
            let expires_at = u64::MAX / 2;
            let digest = h.passkey_digest(&v, "cancel", &(id + 1), expires_at, None);
            serde_json::json!({"vault": v.hex(), "request": id, "expires_at": expires_at,
                "auth": {"Passkey": assertion(&v.passkey, &digest, &Bend::default())}})
        })
        .gas(gas(100))
        .transact()
        .await?;
    assert_refused(&refused, "wrong challenge");
    assert_eq!(h.status(&v, id).await?, "Pending");

    h.cancel_passkey(&v, id).await?.into_result()?;
    assert_eq!(h.status(&v, id).await?, "deleted");
    Ok(())
}

/// The control: a wasm with the forbidden import must fail to link at 86 and run at 88. If this
/// fails, the pinned node proves nothing about the real contract.
#[tokio::test]
async fn forbidden_import_control() -> Result<()> {
    let protocol: u32 = std::env::var("UNDO_PROTOCOL").expect("set UNDO_PROTOCOL").parse()?;
    let dir = std::env::var("UNDO_CONTROL_DIR").expect("set UNDO_CONTROL_DIR");
    let code = std::fs::read(format!("{dir}/link_control.wasm"))?;

    let h = Harness::new().await?;
    let contract = h.worker.dev_deploy(&code).await?;
    let result = contract.call("ping").transact().await?;

    match protocol {
        86 => {
            let text = format!("{:?}", result.failures());
            assert!(result.is_failure(), "protocol 86 must refuse this import");
            assert!(text.contains("Link"), "expected a link error, got {text}");
        }
        88 => {
            assert!(result.is_success(), "protocol 88 must accept this import: {:?}", result.failures());
        }
        other => panic!("no expectation for protocol {other}"),
    }
    Ok(())
}
