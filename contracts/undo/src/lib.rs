//! Undo: one contract, many vaults. Each vault owns one MPC derivation path.
//!
//! This is a thin shell. It checks every signature, then hands `undo-core` the name of the key that
//! signed, and writes a vault back only when the core says yes. Bitcoin bytes come from `undo-btc`.
//!
//! A spend-key signature only creates a pending request. The contract asks the signer for a
//! signature only after the wait, and a passkey or the cold key can cancel before that. Once a sign
//! call has been made the request can no longer be cancelled, because a signature may exist even if
//! the callback reported a timeout.
//!
//! Promises use the low-level env calls on purpose. near-sdk's high-level promise type links every
//! promise host function, including ones a chain on an older protocol version does not export yet,
//! and the contract then fails with a link error on every call.
//!
//! Nothing here reads Bitcoin. Caller-declared values are checked by consensus, and by the pin rules
//! in `undo-core`.

#[cfg(all(target_arch = "wasm32", not(near)))]
compile_error!("build with scripts/build.sh: this build has no --cfg near and no path remapping");

pub mod api;
mod auth;
mod btc;
mod storage;

use api::{
    CancelAuth, CheckView, CreateArgs, HexBytes, InstanceView, OutpointView, PasskeyArgs, Preset,
    RequestView, SignerResponse, Utxo, VaultView, WebAuthn,
};
use auth::{intent_digest, COLD_TAG, PASSKEY_TAG, SPEND_TAG};
use near_sdk::borsh::BorshSerialize;
use near_sdk::{env, near, require, AccountId, Gas, NearToken, PanicOnDefault};
use storage::{Loaded, Row, Short};
use undo_core::{Bounds, Caller, Input, Intent, MpcSig, OutpointState, Outputs, Passkey, Policy, ProposeArgs, RequestStatus, SignedOutcome, Vault};

const PATH_PREFIX: &str = "undo/";
/// Largest signer response the callback will read, so a hostile signer cannot burn its gas.
const MAX_SIGNER_RESPONSE: usize = 1024;
const ON_DERIVED_TGAS: u64 = 10;
/// Own work in `execute` and `create_vault` after the gas check, so the check fails with a message
/// and not an out-of-gas receipt.
const GAS_MARGIN_TGAS: u64 = 3;
/// A sign call needs no more than this. A larger value is a griefer burning a relay's allowance.
const MAX_SIGN_TGAS: u64 = 300;
/// What a caller may attach per sign, if the signer's requirement rises. 0.01 NEAR.
const MAX_SIGN_DEPOSIT: u128 = 10_000_000_000_000_000_000_000;

#[near(serializers = [borsh])]
struct Config {
    preset: Preset,
    operator: AccountId,
    /// On mainnet only the operator may create a vault.
    restrict_create: bool,
    signer: AccountId,
    domain_id: u64,
    sign_tgas: u64,
    callback_tgas: u64,
    derive_tgas: u64,
    network: String,
    origins: Vec<String>,
    policy: Policy,
    bounds: Bounds,
}

/// The signer and its constants have no setter. They change only through the upgrade queue.
#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Undo {
    config: Config,
}

fn fail<E: core::fmt::Debug>(e: E) -> ! {
    env::panic_str(&format!("{e:?}"))
}

fn now() -> u64 {
    env::block_timestamp_ms()
}

fn vault_key(vault: &HexBytes) -> [u8; 32] {
    vault.fixed("vault")
}

fn require_half_sigs(script: &undo_btc::WitnessScript, vault: &Vault, inputs: &[Input], outputs: &Outputs, half_sigs: &[HexBytes]) {
    let digests = btc::sighashes(script, &vault.vault_spk, inputs, outputs);
    for (digest, sig) in digests.iter().zip(half_sigs) {
        require!(auth::secp_signed_by(digest, &sig.0, &vault.k_u), "bad K_u half-signature");
    }
}

#[near]
impl Undo {
    #[init]
    #[private]
    pub fn new(
        preset: Preset,
        operator: AccountId,
        restrict_create: bool,
        signer: AccountId,
        domain_id: u64,
        sign_tgas: u64,
        callback_tgas: u64,
        derive_tgas: u64,
        network: String,
        origins: Vec<String>,
        outflow_cap_24h: u64,
    ) -> Self {
        if undo_btc::Network::from_name(&network).is_err() {
            env::panic_str("unknown network");
        }
        let (policy, bounds) = match preset {
            Preset::TestCoin => (Policy::test_coin(outflow_cap_24h), Bounds::test_coin(outflow_cap_24h)),
            Preset::MainnetProof => (Policy::mainnet_proof(outflow_cap_24h), Bounds::mainnet(outflow_cap_24h)),
        };
        Self {
            config: Config {
                preset,
                operator,
                restrict_create,
                signer,
                domain_id,
                sign_tgas,
                callback_tgas,
                derive_tgas,
                network,
                origins,
                policy,
                bounds,
            },
        }
    }

    /// Stores the vault as Inactive and asks the signer what key this vault's path really derives.
    /// `on_derived` activates it only on an exact match, and propose is refused until then. The
    /// attached deposit becomes the vault's storage credit.
    #[payable]
    pub fn create_vault(&mut self, args: CreateArgs) -> HexBytes {
        let cfg = &self.config;
        require!(!cfg.restrict_create || env::predecessor_account_id() == cfg.operator, "only the operator creates vaults here");
        require!(now() <= args.expires_at, "creation intent expired");
        let k_s: [u8; 32] = args.k_s.fixed("k_s");
        let rp_id_hash: [u8; 32] = args.passkey.rp_id_hash.fixed("rp_id_hash");
        let id = auth::vault_id(&k_s, &args.k_u.0, &args.k_e_leaf.0, &args.k_e_intent.0, &args.passkey.pubkey.0, args.csv);
        require!(!storage::exists(&id), "vault exists");
        let policy = args.policy.map_or(cfg.policy, Policy::from);

        let digest = auth::create_digest(&id, &args.k_m.0, &rp_id_hash, &args.guard, &policy, args.expires_at);
        auth::require_ed25519(&digest, &args.pop_s, &k_s, "K_s");
        auth::require_secp(&digest, &args.pop_u, &args.k_u.0, "K_u");
        auth::require_secp(&digest, &args.pop_e, &args.k_e_intent.0, "K_e");
        auth::require_secp(&auth::leaf_pop_digest(&digest), &args.pop_leaf, &args.k_e_leaf.0, "K_e leaf");
        let flags = auth::require_webauthn(&args.pop_p, &digest, &args.passkey.pubkey.0, &rp_id_hash, &cfg.origins);

        let script = btc::witness_script(&args.k_u.0, &args.k_m.0, &args.k_e_leaf.0, args.csv).unwrap_or_else(|e| fail(e));
        let vault = Vault::create(undo_core::CreateArgs {
            k_s,
            k_u: args.k_u.0,
            k_m: args.k_m.0,
            k_e_leaf: args.k_e_leaf.0,
            k_e_intent: args.k_e_intent.0,
            passkey: Passkey {
                pubkey: args.passkey.pubkey.0,
                rp_id_hash,
                backup_eligible: flags.backup_eligible,
                backup_state: flags.backup_state,
            },
            guard: args.guard.map(|a| a.to_string()),
            csv_blocks: args.csv,
            vault_spk: script.script_pubkey::<btc::HostSha>(),
            policy,
            fixed: cfg.preset.fixed(),
            bounds: cfg.bounds,
        })
        .unwrap_or_else(|e| fail(e));
        storage::insert(
            &id,
            Row { credit: env::attached_deposit().as_yoctonear(), reserved: 0, creator: env::predecessor_account_id(), vault },
        );
        self.ask_signer_for_key(&id);
        env::log_str(&format!("undo:created vault={}", hex::encode(id)));
        HexBytes(id.to_vec())
    }

    /// Asks again for a vault still Inactive, in case the first callback was lost.
    pub fn activate(&mut self, vault: HexBytes) {
        let id = vault_key(&vault);
        require!(!storage::load_row(&id).row.vault.active, "already active");
        self.ask_signer_for_key(&id);
    }

    /// Activates on an exact match. Anything else removes the vault and returns its deposit, so a
    /// wrong `K_m` can never activate and the creator can try again.
    #[private]
    pub fn on_derived(&mut self, vault: HexBytes) {
        let id = vault_key(&vault);
        let Some(mut loaded) = storage::try_load_row(&id) else { return };
        if loaded.row.vault.active {
            return;
        }
        let derived = signer_result().and_then(|raw| parse_secp_key(&raw));
        let activated = derived.is_some_and(|key| loaded.row.vault.activate(&key).is_ok());
        if activated {
            loaded.commit(&id, Short::Reserved);
            env::log_str(&format!("undo:active vault={}", hex::encode(id)));
        } else {
            let refund = storage::remove(&id, &loaded);
            if refund > 0 {
                let promise = env::promise_batch_create(&loaded.row.creator);
                env::promise_batch_action_transfer(promise, NearToken::from_yoctonear(refund));
            }
            env::log_str(&format!("undo:refused vault={} refund={refund}", hex::encode(id)));
        }
    }

    /// Anyone may top up any vault.
    #[payable]
    pub fn deposit_storage(&mut self, vault: HexBytes) {
        let id = vault_key(&vault);
        let mut loaded = storage::load_row(&id);
        loaded.row.credit = loaded.row.credit.saturating_add(env::attached_deposit().as_yoctonear());
        loaded.commit(&id, Short::Reserved);
    }

    /// `K_s` signature plus one `K_u` half-signature per input. Charges the vault's credit and takes
    /// no deposit, so a function-call key can call it.
    pub fn propose_btc(
        &mut self,
        vault: HexBytes,
        inputs: Vec<Utxo>,
        to: HexBytes,
        amount: u64,
        change: Option<u64>,
        half_sigs: Vec<HexBytes>,
        nonce: u64,
        expires_at: u64,
        spend_sig: HexBytes,
    ) -> u64 {
        let id = vault_key(&vault);
        let mut loaded = storage::load(&id);
        let inputs: Vec<Input> = inputs.iter().map(Utxo::input).collect();
        let outputs = Outputs { dest_script: to.0, dest_value: amount, change_value: change };
        // Every signature check is per input, so refuse an oversized request before paying for them.
        if inputs.len() > undo_core::MAX_INPUTS {
            fail(undo_core::Error::TooManyInputs);
        }
        if half_sigs.len() != inputs.len() {
            fail(undo_core::Error::HalfSigCount);
        }
        loaded.load_outpoints(&id, &inputs.iter().map(|i| i.outpoint).collect::<Vec<_>>());
        let args = (spend_args(&inputs), &outputs.dest_script, outputs.dest_value, outputs.change_value);
        let digest = intent_digest(SPEND_TAG, &id, "propose_btc", &args, expires_at, Some(nonce));
        auth::require_ed25519(&digest, &spend_sig, &loaded.row.vault.k_s, "K_s");
        let vault = &loaded.row.vault;
        let script = btc::script_of(vault);
        require_half_sigs(&script, vault, &inputs, &outputs, &half_sigs);

        let caller = Caller::SpendKey(loaded.row.vault.k_s);
        let proposed = loaded
            .row
            .vault
            .propose(
                &caller,
                Intent { nonce, expires_at },
                ProposeArgs { inputs, outputs, half_sigs: half_sigs.into_iter().map(|s| s.0).collect() },
                now(),
            )
            .unwrap_or_else(|e| fail(e));
        loaded.commit(&id, Short::Refuse);
        env::log_str(&format!("undo:proposed request={} unlock={}", proposed.id, proposed.base_unlock));
        proposed.id
    }

    /// `K_s` plus a fresh `K_u` half-signature. One outpoint, back to the vault's own script, after
    /// `T_stuck`. May re-declare the value, because a single-input digest cannot combine with any
    /// other session.
    pub fn reclaim(
        &mut self,
        vault: HexBytes,
        utxo: Utxo,
        fee: u64,
        half_sig: HexBytes,
        nonce: u64,
        expires_at: u64,
        spend_sig: HexBytes,
    ) -> u64 {
        let id = vault_key(&vault);
        let mut loaded = storage::load(&id);
        let input = utxo.input();
        let args = (spend_args(&[input]), fee);
        let digest = intent_digest(SPEND_TAG, &id, "reclaim", &args, expires_at, Some(nonce));
        auth::require_ed25519(&digest, &spend_sig, &loaded.row.vault.k_s, "K_s");
        let vault = &loaded.row.vault;
        let dest_value = input.value.checked_sub(fee).unwrap_or_else(|| fail(undo_core::Error::OutputsExceedInputs));
        let outputs = Outputs { dest_script: vault.vault_spk.clone(), dest_value, change_value: None };
        let script = btc::script_of(vault);
        require_half_sigs(&script, vault, &[input], &outputs, core::slice::from_ref(&half_sig));

        loaded.load_outpoints(&id, &[input.outpoint]);
        // The request that held this coin is superseded, so its other inputs change state too.
        if let OutpointState::Signing(owner) | OutpointState::Spent { request: owner } = loaded.row.vault.outpoint_state(&input.outpoint) {
            loaded.load_request(&id, owner);
        }
        let caller = Caller::SpendKey(loaded.row.vault.k_s);
        let proposed = loaded
            .row
            .vault
            .reclaim(&caller, Intent { nonce, expires_at }, input.outpoint, input.value, fee, half_sig.0, now())
            .unwrap_or_else(|e| fail(e));
        loaded.commit(&id, Short::Refuse);
        env::log_str(&format!("undo:proposed request={} unlock={}", proposed.id, proposed.base_unlock));
        proposed.id
    }

    /// `K_p` or `K_e`, with no vault nonce, so it cannot go stale in a crisis. The intent names the
    /// request and an expiry.
    pub fn cancel(&mut self, vault: HexBytes, request: u64, expires_at: u64, auth: CancelAuth) {
        let id = vault_key(&vault);
        let mut loaded = storage::load(&id);
        loaded.load_request(&id, request);
        let caller = match auth {
            CancelAuth::Passkey(assertion) => self.passkey_caller(&id, &loaded, "cancel", &request, expires_at, None, &assertion),
            CancelAuth::Cold(signature) => {
                let digest = intent_digest(COLD_TAG, &id, "cancel", &request, expires_at, None);
                auth::require_secp(&digest, &signature, &loaded.row.vault.k_e_intent, "K_e");
                Caller::Cold(loaded.row.vault.k_e_intent.clone())
            }
        };
        loaded.row.vault.cancel(&caller, expires_at, request, now()).unwrap_or_else(|e| fail(e));
        loaded.commit(&id, Short::Reserved);
        env::log_str(&format!("undo:cancelled request={request}"));
    }

    /// `K_p`, at once: kills every pending request by bumping the epoch and suspends `K_s`. The new
    /// key waits `T_known` as a grant.
    pub fn cancel_all_and_rotate(&mut self, vault: HexBytes, new_k_s: HexBytes, nonce: u64, expires_at: u64, assertion: WebAuthn) -> u64 {
        let id = vault_key(&vault);
        let mut loaded = storage::load(&id);
        let new_key: [u8; 32] = new_k_s.fixed("new_k_s");
        let caller = self.passkey_caller(&id, &loaded, "cancel_all_and_rotate", &new_key, expires_at, Some(nonce), &assertion);
        let grant = loaded
            .row
            .vault
            .cancel_all_and_rotate(&caller, Intent { nonce, expires_at }, new_key, now())
            .unwrap_or_else(|e| fail(e));
        loaded.commit(&id, Short::Reserved);
        env::log_str(&format!("undo:rotating grant={grant}"));
        grant
    }

    /// Anyone, after the grant's delay.
    pub fn apply_grant(&mut self, vault: HexBytes, grant: u64) {
        let id = vault_key(&vault);
        let mut loaded = storage::load(&id);
        loaded.row.vault.apply_grant(grant, now()).unwrap_or_else(|e| fail(e));
        loaded.commit(&id, Short::Refuse);
    }

    /// `K_p`, at once, for one named self-spend: lets an exit pay more than the fee cap, up to 1/20 of
    /// what it moves. Without this a griefed budget or a fee spike could strand the exit.
    pub fn raise_fee_cap(&mut self, vault: HexBytes, request: u64, cap: u64, nonce: u64, expires_at: u64, assertion: WebAuthn) {
        let id = vault_key(&vault);
        let mut loaded = storage::load(&id);
        loaded.fetch_request(&id, request);
        let caller = self.passkey_caller(&id, &loaded, "raise_fee_cap", &(request, cap), expires_at, Some(nonce), &assertion);
        loaded
            .row
            .vault
            .raise_fee_cap(&caller, Intent { nonce, expires_at }, request, cap, now())
            .unwrap_or_else(|e| fail(e));
        loaded.commit(&id, Short::Reserved);
    }

    /// Anyone, after unlock. The first call is the point of no return: it charges the fee budget,
    /// pins declared values and closes cancel. No deposit is needed, because the contract funds the
    /// signer's 1 yocto and function-call keys cannot attach one. A caller may attach more and pass
    /// more sign gas if the signer's requirement rises, so an outage from that needs no upgrade.
    /// Reads no result here: clients read request state, not transaction status.
    #[payable]
    pub fn execute(&mut self, vault: HexBytes, request: u64, max_inputs: Option<u32>, sign_tgas: Option<u64>) -> u32 {
        let id = vault_key(&vault);
        let mut loaded = storage::load(&id);
        loaded.load_request(&id, request);
        let cfg = &self.config;
        let sign_tgas = sign_tgas.unwrap_or(cfg.sign_tgas);
        require!((cfg.sign_tgas..=MAX_SIGN_TGAS).contains(&sign_tgas), "sign gas out of range");

        // The first execute records the coins this transaction pays back to the vault, so a chain of
        // pre-signed self-spends cannot go faster than the chain wait. It reads their entries too,
        // because one that already exists means the chain was built backwards.
        let txid = loaded.load_children(&id, request);
        let batch = loaded
            .row
            .vault
            .execute(request, max_inputs.unwrap_or(u32::MAX) as usize, now(), env::block_height(), txid)
            .unwrap_or_else(|e| fail(e));
        let vault_state = &loaded.row.vault;
        let stored = vault_state.requests.get(&request).unwrap_or_else(|| env::panic_str("no such request"));
        let script = btc::script_of(vault_state);
        let digests = btc::sighashes(&script, &vault_state.vault_spk, &stored.inputs, &stored.outputs);

        let count = batch.indices.len() as u64;
        let need = Gas::from_tgas(count * (sign_tgas + cfg.callback_tgas) + GAS_MARGIN_TGAS);
        let left = env::prepaid_gas().saturating_sub(env::used_gas());
        require!(left >= need, format!("attach at least {} Tgas more", need.as_tgas()));

        let attached = env::attached_deposit().as_yoctonear();
        let per_sign = (attached / u128::from(count)).max(1);
        require!(per_sign <= MAX_SIGN_DEPOSIT, "deposit per sign above the cap");

        let path = format!("{PATH_PREFIX}{}", hex::encode(id));
        let vault_hex = hex::encode(id);
        for index in &batch.indices {
            let digest = hex::encode(digests[*index]);
            let args = format!(
                r#"{{"request":{{"path":"{path}","payload_v2":{{"Ecdsa":"{digest}"}},"domain_id":{}}}}}"#,
                cfg.domain_id
            );
            let sign = env::promise_create(
                cfg.signer.clone(),
                "sign",
                args,
                NearToken::from_yoctonear(per_sign),
                Gas::from_tgas(sign_tgas),
            );
            let callback = format!(
                r#"{{"vault":"{vault_hex}","request":{request},"attempt":{},"input":{index},"payload":"{digest}"}}"#,
                batch.attempt
            );
            env::promise_then(
                sign,
                env::current_account_id(),
                "on_signed",
                callback,
                NearToken::from_yoctonear(0),
                Gas::from_tgas(cfg.callback_tgas),
            );
        }
        loaded.commit(&id, Short::Reserved);
        env::log_str(&format!("undo:executing request={request} attempt={} inputs={count}", batch.attempt));
        count as u32
    }

    /// Never panics on bad signer output: that would strand `in_flight`. Drops a stale attempt, and
    /// compares the payload with the digest rebuilt from current request state before storing.
    /// Bytes it writes were reserved at propose, so it cannot die with the credit at zero. Its gas is
    /// fixed when `execute` runs, so it reads only the row and this one request: no amount of history
    /// can make it run out. The ledger is read only for the answer that completes the request.
    #[private]
    pub fn on_signed(&mut self, vault: HexBytes, request: u64, attempt: u32, input: u32, payload: HexBytes) {
        let id = vault_key(&vault);
        let Some(mut loaded) = storage::try_load_row(&id) else {
            env::log_str("undo:on_signed dropped unknown_vault");
            return;
        };
        let index = input as usize;
        loaded.fetch_request(&id, request);
        let completes = loaded.row.vault.requests.get(&request).is_some_and(|r| r.sigs.iter().enumerate().all(|(i, s)| i == index || s.is_some()));
        if completes {
            loaded.load_inputs(&id, request);
        }
        let vault_state = &loaded.row.vault;
        let (recomputed, signature) = match vault_state.requests.get(&request).filter(|r| index < r.inputs.len()) {
            Some(stored) => {
                let script = btc::script_of(vault_state);
                let digest = btc::sighashes(&script, &vault_state.vault_spk, &stored.inputs, &stored.outputs)[index];
                (digest, accept_signature(&digest, &vault_state.k_m))
            }
            None => ([0u8; 32], None),
        };
        let payload = <[u8; 32]>::try_from(payload.0.as_slice()).unwrap_or([0xff; 32]);
        let outcome = loaded.row.vault.on_signed(request, attempt, index, payload, recomputed, signature, now());
        match outcome {
            SignedOutcome::DroppedUnknownRequest
            | SignedOutcome::DroppedStaleAttempt
            | SignedOutcome::DroppedNotInFlight => {
                env::log_str(&format!("undo:on_signed dropped {outcome:?} request={request} input={input}"));
                return;
            }
            SignedOutcome::DroppedDigestMismatch | SignedOutcome::Failed => {
                env::log_str(&format!("undo:on_signed {outcome:?} request={request} input={input}"));
            }
            SignedOutcome::Stored { complete } => {
                env::log_str(&format!("undo:signed request={request} input={input} complete={complete}"));
            }
        }
        loaded.commit(&id, Short::Reserved);
    }

    /// Anyone, once a Signed request is older than the expiry window. Its bytes go back to the vault's
    /// credit. The final transaction goes into this call's log first, so it can still be read from
    /// the chain after the row is gone. The coin's ledger entry and pin stay.
    pub fn prune_signed(&mut self, vault: HexBytes, request: u64) {
        let id = vault_key(&vault);
        let mut loaded = storage::load_row(&id);
        loaded.fetch_request(&id, request);
        let tx = loaded.row.vault.requests.get(&request).and_then(|r| btc::final_tx(&loaded.row.vault, r));
        loaded.row.vault.prune_signed(request, now()).unwrap_or_else(|e| fail(e));
        env::log_str(&format!("undo:pruned request={request} tx={}", tx.map(hex::encode).unwrap_or_default()));
        loaded.commit(&id, Short::Reserved);
    }

    /// `K_e`: up to the CSV period with one signature. Kills pending requests and grants, and blocks
    /// propose, execute and every passkey action except cancel.
    pub fn freeze(&mut self, vault: HexBytes, until: u64, nonce: u64, expires_at: u64, signature: HexBytes) {
        let id = vault_key(&vault);
        let mut loaded = storage::load(&id);
        let caller = cold_caller(&id, &loaded, "freeze", &until, expires_at, Some(nonce), &signature);
        loaded.row.vault.freeze(&caller, Intent { nonce, expires_at }, until, now()).unwrap_or_else(|e| fail(e));
        loaded.commit(&id, Short::Reserved);
        env::log_str(&format!("undo:frozen until={until}"));
    }

    /// `K_e`. Nothing else can lift a freeze before it runs out.
    pub fn unfreeze(&mut self, vault: HexBytes, nonce: u64, expires_at: u64, signature: HexBytes) {
        let id = vault_key(&vault);
        let mut loaded = storage::load(&id);
        let caller = cold_caller(&id, &loaded, "unfreeze", &(), expires_at, Some(nonce), &signature);
        loaded.row.vault.unfreeze(&caller, Intent { nonce, expires_at }, now()).unwrap_or_else(|e| fail(e));
        loaded.commit(&id, Short::Reserved);
        env::log_str("undo:unfrozen");
    }

    /// `K_e` stops one grant still waiting.
    pub fn veto_grant(&mut self, vault: HexBytes, grant: u64, nonce: u64, expires_at: u64, signature: HexBytes) {
        let id = vault_key(&vault);
        let mut loaded = storage::load(&id);
        let caller = cold_caller(&id, &loaded, "veto_grant", &grant, expires_at, Some(nonce), &signature);
        loaded.row.vault.veto_grant(&caller, Intent { nonce, expires_at }, grant, now()).unwrap_or_else(|e| fail(e));
        loaded.commit(&id, Short::Reserved);
        env::log_str(&format!("undo:vetoed grant={grant}"));
    }

    /// `K_e` names a new passkey, which also signs the same digest, so the contract knows it is a real
    /// key on an allowed origin and can read its backup flags. It lands after `T_recover`.
    pub fn recover_begin(&mut self, vault: HexBytes, new_passkey: PasskeyArgs, pop_p: WebAuthn, nonce: u64, expires_at: u64, signature: HexBytes) {
        let id = vault_key(&vault);
        let mut loaded = storage::load(&id);
        let rp_id_hash: [u8; 32] = new_passkey.rp_id_hash.fixed("rp_id_hash");
        let args = (&new_passkey.pubkey.0, rp_id_hash);
        let digest = intent_digest(COLD_TAG, &id, "recover_begin", &args, expires_at, Some(nonce));
        auth::require_secp(&digest, &signature, &loaded.row.vault.k_e_intent, "K_e");
        let flags = auth::require_webauthn(&pop_p, &digest, &new_passkey.pubkey.0, &rp_id_hash, &self.config.origins);
        let caller = Caller::Cold(loaded.row.vault.k_e_intent.clone());
        let passkey = Passkey { pubkey: new_passkey.pubkey.0, rp_id_hash, backup_eligible: flags.backup_eligible, backup_state: flags.backup_state };
        loaded.row.vault.recover_begin(&caller, Intent { nonce, expires_at }, passkey, now()).unwrap_or_else(|e| fail(e));
        loaded.commit(&id, Short::Reserved);
        env::log_str("undo:recovery_begun");
    }

    /// The current passkey, at most twice between successful recoveries.
    pub fn recover_cancel(&mut self, vault: HexBytes, nonce: u64, expires_at: u64, assertion: WebAuthn) {
        let id = vault_key(&vault);
        let mut loaded = storage::load(&id);
        let caller = self.passkey_caller(&id, &loaded, "recover_cancel", &(), expires_at, Some(nonce), &assertion);
        loaded.row.vault.recover_cancel(&caller, Intent { nonce, expires_at }, now()).unwrap_or_else(|e| fail(e));
        loaded.commit(&id, Short::Reserved);
        env::log_str("undo:recovery_cancelled");
    }

    /// Anyone, after `T_recover`.
    pub fn recover_finish(&mut self, vault: HexBytes) {
        let id = vault_key(&vault);
        let mut loaded = storage::load(&id);
        loaded.row.vault.recover_finish(now()).unwrap_or_else(|e| fail(e));
        loaded.commit(&id, Short::Reserved);
        env::log_str("undo:recovered");
    }

    // ---------------------------------------------------------------- views

    pub fn instance(&self) -> InstanceView {
        let c = &self.config;
        let f = c.preset.fixed();
        InstanceView {
            preset: c.preset,
            signer: c.signer.clone(),
            domain_id: c.domain_id,
            sign_tgas: c.sign_tgas,
            callback_tgas: c.callback_tgas,
            derive_tgas: c.derive_tgas,
            operator: c.operator.clone(),
            restrict_create: c.restrict_create,
            origins: c.origins.clone(),
            network: c.network.clone(),
            policy: c.policy.into(),
            t_recover_ms: f.t_recover_ms,
            expiry_window_ms: f.expiry_window_ms,
            bump_wait_ms: f.bump_wait_ms,
            block_ms: f.block_ms,
        }
    }

    pub fn vault(&self, vault: HexBytes) -> Option<VaultView> {
        let id = vault_key(&vault);
        let loaded = storage::try_load_row(&id)?;
        let reserved = loaded.row.reserved;
        let v = &loaded.row.vault;
        let network = undo_btc::Network::from_name(&self.config.network).unwrap_or_else(|e| fail(e));
        let program: &[u8; 32] = v.vault_spk[2..].try_into().unwrap_or_else(|_| env::panic_str("bad vault script"));
        Some(VaultView {
            id: HexBytes(id.to_vec()),
            active: v.active,
            k_s: HexBytes(v.k_s.to_vec()),
            k_s_suspended: v.k_s_suspended,
            k_u: HexBytes(v.k_u.clone()),
            k_m: HexBytes(v.k_m.clone()),
            k_e_leaf: HexBytes(v.k_e_leaf.clone()),
            k_e_intent: HexBytes(v.k_e_intent.clone()),
            passkey: HexBytes(v.passkey.pubkey.clone()),
            rp_id_hash: HexBytes(v.passkey.rp_id_hash.to_vec()),
            backup_eligible: v.passkey.backup_eligible,
            backup_state: v.passkey.backup_state,
            guard: v.guard.as_ref().and_then(|g| g.parse().ok()),
            csv: v.csv_blocks,
            script_pubkey: HexBytes(v.vault_spk.clone()),
            address: undo_btc::address::p2wsh_address(network, program),
            policy: v.policy.into(),
            spend_epoch: v.spend_epoch,
            frozen_until: v.frozen_until,
            spend_nonce: v.spend_nonce,
            passkey_nonce: v.passkey_nonce,
            cold_nonce: v.cold_nonce,
            pending: v.pending.clone(),
            grants: v.grants.iter().map(|g| g.id).collect(),
            recover_cancels: v.recover_cancels,
            recovery_ready_at: v.recovery.as_ref().map(|r| r.ready_at),
            storage_credit: loaded.row.credit.into(),
            row_bytes: loaded.row_bytes,
            reserved_bytes: reserved,
        })
    }

    pub fn request(&self, vault: HexBytes, request: u64) -> Option<RequestView> {
        let id = vault_key(&vault);
        let mut loaded = storage::try_load_row(&id)?;
        loaded.fetch_request(&id, request);
        loaded.row.vault.requests.get(&request).map(RequestView::of)
    }

    pub fn script(&self, vault: HexBytes) -> HexBytes {
        let loaded = storage::load_row(&vault_key(&vault));
        HexBytes(btc::script_of(&loaded.row.vault).as_bytes().to_vec())
    }

    /// What `execute` asks the signer to sign, one digest per input.
    pub fn payloads(&self, vault: HexBytes, request: u64) -> Vec<HexBytes> {
        let id = vault_key(&vault);
        let mut loaded = storage::load_row(&id);
        loaded.fetch_request(&id, request);
        let v = &loaded.row.vault;
        let r = v.requests.get(&request).unwrap_or_else(|| env::panic_str("no such request"));
        btc::sighashes(&btc::script_of(v), &v.vault_spk, &r.inputs, &r.outputs)
            .into_iter()
            .map(|d| HexBytes(d.to_vec()))
            .collect()
    }

    /// The whole witness transaction once every input is signed. Anyone can broadcast it. After
    /// `prune_signed` this returns nothing, and the transaction is in that call's log.
    pub fn final_tx(&self, vault: HexBytes, request: u64) -> Option<HexBytes> {
        let id = vault_key(&vault);
        let mut loaded = storage::try_load_row(&id)?;
        loaded.fetch_request(&id, request);
        let r = loaded.row.vault.requests.get(&request)?;
        if r.status != RequestStatus::Signed {
            return None;
        }
        btc::final_tx(&loaded.row.vault, r).map(HexBytes)
    }

    /// Tier, delay and fee, free of charge and with no authority.
    pub fn check_propose(&self, vault: HexBytes, inputs: Vec<Utxo>, to: HexBytes, amount: u64, change: Option<u64>) -> CheckView {
        let id = vault_key(&vault);
        let mut loaded = storage::load(&id);
        let inputs: Vec<Input> = inputs.iter().map(Utxo::input).collect();
        let outputs = Outputs { dest_script: to.0, dest_value: amount, change_value: change };
        loaded.load_outpoints(&id, &inputs.iter().map(|i| i.outpoint).collect::<Vec<_>>());
        let check = loaded.row.vault.check_propose(&inputs, &outputs, now()).unwrap_or_else(|e| fail(e));
        CheckView { tier: api::tier_name(check.tier).to_string(), delay_ms: check.delay_ms, fee: check.fee, unguarded: check.unguarded }
    }

    pub fn delay_now(&self, vault: HexBytes) -> u64 {
        storage::load_row(&vault_key(&vault)).row.vault.delay_now(now())
    }

    pub fn outpoint(&self, vault: HexBytes, txid: HexBytes, vout: u32) -> OutpointView {
        let id = vault_key(&vault);
        let mut loaded = storage::load(&id);
        let point = api::outpoint(&txid, vout);
        loaded.load_outpoints(&id, &[point]);
        let v = &loaded.row.vault;
        let (state, request) = match v.outpoint_state(&point) {
            OutpointState::Free => ("Free", None),
            // A dead request frees its coins when next touched, so tell the truth here already.
            OutpointState::Pending(r) if !v.is_live(r, now()) => ("Free", None),
            OutpointState::Pending(r) => ("Pending", Some(r)),
            OutpointState::Signing(r) => ("Signing", Some(r)),
            OutpointState::Spent { request } => ("Spent", Some(request)),
        };
        OutpointView { state: state.to_string(), request, pinned_value: v.pinned_value(&point), born_at: v.ledger.get(&point).and_then(|e| e.born_at) }
    }
}

impl Undo {
    fn ask_signer_for_key(&self, id: &[u8; 32]) {
        let cfg = &self.config;
        let need = Gas::from_tgas(cfg.derive_tgas + ON_DERIVED_TGAS + GAS_MARGIN_TGAS);
        let left = env::prepaid_gas().saturating_sub(env::used_gas());
        require!(left >= need, format!("attach at least {} Tgas more", need.as_tgas()));
        let hex_id = hex::encode(id);
        let args = format!(
            r#"{{"path":"{PATH_PREFIX}{hex_id}","predecessor":"{}","domain_id":{}}}"#,
            env::current_account_id(),
            cfg.domain_id
        );
        let view = env::promise_create(
            cfg.signer.clone(),
            "derived_public_key",
            args,
            NearToken::from_yoctonear(0),
            Gas::from_tgas(cfg.derive_tgas),
        );
        env::promise_then(
            view,
            env::current_account_id(),
            "on_derived",
            format!(r#"{{"vault":"{hex_id}"}}"#),
            NearToken::from_yoctonear(0),
            Gas::from_tgas(ON_DERIVED_TGAS),
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn passkey_caller<A: BorshSerialize>(
        &self,
        id: &[u8; 32],
        loaded: &Loaded,
        method: &str,
        args: &A,
        expires_at: u64,
        nonce: Option<u64>,
        assertion: &WebAuthn,
    ) -> Caller {
        let passkey = &loaded.row.vault.passkey;
        let digest = intent_digest(PASSKEY_TAG, id, method, args, expires_at, nonce);
        auth::require_webauthn(assertion, &digest, &passkey.pubkey, &passkey.rp_id_hash, &self.config.origins);
        Caller::Passkey(passkey.pubkey.clone())
    }
}

fn cold_caller<A: BorshSerialize>(id: &[u8; 32], loaded: &Loaded, method: &str, args: &A, expires_at: u64, nonce: Option<u64>, signature: &HexBytes) -> Caller {
    let digest = intent_digest(COLD_TAG, id, method, args, expires_at, nonce);
    auth::require_secp(&digest, signature, &loaded.row.vault.k_e_intent, "K_e");
    Caller::Cold(loaded.row.vault.k_e_intent.clone())
}

/// The inputs as the spend intent commits to them.
fn spend_args(inputs: &[Input]) -> Vec<([u8; 32], u32, u64)> {
    inputs.iter().map(|i| (i.outpoint.txid, i.outpoint.vout, i.value)).collect()
}

fn signer_result() -> Option<Vec<u8>> {
    if env::promise_results_count() != 1 {
        return None;
    }
    env::promise_result_checked(0, MAX_SIGNER_RESPONSE).ok()
}

/// `"secp256k1:<base58 of x || y>"`, compressed for comparing with `K_m`.
fn parse_secp_key(raw: &[u8]) -> Option<Vec<u8>> {
    let text: String = near_sdk::serde_json::from_slice(raw).ok()?;
    let body = text.strip_prefix("secp256k1:")?;
    let bytes = bs58::decode(body).into_vec().ok()?;
    let xy: [u8; 64] = bytes.try_into().ok()?;
    Some(auth::compress(&xy).to_vec())
}

/// r || s when the signer's answer recovers to `K_m` over this digest.
fn accept_signature(digest: &[u8; 32], k_m: &[u8]) -> Option<MpcSig> {
    let raw = signer_result()?;
    let resp: SignerResponse = near_sdk::serde_json::from_slice(&raw).ok()?;
    if resp.scheme != "Secp256k1" || resp.big_r.affine_point.0.len() != 33 {
        return None;
    }
    let mut sig = Vec::with_capacity(65);
    sig.extend_from_slice(&resp.big_r.affine_point.0[1..33]);
    sig.extend_from_slice(&resp.s.scalar.0);
    if !btc::encodable(&sig) {
        return None;
    }
    sig.push(resp.recovery_id);
    if !auth::secp_signed_by(digest, &sig, k_m) {
        return None;
    }
    sig.truncate(64);
    Some(sig)
}
