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
    CancelAuth, ChatCompletion, CheckView, CreateArgs, GrantView, GuardAnswer, HexBytes, InstanceView, ModelSignerView,
    OutpointView, PasskeyArgs, PolicyArgs, Preset, RequestView, SignerResponse, StatsView, StatusView, UpgradeView, Utxo,
    VaultView, WebAuthn,
};
use auth::{intent_digest, COLD_TAG, OPERATOR_TAG, PASSKEY_TAG, SPEND_TAG};
use near_sdk::borsh::BorshSerialize;
use near_sdk::{env, near, require, AccountId, Gas, NearToken, PanicOnDefault};
use storage::{Loaded, Row, Short};
use undo_core::{
    utc_text, Bounds, Caller, Input, Intent, MpcSig, OutpointState, Outputs, Passkey, Policy, PolicyOutcome, ProposeArgs,
    Reason, RequestStatus, SignedOutcome, UpgradeQueue, Vault, GUARD_MODEL,
};

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
/// Largest model response `assess` will read. A completion with this template is about 1 KB.
const MAX_GUARD_RESPONSE: usize = 16_384;
/// Registered model signers. Each is one signature check on every `assess`.
const MAX_MODEL_SIGNERS: usize = 8;
/// The team test set taken out of the public count.
const MAX_STATS_EXCLUDED: usize = 32;
/// Gas for the new code's `migrate`, which reads the state to prove it can.
const MIGRATE_TGAS: u64 = 20;

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
    /// A separate contract-level P-256 key held by the operator: it can stop an upgrade and do nothing
    /// else, so losing the operator account does not mean losing the wait.
    operator_passkey: Vec<u8>,
    operator_rp_id_hash: [u8; 32],
    guard_model: String,
    /// A bad signer can only cause delay, so the operator may add one at once.
    model_signers: Vec<(String, [u8; 32])>,
    stats_excluded: Vec<Vec<u8>>,
}

/// Fixed width, so a count changing never changes the contract's own storage.
#[derive(Default)]
#[near(serializers = [borsh])]
struct Stats {
    vaults_created: u64,
    vaults_active: u64,
    passkeys_completed: u64,
}

/// The signer and its constants have no setter. They change only through the upgrade queue: new code
/// whose `migrate` sets them, after the same public wait.
#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct Undo {
    config: Config,
    upgrade: UpgradeQueue,
    stats: Stats,
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
        operator_passkey: PasskeyArgs,
    ) -> Self {
        let chain = undo_btc::Network::from_name(&network).unwrap_or_else(|_| env::panic_str("unknown network"));
        // Real coins go only through the proof preset, and nobody but the operator makes a vault there:
        // the contract cannot limit deposits to an address, so an open door would invite real money.
        require!((preset == Preset::MainnetProof) == (chain == undo_btc::Network::Mainnet), "preset and network do not match");
        require!(preset != Preset::MainnetProof || restrict_create, "the mainnet preset needs restrict_create");
        let (policy, bounds) = match preset {
            Preset::TestCoin => (Policy::test_coin(outflow_cap_24h), Bounds::test_coin(outflow_cap_24h)),
            Preset::MainnetProof => (Policy::mainnet_proof(outflow_cap_24h), Bounds::mainnet(outflow_cap_24h)),
        };
        require!(preset.upgrade().holds(&bounds), "T_upgrade does not outlast a withdrawal by the reaction window");
        require!(operator_passkey.pubkey.0.len() == 33, "the operator passkey must be a compressed P-256 key");
        let operator_rp_id_hash: [u8; 32] = operator_passkey.rp_id_hash.fixed("rp_id_hash");
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
                operator_passkey: operator_passkey.pubkey.0,
                operator_rp_id_hash,
                guard_model: GUARD_MODEL.to_string(),
                model_signers: Vec::new(),
                stats_excluded: Vec::new(),
            },
            upgrade: UpgradeQueue::default(),
            stats: Stats::default(),
        }
    }

    /// The upgrade path's other half. It runs in the same batch as the deploy, so new code that cannot
    /// read this state fails here and the old code stays.
    #[private]
    pub fn migrate(&self) {
        env::log_str("undo:migrated");
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
        self.stats.vaults_created += 1;
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
            now: now(),
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
            self.stats.vaults_active += 1;
            loaded.commit(&id, Short::Reserved);
            env::log_str(&format!("undo:active vault={}", hex::encode(id)));
        } else {
            self.stats.vaults_created = self.stats.vaults_created.saturating_sub(1);
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
        memo: Option<String>,
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
        let args = (spend_args(&inputs), &outputs.dest_script, outputs.dest_value, outputs.change_value, &memo);
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
                ProposeArgs { inputs, outputs, half_sigs: half_sigs.into_iter().map(|s| s.0).collect(), memo },
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
        self.note_completed(&mut loaded);
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

    /// `K_p`, at once: removes a known destination, kills pending requests that pay it, and drops an add
    /// still waiting. Removing power never waits, and needs no credit.
    pub fn remove_destination(&mut self, vault: HexBytes, script: HexBytes, nonce: u64, expires_at: u64, assertion: WebAuthn) {
        let id = vault_key(&vault);
        let mut loaded = storage::load(&id);
        // The requests it kills free their coins here, so those ledger entries must be in hand.
        for request in loaded.row.vault.pending.clone() {
            if loaded.row.vault.requests.get(&request).is_some_and(|r| r.outputs.dest_script == script.0) {
                loaded.load_inputs(&id, request);
            }
        }
        let caller = self.passkey_caller(&id, &loaded, "remove_destination", &script.0, expires_at, Some(nonce), &assertion);
        loaded.row.vault.remove_destination(&caller, Intent { nonce, expires_at }, &script.0, now()).unwrap_or_else(|e| fail(e));
        loaded.commit(&id, Short::Reserved);
        env::log_str(&format!("undo:destination_removed script={}", hex::encode(&script.0)));
    }

    /// `K_p`. A destination becomes known only after `T_new`, and `K_e` can veto it.
    pub fn add_destination(&mut self, vault: HexBytes, script: HexBytes, nonce: u64, expires_at: u64, assertion: WebAuthn) -> u64 {
        let id = vault_key(&vault);
        let mut loaded = storage::load(&id);
        let caller = self.passkey_caller(&id, &loaded, "add_destination", &script.0, expires_at, Some(nonce), &assertion);
        let grant = loaded.row.vault.add_destination(&caller, Intent { nonce, expires_at }, script.0, now()).unwrap_or_else(|e| fail(e));
        loaded.commit(&id, Short::Refuse);
        env::log_str(&format!("undo:grant_begun grant={grant} kind=add_destination"));
        grant
    }

    /// `K_p`. Tightening lands at once and needs no credit, and returns nothing. Loosening any field
    /// waits `T_new` as one grant, which `K_e` can veto, and returns its id. The instance's bounds hold
    /// either way, so `T_upgrade` still outlasts any withdrawal and the fee cap keeps a floor.
    pub fn set_policy(&mut self, vault: HexBytes, policy: PolicyArgs, nonce: u64, expires_at: u64, assertion: WebAuthn) -> Option<u64> {
        let id = vault_key(&vault);
        let mut loaded = storage::load(&id);
        let policy = Policy::from(policy);
        let caller = self.passkey_caller(&id, &loaded, "set_policy", &policy, expires_at, Some(nonce), &assertion);
        match loaded.row.vault.set_policy(&caller, Intent { nonce, expires_at }, policy, now()).unwrap_or_else(|e| fail(e)) {
            PolicyOutcome::Applied => {
                loaded.commit(&id, Short::Reserved);
                env::log_str("undo:policy_tightened");
                None
            }
            PolicyOutcome::Grant(grant) => {
                loaded.commit(&id, Short::Refuse);
                env::log_str(&format!("undo:grant_begun grant={grant} kind=loosen_policy"));
                Some(grant)
            }
        }
    }

    /// `K_p`, after `T_new`, and `K_e` can veto. `None` removes the guard, which counts as loosening.
    /// The new guard counts as offline until its first heartbeat.
    pub fn set_guard(&mut self, vault: HexBytes, guard: Option<AccountId>, nonce: u64, expires_at: u64, assertion: WebAuthn) -> u64 {
        let id = vault_key(&vault);
        let mut loaded = storage::load(&id);
        let caller = self.passkey_caller(&id, &loaded, "set_guard", &guard, expires_at, Some(nonce), &assertion);
        let grant = loaded.row.vault.set_guard(&caller, Intent { nonce, expires_at }, guard.map(|a| a.to_string()), now()).unwrap_or_else(|e| fail(e));
        loaded.commit(&id, Short::Refuse);
        env::log_str(&format!("undo:grant_begun grant={grant} kind=set_guard"));
        grant
    }

    /// `K_p`, at once: back to the base unlock, never earlier. A request gets one hold in its life, so
    /// the guard cannot put it back.
    pub fn clear_hold(&mut self, vault: HexBytes, request: u64, nonce: u64, expires_at: u64, assertion: WebAuthn) {
        let id = vault_key(&vault);
        let mut loaded = storage::load(&id);
        loaded.fetch_request(&id, request);
        let caller = self.passkey_caller(&id, &loaded, "clear_hold", &request, expires_at, Some(nonce), &assertion);
        loaded.row.vault.clear_hold(&caller, Intent { nonce, expires_at }, request, now()).unwrap_or_else(|e| fail(e));
        loaded.commit(&id, Short::Reserved);
        env::log_str(&format!("undo:hold_cleared request={request}"));
    }

    /// The guard's own function-call key, one call per vault it guards. A first beat grows the row, and
    /// a guard that cannot pay for it just stays offline, which only makes delays longer.
    pub fn heartbeat(&mut self, vault: HexBytes) {
        let id = vault_key(&vault);
        let mut loaded = storage::load_row(&id);
        let caller = Caller::Guard(env::predecessor_account_id().to_string());
        loaded.row.vault.heartbeat(&caller, now()).unwrap_or_else(|e| fail(e));
        loaded.commit(&id, Short::Refuse);
    }

    /// The guard's key, with the model's answer and its signature. The contract rebuilds the request
    /// bytes itself, so the guard can choose whether to submit and which answer, but not what was asked.
    /// A hold adds `hold_ms` at most once. A no-hold is recorded too, which makes a skipped request
    /// readable. Nothing grows, so no credit is needed.
    pub fn assess(&mut self, vault: HexBytes, request: u64, response_bytes: HexBytes, signature: HexBytes) {
        let id = vault_key(&vault);
        require!(response_bytes.0.len() <= MAX_GUARD_RESPONSE, "response too large");
        let mut loaded = storage::load(&id);
        loaded.fetch_request(&id, request);
        let cfg = &self.config;
        let stored = loaded.row.vault.requests.get(&request).unwrap_or_else(|| fail(undo_core::Error::RequestNotFound));
        let body = undo_core::request_body(&cfg.guard_model, env::current_account_id().as_str(), &hex::encode(id), stored);
        let text = auth::model_signed_text(&cfg.guard_model, body.as_bytes(), &response_bytes.0);
        let sig: [u8; 64] = signature.fixed("signature");
        let signed = cfg
            .model_signers
            .iter()
            .any(|(model, key)| *model == cfg.guard_model && env::ed25519_verify(&sig, text.as_bytes(), key));
        require!(signed, "not signed by a registered signer for this model");

        let completion: ChatCompletion = near_sdk::serde_json::from_slice(&response_bytes.0).unwrap_or_else(|_| env::panic_str("response is not a chat completion"));
        let content = completion.choices.first().map(|c| c.message.content.as_str()).unwrap_or_else(|| env::panic_str("response has no choice"));
        let answer: GuardAnswer = near_sdk::serde_json::from_str(content).unwrap_or_else(|_| env::panic_str("answer is not the agreed JSON"));
        let reason = Reason::from_name(&answer.reason).unwrap_or_else(|| env::panic_str("answer has an unknown reason"));

        let caller = Caller::Guard(env::predecessor_account_id().to_string());
        loaded.row.vault.assess(&caller, request, answer.hold, reason, now()).unwrap_or_else(|e| fail(e));
        loaded.commit(&id, Short::Reserved);
        env::log_str(&format!("undo:assessed request={request} hold={} reason={} model={}", answer.hold, reason.name(), cfg.guard_model));
    }

    // ---------------------------------------------------------------- operator

    /// At once: a bad signer can only cause delay, so this needs no public wait.
    pub fn add_model_signer(&mut self, model: String, signer: HexBytes) {
        self.require_operator();
        require!(self.config.model_signers.len() < MAX_MODEL_SIGNERS, "too many model signers");
        self.config.model_signers.push((model.clone(), signer.fixed("signer")));
        env::log_str(&format!("undo:model_signer model={model} signer={}", hex::encode(&signer.0)));
    }

    /// At once, for the same reason, and only to a model with a signer. A model that is retired has to
    /// have a way out, and `guard_prompt` shows what is being asked.
    pub fn set_guard_model(&mut self, model: String) {
        self.require_operator();
        require!(self.config.model_signers.iter().any(|(m, _)| *m == model), "no signer for that model");
        env::log_str(&format!("undo:guard_model model={model}"));
        self.config.guard_model = model;
    }

    /// Takes a team test passkey out of the public count, and lists it.
    pub fn stats_exclude(&mut self, passkey: HexBytes) {
        self.require_operator();
        require!(self.config.stats_excluded.len() < MAX_STATS_EXCLUDED, "too many excluded passkeys");
        if !self.config.stats_excluded.contains(&passkey.0) {
            self.config.stats_excluded.push(passkey.0);
        }
    }

    /// The operator starts the public wait for new code, by its hash. One at a time.
    pub fn upgrade_propose(&mut self, code_hash: HexBytes) {
        self.require_operator();
        let hash: [u8; 32] = code_hash.fixed("code_hash");
        let pending = self.upgrade.propose(hash, &self.config.preset.upgrade(), now()).unwrap_or_else(|e| fail(e));
        env::log_str(&format!("undo:upgrade_proposed code_hash={} unlock={} expires={}", hex::encode(hash), pending.unlock_at, pending.expires_at));
    }

    /// The operator passkey. The intent names the proposal, so an old assertion cannot stop a later one
    /// and no nonce can go stale. A cancel means a new full `T_upgrade`.
    pub fn upgrade_cancel(&mut self, expires_at: u64, assertion: WebAuthn) {
        let pending = self.upgrade.pending.unwrap_or_else(|| fail(undo_core::Error::NoUpgrade));
        let args = (pending.code_hash, pending.proposed_at);
        let digest = intent_digest(OPERATOR_TAG, &[0; 32], "upgrade_cancel", &args, expires_at, None);
        require!(now() <= expires_at, "intent expired");
        let cfg = &self.config;
        auth::require_webauthn(&assertion, &digest, &cfg.operator_passkey, &cfg.operator_rp_id_hash, &cfg.origins);
        self.upgrade.cancel().unwrap_or_else(|e| fail(e));
        env::log_str(&format!("undo:upgrade_cancelled code_hash={}", hex::encode(pending.code_hash)));
    }

    /// Anyone, with the code as the raw call input, whose hash matches, once it unlocks and before it
    /// runs out. Deploys to this account through its own receipt, so it needs no access key: the
    /// contract can have none. The new code's `migrate` runs in the same batch, so code that cannot read
    /// this state does not land. The attempt uses up the approval either way.
    pub fn upgrade_apply(&mut self) {
        let code = env::input().unwrap_or_else(|| env::panic_str("no code"));
        let pending = self.upgrade.take_for_apply(env::sha256_array(&code), now()).unwrap_or_else(|e| fail(e));
        let promise = env::promise_batch_create(&env::current_account_id());
        env::promise_batch_action_deploy_contract(promise, &code);
        env::promise_batch_action_function_call(promise, "migrate", &[], NearToken::from_yoctonear(0), Gas::from_tgas(MIGRATE_TGAS));
        // So the transaction's own status says whether the code landed.
        env::promise_return(promise);
        env::log_str(&format!("undo:upgrade_applied code_hash={}", hex::encode(pending.code_hash)));
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
        if outcome == (SignedOutcome::Stored { complete: true }) {
            self.note_completed(&mut loaded);
        }
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
        let rules = c.preset.upgrade();
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
            block_ms: f.block_ms,
            csv_min: f.csv_min,
            csv_max: f.csv_max,
            t_upgrade_ms: rules.t_upgrade_ms,
            upgrade_expiry_ms: rules.expiry_ms,
            reaction_window_ms: rules.reaction_window_ms(&c.bounds),
            pending_upgrade: self.upgrade.pending.map(|p| UpgradeView {
                code_hash: HexBytes(p.code_hash.to_vec()),
                proposed_at: p.proposed_at,
                unlock_at: p.unlock_at,
                expires_at: p.expires_at,
            }),
            operator_passkey: HexBytes(c.operator_passkey.clone()),
            guard_model: c.guard_model.clone(),
            model_signers: c.model_signers.iter().map(|(model, key)| ModelSignerView { model: model.clone(), signer: HexBytes(key.to_vec()) }).collect(),
        }
    }

    /// Plain language. With no vault, the instance: what the operator could do next and when. With a
    /// vault, also that vault's state. Works with one curl line and no key. A contract cannot see its
    /// relay or dispenser, so those report themselves on the page.
    pub fn status(&self, vault: Option<HexBytes>) -> StatusView {
        let mut ok = true;
        let mut lines = Vec::new();
        if let Some(vault) = vault {
            let id = vault_key(&vault);
            let loaded = storage::load(&id);
            let (vault_ok, vault_lines) = loaded.row.vault.status_lines(now());
            ok &= vault_ok;
            lines.extend(vault_lines);
            if loaded.row.credit < storage::request_floor() {
                ok = false;
                lines.push("storage credit low: new proposals stop until anyone tops it up. Cancel, rotate, freeze and execute do not need it".to_string());
            }
        }
        let c = &self.config;
        let rules = c.preset.upgrade();
        match self.upgrade.pending {
            Some(p) if now() > p.expires_at => lines.push(format!("an upgrade approval ran out at {}: it can no longer land, and a new one needs the full wait", utc_text(p.expires_at))),
            Some(p) => {
                ok = false;
                lines.push(format!(
                    "upgrade pending: code {} can land from {} until {}. Any owner can leave before then, if they react within the reaction window of {} min",
                    hex::encode(p.code_hash),
                    utc_text(p.unlock_at),
                    utc_text(p.expires_at),
                    rules.reaction_window_ms(&c.bounds) / 60_000,
                ));
            }
            None => lines.push(format!("no upgrade pending. New code would wait {} min in public", rules.t_upgrade_ms / 60_000)),
        }
        if !c.model_signers.iter().any(|(m, _)| *m == c.guard_model) {
            lines.push(format!("no signer registered for {}: no new holds, and every other rule still holds", c.guard_model));
        }
        StatusView { ok, lines }
    }

    /// The public count. It counts distinct passkeys that completed a cancel or a spend, so one person
    /// with many vaults on one passkey counts once. Sybil cannot be ruled out.
    pub fn stats(&self) -> StatsView {
        let excluded = &self.config.stats_excluded;
        let excluded_that_completed = excluded.iter().filter(|p| storage::passkey_counted(p)).count() as u64;
        StatsView {
            vaults_created: self.stats.vaults_created,
            vaults_active: self.stats.vaults_active,
            passkeys_completed: self.stats.passkeys_completed,
            excluded_passkeys: excluded.iter().map(|p| HexBytes(p.clone())).collect(),
            excluded_that_completed,
            counted: self.stats.passkeys_completed.saturating_sub(excluded_that_completed),
        }
    }

    /// The exact request body the guard must send, as a string whose UTF-8 bytes are what a model signs
    /// over. Built here from the template and the snapshot taken at propose.
    pub fn guard_prompt(&self, vault: HexBytes, request: u64) -> String {
        let id = vault_key(&vault);
        let mut loaded = storage::load_row(&id);
        loaded.fetch_request(&id, request);
        let stored = loaded.row.vault.requests.get(&request).unwrap_or_else(|| fail(undo_core::Error::RequestNotFound));
        undo_core::request_body(&self.config.guard_model, env::current_account_id().as_str(), &hex::encode(id), stored)
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
            guard_online: v.guard_online(now()),
            last_heartbeat: v.last_heartbeat,
            created_at: v.created_at,
            known: v.known.iter().map(|s| HexBytes(s.clone())).collect(),
            fee_used_24h: v.fee_used_24h(now()),
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
            grant_list: v.grants.iter().map(|g| GrantView { id: g.id, kind: g.kind.describe().to_string(), begun_at: g.begun_at, ready_at: g.ready_at }).collect(),
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
    fn require_operator(&self) {
        require!(env::predecessor_account_id() == self.config.operator, "only the operator");
    }

    /// The first completed cancel or spend puts this vault's passkey in the public count.
    fn note_completed(&mut self, loaded: &mut Loaded) {
        if loaded.row.vault.mark_completed() && loaded.count_passkey() {
            self.stats.passkeys_completed += 1;
        }
    }

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
