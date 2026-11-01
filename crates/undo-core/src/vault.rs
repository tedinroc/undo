//! The vault: keys, request lifecycle, outpoint ledger, grants, freeze and recovery.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::Error;
use crate::policy::{
    Bounds, Fixed, Policy, DAY, FEE_OVERRIDE_DIVISOR, HEARTBEAT_STALE_MS, MAX_GRANTS, MAX_INPUTS,
    MAX_PENDING, MIN_FEE_RATE, RECOVERY_CANCEL_CAP, RETRY_AFTER_BLOCKS,
};
use crate::request::{Request, RequestKind, RequestStatus, Tier};
use crate::types::{
    dust_limit, estimate_vsize, Caller, GrantId, HalfSig, Input, Intent, MpcSig, Ms, Outpoint,
    Outputs, Passkey, RequestId, Sats, ScriptKind, MAX_MONEY,
};

/// Where an outpoint stands. An outpoint with no ledger entry is free and unpinned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub enum OutpointState {
    Free,
    Pending(RequestId),
    Signing(RequestId),
    /// An MPC signature is presumed public. `request` may already be deleted.
    Spent { request: RequestId },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct LedgerEntry {
    pub state: OutpointState,
    /// First declared value that reached `execute`. Never changes once set.
    pub pinned_value: Option<Sats>,
    /// When this outpoint last entered signing. `T_stuck` counts from here.
    pub signing_since: Option<Ms>,
    /// When a transaction this vault signed first went out with this coin as an output paying the
    /// vault's own script. Never changes once set. [`Vault::chain_wait_ms`] counts from here.
    pub born_at: Option<Ms>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub enum GrantKind {
    RotateSpend { new_k_s: [u8; 32] },
    AddDestination { script: Vec<u8> },
    LoosenPolicy { policy: Policy },
    SetGuard { guard: Option<String> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct Grant {
    pub id: GrantId,
    pub kind: GrantKind,
    pub begun_at: Ms,
    pub ready_at: Ms,
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct Recovery {
    pub new_passkey: Passkey,
    pub begun_at: Ms,
    pub ready_at: Ms,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
struct SelfSpendSlot {
    last_at: Option<Ms>,
    /// The Pending request that used the slot, while the use can still be refunded.
    holder: Option<RequestId>,
    prev_at: Option<Ms>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
struct OutflowEntry {
    at: Ms,
    amount: Sats,
    request: RequestId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateArgs {
    pub k_s: [u8; 32],
    pub k_u: Vec<u8>,
    pub k_m: Vec<u8>,
    pub k_e_leaf: Vec<u8>,
    pub k_e_intent: Vec<u8>,
    pub passkey: Passkey,
    pub guard: Option<String>,
    pub csv_blocks: u32,
    /// The vault's own P2WSH script pubkey, computed by the shell from the witness script.
    pub vault_spk: Vec<u8>,
    pub policy: Policy,
    pub fixed: Fixed,
    pub bounds: Bounds,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposeArgs {
    pub inputs: Vec<Input>,
    pub outputs: Outputs,
    pub half_sigs: Vec<HalfSig>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProposeCheck {
    pub tier: Tier,
    pub delay_ms: Ms,
    pub fee: Sats,
    pub unguarded: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Proposed {
    pub id: RequestId,
    pub tier: Tier,
    pub base_unlock: Ms,
    pub expires_at: Ms,
    pub fee: Sats,
}

/// Which inputs the shell must ask the signer for, under which attempt number.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignBatch {
    pub attempt: u32,
    pub indices: Vec<usize>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignedOutcome {
    Stored { complete: bool },
    /// The signer reported failure. The input stays missing and retry can ask again.
    Failed,
    DroppedUnknownRequest,
    DroppedStaleAttempt,
    DroppedNotInFlight,
    DroppedDigestMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyOutcome {
    Applied,
    Grant(GrantId),
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct Vault {
    pub active: bool,
    pub k_s: [u8; 32],
    pub k_s_suspended: bool,
    pub k_u: Vec<u8>,
    pub k_m: Vec<u8>,
    pub k_e_leaf: Vec<u8>,
    pub k_e_intent: Vec<u8>,
    pub passkey: Passkey,
    pub guard: Option<String>,
    pub last_heartbeat: Option<Ms>,
    pub csv_blocks: u32,
    pub vault_spk: Vec<u8>,
    pub policy: Policy,
    pub fixed: Fixed,
    pub bounds: Bounds,
    pub spend_epoch: u64,
    pub frozen_until: Option<Ms>,
    pub spend_nonce: u64,
    pub passkey_nonce: u64,
    pub cold_nonce: u64,
    /// Not in the stored row. The contract keeps each request and each ledger entry under its own
    /// storage key and loads only what a call touches, so a vault's history never weighs on a
    /// callback. A method's result depends on these maps holding every entry it reads: an entry
    /// missing here reads as a free, unpinned outpoint.
    #[cfg_attr(feature = "borsh", borsh(skip))]
    pub requests: BTreeMap<RequestId, Request>,
    pub pending: Vec<RequestId>,
    #[cfg_attr(feature = "borsh", borsh(skip))]
    pub ledger: BTreeMap<Outpoint, LedgerEntry>,
    pub known: BTreeSet<Vec<u8>>,
    pub grants: Vec<Grant>,
    pub recovery: Option<Recovery>,
    pub recover_cancels: u8,
    next_request: RequestId,
    next_grant: GrantId,
    slot: SelfSpendSlot,
    fee_window: Vec<(Ms, Sats)>,
    outflow_window: Vec<OutflowEntry>,
}

impl Vault {
    // ---------------------------------------------------------------- creation

    /// Stores the vault as Inactive. The shell calls [`Vault::activate`] from its
    /// `derived_public_key` callback.
    pub fn create(args: CreateArgs) -> Result<Vault, Error> {
        // Block-based and minimally encoded only: csv=0, bit 31 and time-type operands all let
        // K_e spend with no wait, and every one of them falls outside this range.
        if args.csv_blocks == 0 || args.csv_blocks > 65_535 {
            return Err(Error::BadCsv);
        }
        // The instance's own range. The longest freeze is one CSV period, so a CSV far past what the
        // instance documents would let one signature freeze a vault for over a year.
        if args.csv_blocks < args.fixed.csv_min || args.csv_blocks > args.fixed.csv_max {
            return Err(Error::CsvOutOfRange { min: args.fixed.csv_min, max: args.fixed.csv_max });
        }
        let compressed = |k: &[u8]| k.len() == 33 && (k[0] == 2 || k[0] == 3);
        if !compressed(&args.k_u) || !compressed(&args.k_m) || !compressed(&args.k_e_leaf) {
            return Err(Error::BadKey);
        }
        let keys: [&[u8]; 6] = [
            &args.k_s,
            &args.k_u,
            &args.k_m,
            &args.k_e_leaf,
            &args.k_e_intent,
            &args.passkey.pubkey,
        ];
        for (i, a) in keys.iter().enumerate() {
            if a.is_empty() {
                return Err(Error::BadKey);
            }
            if keys[i + 1..].iter().any(|b| a == b) {
                return Err(Error::DuplicateKeys);
            }
        }
        if ScriptKind::of(&args.vault_spk) != Some(ScriptKind::P2wsh) {
            return Err(Error::BadVaultScript);
        }
        if !args.bounds.allows(&args.policy) {
            return Err(Error::PolicyOutOfBounds);
        }
        Ok(Vault {
            active: false,
            k_s: args.k_s,
            k_s_suspended: false,
            k_u: args.k_u,
            k_m: args.k_m,
            k_e_leaf: args.k_e_leaf,
            k_e_intent: args.k_e_intent,
            passkey: args.passkey,
            guard: args.guard,
            last_heartbeat: None,
            csv_blocks: args.csv_blocks,
            vault_spk: args.vault_spk,
            policy: args.policy,
            fixed: args.fixed,
            bounds: args.bounds,
            spend_epoch: 0,
            frozen_until: None,
            spend_nonce: 0,
            passkey_nonce: 0,
            cold_nonce: 0,
            requests: BTreeMap::new(),
            pending: Vec::new(),
            ledger: BTreeMap::new(),
            known: BTreeSet::new(),
            grants: Vec::new(),
            recovery: None,
            recover_cancels: 0,
            next_request: 0,
            next_grant: 0,
            slot: SelfSpendSlot::default(),
            fee_window: Vec::new(),
            outflow_window: Vec::new(),
        })
    }

    /// `signer_key` is what the signer's `derived_public_key` returned. A wrong `K_m` never activates.
    pub fn activate(&mut self, signer_key: &[u8]) -> Result<(), Error> {
        if self.active {
            return Err(Error::AlreadyActive);
        }
        if signer_key != self.k_m.as_slice() {
            return Err(Error::KmMismatch);
        }
        self.active = true;
        Ok(())
    }

    // ---------------------------------------------------------------- views

    pub fn is_frozen(&self, now: Ms) -> bool {
        self.frozen_until.is_some_and(|until| now < until)
    }

    pub fn csv_period_ms(&self) -> Ms {
        (self.csv_blocks as Ms).saturating_mul(self.fixed.block_ms)
    }

    pub fn guard_online(&self, now: Ms) -> bool {
        self.guard.is_some()
            && self
                .last_heartbeat
                .is_some_and(|beat| now.saturating_sub(beat) <= HEARTBEAT_STALE_MS)
    }

    /// New-destination delay right now. It fails slow: a dead guard doubles the delay and blocks
    /// nothing.
    pub fn delay_now(&self, now: Ms) -> Ms {
        if self.guard_online(now) {
            self.policy.t_new_ms
        } else {
            self.policy.t_new_unguarded_ms
        }
    }

    /// Pending, current epoch and not expired. Dead requests may still sit in `pending` until the
    /// next state change sweeps them.
    pub fn is_live(&self, id: RequestId, now: Ms) -> bool {
        self.requests.get(&id).is_some_and(|r| {
            r.status == RequestStatus::Pending && !self.is_dead(r, now)
        })
    }

    pub fn live_pending(&self, now: Ms) -> Vec<RequestId> {
        self.pending.iter().copied().filter(|id| self.is_live(*id, now)).collect()
    }

    pub fn outpoint_state(&self, outpoint: &Outpoint) -> OutpointState {
        self.ledger.get(outpoint).map_or(OutpointState::Free, |e| e.state)
    }

    pub fn pinned_value(&self, outpoint: &Outpoint) -> Option<Sats> {
        self.ledger.get(outpoint).and_then(|e| e.pinned_value)
    }

    pub fn fee_used_24h(&self, now: Ms) -> Sats {
        self.fee_window
            .iter()
            .filter(|(at, _)| now < at.saturating_add(DAY))
            .fold(0, |sum, (_, amount)| sum.saturating_add(*amount))
    }

    pub fn outflow_used_24h(&self, now: Ms) -> Sats {
        self.outflow_window
            .iter()
            .filter(|e| now < e.at.saturating_add(DAY))
            .fold(0, |sum, e| sum.saturating_add(e.amount))
    }

    /// Entries the 24 h fee window holds in the row. Each is 16 bytes on every later call, so this is
    /// what keeps a vault's row bounded by what it did in the last day.
    pub fn fee_window_entries(&self) -> usize {
        self.fee_window.len()
    }

    /// The same for the 24 h outflow window. A known destination's tier reads only the last day, so
    /// this matters for the row's size and not for any rule.
    pub fn outflow_window_entries(&self) -> usize {
        self.outflow_window.len()
    }

    /// How long a coin this vault's own signed transaction paid back to itself must wait before it
    /// can go into another transaction that pays back to the vault. A signature cannot be taken back
    /// and the contract cannot see Bitcoin, so a thief can sign a whole chain of these before
    /// broadcasting any of them, and each link restarts CSV once. This spaces the links. Three
    /// quarters of the CSV period, so a refresh at the page's 80% warning still goes through.
    pub fn chain_wait_ms(&self) -> Ms {
        self.csv_period_ms().saturating_mul(3) / 4
    }

    pub fn self_spend_slot_free_at(&self) -> Option<Ms> {
        self.slot.last_at.map(|at| at.saturating_add(self.policy.t_new_ms))
    }

    /// Tier, delay and fee a proposal would get, with no authority needed and no state changed.
    pub fn check_propose(
        &self,
        inputs: &[Input],
        outputs: &Outputs,
        now: Ms,
    ) -> Result<ProposeCheck, Error> {
        let mut scratch = self.clone();
        scratch.sweep(now);
        scratch.require_active()?;
        scratch.require_not_frozen(now)?;
        scratch.plan_propose(inputs, outputs, now)
    }

    // ---------------------------------------------------------------- spend-key methods

    pub fn propose(
        &mut self,
        caller: &Caller,
        intent: Intent,
        args: ProposeArgs,
        now: Ms,
    ) -> Result<Proposed, Error> {
        self.sweep(now);
        self.require_active()?;
        self.require_not_frozen(now)?;
        self.auth_spend(caller, intent, now)?;
        let plan = self.plan_propose(&args.inputs, &args.outputs, now)?;
        if args.half_sigs.len() != args.inputs.len() {
            return Err(Error::HalfSigCount);
        }
        let outflow = if plan.tier == Tier::SelfSpend { 0 } else { args.outputs.dest_value };
        let restarts_csv = self.restarts_csv(&args.outputs);
        let base_unlock = now.saturating_add(plan.delay_ms);
        let id = self.insert_pending(
            RequestKind::Normal,
            args.inputs,
            args.half_sigs,
            args.outputs,
            plan.tier,
            plan.fee,
            0,
            now,
            base_unlock,
            base_unlock.saturating_add(self.fixed.expiry_window_ms),
        );
        if restarts_csv {
            self.take_slot(id, now);
        }
        if outflow > 0 {
            self.outflow_window.push(OutflowEntry { at: now, amount: outflow, request: id });
        }
        Ok(self.proposed(id))
    }

    /// Same inputs, same declared values, same destination, higher fee. Creates a new request id and
    /// deletes the old request; it never mutates one. The only way a pinned outpoint enters a
    /// multi-input request, and safe because no declared value can differ.
    pub fn bump(
        &mut self,
        caller: &Caller,
        intent: Intent,
        old_id: RequestId,
        new_fee: Sats,
        half_sigs: Vec<HalfSig>,
        now: Ms,
    ) -> Result<Proposed, Error> {
        self.sweep(now);
        self.require_active()?;
        self.require_not_frozen(now)?;
        self.auth_spend(caller, intent, now)?;
        let old = self.requests.get(&old_id).ok_or(Error::RequestNotFound)?.clone();
        let first_execute_at = old.first_execute_at.ok_or(Error::NotExecuted)?;
        let ready_at = first_execute_at.saturating_add(self.fixed.bump_wait_ms);
        if now < ready_at {
            return Err(Error::BumpTooSoon { ready_at });
        }
        if new_fee <= old.fee {
            return Err(Error::BumpNotHigher);
        }
        if half_sigs.len() != old.inputs.len() {
            return Err(Error::HalfSigCount);
        }
        let delta = new_fee - old.fee;
        let mut outputs = old.outputs.clone();
        match outputs.change_value {
            Some(change) => {
                let reduced = change.checked_sub(delta).ok_or(Error::ChangeBelowDust)?;
                if reduced < dust_limit(ScriptKind::P2wsh) {
                    return Err(Error::ChangeBelowDust);
                }
                outputs.change_value = Some(reduced);
            }
            None => {
                let reduced = outputs.dest_value.checked_sub(delta).ok_or(Error::DustOutput)?;
                let kind = ScriptKind::of(&outputs.dest_script).ok_or(Error::BadDestination)?;
                if reduced < dust_limit(kind) {
                    return Err(Error::DustOutput);
                }
                outputs.dest_value = reduced;
            }
        }
        self.check_fee_ceiling(old.tier, new_fee, &outputs)?;
        if self.pending.len() >= MAX_PENDING {
            return Err(Error::PendingCap);
        }

        self.requests.remove(&old_id);
        // base_unlock is inherited, so a bump can never reach an earlier unlock. The old request's
        // outflow stays counted: its signature may still confirm.
        let id = self.insert_pending(
            RequestKind::Bump { predecessor: old_id },
            old.inputs,
            half_sigs,
            outputs,
            old.tier,
            new_fee,
            old.fee,
            now,
            old.base_unlock,
            now.saturating_add(self.fixed.expiry_window_ms),
        );
        Ok(self.proposed(id))
    }

    /// After `T_stuck`, a single-input request back to the vault's own script, at `T_known`. May
    /// re-declare the value. A single-input digest cannot combine with any other session, because
    /// `hashPrevouts` covers only that input. Supersedes the request that held the outpoint.
    pub fn reclaim(
        &mut self,
        caller: &Caller,
        intent: Intent,
        outpoint: Outpoint,
        value: Sats,
        fee: Sats,
        half_sig: HalfSig,
        now: Ms,
    ) -> Result<Proposed, Error> {
        self.sweep(now);
        self.require_active()?;
        self.require_not_frozen(now)?;
        self.auth_spend(caller, intent, now)?;
        let entry = *self.ledger.get(&outpoint).ok_or(Error::NotReclaimable)?;
        let owner = match entry.state {
            OutpointState::Signing(id) => id,
            OutpointState::Spent { request } => request,
            OutpointState::Free | OutpointState::Pending(_) => return Err(Error::NotReclaimable),
        };
        let since = entry.signing_since.ok_or(Error::NotReclaimable)?;
        let ready_at = since.saturating_add(self.policy.t_stuck_ms);
        if now < ready_at {
            return Err(Error::NotStuck { ready_at });
        }
        if value == 0 || value > MAX_MONEY {
            return Err(Error::BadValue);
        }
        let dest_value = value.checked_sub(fee).ok_or(Error::OutputsExceedInputs)?;
        let outputs =
            Outputs { dest_script: self.vault_spk.clone(), dest_value, change_value: None };
        if dest_value < dust_limit(ScriptKind::P2wsh) {
            return Err(Error::DustOutput);
        }
        let floor = estimate_vsize(1, &outputs).saturating_mul(MIN_FEE_RATE);
        if fee < floor {
            return Err(Error::FeeRateTooLow { fee, floor });
        }
        self.check_fee_ceiling(Tier::SelfSpend, fee, &outputs)?;
        self.require_slot_free(now)?;
        let base_unlock = now.saturating_add(self.policy.t_known_ms);
        self.require_chain_wait(&[Input { outpoint, value }], base_unlock)?;
        if self.pending.len() >= MAX_PENDING {
            return Err(Error::PendingCap);
        }

        self.supersede(owner);
        let id = self.insert_pending(
            RequestKind::Reclaim,
            vec![Input { outpoint, value }],
            vec![half_sig],
            outputs,
            Tier::SelfSpend,
            fee,
            0,
            now,
            base_unlock,
            base_unlock.saturating_add(self.fixed.expiry_window_ms),
        );
        self.take_slot(id, now);
        Ok(self.proposed(id))
    }

    // ---------------------------------------------------------------- open methods

    /// Anyone, after unlock. The first call on a request is the point of no return: it charges the
    /// fee budget, pins declared values and closes cancel for every input, signed or not. `txid` is
    /// the transaction this request builds, which the shell computes, because this crate has no hash.
    pub fn execute(
        &mut self,
        id: RequestId,
        max_inputs: usize,
        now: Ms,
        height: u64,
        txid: [u8; 32],
    ) -> Result<SignBatch, Error> {
        self.sweep(now);
        self.require_active()?;
        self.require_not_frozen(now)?;
        if max_inputs == 0 {
            return Err(Error::NothingToSign);
        }
        let request = self.requests.get(&id).ok_or(Error::RequestNotFound)?.clone();
        match request.status {
            RequestStatus::Pending => self.first_execute(&request, now, txid)?,
            RequestStatus::Signing => {
                let retry_at_height = request.last_attempt_height.saturating_add(RETRY_AFTER_BLOCKS);
                if !request.in_flight.is_empty() && height < retry_at_height {
                    return Err(Error::InFlight { retry_at_height });
                }
            }
            RequestStatus::Signed => return Err(Error::AlreadySigned),
        }
        let request = self.requests.get_mut(&id).ok_or(Error::RequestNotFound)?;
        let indices: Vec<usize> = request.missing_inputs().into_iter().take(max_inputs).collect();
        if indices.is_empty() {
            return Err(Error::NothingToSign);
        }
        request.attempt += 1;
        request.in_flight = indices.clone();
        request.last_attempt_height = height;
        Ok(SignBatch { attempt: request.attempt, indices })
    }

    /// Callback from the signer. `recomputed` is the digest the shell rebuilt from current request
    /// state. This never returns `Err`, because a failing callback must not lose what it can store.
    pub fn on_signed(
        &mut self,
        id: RequestId,
        attempt: u32,
        index: usize,
        payload: [u8; 32],
        recomputed: [u8; 32],
        signature: Option<MpcSig>,
        now: Ms,
    ) -> SignedOutcome {
        let Some(request) = self.requests.get_mut(&id) else {
            return SignedOutcome::DroppedUnknownRequest;
        };
        if attempt != request.attempt {
            return SignedOutcome::DroppedStaleAttempt;
        }
        let Some(position) = request.in_flight.iter().position(|i| *i == index) else {
            return SignedOutcome::DroppedNotInFlight;
        };
        request.in_flight.remove(position);
        if payload != recomputed {
            return SignedOutcome::DroppedDigestMismatch;
        }
        let Some(signature) = signature else {
            return SignedOutcome::Failed;
        };
        request.sigs[index] = Some(signature);
        let complete = request.sigs.iter().all(Option::is_some);
        if complete {
            request.status = RequestStatus::Signed;
            request.signed_at = Some(now);
            let outpoints: Vec<Outpoint> = request.inputs.iter().map(|i| i.outpoint).collect();
            for outpoint in outpoints {
                if let Some(entry) = self.ledger.get_mut(&outpoint) {
                    entry.state = OutpointState::Spent { request: id };
                }
            }
        }
        SignedOutcome::Stored { complete }
    }

    /// Anyone, once a Signed request is older than the expiry window. Deletes the request so its bytes
    /// go back to the vault's credit. The ledger entries stay `Spent` with their pins, which the fee
    /// rules need forever, and `reclaim` needs nothing from the deleted request. The shell logs the
    /// final transaction first, so the witness data outlives the row.
    pub fn prune_signed(&mut self, id: RequestId, now: Ms) -> Result<(), Error> {
        let request = self.requests.get(&id).ok_or(Error::RequestNotFound)?;
        if request.status != RequestStatus::Signed {
            return Err(Error::NotSigned);
        }
        let signed_at = request.signed_at.ok_or(Error::NotSigned)?;
        let ready_at = signed_at.saturating_add(self.fixed.expiry_window_ms);
        if now < ready_at {
            return Err(Error::PruneTooSoon { ready_at });
        }
        self.requests.remove(&id);
        Ok(())
    }

    /// Anyone, after the grant's delay.
    pub fn apply_grant(&mut self, id: GrantId, now: Ms) -> Result<(), Error> {
        self.sweep(now);
        self.require_not_frozen(now)?;
        let position = self.grants.iter().position(|g| g.id == id).ok_or(Error::GrantNotFound)?;
        let ready_at = self.grants[position].ready_at;
        if now < ready_at {
            return Err(Error::GrantNotReady { ready_at });
        }
        let grant = self.grants.remove(position);
        match grant.kind {
            GrantKind::RotateSpend { new_k_s } => {
                self.k_s = new_k_s;
                self.k_s_suspended = false;
                // A stolen K_s can burn the 24 h budget with coins that do not exist, and the exit to a
                // new vault is not a self-spend, so no override reaches it. The thief's key is gone
                // now, so its spending does not count against the owner. This lands after `T_known`
                // and `K_e` can veto it, so it is a grant that waits like any other. The per-tx cap
                // still holds.
                self.fee_window.clear();
            }
            GrantKind::AddDestination { script } => {
                self.known.insert(script);
            }
            GrantKind::LoosenPolicy { policy } => self.policy = policy,
            GrantKind::SetGuard { guard } => {
                self.guard = guard;
                self.last_heartbeat = None;
            }
        }
        Ok(())
    }

    /// Anyone, after `T_recover`. Pending grants die with the passkey that asked for them.
    pub fn recover_finish(&mut self, now: Ms) -> Result<(), Error> {
        self.sweep(now);
        let recovery = self.recovery.as_ref().ok_or(Error::NoRecovery)?;
        if now < recovery.ready_at {
            return Err(Error::RecoveryNotReady { ready_at: recovery.ready_at });
        }
        let recovery = self.recovery.take().ok_or(Error::NoRecovery)?;
        self.passkey = recovery.new_passkey;
        self.recover_cancels = 0;
        self.grants.clear();
        Ok(())
    }

    // ---------------------------------------------------------------- guard methods

    pub fn heartbeat(&mut self, caller: &Caller, now: Ms) -> Result<(), Error> {
        self.auth_guard(caller)?;
        self.last_heartbeat = Some(now);
        Ok(())
    }

    /// Records the outcome in both directions. `hold=true` overrides an earlier `hold=false` until
    /// unlock, and a request gets at most one hold in its life, even after a passkey clears it.
    pub fn assess(
        &mut self,
        caller: &Caller,
        id: RequestId,
        hold: bool,
        now: Ms,
    ) -> Result<(), Error> {
        self.sweep(now);
        self.auth_guard(caller)?;
        let hold_ms = self.policy.hold_ms;
        let request = self.requests.get_mut(&id).ok_or(Error::RequestNotFound)?;
        if request.status != RequestStatus::Pending {
            return Err(Error::NotPending);
        }
        if request.hold_used {
            return Err(Error::HoldAlreadyUsed);
        }
        if now >= request.unlock {
            return Err(Error::PastUnlock);
        }
        request.assessed = true;
        if hold {
            request.hold_used = true;
            request.hold_active = true;
            request.unlock = request.base_unlock.saturating_add(hold_ms);
            request.expires_at = request.expires_at.saturating_add(hold_ms);
        }
        Ok(())
    }

    // ---------------------------------------------------------------- passkey and cold-key cancel

    /// `K_p` or `K_e`, including during a freeze. Binds to the request id with no vault nonce, so it
    /// cannot go stale in a crisis.
    pub fn cancel(
        &mut self,
        caller: &Caller,
        expires_at: Ms,
        id: RequestId,
        now: Ms,
    ) -> Result<(), Error> {
        self.sweep(now);
        let allowed = match caller {
            Caller::Passkey(key) => *key == self.passkey.pubkey,
            Caller::Cold(key) => *key == self.k_e_intent,
            _ => false,
        };
        if !allowed {
            return Err(Error::Unauthorized);
        }
        if now > expires_at {
            return Err(Error::IntentExpired);
        }
        let request = self.requests.get(&id).ok_or(Error::RequestNotFound)?;
        if request.status != RequestStatus::Pending {
            return Err(Error::NotPending);
        }
        self.refund_slot(id);
        self.kill_pending(id);
        Ok(())
    }

    // ---------------------------------------------------------------- passkey methods

    /// At once: bumps `spend_epoch` and suspends `K_s`. The new key installs after `T_known`, unless
    /// `K_e` vetoes. A second call replaces a rotation still waiting.
    pub fn cancel_all_and_rotate(
        &mut self,
        caller: &Caller,
        intent: Intent,
        new_k_s: [u8; 32],
        now: Ms,
    ) -> Result<GrantId, Error> {
        self.sweep(now);
        self.require_not_frozen(now)?;
        self.auth_passkey(caller, intent, now)?;
        self.grants.retain(|g| !matches!(g.kind, GrantKind::RotateSpend { .. }));
        self.bump_epoch();
        self.k_s_suspended = true;
        let delay = self.policy.t_known_ms;
        self.push_grant(GrantKind::RotateSpend { new_k_s }, delay, now)
    }

    /// Back to the base unlock, never earlier.
    pub fn clear_hold(
        &mut self,
        caller: &Caller,
        intent: Intent,
        id: RequestId,
        now: Ms,
    ) -> Result<(), Error> {
        self.sweep(now);
        self.require_not_frozen(now)?;
        self.auth_passkey(caller, intent, now)?;
        let window = self.fixed.expiry_window_ms;
        let request = self.requests.get_mut(&id).ok_or(Error::RequestNotFound)?;
        if request.status != RequestStatus::Pending {
            return Err(Error::NotPending);
        }
        if !request.hold_active {
            return Err(Error::NoHold);
        }
        request.hold_active = false;
        request.unlock = request.base_unlock;
        request.expires_at = request.base_unlock.saturating_add(window);
        Ok(())
    }

    /// At once. Also kills pending requests to that script and any add still waiting for it.
    pub fn remove_destination(
        &mut self,
        caller: &Caller,
        intent: Intent,
        script: &[u8],
        now: Ms,
    ) -> Result<(), Error> {
        self.sweep(now);
        self.require_not_frozen(now)?;
        self.auth_passkey(caller, intent, now)?;
        self.known.remove(script);
        self.grants.retain(|g| {
            !matches!(&g.kind, GrantKind::AddDestination { script: s } if s.as_slice() == script)
        });
        let doomed: Vec<RequestId> = self
            .pending
            .iter()
            .copied()
            .filter(|id| {
                self.requests.get(id).is_some_and(|r| r.outputs.dest_script.as_slice() == script)
            })
            .collect();
        for id in doomed {
            self.refund_slot(id);
            self.kill_pending(id);
        }
        Ok(())
    }

    /// Waits `T_new`, and `K_e` can veto.
    pub fn add_destination(
        &mut self,
        caller: &Caller,
        intent: Intent,
        script: Vec<u8>,
        now: Ms,
    ) -> Result<GrantId, Error> {
        self.sweep(now);
        self.require_not_frozen(now)?;
        self.auth_passkey(caller, intent, now)?;
        if ScriptKind::of(&script).is_none() {
            return Err(Error::BadDestination);
        }
        if self.known.contains(&script) {
            return Err(Error::AlreadyKnown);
        }
        let delay = self.policy.t_new_ms;
        self.push_grant(GrantKind::AddDestination { script }, delay, now)
    }

    /// Waits `T_new`, and `K_e` can veto. Removing the guard counts as loosening.
    pub fn set_guard(
        &mut self,
        caller: &Caller,
        intent: Intent,
        guard: Option<String>,
        now: Ms,
    ) -> Result<GrantId, Error> {
        self.sweep(now);
        self.require_not_frozen(now)?;
        self.auth_passkey(caller, intent, now)?;
        let delay = self.policy.t_new_ms;
        self.push_grant(GrantKind::SetGuard { guard }, delay, now)
    }

    /// A pure tightening applies at once and drops any loosening still waiting, because removing
    /// power wins. Anything that loosens any field waits `T_new` as one grant.
    pub fn set_policy(
        &mut self,
        caller: &Caller,
        intent: Intent,
        policy: Policy,
        now: Ms,
    ) -> Result<PolicyOutcome, Error> {
        self.sweep(now);
        self.require_not_frozen(now)?;
        self.auth_passkey(caller, intent, now)?;
        if !self.bounds.allows(&policy) {
            return Err(Error::PolicyOutOfBounds);
        }
        if policy == self.policy {
            return Err(Error::PolicyUnchanged);
        }
        if policy.loosens(&self.policy) {
            let delay = self.policy.t_new_ms;
            return self
                .push_grant(GrantKind::LoosenPolicy { policy }, delay, now)
                .map(PolicyOutcome::Grant);
        }
        self.policy = policy;
        self.grants.retain(|g| !matches!(g.kind, GrantKind::LoosenPolicy { .. }));
        Ok(PolicyOutcome::Applied)
    }

    /// At once, for one named self-spend that is still Pending, up to 1/20 of the value it moves.
    /// It lifts that request's per-tx cap and 24 h budget check. The fee is still charged.
    pub fn raise_fee_cap(
        &mut self,
        caller: &Caller,
        intent: Intent,
        id: RequestId,
        cap: Sats,
        now: Ms,
    ) -> Result<(), Error> {
        self.sweep(now);
        self.require_not_frozen(now)?;
        self.auth_passkey(caller, intent, now)?;
        let request = self.requests.get_mut(&id).ok_or(Error::RequestNotFound)?;
        if request.status != RequestStatus::Pending {
            return Err(Error::NotPending);
        }
        if !request.is_self_spend() {
            return Err(Error::NotSelfSpend);
        }
        let limit = request.outputs.total() / FEE_OVERRIDE_DIVISOR;
        if cap > limit {
            return Err(Error::OverrideTooHigh { limit });
        }
        request.fee_override = Some(cap);
        Ok(())
    }

    /// `K_p`, at most twice between successful recoveries. The counter is not time-based, and a
    /// freeze blocks this call like every other passkey action except `cancel`.
    pub fn recover_cancel(
        &mut self,
        caller: &Caller,
        intent: Intent,
        now: Ms,
    ) -> Result<(), Error> {
        self.sweep(now);
        self.require_not_frozen(now)?;
        self.auth_passkey(caller, intent, now)?;
        if self.recovery.is_none() {
            return Err(Error::NoRecovery);
        }
        if self.recover_cancels >= RECOVERY_CANCEL_CAP {
            return Err(Error::RecoveryCancelCapReached);
        }
        self.recover_cancels += 1;
        self.recovery = None;
        Ok(())
    }

    // ---------------------------------------------------------------- cold-key methods

    /// One signature, for up to the CSV period. Bumps `spend_epoch` and cancels pending grants. It
    /// may also renew a running freeze. Only `K_e` lifts it early.
    pub fn freeze(
        &mut self,
        caller: &Caller,
        intent: Intent,
        until: Ms,
        now: Ms,
    ) -> Result<(), Error> {
        self.sweep(now);
        self.auth_cold(caller, intent, now)?;
        let max_until = now.saturating_add(self.csv_period_ms());
        if until > max_until || until <= now {
            return Err(Error::FreezeTooLong { max_until });
        }
        self.frozen_until = Some(until);
        self.bump_epoch();
        self.grants.clear();
        Ok(())
    }

    pub fn unfreeze(&mut self, caller: &Caller, intent: Intent, now: Ms) -> Result<(), Error> {
        self.sweep(now);
        self.auth_cold(caller, intent, now)?;
        if !self.is_frozen(now) {
            return Err(Error::NotFrozen);
        }
        self.frozen_until = None;
        Ok(())
    }

    pub fn veto_grant(
        &mut self,
        caller: &Caller,
        intent: Intent,
        id: GrantId,
        now: Ms,
    ) -> Result<(), Error> {
        self.sweep(now);
        self.auth_cold(caller, intent, now)?;
        let position = self.grants.iter().position(|g| g.id == id).ok_or(Error::GrantNotFound)?;
        self.grants.remove(position);
        Ok(())
    }

    pub fn recover_begin(
        &mut self,
        caller: &Caller,
        intent: Intent,
        new_passkey: Passkey,
        now: Ms,
    ) -> Result<(), Error> {
        self.sweep(now);
        self.auth_cold(caller, intent, now)?;
        if new_passkey.pubkey.is_empty() {
            return Err(Error::BadKey);
        }
        if self.recovery.is_some() {
            return Err(Error::RecoveryInProgress);
        }
        self.recovery = Some(Recovery {
            new_passkey,
            begun_at: now,
            ready_at: now.saturating_add(self.fixed.t_recover_ms),
        });
        Ok(())
    }

    // ---------------------------------------------------------------- internals

    fn require_active(&self) -> Result<(), Error> {
        if self.active {
            Ok(())
        } else {
            Err(Error::Inactive)
        }
    }

    fn require_not_frozen(&self, now: Ms) -> Result<(), Error> {
        match self.frozen_until {
            Some(until) if now < until => Err(Error::Frozen { until }),
            _ => Ok(()),
        }
    }

    fn check_intent(expected: u64, intent: Intent, now: Ms) -> Result<(), Error> {
        if now > intent.expires_at {
            return Err(Error::IntentExpired);
        }
        if intent.nonce != expected {
            return Err(Error::BadNonce { expected });
        }
        Ok(())
    }

    fn auth_spend(&mut self, caller: &Caller, intent: Intent, now: Ms) -> Result<(), Error> {
        match caller {
            Caller::SpendKey(key) if *key == self.k_s => {}
            _ => return Err(Error::Unauthorized),
        }
        if self.k_s_suspended {
            return Err(Error::SpendKeySuspended);
        }
        Self::check_intent(self.spend_nonce, intent, now)?;
        self.spend_nonce += 1;
        Ok(())
    }

    fn auth_passkey(&mut self, caller: &Caller, intent: Intent, now: Ms) -> Result<(), Error> {
        match caller {
            Caller::Passkey(key) if *key == self.passkey.pubkey => {}
            _ => return Err(Error::Unauthorized),
        }
        Self::check_intent(self.passkey_nonce, intent, now)?;
        self.passkey_nonce += 1;
        Ok(())
    }

    fn auth_cold(&mut self, caller: &Caller, intent: Intent, now: Ms) -> Result<(), Error> {
        match caller {
            Caller::Cold(key) if *key == self.k_e_intent => {}
            _ => return Err(Error::Unauthorized),
        }
        Self::check_intent(self.cold_nonce, intent, now)?;
        self.cold_nonce += 1;
        Ok(())
    }

    fn auth_guard(&self, caller: &Caller) -> Result<(), Error> {
        match (caller, &self.guard) {
            (Caller::Guard(name), Some(guard)) if name == guard => Ok(()),
            _ => Err(Error::Unauthorized),
        }
    }

    fn is_dead(&self, request: &Request, now: Ms) -> bool {
        // Execute wins any race in the same block, so a request is still alive at exactly
        // expires_at.
        request.status == RequestStatus::Pending
            && (request.epoch != self.spend_epoch || now > request.expires_at)
    }

    /// Frees old-epoch and expired requests. Bounded: each state change sweeps, and `pending` only
    /// grows through the cap.
    fn sweep(&mut self, now: Ms) {
        let dead: Vec<RequestId> = self
            .pending
            .iter()
            .copied()
            .filter(|id| self.requests.get(id).is_none_or(|r| self.is_dead(r, now)))
            .collect();
        for id in dead {
            self.kill_pending(id);
        }
        self.fee_window.retain(|(at, _)| now < at.saturating_add(DAY));
        self.outflow_window.retain(|e| now < e.at.saturating_add(DAY));
    }

    /// Pending to deleted: outpoints freed, reserved outflow released.
    fn kill_pending(&mut self, id: RequestId) {
        self.pending.retain(|p| *p != id);
        self.outflow_window.retain(|e| e.request != id);
        let Some(request) = self.requests.remove(&id) else { return };
        for input in &request.inputs {
            if self.outpoint_state(&input.outpoint) == OutpointState::Pending(id) {
                self.free_outpoint(input.outpoint);
            }
        }
    }

    /// A pin or a birth time outlives the request. An outpoint with neither leaves the ledger, which
    /// returns its bytes.
    fn free_outpoint(&mut self, outpoint: Outpoint) {
        let Some(entry) = self.ledger.get_mut(&outpoint) else { return };
        if entry.pinned_value.is_some() || entry.born_at.is_some() {
            entry.state = OutpointState::Free;
            entry.signing_since = None;
        } else {
            self.ledger.remove(&outpoint);
        }
    }

    /// Deletes a request whose signatures may be public. Its other inputs stay `Spent`, so each one
    /// needs its own reclaim, and a late `on_signed` finds no request.
    fn supersede(&mut self, id: RequestId) {
        let Some(request) = self.requests.remove(&id) else { return };
        for input in &request.inputs {
            if let Some(entry) = self.ledger.get_mut(&input.outpoint) {
                if matches!(entry.state, OutpointState::Signing(owner) if owner == id) {
                    entry.state = OutpointState::Spent { request: id };
                }
            }
        }
    }

    fn bump_epoch(&mut self) {
        self.spend_epoch += 1;
        if let Some(holder) = self.slot.holder {
            if self.requests.get(&holder).is_some_and(|r| r.status == RequestStatus::Pending) {
                self.refund_slot(holder);
            }
        }
    }

    /// Refuses a transaction paying back to the vault, unlocking at `at`, while one of its inputs is
    /// still inside the chain wait.
    fn require_chain_wait(&self, inputs: &[Input], at: Ms) -> Result<(), Error> {
        let wait = self.chain_wait_ms();
        for input in inputs {
            if let Some(born) = self.ledger.get(&input.outpoint).and_then(|e| e.born_at) {
                let ready_at = born.saturating_add(wait);
                if at < ready_at {
                    return Err(Error::ChainTooYoung { ready_at });
                }
            }
        }
        Ok(())
    }

    fn require_slot_free(&self, now: Ms) -> Result<(), Error> {
        if let Some(free_at) = self.self_spend_slot_free_at() {
            if now < free_at {
                return Err(Error::SelfSpendSlotUsed { free_at });
            }
        }
        Ok(())
    }

    fn take_slot(&mut self, id: RequestId, now: Ms) {
        self.slot =
            SelfSpendSlot { last_at: Some(now), holder: Some(id), prev_at: self.slot.last_at };
    }

    /// Only the request that took the slot last can give it back.
    fn refund_slot(&mut self, id: RequestId) {
        if self.slot.holder == Some(id) {
            self.slot.last_at = self.slot.prev_at;
            self.slot.holder = None;
        }
    }

    /// True when the transaction pays back to the vault's own script. That output is a new coin with
    /// age zero, so a thief who keeps a signed chain of these can restart CSV once per link. A 294-sat
    /// spend with the rest as change does this just as a self-spend does, so the slot counts both.
    fn restarts_csv(&self, outputs: &Outputs) -> bool {
        outputs.dest_script == self.vault_spk || outputs.change_value.is_some()
    }

    /// Highest fee a request of this tier can ever execute with. Above the policy cap only a
    /// self-spend has a path, through a named override, so anything else is refused at once.
    fn check_fee_ceiling(&self, tier: Tier, fee: Sats, outputs: &Outputs) -> Result<(), Error> {
        let cap = if tier == Tier::SelfSpend {
            self.policy.fee_cap_tx.max(outputs.total() / FEE_OVERRIDE_DIVISOR)
        } else {
            self.policy.fee_cap_tx
        };
        if fee > cap {
            return Err(Error::FeeOverCap { fee, cap });
        }
        Ok(())
    }

    fn plan_propose(
        &self,
        inputs: &[Input],
        outputs: &Outputs,
        now: Ms,
    ) -> Result<ProposeCheck, Error> {
        if inputs.is_empty() {
            return Err(Error::NoInputs);
        }
        if inputs.len() > MAX_INPUTS {
            return Err(Error::TooManyInputs);
        }
        let mut total: Sats = 0;
        for (i, input) in inputs.iter().enumerate() {
            if input.value == 0 || input.value > MAX_MONEY {
                return Err(Error::BadValue);
            }
            if inputs[..i].iter().any(|other| other.outpoint == input.outpoint) {
                return Err(Error::DuplicateInput(input.outpoint));
            }
            total = total.checked_add(input.value).ok_or(Error::BadValue)?;
        }

        let kind = ScriptKind::of(&outputs.dest_script).ok_or(Error::BadDestination)?;
        if outputs.dest_value < dust_limit(kind) {
            return Err(Error::DustOutput);
        }
        if let Some(change) = outputs.change_value {
            if change < dust_limit(ScriptKind::P2wsh) {
                return Err(Error::DustOutput);
            }
        }
        let spent = outputs
            .dest_value
            .checked_add(outputs.change_value.unwrap_or(0))
            .ok_or(Error::BadValue)?;
        let fee = total.checked_sub(spent).ok_or(Error::OutputsExceedInputs)?;
        let floor = estimate_vsize(inputs.len(), outputs).saturating_mul(MIN_FEE_RATE);
        if fee < floor {
            return Err(Error::FeeRateTooLow { fee, floor });
        }

        for input in inputs {
            if self.outpoint_state(&input.outpoint) != OutpointState::Free {
                return Err(Error::OutpointBusy(input.outpoint));
            }
            // BIP-143 commits only to the value of the input being signed, so two multi-input
            // sessions over the same outpoints can combine into a transaction no cap ever saw.
            if inputs.len() > 1 && self.pinned_value(&input.outpoint).is_some() {
                return Err(Error::PinnedInMultiInput(input.outpoint));
            }
        }
        if self.pending.len() >= MAX_PENDING {
            return Err(Error::PendingCap);
        }

        let unguarded = !self.guard_online(now);
        let (tier, delay_ms) = if outputs.dest_script == self.vault_spk {
            (Tier::SelfSpend, self.policy.t_known_ms)
        } else if self.known.contains(&outputs.dest_script)
            && self.outflow_used_24h(now).saturating_add(outputs.dest_value)
                <= self.policy.outflow_cap_24h
        {
            (Tier::Known, self.policy.t_known_ms)
        } else {
            (Tier::New, self.delay_now(now))
        };
        if self.restarts_csv(outputs) {
            self.require_slot_free(now)?;
            self.require_chain_wait(inputs, now.saturating_add(delay_ms))?;
        }
        self.check_fee_ceiling(tier, fee, outputs)?;
        Ok(ProposeCheck { tier, delay_ms, fee, unguarded })
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_pending(
        &mut self,
        kind: RequestKind,
        inputs: Vec<Input>,
        half_sigs: Vec<HalfSig>,
        outputs: Outputs,
        tier: Tier,
        fee: Sats,
        fee_prepaid: Sats,
        now: Ms,
        base_unlock: Ms,
        expires_at: Ms,
    ) -> RequestId {
        let id = self.next_request;
        self.next_request += 1;
        for input in &inputs {
            let entry = self.ledger.entry(input.outpoint).or_insert(LedgerEntry {
                state: OutpointState::Free,
                pinned_value: None,
                signing_since: None,
                born_at: None,
            });
            entry.state = OutpointState::Pending(id);
            entry.signing_since = None;
        }
        let sigs = vec![None; inputs.len()];
        self.requests.insert(
            id,
            Request {
                id,
                kind,
                status: RequestStatus::Pending,
                epoch: self.spend_epoch,
                inputs,
                half_sigs,
                outputs,
                tier,
                fee,
                fee_prepaid,
                fee_override: None,
                proposed_at: now,
                base_unlock,
                unlock: base_unlock,
                expires_at,
                assessed: false,
                hold_used: false,
                hold_active: false,
                first_execute_at: None,
                attempt: 0,
                in_flight: Vec::new(),
                last_attempt_height: 0,
                signed_at: None,
                sigs,
            },
        );
        self.pending.push(id);
        id
    }

    fn proposed(&self, id: RequestId) -> Proposed {
        let r = &self.requests[&id];
        Proposed { id, tier: r.tier, base_unlock: r.base_unlock, expires_at: r.expires_at, fee: r.fee }
    }

    /// The Pending to Signing step: enforce and charge the fee, pin every declared value, and stop
    /// the request from being cancellable. Fee checks run here and not at propose, so proposals that
    /// never survive their delay cannot use up the owner's budget.
    fn first_execute(&mut self, request: &Request, now: Ms, txid: [u8; 32]) -> Result<(), Error> {
        if request.epoch != self.spend_epoch {
            return Err(Error::RequestNotFound);
        }
        if now < request.unlock {
            return Err(Error::NotUnlocked { unlock: request.unlock });
        }
        let cap = request.fee_override.unwrap_or(self.policy.fee_cap_tx);
        if request.fee > cap {
            return Err(Error::FeeOverCap { fee: request.fee, cap });
        }
        let charge = request.fee.saturating_sub(request.fee_prepaid);
        let used = self.fee_used_24h(now);
        if request.fee_override.is_none()
            && used.saturating_add(charge) > self.policy.fee_budget_24h
        {
            return Err(Error::FeeBudgetExceeded {
                charge,
                used,
                budget: self.policy.fee_budget_24h,
            });
        }
        // The chain rule's other half. Propose waits out a parent's birth time, but a child proposed
        // against its parent's future txid has none yet. So the parent cannot go out while a child
        // holds its coin, or once one has gone out. That is why execute has no wait of its own: a
        // birth time never moves, and every request that can be Pending now passed the check at
        // propose or came after its parent.
        let children: Vec<Outpoint> =
            request.vault_vouts().into_iter().map(|vout| Outpoint { txid, vout }).collect();
        for child in &children {
            if self.ledger.get(child).is_some_and(|e| e.state != OutpointState::Free || e.pinned_value.is_some()) {
                return Err(Error::ChainOutOfOrder(*child));
            }
        }
        for child in children {
            self.ledger.entry(child).or_insert(LedgerEntry {
                state: OutpointState::Free,
                pinned_value: None,
                signing_since: None,
                born_at: Some(now),
            });
        }
        if charge > 0 {
            self.fee_window.push((now, charge));
        }
        for input in &request.inputs {
            let entry = self.ledger.get_mut(&input.outpoint).ok_or(Error::NotPending)?;
            entry.pinned_value.get_or_insert(input.value);
            entry.state = OutpointState::Signing(request.id);
            entry.signing_since = Some(now);
        }
        // The slot use can no longer be refunded once a signature may exist.
        if self.slot.holder == Some(request.id) {
            self.slot.holder = None;
        }
        self.pending.retain(|p| *p != request.id);
        let stored = self.requests.get_mut(&request.id).ok_or(Error::RequestNotFound)?;
        stored.status = RequestStatus::Signing;
        stored.first_execute_at = Some(now);
        Ok(())
    }

    fn push_grant(&mut self, kind: GrantKind, delay: Ms, now: Ms) -> Result<GrantId, Error> {
        if self.grants.len() >= MAX_GRANTS {
            return Err(Error::TooManyGrants);
        }
        let id = self.next_grant;
        self.next_grant += 1;
        self.grants.push(Grant {
            id,
            kind,
            begun_at: now,
            ready_at: now.saturating_add(delay),
        });
        Ok(id)
    }
}
