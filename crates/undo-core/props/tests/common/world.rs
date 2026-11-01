//! A generated-action harness with a shadow model. The shadow restates the spec's timing rules
//! without calling the code under test, so the properties do not read their answers from it.

use std::collections::{BTreeMap, BTreeSet};

use proptest::prelude::*;
use undo_core::*;

use super::*;

pub const FALSE_VALUE: Sats = 1_500;
/// Hidden real values of the coin pool. The contract never sees these.
pub const REALS: [Sats; 4] = [1_000_000, 1_000_000, 1_000_000, 50_000];

#[derive(Clone, Debug)]
pub enum Action {
    Advance(Ms),
    /// `declare_false[i]` lies about input i. `dest` picks vault, known or new. `stale_key` signs
    /// with a key that is not the current one.
    Propose { ops: Vec<usize>, declare_false: Vec<bool>, dest: usize, fee: Sats, change: bool, stale_key: bool },
    Cancel { pick: usize, cold: bool },
    CancelOwning { coin: usize },
    Rotate { key: u8 },
    Execute { pick: usize, max_inputs: usize },
    ExecuteOwning { coin: usize },
    DeliverSignatures { pick: usize },
    Reclaim { coin: usize, truth: bool, fee: Sats },
    Assess { pick: usize, hold: bool },
    ClearHold { pick: usize },
    Heartbeat,
    AddDest { dest: usize },
    RemoveDest { dest: usize },
    ApplyGrant { pick: usize },
    Veto { pick: usize },
    Freeze { ms: Ms },
    Unfreeze,
    RecoverBegin,
    RecoverCancel,
    RecoverFinish,
    SetPolicy { kind: usize },
    SetGuard { present: bool },
    RaiseFeeCap { pick: usize, share: Sats },
}

/// One signing session: what the signer was asked to commit to. Under BIP-143 a signature for input
/// i commits to the ordered outpoints, the outputs, and the declared value of input i only.
#[derive(Clone, Debug)]
pub struct Session {
    pub request: RequestId,
    pub prevouts: Vec<Outpoint>,
    pub declared: Vec<Sats>,
    pub outputs: Outputs,
    pub signed: BTreeSet<usize>,
    /// The per-tx cap this session passed, with any named override.
    pub allowed_fee: Sats,
}

#[derive(Clone, Debug)]
struct ShadowRequest {
    base: Ms,
    hold: Ms,
    epoch: u64,
    expires_at: Ms,
    executed_at: Option<Ms>,
    kind: RequestKind,
}

#[derive(Clone, Debug)]
struct ShadowGrant {
    ready_at: Ms,
    kind: GrantKind,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Coverage {
    pub accepted: usize,
    pub refused: usize,
    pub executes: usize,
    pub executed_with_hold_cleared: usize,
    pub reclaims: usize,
    pub grants_applied: usize,
    pub freezes: usize,
    pub rotations: usize,
    pub pinned_multi_refused: usize,
    pub multi_sessions: usize,
    pub early_execute_refused: usize,
}

pub struct World {
    pub h: H,
    pub reals: BTreeMap<Outpoint, Sats>,
    pub sessions: Vec<Session>,
    pub coverage: Coverage,
    // Shadow state, updated only from accepted actions.
    reqs: BTreeMap<RequestId, ShadowRequest>,
    grants: BTreeMap<GrantId, ShadowGrant>,
    policy: Policy,
    known: BTreeSet<Vec<u8>>,
    guard: Option<String>,
    beat: Option<Ms>,
    epoch: u64,
    frozen_until: Option<Ms>,
    charges: Vec<(Ms, Sats, bool)>,
    pins: BTreeMap<Outpoint, Sats>,
    spend_key: [u8; 32],
    suspended: bool,
    recover_cancels: u8,
}

pub fn coin(i: usize) -> Outpoint {
    op(i as u8 + 1)
}

fn dests(vault_spk: &[u8]) -> [Vec<u8>; 3] {
    [vault_spk.to_vec(), p2tr(0x88), p2wpkh(0x89)]
}

/// Wide bounds, so generated policy changes really move delays both ways.
pub fn wide_bounds() -> Bounds {
    let p = Policy::test_coin(OUTFLOW_CAP);
    Bounds {
        min: Policy {
            t_known_ms: p.t_known_ms / 2,
            t_new_ms: p.t_new_ms / 2,
            t_new_unguarded_ms: p.t_new_unguarded_ms / 2,
            hold_ms: p.hold_ms / 2,
            t_stuck_ms: p.t_stuck_ms / 2,
            fee_cap_tx: 500,
            fee_budget_24h: 1_000,
            outflow_cap_24h: 0,
        },
        max: Policy {
            t_known_ms: p.t_known_ms * 4,
            t_new_ms: p.t_new_ms * 4,
            t_new_unguarded_ms: p.t_new_unguarded_ms * 4,
            hold_ms: p.hold_ms * 4,
            t_stuck_ms: p.t_stuck_ms * 4,
            fee_cap_tx: 8_000,
            fee_budget_24h: 40_000,
            outflow_cap_24h: OUTFLOW_CAP * 4,
        },
    }
}

impl World {
    pub fn new(vault_spk: Vec<u8>) -> World {
        let policy = Policy::test_coin(OUTFLOW_CAP);
        let mut v = Vault::create(create_args(policy, Fixed::test_coin(), wide_bounds(), vault_spk)).unwrap();
        v.activate(&k_m()).unwrap();
        let reals = REALS.iter().enumerate().map(|(i, r)| (coin(i), *r)).collect();
        World {
            h: H::new(v),
            reals,
            sessions: Vec::new(),
            coverage: Coverage::default(),
            reqs: BTreeMap::new(),
            grants: BTreeMap::new(),
            policy,
            known: BTreeSet::new(),
            guard: Some(GUARD.to_string()),
            beat: None,
            epoch: 0,
            frozen_until: None,
            charges: Vec::new(),
            pins: BTreeMap::new(),
            spend_key: SPEND,
            suspended: false,
            recover_cancels: 0,
        }
    }

    fn frozen(&self) -> bool {
        self.frozen_until.is_some_and(|until| self.h.now < until)
    }

    fn new_dest_delay(&self) -> Ms {
        let online = self.guard.is_some()
            && self.beat.is_some_and(|b| self.h.now - b <= 20 * MINUTE);
        if online { self.policy.t_new_ms } else { self.policy.t_new_unguarded_ms }
    }

    fn pick_request(&self, pick: usize) -> Option<RequestId> {
        let ids: Vec<RequestId> = self.h.v.requests.keys().copied().collect();
        if ids.is_empty() { None } else { Some(ids[pick % ids.len()]) }
    }

    fn pick_grant(&self, pick: usize) -> Option<GrantId> {
        let g = &self.h.v.grants;
        if g.is_empty() { None } else { Some(g[pick % g.len()].id) }
    }

    fn owner_of(&self, coin_index: usize) -> Option<RequestId> {
        let id = match self.h.v.outpoint_state(&coin(coin_index)) {
            OutpointState::Pending(id) | OutpointState::Signing(id) => id,
            OutpointState::Spent { request } => request,
            OutpointState::Free => return None,
        };
        // A Spent entry can name a request that has since been deleted.
        self.h.v.requests.contains_key(&id).then_some(id)
    }

    pub fn step(&mut self, action: &Action) {
        let before = self.h.clone();
        let accepted = self.apply(action);
        if accepted {
            self.coverage.accepted += 1;
        } else {
            self.coverage.refused += 1;
            assert_eq!(self.h.v, before.v, "a refused call must leave the vault as it was: {action:?}");
        }
        self.check_invariants(action);
    }

    fn apply(&mut self, action: &Action) -> bool {
        match action.clone() {
            Action::Advance(ms) => {
                self.h.advance(ms);
                true
            }
            Action::Propose { ops, declare_false, dest, fee, change, stale_key } => {
                self.do_propose(&ops, &declare_false, dest, fee, change, stale_key)
            }
            Action::Cancel { pick, cold } => match self.pick_request(pick) {
                Some(id) => self.do_cancel(id, cold),
                None => false,
            },
            Action::CancelOwning { coin } => match self.owner_of(coin) {
                Some(id) => self.do_cancel(id, false),
                None => false,
            },
            Action::Rotate { key } => {
                let new_key = if key % 2 == 0 { SPEND_2 } else { SPEND };
                match self.h.rotate(new_key) {
                    Ok(grant) => {
                        self.epoch += 1;
                        self.suspended = true;
                        self.coverage.rotations += 1;
                        self.grants.retain(|_, g| !matches!(g.kind, GrantKind::RotateSpend { .. }));
                        self.grants.insert(grant, ShadowGrant {
                            ready_at: self.h.now + self.policy.t_known_ms,
                            kind: GrantKind::RotateSpend { new_k_s: new_key },
                        });
                        assert!(!self.frozen(), "rotation during a freeze");
                        true
                    }
                    Err(_) => false,
                }
            }
            Action::Execute { pick, max_inputs } => match self.pick_request(pick) {
                Some(id) => self.do_execute(id, max_inputs),
                None => false,
            },
            Action::ExecuteOwning { coin } => match self.owner_of(coin) {
                Some(id) => self.do_execute(id, MAX_INPUTS),
                None => false,
            },
            Action::DeliverSignatures { pick } => {
                let Some(id) = self.pick_request(pick) else { return false };
                let request = self.h.v.requests[&id].clone();
                for index in request.in_flight {
                    self.h.v.on_signed(id, request.attempt, index, [7; 32], [7; 32], Some(vec![1]), self.h.now);
                }
                true
            }
            Action::Reclaim { coin: c, truth, fee } => {
                let outpoint = coin(c);
                let value = if truth { self.reals[&outpoint] } else { FALSE_VALUE };
                let since = self.h.v.ledger.get(&outpoint).and_then(|e| e.signing_since);
                match self.h.reclaim(outpoint, value, fee) {
                    Ok(p) => {
                        let now = self.h.now;
                        assert!(since.is_some_and(|s| now >= s + self.policy.t_stuck_ms), "reclaim before T_stuck");
                        assert_eq!(p.base_unlock, now + self.policy.t_known_ms, "reclaim is at T_known");
                        assert!(!self.frozen() && !self.suspended);
                        self.reqs.retain(|id, _| self.h.v.requests.contains_key(id));
                        self.track_new(p, RequestKind::Reclaim);
                        self.coverage.reclaims += 1;
                        true
                    }
                    Err(_) => false,
                }
            }
            Action::Assess { pick, hold } => {
                let Some(id) = self.pick_request(pick) else { return false };
                let hold_ms = self.policy.hold_ms;
                match self.h.assess(id, hold) {
                    Ok(()) => {
                        if hold {
                            let s = self.reqs.get_mut(&id).unwrap();
                            s.hold = hold_ms;
                            s.expires_at += hold_ms;
                        }
                        true
                    }
                    Err(_) => false,
                }
            }
            Action::ClearHold { pick } => {
                let Some(id) = self.pick_request(pick) else { return false };
                match self.h.clear_hold(id) {
                    Ok(()) => {
                        let window = self.h.v.fixed.expiry_window_ms;
                        let s = self.reqs.get_mut(&id).unwrap();
                        s.hold = 0;
                        s.expires_at = s.base + window;
                        true
                    }
                    Err(_) => false,
                }
            }
            Action::Heartbeat => match self.h.heartbeat() {
                Ok(()) => {
                    self.beat = Some(self.h.now);
                    true
                }
                Err(_) => false,
            },
            Action::AddDest { dest } => {
                let script = dests(&self.h.v.vault_spk)[1 + dest % 2].clone();
                match self.h.add_dest(&script) {
                    Ok(grant) => {
                        self.grants.insert(grant, ShadowGrant {
                            ready_at: self.h.now + self.policy.t_new_ms,
                            kind: GrantKind::AddDestination { script },
                        });
                        true
                    }
                    Err(_) => false,
                }
            }
            Action::RemoveDest { dest } => {
                let script = dests(&self.h.v.vault_spk)[1 + dest % 2].clone();
                match self.h.remove_dest(&script) {
                    Ok(()) => {
                        self.known.remove(&script);
                        self.grants.retain(|_, g| {
                            !matches!(&g.kind, GrantKind::AddDestination { script: s } if *s == script)
                        });
                        self.reqs.retain(|id, _| self.h.v.requests.contains_key(id));
                        true
                    }
                    Err(_) => false,
                }
            }
            Action::ApplyGrant { pick } => {
                let Some(id) = self.pick_grant(pick) else { return false };
                match self.h.apply(id) {
                    Ok(()) => {
                        let grant = self.grants.remove(&id).expect("a grant the shadow never saw");
                        assert!(self.h.now >= grant.ready_at, "a grant landed early");
                        match grant.kind {
                            GrantKind::RotateSpend { new_k_s } => {
                                self.spend_key = new_k_s;
                                self.suspended = false;
                                self.charges.clear();
                            }
                            GrantKind::AddDestination { script } => {
                                self.known.insert(script);
                            }
                            GrantKind::LoosenPolicy { policy } => self.policy = policy,
                            GrantKind::SetGuard { guard } => {
                                self.guard = guard;
                                self.beat = None;
                            }
                        }
                        self.coverage.grants_applied += 1;
                        true
                    }
                    Err(_) => false,
                }
            }
            Action::Veto { pick } => {
                let Some(id) = self.pick_grant(pick) else { return false };
                let accepted = self.h.veto(id).is_ok();
                if accepted {
                    self.grants.remove(&id);
                }
                accepted
            }
            Action::Freeze { ms } => match self.h.freeze(self.h.now + ms) {
                Ok(()) => {
                    assert!(ms <= self.h.v.csv_period_ms(), "freeze longer than CSV");
                    self.frozen_until = Some(self.h.now + ms);
                    self.epoch += 1;
                    self.grants.clear();
                    self.coverage.freezes += 1;
                    true
                }
                Err(_) => false,
            },
            Action::Unfreeze => {
                let accepted = self.h.unfreeze().is_ok();
                if accepted {
                    self.frozen_until = None;
                }
                accepted
            }
            Action::RecoverBegin => self.h.recover_begin(passkey(0x40 + self.recover_cancels)).is_ok(),
            Action::RecoverCancel => match self.h.recover_cancel() {
                Ok(()) => {
                    self.recover_cancels += 1;
                    assert!(self.recover_cancels <= 2, "third recovery cancel accepted");
                    assert!(!self.frozen(), "passkey acted during a freeze");
                    true
                }
                Err(_) => false,
            },
            Action::RecoverFinish => match self.h.recover_finish() {
                Ok(()) => {
                    self.recover_cancels = 0;
                    self.grants.clear();
                    true
                }
                Err(_) => false,
            },
            Action::SetPolicy { kind } => self.do_set_policy(kind),
            Action::SetGuard { present } => {
                let guard = if present { Some(GUARD.to_string()) } else { None };
                match self.h.set_guard(guard.clone()) {
                    Ok(grant) => {
                        self.grants.insert(grant, ShadowGrant {
                            ready_at: self.h.now + self.policy.t_new_ms,
                            kind: GrantKind::SetGuard { guard },
                        });
                        true
                    }
                    Err(_) => false,
                }
            }
            Action::RaiseFeeCap { pick, share } => {
                let Some(id) = self.pick_request(pick) else { return false };
                let moved = self.h.v.requests[&id].outputs.total();
                self.h.raise_fee_cap(id, moved / share).is_ok()
            }
        }
    }

    fn do_propose(
        &mut self,
        ops: &[usize],
        declare_false: &[bool],
        dest: usize,
        fee: Sats,
        change: bool,
        stale_key: bool,
    ) -> bool {
        let inputs: Vec<(Outpoint, Sats)> = ops
            .iter()
            .zip(declare_false.iter().chain(std::iter::repeat(&false)))
            .map(|(i, lie)| {
                let o = coin(*i);
                (o, if *lie { FALSE_VALUE } else { self.reals[&o] })
            })
            .collect();
        let total: Sats = inputs.iter().map(|(_, v)| *v).sum();
        let script = dests(&self.h.v.vault_spk)[dest % 3].clone();
        let Some(spendable) = total.checked_sub(fee) else { return false };
        let (dest_value, change_value) = if change && spendable > 2_000 {
            (spendable - 1_000, Some(1_000))
        } else {
            (spendable, None)
        };
        let args = ProposeArgs {
            inputs: inputs.iter().map(|(o, v)| Input { outpoint: *o, value: *v }).collect(),
            outputs: Outputs { dest_script: script.clone(), dest_value, change_value },
            half_sigs: vec![vec![1; 65]; inputs.len()],
            memo: None,
        };
        let key = if stale_key { [0xee; 32] } else { self.h.v.k_s };
        let intent = self.h.sp();
        let result = self.h.tx(|v, now| v.propose(&Caller::SpendKey(key), intent, args, now));
        match result {
            Ok(p) => {
                assert!(!stale_key, "a stale spend key proposed");
                assert_eq!(key, self.spend_key, "a key other than the installed one proposed");
                assert!(!self.suspended, "a suspended spend key proposed");
                assert!(!self.frozen(), "a proposal landed during a freeze");
                let delay = p.base_unlock - self.h.now;
                if script == self.h.v.vault_spk || self.known.contains(&script) {
                    assert!(delay >= self.policy.t_known_ms, "under T_known: {delay}");
                } else {
                    assert_eq!(delay, self.new_dest_delay(), "new destination under its delay");
                }
                if inputs.len() > 1 {
                    for (o, _) in &inputs {
                        assert!(!self.pins.contains_key(o), "a pinned outpoint entered a multi-input request");
                    }
                }
                self.track_new(p, RequestKind::Normal);
                true
            }
            Err(Error::PinnedInMultiInput(_)) => {
                self.coverage.pinned_multi_refused += 1;
                false
            }
            Err(_) => false,
        }
    }

    fn track_new(&mut self, p: Proposed, kind: RequestKind) {
        self.reqs.insert(p.id, ShadowRequest {
            base: p.base_unlock,
            hold: 0,
            epoch: self.epoch,
            expires_at: p.expires_at,
            executed_at: None,
            kind,
        });
    }

    fn do_cancel(&mut self, id: RequestId, cold: bool) -> bool {
        let result = if cold { self.h.cancel_cold(id) } else { self.h.cancel(id) };
        let accepted = result.is_ok();
        if accepted {
            let shadow = &self.reqs[&id];
            assert!(shadow.executed_at.is_none(), "cancel after execute");
            self.reqs.remove(&id);
            self.reqs.retain(|r, _| self.h.v.requests.contains_key(r));
        }
        accepted
    }

    fn do_execute(&mut self, id: RequestId, max_inputs: usize) -> bool {
        let request = self.h.v.requests[&id].clone();
        let now = self.h.now;
        match self.h.execute(id, max_inputs) {
            Ok(batch) => {
                let shadow = self.reqs.get(&id).expect("executed a request the shadow lost").clone();
                assert!(!self.frozen(), "execute during a freeze");
                if shadow.executed_at.is_none() {
                    self.check_first_execute(id, &request, &shadow, now);
                }
                self.reqs.get_mut(&id).unwrap().executed_at.get_or_insert(now);
                self.record_session(&request, &batch);
                self.coverage.executes += 1;
                true
            }
            Err(Error::NotUnlocked { .. }) => {
                self.coverage.early_execute_refused += 1;
                false
            }
            Err(_) => false,
        }
    }

    /// `no_unlock_before_base` lives here: every first execute is checked against the shadow.
    fn check_first_execute(&mut self, id: RequestId, request: &Request, shadow: &ShadowRequest, now: Ms) {
        assert!(now >= shadow.base, "request {id} signed before its base unlock: {now} < {}", shadow.base);
        assert!(now >= shadow.base + shadow.hold, "request {id} signed during a standing hold");
        assert_eq!(shadow.epoch, self.epoch, "old-epoch request {id} signed");
        assert!(now <= shadow.expires_at, "expired request {id} signed");
        let overridden = request.fee_override.is_some();
        let cap = request.fee_override.unwrap_or(self.policy.fee_cap_tx);
        assert!(request.fee <= cap, "fee over cap at execute");
        let charge = request.fee;
        self.charges.retain(|(at, _, _)| now < at + DAY);
        let used: Sats = self.charges.iter().map(|c| c.1).sum();
        if !overridden {
            assert!(used + charge <= self.policy.fee_budget_24h, "24 h fee budget passed without an override");
        }
        self.charges.push((now, charge, overridden));
        assert_eq!(self.h.v.fee_used_24h(now), used + charge, "budget charged at execute, once");
        for input in &request.inputs {
            self.pins.entry(input.outpoint).or_insert(input.value);
        }
        if request.inputs.len() > 1 && matches!(shadow.kind, RequestKind::Normal) {
            self.coverage.multi_sessions += 1;
        }
        if shadow.hold == 0 && request.hold_used {
            self.coverage.executed_with_hold_cleared += 1;
        }
        let cap_for_session = request.fee_override.unwrap_or(self.policy.fee_cap_tx);
        self.sessions.push(Session {
            request: id,
            prevouts: request.inputs.iter().map(|i| i.outpoint).collect(),
            declared: request.inputs.iter().map(|i| i.value).collect(),
            outputs: request.outputs.clone(),
            signed: BTreeSet::new(),
            allowed_fee: cap_for_session,
        });
    }

    fn record_session(&mut self, request: &Request, batch: &SignBatch) {
        // A signature is presumed public from the moment it is asked for.
        let session = self
            .sessions
            .iter_mut()
            .rev()
            .find(|s| s.request == request.id)
            .expect("session recorded at first execute");
        session.signed.extend(batch.indices.iter().copied());
    }

    fn do_set_policy(&mut self, kind: usize) -> bool {
        let p = self.h.v.policy;
        let next = match kind % 6 {
            0 => Policy { t_known_ms: p.t_known_ms * 2, t_new_ms: p.t_new_ms * 2, t_new_unguarded_ms: p.t_new_unguarded_ms * 2, hold_ms: p.hold_ms * 2, ..p },
            1 => Policy { t_known_ms: p.t_known_ms / 2, t_new_ms: p.t_new_ms / 2, t_new_unguarded_ms: p.t_new_unguarded_ms / 2, hold_ms: p.hold_ms / 2, ..p },
            2 => Policy { fee_cap_tx: p.fee_cap_tx * 2, fee_budget_24h: p.fee_budget_24h * 2, ..p },
            3 => Policy { fee_cap_tx: (p.fee_cap_tx / 2).max(500), ..p },
            4 => Policy { t_stuck_ms: p.t_stuck_ms / 2, ..p },
            _ => Policy { outflow_cap_24h: p.outflow_cap_24h / 2, ..p },
        };
        match self.h.set_policy(next) {
            Ok(PolicyOutcome::Applied) => {
                assert!(!next.loosens(&self.policy), "a loosening applied at once");
                self.policy = next;
                self.grants.retain(|_, g| !matches!(g.kind, GrantKind::LoosenPolicy { .. }));
                true
            }
            Ok(PolicyOutcome::Grant(grant)) => {
                self.grants.insert(grant, ShadowGrant {
                    ready_at: self.h.now + self.policy.t_new_ms,
                    kind: GrantKind::LoosenPolicy { policy: next },
                });
                true
            }
            Err(_) => false,
        }
    }

    fn check_invariants(&mut self, action: &Action) {
        let v = &self.h.v;
        assert_eq!(v.policy, self.policy, "policy moved without its rule: {action:?}");
        assert_eq!(v.spend_epoch, self.epoch);
        assert_eq!(v.k_s, self.spend_key);
        assert_eq!(v.k_s_suspended, self.suspended);
        assert_eq!(v.known, self.known);
        assert!(v.recover_cancels <= 2);
        for (id, request) in &v.requests {
            let shadow = self.reqs.get(id).unwrap_or_else(|| panic!("request {id} unknown to the shadow after {action:?}"));
            assert_eq!(request.base_unlock, shadow.base, "base unlock of {id} moved after {action:?}");
            assert!(request.unlock >= request.base_unlock, "unlock of {id} below base after {action:?}");
            assert_eq!(request.unlock, shadow.base + shadow.hold, "unlock of {id} after {action:?}");
            if request.status == RequestStatus::Pending {
                let held = request.inputs.iter().all(|i| v.outpoint_state(&i.outpoint) == OutpointState::Pending(*id));
                assert!(held, "pending request {id} does not hold its outpoints");
            }
            if request.status == RequestStatus::Signing || request.status == RequestStatus::Signed {
                for i in &request.inputs {
                    assert!(v.pinned_value(&i.outpoint).is_some(), "executed input with no pin");
                }
            }
        }
        for (o, entry) in &v.ledger {
            if let Some(expected) = self.pins.get(o) {
                assert_eq!(entry.pinned_value, Some(*expected), "a pin changed after {action:?}");
            }
            match entry.state {
                OutpointState::Pending(id) => assert!(v.requests.contains_key(&id) && v.pending.contains(&id)),
                OutpointState::Signing(id) => assert!(v.requests.contains_key(&id)),
                OutpointState::Spent { .. } | OutpointState::Free => {}
            }
        }
        for o in self.pins.keys() {
            assert!(v.ledger.contains_key(o), "a pinned outpoint left the ledger");
        }
        for r in v.pending.iter() {
            assert!(v.requests.contains_key(r));
        }
        assert!(v.live_pending(self.h.now).len() <= MAX_PENDING);
    }
}

/// The transactions the recorded sessions could assemble. Signatures combine only when their
/// sessions agree on outpoints and outputs, and a signature counts only if its declared value is
/// the real one. Returns (real fee, the highest cap any session in the group passed).
pub fn valid_combinations(sessions: &[Session], reals: &BTreeMap<Outpoint, Sats>) -> Vec<(Sats, Sats)> {
    let mut groups: BTreeMap<(Vec<Outpoint>, Vec<u8>, Sats, Option<Sats>), Vec<&Session>> = BTreeMap::new();
    for s in sessions {
        let key = (s.prevouts.clone(), s.outputs.dest_script.clone(), s.outputs.dest_value, s.outputs.change_value);
        groups.entry(key).or_default().push(s);
    }
    let mut found = Vec::new();
    for ((prevouts, _, dest_value, change), group) in groups {
        let all_true = (0..prevouts.len()).all(|i| {
            let Some(real) = reals.get(&prevouts[i]) else { return false };
            group.iter().any(|s| s.signed.contains(&i) && s.declared[i] == *real)
        });
        if !all_true {
            continue;
        }
        let total: Sats = prevouts.iter().map(|o| reals[o]).sum();
        let out = dest_value + change.unwrap_or(0);
        if total >= out {
            let cap = group.iter().map(|s| s.allowed_fee).max().unwrap_or(0);
            found.push((total - out, cap));
        }
    }
    found
}

// ------------------------------------------------------------------ strategies

fn pick() -> impl Strategy<Value = usize> {
    0usize..16
}

fn coin_index() -> impl Strategy<Value = usize> {
    0usize..REALS.len()
}

fn time_step() -> impl Strategy<Value = Ms> {
    prop_oneof![
        Just(1_000),
        Just(MINUTE),
        Just(5 * MINUTE),
        Just(10 * MINUTE),
        Just(16 * MINUTE),
        Just(21 * MINUTE),
        Just(HOUR),
        Just(25 * HOUR),
        1u64..(30 * MINUTE),
    ]
}

pub fn action() -> impl Strategy<Value = Action> {
    let propose = (
        proptest::sample::subsequence(vec![0usize, 1, 2, 3], 1..=4).prop_shuffle(),
        proptest::collection::vec(any::<bool>(), 4),
        0usize..3,
        prop_oneof![Just(400u64), Just(600), Just(1_000), Just(1_500), Just(30_000)],
        any::<bool>(),
        prop::bool::weighted(0.05),
    )
        .prop_map(|(ops, declare_false, dest, fee, change, stale_key)| Action::Propose {
            ops,
            declare_false,
            dest,
            fee,
            change,
            stale_key,
        });
    // Rotation and freeze kill everything pending, so they stay rare or sequences die young.
    prop_oneof![
        40 => time_step().prop_map(Action::Advance),
        40 => propose,
        15 => (pick(), any::<bool>()).prop_map(|(pick, cold)| Action::Cancel { pick, cold }),
        10 => coin_index().prop_map(|coin| Action::CancelOwning { coin }),
        2 => any::<u8>().prop_map(|key| Action::Rotate { key }),
        30 => (pick(), 1usize..=4).prop_map(|(pick, max_inputs)| Action::Execute { pick, max_inputs }),
        15 => coin_index().prop_map(|coin| Action::ExecuteOwning { coin }),
        15 => pick().prop_map(|pick| Action::DeliverSignatures { pick }),
        20 => (coin_index(), any::<bool>(), prop_oneof![Just(400u64), Just(1_000)])
            .prop_map(|(coin, truth, fee)| Action::Reclaim { coin, truth, fee }),
        15 => (pick(), any::<bool>()).prop_map(|(pick, hold)| Action::Assess { pick, hold }),
        10 => pick().prop_map(|pick| Action::ClearHold { pick }),
        15 => Just(Action::Heartbeat),
        10 => (0usize..2).prop_map(|dest| Action::AddDest { dest }),
        5 => (0usize..2).prop_map(|dest| Action::RemoveDest { dest }),
        20 => pick().prop_map(|pick| Action::ApplyGrant { pick }),
        3 => pick().prop_map(|pick| Action::Veto { pick }),
        2 => (1u64..(4 * MINUTE)).prop_map(|ms| Action::Freeze { ms }),
        3 => Just(Action::Unfreeze),
        3 => Just(Action::RecoverBegin),
        3 => Just(Action::RecoverCancel),
        3 => Just(Action::RecoverFinish),
        8 => (0usize..6).prop_map(|kind| Action::SetPolicy { kind }),
        3 => any::<bool>().prop_map(|present| Action::SetGuard { present }),
        5 => (pick(), prop_oneof![Just(20u64), Just(100), Just(19)])
            .prop_map(|(pick, share)| Action::RaiseFeeCap { pick, share }),
    ]
}

/// The attack review's fee swap as a skeleton, with generated noise between its steps. Random
/// sequences alone rarely walk two coins through execute, T_stuck, reclaim and cancel.
pub fn fee_swap_sequence() -> impl Strategy<Value = Vec<Action>> {
    let noise = || proptest::collection::vec(action(), 0..3);
    (
        (0usize..3, 1usize..3),
        prop_oneof![Just(400u64), Just(600), Just(1_000)],
        any::<bool>(),
        proptest::collection::vec(noise(), 9),
    )
        .prop_map(|((a, offset), fee, order_swap, noises)| {
            let b = (a + offset) % 3;
            let (x, y) = if order_swap { (b, a) } else { (a, b) };
            let mut skeleton: Vec<Vec<Action>> = vec![
                vec![Action::Propose { ops: vec![x, y], declare_false: vec![false, true], dest: 0, fee, change: false, stale_key: false }],
                vec![Action::Advance(2 * MINUTE), Action::ExecuteOwning { coin: x }],
                vec![Action::Advance(20 * MINUTE), Action::Reclaim { coin: x, truth: false, fee }],
                vec![Action::CancelOwning { coin: x }],
                vec![Action::Reclaim { coin: y, truth: true, fee }],
                vec![Action::CancelOwning { coin: y }],
                vec![Action::Propose { ops: vec![x, y], declare_false: vec![true, false], dest: 0, fee, change: false, stale_key: false }],
                vec![Action::Advance(2 * MINUTE), Action::ExecuteOwning { coin: x }],
            ];
            let mut out = Vec::new();
            for (step, extra) in skeleton.drain(..).zip(noises) {
                out.extend(step);
                out.extend(extra);
            }
            out
        })
}

/// A coin signed, stuck, reclaimed and signed again, then a bump. This is what puts several
/// sessions over one outpoint in front of the property.
pub fn reclaim_sequence() -> impl Strategy<Value = Vec<Action>> {
    let noise = || proptest::collection::vec(action(), 0..2);
    (
        0usize..4,
        any::<bool>(),
        prop_oneof![Just(600u64), Just(1_000)],
        proptest::collection::vec(noise(), 8),
    )
        .prop_map(|(x, truth, fee, noises)| {
            let steps: Vec<Vec<Action>> = vec![
                vec![Action::Propose { ops: vec![x], declare_false: vec![!truth], dest: 0, fee, change: false, stale_key: false }],
                vec![Action::Advance(2 * MINUTE), Action::ExecuteOwning { coin: x }],
                vec![Action::Advance(21 * MINUTE), Action::Reclaim { coin: x, truth, fee: 400 }],
                vec![Action::Advance(2 * MINUTE), Action::ExecuteOwning { coin: x }],
                vec![Action::Advance(6 * MINUTE)],
                vec![Action::ExecuteOwning { coin: x }],
                vec![Action::Advance(21 * MINUTE), Action::Reclaim { coin: x, truth: !truth, fee: 600 }],
                vec![Action::Advance(2 * MINUTE), Action::ExecuteOwning { coin: x }],
            ];
            let mut out = Vec::new();
            for (step, extra) in steps.into_iter().zip(noises) {
                out.extend(step);
                out.extend(extra);
            }
            out
        })
}

pub fn sequence() -> impl Strategy<Value = Vec<Action>> {
    prop_oneof![
        2 => proptest::collection::vec(action(), 1..80),
        1 => fee_swap_sequence(),
        1 => reclaim_sequence(),
    ]
}
