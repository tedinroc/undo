//! Fixtures shared by the scenario, property and consensus tests. Keys here are fixed labels with
//! no secret behind them, and they never touch a real signature except in the [test-only]
//! consensus test, which derives its own.
#![allow(dead_code)]

pub mod world;

use undo_core::*;

pub const SPEND: [u8; 32] = [0x11; 32];
pub const SPEND_2: [u8; 32] = [0x12; 32];
pub const GUARD: &str = "guard.test";

pub fn compressed(fill: u8, prefix: u8) -> Vec<u8> {
    let mut key = vec![prefix];
    key.extend([fill; 32]);
    key
}
pub fn k_u() -> Vec<u8> {
    compressed(0x21, 2)
}
pub fn k_m() -> Vec<u8> {
    compressed(0x22, 3)
}
pub fn k_e_leaf() -> Vec<u8> {
    compressed(0x23, 2)
}
pub fn k_e_intent() -> Vec<u8> {
    compressed(0x24, 3)
}
pub fn passkey(fill: u8) -> Passkey {
    Passkey {
        pubkey: compressed(fill, 2),
        rp_id_hash: [0x31; 32],
        backup_eligible: false,
        backup_state: false,
    }
}
pub fn p2wsh(fill: u8) -> Vec<u8> {
    let mut s = vec![0x00, 0x20];
    s.extend([fill; 32]);
    s
}
pub fn p2wpkh(fill: u8) -> Vec<u8> {
    let mut s = vec![0x00, 0x14];
    s.extend([fill; 20]);
    s
}
pub fn p2tr(fill: u8) -> Vec<u8> {
    let mut s = vec![0x51, 0x20];
    s.extend([fill; 32]);
    s
}
pub fn op(i: u8) -> Outpoint {
    Outpoint { txid: [i; 32], vout: i as u32 }
}

pub const OUTFLOW_CAP: Sats = 2_000_000;

pub fn create_args(policy: Policy, fixed: Fixed, bounds: Bounds, spk: Vec<u8>) -> CreateArgs {
    CreateArgs {
        k_s: SPEND,
        k_u: k_u(),
        k_m: k_m(),
        k_e_leaf: k_e_leaf(),
        k_e_intent: k_e_intent(),
        passkey: passkey(0x30),
        guard: Some(GUARD.to_string()),
        csv_blocks: 6,
        vault_spk: spk,
        policy,
        fixed,
        bounds,
    }
}

pub fn test_coin_vault() -> Vault {
    let mut v = Vault::create(create_args(
        Policy::test_coin(OUTFLOW_CAP),
        Fixed::test_coin(),
        Bounds::test_coin(OUTFLOW_CAP),
        p2wsh(0x77),
    ))
    .unwrap();
    v.activate(&k_m()).unwrap();
    v
}

pub fn mainnet_vault() -> Vault {
    let mut v = Vault::create(create_args(
        Policy::mainnet_proof(OUTFLOW_CAP),
        Fixed::mainnet_proof(),
        Bounds::mainnet(OUTFLOW_CAP),
        p2wsh(0x77),
    ))
    .unwrap();
    v.activate(&k_m()).unwrap();
    v
}

/// Stands in for the txid the shell computes. This crate treats it as opaque, so anything that
/// depends only on the inputs and outputs will do, and nothing here relies on how it is made. The
/// byte-exact one is checked on the wasm in `tests/tests/review2.rs`.
pub fn txid_of(r: &Request) -> [u8; 32] {
    use std::hash::{DefaultHasher, Hash, Hasher};
    let mut out = [0u8; 32];
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        let mut h = DefaultHasher::new();
        (i, &r.inputs.iter().map(|x| x.outpoint).collect::<Vec<_>>(), &r.outputs.dest_script, r.outputs.dest_value, r.outputs.change_value).hash(&mut h);
        chunk.copy_from_slice(&h.finish().to_le_bytes());
    }
    out
}

/// Drives a vault the way the shell must: a call runs on a copy, and the copy is kept only on `Ok`.
#[derive(Clone)]
pub struct H {
    pub v: Vault,
    pub now: Ms,
    pub height: u64,
}

pub const START: Ms = 1_000_000_000;

impl H {
    pub fn new(v: Vault) -> H {
        H { v, now: START, height: 1_000 }
    }
    pub fn test_coin() -> H {
        H::new(test_coin_vault())
    }
    pub fn mainnet() -> H {
        H::new(mainnet_vault())
    }
    pub fn advance(&mut self, ms: Ms) {
        self.now += ms;
        self.height += ms / 1_000;
    }
    pub fn tx<T>(&mut self, f: impl FnOnce(&mut Vault, Ms) -> Result<T, Error>) -> Result<T, Error> {
        let mut next = self.v.clone();
        let result = f(&mut next, self.now);
        if result.is_ok() {
            self.v = next;
        }
        result
    }
    fn exp(&self) -> Ms {
        self.now + HOUR
    }
    pub fn sp(&self) -> Intent {
        Intent { nonce: self.v.spend_nonce, expires_at: self.exp() }
    }
    pub fn pk(&self) -> Intent {
        Intent { nonce: self.v.passkey_nonce, expires_at: self.exp() }
    }
    pub fn ck(&self) -> Intent {
        Intent { nonce: self.v.cold_nonce, expires_at: self.exp() }
    }
    pub fn spend_caller(&self) -> Caller {
        Caller::SpendKey(self.v.k_s)
    }
    pub fn pass_caller(&self) -> Caller {
        Caller::Passkey(self.v.passkey.pubkey.clone())
    }
    pub fn cold_caller(&self) -> Caller {
        Caller::Cold(k_e_intent())
    }
    pub fn guard_caller(&self) -> Caller {
        Caller::Guard(GUARD.to_string())
    }

    pub fn propose(
        &mut self,
        inputs: &[(Outpoint, Sats)],
        dest: &[u8],
        dest_value: Sats,
        change: Option<Sats>,
    ) -> Result<Proposed, Error> {
        let args = ProposeArgs {
            inputs: inputs.iter().map(|(o, v)| Input { outpoint: *o, value: *v }).collect(),
            outputs: Outputs { dest_script: dest.to_vec(), dest_value, change_value: change },
            half_sigs: vec![vec![0xaa; 65]; inputs.len()],
        };
        let (caller, intent) = (self.spend_caller(), self.sp());
        self.tx(|v, now| v.propose(&caller, intent, args, now))
    }
    /// A self-spend with no change, paying `fee` over the declared inputs.
    pub fn self_spend(&mut self, inputs: &[(Outpoint, Sats)], fee: Sats) -> Result<Proposed, Error> {
        let total: Sats = inputs.iter().map(|(_, v)| *v).sum();
        let spk = self.v.vault_spk.clone();
        self.propose(inputs, &spk, total - fee, None)
    }
    pub fn execute(&mut self, id: RequestId, max: usize) -> Result<SignBatch, Error> {
        let height = self.height;
        let txid = self.v.requests.get(&id).map_or([0; 32], txid_of);
        self.tx(|v, now| v.execute(id, max, now, height, txid))
    }
    /// Delivers a good signature for every input in `batch`.
    pub fn sign_batch(&mut self, id: RequestId, batch: &SignBatch) {
        for index in &batch.indices {
            let out = self.v.on_signed(id, batch.attempt, *index, [7; 32], [7; 32], Some(vec![0xbb]), self.now);
            assert!(matches!(out, SignedOutcome::Stored { .. }), "{out:?}");
        }
    }
    pub fn execute_all_signed(&mut self, id: RequestId) {
        let batch = self.execute(id, MAX_INPUTS).unwrap();
        self.sign_batch(id, &batch);
    }
    pub fn reclaim(&mut self, outpoint: Outpoint, value: Sats, fee: Sats) -> Result<Proposed, Error> {
        let (caller, intent) = (self.spend_caller(), self.sp());
        self.tx(|v, now| v.reclaim(&caller, intent, outpoint, value, fee, vec![0xaa; 65], now))
    }
    pub fn bump(&mut self, id: RequestId, new_fee: Sats) -> Result<Proposed, Error> {
        let n = self.v.requests.get(&id).map_or(1, |r| r.inputs.len());
        let (caller, intent) = (self.spend_caller(), self.sp());
        self.tx(|v, now| v.bump(&caller, intent, id, new_fee, vec![vec![0xaa; 65]; n], now))
    }
    pub fn cancel(&mut self, id: RequestId) -> Result<(), Error> {
        let (caller, exp) = (self.pass_caller(), self.exp());
        self.tx(|v, now| v.cancel(&caller, exp, id, now))
    }
    pub fn cancel_cold(&mut self, id: RequestId) -> Result<(), Error> {
        let (caller, exp) = (self.cold_caller(), self.exp());
        self.tx(|v, now| v.cancel(&caller, exp, id, now))
    }
    pub fn rotate(&mut self, new_key: [u8; 32]) -> Result<GrantId, Error> {
        let (caller, intent) = (self.pass_caller(), self.pk());
        self.tx(|v, now| v.cancel_all_and_rotate(&caller, intent, new_key, now))
    }
    pub fn apply(&mut self, id: GrantId) -> Result<(), Error> {
        self.tx(|v, now| v.apply_grant(id, now))
    }
    pub fn add_dest(&mut self, script: &[u8]) -> Result<GrantId, Error> {
        let (caller, intent) = (self.pass_caller(), self.pk());
        let script = script.to_vec();
        self.tx(|v, now| v.add_destination(&caller, intent, script, now))
    }
    pub fn remove_dest(&mut self, script: &[u8]) -> Result<(), Error> {
        let (caller, intent) = (self.pass_caller(), self.pk());
        self.tx(|v, now| v.remove_destination(&caller, intent, script, now))
    }
    pub fn set_policy(&mut self, policy: Policy) -> Result<PolicyOutcome, Error> {
        let (caller, intent) = (self.pass_caller(), self.pk());
        self.tx(|v, now| v.set_policy(&caller, intent, policy, now))
    }
    pub fn set_guard(&mut self, guard: Option<String>) -> Result<GrantId, Error> {
        let (caller, intent) = (self.pass_caller(), self.pk());
        self.tx(|v, now| v.set_guard(&caller, intent, guard, now))
    }
    pub fn raise_fee_cap(&mut self, id: RequestId, cap: Sats) -> Result<(), Error> {
        let (caller, intent) = (self.pass_caller(), self.pk());
        self.tx(|v, now| v.raise_fee_cap(&caller, intent, id, cap, now))
    }
    pub fn clear_hold(&mut self, id: RequestId) -> Result<(), Error> {
        let (caller, intent) = (self.pass_caller(), self.pk());
        self.tx(|v, now| v.clear_hold(&caller, intent, id, now))
    }
    pub fn recover_cancel(&mut self) -> Result<(), Error> {
        let (caller, intent) = (self.pass_caller(), self.pk());
        self.tx(|v, now| v.recover_cancel(&caller, intent, now))
    }
    pub fn freeze(&mut self, until: Ms) -> Result<(), Error> {
        let (caller, intent) = (self.cold_caller(), self.ck());
        self.tx(|v, now| v.freeze(&caller, intent, until, now))
    }
    pub fn unfreeze(&mut self) -> Result<(), Error> {
        let (caller, intent) = (self.cold_caller(), self.ck());
        self.tx(|v, now| v.unfreeze(&caller, intent, now))
    }
    pub fn veto(&mut self, id: GrantId) -> Result<(), Error> {
        let (caller, intent) = (self.cold_caller(), self.ck());
        self.tx(|v, now| v.veto_grant(&caller, intent, id, now))
    }
    pub fn recover_begin(&mut self, new: Passkey) -> Result<(), Error> {
        let (caller, intent) = (self.cold_caller(), self.ck());
        self.tx(|v, now| v.recover_begin(&caller, intent, new, now))
    }
    pub fn recover_finish(&mut self) -> Result<(), Error> {
        self.tx(|v, now| v.recover_finish(now))
    }
    pub fn heartbeat(&mut self) -> Result<(), Error> {
        let caller = self.guard_caller();
        self.tx(|v, now| v.heartbeat(&caller, now))
    }
    pub fn assess(&mut self, id: RequestId, hold: bool) -> Result<(), Error> {
        let caller = self.guard_caller();
        self.tx(|v, now| v.assess(&caller, id, hold, now))
    }
}
