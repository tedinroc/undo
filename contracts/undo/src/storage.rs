//! Vault rows, per-key history and per-vault storage credit.
//!
//! A vault is one small row plus one storage entry per request and per ledger entry. A call loads the
//! row and only the entries it touches, and writes back only what changed, so what a vault has done
//! in the past does not weigh on what it does next. Above all it does not weigh on `on_signed`, whose
//! gas is fixed when `execute` runs.
//!
//! The contract's own balance never pays for vault growth. A vault's bytes are paid from its credit,
//! and deleting bytes pays them back. The row also keeps a reservation: the bytes that `execute`,
//! `on_signed`, a passkey rotation and the cold key's methods can still add. Those methods must never
//! fail for lack of credit, so the bytes are paid for ahead of time. A call adjusts the reservation by
//! what it changes, so it never has to read the whole vault to know the total.
//!
//! The same goes for all vaults together. Credit and reservations sit in the contract's balance, and
//! nothing but the running total in `Stats` keeps new code from spending them.

use std::collections::BTreeMap;

use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::{env, AccountId};
use undo_core::{GrantKind, LedgerEntry, Outpoint, Request, RequestId, RequestStatus, Vault};

/// Option tag stays, then length and r || s.
const SIG_BYTES: u64 = 4 + 64;
/// One entry of `in_flight`.
const IN_FLIGHT_BYTES: u64 = 8;
/// `pinned_value` and `signing_since` become `Some` in the ledger entry at first execute.
const PIN_BYTES: u64 = 16;
/// `first_execute_at` and one fee-window entry.
const FIRST_EXECUTE_BYTES: u64 = 8 + 16;
/// `fee_override` becoming `Some`: an exit must not need new credit.
const FEE_OVERRIDE_BYTES: u64 = 8;
/// A coin this request's transaction pays back to the vault gets a ledger entry at first execute:
/// the entry's overhead, its key, and a state tag, an empty pin, an empty `signing_since` and a set
/// `born_at`.
const CHILD_ENTRY_BYTES: u64 = 40 + 69 + 1 + 1 + 1 + 9;
/// `signed_at` becomes `Some` when the last signature lands.
const SIGNED_AT_BYTES: u64 = 8;
/// A waiting rotation grant: id, kind tag, key, two times. The panic button must always fit.
const ROTATE_GRANT_BYTES: u64 = 8 + 1 + 32 + 16;
/// `frozen_until` becoming `Some`.
const FREEZE_BYTES: u64 = 8;
/// A waiting recovery: key with its length, rp id hash, two flags, two times.
const RECOVERY_BYTES: u64 = 4 + 33 + 32 + 2 + 16;
/// The public count's entry for this vault's passkey: overhead, tag and hash, one value byte. The
/// first completed cancel writes it, and a cancel must not need credit.
const COUNT_ENTRY_BYTES: u64 = 40 + 33 + 1;

#[derive(BorshSerialize, BorshDeserialize)]
#[borsh(crate = "near_sdk::borsh")]
pub struct Row {
    /// Fixed width, so its value never changes the row's size.
    pub credit: u128,
    /// Fixed width too. The bytes this vault can still grow by without being asked for credit.
    pub reserved: u64,
    pub creator: AccountId,
    pub vault: Vault,
}

/// What this vault has paid in and not yet used: its credit, and what its reservation paid for.
fn paid_in(row: &Row) -> u128 {
    row.credit.saturating_add(cost(row.reserved))
}

fn row_reserve(vault: &Vault) -> u64 {
    let mut bytes = 0;
    if !vault.grants.iter().any(|g| matches!(g.kind, GrantKind::RotateSpend { .. })) {
        bytes += ROTATE_GRANT_BYTES;
    }
    if vault.frozen_until.is_none() {
        bytes += FREEZE_BYTES;
    }
    if vault.recovery.is_none() {
        bytes += RECOVERY_BYTES;
    }
    if !vault.completed {
        bytes += COUNT_ENTRY_BYTES;
    }
    bytes
}

fn request_reserve(request: &Request) -> u64 {
    let missing = request.sigs.iter().filter(|s| s.is_none()).count() as u64;
    match request.status {
        RequestStatus::Pending => {
            let override_bytes = if request.fee_override.is_none() { FEE_OVERRIDE_BYTES } else { 0 };
            missing * (SIG_BYTES + IN_FLIGHT_BYTES + PIN_BYTES)
                + FIRST_EXECUTE_BYTES
                + override_bytes
                + SIGNED_AT_BYTES
                + request.vault_vouts().len() as u64 * CHILD_ENTRY_BYTES
        }
        RequestStatus::Signing => {
            missing * SIG_BYTES
                + missing.saturating_sub(request.in_flight.len() as u64) * IN_FLIGHT_BYTES
                + SIGNED_AT_BYTES
        }
        RequestStatus::Signed => 0,
    }
}

fn with_id(tag: u8, id: &[u8; 32], extra: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(33 + extra);
    key.push(tag);
    key.extend_from_slice(id);
    key
}

fn row_key(id: &[u8; 32]) -> Vec<u8> {
    with_id(b'v', id, 0)
}

fn request_key(id: &[u8; 32], request: RequestId) -> Vec<u8> {
    let mut key = with_id(b'r', id, 8);
    key.extend_from_slice(&request.to_le_bytes());
    key
}

fn ledger_key(id: &[u8; 32], outpoint: &Outpoint) -> Vec<u8> {
    let mut key = with_id(b'l', id, 36);
    key.extend_from_slice(&outpoint.txid);
    key.extend_from_slice(&outpoint.vout.to_le_bytes());
    key
}

pub fn cost(bytes: u64) -> u128 {
    env::storage_byte_cost().as_yoctonear().saturating_mul(u128::from(bytes))
}

fn encoded<T: BorshSerialize>(value: &T) -> Vec<u8> {
    borsh::to_vec(value).unwrap_or_else(|_| env::panic_str("bad row"))
}

/// Whether a passkey is in the public count.
pub fn passkey_counted(passkey: &[u8]) -> bool {
    let mut key = vec![b'p'];
    key.extend_from_slice(&env::sha256_array(passkey));
    env::storage_has_key(&key)
}

pub fn exists(id: &[u8; 32]) -> bool {
    env::storage_has_key(&row_key(id))
}

/// Roughly what a proposal costs, for a status line, measured on a vault with no credit: nothing refuses
/// on these, because a proposal is refused by what it really grows by. A one-input proposal and the
/// largest there is.
pub fn proposal_cost() -> (u128, u128) {
    (cost(650), cost(5_700))
}

/// A loaded vault, and what its pieces held when they were read.
pub struct Loaded {
    pub row: Row,
    pub row_bytes: u64,
    raw_row: Vec<u8>,
    raw_requests: BTreeMap<RequestId, Vec<u8>>,
    raw_ledger: BTreeMap<Outpoint, Option<Vec<u8>>>,
    /// The part of `row.reserved` that the pieces read so far account for.
    reserve_read: u64,
    /// Bytes written outside the row and its entries since loading, which `commit` settles too.
    written_early: u64,
    /// What [`paid_in`] read when this was loaded, so the running total can move by the difference.
    paid_in_read: u128,
}

/// The row alone. For views, and for callers that name exactly what they touch.
pub fn try_load_row(id: &[u8; 32]) -> Option<Loaded> {
    let raw_row = env::storage_read(&row_key(id))?;
    let row = Row::try_from_slice(&raw_row).unwrap_or_else(|_| env::panic_str("bad row"));
    let reserve_read = row_reserve(&row.vault);
    let paid_in_read = paid_in(&row);
    Some(Loaded {
        row,
        row_bytes: raw_row.len() as u64,
        raw_row,
        raw_requests: BTreeMap::new(),
        raw_ledger: BTreeMap::new(),
        reserve_read,
        written_early: 0,
        paid_in_read,
    })
}

pub fn load_row(id: &[u8; 32]) -> Loaded {
    try_load_row(id).unwrap_or_else(|| env::panic_str("no such vault"))
}

/// The row and every pending request, which `undo-core` sweeps on each state change. A pending
/// request that is already dead brings its ledger entries too, because the sweep frees them.
pub fn load(id: &[u8; 32]) -> Loaded {
    let mut loaded = load_row(id);
    let now = env::block_timestamp_ms();
    for request in loaded.row.vault.pending.clone() {
        loaded.fetch_request(id, request);
        if !loaded.row.vault.is_live(request, now) {
            loaded.load_inputs(id, request);
        }
    }
    loaded
}

impl Loaded {
    /// One request, without its ledger entries. False when there is no such request.
    pub fn fetch_request(&mut self, id: &[u8; 32], request: RequestId) -> bool {
        if self.raw_requests.contains_key(&request) {
            return true;
        }
        let Some(raw) = env::storage_read(&request_key(id, request)) else { return false };
        let parsed = Request::try_from_slice(&raw).unwrap_or_else(|_| env::panic_str("bad request"));
        self.reserve_read += request_reserve(&parsed);
        self.raw_requests.insert(request, raw);
        self.row.vault.requests.insert(request, parsed);
        true
    }

    /// The ledger entries of a request's inputs. Does nothing for a request not fetched.
    pub fn load_inputs(&mut self, id: &[u8; 32], request: RequestId) {
        let inputs: Vec<Outpoint> = match self.row.vault.requests.get(&request) {
            Some(r) => r.inputs.iter().map(|i| i.outpoint).collect(),
            None => return,
        };
        self.load_outpoints(id, &inputs);
    }

    /// One request and its ledger entries.
    pub fn load_request(&mut self, id: &[u8; 32], request: RequestId) {
        if self.fetch_request(id, request) {
            self.load_inputs(id, request);
        }
    }

    /// For a request not yet executed: reads the ledger entries of the coins its transaction pays back
    /// to the vault, and returns that transaction's id. Zeros for anything else, where the core does
    /// not read it.
    pub fn load_children(&mut self, id: &[u8; 32], request: RequestId) -> [u8; 32] {
        let vault = &self.row.vault;
        let Some(stored) = vault.requests.get(&request).filter(|r| r.status == RequestStatus::Pending) else {
            return [0; 32];
        };
        let txid = crate::btc::txid_of(&vault.vault_spk, stored);
        let children: Vec<Outpoint> = stored.vault_vouts().into_iter().map(|vout| Outpoint { txid, vout }).collect();
        self.load_outpoints(id, &children);
        txid
    }

    /// Records this vault's passkey in the public count. True when the passkey is new to it. Its bytes
    /// come from what the row reserved for this, and a passkey already counted gives them back.
    pub fn count_passkey(&mut self) -> bool {
        let mut key = vec![b'p'];
        key.extend_from_slice(&env::sha256_array(&self.row.vault.passkey.pubkey));
        if env::storage_has_key(&key) {
            return false;
        }
        let before = env::storage_usage();
        env::storage_write(&key, &[1]);
        self.written_early += env::storage_usage() - before;
        true
    }

    /// `undo-core` reads an outpoint with no entry as free and unpinned, so every outpoint a call can
    /// touch must come through here first. Missing one would forget its pin.
    pub fn load_outpoints(&mut self, id: &[u8; 32], outpoints: &[Outpoint]) {
        for outpoint in outpoints {
            if self.raw_ledger.contains_key(outpoint) {
                continue;
            }
            let raw = env::storage_read(&ledger_key(id, outpoint));
            if let Some(bytes) = &raw {
                let entry = LedgerEntry::try_from_slice(bytes).unwrap_or_else(|_| env::panic_str("bad ledger"));
                self.row.vault.ledger.insert(*outpoint, entry);
            }
            self.raw_ledger.insert(*outpoint, raw);
        }
    }
}

/// What a method may do when the credit cannot pay for the growth.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Short {
    /// Refuse. For methods a spend key can use to grow state.
    Refuse,
    /// Keep going. For methods that must not fail, whose growth the reservation already covers.
    Reserved,
}

impl Loaded {
    /// Writes what changed, settles the credit for the change in bytes plus reservation, and moves the
    /// total the vaults have paid in by what this one's share became.
    pub fn commit(mut self, id: &[u8; 32], short: Short, vault_funds: &mut u128) {
        let usage_before = env::storage_usage() - self.written_early;
        let requests = core::mem::take(&mut self.row.vault.requests);
        let ledger = core::mem::take(&mut self.row.vault.ledger);

        for request in self.raw_requests.keys() {
            if !requests.contains_key(request) {
                env::storage_remove(&request_key(id, *request));
            }
        }
        for (request, value) in &requests {
            let bytes = encoded(value);
            if self.raw_requests.get(request) != Some(&bytes) {
                env::storage_write(&request_key(id, *request), &bytes);
            }
        }
        for outpoint in self.raw_ledger.keys() {
            if !ledger.contains_key(outpoint) {
                env::storage_remove(&ledger_key(id, outpoint));
            }
        }
        for (outpoint, value) in &ledger {
            let bytes = encoded(value);
            let unchanged = matches!(self.raw_ledger.get(outpoint), Some(Some(old)) if *old == bytes);
            if !unchanged {
                env::storage_write(&ledger_key(id, outpoint), &bytes);
            }
        }

        let reserve_after = row_reserve(&self.row.vault) + requests.values().map(request_reserve).sum::<u64>();
        self.row.reserved = self.row.reserved.saturating_sub(self.reserve_read) + reserve_after;
        // Credit and reservation are fixed width, so settling them cannot change the row's length.
        let row_after = borsh::object_length(&self.row).unwrap_or_else(|_| env::panic_str("bad row")) as u64;
        let before = usage_before + self.reserve_read;
        let after = env::storage_usage() + row_after - self.row_bytes + reserve_after;
        if after >= before {
            let need = cost(after - before);
            if need > self.row.credit {
                if short == Short::Refuse {
                    env::panic_str(&format!(
                        "storage credit short: need {need} yoctoNEAR, have {}",
                        self.row.credit
                    ));
                }
                env::log_str("undo:credit_short");
            }
            self.row.credit = self.row.credit.saturating_sub(need);
        } else {
            self.row.credit = self.row.credit.saturating_add(cost(before - after));
        }
        *vault_funds = vault_funds.saturating_sub(self.paid_in_read).saturating_add(paid_in(&self.row));
        let bytes = encoded(&self.row);
        if bytes != self.raw_row {
            env::storage_write(&row_key(id), &bytes);
        }
    }
}

/// First write of a row. The whole cost, with the entry's overhead, comes out of the attached
/// deposit. Anything above it stays as credit.
pub fn insert(id: &[u8; 32], mut row: Row, vault_funds: &mut u128) {
    let before = env::storage_usage();
    row.reserved = row_reserve(&row.vault);
    env::storage_write(&row_key(id), &encoded(&row));
    let used = env::storage_usage().saturating_sub(before) + row.reserved;
    let need = cost(used);
    if need > row.credit {
        env::panic_str(&format!("attach at least {need} yoctoNEAR for {used} bytes"));
    }
    row.credit -= need;
    *vault_funds = vault_funds.saturating_add(paid_in(&row));
    env::storage_write(&row_key(id), &encoded(&row));
}

/// Deletes a row and returns everything it held: its credit, and what its bytes and reservation
/// were paying for. Only for a vault that never activated, which has no requests or ledger entries.
pub fn remove(id: &[u8; 32], loaded: &Loaded, vault_funds: &mut u128) -> u128 {
    *vault_funds = vault_funds.saturating_sub(loaded.paid_in_read);
    let before = env::storage_usage();
    env::storage_remove(&row_key(id));
    let freed = before.saturating_sub(env::storage_usage()) + loaded.row.reserved;
    loaded.row.credit.saturating_add(cost(freed))
}
