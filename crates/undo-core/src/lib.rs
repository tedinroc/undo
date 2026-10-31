//! Pure state machine for Undo vaults: no NEAR tooling, no crypto, and no dependencies unless the
//! contract turns on the `borsh` feature for its storage encoding.
//!
//! The contract shell verifies every signature, then calls these methods with a [`Caller`] naming
//! the key that signed. It writes the vault back only on `Ok`, so a refused call changes nothing.
//! Methods therefore mutate as they go and do not undo themselves on `Err`.
//!
//! Not in this crate, on purpose: signature checks, sighash computation, storage credit, the
//! feature snapshot, WebAuthn parsing and the upgrade queue.

#![forbid(unsafe_code)]

mod error;
mod policy;
mod request;
mod types;
mod vault;

pub use error::Error;
pub use policy::{
    Bounds, Fixed, Policy, DAY, FEE_OVERRIDE_DIVISOR, HEARTBEAT_STALE_MS, HOUR, MAX_GRANTS,
    MAX_INPUTS, MAX_PENDING, MIN_FEE_RATE, MINUTE, RECOVERY_CANCEL_CAP, RETRY_AFTER_BLOCKS,
};
pub use request::{Request, RequestKind, RequestStatus, Tier};
pub use types::{
    dust_limit, estimate_vsize, Caller, HalfSig, Input, Intent, MpcSig, Ms, Outpoint, Outputs,
    Passkey, RequestId, Sats, ScriptKind, GrantId, MAX_MONEY,
};
pub use vault::{
    CreateArgs, Grant, GrantKind, LedgerEntry, OutpointState, PolicyOutcome, ProposeArgs,
    ProposeCheck, Proposed, Recovery, SignBatch, SignedOutcome, Vault,
};
