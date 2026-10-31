//! Signed intents and WebAuthn. The core never sees a signature, only who signed.

use near_sdk::borsh::{self, BorshSerialize};
use near_sdk::serde::Deserialize;
use near_sdk::{env, require, AccountId};

use crate::api::{HexBytes, WebAuthn};

pub const SPEND_TAG: &str = "undo-spend-v1";
pub const PASSKEY_TAG: &str = "undo-passkey-v1";
pub const COLD_TAG: &str = "undo-cold-v1";
const CREATE_TAG: &str = "undo-create-v1";
const VAULT_ID_TAG: &str = "undo-vault-id-v1";
const LEAF_POP_TAG: &[u8] = b"undo-leaf-pop-v1";

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;
/// rpIdHash, flags and the sign count.
const AUTH_DATA_MIN: usize = 37;

/// Contract, vault, method, args hash, expiry, and a per-key nonce except on `cancel`.
#[derive(BorshSerialize)]
#[borsh(crate = "near_sdk::borsh")]
struct IntentBytes<'a> {
    tag: &'a str,
    contract: &'a AccountId,
    vault: &'a [u8; 32],
    method: &'a str,
    args_hash: [u8; 32],
    expires_at: u64,
    nonce: Option<u64>,
}

pub fn intent_digest<A: BorshSerialize>(
    tag: &str,
    vault: &[u8; 32],
    method: &str,
    args: &A,
    expires_at: u64,
    nonce: Option<u64>,
) -> [u8; 32] {
    let bytes = IntentBytes {
        tag,
        contract: &env::current_account_id(),
        vault,
        method,
        args_hash: env::sha256_array(borsh::to_vec(args).unwrap()),
        expires_at,
        nonce,
    };
    env::sha256_array(borsh::to_vec(&bytes).unwrap())
}

/// Hash of the keys, the CSV and the contract. `K_m` is not in it, because `K_m` is derived from
/// the path this id names. So nobody can squat an id before creation lands, since proofs of
/// possession for these same keys are required to create it.
pub fn vault_id(
    k_s: &[u8; 32],
    k_u: &[u8],
    k_e_leaf: &[u8],
    k_e_intent: &[u8],
    k_p: &[u8],
    csv: u32,
) -> [u8; 32] {
    let bytes = (VAULT_ID_TAG, env::current_account_id(), k_s, k_u, k_e_leaf, k_e_intent, k_p, csv);
    env::sha256_array(borsh::to_vec(&bytes).unwrap())
}

/// What every proof of possession signs. It binds the choices that are not part of the id, so a
/// relay cannot replay the proofs with a different `K_m`, guard or policy.
pub fn create_digest(
    vault: &[u8; 32],
    k_m: &[u8],
    rp_id_hash: &[u8; 32],
    guard: &Option<AccountId>,
    policy: &undo_core::Policy,
    expires_at: u64,
) -> [u8; 32] {
    let bytes = (CREATE_TAG, env::current_account_id(), vault, k_m, rp_id_hash, guard, policy, expires_at);
    env::sha256_array(borsh::to_vec(&bytes).unwrap())
}

/// What the Bitcoin escape key signs, once, at creation. This is the only thing that key ever signs
/// besides a real escape, so it must not be possible to make it equal a sighash. A sighash is
/// SHA-256 of exactly 32 bytes. This is SHA-256 of 48 bytes, so the two meet only by a SHA-256
/// collision, whatever the digest holds.
pub fn leaf_pop_digest(create_digest: &[u8; 32]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(LEAF_POP_TAG.len() + 32);
    preimage.extend_from_slice(LEAF_POP_TAG);
    preimage.extend_from_slice(create_digest);
    env::sha256_array(&preimage)
}

pub fn compress(xy: &[u8; 64]) -> [u8; 33] {
    let mut out = [0u8; 33];
    out[0] = 2 + (xy[63] & 1);
    out[1..].copy_from_slice(&xy[..32]);
    out
}

/// Recovers the signer of `digest` from r || s || v and compares it with a compressed key.
/// Either S form is accepted; DER encoding normalises later.
pub fn secp_signed_by(digest: &[u8; 32], rsv: &[u8], key: &[u8]) -> bool {
    if rsv.len() != 65 || rsv[64] > 3 {
        return false;
    }
    env::ecrecover(digest, &rsv[..64], rsv[64], false).is_some_and(|xy| compress(&xy).as_slice() == key)
}

pub fn require_secp(digest: &[u8; 32], rsv: &HexBytes, key: &[u8], what: &str) {
    require!(secp_signed_by(digest, &rsv.0, key), format!("bad {what} signature"));
}

pub fn require_ed25519(digest: &[u8; 32], signature: &HexBytes, key: &[u8; 32], what: &str) {
    let sig: [u8; 64] = signature.fixed("signature");
    require!(env::ed25519_verify(&sig, digest, key), format!("bad {what} signature"));
}

#[derive(Deserialize)]
#[serde(crate = "near_sdk::serde")]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: bool,
}

pub struct AssertionFlags {
    pub backup_eligible: bool,
    pub backup_state: bool,
}

/// Unpadded base64url, for comparing the challenge.
fn base64url(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len() * 4 / 3 + 2);
    for chunk in bytes.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for i in 0..=chunk.len() {
            out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

/// Requires `webauthn.get`, this digest as the challenge, the stored rpIdHash, UP and UV, no
/// `crossOrigin`, and an allowed origin. Both S forms pass: a nonce already stops replay, and
/// authenticators often emit high S, so a low-S rule would fail about half of real cancels.
pub fn require_webauthn(
    assertion: &WebAuthn,
    digest: &[u8; 32],
    pubkey: &[u8],
    rp_id_hash: &[u8; 32],
    origins: &[String],
) -> AssertionFlags {
    let auth = &assertion.authenticator_data.0;
    require!(auth.len() >= AUTH_DATA_MIN, "webauthn: short authenticator data");
    require!(&auth[..32] == rp_id_hash, "webauthn: wrong rp id");
    let flags = auth[32];
    require!(flags & FLAG_UP != 0, "webauthn: user not present");
    require!(flags & FLAG_UV != 0, "webauthn: user not verified");

    let client: ClientData = near_sdk::serde_json::from_slice(&assertion.client_data_json.0)
        .unwrap_or_else(|_| env::panic_str("webauthn: bad client data"));
    require!(client.kind == "webauthn.get", "webauthn: wrong type");
    require!(client.challenge == base64url(digest), "webauthn: wrong challenge");
    require!(!client.cross_origin, "webauthn: cross origin");
    require!(origins.contains(&client.origin), "webauthn: origin not allowed");

    let mut signed = Vec::with_capacity(auth.len() + 32);
    signed.extend_from_slice(auth);
    signed.extend_from_slice(&env::sha256_array(&assertion.client_data_json.0));
    let prehash = env::sha256_array(&signed);
    let sig: [u8; 64] = assertion.signature.fixed("webauthn signature");
    let key: [u8; 33] = pubkey.try_into().unwrap_or_else(|_| env::panic_str("webauthn: bad stored key"));
    require!(env::p256_verify(&sig, &prehash, &key), "webauthn: bad signature");
    AssertionFlags { backup_eligible: flags & FLAG_BE != 0, backup_state: flags & FLAG_BS != 0 }
}
