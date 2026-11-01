//! Test-only stand-in for the live MPC signer. Same `sign` arguments, same response JSON,
//! same key derivation and the same yield/resume timeout behaviour. Never deploy it
//! anywhere that matters: its secret sits in contract state.

#[cfg(all(target_arch = "wasm32", not(near)))]
compile_error!("build with scripts/build.sh: this build has no --cfg near and no path remapping");

use k256::ecdsa::SigningKey;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::PrimeField;
use k256::{NonZeroScalar, Scalar, U256};
use near_sdk::serde::{Deserialize, Serialize};
use near_sdk::{env, near, require, CryptoHash, Gas, GasWeight, NearToken, PanicOnDefault};
use sha3::{Digest, Sha3_256};

const TWEAK_PREFIX: &str = "near-mpc-recovery v0.1.0 epsilon derivation:";
const REQUIRED_SIGN_TGAS: u64 = 15;
const RETURN_SIGNATURE_TGAS: u64 = 7;
const DATA_ID_REGISTER: u64 = 0;

#[derive(Clone, Copy, PartialEq, Eq)]
#[near(serializers = [borsh, json])]
pub enum Mode {
    /// Sign inside `sign`. Expensive in wasm, so the caller must attach more gas.
    Instant,
    /// Hold the request until `respond` or the protocol's yield timeout, like the live signer.
    Yield,
    /// Return JSON that is not a signature.
    Garbage,
    /// Sign inside `sign`, with far more bytes around the signature than a real answer has.
    Padded,
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[near(serializers = [borsh, json])]
pub enum Payload {
    Ecdsa(String),
    Eddsa(String),
}

#[near(serializers = [json])]
pub struct SignRequestArgs {
    pub path: String,
    pub payload_v2: Payload,
    pub domain_id: u64,
}

#[derive(Clone, PartialEq, Eq, Debug)]
#[near(serializers = [borsh, json])]
pub struct SignatureRequest {
    pub tweak: String,
    pub payload: Payload,
    pub domain_id: u64,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct AffinePoint {
    pub affine_point: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct ScalarHex {
    pub scalar: String,
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(crate = "near_sdk::serde")]
pub struct SignatureResponse {
    pub scheme: String,
    pub big_r: AffinePoint,
    pub s: ScalarHex,
    pub recovery_id: u8,
}

#[near(serializers = [borsh])]
pub struct Pending {
    request: SignatureRequest,
    data_id: CryptoHash,
}

#[near(contract_state)]
#[derive(PanicOnDefault)]
pub struct MockSigner {
    secret: [u8; 32],
    mode: Mode,
    pending: Vec<Pending>,
}

#[near]
impl MockSigner {
    #[init]
    pub fn new(secret_hex: String, mode: Mode) -> Self {
        let secret: [u8; 32] = hex::decode(secret_hex).unwrap().try_into().unwrap();
        Self { secret, mode, pending: Vec::new() }
    }

    pub fn set_mode(&mut self, mode: Mode) {
        self.mode = mode;
    }

    pub fn pending(&self) -> Vec<SignatureRequest> {
        self.pending.iter().map(|p| p.request.clone()).collect()
    }

    #[payable]
    pub fn sign(&mut self, request: SignRequestArgs) {
        require!(env::attached_deposit() >= NearToken::from_yoctonear(1), "attach 1 yoctoNEAR");
        require!(env::prepaid_gas() >= Gas::from_tgas(REQUIRED_SIGN_TGAS), "insufficient gas");
        require!(request.domain_id == 0, "domain not found");
        let Payload::Ecdsa(payload) = &request.payload_v2 else {
            env::panic_str("Payload is not Ecdsa");
        };
        let tweak = derive_tweak(env::predecessor_account_id().as_str(), &request.path);
        match self.mode {
            Mode::Garbage => {
                env::value_return(br#"{"scheme":"Secp256k1","surprise":true}"#);
            }
            Mode::Instant => {
                let response = sign_payload(&self.secret, &tweak, payload);
                env::value_return(&near_sdk::serde_json::to_vec(&response).unwrap());
            }
            Mode::Padded => {
                let response = near_sdk::serde_json::to_value(sign_payload(&self.secret, &tweak, payload)).unwrap();
                let mut object = response.as_object().unwrap().clone();
                object.insert("padding".to_string(), "x".repeat(4_096).into());
                env::value_return(&near_sdk::serde_json::to_vec(&object).unwrap());
            }
            Mode::Yield => {
                let stored = SignatureRequest {
                    tweak: hex::encode(tweak),
                    payload: request.payload_v2.clone(),
                    domain_id: request.domain_id,
                };
                let args = near_sdk::serde_json::to_vec(&(&stored,)).unwrap();
                let index = env::promise_yield_create(
                    "return_signature",
                    args,
                    Gas::from_tgas(RETURN_SIGNATURE_TGAS),
                    GasWeight(0),
                    DATA_ID_REGISTER,
                );
                let data_id: CryptoHash = env::read_register(DATA_ID_REGISTER).unwrap().try_into().unwrap();
                self.pending.push(Pending { request: stored, data_id });
                env::promise_return(index);
            }
        }
    }

    /// Same shape as the live signer's view: `"secp256k1:<base58 of x || y>"`. Garbage mode returns
    /// something that is not a key, and the deriving arithmetic matches the live signer's.
    pub fn derived_public_key(&self, path: String, predecessor: Option<near_sdk::AccountId>, domain_id: Option<u64>) -> String {
        require!(domain_id.unwrap_or(0) == 0, "domain not found");
        if self.mode == Mode::Garbage {
            return "not-a-key".to_string();
        }
        let predecessor = predecessor.unwrap_or_else(env::predecessor_account_id);
        let tweak = derive_tweak(predecessor.as_str(), &path);
        let point = derived_key(&self.secret, &tweak).verifying_key().to_encoded_point(false);
        format!("secp256k1:{}", bs58::encode(&point.as_bytes()[1..]).into_string())
    }

    /// What a live node does: resolve the oldest yield queued for this request.
    pub fn respond(&mut self, request: SignatureRequest, response: SignatureResponse) {
        let position = self
            .pending
            .iter()
            .position(|p| p.request == request)
            .unwrap_or_else(|| env::panic_str("RequestNotFound"));
        let entry = self.pending.remove(position);
        env::promise_yield_resume(&entry.data_id, near_sdk::serde_json::to_vec(&response).unwrap());
    }

    #[private]
    pub fn return_signature(
        &mut self,
        request: SignatureRequest,
        #[callback_result] signature: Result<SignatureResponse, near_sdk::PromiseError>,
    ) {
        match signature {
            Ok(signature) => env::value_return(near_sdk::serde_json::to_vec(&signature).unwrap()),
            Err(_) => {
                if let Some(position) = self.pending.iter().position(|p| p.request == request) {
                    self.pending.remove(position);
                }
                // A panic here would roll back the cleanup, so fail in a follow-up receipt
                // the way the live signer does.
                let fail = env::promise_create(
                    env::current_account_id(),
                    "fail_on_timeout",
                    [],
                    NearToken::from_yoctonear(0),
                    Gas::from_tgas(2),
                );
                env::promise_return(fail);
            }
        }
    }

    #[private]
    pub fn fail_on_timeout(&self) {
        env::panic_str("Request has timed out");
    }
}

fn derive_tweak(predecessor: &str, path: &str) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(format!("{TWEAK_PREFIX}{predecessor},{path}"));
    hasher.finalize().into()
}

fn derived_key(secret: &[u8; 32], tweak: &[u8; 32]) -> SigningKey {
    let base = Scalar::from_repr((*secret).into()).unwrap();
    let tweak = <Scalar as Reduce<U256>>::reduce_bytes(tweak.into());
    SigningKey::from(NonZeroScalar::new(base + tweak).unwrap())
}

fn sign_payload(secret: &[u8; 32], tweak: &[u8; 32], payload_hex: &str) -> SignatureResponse {
    let signing = derived_key(secret, tweak);
    let payload = hex::decode(payload_hex).unwrap();
    let (sig, recid) = signing.sign_prehash_recoverable(&payload).unwrap();
    let bytes = sig.to_bytes();
    let mut big_r = vec![2 + recid.is_y_odd() as u8];
    big_r.extend_from_slice(&bytes[..32]);
    SignatureResponse {
        scheme: "Secp256k1".to_string(),
        big_r: AffinePoint { affine_point: hex::encode(big_r) },
        s: ScalarHex { scalar: hex::encode(&bytes[32..]) },
        recovery_id: recid.to_byte(),
    }
}
