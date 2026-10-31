//! Plain data shared by the state machine and the shell.

pub type Sats = u64;
pub type Ms = u64;
pub type RequestId = u64;
pub type GrantId = u64;
/// Half-signature from `K_u`. The shell checks it with `ecrecover`; this crate only stores it.
pub type HalfSig = Vec<u8>;
/// MPC signature from the signer. The shell checks it; this crate only stores it.
pub type MpcSig = Vec<u8>;

/// 21,000,000 BTC. Declared values above this are refused, which also keeps sums inside `u64`
/// at `MAX_INPUTS`.
pub const MAX_MONEY: Sats = 2_100_000_000_000_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct Outpoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

/// A caller-declared coin. Nothing about it is trusted: a false value yields a signature that
/// consensus rejects, as long as the pin rules stop two sessions from combining.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct Input {
    pub outpoint: Outpoint,
    pub value: Sats,
}

/// One destination plus at most one change output. Change always pays the vault's own script.
#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct Outputs {
    pub dest_script: Vec<u8>,
    pub dest_value: Sats,
    pub change_value: Option<Sats>,
}

impl Outputs {
    pub fn total(&self) -> Sats {
        self.dest_value.saturating_add(self.change_value.unwrap_or(0))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "borsh", derive(borsh::BorshSerialize, borsh::BorshDeserialize))]
pub struct Passkey {
    pub pubkey: Vec<u8>,
    pub rp_id_hash: [u8; 32],
    pub backup_eligible: bool,
    pub backup_state: bool,
}

/// Who signed, as established by the shell. Keys are compared with vault state here, so a rotated
/// or recovered key is refused even if its signature checks out.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Caller {
    SpendKey([u8; 32]),
    Passkey(Vec<u8>),
    Cold(Vec<u8>),
    Guard(String),
    Anyone,
}

/// Replay fields of a signed intent. `cancel` carries only `expires_at`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Intent {
    pub nonce: u64,
    pub expires_at: Ms,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ScriptKind {
    P2wpkh,
    P2wsh,
    P2tr,
}

impl ScriptKind {
    /// Exact template and length. Everything else, bare scripts and `OP_RETURN` included, is `None`.
    pub fn of(script: &[u8]) -> Option<ScriptKind> {
        match script {
            [0x00, 0x14, rest @ ..] if rest.len() == 20 => Some(ScriptKind::P2wpkh),
            [0x00, 0x20, rest @ ..] if rest.len() == 32 => Some(ScriptKind::P2wsh),
            [0x51, 0x20, rest @ ..] if rest.len() == 32 => Some(ScriptKind::P2tr),
            _ => None,
        }
    }
}

/// Default-relay dust limits at 3 sat/vB.
pub fn dust_limit(kind: ScriptKind) -> Sats {
    match kind {
        ScriptKind::P2wpkh => 294,
        ScriptKind::P2wsh | ScriptKind::P2tr => 330,
    }
}

/// Virtual size estimate from counts: 11 vB overhead, 107 vB per co-signed input, and each output
/// at 9 vB plus its script. One input with a P2WPKH destination and vault change gives 192 vB,
/// close to the spec's arithmetic of about 191.
pub fn estimate_vsize(inputs: usize, outputs: &Outputs) -> u64 {
    let out = |len: usize| 9 + len as u64;
    let mut vsize = 11 + 107 * inputs as u64 + out(outputs.dest_script.len());
    if outputs.change_value.is_some() {
        vsize += out(34);
    }
    vsize
}
