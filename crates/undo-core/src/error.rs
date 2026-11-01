use crate::types::{Ms, Outpoint, Sats};

/// Why a call was refused. The shell writes nothing when it gets one of these.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    // Creation.
    BadCsv,
    CsvOutOfRange { min: u32, max: u32 },
    BadKey,
    DuplicateKeys,
    BadVaultScript,
    KmMismatch,
    AlreadyActive,
    Inactive,
    // Authority.
    Unauthorized,
    SpendKeySuspended,
    BadNonce { expected: u64 },
    IntentExpired,
    Frozen { until: Ms },
    // Request shape.
    NoInputs,
    TooManyInputs,
    DuplicateInput(Outpoint),
    BadValue,
    HalfSigCount,
    BadDestination,
    DustOutput,
    OutputsExceedInputs,
    FeeRateTooLow { fee: Sats, floor: Sats },
    BadMemo,
    // Ledger.
    OutpointBusy(Outpoint),
    PinnedInMultiInput(Outpoint),
    PendingCap,
    SelfSpendSlotUsed { free_at: Ms },
    ChainTooYoung { ready_at: Ms },
    ChainOutOfOrder(Outpoint),
    // Fees.
    FeeOverCap { fee: Sats, cap: Sats },
    FeeBudgetExceeded { charge: Sats, used: Sats, budget: Sats },
    NotSelfSpend,
    OverrideTooHigh { limit: Sats },
    // Request lifecycle.
    RequestNotFound,
    NotPending,
    NotUnlocked { unlock: Ms },
    AlreadySigned,
    InFlight { retry_at_height: u64 },
    NothingToSign,
    NotReclaimable,
    NotStuck { ready_at: Ms },
    NotSigned,
    PruneTooSoon { ready_at: Ms },
    // Guard.
    HoldAlreadyUsed,
    PastUnlock,
    NoHold,
    // Policy and grants.
    PolicyOutOfBounds,
    PolicyUnchanged,
    AlreadyKnown,
    GrantNotFound,
    GrantNotReady { ready_at: Ms },
    TooManyGrants,
    TooManyDestinations,
    // Freeze.
    FreezeTooLong { max_until: Ms },
    NotFrozen,
    // Recovery.
    RecoveryInProgress,
    NoRecovery,
    RecoveryCancelCapReached,
    RecoveryNotReady { ready_at: Ms },
    // Upgrades.
    UpgradeInProgress,
    NoUpgrade,
    UpgradeHashMismatch,
    UpgradeNotReady { ready_at: Ms },
    UpgradeExpired,
}
