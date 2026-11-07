// What a request is, read from the contract. One function, so the thief tab and the phone cannot disagree.
//
// The rule that matters: a rotation or a freeze moves the vault's epoch at once and the request stays in
// the row reading Pending until a later state change sweeps it. So a Pending request of an old epoch is
// cancelled, whatever its status says. Only Pending: is_dead in crates/undo-core applies that rule to
// Pending alone, because once `execute` has run, a signature is presumed public and nothing stops it. A
// Signed request of an old epoch is a spend that got through, and calling it cancelled would be a lie.

export const STATES = ['no_vault', 'unseen', 'waiting', 'unlocked', 'signing', 'signed', 'cancelled', 'expired'];
// Not `expired`: it comes from the block time, and one bad read of that must not stick. A request past its expiry
// reads expired on every later read anyway. Cancelled and signed come from the contract's own state.
const TERMINAL = new Set(['cancelled', 'signed']);

const state = (kind, reason = null) => ({
  kind,
  reason,
  /** The contract would still accept a cancel. True at zero, until the first `execute`. */
  cancellable: kind === 'waiting' || kind === 'unlocked',
  /** A clock for this request is true now. */
  clockRuns: kind === 'waiting',
  /** Anyone can call `execute` now. */
  executable: kind === 'unlocked',
  terminal: TERMINAL.has(kind),
});

/**
 * @param request parsed request, or null when the view returned nothing
 * @param vault parsed vault, or null
 * @param chainNow the contract's time, from clock() or a block read
 * @param lastKnown the last non-null reading of this request, if any
 */
export function requestState({ request, vault, chainNow, lastKnown = null }) {
  if (!vault) return state('no_vault');
  if (request === null || request === undefined) {
    // A node that has not seen the proposal yet also answers null, so null means gone only for a
    // request this page has already read.
    if (!lastKnown) return state('unseen');
    if (lastKnown.status !== 'Pending') return state('signed', 'pruned');
    if (lastKnown.epoch !== vault.spend_epoch) return state('cancelled', vault.frozen_until !== null ? 'frozen' : 'rotated');
    if (chainNow > lastKnown.expires_at) return state('expired', 'swept');
    return state('cancelled', 'deleted');
  }
  if (request.status === 'Signed') return state('signed');
  if (request.status === 'Signing') return state('signing');
  // Epochs only rise, so this is a vault read from a node behind the one that served the request. Calling it
  // cancelled would be a sticky lie on a screen. Wait for the next poll.
  if (request.epoch > vault.spend_epoch) return state('unseen', 'vault_read_is_behind');
  if (request.epoch !== vault.spend_epoch) return state('cancelled', vault.frozen_until !== null ? 'frozen' : 'rotated');
  if (chainNow > request.expires_at) return state('expired');
  if (chainNow >= request.unlock) return state('unlocked');
  return state('waiting');
}

/**
 * The next state to act on, given the last. A terminal state holds against a read from a lagging node.
 * The one thing that overrides `cancelled` is the contract itself reporting a signature.
 */
export function advanceState(previous, next) {
  if (!previous || !previous.terminal) return next;
  if (next.kind === 'signed' || next.kind === 'signing') return next;
  return previous;
}

/**
 * Whether the phone may draw a Cancel button, and if not, the reason it says so instead. It never shows a
 * button that cannot work.
 * @param state from requestState
 * @param relay from RelayClient.status
 * @param passkey { canAssert: bool, rpMatches: bool }, what this device can sign for this vault
 * @param originAllowed instance.origins includes this page's origin
 */
export function cancelButton({ state: s, relay, passkey, originAllowed, frozen = false }) {
  if (!s.cancellable) return { show: false, why: 'not_cancellable' };
  if (frozen) return { show: false, why: 'frozen' };
  if (!originAllowed) return { show: false, why: 'origin_not_allowed' };
  if (!passkey.rpMatches) return { show: false, why: 'wrong_site_for_passkey' };
  if (!passkey.canAssert) return { show: false, why: 'no_passkey_here' };
  if (!relay.reachable) return { show: false, why: 'relay_down' };
  if (!relay.owner.up) return { show: false, why: relay.owner.why ?? 'relay_owner_down' };
  return { show: true, why: null };
}

// `execute` on a Signing request, as crates/undo-core decides it. A request that pays out gets its missing signatures
// asked for until a day after its first execute (RetryWindowClosed); a self-spend, which a reclaim also is, has no such
// limit. A sign call that has not answered blocks another ask for RETRY_AFTER_BLOCKS blocks after the last (InFlight).
// A request an earlier build executed can close sooner, which no view shows, so for that one the contract decides.
export const RETRY_WINDOW_MS = 24 * 60 * 60 * 1000;
export const RETRY_AFTER_BLOCKS = 250;

/** When the contract stops asking the signer for this request's missing signatures, or null if this cannot tell it ever does. */
export function retryClosesAt(request) {
  if (!request || request.status !== 'Signing' || request.tier === 'SelfSpend') return null;
  if (typeof request.first_execute_at !== 'number') return null;
  return request.first_execute_at + RETRY_WINDOW_MS;
}
