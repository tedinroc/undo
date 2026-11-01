// Which of a vault's requests a phone puts on its screen. A thief can propose more than one, and `cancel_all_and_rotate`
// kills them all, so Cancel stays while any can still be cancelled, whatever another one has done. Picking the newest
// would let a small self-spend hide a drain and then end the screen with "too late" while the drain still waits.

const declaredValue = (request) => request.inputs.reduce((sum, c) => sum + c.value, 0);

/**
 * @param items [{ id, request, state }]: `request` the last reading, `state` from requestState. Null ones are skipped.
 * @param selfSpk the vault's own output script
 * @param realValue the sats a request's coins really hold, as far as a node has said. Defaults to what it declares
 * @returns { focus, moreWaiting, alreadySigned }
 */
export function chooseOnScreen(items, { selfSpk, realValue = declaredValue }) {
  const seen = items.filter((item) => item.state && item.request);
  const paysOut = (item) => (item.request.to === selfSpk ? 0 : 1);
  const live = seen.filter((item) => item.state.cancellable);
  const ended = seen.filter((item) => !item.state.cancellable);
  const biggest = (a, b) => paysOut(b) - paysOut(a) || realValue(b.request) - realValue(a.request) || a.request.unlock - b.request.unlock || b.id - a.id;
  const latest = (a, b) => paysOut(b) - paysOut(a) || b.id - a.id;
  const focus = [...live].sort(biggest)[0] ?? [...ended].sort(latest)[0] ?? null;
  const signed = seen.filter((item) => item !== focus && (item.state.kind === 'signed' || item.state.kind === 'signing'));
  return { focus, moreWaiting: Math.max(0, live.length - 1), alreadySigned: signed.length };
}

/**
 * What a node says about a request's coins, from `facts`: a Map of `txid:vout` to { known, value }. A coin no node has
 * been asked about counts as declared until one has.
 */
export function coinCheck(request, facts) {
  let real = 0;
  let unknown = 0;
  let differs = false;
  let asked = 0;
  for (const coin of request.inputs) {
    const fact = facts.get(`${coin.txid}:${coin.vout}`);
    if (!fact) {
      real += coin.value;
      continue;
    }
    asked += 1;
    if (!fact.known) unknown += 1;
    else {
      real += fact.value;
      if (fact.value !== coin.value) differs = true;
    }
  }
  return { real, unknown, differs, complete: asked === request.inputs.length };
}
