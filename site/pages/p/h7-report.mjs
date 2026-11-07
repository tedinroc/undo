// The test mode's report, in plain words, so the person holding the phone only has to copy it. Same input, same text.
import { toHex } from '/tools/lib/bytes.mjs';
import { rpIdHashOf } from '/site/lib/index.mjs';

const yesNo = (v) => (v === null || v === undefined ? 'unknown' : v ? 'yes' : 'no');
const seconds = (ms) => (ms === null || ms === undefined || Number.isNaN(ms) ? '?' : (ms / 1000).toFixed(2));

export function encodeTry(t) {
  const sheet = `${t.hidden ? 'h' : ''}${t.blurred ? 'b' : ''}${t.pagehide ? 'p' : ''}` || 'n';
  return [t.m, t.s, t.sheetMs, t.includedMs, t.readMs, sheet, t.stallMs, t.hash ?? 'x'].join('.');
}

export function decodeTries(text) {
  if (!text) return [];
  return text.split('~').filter(Boolean).map((part) => {
    const [m, s, sheetMs, includedMs, readMs, sheet, stallMs, hash] = part.split('.');
    return {
      m, s, sheetMs: Number(sheetMs), includedMs: Number(includedMs), readMs: Number(readMs),
      hidden: sheet.includes('h'), blurred: sheet.includes('b'), pagehide: sheet.includes('p'), stallMs: Number(stallMs), hash: hash === 'x' ? null : hash,
    };
  });
}

/** The S-form sentence the passkey gate needs. */
export function sFormSentence(tries) {
  const at = tries.findIndex((t) => t.s === 'h');
  if (at >= 0) return `A high-S signature appeared on try ${at + 1} of ${tries.length}. The page sent it in low-S form and the contract took it.`;
  if (tries.length >= 8) return 'No high-S signature in 8 tries. Fixtures cover high-S, and CLAIMS.md must say so.';
  return `${tries.length} of 8 tries so far, no high-S yet.`;
}

export function sheetSentence(tries) {
  if (tries.length === 0) return null;
  const hidden = tries.filter((t) => t.hidden || t.pagehide).length;
  const blurred = tries.filter((t) => t.blurred).length;
  const stall = Math.max(...tries.map((t) => t.stallMs));
  return `While the sheet was up, over ${tries.length} tries: the page went hidden ${hidden} times, lost focus ${blurred} times, and its longest drawing stall was ${seconds(stall)} s.`;
}

export function reportText({ sense, config, passkeyFlags, proofS, tries, operator, answers, vault, problems = [], awake = null }) {
  const lines = ['Undo phone test report', `Page: ${config.labels.chip}, contract ${config.contract}, rp id ${config.rpId}`, `Browser: ${sense.ua}`];
  lines.push('Everything below was made or seen in this browser tab. A link cannot add to it.');
  lines.push(`Opened inside an app: ${sense.inApp ?? 'no'}. Passkeys in this browser: ${yesNo(sense.api)}. Secure page: ${yesNo(sense.secure)}. Platform authenticator: ${yesNo(sense.platform)}.`);
  if (awake) lines.push(`Screen kept on during the wait: ${awake}.`);
  for (const p of problems) lines.push(`Problem seen: ${p}`);
  if (vault) lines.push(`Test vault: ${vault}`);
  if (passkeyFlags) lines.push(`Passkey "test vault": made. Can sync: ${yesNo(passkeyFlags.be)}. Synced now: ${yesNo(passkeyFlags.bs)}.`);
  if (proofS) lines.push(`Creation tap: ${proofS === 'h' ? 'high-S' : 'low-S'}.`);
  lines.push('');
  lines.push(sFormSentence(tries));
  tries.forEach((t, i) => {
    const call = t.m === 'r' ? 'cancel_all_and_rotate' : 'cancel';
    lines.push(`Try ${i + 1}: ${call}, ${t.s === 'h' ? 'high-S' : 'low-S'}, contract took it. Tap to sheet done ${seconds(t.sheetMs)} s, to included ${seconds(t.includedMs)} s, to read cancelled ${seconds(t.readMs)} s. ${t.hash ? `${config.labels.near} tx ${t.hash}` : ''}`.trimEnd());
  });
  const sheet = sheetSentence(tries);
  if (sheet) lines.push(sheet);
  if (tries.some((t) => t.m === 'r')) {
    const rotate = tries.find((t) => t.m === 'r');
    lines.push(`Tap to read cancelled on the film's call: ${seconds(rotate.readMs)} s. That is the wait to allow for when filming.`);
  }
  lines.push('');
  if (operator) {
    lines.push('Passkey "operator": made.');
    lines.push(`operator_passkey for the contract's new: {"pubkey":"${operator.pub}","rp_id_hash":"${toHex(rpIdHashOf(config.rpId))}"}`);
    lines.push(`Its credential id: ${operator.cred}`);
  } else lines.push('Passkey "operator": not made yet.');
  lines.push('');
  lines.push(`Screen recording while the sheet was up went blank: ${answers.recording ?? 'not answered'}.`);
  lines.push(`Touches or looks for one Cancel: ${answers.gestures ?? 'not answered'}.`);
  return lines.join('\n');
}
