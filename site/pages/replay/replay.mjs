// The replay: real steps from earlier runs, read from run.json next to this page (built from proofs/ by
// tools/replay-run.mjs), shown one at a time. Every hash names its chain and links its explorer. There is no clock and
// no timer: a step appears when the visitor asks for it, and a recorded wait is told as the number it was.
import { loadConfig } from '/site/lib/index.mjs';

const $ = (id) => document.getElementById(id);
const EXPLORERS = {
  Mutinynet: { txid: 'https://mutinynet.com/tx/{}', address: 'https://mutinynet.com/address/{}' },
  'NEAR testnet': { tx: 'https://testnet.nearblocks.io/txns/{}' },
};

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  for (const c of children) el.append(c);
  return el;
}

function line(l) {
  if (l.kind === 'hash') {
    const template = EXPLORERS[l.chain]?.[l.type];
    const body = [h('span', { class: 'chain' }, `${l.chain} ${l.type}`), h('span', { class: 'mono h' }, l.hash), h('span', { class: 'what' }, l.what)];
    const inner = template ? h('a', { href: template.replace('{}', encodeURIComponent(l.hash)) }, ...body) : h('span', {}, ...body);
    return h('div', { class: 'line hash-line', 'data-hash': l.hash }, inner);
  }
  // A node's words, untouched.
  if (l.kind === 'node') return h('div', { class: 'node' }, h('div', { class: 'node-label' }, `${l.chain} node:`), h('div', { class: 'node-text' }, l.text));
  return h('p', { class: 'line' }, l.text);
}

function stepCard(step, n, run) {
  const recorded = step.recorded !== false;
  const when = recorded ? `replay · earlier run · ${run.runs[step.run].date} UTC${step.at ? ` ${step.at.slice(11, 19)}` : ''}` : 'not recorded yet';
  const card = h('li', { class: 'step', id: `step-${step.id}`, 'data-step': step.id, 'data-recorded': String(recorded) },
    h('div', { class: 'step-head' }, h('span', {}, `Step ${n} of ${run.steps.length}`), h('span', { class: 'when' }, when)),
    h('h2', { class: 'step-title' }, step.title),
    ...step.lines.map(line));
  card.hidden = true;
  return card;
}

function plain(text) {
  document.documentElement.dataset.state = 'no_data';
  $('plain').textContent = text;
  $('plain').hidden = false;
}

async function main() {
  loadConfig().then((config) => {
    $('chip').textContent = config.labels.chip;
    $('foot-chip').textContent = config.labels.chip;
  }, () => {});
  let run;
  try {
    const res = await fetch('/replay/run.json', { cache: 'no-store' });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    run = await res.json();
    if (run.schema !== 'undo-replay-v1' || run.label !== 'replay' || !Array.isArray(run.steps)) throw new Error('not a replay record');
  } catch (err) {
    plain(`The replay's record did not load (${err.message}), so there is nothing to show.`);
    return;
  }
  $('note').textContent = run.note;
  const cards = run.steps.map((s, i) => stepCard(s, i + 1, run));
  $('steps').append(...cards);
  let shown = 0;
  const show = (count) => {
    shown = Math.min(count, cards.length);
    cards.forEach((c, i) => { c.hidden = i >= shown; });
    document.documentElement.dataset.step = String(shown);
    const done = shown === cards.length;
    $('next').disabled = done;
    $('next').textContent = done ? 'That was every step' : 'Next step';
    $('all').hidden = done;
  };
  $('next').addEventListener('click', () => {
    show(shown + 1);
    cards[shown - 1].scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  });
  $('all').addEventListener('click', () => show(cards.length));
  $('controls').hidden = false;
  document.documentElement.dataset.state = 'replay';
  show(location.hash === '#all' ? cards.length : 1);
}

main();
