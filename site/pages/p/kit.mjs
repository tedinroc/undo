// Small DOM helpers and the clock widget. The page's CSP allows no inline script or style, so everything here
// is plain nodes and CSSOM. Text only ever goes in through textContent, because a node's words and an address
// read from a contract reach this file.

export function h(tag, attrs = {}, ...kids) {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (name === 'onclick') node.addEventListener('click', value);
    else if (name === 'class') node.className = value;
    else node.setAttribute(name, value === true ? '' : String(value));
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid === null || kid === undefined || kid === false) continue;
    node.append(kid);
  }
  return node;
}

export const screen = () => document.getElementById('screen');
export const setState = (id) => { document.documentElement.dataset.state = id; };
export const stateOf = () => document.documentElement.dataset.state;

export function show(...nodes) {
  screen().replaceChildren(...nodes.flat(Infinity).filter(Boolean));
}

/** A label and a hash on one reading line: `NEAR testnet tx` above its hash, linked if the config has an explorer. */
export function hashBlock(labelled, value, link) {
  const words = labelled.slice(0, labelled.length - value.length).trim();
  const body = link
    ? h('a', { class: 'hash', href: link, target: '_blank', rel: 'noopener noreferrer' }, value)
    : h('span', { class: 'hash' }, value);
  return h('div', { class: 'hashblock' }, h('div', { class: 'hashline' }, words), body);
}

/**
 * m:ss.t in fixed slots, so nothing shifts when a digit changes. Only text changes. `data-clock` holds what is on
 * the screen, which is what the recorder waits on, and what a cancel freezes at.
 */
export class ClockFace {
  constructor() {
    this.minutes = h('span', { class: 'sl' });
    this.s1 = h('span', { class: 'sl' });
    this.s2 = h('span', { class: 'sl' });
    this.t = h('span', { class: 'sl ten' });
    this.el = h('div', { class: 'clock', id: 'digits' }, this.minutes, h('span', { class: 'col' }, ':'), this.s1, this.s2, h('span', { class: 'col ten' }, '.'), this.t);
    this.fuseBar = h('div');
    this.fuse = h('div', { class: 'fuse' }, this.fuseBar);
    this.wrap = h('div', { class: 'clockwrap' }, this.el);
    this.text = null;
    this.minuteWidth = 1;
    // The most the digits may take, in px, when a screen needs the room for its control. Null: as large as fits.
    this.cap = null;
    this.resize = () => this.fit();
    window.addEventListener('resize', this.resize);
  }

  dispose() {
    window.removeEventListener('resize', this.resize);
  }

  /** Largest size whose slots fit the column. Fonts differ by phone, so this measures. */
  fit() {
    const room = this.wrap.clientWidth - 32;
    if (room <= 0) return;
    this.el.style.fontSize = '100px';
    const width = this.el.getBoundingClientRect().width;
    // A short phone gives the clock a quarter of its height at most, so Cancel stays on the screen.
    if (width > 0) this.el.style.fontSize = `${Math.floor(Math.min((room / width) * 100, window.innerHeight * 0.26, this.cap ?? Infinity))}px`;
  }

  /** The digits' size now, in px. */
  get size() {
    return Number.parseFloat(this.el.style.fontSize) || 0;
  }

  set(text) {
    if (text === this.text) return;
    this.text = text;
    const match = /^(\d+):(\d)(\d)\.(\d)$/.exec(text);
    if (!match) return;
    const [, m, a, b, t] = match;
    if (m.length !== this.minuteWidth) {
      this.minuteWidth = m.length;
      this.minutes.style.width = `${m.length}ch`;
      this.minutes.textContent = m;
      this.fit();
    } else if (this.minutes.textContent !== m) this.minutes.textContent = m;
    if (this.s1.textContent !== a) this.s1.textContent = a;
    if (this.s2.textContent !== b) this.s2.textContent = b;
    if (this.t.textContent !== t) this.t.textContent = t;
    this.el.dataset.clock = text;
  }

  setFuse(fraction) {
    if (fraction === null || fraction === undefined) return;
    this.fuseBar.style.transform = `scaleX(${fraction})`;
  }

  stop() {
    this.el.classList.add('stopped');
    this.wrap.classList.add('stopped');
    this.fuse.hidden = true;
  }

  dim(on) {
    this.el.classList.toggle('dimmed', on);
  }
}

/** Formats a whole number of sats. `2,000 sats`, the same way every time. */
export const satsText = (n) => `${n.toLocaleString('en-US')} sats`;

export const sumInputs = (request) => request.inputs.reduce((sum, c) => sum + c.value, 0);
