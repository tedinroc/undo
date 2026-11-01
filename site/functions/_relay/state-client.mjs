// The Pages Function's and the cron's side of the Durable Object. A stub is made per call, because a Worker
// may not carry one from one request to the next.

export const STATE_NAME = 'undo-testnet-v1';

/** The state store did not answer, or answered with an error, as it does over its free limit. */
export class StateDown extends Error {}

export class StateClient {
  constructor(namespace, name = STATE_NAME) {
    Object.assign(this, { namespace, name });
  }

  async call(op, body = {}) {
    if (!this.namespace) throw new StateDown('no state binding');
    let res;
    try {
      res = await this.namespace.get(this.namespace.idFromName(this.name)).fetch(`https://do/${op}`, { method: 'POST', body: JSON.stringify(body) });
    } catch (err) {
      throw new StateDown(err.name);
    }
    if (!res.ok) throw new StateDown(`HTTP ${res.status}`);
    return res.json();
  }

  // The nonce rows, in the form the sender takes.
  lease = (key) => this.call('lease', { key: key.id, now: Date.now() });

  seed = (key, chainNonce, now) => this.call('seed', { key: key.id, chain_nonce: chainNonce, now });

  reset = (key, akNonce, now) => this.call('reset', { key: key.id, ak_nonce: akNonce, now });
}
