// The Durable Object's storage over node:sqlite, so stage.mjs and the offline tests run the same UndoState class
// the Worker deploys. Only what that class uses: `sql.exec` and `transactionSync`.
import { DatabaseSync } from 'node:sqlite';
import { UndoState } from '../../worker/undo-cron/src/undo-state.mjs';

class Sql {
  constructor(db) {
    this.db = db;
  }

  exec(query, ...bindings) {
    const rows = this.db.prepare(query).all(...bindings).map((row) => ({ ...row }));
    return {
      toArray: () => rows,
      one: () => {
        if (rows.length !== 1) throw new Error('expected one row');
        return rows[0];
      },
    };
  }
}

export function localStorage() {
  const db = new DatabaseSync(':memory:');
  return {
    sql: new Sql(db),
    transactionSync(fn) {
      db.exec('BEGIN');
      try {
        const out = fn();
        db.exec('COMMIT');
        return out;
      } catch (err) {
        db.exec('ROLLBACK');
        throw err;
      }
    },
  };
}

/** What the `UNDO_STATE` binding looks like to a Pages Function, one object per name. `down` makes it fail. */
export function localStateNamespace(env = {}) {
  const objects = new Map();
  const ns = {
    down: false,
    calls: [],
    idFromName: (name) => name,
    get: (id) => ({
      fetch: async (url, init) => {
        if (ns.down) throw new Error('state store down');
        if (!objects.has(id)) objects.set(id, new UndoState({ storage: localStorage() }, env));
        ns.calls.push(new URL(url).pathname.slice(1));
        return objects.get(id).fetch(new Request(url, init));
      },
    }),
  };
  return ns;
}
