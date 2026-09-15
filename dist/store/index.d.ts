/**
 * Store factory: sqlite when available, jsonl otherwise.
 *
 * Backend resolution order:
 *   1. opts.backend (forced — errors propagate, no silent fallback)
 *   2. process.env[ENV.STORE] ('sqlite' | 'jsonl'; unknown values ignored
 *      with a stderr warning)
 *   3. whichever evidence file ALREADY EXISTS in the data dir wins — this is
 *      what keeps a native-module availability flip (Node upgrade, npm
 *      rebuild losing the better-sqlite3 binding, ...) from silently reading
 *      an empty store or starting a second chain in the other backend. If
 *      evidence.db exists but better-sqlite3 cannot load, that is a loud
 *      error, not a fallback: silently switching to jsonl there would look
 *      like "no sessions" / a 0-event verify PASS and quietly start writing
 *      a second, disconnected chain. Both files existing is always a warning
 *      (evidence may be split across backends), whichever way it resolves.
 *   4. neither file exists yet (a genuinely fresh data dir): sqlite when
 *      better-sqlite3 loads AND the database opens, else jsonl — the
 *      original "pick a backend to create" default, with a single stderr
 *      notice on fallback.
 */
import type { EvidenceStore, OpenStoreOpts } from '../types.js';
export { SqliteStore, isSqliteAvailable } from './sqlite.js';
export { JsonlStore } from './jsonl.js';
export declare function openStore(opts: OpenStoreOpts): EvidenceStore;
/**
 * Read-only variant for inspection commands (verify/query/sessions/ui/export):
 * identical resolution, except when no backend is forced and NEITHER evidence
 * file exists yet, it returns an empty store without creating one. Opening a
 * fresh SqliteStore in that case would create evidence.db as a side effect
 * (better-sqlite3 creates the file on open) purely from looking — e.g.
 * running `sessions` on a directory nothing has ever recorded to.
 */
export declare function openStoreReadOnly(opts: OpenStoreOpts): EvidenceStore;
