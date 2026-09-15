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

import { existsSync, mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { ENV, FILES } from '../types.js';
import type { EvidenceStore, OpenStoreOpts } from '../types.js';
import { SqliteStore, isSqliteAvailable } from './sqlite.js';
import { JsonlStore } from './jsonl.js';

export { SqliteStore, isSqliteAvailable } from './sqlite.js';
export { JsonlStore } from './jsonl.js';

let fallbackNoticeShown = false;

function noticeFallback(reason: string): void {
  if (fallbackNoticeShown) return;
  fallbackNoticeShown = true;
  process.stderr.write(`[mcp-recorder] ${reason}; using jsonl evidence store\n`);
}

function envBackend(): 'sqlite' | 'jsonl' | undefined {
  const value = process.env[ENV.STORE];
  if (value === undefined || value === '') return undefined;
  if (value === 'sqlite' || value === 'jsonl') return value;
  process.stderr.write(
    `[mcp-recorder] ignoring unknown ${ENV.STORE}=${value} (expected 'sqlite' or 'jsonl')\n`,
  );
  return undefined;
}

interface ExistingBackendFiles {
  sqlite: boolean;
  jsonl: boolean;
}

function existingBackendFiles(dataDir: string): ExistingBackendFiles {
  return {
    sqlite: existsSync(join(dataDir, FILES.SQLITE_DB)),
    jsonl: existsSync(join(dataDir, FILES.JSONL_LOG)),
  };
}

function warnBothBackendsExist(dataDir: string): void {
  process.stderr.write(
    `[mcp-recorder] warning: both ${FILES.SQLITE_DB} and ${FILES.JSONL_LOG} exist in ${dataDir} ` +
      '— evidence may be split across two backends; pass --store (or MCP_RECORDER_STORE) to pick one explicitly\n',
  );
}

/** Fresh data dir, no backend forced: create sqlite when available, else jsonl. */
function openFreshStore(dataDir: string): EvidenceStore {
  if (isSqliteAvailable()) {
    try {
      return new SqliteStore(dataDir);
    } catch (err) {
      noticeFallback(`sqlite store failed to open (${(err as Error).message})`);
      return new JsonlStore(dataDir);
    }
  }
  noticeFallback('better-sqlite3 unavailable');
  return new JsonlStore(dataDir);
}

export function openStore(opts: OpenStoreOpts): EvidenceStore {
  mkdirSync(opts.dataDir, { recursive: true });
  const backend = opts.backend ?? envBackend();

  if (backend === 'sqlite') return new SqliteStore(opts.dataDir);
  if (backend === 'jsonl') return new JsonlStore(opts.dataDir);

  const existing = existingBackendFiles(opts.dataDir);
  if (existing.sqlite && existing.jsonl) warnBothBackendsExist(opts.dataDir);
  if (existing.sqlite) {
    if (!isSqliteAvailable()) {
      throw new Error(
        `mcp-recorder: ${FILES.SQLITE_DB} exists but better-sqlite3 cannot load ` +
          '(refusing to silently start a second chain in jsonl — fix the better-sqlite3 ' +
          'install/rebuild, or pass --store jsonl to force a switch)',
      );
    }
    return new SqliteStore(opts.dataDir);
  }
  if (existing.jsonl) return new JsonlStore(opts.dataDir);

  return openFreshStore(opts.dataDir);
}

/**
 * Read-only variant for inspection commands (verify/query/sessions/ui/export):
 * identical resolution, except when no backend is forced and NEITHER evidence
 * file exists yet, it returns an empty store without creating one. Opening a
 * fresh SqliteStore in that case would create evidence.db as a side effect
 * (better-sqlite3 creates the file on open) purely from looking — e.g.
 * running `sessions` on a directory nothing has ever recorded to.
 */
export function openStoreReadOnly(opts: OpenStoreOpts): EvidenceStore {
  const backend = opts.backend ?? envBackend();
  if (backend === undefined) {
    const existing = existingBackendFiles(opts.dataDir);
    if (!existing.sqlite && !existing.jsonl) {
      // JsonlStore never writes at open — reads nothing, creates nothing.
      return new JsonlStore(opts.dataDir);
    }
  }
  return openStore(opts);
}
