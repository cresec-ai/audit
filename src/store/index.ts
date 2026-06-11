/**
 * Store factory: sqlite when available, jsonl otherwise.
 *
 * Backend resolution order:
 *   1. opts.backend (forced — errors propagate, no silent fallback)
 *   2. process.env[ENV.STORE] ('sqlite' | 'jsonl'; unknown values ignored
 *      with a stderr warning)
 *   3. sqlite when better-sqlite3 loads AND the database opens
 *   4. jsonl, with a single stderr notice
 */

import { mkdirSync } from 'node:fs';
import { ENV } from '../types.js';
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

export function openStore(opts: OpenStoreOpts): EvidenceStore {
  mkdirSync(opts.dataDir, { recursive: true });
  const backend = opts.backend ?? envBackend();

  if (backend === 'sqlite') return new SqliteStore(opts.dataDir);
  if (backend === 'jsonl') return new JsonlStore(opts.dataDir);

  if (isSqliteAvailable()) {
    try {
      return new SqliteStore(opts.dataDir);
    } catch (err) {
      noticeFallback(`sqlite store failed to open (${(err as Error).message})`);
      return new JsonlStore(opts.dataDir);
    }
  }
  noticeFallback('better-sqlite3 unavailable');
  return new JsonlStore(opts.dataDir);
}
