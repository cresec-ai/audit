/**
 * Opening the sqlite store while ANOTHER PROCESS holds a write lock on a
 * database that is still in rollback mode — what a second `mcp-recorder
 * record` sees when it starts at the same moment as the first one on a
 * fresh data dir.
 *
 * `PRAGMA busy_timeout` does not cover this case: the WAL switch upgrades a
 * read transaction to a write transaction, and SQLite skips the busy handler
 * on that upgrade (deadlock avoidance), failing with SQLITE_BUSY at once.
 * The store retries the switch itself; these tests pin that down with a
 * real lock holder in a child process (the only way to get a genuine
 * cross-process RESERVED lock).
 */
import { spawn } from 'node:child_process';
import type { ChildProcess } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { SqliteStore, isSqliteAvailable } from '../src/store/sqlite.js';
import { FILES } from '../src/types.js';
import { SCHEMA } from '../src/schema/events.js';
import type { SessionStartEvent } from '../src/schema/events.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const LOCK_HOLDER = fileURLToPath(new URL('./fixtures/sqlite-lock-holder.cjs', import.meta.url));

const cleanups: Array<() => void> = [];
afterEach(() => {
  while (cleanups.length > 0) {
    try {
      cleanups.pop()!();
    } catch {
      /* best-effort teardown */
    }
  }
});

interface Holder {
  child: ChildProcess;
  /** Resolves once the child reports the lock is held. */
  locked: Promise<void>;
  /** Resolves with the exit code and everything the child wrote. */
  done: Promise<{ code: number | null; stdout: string; stderr: string }>;
}

function holdLock(dbPath: string, holdMs: number): Holder {
  const child = spawn(process.execPath, [LOCK_HOLDER, dbPath, String(holdMs)], {
    cwd: ROOT,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stdout = '';
  let stderr = '';
  child.stdout!.setEncoding('utf8');
  child.stderr!.setEncoding('utf8');
  child.stderr!.on('data', (chunk: string) => {
    stderr += chunk;
  });
  const locked = new Promise<void>((resolve, reject) => {
    child.stdout!.on('data', (chunk: string) => {
      stdout += chunk;
      if (stdout.includes('locked')) resolve();
    });
    child.on('error', reject);
    child.on('close', (code) => {
      if (!stdout.includes('locked')) reject(new Error(`lock holder exited ${code} before locking:\n${stderr}`));
    });
  });
  const done = new Promise<{ code: number | null; stdout: string; stderr: string }>((resolve) => {
    child.on('close', (code) => resolve({ code, stdout, stderr }));
  });
  cleanups.push(() => child.kill());
  return { child, locked, done };
}

function tmpDataDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'mcp-rec-sqlite-open-'));
  cleanups.push(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function sessionStart(): SessionStartEvent {
  return {
    schema: SCHEMA,
    kind: 'session_start',
    session_id: 'open-test-session',
    timestamp: new Date().toISOString(),
    transport: 'stdio',
    server: { name: 'echo', command: 'node', args_hash: 'sha256:x' },
    identity: { fingerprint: 'sha256:y' },
  };
}

describe.skipIf(!isSqliteAvailable())('SqliteStore open vs a concurrent writer (cross-process)', () => {
  it(
    'waits for a rollback-mode database another process is writing, then switches it to WAL and works',
    async () => {
      const dataDir = tmpDataDir();
      const dbPath = join(dataDir, FILES.SQLITE_DB);
      const holder = holdLock(dbPath, 1_500);
      await holder.locked;

      const t0 = Date.now();
      const store = new SqliteStore(dataDir); // blocks until the holder commits
      const waitedMs = Date.now() - t0;
      cleanups.push(() => store.close());

      // The open genuinely contended with the holder: it cannot have
      // finished before the RESERVED lock was released.
      expect(waitedMs).toBeGreaterThanOrEqual(500);

      // ...and came out fully initialized: WAL mode, schema present, usable.
      const require = createRequire(import.meta.url);
      const Database = require('better-sqlite3') as typeof import('better-sqlite3');
      const probe = new Database(dbPath, { readonly: true });
      try {
        expect(probe.pragma('journal_mode', { simple: true })).toBe('wal');
      } finally {
        probe.close();
      }
      store.appendEvents([sessionStart()]);
      expect(store.count()).toBe(1);

      const result = await holder.done;
      expect(result.code, result.stderr).toBe(0);
      expect(result.stdout).toContain('released');
    },
    20_000,
  );

  it(
    'gives up with the SQLite busy error once the open deadline passes (never hangs, leaks no handle)',
    async () => {
      const dataDir = tmpDataDir();
      const dbPath = join(dataDir, FILES.SQLITE_DB);
      const holder = holdLock(dbPath, 2_500);
      await holder.locked;

      const t0 = Date.now();
      expect(() => new SqliteStore(dataDir, { openTimeoutMs: 300 })).toThrow(/database is locked/);
      const waitedMs = Date.now() - t0;
      expect(waitedMs).toBeGreaterThanOrEqual(250);
      expect(waitedMs).toBeLessThan(2_000);

      const result = await holder.done;
      expect(result.code, result.stderr).toBe(0);
      // With the failed open's handle closed, a fresh open now succeeds
      // (and on Windows the temp dir can be removed by the teardown).
      const store = new SqliteStore(dataDir);
      cleanups.push(() => store.close());
      expect(store.count()).toBe(0);
    },
    20_000,
  );
});
