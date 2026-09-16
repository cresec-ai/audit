/**
 * SQLite evidence store (primary backend).
 *
 * better-sqlite3 is a CJS optionalDependency with a native binding, so it is
 * loaded lazily via createRequire — environments without it never touch the
 * module and fall back to the jsonl backend (see src/store/index.ts).
 *
 * Tamper-EVIDENCE comes from the hash chain + signatures; the append-only
 * triggers here merely block casual UPDATE/DELETE edits at the SQL layer.
 */

import { mkdirSync } from 'node:fs';
import { join } from 'node:path';
import { createRequire } from 'node:module';
import type Database from 'better-sqlite3';
import type { AnyEvent, ChainRecord, HeadSignature } from '../schema/events.js';
import { GENESIS_HASH, canonicalJson, computeHash, makeRecord } from '../chain/hash.js';
import { FILES } from '../types.js';
import type { ChainHead, EvidenceStore, IterateOpts, SessionSummary } from '../types.js';
import { sleepSync } from '../util/sleep-sync.js';

type SqliteCtor = typeof Database;

let cachedCtor: SqliteCtor | undefined;
let loadFailed = false;

function loadSqlite(): SqliteCtor | undefined {
  if (cachedCtor !== undefined) return cachedCtor;
  if (loadFailed) return undefined;
  try {
    const require = createRequire(import.meta.url);
    cachedCtor = require('better-sqlite3') as SqliteCtor;
    return cachedCtor;
  } catch {
    loadFailed = true;
    return undefined;
  }
}

/** True when the optional better-sqlite3 dependency can be loaded. */
export function isSqliteAvailable(): boolean {
  return loadSqlite() !== undefined;
}

const DDL = `
CREATE TABLE IF NOT EXISTS records (
  seq        INTEGER PRIMARY KEY,
  prev_hash  TEXT NOT NULL,
  hash       TEXT NOT NULL,
  session_id TEXT NOT NULL,
  kind       TEXT NOT NULL,
  timestamp  TEXT NOT NULL,
  event      TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS signatures (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  seq        INTEGER NOT NULL,
  chain_hash TEXT NOT NULL,
  algo       TEXT NOT NULL,
  public_key TEXT NOT NULL,
  signature  TEXT NOT NULL,
  signed_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_records_session_id ON records(session_id);
CREATE INDEX IF NOT EXISTS idx_records_kind ON records(kind);
CREATE TRIGGER IF NOT EXISTS records_no_update BEFORE UPDATE ON records
BEGIN SELECT RAISE(ABORT, 'mcp-recorder: append-only'); END;
CREATE TRIGGER IF NOT EXISTS records_no_delete BEFORE DELETE ON records
BEGIN SELECT RAISE(ABORT, 'mcp-recorder: append-only'); END;
CREATE TRIGGER IF NOT EXISTS signatures_no_update BEFORE UPDATE ON signatures
BEGIN SELECT RAISE(ABORT, 'mcp-recorder: append-only'); END;
CREATE TRIGGER IF NOT EXISTS signatures_no_delete BEFORE DELETE ON signatures
BEGIN SELECT RAISE(ABORT, 'mcp-recorder: append-only'); END;
`;

interface HeadRow {
  seq: number;
  hash: string;
}

interface RecordRow {
  seq: number;
  prev_hash: string;
  hash: string;
  event: string;
}

interface SigRow {
  seq: number;
  chain_hash: string;
  algo: string;
  public_key: string;
  signature: string;
  signed_at: string;
}

interface SessionRow {
  session_id: string;
  started_at: string;
  ended_at: string | null;
  server_name: string | null;
  identity_fingerprint: string | null;
  event_count: number;
  tool_call_count: number;
  error_count: number;
  server_count: number;
}

/**
 * Per-session aggregate. Must stay in step with JsonlStore.sessions() —
 * test/store.test.ts runs the same fixtures through both backends.
 *
 * tool_call_count counts CALLS, not tool_call events: a proxy-captured call
 * is one event with no `phase`, while `mcp-recorder hook` records a call as
 * a `phase: 'pre'` event plus (once PostToolUse or PostToolUseFailure fired
 * for it) a `phase: 'post'` event sharing its request_id. Counting the pre
 * half only gives one per call either way, and a lone pre (the post half
 * never arrived) still counts once. error_count counts is_error on any
 * phase: a failed hook call has exactly one such event (the denied pre, or
 * the failing post — a PostToolUseFailure, or a PostToolUse response shaped
 * `{isError: true}`). A post whose pre was never recorded (the hook
 * installed mid-call) is therefore counted in error_count but not in
 * tool_call_count.
 * server_count is the number of distinct server.name values over the
 * session's tool_call events ONLY — the servers actually called. Counting
 * every event would read 2 for a plain proxy session recorded without
 * --name (server.name is the argv-derived basename until the initialize
 * handshake and the learned serverInfo.name after it — review of the
 * integrated change), and would count the client's own session-level
 * events (`claude-code`) as a server in a hook session. 1 for a proxy
 * session with or without --name, 0 for a session that never called a
 * tool, and the number of MCP servers called for a hook session.
 *
 * Non-conforming records are read the same way jsonl.ts reads them: an
 * explicit `phase: null` counts as a call like an absent phase, a
 * server.name that is not a JSON string is not a server, and is_error only
 * counts on tool_call/rpc events.
 */
const SESSIONS_SQL = `
SELECT
  r.session_id                                          AS session_id,
  MIN(r.timestamp)                                      AS started_at,
  MAX(CASE WHEN r.kind = 'session_end' THEN r.timestamp END) AS ended_at,
  COUNT(*)                                              AS event_count,
  SUM(CASE WHEN r.kind = 'tool_call'
            AND (json_extract(r.event, '$.phase') IS NULL
                 OR json_extract(r.event, '$.phase') = 'pre')
           THEN 1 ELSE 0 END)                           AS tool_call_count,
  SUM(CASE WHEN r.kind IN ('tool_call', 'rpc')
            AND json_extract(r.event, '$.is_error') = 1 THEN 1 ELSE 0 END) AS error_count,
  COUNT(DISTINCT CASE WHEN r.kind = 'tool_call'
                       AND json_type(r.event, '$.server.name') = 'text'
                      THEN json_extract(r.event, '$.server.name') END) AS server_count,
  (SELECT json_extract(f.event, '$.server.name')
     FROM records f WHERE f.session_id = r.session_id ORDER BY f.seq LIMIT 1) AS server_name,
  (SELECT json_extract(f.event, '$.identity.fingerprint')
     FROM records f WHERE f.session_id = r.session_id ORDER BY f.seq LIMIT 1) AS identity_fingerprint,
  MIN(r.seq)                                            AS first_seq
FROM records r
GROUP BY r.session_id
ORDER BY first_seq
`;

export interface SqliteStoreOpts {
  /**
   * How long opening may wait, in total, for another process's write
   * transaction to clear (the journal-mode switch and schema creation).
   * Defaults to {@link OPEN_BUSY_TIMEOUT_MS}; tests lower it.
   */
  openTimeoutMs?: number;
}

/** Synchronous open-time wait: generous, because it happens once before any traffic flows. */
export const OPEN_BUSY_TIMEOUT_MS = 10_000;

function isBusyError(err: unknown): boolean {
  const code = (err as { code?: unknown } | null)?.code;
  return typeof code === 'string' && (code.startsWith('SQLITE_BUSY') || code === 'SQLITE_LOCKED');
}


/**
 * Run `fn`, retrying on SQLITE_BUSY/SQLITE_LOCKED with a short, jittered
 * synchronous backoff until `timeoutMs` has elapsed; the last error is
 * rethrown once the deadline passes.
 */
function retryWhileBusy<T>(fn: () => T, timeoutMs: number): T {
  const deadline = Date.now() + timeoutMs;
  let delay = 5;
  for (;;) {
    try {
      return fn();
    } catch (err) {
      if (!isBusyError(err) || Date.now() >= deadline) throw err;
      sleepSync(Math.min(delay, Math.max(1, deadline - Date.now())) + Math.random() * delay);
      delay = Math.min(delay * 2, 100);
    }
  }
}

export class SqliteStore implements EvidenceStore {
  readonly backend = 'sqlite' as const;
  readonly path: string;

  private readonly db: Database.Database;
  private readonly headStmt: Database.Statement<[], HeadRow>;
  private readonly insertRecordStmt: Database.Statement<
    [number, string, string, string, string, string, string]
  >;
  private readonly insertSigStmt: Database.Statement<
    [number, string, string, string, string, string]
  >;
  private readonly appendTx: (records: ChainRecord[]) => void;
  private readonly appendEventsTx: (events: AnyEvent[]) => ChainRecord[];

  constructor(dataDir: string, opts: SqliteStoreOpts = {}) {
    const Ctor = loadSqlite();
    if (Ctor === undefined) {
      throw new Error('mcp-recorder: better-sqlite3 is not available in this environment');
    }
    mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    this.path = join(dataDir, FILES.SQLITE_DB);
    this.db = new Ctor(this.path);
    // Several `mcp-recorder record` processes normally share one data dir
    // (one wrapper per MCP server) — without a busy_timeout, a concurrent
    // writer makes better-sqlite3 throw SQLITE_BUSY immediately instead of
    // waiting for the other transaction to finish. The wait is SYNCHRONOUS
    // (better-sqlite3 blocks the event loop, and with it the proxy's
    // forwarding), so it is kept very short: write transactions here take
    // microseconds, and the recorder retries a busy batch asynchronously
    // with ~6s of non-blocking backoff (src/capture/recorder.ts).
    // Opening: several processes starting at once all race to switch the
    // journal mode and create the schema, which takes real time on a slow
    // machine. This happens once, before any traffic flows, so a generous
    // synchronous wait is fine here — a failure at this point would disable
    // recording for the whole session.
    this.db.pragma(`busy_timeout = ${OPEN_BUSY_TIMEOUT_MS}`);
    // busy_timeout alone does NOT cover the WAL switch. Setting journal_mode
    // = WAL rewrites the file header inside a read transaction that SQLite
    // then upgrades to a write transaction — and SQLite deliberately skips
    // the busy handler on a SHARED -> RESERVED upgrade (it could deadlock two
    // upgraders), returning SQLITE_BUSY immediately instead. So two recorders
    // opening a fresh data dir at the same moment can have one fail with
    // "database is locked" straight away, however long the timeout — seen on
    // the Windows CI runner, where file locking is slow enough to hit the
    // window reliably. Retry the switch (and the schema, for symmetry) with a
    // synchronous sleep until the same deadline instead of giving up.
    const openDeadline = opts.openTimeoutMs ?? OPEN_BUSY_TIMEOUT_MS;
    try {
      retryWhileBusy(() => this.db.pragma('journal_mode = WAL'), openDeadline);
      retryWhileBusy(() => this.db.exec(DDL), openDeadline);
    } catch (err) {
      // Don't leak the handle on a failed open: the caller falls back or
      // disables recording, and an open handle would keep the file locked
      // (which on Windows also blocks deleting the data dir).
      try {
        this.db.close();
      } catch {
        /* best effort */
      }
      throw err;
    }
    // Steady state: appends must never stall forwarding, so the wait is
    // short and the recorder retries asynchronously instead.
    this.db.pragma('busy_timeout = 100');

    this.headStmt = this.db.prepare<[], HeadRow>(
      'SELECT seq, hash FROM records ORDER BY seq DESC LIMIT 1',
    );
    this.insertRecordStmt = this.db.prepare(
      'INSERT INTO records (seq, prev_hash, hash, session_id, kind, timestamp, event) VALUES (?, ?, ?, ?, ?, ?, ?)',
    );
    this.insertSigStmt = this.db.prepare(
      'INSERT INTO signatures (seq, chain_hash, algo, public_key, signature, signed_at) VALUES (?, ?, ?, ?, ?, ?)',
    );
    this.appendTx = this.db.transaction((records: ChainRecord[]) => {
      let head = this.head();
      for (const record of records) {
        validateExtendsHead(head, record);
        this.insertRecordStmt.run(
          record.seq,
          record.prev_hash,
          record.hash,
          record.event.session_id,
          record.event.kind,
          record.event.timestamp,
          canonicalJson(record.event),
        );
        head = { seq: record.seq, hash: record.hash };
      }
    }) as (records: ChainRecord[]) => void;

    // IMMEDIATE: grabs the write lock up front (rather than deferring it
    // until the first write, as a normal BEGIN would), so the head read
    // below is never followed by another connection sneaking in a write
    // before we insert — the read-then-write is atomic across processes.
    const sealAndInsert = this.db.transaction((events: AnyEvent[]): ChainRecord[] => {
      let head = this.head();
      const sealed: ChainRecord[] = [];
      for (const event of events) {
        const record = makeRecord(head, event);
        this.insertRecordStmt.run(
          record.seq,
          record.prev_hash,
          record.hash,
          record.event.session_id,
          record.event.kind,
          record.event.timestamp,
          canonicalJson(record.event),
        );
        sealed.push(record);
        head = { seq: record.seq, hash: record.hash };
      }
      return sealed;
    });
    this.appendEventsTx = (events: AnyEvent[]) => sealAndInsert.immediate(events);
  }

  head(): ChainHead {
    const row = this.headStmt.get();
    return row === undefined ? { seq: 0, hash: GENESIS_HASH } : { seq: row.seq, hash: row.hash };
  }

  append(records: ChainRecord[]): void {
    if (records.length === 0) return;
    this.appendTx(records);
  }

  appendEvents(events: AnyEvent[]): ChainRecord[] {
    if (events.length === 0) return [];
    return this.appendEventsTx(events);
  }

  addSignature(sig: HeadSignature): void {
    this.insertSigStmt.run(
      sig.seq,
      sig.chain_hash,
      sig.algo,
      sig.public_key,
      sig.signature,
      sig.signed_at,
    );
  }

  latestSignature(): HeadSignature | null {
    const row = this.db
      .prepare<[], SigRow>(
        'SELECT seq, chain_hash, algo, public_key, signature, signed_at FROM signatures ORDER BY id DESC LIMIT 1',
      )
      .get();
    return row === undefined ? null : sigFromRow(row);
  }

  signatures(): HeadSignature[] {
    const rows = this.db
      .prepare<[], SigRow>(
        'SELECT seq, chain_hash, algo, public_key, signature, signed_at FROM signatures ORDER BY id',
      )
      .all();
    return rows.map(sigFromRow);
  }

  *iterate(opts: IterateOpts = {}): Iterable<ChainRecord> {
    const where: string[] = [];
    const params: Array<string | number> = [];
    if (opts.fromSeq !== undefined) {
      where.push('seq >= ?');
      params.push(opts.fromSeq);
    }
    if (opts.toSeq !== undefined) {
      where.push('seq <= ?');
      params.push(opts.toSeq);
    }
    if (opts.sessionId !== undefined) {
      where.push('session_id = ?');
      params.push(opts.sessionId);
    }
    const sql =
      'SELECT seq, prev_hash, hash, event FROM records' +
      (where.length > 0 ? ' WHERE ' + where.join(' AND ') : '') +
      ' ORDER BY seq';
    const stmt = this.db.prepare<Array<string | number>, RecordRow>(sql);
    for (const row of stmt.iterate(...params)) {
      yield {
        seq: row.seq,
        prev_hash: row.prev_hash,
        hash: row.hash,
        event: JSON.parse(row.event) as AnyEvent,
      };
    }
  }

  count(): number {
    const row = this.db.prepare<[], { n: number }>('SELECT COUNT(*) AS n FROM records').get();
    return row?.n ?? 0;
  }

  sessions(): SessionSummary[] {
    const rows = this.db.prepare<[], SessionRow>(SESSIONS_SQL).all();
    return rows.map((row) => {
      const summary: SessionSummary = {
        session_id: row.session_id,
        started_at: row.started_at,
        server_name: row.server_name ?? '',
        identity_fingerprint: row.identity_fingerprint ?? '',
        event_count: row.event_count,
        tool_call_count: row.tool_call_count,
        error_count: row.error_count,
        server_count: row.server_count,
      };
      if (row.ended_at !== null) summary.ended_at = row.ended_at;
      return summary;
    });
  }

  close(): void {
    this.db.close();
  }
}

/**
 * Shared write-boundary check: a record may only be appended when it extends
 * the current head exactly (used by both backends; safe to import from
 * anywhere — this module never loads better-sqlite3 unless a store is opened).
 */
export function validateExtendsHead(head: ChainHead, record: ChainRecord): void {
  const expectedSeq = head.seq + 1;
  if (record.seq !== expectedSeq) {
    throw new Error(
      `chain integrity violation: expected seq ${expectedSeq}, got ${record.seq}`,
    );
  }
  const expectedPrev = head.seq === 0 ? GENESIS_HASH : head.hash;
  if (record.prev_hash !== expectedPrev) {
    throw new Error(
      `chain integrity violation: prev_hash mismatch at seq ${record.seq} (expected ${expectedPrev}, got ${record.prev_hash})`,
    );
  }
  const recomputed = computeHash(record.prev_hash, record.event);
  if (record.hash !== recomputed) {
    throw new Error(
      `chain integrity violation: hash mismatch at seq ${record.seq} (recomputed ${recomputed}, got ${record.hash})`,
    );
  }
}

function sigFromRow(row: SigRow): HeadSignature {
  return {
    seq: row.seq,
    chain_hash: row.chain_hash,
    algo: row.algo as HeadSignature['algo'],
    public_key: row.public_key,
    signature: row.signature,
    signed_at: row.signed_at,
  };
}
