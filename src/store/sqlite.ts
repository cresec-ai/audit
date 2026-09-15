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

/**
 * How long the one-time open/schema step keeps retrying SQLITE_BUSY. It
 * runs once per process, before any traffic flows, so a generous bound is
 * fine — see the constructor for why `busy_timeout` alone is not enough.
 */
export const INIT_BUSY_DEADLINE_MS = 10_000;

/** better-sqlite3 surfaces lock contention as a SqliteError with this code. */
export function isSqliteBusy(err: unknown): boolean {
  if (!(err instanceof Error)) return false;
  const code = (err as { code?: unknown }).code;
  if (typeof code === 'string' && code.startsWith('SQLITE_BUSY')) return true;
  return /database is locked/i.test(err.message);
}

/** A real synchronous sleep, without a native dependency. */
function sleepSync(ms: number): void {
  const sab = new SharedArrayBuffer(4);
  Atomics.wait(new Int32Array(sab), 0, 0, ms);
}

/**
 * Run `fn`, retrying with a short exponential backoff (5 ms doubling up to
 * 100 ms) for as long as it fails with SQLITE_BUSY and the deadline has not
 * passed. Any other error, or a busy error past the deadline, propagates.
 * `sleep`/`now` are injectable for tests.
 */
export function retryWhileBusy<T>(
  fn: () => T,
  opts: { deadlineMs: number; sleep?: (ms: number) => void; now?: () => number },
): T {
  const sleep = opts.sleep ?? sleepSync;
  const now = opts.now ?? Date.now;
  const start = now();
  let delay = 5;
  for (;;) {
    try {
      return fn();
    } catch (err) {
      if (!isSqliteBusy(err) || now() - start >= opts.deadlineMs) throw err;
      sleep(delay);
      delay = Math.min(delay * 2, 100);
    }
  }
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
}

const SESSIONS_SQL = `
SELECT
  r.session_id                                          AS session_id,
  MIN(r.timestamp)                                      AS started_at,
  MAX(CASE WHEN r.kind = 'session_end' THEN r.timestamp END) AS ended_at,
  COUNT(*)                                              AS event_count,
  SUM(CASE WHEN r.kind = 'tool_call' THEN 1 ELSE 0 END) AS tool_call_count,
  SUM(CASE WHEN json_extract(r.event, '$.is_error') = 1 THEN 1 ELSE 0 END) AS error_count,
  (SELECT json_extract(f.event, '$.server.name')
     FROM records f WHERE f.session_id = r.session_id ORDER BY f.seq LIMIT 1) AS server_name,
  (SELECT json_extract(f.event, '$.identity.fingerprint')
     FROM records f WHERE f.session_id = r.session_id ORDER BY f.seq LIMIT 1) AS identity_fingerprint,
  MIN(r.seq)                                            AS first_seq
FROM records r
GROUP BY r.session_id
ORDER BY first_seq
`;

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

  constructor(dataDir: string) {
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
    //
    // busy_timeout alone does not cover this race: SQLite deliberately skips
    // the busy handler and returns SQLITE_BUSY at once when waiting could
    // deadlock — the classic case being a connection that already holds a
    // SHARED lock (it just read the header/schema) asking to write while
    // another connection holds PENDING, which is exactly what two fresh
    // processes switching to WAL and running CREATE TABLE at the same moment
    // look like. So the open/schema step is additionally retried from
    // scratch on SQLITE_BUSY with a short backoff (CI reproduced the bare
    // "database is locked" at init with the 10 s timeout already in place).
    this.db.pragma('busy_timeout = 10000');
    retryWhileBusy(
      () => {
        this.db.pragma('journal_mode = WAL');
        this.db.exec(DDL);
      },
      { deadlineMs: INIT_BUSY_DEADLINE_MS },
    );
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
