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
import { GENESIS_HASH, canonicalJson, computeHash, makeRecord } from '../chain/hash.js';
import { FILES } from '../types.js';
import { sleepSync } from '../util/sleep-sync.js';
let cachedCtor;
let loadFailed = false;
function loadSqlite() {
    if (cachedCtor !== undefined)
        return cachedCtor;
    if (loadFailed)
        return undefined;
    try {
        const require = createRequire(import.meta.url);
        cachedCtor = require('better-sqlite3');
        return cachedCtor;
    }
    catch {
        loadFailed = true;
        return undefined;
    }
}
/** True when the optional better-sqlite3 dependency can be loaded. */
export function isSqliteAvailable() {
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
/** Synchronous open-time wait: generous, because it happens once before any traffic flows. */
export const OPEN_BUSY_TIMEOUT_MS = 10_000;
function isBusyError(err) {
    const code = err?.code;
    return typeof code === 'string' && (code.startsWith('SQLITE_BUSY') || code === 'SQLITE_LOCKED');
}
/**
 * Run `fn`, retrying on SQLITE_BUSY/SQLITE_LOCKED with a short, jittered
 * synchronous backoff until `timeoutMs` has elapsed; the last error is
 * rethrown once the deadline passes.
 */
function retryWhileBusy(fn, timeoutMs) {
    const deadline = Date.now() + timeoutMs;
    let delay = 5;
    for (;;) {
        try {
            return fn();
        }
        catch (err) {
            if (!isBusyError(err) || Date.now() >= deadline)
                throw err;
            sleepSync(Math.min(delay, Math.max(1, deadline - Date.now())) + Math.random() * delay);
            delay = Math.min(delay * 2, 100);
        }
    }
}
export class SqliteStore {
    backend = 'sqlite';
    path;
    db;
    headStmt;
    insertRecordStmt;
    insertSigStmt;
    appendTx;
    appendEventsTx;
    constructor(dataDir, opts = {}) {
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
        }
        catch (err) {
            // Don't leak the handle on a failed open: the caller falls back or
            // disables recording, and an open handle would keep the file locked
            // (which on Windows also blocks deleting the data dir).
            try {
                this.db.close();
            }
            catch {
                /* best effort */
            }
            throw err;
        }
        // Steady state: appends must never stall forwarding, so the wait is
        // short and the recorder retries asynchronously instead.
        this.db.pragma('busy_timeout = 100');
        this.headStmt = this.db.prepare('SELECT seq, hash FROM records ORDER BY seq DESC LIMIT 1');
        this.insertRecordStmt = this.db.prepare('INSERT INTO records (seq, prev_hash, hash, session_id, kind, timestamp, event) VALUES (?, ?, ?, ?, ?, ?, ?)');
        this.insertSigStmt = this.db.prepare('INSERT INTO signatures (seq, chain_hash, algo, public_key, signature, signed_at) VALUES (?, ?, ?, ?, ?, ?)');
        this.appendTx = this.db.transaction((records) => {
            let head = this.head();
            for (const record of records) {
                validateExtendsHead(head, record);
                this.insertRecordStmt.run(record.seq, record.prev_hash, record.hash, record.event.session_id, record.event.kind, record.event.timestamp, canonicalJson(record.event));
                head = { seq: record.seq, hash: record.hash };
            }
        });
        // IMMEDIATE: grabs the write lock up front (rather than deferring it
        // until the first write, as a normal BEGIN would), so the head read
        // below is never followed by another connection sneaking in a write
        // before we insert — the read-then-write is atomic across processes.
        const sealAndInsert = this.db.transaction((events) => {
            let head = this.head();
            const sealed = [];
            for (const event of events) {
                const record = makeRecord(head, event);
                this.insertRecordStmt.run(record.seq, record.prev_hash, record.hash, record.event.session_id, record.event.kind, record.event.timestamp, canonicalJson(record.event));
                sealed.push(record);
                head = { seq: record.seq, hash: record.hash };
            }
            return sealed;
        });
        this.appendEventsTx = (events) => sealAndInsert.immediate(events);
    }
    head() {
        const row = this.headStmt.get();
        return row === undefined ? { seq: 0, hash: GENESIS_HASH } : { seq: row.seq, hash: row.hash };
    }
    append(records) {
        if (records.length === 0)
            return;
        this.appendTx(records);
    }
    appendEvents(events) {
        if (events.length === 0)
            return [];
        return this.appendEventsTx(events);
    }
    addSignature(sig) {
        this.insertSigStmt.run(sig.seq, sig.chain_hash, sig.algo, sig.public_key, sig.signature, sig.signed_at);
    }
    latestSignature() {
        const row = this.db
            .prepare('SELECT seq, chain_hash, algo, public_key, signature, signed_at FROM signatures ORDER BY id DESC LIMIT 1')
            .get();
        return row === undefined ? null : sigFromRow(row);
    }
    signatures() {
        const rows = this.db
            .prepare('SELECT seq, chain_hash, algo, public_key, signature, signed_at FROM signatures ORDER BY id')
            .all();
        return rows.map(sigFromRow);
    }
    *iterate(opts = {}) {
        const where = [];
        const params = [];
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
        const sql = 'SELECT seq, prev_hash, hash, event FROM records' +
            (where.length > 0 ? ' WHERE ' + where.join(' AND ') : '') +
            ' ORDER BY seq';
        const stmt = this.db.prepare(sql);
        for (const row of stmt.iterate(...params)) {
            yield {
                seq: row.seq,
                prev_hash: row.prev_hash,
                hash: row.hash,
                event: JSON.parse(row.event),
            };
        }
    }
    count() {
        const row = this.db.prepare('SELECT COUNT(*) AS n FROM records').get();
        return row?.n ?? 0;
    }
    sessions() {
        const rows = this.db.prepare(SESSIONS_SQL).all();
        return rows.map((row) => {
            const summary = {
                session_id: row.session_id,
                started_at: row.started_at,
                server_name: row.server_name ?? '',
                identity_fingerprint: row.identity_fingerprint ?? '',
                event_count: row.event_count,
                tool_call_count: row.tool_call_count,
                error_count: row.error_count,
            };
            if (row.ended_at !== null)
                summary.ended_at = row.ended_at;
            return summary;
        });
    }
    close() {
        this.db.close();
    }
}
/**
 * Shared write-boundary check: a record may only be appended when it extends
 * the current head exactly (used by both backends; safe to import from
 * anywhere — this module never loads better-sqlite3 unless a store is opened).
 */
export function validateExtendsHead(head, record) {
    const expectedSeq = head.seq + 1;
    if (record.seq !== expectedSeq) {
        throw new Error(`chain integrity violation: expected seq ${expectedSeq}, got ${record.seq}`);
    }
    const expectedPrev = head.seq === 0 ? GENESIS_HASH : head.hash;
    if (record.prev_hash !== expectedPrev) {
        throw new Error(`chain integrity violation: prev_hash mismatch at seq ${record.seq} (expected ${expectedPrev}, got ${record.prev_hash})`);
    }
    const recomputed = computeHash(record.prev_hash, record.event);
    if (record.hash !== recomputed) {
        throw new Error(`chain integrity violation: hash mismatch at seq ${record.seq} (recomputed ${recomputed}, got ${record.hash})`);
    }
}
function sigFromRow(row) {
    return {
        seq: row.seq,
        chain_hash: row.chain_hash,
        algo: row.algo,
        public_key: row.public_key,
        signature: row.signature,
        signed_at: row.signed_at,
    };
}
//# sourceMappingURL=sqlite.js.map