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
import type { AnyEvent, ChainRecord, HeadSignature } from '../schema/events.js';
import type { ChainHead, EvidenceStore, IterateOpts, SessionSummary } from '../types.js';
/** True when the optional better-sqlite3 dependency can be loaded. */
export declare function isSqliteAvailable(): boolean;
export interface SqliteStoreOpts {
    /**
     * How long opening may wait, in total, for another process's write
     * transaction to clear (the journal-mode switch and schema creation).
     * Defaults to {@link OPEN_BUSY_TIMEOUT_MS}; tests lower it.
     */
    openTimeoutMs?: number;
}
/** Synchronous open-time wait: generous, because it happens once before any traffic flows. */
export declare const OPEN_BUSY_TIMEOUT_MS = 10000;
export declare class SqliteStore implements EvidenceStore {
    readonly backend: "sqlite";
    readonly path: string;
    private readonly db;
    private readonly headStmt;
    private readonly insertRecordStmt;
    private readonly insertSigStmt;
    private readonly appendTx;
    private readonly appendEventsTx;
    constructor(dataDir: string, opts?: SqliteStoreOpts);
    head(): ChainHead;
    append(records: ChainRecord[]): void;
    appendEvents(events: AnyEvent[]): ChainRecord[];
    addSignature(sig: HeadSignature): void;
    latestSignature(): HeadSignature | null;
    signatures(): HeadSignature[];
    iterate(opts?: IterateOpts): Iterable<ChainRecord>;
    count(): number;
    sessions(): SessionSummary[];
    close(): void;
}
/**
 * Shared write-boundary check: a record may only be appended when it extends
 * the current head exactly (used by both backends; safe to import from
 * anywhere — this module never loads better-sqlite3 unless a store is opened).
 */
export declare function validateExtendsHead(head: ChainHead, record: ChainRecord): void;
