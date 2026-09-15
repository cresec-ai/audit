/**
 * Gateway hold store — `<dataDir>/holds/<approval_id>.json`.
 *
 * A `hold` policy action parks a tools/call until a human runs
 * `mcp-recorder approve|deny <id>` (or it times out / is cancelled). The
 * proxy and the CLI share nothing but the filesystem, so a hold is one
 * small JSON file, written atomically (temp + rename) and re-read by
 * polling: `fs.watch` is unreliable across platforms and the proxy must
 * never block on it.
 *
 * Invariants:
 *  - Hold files never contain readable payloads: `args` is the SCRUBBED
 *    tree (hashed unconditionally, like `tool_call.args`) and `args_hash`
 *    the canonical hash. This module stores what it is given; the caller
 *    scrubs.
 *  - The directory is created 0700 and files 0600 (best effort on Windows).
 *  - `waitForDecision()` never throws and never keeps the process alive:
 *    every timer is `unref()`'d, a corrupt or missing file is just "still
 *    pending" until the deadline.
 *  - Ids are uuid v4 (`randomUUID`) and are validated before they touch a
 *    path, so a CLI argument can never escape the holds directory.
 */
export type HoldStatus = 'pending' | 'approved' | 'denied' | 'timeout' | 'cancelled' | 'session_end';
export interface HoldRecord {
    version: 1;
    approval_id: string;
    created_at: string;
    session_id: string;
    server: string;
    tool: string;
    /** Scrubbed tree — never readable. */
    args: unknown;
    args_hash: string;
    rule_id?: string;
    reason?: string;
    status: HoldStatus;
    timeout_at: string;
    decided_at?: string;
    decided_by?: string;
}
/** What `create()` needs; the store fills in version/status/created_at and
 * (when absent) the approval id. */
export type HoldCreateInput = Omit<HoldRecord, 'version' | 'status' | 'created_at' | 'approval_id'> & {
    created_at?: string;
    approval_id?: string;
};
export type HoldDecision = 'approved' | 'denied';
export interface HoldWaitOptions {
    timeoutMs: number;
    /** Poll interval; default 200 ms. */
    pollMs?: number;
    /** Aborting resolves `cancelled` immediately. */
    signal?: AbortSignal;
}
export interface HoldWaitResult {
    status: 'approved' | 'denied' | 'timeout' | 'cancelled';
    /** The last record read, when one could be read. */
    record?: HoldRecord;
    waitedMs: number;
}
export type HoldErrorCode = 'not_found' | 'not_pending' | 'invalid_id';
export declare class HoldError extends Error {
    readonly code: HoldErrorCode;
    constructor(code: HoldErrorCode, message: string);
}
/** Default poll interval for `waitForDecision`. */
export declare const DEFAULT_POLL_MS = 200;
export declare class HoldStore {
    /** `<dataDir>/holds` */
    readonly dir: string;
    constructor(dataDir: string);
    private pathOf;
    private ensureDir;
    private write;
    /** Write a new pending hold. Throws on I/O failure (caller denies: "hold unavailable"). */
    create(input: HoldCreateInput): HoldRecord;
    /** The record, or undefined when missing, unreadable, corrupt or oddly shaped. Never throws. */
    read(id: string): HoldRecord | undefined;
    /** Ids of every well-formed hold file name in the directory (unsorted). */
    private ids;
    /** Pending holds (default) or every hold with `all`, oldest first. Corrupt files are skipped. */
    list(opts?: {
        all?: boolean;
    }): HoldRecord[];
    /** Resolve a full id or a unique prefix of one against the files on disk. */
    resolveId(prefix: string): {
        ok: true;
        id: string;
    } | {
        ok: false;
        reason: 'not_found' | 'ambiguous';
    };
    /** Approve or deny a PENDING hold (the CLI path). Throws HoldError otherwise. */
    decide(id: string, status: HoldDecision, by?: string): HoldRecord;
    /**
     * Record the final status of a hold the proxy stopped waiting on
     * (timeout / cancelled / session_end, or an approval it acted on). Best
     * effort: a missing or unreadable file, or an I/O failure, is ignored —
     * this runs on the proxy's fail-open path.
     */
    finalize(id: string, status: HoldStatus): void;
    /**
     * Poll the hold file until it is approved/denied, the deadline passes, or
     * `signal` aborts. Timers are unref()'d; never rejects.
     */
    waitForDecision(id: string, opts: HoldWaitOptions): Promise<HoldWaitResult>;
}
