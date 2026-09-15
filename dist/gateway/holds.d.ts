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
 *  - The pending -> final transition happens EXACTLY ONCE, across processes.
 *    Reading the file and writing it back is not enough: two
 *    `mcp-recorder approve|deny` runs (or an approval racing the proxy's own
 *    timeout) both saw `pending`, both wrote, and the last rename won. Every
 *    writer therefore first creates `<id>.decided` with `openSync(..., 'wx')`
 *    — an atomic, Windows-safe create-if-absent — and only the process that
 *    wins that CAS writes the record: `decide()` throws `not_pending` when it
 *    loses, `finalize()` (timeout / cancelled / session_end) returns without
 *    touching a decision that got there first.
 *  - A `pending` hold whose `timeout_at` has passed is reported and treated
 *    as `timeout` even if nothing ever rewrote it: the proxy that parked it
 *    may have died, and a stale hold must not stay approvable forever.
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
/** Total wall-clock budget for {@link renameRetrying} before the error propagates. */
export declare const RENAME_RETRY_BUDGET_MS = 1000;
export interface RenameRetryDeps {
    rename: (from: string, to: string) => void;
    sleep: (ms: number) => void;
    now: () => number;
}
/**
 * `renameSync(from, to)` that retries the transient Windows sharing errors
 * above with exponential backoff (2, 4, 8, … 50 ms) for at most
 * {@link RENAME_RETRY_BUDGET_MS}. Every other error, and a transient one
 * that outlives the budget, is thrown unchanged.
 */
export declare function renameRetrying(from: string, to: string, deps?: RenameRetryDeps): void;
export declare class HoldStore {
    /** `<dataDir>/holds` */
    readonly dir: string;
    constructor(dataDir: string);
    private pathOf;
    /**
     * Win the pending -> final transition, atomically and across processes.
     * `wx` fails with EEXIST when the file is already there — the one syscall
     * POSIX and Windows both make exclusive — so exactly one caller can ever
     * see `true` for a given hold.
     */
    private claim;
    /** Give a claim back when the record it was taken for could not be written. */
    private releaseClaim;
    private ensureDir;
    private write;
    /** Write a new pending hold. Throws on I/O failure (caller denies: "hold unavailable"). */
    create(input: HoldCreateInput): HoldRecord;
    /** The record, or undefined when missing, unreadable, corrupt or oddly shaped. Never throws. */
    read(id: string): HoldRecord | undefined;
    /** Ids of every well-formed hold file name in the directory (unsorted). */
    private ids;
    /**
     * Pending holds (default) or every hold with `all`, oldest first. Corrupt
     * files are skipped. A hold still marked `pending` on disk whose
     * `timeout_at` has passed is reported as `timeout` (and is therefore NOT in
     * the default, actionable listing) — the proxy that would have written that
     * status may be long gone.
     */
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
    /**
     * Approve or deny a PENDING hold (the CLI path). Throws HoldError
     * otherwise — including when another process (a second `approve`, or the
     * proxy's own timeout) won the transition between the read and the write:
     * the sentinel makes that race a clean `not_pending`, never two "success"
     * lines for one hold.
     */
    decide(id: string, status: HoldDecision, by?: string): HoldRecord;
    /**
     * Record the final status of a hold the proxy stopped waiting on
     * (timeout / cancelled / session_end, or an approval it acted on). Best
     * effort: a missing or unreadable file, or an I/O failure, is ignored —
     * this runs on the proxy's fail-open path.
     *
     * It takes the same sentinel as `decide()`: a human decision that got there
     * first is NEVER overwritten (the call simply returns, leaving the approver,
     * their timestamp and the status a concurrent `waitForDecision` is about to
     * read), and a timeout that got there first cannot be undone by a late
     * approval either.
     */
    finalize(id: string, status: HoldStatus): void;
    /**
     * Poll the hold file until it is approved/denied, the deadline passes, or
     * `signal` aborts. Timers are unref()'d; never rejects.
     */
    waitForDecision(id: string, opts: HoldWaitOptions): Promise<HoldWaitResult>;
}
