/**
 * Async, fail-open capture sink (M1). `record()` is synchronous, O(1) and
 * never throws; events are batched off the hot path via setImmediate and
 * sealed into chain records by the store itself (`appendEvents`), under the
 * store's own exclusive lock — several `mcp-recorder record` processes
 * normally share one data dir (one wrapper per MCP server), so a batch can
 * fail transiently (lock contention, a busy database) without being a real
 * problem. A failed batch is retried with backoff before anything is
 * dropped; only once every retry has failed does the recorder flip into
 * drop mode, where traffic is never affected, drops are counted, and
 * exactly one diagnostic line goes to stderr.
 */
import type { AnyEvent } from '../schema/events.js';
import type { EvidenceStore, RecorderLike, RecorderStats, SignerLike } from '../types.js';
export interface RecorderOpts {
    store: EvidenceStore | null;
    signer: SignerLike | null;
    /** Sign the chain head after every flush (default true). */
    signEveryFlush?: boolean;
    /** Backoff (ms) before each retry of a failed batch; tests pass [] for none. */
    retryDelaysMs?: readonly number[];
}
export declare class Recorder implements RecorderLike {
    private readonly store;
    private readonly signer;
    private readonly signEveryFlush;
    private readonly retryDelaysMs;
    private queue;
    private flushScheduled;
    /** In-flight flush, so flush()/close() can await the active drain. */
    private flushing;
    private enqueued;
    private written;
    private dropped;
    private storeFailed;
    private closed;
    private closePromise;
    private readonly storeErrorLogged;
    private readonly signerErrorLogged;
    constructor(opts: RecorderOpts);
    /** Hot path: O(1), never throws. */
    record(event: AnyEvent): void;
    /** Drain the queue in one batch. Never rejects. */
    flush(): Promise<void>;
    private drainOnce;
    /** Flush, then release the store. Idempotent. */
    close(): Promise<void>;
    stats(): RecorderStats;
}
