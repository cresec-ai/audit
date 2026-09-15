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
/**
 * Backoff before each retry of a failed batch, after the initial attempt —
 * transient contention (lock wait, a busy database) among several recorder
 * processes sharing one data dir usually clears within a few ms. The waits
 * here are asynchronous (they never block forwarding); the stores' own
 * synchronous waits are kept to ~100ms per attempt for the same reason. The
 * sum (~5.9s) outlasts the jsonl store's 5s stale-lock reclaim, so a lock
 * abandoned by a crashed peer costs a delay, not a dropped batch, and it is
 * covered by stdio.ts's recorder.close() timeout so a session_end still
 * lands on shutdown even after a full retry run.
 */
const RETRY_DELAYS_MS = [10, 25, 50, 100, 250, 500, 1000, 2000, 2000];
function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}
function logOnce(loggedRef, msg, err) {
    if (loggedRef.v)
        return;
    loggedRef.v = true;
    const detail = err instanceof Error ? err.message : err !== undefined ? String(err) : '';
    try {
        process.stderr.write(`[mcp-recorder] ${msg}${detail ? `: ${detail}` : ''}\n`);
    }
    catch {
        /* even diagnostics are fail-open: a closed stderr must never take the proxy down */
    }
}
export class Recorder {
    store;
    signer;
    signEveryFlush;
    retryDelaysMs;
    queue = [];
    flushScheduled = false;
    /** In-flight flush, so flush()/close() can await the active drain. */
    flushing = Promise.resolve();
    enqueued = 0;
    written = 0;
    dropped = 0;
    storeFailed = false;
    closed = false;
    closePromise = null;
    storeErrorLogged = { v: false };
    signerErrorLogged = { v: false };
    constructor(opts) {
        this.store = opts.store;
        this.signer = opts.signer;
        this.signEveryFlush = opts.signEveryFlush ?? true;
        this.retryDelaysMs = opts.retryDelaysMs ?? RETRY_DELAYS_MS;
    }
    /** Hot path: O(1), never throws. */
    record(event) {
        try {
            this.enqueued++;
            if (this.store === null || this.storeFailed || this.closed) {
                this.dropped++;
                return;
            }
            this.queue.push(event);
            if (!this.flushScheduled) {
                this.flushScheduled = true;
                setImmediate(() => {
                    this.flushScheduled = false;
                    void this.flush();
                });
            }
        }
        catch (err) {
            // Defensive: nothing above should throw, but fail-open regardless.
            this.dropped++;
            logOnce(this.storeErrorLogged, 'record() failed; dropping events', err);
        }
    }
    /** Drain the queue in one batch. Never rejects. */
    flush() {
        const run = this.flushing.then(() => this.drainOnce());
        // Keep the chain alive even though drainOnce never rejects.
        this.flushing = run.catch(() => undefined);
        return this.flushing;
    }
    async drainOnce() {
        if (this.queue.length === 0)
            return;
        const events = this.queue;
        this.queue = [];
        if (this.store === null || this.storeFailed) {
            this.dropped += events.length;
            return;
        }
        const store = this.store;
        let batch;
        let lastErr;
        for (let attempt = 0;; attempt++) {
            try {
                batch = store.appendEvents(events);
                break;
            }
            catch (err) {
                lastErr = err;
                if (attempt >= this.retryDelaysMs.length)
                    break; // every retry spent
                await sleep(this.retryDelaysMs[attempt]);
            }
        }
        if (batch === undefined) {
            this.storeFailed = true;
            this.dropped += events.length;
            logOnce(this.storeErrorLogged, 'store append failed; recording disabled, dropping events', lastErr);
            return;
        }
        this.written += batch.length;
        if (this.signer && this.signEveryFlush && batch.length > 0) {
            const tip = batch[batch.length - 1];
            try {
                const sig = await this.signer.sign(tip.seq, tip.hash);
                store.addSignature(sig);
            }
            catch (err) {
                // Signature failure does not invalidate stored events; warn once.
                logOnce(this.signerErrorLogged, 'head signing failed', err);
            }
        }
    }
    /** Flush, then release the store. Idempotent. */
    close() {
        if (this.closePromise)
            return this.closePromise;
        this.closePromise = (async () => {
            await this.flush();
            this.closed = true;
            if (this.store && !this.storeFailed) {
                try {
                    this.store.close();
                }
                catch (err) {
                    logOnce(this.storeErrorLogged, 'store close failed', err);
                }
            }
        })();
        return this.closePromise;
    }
    stats() {
        return {
            enqueued: this.enqueued,
            written: this.written,
            dropped: this.dropped,
            storeFailed: this.storeFailed,
        };
    }
}
//# sourceMappingURL=recorder.js.map