/**
 * THE SHIPPER — a reader of the chain, and nothing else.
 *
 * It runs in its OWN process (`mcp-recorder ship`), never on the forwarding
 * path. It does not call `record()`, never holds the store's write lock
 * while doing I/O, and in the default deployment does not run inside the
 * proxy at all. That is not a preference: `hook` is a SHORT-LIVED PROCESS
 * PER HOOK INVOCATION (src/hook/state.ts), so there is no long-lived event
 * loop to put an in-process shipper into, and blocking a hook on a POST
 * would put sink latency directly in front of every tool call.
 *
 * THE SPOOL IS THE CHAIN. There is no second queue and no separate spool
 * file: the shipper reads with `store.iterate({fromSeq, toSeq})`. The jsonl
 * backend's read methods do not take the advisory write lock (they
 * incrementally parse only the bytes another process appended), and sqlite
 * reads under WAL, so a shipper never contends with a recording process.
 * Nothing is ever dropped from the local store because of the sink; the
 * backlog is bounded only by disk.
 *
 * THE SHIPPER NEVER APPENDS TO THE CHAIN. Writing a "shipped" event would
 * change the chain it is trying to ship. All sink state lives in
 * <data-dir>/sink-cursor.json (a cache) and <data-dir>/ship-status.json
 * (what an operator reads).
 *
 * Crash-only by construction: there are no "unsent events" to drain, because
 * everything `record()` sealed is already in the store. The next shipper
 * start reads the receiver's cursor and ships the backlog. If the machine
 * never comes back, the receiver holds everything up to the last 202 PLUS a
 * signed head proving how much more existed.
 *
 * Every terminal condition here STALLS LOUDLY rather than degrading quietly.
 * The sender must NEVER skip a seq: a gap at the receiver makes everything
 * after it unverifiable forever, which is far worse than a visible stall.
 */
import type { ChainRecord, HeadSignature } from '../schema/events.js';
import type { EvidenceStore, SignerLike } from '../types.js';
import type { SinkSigner } from './client.js';
import type { SinkConfig } from './config.js';
import type { SinkSurface } from './protocol.js';
import type { ShipState } from './state.js';
/** Both halves of the signing surface: request signatures and head signatures. */
export type ShipSigner = SinkSigner & SignerLike;
export interface ShipperOpts {
    dataDir: string;
    sink: SinkConfig;
    store: EvidenceStore;
    signer: ShipSigner;
    toolVersion: string;
    surface: SinkSurface;
    env?: NodeJS.ProcessEnv;
    /** One stderr line per distinct condition; see `logOnce` below. */
    log?: (msg: string) => void;
    now?: () => number;
    sleep?: (ms: number) => Promise<void>;
    random?: () => number;
    /** Refresh the single-instance lock so peers can tell it from a corpse. */
    touchLock?: () => void;
    heartbeatIntervalMs?: number;
    /** Ship the backlog and exit — the CI mode (`ship --drain`). */
    drain?: boolean;
    /** Wall-clock ceiling for drain mode. */
    drainTimeoutMs?: number;
    /** Exit after this long with neither local growth nor a delivery. 0 = never. */
    idleExitMs?: number;
    /** How often to look for new records while caught up. */
    pollIntervalMs?: number;
    connectTimeoutMs?: number;
    totalTimeoutMs?: number;
    gzipThresholdBytes?: number;
    /** Test seam: stop after this many POST attempts. */
    maxPosts?: number;
}
export interface ShipperResult {
    state: ShipState;
    chainId?: string;
    /** Records this run got a 202 for. */
    delivered: number;
    /** Receiver's resume point as last reported. */
    nextSeq: number;
    localHeadSeq: number;
    /** localHeadSeq - (nextSeq - 1): sealed records the receiver does not have. */
    lag: number;
    lastError?: string;
    posts: number;
}
/** No local growth and no delivery for this long: exit, and let the next
 *  `record`/`hook` respawn us. Supervised fleets pass 0 and run forever. */
export declare const DEFAULT_IDLE_EXIT_MS: number;
/**
 * Pick the next batch: contiguous, ascending, from `fromSeq`, bounded by
 * whichever cap binds first — but ALWAYS at least one record, even when that
 * record alone blows the byte cap. Skipping is not an option.
 */
export declare function collectBatch(store: EvidenceStore, fromSeq: number, maxRecords: number, maxBytes: number): ChainRecord[];
/** Signatures whose seq falls inside [fromSeq, toSeq] — every one we hold. */
export declare function signaturesInRange(store: EvidenceStore, fromSeq: number, toSeq: number): HeadSignature[];
/**
 * One shipping run. Resolves when the loop ends: drained, idle-exited,
 * post-capped, or parked in a terminal state. Never throws for a sink
 * condition — every one of them is a state plus a diagnostic.
 */
export declare function runShipper(opts: ShipperOpts): Promise<ShipperResult>;
