/**
 * The shipper's only durable state, all of it outside the chain.
 *
 * THE SHIPPER NEVER APPENDS TO THE CHAIN. It is a reader: writing a
 * "shipped" event would change the very chain it is trying to ship, a
 * self-referential moving target. So everything it needs to remember lives
 * in two small files beside the store:
 *
 *   <data-dir>/sink-cursor.json — a CACHE of the receiver's cursor, consulted
 *       only to avoid a round trip. NEVER authoritative: the shipper re-reads
 *       the receiver's cursor on startup, on any 409 and on any 4xx, and a
 *       stale cache is harmless because the receiver hash-checks the
 *       overlapping prefix and commits only the suffix.
 *   <data-dir>/ship-status.json — what `mcp-recorder ship --status` prints.
 *       This is the file that turns a stall from an invisible condition into
 *       a human-legible one.
 *
 * Both are written tmp+rename, and a failed write is non-fatal — the local
 * store is the source of truth and the receiver is the authority on what it
 * holds.
 *
 * Single instance is a `<data-dir>/ship.lock` DIRECTORY created with
 * `mkdirSync`: the same atomic-create mutex the jsonl store, the hook's
 * session markers and `identity.key` already use, and the only one that is
 * atomic on every platform node supports.
 */
import type { SinkCursor } from './protocol.js';
export interface CursorCache extends SinkCursor {
    /** The sink this cursor came from — a different sink invalidates it. */
    sink: string;
    updated_at: string;
}
export declare function cursorCachePath(dataDir: string): string;
/** Read the cached cursor, or undefined for missing/corrupt/other-sink. */
export declare function readCursorCache(dataDir: string, sinkUrl: string): CursorCache | undefined;
/** Best effort; a failed cursor write is never fatal. */
export declare function writeCursorCache(dataDir: string, sinkUrl: string, cursor: SinkCursor): void;
/**
 * `idle` and `shipping` are healthy. Everything else is a condition an
 * operator has to see, which is exactly why it is written down rather than
 * only logged: a stall that nobody can observe is the failure mode this
 * whole design exists to avoid.
 */
export type ShipState = 'idle' | 'shipping' | 'retrying' | 'stalled' | 'forked' | 'unauthorized' | 'refused';
export interface ShipStatus {
    sink: string;
    key?: string;
    chain_id?: string;
    state: ShipState;
    /** Sender's local head seq at the last loop iteration. */
    local_head_seq: number;
    /** Receiver's resume point, as the receiver last reported it. */
    next_seq?: number;
    attested_seq?: number;
    /** local_head_seq - (next_seq - 1): sealed records the receiver lacks. */
    lag: number;
    last_error?: string;
    last_error_at?: string;
    last_success_at?: string;
    /** Records dropped by the STORE (disk full, ...) as counted by the
     *  recorder — surfaced here because a dropped record is the one gap the
     *  chain itself cannot show, and it must never be silent. */
    updated_at: string;
    pid: number;
}
export declare function statusPath(dataDir: string): string;
export declare function readShipStatus(dataDir: string): ShipStatus | undefined;
export declare function writeShipStatus(dataDir: string, status: ShipStatus): void;
/**
 * A shipper that has not touched its lock in this long is assumed dead (the
 * container was reclaimed, the laptop lid closed, SIGKILL). Deliberately
 * several heartbeats wide so a slow POST never looks like a corpse.
 */
export declare const SHIP_LOCK_STALE_MS: number;
export declare function shipLockPath(dataDir: string): string;
export interface ShipLock {
    /** Refresh the lock's mtime so peers can tell it from an abandoned one. */
    touch(): void;
    release(): void;
    readonly path: string;
}
/**
 * True when some other process looks like it is already shipping for this
 * data dir. Cheap (one statSync) because `record`/`hook`/`http` call it on
 * their way past, and `hook` is a fresh process per tool call.
 */
export declare function shipperLooksAlive(dataDir: string): boolean;
/**
 * Take the single-instance lock, reclaiming one that looks abandoned.
 * Returns undefined when another live shipper holds it — the caller then
 * simply exits, because one shipper per data dir is the whole rule.
 */
export declare function acquireShipLock(dataDir: string): ShipLock | undefined;
