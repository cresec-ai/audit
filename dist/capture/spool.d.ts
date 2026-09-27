import { type AnyEvent, type CoverageGapEvent, type EventBase } from '../schema/events.js';
import type { EvidenceStore, SignerLike } from '../types.js';
import { type Reconciliation } from './reconcile.js';
export declare const SPOOL_MAX_BYTES: number;
export declare function coverageGap(base: EventBase, reason: CoverageGapEvent['reason'], count: number): CoverageGapEvent;
export interface DeliveryResult {
    written: number;
    dropped: number;
    pending: boolean;
}
export declare class DurableDelivery {
    private readonly opts;
    readonly runId: `${string}-${string}-${string}-${string}-${string}`;
    readonly directory: string;
    private readonly journal;
    private readonly locks;
    private readonly runs;
    private readonly leasePath;
    private store;
    private signer;
    private ready;
    private acknowledged;
    private endedHook;
    private tail;
    private warned;
    private lostGap;
    constructor(opts: {
        dataDir: string;
        openStore: () => EvidenceStore;
        store?: EvidenceStore | null;
        signer?: SignerLike | null;
        maxBytes?: number;
        warn?: (message: string) => void;
    });
    private warn;
    private initialize;
    /** Filesystem bakery lock: publish choosing before reading the largest
     * ticket, then wait for lower tickets and unfinished choices. Immutable,
     * uniquely named tickets avoid stale-lock deletion racing a new owner.
     * Fully written files are published atomically (hardlink/rename); a kill
     * cannot leave an ownerless lock. Dead owners are ignored and cleaned up.
     * Requires a local filesystem with coherent directory reads (NTFS/POSIX).
     */
    private withLock;
    private serial;
    /** Persist before attempting the store: even a kill inside a partial append
     * can be retried safely. This is off the forwarding path, not durable intent
     * before execution. Each frame is independently parseable on recovery. */
    private append;
    private repairTail;
    private replay;
    private fallbackBase;
    private acknowledge;
    deliver(events: AnyEvent[]): Promise<DeliveryResult>;
    start(includeEndedHooks?: boolean): Promise<void>;
    /** Recover only known-dead process incarnations, or explicitly ended hook
     * sessions. PID reuse/permission errors are conservatively left unresolved.
     * Deterministic recovery IDs and timestamps make a kill during recovery safe. */
    recover(includeEndedHooks?: boolean): Promise<void>;
    sweep(): Promise<Reconciliation | undefined>;
    close(): Promise<void>;
}
/** Read-only snapshot, including durable evidence not yet in the chain. Active
 * runs may append after this snapshot; zero findings is not global completeness. */
export declare function inspectDelivery(dataDir: string): Promise<{
    events: AnyEvent[];
    pending_events: number;
    active_runs: number;
    abandoned_runs: number;
    errors: string[];
}>;
