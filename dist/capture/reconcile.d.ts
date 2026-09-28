/** Read-only coverage accounting. Integrity verification is a separate operation. */
import type { ActionLifecycleEvent, AnyEvent, CoverageGapEvent } from '../schema/events.js';
import type { EvidenceStore } from '../types.js';
export interface Reconciliation {
    scope: 'locally_recorded_decisions';
    allowed: number;
    missing_outcomes: ActionLifecycleEvent[];
    unknown_outcomes: ActionLifecycleEvent[];
    missing_companion_records: ActionLifecycleEvent[];
    gaps: CoverageGapEvent[];
    legacy_decisions_without_ids: number;
}
export declare function reconcileEvents(events: Iterable<AnyEvent>): Reconciliation;
export declare function reconcileStore(store: EvidenceStore): Reconciliation;
