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

export function reconcileEvents(events: Iterable<AnyEvent>): Reconciliation {
  const allowed = new Map<string, ActionLifecycleEvent>();
  const outcomes = new Map<string, ActionLifecycleEvent>();
  const ids = new Set<string>();
  const gaps: CoverageGapEvent[] = [];
  let legacy = 0;
  for (const e of events) {
    ids.add(e.event_id);
    if (e.kind === 'coverage_gap') gaps.push(e);
    if ((e.kind === 'policy_decision' || (e.kind === 'tool_call' && e.gateway !== undefined)) && e.action_id === undefined) legacy++;
    if (e.kind !== 'action_lifecycle') continue;
    const key = JSON.stringify([e.action_id, e.attempt_id]);
    if (e.phase === 'decision' && e.decision === 'allow') allowed.set(key, e);
    if (e.phase === 'outcome') outcomes.set(key, e);
  }
  return {
    scope: 'locally_recorded_decisions', allowed: allowed.size,
    missing_outcomes: [...allowed].filter(([key]) => !outcomes.has(key)).map(([, e]) => e),
    unknown_outcomes: [...outcomes.values()].filter((e) => e.outcome === 'unknown'),
    missing_companion_records: [...outcomes.values()].filter((e) => e.record_event_id !== undefined && !ids.has(e.record_event_id)),
    gaps, legacy_decisions_without_ids: legacy,
  };
}

export function reconcileStore(store: EvidenceStore): Reconciliation {
  return reconcileEvents([...store.iterate()].map((r) => r.event));
}
