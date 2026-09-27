export function reconcileEvents(events) {
    const allowed = new Map();
    const outcomes = new Map();
    const ids = new Set();
    const gaps = [];
    let legacy = 0;
    for (const e of events) {
        ids.add(e.event_id);
        if (e.kind === 'coverage_gap')
            gaps.push(e);
        if ((e.kind === 'policy_decision' || (e.kind === 'tool_call' && e.gateway !== undefined)) && e.action_id === undefined)
            legacy++;
        if (e.kind !== 'action_lifecycle')
            continue;
        const key = JSON.stringify([e.action_id, e.attempt_id]);
        if (e.phase === 'decision' && e.decision === 'allow')
            allowed.set(key, e);
        if (e.phase === 'outcome')
            outcomes.set(key, e);
    }
    return {
        scope: 'locally_recorded_decisions', allowed: allowed.size,
        missing_outcomes: [...allowed].filter(([key]) => !outcomes.has(key)).map(([, e]) => e),
        unknown_outcomes: [...outcomes.values()].filter((e) => e.outcome === 'unknown'),
        missing_companion_records: [...outcomes.values()].filter((e) => e.record_event_id !== undefined && !ids.has(e.record_event_id)),
        gaps, legacy_decisions_without_ids: legacy,
    };
}
export function reconcileStore(store) {
    return reconcileEvents([...store.iterate()].map((r) => r.event));
}
//# sourceMappingURL=reconcile.js.map