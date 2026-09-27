/** Lifecycle construction has no I/O and never waits for evidence delivery. */
import { createHash, randomUUID } from 'node:crypto';
import type { ActionLifecycleEvent, AnyEvent, EventBase, ToolCallEvent } from '../schema/events.js';

/** Canonical hash without recursive JS calls or depth truncation. Same JSON rules
 * as chain canonicalJson; kept separate so the frozen chain primitive is unchanged. */
export function requestHash(value: unknown): string {
  const hash = createHash('sha256');
  const stack: Array<{ value: unknown } | { text: string }> = [{ value }];
  while (stack.length) {
    const item = stack.pop()!;
    if ('text' in item) { hash.update(item.text); continue; }
    const v = item.value;
    if (v === null || v === undefined) { hash.update('null'); continue; }
    if (typeof v !== 'object') { hash.update(JSON.stringify(v) ?? 'null'); continue; }
    const array = Array.isArray(v);
    const obj = v as Record<string, unknown>;
    const keys = array ? Array.from({ length: v.length }, (_, i) => String(i))
      : Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
    hash.update(array ? '[' : '{');
    stack.push({ text: array ? ']' : '}' });
    for (let i = keys.length - 1; i >= 0; i--) {
      const key = keys[i]!;
      stack.push({ value: obj[key] });
      if (!array) stack.push({ text: JSON.stringify(key) + ':' });
      if (i > 0) stack.push({ text: ',' });
    }
  }
  return 'sha256:' + hash.digest('hex');
}

export interface Lifecycle {
  intent: ActionLifecycleEvent;
  decided: boolean;
}

type Emit = (event: AnyEvent) => void;
export function beginAction(
  base: EventBase, tool: string, request: unknown, emit: Emit,
  ids: { action_id: string; attempt_id: string } = { action_id: randomUUID(), attempt_id: randomUUID() },
  requestId?: string | number,
): Lifecycle {
  const intent: ActionLifecycleEvent = {
    ...base, ...ids, kind: 'action_lifecycle', phase: 'intent', tool,
    request_hash: requestHash(request),
    ...(requestId === undefined ? {} : { request_id: requestId }),
  };
  emit(intent);
  return { intent, decided: false };
}

export function correlate(event: EventBase, lifecycle: Lifecycle | undefined): void {
  if (!lifecycle) return;
  event.action_id = lifecycle.intent.action_id;
  event.attempt_id = lifecycle.intent.attempt_id;
  event.request_hash = lifecycle.intent.request_hash!;
}

export function decideAction(lifecycle: Lifecycle, decision: 'allow' | 'deny', emit: Emit,
  policyHash?: string, decisionId?: string): void {
  if (lifecycle.decided) return;
  lifecycle.decided = true;
  emit({ ...lifecycle.intent, event_id: randomUUID(), timestamp: new Date().toISOString(),
    phase: 'decision', decision, decision_id: decisionId ?? randomUUID(),
    ...(policyHash === undefined ? {} : { policy_hash: policyHash }) });
}

export function endAction(lifecycle: Lifecycle | undefined, event: EventBase,
  outcome: NonNullable<ActionLifecycleEvent['outcome']>, emit: Emit, reason?: string): void {
  if (!lifecycle) return;
  correlate(event, lifecycle);
  emit({ ...lifecycle.intent, event_id: randomUUID(), timestamp: event.timestamp,
    phase: 'outcome', outcome, record_event_id: event.event_id,
    ...(reason === undefined ? {} : { reason }) });
}

/** An observed error is not success. Loss of a response says nothing about
 * upstream side effects; never infer failure/success or resend the call. */
export function toolOutcome(event: ToolCallEvent): NonNullable<ActionLifecycleEvent['outcome']> {
  if (event.gateway?.decision === 'deny' || event.error?.type === 'policy_denied') return 'denied';
  if (event.error?.code === -32001) return 'unknown';
  if (['unanswered', 'interrupted', 'pending_evicted', 'duplicate_id'].includes(event.error?.type ?? '')) return 'unknown';
  return event.is_error ? 'error' : 'success';
}
