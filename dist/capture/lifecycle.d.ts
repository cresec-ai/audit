import type { ActionLifecycleEvent, AnyEvent, EventBase, ToolCallEvent } from '../schema/events.js';
/** Canonical hash without recursive JS calls or depth truncation. Same JSON rules
 * as chain canonicalJson; kept separate so the frozen chain primitive is unchanged. */
export declare function requestHash(value: unknown): string;
export interface Lifecycle {
    intent: ActionLifecycleEvent;
    decided: boolean;
}
type Emit = (event: AnyEvent) => void;
export declare function beginAction(base: EventBase, tool: string, request: unknown, emit: Emit, ids?: {
    action_id: string;
    attempt_id: string;
}, requestId?: string | number): Lifecycle;
export declare function correlate(event: EventBase, lifecycle: Lifecycle | undefined): void;
export declare function decideAction(lifecycle: Lifecycle, decision: 'allow' | 'deny', emit: Emit, policyHash?: string, decisionId?: string): void;
export declare function endAction(lifecycle: Lifecycle | undefined, event: EventBase, outcome: NonNullable<ActionLifecycleEvent['outcome']>, emit: Emit, reason?: string): void;
/** An observed error is not success. Loss of a response says nothing about
 * upstream side effects; never infer failure/success or resend the call. */
export declare function toolOutcome(event: ToolCallEvent): NonNullable<ActionLifecycleEvent['outcome']>;
export {};
