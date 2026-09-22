/**
 * Policy evaluation: the local TypeScript twin of the emitted Rego.
 *
 * Rules are checked in order and the first match wins; when nothing matches
 * the section's default applies. Every predicate here has a line-for-line
 * counterpart in `rego.ts`, and the OPA comparison test proves they agree:
 *
 * - server / tool / host / path: `globMatch` with the section's delimiter,
 *   any entry of the list matching.
 * - args: each dot-path is resolved like `object.get(input.args, [...], null)`
 *   — the root must be a plain object (Rego's `object.get` is undefined for
 *   an array or scalar root), numeric segments address ARRAY INDEXES only,
 *   other segments address OBJECT KEYS only; a missing path, a null, or a
 *   non-scalar value means the rule does not match. Scalars are coerced with
 *   `String()` (Rego: `scalar_text`, i.e. `json.marshal` for non-strings,
 *   whose number formatting is the ES6 one `String()` also uses). A string
 *   longer than `REGEX_VALUE_CAP` UTF-16 units is NOT matched at all: it used
 *   to be truncated, which let `"x".repeat(5000) + "rm -rf /"` sail through a
 *   `cmd: "rm -rf /"` deny rule, so an over-long value is now unevaluable and
 *   denies (see {@link VALUE_TOO_LONG}).
 * - any_arg: one regex against every STRING LEAF of `input.args`, at any
 *   depth and under any key — `walk(input.args, [_, v]); is_string(v);
 *   regex.match(pat, v)` in the Rego twin, behind the same explicit
 *   `is_object(input.args)`. The leaves are collected once and matched in ONE
 *   bounded request, and a call whose arguments exceed the leaf/byte budget
 *   is UNEVALUABLE and denies rather than being scanned in part. OPA has no
 *   budget, so the two engines can differ only PAST it, in the safe
 *   direction (local deny, control-plane allow) — the same residual the
 *   `REGEX_VALUE_CAP` on `args` already has.
 * - max_args_bytes / max_body_bytes: `<=` on the caller-supplied byte count.
 *
 * Every `args` regex runs through `regex-guard.ts`, which matches it off the
 * main thread under a hard deadline: V8's RegExp is a backtracking engine and
 * RE2 is not, so a pattern that is linear under OPA can still hang the proxy
 * thread here. A match that overruns its deadline is UNEVALUABLE — the rule
 * neither matches nor is skipped, it denies — and the offending pattern is
 * poisoned for the rest of the process.
 *
 * `evaluateMcp` / `evaluateEgress` NEVER throw: any internal error becomes a
 * deny with `reason: "policy evaluation error: ..."` and `failClosed: true`
 * (enforcement is fail-closed, unlike recording). A timed-out args regex
 * lands there as `policy evaluation error: regex timed out (<rule id>)`.
 * `failClosed` is how a caller tells that deny apart from one a rule or a
 * section default actually decided, without parsing the reason string.
 */
import type { Action, AnyArgBudget, Policy } from './types.js';
export interface McpRequestInput {
    server: string;
    tool: string;
    args: unknown;
    /** Byte length of the canonical JSON of `args`. */
    argsBytes: number;
}
export interface EgressRequestInput {
    host: string;
    method: string;
    path: string;
    bodyBytes: number;
}
export interface Decision {
    action: Action;
    /** Absent when the default action applied. */
    ruleId?: string;
    ruleIndex?: number;
    reason?: string;
    /** True when a rule matched, false when the default applied. */
    matched: boolean;
    /**
     * Only ever set (to `true`) on the fail-closed deny below: the policy
     * could NOT be evaluated, so nothing was decided about this request. It is
     * the difference between "the operator said no" and "the gateway refused
     * rather than guess", which the proxy turns into the guidance an agent
     * reads on a refusal (`FAIL_CLOSED_REFUSAL_GUIDANCE`). Additive and
     * optional: a real allow/deny/hold decision simply omits it, so every
     * existing consumer, and the Rego twin (which has no counterpart — OPA
     * evaluates or it does not answer at all), is unaffected. This is an
     * internal TypeScript type, not the frozen `edut.mcp-recorder.event.v1`
     * schema; no event gains a field.
     */
    failClosed?: true;
    /**
     * A STABLE machine label for WHY the gateway could not decide, set only
     * beside `failClosed`. `reason` is free-form prose that names a rule id and
     * a byte count; `errorCode` is the thing a person, a refusal clause and
     * `mcp-recorder why` can all agree on.
     *
     * It exists because the three sides used to disagree: the model was told a
     * RULE had denied it, the proxy's own stderr said `rule default`, and the
     * recorded event carried neither — so `why` could explain nothing and the
     * refusal told the model to retry a call that is refused identically every
     * time. This is an internal TypeScript type; the event field it feeds
     * (`policy_decision.error_code`) is an additive optional one.
     */
    errorCode?: PolicyErrorCode;
}
/**
 * Why a fail-closed deny happened. Deliberately small and closed: each value
 * has a remedy a person can act on, and a refusal clause of its own.
 */
export type PolicyErrorCode = 'arguments-too-large-to-scan' | 'value-too-long' | 'regex-timed-out' | 'policy-unevaluable';
/** An internal evaluation failure that knows its own {@link PolicyErrorCode}. */
export declare class PolicyEvalError extends Error {
    readonly code: PolicyErrorCode;
    constructor(message: string, code: PolicyErrorCode);
}
export type McpDecision = Decision;
export type EgressDecision = Decision;
/** Split a dot-path into Rego-style segments: canonical integers become numbers. */
export declare function dotPathSegments(dotPath: string): Array<string | number>;
/**
 * Resolve a dot-path like `object.get(root, segments, undefined)`: numeric
 * segments index arrays only, string segments read own keys of plain
 * objects only. Returns undefined when the path does not exist.
 *
 * The ROOT must be a plain (non-array) object: an array `params.arguments`
 * (or a string, number, boolean or null) never matches any `args` condition.
 * `params.arguments` is an object per MCP, so this only bites on malformed
 * requests. The compiled Rego states the same rule as an explicit
 * `is_object(input.args)` line — it used to inherit it from `object.get`
 * erroring on a non-object root, which is undefined in Rego and so agreed
 * with this by silent failure rather than by saying anything.
 */
export declare function getPath(root: unknown, dotPath: string): unknown;
/**
 * A string argument too long to match against a backtracking regex.
 *
 * The cap bounds how much work one hostile argument can ask of V8, but
 * TRUNCATING to it silently changed the answer: `"x".repeat(5000) + "rm -rf
 * /"` did not match a `cmd: "rm -rf /"` deny rule, because the tail was cut
 * off before matching, and the call was forwarded. RE2 (the Rego side) does
 * not truncate and would have matched. Enforcement fails closed, so the local
 * engine now refuses to answer instead of answering differently: `argsMatch`
 * turns this into the same fail-closed deny a timed-out regex produces.
 */
export declare const VALUE_TOO_LONG: unique symbol;
/**
 * String form used for regex matching, {@link VALUE_TOO_LONG} when the value
 * is a string longer than `REGEX_VALUE_CAP`, or undefined when the value is
 * not a scalar at all.
 */
export declare function coerceScalar(value: unknown): string | typeof VALUE_TOO_LONG | undefined;
/**
 * Every string leaf of `root`, at any depth, in document order — the exact
 * set `walk(input.args, [_, v]); is_string(v)` yields in Rego, minus object
 * KEYS (a key is a path element there, never a value).
 *
 * Returns undefined when the root is not a plain object, which is
 * `is_object(input.args)`: a `params.arguments` that is an array, a scalar
 * or null matches no `any_arg` condition in either engine.
 *
 * Throws when the arguments exceed {@link ANY_ARG_MAX_LEAVES} or
 * {@link ANY_ARG_MAX_BYTES}. It stops at the budget rather than collecting
 * the rest, so a hostile payload cannot buy unbounded work by being refused
 * — but it never returns a PARTIAL set, because a partial scan is a deny
 * that silently became an allow. Traversal is iterative: a 10 000-deep
 * argument tree must not be a stack overflow on the proxy thread.
 */
export declare function collectStringLeaves(root: unknown, budget?: AnyArgBudget): string[] | undefined;
/**
 * Decide a `tools/call`. A policy without an `mcp` section yields the
 * documented default (`allow`, unmatched). Never throws.
 */
export declare function evaluateMcp(policy: Policy, input: McpRequestInput): McpDecision;
/**
 * Decide an HTTP egress request (not enforced by mcp-recorder; kept 1:1 with
 * the Rego so both can be tested). A policy without `egress` yields the
 * documented default (`deny`, unmatched). Never throws.
 */
export declare function evaluateEgress(policy: Policy, input: EgressRequestInput): EgressDecision;
/**
 * The rule id that produced a decision, or — for a fail-closed deny, where no
 * rule decided anything — the stable error code. It is the label the proxy's
 * own diagnostics print, and it must not read `default` for a refusal the
 * default did not make: that is the disagreement that left a person with a
 * client message naming one rule, a stderr line naming another and an event
 * naming neither.
 */
export declare function ruleLabel(decision: Decision): string;
