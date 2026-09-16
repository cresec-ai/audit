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
 *   whose number formatting is the ES6 one `String()` also uses), truncated
 *   to `REGEX_VALUE_CAP` UTF-16 units before matching (Rego does not
 *   truncate: RE2 is linear-time, so only values beyond the cap can ever
 *   differ, and that is documented).
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
import type { Action, Policy } from './types.js';
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
 * The ROOT must be a plain (non-array) object, exactly like Rego's
 * `object.get(input.args, ...)`, which is undefined for every non-object
 * root — an array `params.arguments` (or a string, number, boolean or null)
 * therefore never matches any `args` condition. `params.arguments` is an
 * object per MCP, so this only bites on malformed requests, and both engines
 * now agree that those never match.
 */
export declare function getPath(root: unknown, dotPath: string): unknown;
/** String form used for regex matching, or undefined when the value is not a scalar. */
export declare function coerceScalar(value: unknown): string | undefined;
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
/** The rule id that produced a decision, or "default". */
export declare function ruleLabel(decision: Decision): string;
