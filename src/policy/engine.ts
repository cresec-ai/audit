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

import { globMatch } from './glob.js';
import { RegexGuardError, matchAnyBounded, matchBounded } from './regex-guard.js';
import type { Action, AnyArgBudget, EgressRule, McpRule, Policy } from './types.js';
import { ANY_ARG_MAX_BYTES, ANY_ARG_MAX_LEAVES, DEFAULTS, REGEX_VALUE_CAP } from './types.js';

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
export class PolicyEvalError extends Error {
  readonly code: PolicyErrorCode;
  constructor(message: string, code: PolicyErrorCode) {
    super(message);
    this.name = 'PolicyEvalError';
    this.code = code;
  }
}

export type McpDecision = Decision;
export type EgressDecision = Decision;

const ARRAY_INDEX = /^(0|[1-9][0-9]*)$/;

/** Split a dot-path into Rego-style segments: canonical integers become numbers. */
export function dotPathSegments(dotPath: string): Array<string | number> {
  return dotPath.split('.').map((seg) => (ARRAY_INDEX.test(seg) ? Number(seg) : seg));
}

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
export function getPath(root: unknown, dotPath: string): unknown {
  if (typeof root !== 'object' || root === null || Array.isArray(root)) return undefined;
  let cur: unknown = root;
  for (const seg of dotPathSegments(dotPath)) {
    if (typeof seg === 'number') {
      if (!Array.isArray(cur) || seg >= cur.length) return undefined;
      cur = cur[seg];
    } else {
      if (typeof cur !== 'object' || cur === null || Array.isArray(cur)) return undefined;
      if (!Object.prototype.hasOwnProperty.call(cur, seg)) return undefined;
      cur = (cur as Record<string, unknown>)[seg];
    }
  }
  return cur;
}

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
export const VALUE_TOO_LONG: unique symbol = Symbol('policy: args value exceeds REGEX_VALUE_CAP');

/**
 * String form used for regex matching, {@link VALUE_TOO_LONG} when the value
 * is a string longer than `REGEX_VALUE_CAP`, or undefined when the value is
 * not a scalar at all.
 */
export function coerceScalar(value: unknown): string | typeof VALUE_TOO_LONG | undefined {
  switch (typeof value) {
    case 'string':
      return value.length > REGEX_VALUE_CAP ? VALUE_TOO_LONG : value;
    case 'number':
    case 'boolean':
      return String(value);
    default:
      return undefined;
  }
}

/**
 * All `args` conditions of one rule. Throws when a condition is unevaluable
 * (deadline overrun, poisoned pattern, no guard worker for a pattern that is
 * not provably linear, or a value past `REGEX_VALUE_CAP`): the rule is then
 * neither a match nor a miss, and the caller's fail-closed path turns it into
 * a deny naming `ruleId`.
 */
function argsMatch(args: Record<string, string>, input: unknown, ruleId: string): boolean {
  for (const [dotPath, pattern] of Object.entries(args)) {
    const s = coerceScalar(getPath(input, dotPath));
    if (s === undefined) return false;
    if (s === VALUE_TOO_LONG) {
      throw new PolicyEvalError(
        `args value at ${JSON.stringify(dotPath)} is longer than the ${REGEX_VALUE_CAP}-character regex cap` +
          ` and cannot be matched safely (${ruleId})`,
        'value-too-long',
      );
    }
    let matched: boolean;
    try {
      matched = matchBounded(pattern, s);
    } catch (err) {
      if (err instanceof RegexGuardError) throw new PolicyEvalError(`${err.message} (${ruleId})`, 'regex-timed-out');
      throw err;
    }
    if (!matched) return false;
  }
  return true;
}

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
export function collectStringLeaves(root: unknown, budget?: AnyArgBudget): string[] | undefined {
  const maxLeaves = budget?.max_leaves ?? ANY_ARG_MAX_LEAVES;
  const maxBytes = budget?.max_bytes ?? ANY_ARG_MAX_BYTES;
  if (typeof root !== 'object' || root === null || Array.isArray(root)) return undefined;
  const leaves: string[] = [];
  let bytes = 0;
  const stack: unknown[] = [root];
  while (stack.length > 0) {
    const node = stack.pop();
    if (typeof node === 'string') {
      if (leaves.length >= maxLeaves) {
        throw new PolicyEvalError(
          `arguments too large to scan: more than ${maxLeaves} string values (raise mcp.any_arg.max_leaves, or split the call)`,
          'arguments-too-large-to-scan',
        );
      }
      bytes += Buffer.byteLength(node, 'utf8');
      if (bytes > maxBytes) {
        throw new PolicyEvalError(
          `arguments too large to scan: more than ${maxBytes} bytes of string values (raise mcp.any_arg.max_bytes, or split the call)`,
          'arguments-too-large-to-scan',
        );
      }
      leaves.push(node);
      continue;
    }
    if (Array.isArray(node)) {
      for (let i = node.length - 1; i >= 0; i--) stack.push(node[i]);
      continue;
    }
    if (typeof node === 'object' && node !== null) {
      const entries = Object.keys(node as Record<string, unknown>);
      for (let i = entries.length - 1; i >= 0; i--) stack.push((node as Record<string, unknown>)[entries[i] as string]);
    }
    // numbers, booleans, null, undefined: not strings, so `is_string(v)` is
    // false for them in Rego too. Nothing to do.
  }
  return leaves;
}

/**
 * `match.any_arg` for one rule. Throws when the arguments are past the scan
 * budget or the regex is unevaluable — the caller's fail-closed path turns
 * either into a deny naming `ruleId`, never a miss.
 */
function anyArgMatches(pattern: string, input: unknown, ruleId: string, budget: AnyArgBudget): boolean {
  let leaves: string[] | undefined;
  try {
    leaves = collectStringLeaves(input, budget);
  } catch (err) {
    if (err instanceof PolicyEvalError) throw new PolicyEvalError(`${err.message} (${ruleId})`, err.code);
    throw new PolicyEvalError(`${err instanceof Error ? err.message : String(err)} (${ruleId})`, 'policy-unevaluable');
  }
  if (leaves === undefined) return false;
  try {
    return matchAnyBounded(pattern, leaves);
  } catch (err) {
    if (err instanceof RegexGuardError) throw new PolicyEvalError(`${err.message} (${ruleId})`, 'regex-timed-out');
    throw err;
  }
}

function mcpRuleMatches(rule: McpRule, input: McpRequestInput, budget: AnyArgBudget): boolean {
  const m = rule.match;
  if (!m.server.some((g) => globMatch(g, '/', input.server))) return false;
  if (!m.tool.some((g) => globMatch(g, '/', input.tool))) return false;
  if (m.args !== undefined && !argsMatch(m.args, input.args, rule.id)) return false;
  if (m.any_arg !== undefined && !anyArgMatches(m.any_arg, input.args, rule.id, budget)) return false;
  if (m.max_args_bytes !== undefined && !(input.argsBytes <= m.max_args_bytes)) return false;
  return true;
}

function egressRuleMatches(rule: EgressRule, input: EgressRequestInput): boolean {
  const m = rule.match;
  if (!m.host.some((g) => globMatch(g, '.', input.host))) return false;
  if (m.methods !== undefined && !m.methods.includes(input.method)) return false;
  if (!m.path.some((g) => globMatch(g, '/', input.path))) return false;
  if (m.max_body_bytes !== undefined && !(input.bodyBytes <= m.max_body_bytes)) return false;
  return true;
}

function decide<R extends { id: string; action: Action; reason?: string }>(
  rules: readonly R[],
  defaultAction: Action,
  matches: (rule: R) => boolean,
): Decision {
  for (let i = 0; i < rules.length; i++) {
    const rule = rules[i] as R;
    if (matches(rule)) {
      const d: Decision = { action: rule.action, ruleId: rule.id, ruleIndex: i, matched: true };
      if (rule.reason !== undefined) d.reason = rule.reason;
      return d;
    }
  }
  return { action: defaultAction, matched: false };
}

function evaluationError(err: unknown): Decision {
  const msg = err instanceof Error ? err.message : String(err);
  const code: PolicyErrorCode = err instanceof PolicyEvalError ? err.code : 'policy-unevaluable';
  return { action: 'deny', matched: false, reason: `policy evaluation error: ${msg}`, failClosed: true, errorCode: code };
}

/**
 * Decide a `tools/call`. A policy without an `mcp` section yields the
 * documented default (`allow`, unmatched). Never throws.
 */
export function evaluateMcp(policy: Policy, input: McpRequestInput): McpDecision {
  try {
    const mcp = policy.mcp;
    if (mcp === undefined) return { action: DEFAULTS.mcp.default, matched: false };
    // `any_arg` is absent on a policy object built before the budget was
    // settable (normalizePolicy always fills it); the defaults stand in.
    const budget: AnyArgBudget = mcp.any_arg ?? { max_leaves: ANY_ARG_MAX_LEAVES, max_bytes: ANY_ARG_MAX_BYTES };
    return decide(mcp.rules, mcp.default, (rule) => mcpRuleMatches(rule, input, budget));
  } catch (err) {
    return evaluationError(err);
  }
}

/**
 * Decide an HTTP egress request (not enforced by mcp-recorder; kept 1:1 with
 * the Rego so both can be tested). A policy without `egress` yields the
 * documented default (`deny`, unmatched). Never throws.
 */
export function evaluateEgress(policy: Policy, input: EgressRequestInput): EgressDecision {
  try {
    const egress = policy.egress;
    if (egress === undefined) return { action: DEFAULTS.egress.default, matched: false };
    return decide(egress.rules, egress.default, (rule) => egressRuleMatches(rule, input));
  } catch (err) {
    return evaluationError(err);
  }
}

/**
 * The rule id that produced a decision, or — for a fail-closed deny, where no
 * rule decided anything — the stable error code. It is the label the proxy's
 * own diagnostics print, and it must not read `default` for a refusal the
 * default did not make: that is the disagreement that left a person with a
 * client message naming one rule, a stderr line naming another and an event
 * naming neither.
 */
export function ruleLabel(decision: Decision): string {
  return decision.ruleId ?? decision.errorCode ?? 'default';
}
