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
 * deny with `reason: "policy evaluation error: ..."` (enforcement is
 * fail-closed, unlike recording). A timed-out args regex lands there as
 * `policy evaluation error: regex timed out (<rule id>)`.
 */
import { globMatch } from './glob.js';
import { RegexGuardError, matchBounded } from './regex-guard.js';
import { DEFAULTS, REGEX_VALUE_CAP } from './types.js';
const ARRAY_INDEX = /^(0|[1-9][0-9]*)$/;
/** Split a dot-path into Rego-style segments: canonical integers become numbers. */
export function dotPathSegments(dotPath) {
    return dotPath.split('.').map((seg) => (ARRAY_INDEX.test(seg) ? Number(seg) : seg));
}
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
export function getPath(root, dotPath) {
    if (typeof root !== 'object' || root === null || Array.isArray(root))
        return undefined;
    let cur = root;
    for (const seg of dotPathSegments(dotPath)) {
        if (typeof seg === 'number') {
            if (!Array.isArray(cur) || seg >= cur.length)
                return undefined;
            cur = cur[seg];
        }
        else {
            if (typeof cur !== 'object' || cur === null || Array.isArray(cur))
                return undefined;
            if (!Object.prototype.hasOwnProperty.call(cur, seg))
                return undefined;
            cur = cur[seg];
        }
    }
    return cur;
}
/** String form used for regex matching, or undefined when the value is not a scalar. */
export function coerceScalar(value) {
    switch (typeof value) {
        case 'string':
            return value.length > REGEX_VALUE_CAP ? value.slice(0, REGEX_VALUE_CAP) : value;
        case 'number':
        case 'boolean':
            return String(value);
        default:
            return undefined;
    }
}
/**
 * All `args` conditions of one rule. Throws when a pattern is unevaluable
 * (deadline overrun, poisoned, or no guard worker for a pattern that is not
 * provably linear): the rule is then neither a match nor a miss, and the
 * caller's fail-closed path turns it into a deny naming `ruleId`.
 */
function argsMatch(args, input, ruleId) {
    for (const [dotPath, pattern] of Object.entries(args)) {
        const s = coerceScalar(getPath(input, dotPath));
        if (s === undefined)
            return false;
        let matched;
        try {
            matched = matchBounded(pattern, s);
        }
        catch (err) {
            if (err instanceof RegexGuardError)
                throw new Error(`${err.message} (${ruleId})`);
            throw err;
        }
        if (!matched)
            return false;
    }
    return true;
}
function mcpRuleMatches(rule, input) {
    const m = rule.match;
    if (!m.server.some((g) => globMatch(g, '/', input.server)))
        return false;
    if (!m.tool.some((g) => globMatch(g, '/', input.tool)))
        return false;
    if (m.args !== undefined && !argsMatch(m.args, input.args, rule.id))
        return false;
    if (m.max_args_bytes !== undefined && !(input.argsBytes <= m.max_args_bytes))
        return false;
    return true;
}
function egressRuleMatches(rule, input) {
    const m = rule.match;
    if (!m.host.some((g) => globMatch(g, '.', input.host)))
        return false;
    if (m.methods !== undefined && !m.methods.includes(input.method))
        return false;
    if (!m.path.some((g) => globMatch(g, '/', input.path)))
        return false;
    if (m.max_body_bytes !== undefined && !(input.bodyBytes <= m.max_body_bytes))
        return false;
    return true;
}
function decide(rules, defaultAction, matches) {
    for (let i = 0; i < rules.length; i++) {
        const rule = rules[i];
        if (matches(rule)) {
            const d = { action: rule.action, ruleId: rule.id, ruleIndex: i, matched: true };
            if (rule.reason !== undefined)
                d.reason = rule.reason;
            return d;
        }
    }
    return { action: defaultAction, matched: false };
}
function evaluationError(err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { action: 'deny', matched: false, reason: `policy evaluation error: ${msg}` };
}
/**
 * Decide a `tools/call`. A policy without an `mcp` section yields the
 * documented default (`allow`, unmatched). Never throws.
 */
export function evaluateMcp(policy, input) {
    try {
        const mcp = policy.mcp;
        if (mcp === undefined)
            return { action: DEFAULTS.mcp.default, matched: false };
        return decide(mcp.rules, mcp.default, (rule) => mcpRuleMatches(rule, input));
    }
    catch (err) {
        return evaluationError(err);
    }
}
/**
 * Decide an HTTP egress request (not enforced by mcp-recorder; kept 1:1 with
 * the Rego so both can be tested). A policy without `egress` yields the
 * documented default (`deny`, unmatched). Never throws.
 */
export function evaluateEgress(policy, input) {
    try {
        const egress = policy.egress;
        if (egress === undefined)
            return { action: DEFAULTS.egress.default, matched: false };
        return decide(egress.rules, egress.default, (rule) => egressRuleMatches(rule, input));
    }
    catch (err) {
        return evaluationError(err);
    }
}
/** The rule id that produced a decision, or "default". */
export function ruleLabel(decision) {
    return decision.ruleId ?? 'default';
}
//# sourceMappingURL=engine.js.map