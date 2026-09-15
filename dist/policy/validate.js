/**
 * policy.yaml v1 validation: JSON Schema first, then the semantic checks the
 * schema cannot express, then normalization.
 *
 * Schema validation (`schema.ts` via `jsonschema.ts`) covers shapes, enums,
 * identifier patterns, numeric ranges (hold timeout, boundary scan size),
 * upper-case methods, non-empty glob strings/lists and the "at least one of
 * mcp / egress" rule (a root `anyOf`, whose error is reworded here).
 *
 * Semantic checks add what JSON Schema (in our keyword subset) cannot say:
 * - duplicate rule ids within a section;
 * - `args` values are strings, keys are well-formed dot-paths;
 * - regexes compile in JS AND stay inside the RE2-portable subset (no
 *   lookaround, no backreferences, no inline flag / modifier groups, no
 *   RE2-only or JS-only escapes) so the local engine and OPA agree on every
 *   input, whatever the running Node version's V8 happens to accept;
 * - globs are not blank and do not use `[ ] { } \`, which OPA's glob library
 *   interprets and ours does not.
 *
 * Every error keeps an RFC 6901 pointer (`/mcp/rules/1/match/tool`).
 */
import { escapePointerToken, validateAgainstSchema } from './jsonschema.js';
import { POLICY_SCHEMA } from './schema.js';
import { normalizePolicy } from './types.js';
/** Characters with glob meaning in OPA (`glob.match`) but not in policy v1. */
const GLOB_RESERVED = /[[\]{}\\]/;
/**
 * Why `glob` is not acceptable, or undefined when it is. Blank globs can
 * never match anything useful and the reserved characters would make the TS
 * engine and the emitted Rego disagree.
 */
export function checkGlob(glob) {
    if (glob.trim().length === 0)
        return 'glob must not be empty or blank';
    const m = GLOB_RESERVED.exec(glob);
    if (m !== null) {
        return `glob must not contain ${JSON.stringify(m[0])} (reserved: [ ] { } \\ have no meaning in policy v1)`;
    }
    return undefined;
}
/** Escapes that mean something in RE2 but not in JavaScript (or vice versa). */
const NON_PORTABLE_ESCAPES = new Set(['A', 'z', 'Z', 'p', 'P', 'Q', 'E', 'C', 'G', 'u', 'U', 'c']);
/**
 * Why `pattern` is outside the RE2-portable subset (or fails to compile), or
 * undefined when it is acceptable. Rejected: lookaround `(?=` `(?!` `(?<=`
 * `(?<!`, every other `(?` group that is not a plain non-capturing `(?:`
 * or a named group `(?<name>` — inline flags `(?i)` `(?s)` `(?m)` `(?U)`,
 * modifier groups `(?i:...)` `(?-i:...)`, `(?P<name>`, comments `(?#` —
 * backreferences `\1`..`\9`, escapes that only one engine knows
 * (`\A \z \Z \p \P \Q \E \C \G \u \U \c`), `\x{...}` and POSIX classes
 * `[:alpha:]`.
 *
 * The `(?` check is explicit and runs BEFORE `new RegExp`: RE2 accepts inline
 * flags, Node 20's V8 rejects them all, and Node 24's V8 accepts the
 * `(?i:...)` modifier form — the policy must mean the same thing everywhere,
 * so none of them is allowed regardless of what the local engine says.
 */
export function checkRe2Subset(pattern) {
    let inClass = false;
    for (let i = 0; i < pattern.length; i++) {
        const ch = pattern[i];
        if (ch === '\\') {
            const next = pattern[i + 1];
            if (next === undefined)
                return 'pattern ends with a dangling backslash';
            if (next >= '1' && next <= '9')
                return `backreference "\\${next}" is not supported (RE2 subset)`;
            if (NON_PORTABLE_ESCAPES.has(next)) {
                return `escape "\\${next}" is not portable between JavaScript and RE2`;
            }
            if (next === 'x' && pattern[i + 2] === '{')
                return 'escape "\\x{...}" is not supported; use "\\xhh"';
            i++;
            continue;
        }
        if (inClass) {
            if (ch === '[' && pattern[i + 1] === ':')
                return 'POSIX character classes like [:alpha:] are not supported';
            if (ch === ']')
                inClass = false;
            continue;
        }
        if (ch === '[') {
            inClass = true;
            // A leading "]" (or "^]") is literal in RE2; JS treats "[]" as empty. Skip it consistently.
            if (pattern[i + 1] === '^' && pattern[i + 2] === ']')
                i += 2;
            else if (pattern[i + 1] === ']')
                i += 1;
            continue;
        }
        if (ch === '(' && pattern[i + 1] === '?') {
            const why = checkGroupPrefix(pattern, i + 2);
            if (why !== undefined)
                return why;
        }
    }
    try {
        new RegExp(pattern);
    }
    catch (err) {
        return `invalid regular expression: ${err instanceof Error ? err.message : String(err)}`;
    }
    return undefined;
}
/**
 * Why the `(?` group whose body starts at `at` is not acceptable, or
 * undefined for `(?:` and `(?<name>`. Named groups are spelled the same in
 * JavaScript and RE2 (Go regexp since 1.22), so they stay allowed; anything
 * else after `(?` is either lookaround or an inline flag / modifier group.
 */
function checkGroupPrefix(pattern, at) {
    const head = pattern.slice(at, at + 2);
    const first = head[0];
    if (first === ':')
        return undefined;
    if (first === '=' || first === '!')
        return `lookahead "(?${first}" is not supported (RE2 subset)`;
    if (head === '<=' || head === '<!')
        return `lookbehind "(?${head}" is not supported (RE2 subset)`;
    if (first === '<')
        return undefined; // (?<name>...): validated by new RegExp below
    const shown = first === undefined ? '(?' : `(?${first}`;
    return `group "${shown}" is not supported (RE2 subset): only "(?:" non-capturing groups are allowed (no inline flags or modifier groups such as (?i), (?s), (?m), (?U), (?i:...), (?-i:...))`;
}
/** `a.b.0.c`: non-empty segments separated by single dots. */
const DOT_PATH = /^[^.]+(\.[^.]+)*$/;
function checkGlobField(value, path, errors) {
    if (typeof value === 'string') {
        const why = checkGlob(value);
        if (why !== undefined)
            errors.push({ path, message: why, keyword: 'glob' });
        return;
    }
    value.forEach((g, i) => {
        const why = checkGlob(g);
        if (why !== undefined)
            errors.push({ path: `${path}/${i}`, message: why, keyword: 'glob' });
    });
}
function checkDuplicateIds(rules, section, errors) {
    const seen = new Map();
    rules.forEach((rule, i) => {
        if (rule.id === undefined)
            return;
        const first = seen.get(rule.id);
        if (first !== undefined) {
            errors.push({
                path: `/${section}/rules/${i}/id`,
                message: `duplicate rule id ${JSON.stringify(rule.id)} (already used by rule ${first})`,
                keyword: 'duplicateId',
            });
        }
        else {
            seen.set(rule.id, i);
        }
    });
}
function checkMcpRule(rule, i, errors) {
    const base = `/mcp/rules/${i}/match`;
    if (rule.match.server !== undefined)
        checkGlobField(rule.match.server, `${base}/server`, errors);
    checkGlobField(rule.match.tool, `${base}/tool`, errors);
    if (rule.match.args === undefined)
        return;
    for (const [key, pattern] of Object.entries(rule.match.args)) {
        const path = `${base}/args/${escapePointerToken(key)}`;
        if (!DOT_PATH.test(key)) {
            errors.push({ path, message: `invalid dot-path ${JSON.stringify(key)} (expected e.g. "a.b.0.c")`, keyword: 'dotPath' });
        }
        if (typeof pattern !== 'string') {
            errors.push({ path, message: `expected a regex string, got ${Array.isArray(pattern) ? 'array' : typeof pattern}`, keyword: 'type' });
            continue;
        }
        const why = checkRe2Subset(pattern);
        if (why !== undefined)
            errors.push({ path, message: why, keyword: 'regex' });
    }
}
function checkEgressRule(rule, i, errors) {
    const base = `/egress/rules/${i}/match`;
    checkGlobField(rule.match.host, `${base}/host`, errors);
    if (rule.match.path !== undefined)
        checkGlobField(rule.match.path, `${base}/path`, errors);
}
function semanticErrors(raw) {
    const errors = [];
    if (raw.mcp?.rules !== undefined) {
        checkDuplicateIds(raw.mcp.rules, 'mcp', errors);
        raw.mcp.rules.forEach((rule, i) => checkMcpRule(rule, i, errors));
    }
    if (raw.egress?.rules !== undefined) {
        checkDuplicateIds(raw.egress.rules, 'egress', errors);
        raw.egress.rules.forEach((rule, i) => checkEgressRule(rule, i, errors));
    }
    return errors;
}
/** Reword the root `anyOf` (which encodes "mcp or egress") into plain language. */
function friendly(err) {
    if (err.path === '' && err.keyword === 'anyOf') {
        return { ...err, message: 'at least one of "mcp" or "egress" is required' };
    }
    return err;
}
/**
 * Validate a parsed policy document. On success the returned policy is
 * normalized (defaults filled, globs as lists, every rule with an id).
 */
export function validatePolicyObject(raw) {
    const schemaErrors = validateAgainstSchema(POLICY_SCHEMA, raw).map(friendly);
    if (schemaErrors.length > 0)
        return { ok: false, errors: schemaErrors };
    const input = raw;
    const errors = semanticErrors(input);
    if (errors.length > 0)
        return { ok: false, errors };
    return { ok: true, policy: normalizePolicy(input) };
}
/** One line per error, e.g. `/mcp/rules/1/match/tool: glob must not be empty or blank`. */
export function formatPolicyErrors(errors) {
    return errors.map((e) => `${e.path === '' ? '/' : e.path}: ${e.message}`).join('\n');
}
//# sourceMappingURL=validate.js.map