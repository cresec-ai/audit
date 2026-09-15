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
 *   lookaround, no backreferences, no inline flag / modifier groups, only
 *   whitelisted escapes, no leading `]` in a character class) so the local
 *   engine and OPA agree on every input, whatever the running Node version's
 *   V8 happens to accept;
 * - regexes avoid the repeated-group shapes that are linear under RE2 but
 *   EXPONENTIAL under V8's backtracking engine (`redos.ts`): the compiled
 *   Rego would shrug them off, the local engine on the proxy thread would
 *   not;
 * - globs are not blank and use neither `[ ] { } \`, which OPA's glob library
 *   interprets and ours does not, nor `?`, which both interpret but not the
 *   same way (OPA's `?` is ASCII-only).
 *
 * Every error keeps an RFC 6901 pointer (`/mcp/rules/1/match/tool`).
 */

import { escapePointerToken, validateAgainstSchema } from './jsonschema.js';
import type { SchemaError } from './jsonschema.js';
import { checkCatastrophicShape } from './redos.js';
import { POLICY_SCHEMA } from './schema.js';
import { normalizePolicy } from './types.js';
import type { EgressRuleInput, GlobOrList, McpRuleInput, Policy, PolicyInput } from './types.js';

export type PolicyError = SchemaError;

export type ValidationResult = { ok: true; policy: Policy } | { ok: false; errors: PolicyError[] };

/** Characters with glob meaning in OPA (`glob.match`) but not in policy v1. */
const GLOB_RESERVED = /[[\]{}\\]/;

/**
 * Why `glob` is not acceptable, or undefined when it is. Blank globs can
 * never match anything useful and the reserved characters would make the TS
 * engine and the emitted Rego disagree.
 *
 * `?` is rejected for the same reason: OPA's glob library matches `?`
 * against exactly one ASCII character, while the TS engine (a RegExp over
 * UTF-16) matches any non-delimiter character — `a?b` accepts "aéb" locally
 * and rejects it in OPA. `*` / `**` have no such split, so v1 ships without
 * `?` rather than with two meanings for it.
 */
export function checkGlob(glob: string): string | undefined {
  if (glob.trim().length === 0) return 'glob must not be empty or blank';
  const m = GLOB_RESERVED.exec(glob);
  if (m !== null) {
    return `glob must not contain ${JSON.stringify(m[0])} (reserved: [ ] { } \\ have no meaning in policy v1)`;
  }
  if (glob.includes('?')) {
    return (
      'the ? wildcard is not supported in policy.yaml v1 (use * or **): ' +
      "OPA's glob matches it against one ASCII character only, so it would not mean the same thing in the compiled Rego"
    );
  }
  return undefined;
}

/**
 * The ONLY backslash-letter/digit escapes allowed: each means exactly the
 * same thing in V8 without the `u` flag and in RE2. Everything else is
 * rejected, including escapes both engines know but read differently
 * (`\s`, `\0`, `\x{...}`) and escapes only one of them knows
 * (`\A \z \Z \p \P \Q \E \C \G \u \U \c \a \e \h \k`). Any escaped
 * NON-alphanumeric character (`\.` `\\` `\-` `\]` ...) is a literal in both
 * and stays allowed; `\xhh` (exactly two hex digits) is handled separately.
 */
const PORTABLE_LETTER_ESCAPES: ReadonlySet<string> = new Set(['d', 'D', 'w', 'W', 'b', 'B', 'n', 'r', 't', 'f', 'v']);

/** The escape whitelist, for error messages. */
const ALLOWED_ESCAPES = '\\d \\D \\w \\W \\b \\B \\n \\r \\t \\f \\v \\xhh and any escaped punctuation';

const HEX_DIGIT = /^[0-9A-Fa-f]$/;
const ALPHANUMERIC = /^[0-9A-Za-z]$/;

/**
 * Why the escape starting at `pattern[i]` (a backslash) is not acceptable, or
 * undefined when it is. `inClass` is true inside a `[...]` character class,
 * where `\b` / `\B` are a JavaScript-only spelling (backspace / literal "B")
 * that RE2 rejects outright.
 */
function checkEscape(pattern: string, i: number, inClass: boolean): string | undefined {
  const next = pattern[i + 1];
  if (next === undefined) return 'pattern ends with a dangling backslash';
  if (next >= '1' && next <= '9') return `backreference "\\${next}" is not supported (RE2 subset)`;
  if (next === 'k') return 'named backreference "\\k<name>" is not supported (RE2 subset)';
  if (next === 'x') {
    if (pattern[i + 2] === '{') return 'escape "\\x{...}" is not supported; use "\\xhh"';
    if (!HEX_DIGIT.test(pattern[i + 2] ?? '') || !HEX_DIGIT.test(pattern[i + 3] ?? '')) {
      return 'escape "\\x" must be followed by exactly two hex digits (e.g. "\\x41")';
    }
    return undefined;
  }
  if (next === 's' || next === 'S') {
    return (
      `escape "\\${next}" is not portable between JavaScript and RE2 ` +
      "(RE2's \\s is ASCII-only, JavaScript's also matches Unicode spaces); use \"[ \\t\\r\\n\\f]\""
    );
  }
  if ((next === 'b' || next === 'B') && inClass) {
    return `escape "\\${next}" inside a character class is not supported: RE2 rejects it and JavaScript reads it as ${
      next === 'b' ? 'a backspace' : 'a literal "B"'
    }`;
  }
  if (PORTABLE_LETTER_ESCAPES.has(next)) return undefined;
  // RE2 reads `\<ASCII punctuation>` as that literal character and rejects
  // everything else; V8 quietly turns any unknown escape into the literal.
  if (ALPHANUMERIC.test(next) || next.charCodeAt(0) > 0x7f) {
    return `escape "\\${next}" is not portable between JavaScript and RE2 (allowed: ${ALLOWED_ESCAPES})`;
  }
  return undefined; // escaped ASCII punctuation: a literal in both engines
}

/**
 * Why `pattern` is outside the RE2-portable subset (or fails to compile), or
 * undefined when it is acceptable. Rejected: lookaround `(?=` `(?!` `(?<=`
 * `(?<!`, every other `(?` group that is not a plain non-capturing `(?:`
 * or a named group `(?<name>` — inline flags `(?i)` `(?s)` `(?m)` `(?U)`,
 * modifier groups `(?i:...)` `(?-i:...)`, `(?P<name>`, comments `(?#` —
 * backreferences `\1`..`\9` and `\k<name>`, every backslash-letter/digit
 * escape outside `PORTABLE_LETTER_ESCAPES` + `\xhh`, a leading `]` in a
 * character class, and POSIX classes `[:alpha:]`.
 *
 * Last, a pattern that compiles and is portable is still rejected when it has
 * a clearly exponential shape — a repeated group whose body alternates
 * (`(a|aa)+`), ends with a quantified atom (`(a+)+`, `(\w+[ ]?)*`) or ends
 * with characters the repeated part can also match (`(.*a)*`). See
 * `redos.ts`; `([a-z0-9-]+\.)*` and friends stay allowed.
 *
 * The `(?` check is explicit and runs BEFORE `new RegExp`: RE2 accepts inline
 * flags, Node 20's V8 rejects them all, and Node 24's V8 accepts the
 * `(?i:...)` modifier form — the policy must mean the same thing everywhere,
 * so none of them is allowed regardless of what the local engine says. The
 * escape whitelist is explicit for the same reason: V8 silently turns an
 * unknown escape into the literal character (`\e` is "e"), where RE2 either
 * rejects it or gives it a meaning of its own.
 */
export function checkRe2Subset(pattern: string): string | undefined {
  let inClass = false;
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === '\\') {
      const why = checkEscape(pattern, i, inClass);
      if (why !== undefined) return why;
      i++;
      continue;
    }
    if (inClass) {
      if (ch === '[' && pattern[i + 1] === ':') return 'POSIX character classes like [:alpha:] are not supported';
      if (ch === ']') inClass = false;
      continue;
    }
    if (ch === '[') {
      // A leading "]" (after an optional "^") is a literal "]" in RE2 but
      // closes an EMPTY class in JavaScript — the two engines cannot agree.
      const lead = pattern[i + 1] === '^' ? pattern[i + 2] : pattern[i + 1];
      if (lead === ']') {
        return 'a "]" directly after "[" or "[^" means a literal "]" in RE2 but an empty character class in JavaScript; escape it as "\\]"';
      }
      inClass = true;
      continue;
    }
    if (ch === '(' && pattern[i + 1] === '?') {
      const why = checkGroupPrefix(pattern, i + 2);
      if (why !== undefined) return why;
    }
  }
  try {
    new RegExp(pattern);
  } catch (err) {
    return `invalid regular expression: ${err instanceof Error ? err.message : String(err)}`;
  }
  return checkCatastrophicShape(pattern);
}

/**
 * Why the `(?` group whose body starts at `at` is not acceptable, or
 * undefined for `(?:` and `(?<name>`. Named groups are spelled the same in
 * JavaScript and RE2 (Go regexp since 1.22), so they stay allowed; anything
 * else after `(?` is either lookaround or an inline flag / modifier group.
 */
function checkGroupPrefix(pattern: string, at: number): string | undefined {
  const head = pattern.slice(at, at + 2);
  const first = head[0];
  if (first === ':') return undefined;
  if (first === '=' || first === '!') return `lookahead "(?${first}" is not supported (RE2 subset)`;
  if (head === '<=' || head === '<!') return `lookbehind "(?${head}" is not supported (RE2 subset)`;
  if (first === '<') return undefined; // (?<name>...): validated by new RegExp below
  const shown = first === undefined ? '(?' : `(?${first}`;
  return `group "${shown}" is not supported (RE2 subset): only "(?:" non-capturing groups are allowed (no inline flags or modifier groups such as (?i), (?s), (?m), (?U), (?i:...), (?-i:...))`;
}

/** `a.b.0.c`: non-empty segments separated by single dots. */
const DOT_PATH = /^[^.]+(\.[^.]+)*$/;

function checkGlobField(value: GlobOrList, path: string, errors: PolicyError[]): void {
  if (typeof value === 'string') {
    const why = checkGlob(value);
    if (why !== undefined) errors.push({ path, message: why, keyword: 'glob' });
    return;
  }
  value.forEach((g, i) => {
    const why = checkGlob(g);
    if (why !== undefined) errors.push({ path: `${path}/${i}`, message: why, keyword: 'glob' });
  });
}

function checkDuplicateIds(rules: ReadonlyArray<{ id?: string }>, section: string, errors: PolicyError[]): void {
  const seen = new Map<string, number>();
  rules.forEach((rule, i) => {
    if (rule.id === undefined) return;
    const first = seen.get(rule.id);
    if (first !== undefined) {
      errors.push({
        path: `/${section}/rules/${i}/id`,
        message: `duplicate rule id ${JSON.stringify(rule.id)} (already used by rule ${first})`,
        keyword: 'duplicateId',
      });
    } else {
      seen.set(rule.id, i);
    }
  });
}

function checkMcpRule(rule: McpRuleInput, i: number, errors: PolicyError[]): void {
  const base = `/mcp/rules/${i}/match`;
  if (rule.match.server !== undefined) checkGlobField(rule.match.server, `${base}/server`, errors);
  checkGlobField(rule.match.tool, `${base}/tool`, errors);
  if (rule.match.args === undefined) return;
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
    if (why !== undefined) errors.push({ path, message: why, keyword: 'regex' });
  }
}

function checkEgressRule(rule: EgressRuleInput, i: number, errors: PolicyError[]): void {
  const base = `/egress/rules/${i}/match`;
  checkGlobField(rule.match.host, `${base}/host`, errors);
  if (rule.match.path !== undefined) checkGlobField(rule.match.path, `${base}/path`, errors);
}

function semanticErrors(raw: PolicyInput): PolicyError[] {
  const errors: PolicyError[] = [];
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
function friendly(err: SchemaError): PolicyError {
  if (err.path === '' && err.keyword === 'anyOf') {
    return { ...err, message: 'at least one of "mcp" or "egress" is required' };
  }
  return err;
}

/**
 * Validate a parsed policy document. On success the returned policy is
 * normalized (defaults filled, globs as lists, every rule with an id).
 */
export function validatePolicyObject(raw: unknown): ValidationResult {
  const schemaErrors = validateAgainstSchema(POLICY_SCHEMA, raw).map(friendly);
  if (schemaErrors.length > 0) return { ok: false, errors: schemaErrors };
  const input = raw as PolicyInput;
  const errors = semanticErrors(input);
  if (errors.length > 0) return { ok: false, errors };
  return { ok: true, policy: normalizePolicy(input) };
}

/** One line per error, e.g. `/mcp/rules/1/match/tool: glob must not be empty or blank`. */
export function formatPolicyErrors(errors: readonly PolicyError[]): string {
  return errors.map((e) => `${e.path === '' ? '/' : e.path}: ${e.message}`).join('\n');
}
