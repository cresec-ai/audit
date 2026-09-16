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
 * - regexes also compile in JavaScript's UNICODE mode after
 *   {@link toUnicodeSource} rewrites the spellings `u` refuses: the local
 *   engine matches with the `u` flag so that it counts runes the way RE2
 *   does (`^.{1,8}$` against five U+1F600 must not mean one thing here and
 *   another in OPA), and a pattern that cannot be expressed that way is
 *   rejected rather than silently split between the engines;
 * - no policy string carries an unpaired surrogate, which Go (and therefore
 *   OPA) cannot represent and reads back as U+FFFD;
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
 * An unpaired surrogate: legal in a JavaScript string, impossible in a Go
 * one. OPA reads `"\ud800"` back as U+FFFD, so a glob, regex or reason
 * containing one means a different thing in the compiled Rego than it does
 * here — and, unlike U+FEFF (which `rego.ts` escapes), no spelling of it
 * survives the trip. Rejected at validation time instead.
 */
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** Why `text` cannot be carried through to OPA unchanged, or undefined. */
export function checkPortableText(text: string): string | undefined {
  const m = LONE_SURROGATE.exec(text);
  if (m === null) return undefined;
  const code = (m[0] as string).charCodeAt(0).toString(16).padStart(4, '0');
  return (
    `the unpaired surrogate \\u${code} cannot be represented in a Rego string ` +
    '(OPA reads it back as U+FFFD), so the two engines would not see the same text'
  );
}

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
  const unportable = checkPortableText(glob);
  if (unportable !== undefined) return unportable;
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

/** Punctuation JavaScript still allows after a backslash in Unicode (`u`) mode. */
const U_MODE_ESCAPABLE: ReadonlySet<string> = new Set(['^', '$', '\\', '.', '*', '+', '?', '(', ')', '[', ']', '{', '}', '|', '/']);

/** A `{n}` / `{n,}` / `{n,m}` quantifier starting at `at`, or undefined for a literal brace. */
function braceQuantifierAt(pattern: string, at: number): string | undefined {
  const m = /^\{[0-9]+(,[0-9]*)?\}/.exec(pattern.slice(at));
  return m === null ? undefined : m[0];
}

/** Two-digit hex escape for an ASCII character. */
function hexEscape(ch: string): string {
  return `\\x${ch.charCodeAt(0).toString(16).padStart(2, '0')}`;
}

/**
 * The same regex, spelled so JavaScript accepts it with the `u` flag.
 *
 * The local engine matches with `u` on purpose: without it V8 counts UTF-16
 * units where RE2 counts runes, so `^.{1,8}$` matches five U+1F600 in OPA and
 * not here, and `^..$` matches one U+1F600 here and not in OPA. Turning `u`
 * on also tightens the SPELLING rules, and those tightenings carry no meaning
 * — they are rewritten here rather than rejected, so policies that already
 * pass validation keep working:
 *
 * - `\-`, `\ `, `\@`, `\:` ... — escaped punctuation `u` does not recognise —
 *   become `\x2d`, `\x20`, `\x40`, `\x3a`: the same literal in V8 and in RE2
 *   (inside a character class `\-` is already legal under `u` and is left
 *   alone, because `\x2d` there would be a range endpoint spelled differently
 *   but the same character);
 * - a lone `]`, `{` or `}` outside a character class becomes `\]`, `\{`,
 *   `\}`: a literal in RE2 either way, and `u` refuses the bare form;
 * - an escaped non-ASCII character (`\é`) loses the backslash, which is what
 *   V8 without `u` reads it as anyway (the subset check rejects it before
 *   this, so only hand-built patterns get here).
 *
 * Nothing else changes: the rewrite never alters which strings match, only
 * how the pattern is written.
 */
export function toUnicodeSource(pattern: string): string {
  let out = '';
  let inClass = false;
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i] as string;
    if (ch === '\\') {
      const next = pattern[i + 1];
      if (next === undefined) {
        out += ch; // dangling backslash: let `new RegExp` report it
        continue;
      }
      if (next === 'x' && HEX_DIGIT.test(pattern[i + 2] ?? '') && HEX_DIGIT.test(pattern[i + 3] ?? '')) {
        out += pattern.slice(i, i + 4);
        i += 3;
        continue;
      }
      if (ALPHANUMERIC.test(next) || U_MODE_ESCAPABLE.has(next) || (inClass && next === '-')) {
        out += ch + next;
      } else if (next.charCodeAt(0) > 0x7f) {
        out += next; // `\é` is the literal "é" without the `u` flag
      } else {
        out += hexEscape(next);
      }
      i++;
      continue;
    }
    if (inClass) {
      if (ch === ']') inClass = false;
      out += ch;
      continue;
    }
    if (ch === '[') {
      inClass = true;
      out += ch;
      continue;
    }
    if (ch === ']' || ch === '}') {
      out += '\\' + ch; // a literal in RE2; `u` mode refuses the bare form
      continue;
    }
    if (ch === '{') {
      const quant = braceQuantifierAt(pattern, i);
      if (quant === undefined) {
        out += '\\{';
        continue;
      }
      out += quant;
      i += quant.length - 1;
      continue;
    }
    out += ch;
  }
  return out;
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
  const groupNames = new Set<string>();
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
    if (ch === '{') {
      const why = checkRepeat(pattern, i);
      if (why !== undefined) return why;
      continue;
    }
    if (ch === '(' && pattern[i + 1] === '?') {
      const why = checkGroupPrefix(pattern, i + 2, groupNames);
      if (why !== undefined) return why;
    }
  }
  try {
    new RegExp(pattern);
  } catch (err) {
    return `invalid regular expression: ${err instanceof Error ? err.message : String(err)}`;
  }
  // The local engine matches with the `u` flag (so it counts runes, like
  // RE2). `toUnicodeSource` rewrites the spellings `u` refuses without
  // changing what matches; anything still rejected means something different
  // in the two engines and cannot be translated, so it is refused here.
  try {
    new RegExp(toUnicodeSource(pattern), 'u');
  } catch (err) {
    return (
      'pattern cannot be matched in Unicode mode, which the local engine needs so that it counts characters' +
      ` the way RE2 does: ${err instanceof Error ? err.message : String(err)}`
    );
  }
  const unportable = checkPortableText(pattern);
  if (unportable !== undefined) return unportable;
  return checkCatastrophicShape(pattern);
}

/**
 * Why the `(?` group whose body starts at `at` is not acceptable, or
 * undefined for `(?:` and `(?<name>`. Named groups are spelled the same in
 * JavaScript and RE2 (Go regexp since 1.22), so they stay allowed; anything
 * else after `(?` is either lookaround or an inline flag / modifier group.
 */
/**
 * RE2's repeat limit: Go's `regexp/syntax` refuses a count above 1000
 * (`maxRepeat`), where V8 accepts anything up to 2^53. A pattern past it
 * compiles here, compiles into the bundle, passes `opa check --strict` — and
 * then `regex.match` ERRORS at evaluation time. An erroring builtin is
 * `undefined` in Rego, so the whole rule drops out of the decision silently:
 * a deny rule the control plane simply does not have. Refuse it here, where
 * the author sees why.
 */
const RE2_MAX_REPEAT = 1000;

/** `{n}` / `{n,}` / `{n,m}` starting at `at`, when it is a real quantifier. */
const REPEAT_AT = /^\{(\d+)(?:,(\d*))?\}/;

function checkRepeat(pattern: string, at: number): string | undefined {
  const m = REPEAT_AT.exec(pattern.slice(at));
  if (m === null) return undefined; // a literal "{", which both engines accept
  const counts = [m[1], m[2]].filter((c): c is string => c !== undefined && c.length > 0);
  for (const c of counts) {
    if (Number(c) > RE2_MAX_REPEAT) {
      return (
        `repeat count ${c} is above RE2's limit of ${RE2_MAX_REPEAT}: the compiled policy would fail to` +
        ' evaluate in OPA and the rule would be dropped from the decision'
      );
    }
  }
  return undefined;
}

/**
 * Go's grammar for a capture-group name is `[A-Za-z0-9_]+`, where JavaScript
 * accepts any identifier — including `é` and `$`. The mismatch fails the
 * same silent way as an over-long repeat, so the name is held to the
 * narrower grammar. Go also refuses duplicate names, which V8 allows across
 * alternation branches.
 */
const RE2_GROUP_NAME = /^[A-Za-z0-9_]+$/;

function checkGroupPrefix(pattern: string, at: number, groupNames: Set<string>): string | undefined {
  const head = pattern.slice(at, at + 2);
  const first = head[0];
  if (first === ':') return undefined;
  if (first === '=' || first === '!') return `lookahead "(?${first}" is not supported (RE2 subset)`;
  if (head === '<=' || head === '<!') return `lookbehind "(?${head}" is not supported (RE2 subset)`;
  if (first === '<') {
    const close = pattern.indexOf('>', at);
    if (close < 0) return undefined; // malformed: `new RegExp` below reports it
    const name = pattern.slice(at + 1, close);
    if (!RE2_GROUP_NAME.test(name)) {
      return (
        `capture-group name "${name}" is not valid in RE2, which allows only letters, digits and "_":` +
        ' the compiled policy would fail to evaluate in OPA and the rule would be dropped from the decision'
      );
    }
    if (groupNames.has(name)) {
      return `capture-group name "${name}" is used twice, which RE2 rejects`;
    }
    groupNames.add(name);
    return undefined;
  }
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

function checkReason(reason: unknown, path: string, errors: PolicyError[]): void {
  if (typeof reason !== 'string') return; // the schema already reported the type
  const why = checkPortableText(reason);
  if (why !== undefined) errors.push({ path, message: why, keyword: 'text' });
}

function checkMcpRule(rule: McpRuleInput, i: number, errors: PolicyError[]): void {
  const base = `/mcp/rules/${i}/match`;
  checkReason(rule.reason, `/mcp/rules/${i}/reason`, errors);
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
  checkReason(rule.reason, `/egress/rules/${i}/reason`, errors);
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
