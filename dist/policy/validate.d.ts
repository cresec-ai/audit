/**
 * policy.yaml v1 validation: JSON Schema first, then the semantic checks the
 * schema cannot express, then normalization.
 *
 * Schema validation (`schema.ts` via `jsonschema.ts`) covers shapes, enums,
 * identifier patterns, numeric ranges (hold timeout, boundary scan size),
 * upper-case methods, non-empty glob strings/lists, the discriminated union a
 * credential `source` / `host` / `path` is, and the "at least one of mcp /
 * credentials / egress" rule (a root `anyOf`, whose error is reworded here).
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
 *   same way (OPA's `?` is ASCII-only);
 * - `credentials` entries hold together: ids unique within the section and
 *   site ids within their credential, dot-paths well-formed, every path a
 *   source names absolute (a relative one resolves against the CLIENT's
 *   working directory), a `github-app` with exactly one private-key
 *   spelling, and a destination that is not read from the same argument the
 *   credential is about to overwrite.
 *
 * Every error keeps an RFC 6901 pointer (`/mcp/rules/1/match/tool`).
 */
import type { SchemaError } from './jsonschema.js';
import type { Policy } from './types.js';
export type PolicyError = SchemaError;
export type ValidationResult = {
    ok: true;
    policy: Policy;
} | {
    ok: false;
    errors: PolicyError[];
};
/** Why `text` cannot be carried through to OPA unchanged, or undefined. */
export declare function checkPortableText(text: string): string | undefined;
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
export declare function checkGlob(glob: string): string | undefined;
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
export declare function toUnicodeSource(pattern: string): string;
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
export declare function checkRe2Subset(pattern: string): string | undefined;
/**
 * The control plane's closed connector set (cresec-ai/nhi
 * `packages/contracts/src/names.ts`, `CONNECTORS`). A `broker` credential's
 * `provider` goes on the wire as `connector`, and the endpoint answers 400
 * to anything else — which the gateway would then report as a `broker_error`
 * deny on every call. Said here, at validation, instead.
 */
export declare const CONTROL_PLANE_CONNECTORS: readonly string[];
/**
 * Validate a parsed policy document. On success the returned policy is
 * normalized (defaults filled, globs as lists, every rule with an id).
 */
export declare function validatePolicyObject(raw: unknown): ValidationResult;
/** One line per error, e.g. `/mcp/rules/1/match/tool: glob must not be empty or blank`. */
export declare function formatPolicyErrors(errors: readonly PolicyError[]): string;
