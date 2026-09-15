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
 * - globs are not blank and use neither `[ ] { } \`, which OPA's glob library
 *   interprets and ours does not, nor `?`, which both interpret but not the
 *   same way (OPA's `?` is ASCII-only).
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
 * Why `pattern` is outside the RE2-portable subset (or fails to compile), or
 * undefined when it is acceptable. Rejected: lookaround `(?=` `(?!` `(?<=`
 * `(?<!`, every other `(?` group that is not a plain non-capturing `(?:`
 * or a named group `(?<name>` — inline flags `(?i)` `(?s)` `(?m)` `(?U)`,
 * modifier groups `(?i:...)` `(?-i:...)`, `(?P<name>`, comments `(?#` —
 * backreferences `\1`..`\9` and `\k<name>`, every backslash-letter/digit
 * escape outside `PORTABLE_LETTER_ESCAPES` + `\xhh`, a leading `]` in a
 * character class, and POSIX classes `[:alpha:]`.
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
 * Validate a parsed policy document. On success the returned policy is
 * normalized (defaults filled, globs as lists, every rule with an id).
 */
export declare function validatePolicyObject(raw: unknown): ValidationResult;
/** One line per error, e.g. `/mcp/rules/1/match/tool: glob must not be empty or blank`. */
export declare function formatPolicyErrors(errors: readonly PolicyError[]): string;
