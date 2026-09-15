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
 *   lookaround, no backreferences, no RE2-only or JS-only escapes) so the
 *   local engine and OPA agree on every input;
 * - globs are not blank and do not use `[ ] { } \`, which OPA's glob library
 *   interprets and ours does not.
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
 */
export declare function checkGlob(glob: string): string | undefined;
/**
 * Why `pattern` is outside the RE2-portable subset (or fails to compile), or
 * undefined when it is acceptable. Rejected: lookaround `(?=` `(?!` `(?<=`
 * `(?<!`, backreferences `\1`..`\9`, escapes that only one engine knows
 * (`\A \z \Z \p \P \Q \E \C \G \u \U \c`), `\x{...}` and POSIX classes
 * `[:alpha:]`.
 */
export declare function checkRe2Subset(pattern: string): string | undefined;
/**
 * Validate a parsed policy document. On success the returned policy is
 * normalized (defaults filled, globs as lists, every rule with an id).
 */
export declare function validatePolicyObject(raw: unknown): ValidationResult;
/** One line per error, e.g. `/mcp/rules/1/match/tool: glob must not be empty or blank`. */
export declare function formatPolicyErrors(errors: readonly PolicyError[]): string;
