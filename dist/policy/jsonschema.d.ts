/**
 * A tiny, dependency-free JSON Schema (draft 2020-12) validator.
 *
 * It implements EXACTLY the keyword subset used by `docs/policy-schema.json`
 * (see `SUPPORTED_KEYWORDS`); any other keyword makes `validateAgainstSchema`
 * throw rather than silently pass, and `collectKeywords()` lets a test pin the
 * shipped schema to that subset. Errors carry an RFC 6901 JSON pointer to the
 * offending value ("" for the root) so callers can print `/mcp/rules/1/...`.
 *
 * Deliberately not a general-purpose validator: no `$ref` beyond
 * `#/$defs/<name>`, no `additionalProperties` schemas (boolean `false` only),
 * no `patternProperties`, no format/annotation semantics beyond ignoring the
 * documentary keywords listed in `ANNOTATION_KEYWORDS`.
 */
/** A schema object; keywords are checked at runtime, hence the loose shape. */
export type JsonSchema = {
    readonly [keyword: string]: unknown;
};
export interface SchemaError {
    /** RFC 6901 JSON pointer to the failing value; "" is the root. */
    path: string;
    message: string;
    /** The keyword that failed (`type`, `required`, `anyOf`, ...). */
    keyword: string;
}
/** Keywords that validate; every entry is implemented below. */
export declare const VALIDATION_KEYWORDS: readonly string[];
/** Documentary keywords that are accepted and ignored. */
export declare const ANNOTATION_KEYWORDS: readonly string[];
export declare const SUPPORTED_KEYWORDS: ReadonlySet<string>;
type TypeName = 'string' | 'number' | 'integer' | 'boolean' | 'null' | 'object' | 'array';
/** RFC 6901 token escaping. */
export declare function escapePointerToken(token: string): string;
/** Human-readable JSON type of a value ("integer" is reported as "number"). */
export declare function typeOf(value: unknown): Exclude<TypeName, 'integer'>;
/** Structural (JSON) equality for `const` / `enum`. */
export declare function jsonEqual(a: unknown, b: unknown): boolean;
/**
 * Walk a schema and return every keyword it uses, at any depth. Keys under
 * `properties` / `$defs` are property names, not keywords, and are skipped;
 * their values are schemas and are walked.
 */
export declare function collectKeywords(schema: unknown): Set<string>;
/**
 * Validate `value` against `schema`. Returns every error found (empty array
 * = valid). Throws `TypeError` if the schema uses a keyword outside
 * `SUPPORTED_KEYWORDS` or an unresolvable `$ref`.
 */
export declare function validateAgainstSchema(schema: JsonSchema, value: unknown): SchemaError[];
export {};
