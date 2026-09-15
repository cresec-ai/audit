/**
 * Glob matching with the exact semantics shared by the TS engine and the
 * emitted Rego (`glob.match(pattern, [delimiter], subject)`):
 *
 *   `*`  any run of characters NOT containing the delimiter (may be empty)
 *   `**` any run of characters, delimiter included (may be empty)
 *   `?`  exactly one non-delimiter character
 *   everything else is literal; anchored; case-sensitive.
 *
 * Both wildcards match newlines (OPA's glob does too). The characters
 * `[ ] { } \` carry meaning in OPA's glob library and NONE here, so the
 * validator rejects them to keep the two engines identical; this module
 * treats them as literals if it ever sees them.
 *
 * Compiled patterns are kept in a small LRU cache keyed by delimiter+glob so
 * the hot path of the gateway never recompiles.
 */
export type GlobDelimiter = '/' | '.';
/** Max compiled globs retained; beyond this the least recently used is evicted. */
export declare const GLOB_CACHE_SIZE = 512;
/** Translate a glob into an anchored, flag-less RegExp (uncached). */
export declare function globToRegExp(glob: string, delimiter: GlobDelimiter): RegExp;
/** Cached variant of `globToRegExp`. */
export declare function compileGlob(glob: string, delimiter: GlobDelimiter): RegExp;
/** True when `s` matches `glob` under `delimiter` semantics. */
export declare function globMatch(glob: string, delimiter: GlobDelimiter, s: string): boolean;
/** Number of compiled globs currently cached (for tests). */
export declare function globCacheSize(): number;
/** Drop every cached glob (for tests). */
export declare function clearGlobCache(): void;
