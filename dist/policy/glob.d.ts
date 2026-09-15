/**
 * Glob matching with the exact semantics shared by the TS engine and the
 * emitted Rego (`glob.match(pattern, [delimiter], subject)`):
 *
 *   `*`  any run of characters NOT containing the delimiter (may be empty)
 *   `**` any run of characters, delimiter included (may be empty)
 *   everything else is literal; anchored; case-sensitive.
 *
 * Both wildcards match newlines (OPA's glob does too). The characters
 * `[ ] { } \` carry meaning in OPA's glob library and NONE here, so the
 * validator rejects them to keep the two engines identical; this module
 * treats them as literals if it ever sees them.
 *
 * `?` is NOT part of policy v1: OPA's glob matches it against exactly one
 * ASCII character while a UTF-16 RegExp matches any non-delimiter character
 * (`a?b` vs "aéb"), so `checkGlob` rejects any pattern containing it. The
 * translation below still gives `?` the "one non-delimiter character"
 * meaning — unreachable from a validated policy, and the closer of the two
 * readings to OPA's should v2 ever revisit it — rather than silently turning
 * it into a literal `?`, which is what removing the branch would do.
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
