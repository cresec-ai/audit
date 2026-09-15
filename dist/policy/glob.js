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
/** Max compiled globs retained; beyond this the least recently used is evicted. */
export const GLOB_CACHE_SIZE = 512;
const cache = new Map();
function escapeRegExp(ch) {
    return /[\\^$.*+?()[\]{}|/-]/.test(ch) ? '\\' + ch : ch;
}
/** Translate a glob into an anchored, flag-less RegExp (uncached). */
export function globToRegExp(glob, delimiter) {
    const d = escapeRegExp(delimiter);
    let out = '^';
    for (let i = 0; i < glob.length; i++) {
        const ch = glob[i];
        if (ch === '*') {
            if (glob[i + 1] === '*') {
                out += '[\\s\\S]*';
                i++;
            }
            else {
                out += `[^${d}]*`;
            }
        }
        else if (ch === '?') {
            out += `[^${d}]`;
        }
        else {
            out += escapeRegExp(ch);
        }
    }
    return new RegExp(out + '$');
}
/** Cached variant of `globToRegExp`. */
export function compileGlob(glob, delimiter) {
    const key = delimiter + '\0' + glob;
    const hit = cache.get(key);
    if (hit !== undefined) {
        // Refresh recency: Map iteration order is insertion order.
        cache.delete(key);
        cache.set(key, hit);
        return hit;
    }
    const re = globToRegExp(glob, delimiter);
    if (cache.size >= GLOB_CACHE_SIZE) {
        const oldest = cache.keys().next();
        if (!oldest.done)
            cache.delete(oldest.value);
    }
    cache.set(key, re);
    return re;
}
/** True when `s` matches `glob` under `delimiter` semantics. */
export function globMatch(glob, delimiter, s) {
    return compileGlob(glob, delimiter).test(s);
}
/** Number of compiled globs currently cached (for tests). */
export function globCacheSize() {
    return cache.size;
}
/** Drop every cached glob (for tests). */
export function clearGlobCache() {
    cache.clear();
}
//# sourceMappingURL=glob.js.map