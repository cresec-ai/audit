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
export const GLOB_CACHE_SIZE = 512;

const cache = new Map<string, RegExp>();

function escapeRegExp(ch: string): string {
  return /[\\^$.*+?()[\]{}|/-]/.test(ch) ? '\\' + ch : ch;
}

/** Translate a glob into an anchored, flag-less RegExp (uncached). */
export function globToRegExp(glob: string, delimiter: GlobDelimiter): RegExp {
  const d = escapeRegExp(delimiter);
  let out = '^';
  for (let i = 0; i < glob.length; i++) {
    const ch = glob[i];
    if (ch === '*') {
      if (glob[i + 1] === '*') {
        out += '[\\s\\S]*';
        i++;
      } else {
        out += `[^${d}]*`;
      }
    } else if (ch === '?') {
      out += `[^${d}]`;
    } else {
      out += escapeRegExp(ch as string);
    }
  }
  return new RegExp(out + '$');
}

/** Cached variant of `globToRegExp`. */
export function compileGlob(glob: string, delimiter: GlobDelimiter): RegExp {
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
    if (!oldest.done) cache.delete(oldest.value);
  }
  cache.set(key, re);
  return re;
}

/** True when `s` matches `glob` under `delimiter` semantics. */
export function globMatch(glob: string, delimiter: GlobDelimiter, s: string): boolean {
  return compileGlob(glob, delimiter).test(s);
}

/** Number of compiled globs currently cached (for tests). */
export function globCacheSize(): number {
  return cache.size;
}

/** Drop every cached glob (for tests). */
export function clearGlobCache(): void {
  cache.clear();
}
