/**
 * Bounded evaluation of `match.args` regexes — the runtime half of the ReDoS
 * defence (`redos.ts` is the validation-time half).
 *
 * The policy regex subset is RE2-portable and therefore linear under OPA, but
 * the local engine matches with V8's backtracking `RegExp`: `^(a+)+$` against
 * 29 non-matching characters takes ~14 s, and the stdio proxy is single
 * threaded, so that would freeze ALL traffic, not just the offending call.
 * Validation rejects the obvious shapes; this module is the guarantee that
 * holds whatever the pattern is.
 *
 * How: a lazily created `worker_threads` Worker (inline source via
 * `new Worker(code, { eval: true })`, so it works identically from `src/`
 * under tsx and from the compiled `dist/`) does the matching, and the caller
 * blocks on `Atomics.wait` over a `SharedArrayBuffer` for at most
 * `REGEX_DEADLINE_MS`. On timeout the worker is terminated, the pattern is
 * POISONED for the rest of the process (every later evaluation of it fails
 * immediately) and the caller gets a `RegexGuardError` — the engine turns
 * that into the fail-closed `deny` with `policy evaluation error: regex timed
 * out (<rule id>)`. A fresh worker is created on the next call that needs one.
 *
 * Costs (measured on the repo's CI-class hardware): ~60 ms once for the
 * worker handshake, ~0.04 ms per evaluation afterwards; the worker is
 * `unref()`'d, so it never keeps the proxy (or a test runner) alive, and its
 * stdio is NOT piped to the parent's, so nothing it ever prints can reach the
 * proxy's protocol channel on stdout.
 *
 * Fallback: if the worker cannot be started at all (no `worker_threads`, a
 * sandbox that refuses threads, a startup handshake that misses its budget),
 * the guard degrades to IN-THREAD matching, but ONLY for patterns that pass
 * `checkCatastrophicShape`; anything else is refused as unevaluable, which is
 * again a fail-closed deny. The degradation is reported once through the diag
 * callback.
 */
/** Max wall-clock time one `match.args` regex may take before it is abandoned. */
export declare const REGEX_DEADLINE_MS = 25;
/** Budget for the one-time worker startup handshake (paid on the first `args` rule only). */
export declare const REGEX_STARTUP_MS = 1000;
/** Max compiled arg regexes retained (LRU). */
export declare const REGEX_CACHE_SIZE = 512;
/** Why a bounded match could not produce an answer. Always fail-closed for the caller. */
export type RegexGuardFailure = 'timeout' | 'unavailable';
/**
 * An `args` regex that could not be evaluated within its deadline (or at all).
 * `message` is the stem the engine stamps the rule id onto.
 */
export declare class RegexGuardError extends Error {
    readonly failure: RegexGuardFailure;
    constructor(failure: RegexGuardFailure, message: string);
}
export interface RegexGuardOptions {
    /** Per-match deadline in ms (default {@link REGEX_DEADLINE_MS}). */
    deadlineMs?: number;
    /** Worker startup budget in ms (default {@link REGEX_STARTUP_MS}). */
    startupMs?: number;
    /** One line of diagnostics; called at most once per poisoned pattern / degradation. */
    onDiag?: (msg: string) => void;
}
/** Compile with an LRU cache. Throws `SyntaxError` for a pattern V8 rejects. */
export declare function compiledRegex(pattern: string): RegExp;
/**
 * Install the diagnostics callback (the proxy passes its stderr `diag`).
 * There is deliberately no default: nothing here may write to stdout, which
 * is the proxy's protocol channel.
 */
export declare function setRegexGuardDiag(fn: ((msg: string) => void) | undefined): void;
/** Override the deadline / startup budget / diagnostics (tests, embedders). */
export declare function configureRegexGuard(opts: RegexGuardOptions): void;
/** Terminate the worker and forget every knob, poisoned pattern and cached regex (tests). */
export declare function resetRegexGuard(): void;
/** Current guard state, for tests and diagnostics. */
export declare function regexGuardState(): {
    worker: boolean;
    degraded: boolean;
    poisoned: number;
};
/**
 * Start the worker now (paying the handshake off the hot path) and report
 * whether the bounded path is live. Safe to call more than once; gateway
 * startup is the natural place for it.
 */
export declare function warmRegexGuard(): boolean;
/**
 * `new RegExp(pattern).test(value)` with a hard deadline. Returns the match
 * result, or throws:
 *
 * - `SyntaxError` when `pattern` does not compile (unchanged from a plain
 *   `RegExp`, so a hand-built policy still denies with V8's message);
 * - `RegexGuardError` when the match overran its deadline, when the pattern
 *   has already been poisoned, or when no worker is available and the pattern
 *   is not provably linear.
 */
export declare function matchBounded(pattern: string, value: string): boolean;
