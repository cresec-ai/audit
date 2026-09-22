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
 * One request may carry ONE value (`match.args`, one dot-path) or a LIST of
 * them (`match.any_arg`, every string leaf of the arguments): the list is a
 * single round trip under a single deadline, never one hop per leaf, and the
 * worker stops at the first match.
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
 * the guard degrades to IN-THREAD matching — but the absence of
 * `worker_threads` must never turn enforcement fail-OPEN, so in that state:
 *
 * - a pattern runs on this thread ONLY if `checkProvablyLinear` clears it
 *   (no repeated groups, at most two repeated atoms, a bounded number of
 *   alternation paths). That is a proof of boundedness, not the mere absence
 *   of a known-bad shape: `^((a+))+$` used to slip through the blacklist and
 *   took 40 s in one call, blocking every other request behind it, and then
 *   ALLOWED. Anything not cleared is refused as unevaluable — a fail-closed
 *   deny, never an allow, and never a wait;
 * - a cleared match that still overruns the deadline (a machine under load, a
 *   shape the analysis was too generous about) cannot be interrupted, so its
 *   answer is thrown away and the pattern is POISONED: it can happen at most
 *   once per pattern, and every later call denies immediately;
 * - the degradation is NOT permanent. A single slow startup handshake used to
 *   disable the bounded path for the lifetime of the process; now the guard
 *   retries after `REGEX_RETRY_MS` (doubling up to `REGEX_RETRY_MAX_MS`), and
 *   a retry never blocks the caller — the worker is adopted by a later call
 *   once its handshake lands.
 *
 * Every `match.args` regex is matched with the `u` flag (through
 * `toUnicodeSource`, which rewrites the spellings `u` refuses without
 * changing what matches), because without it V8 counts UTF-16 units where
 * RE2 counts runes and the two engines disagree about `^.{1,8}$`.
 */
/** Max wall-clock time one `match.args` regex may take before it is abandoned. */
export declare const REGEX_DEADLINE_MS = 25;
/** Budget for the one-time worker startup handshake (paid on the first `args` rule only). */
export declare const REGEX_STARTUP_MS = 1000;
/** Max compiled arg regexes retained (LRU). */
export declare const REGEX_CACHE_SIZE = 512;
/** How long the guard waits after a failed worker start before trying again. */
export declare const REGEX_RETRY_MS = 30000;
/** Ceiling for the doubling retry backoff. */
export declare const REGEX_RETRY_MAX_MS = 300000;
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
    /** Delay before the first retry after a failed start (default {@link REGEX_RETRY_MS}); it doubles from there. */
    retryMs?: number;
    /** One line of diagnostics; called at most once per poisoned pattern / degradation. */
    onDiag?: (msg: string) => void;
    /**
     * Replace the worker's source (TESTS ONLY). The real worker never dies on
     * its own, which is exactly why the handling of one that does went
     * untested: the handlers cleared the slot without arming the backoff, so
     * the guard built one OS thread per evaluation forever. A test worker that
     * signals ready and then exits reproduces it in a second.
     */
    workerSource?: string;
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
/**
 * Current guard state, for tests and diagnostics. `degraded` means the
 * bounded path is not available right now — either waiting out the retry
 * backoff or waiting for a retried worker's handshake.
 */
export declare function regexGuardState(): {
    worker: boolean;
    degraded: boolean;
    poisoned: number;
    retrying: boolean;
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
/**
 * `matchBounded` over a LIST: true when ANY value matches, under ONE
 * deadline for the whole list. This is what `match.any_arg` runs — every
 * string leaf of one call's arguments in a single request, never one round
 * trip per leaf. An empty list never matches and costs nothing.
 *
 * Throws exactly what {@link matchBounded} throws, so the engine's
 * fail-closed path is the same one.
 */
export declare function matchAnyBounded(pattern: string, values: readonly string[]): boolean;
