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
import { Worker } from 'node:worker_threads';
import { checkProvablyLinear } from './redos.js';
import { toUnicodeSource } from './validate.js';
/** Max wall-clock time one `match.args` regex may take before it is abandoned. */
export const REGEX_DEADLINE_MS = 25;
/** Budget for the one-time worker startup handshake (paid on the first `args` rule only). */
export const REGEX_STARTUP_MS = 1_000;
/** Max compiled arg regexes retained (LRU). */
export const REGEX_CACHE_SIZE = 512;
/** How long the guard waits after a failed worker start before trying again. */
export const REGEX_RETRY_MS = 30_000;
/** Ceiling for the doubling retry backoff. */
export const REGEX_RETRY_MAX_MS = 300_000;
/** Max patterns remembered as poisoned; beyond this the oldest is forgotten. */
const MAX_POISONED = 1_024;
/**
 * An `args` regex that could not be evaluated within its deadline (or at all).
 * `message` is the stem the engine stamps the rule id onto.
 */
export class RegexGuardError extends Error {
    failure;
    constructor(failure, message) {
        super(message);
        this.name = 'RegexGuardError';
        this.failure = failure;
    }
}
/* ------------------------------ worker side ------------------------------ */
/** Control slots in the shared buffer. */
const READY = 0;
const STATE = 1;
const RESULT = 2;
/** Result codes written into `RESULT`. */
const NO_MATCH = 0;
const MATCH = 1;
const BAD_PATTERN = 2;
/**
 * The worker, as source: CommonJS (that is what `eval: true` gets) with no
 * imports beyond `node:worker_threads`, so it is identical under tsx and in
 * `dist/`. It answers through the SharedArrayBuffer — a `postMessage` reply
 * could never be read by a caller that is blocked in `Atomics.wait`.
 */
const WORKER_SOURCE = `
'use strict';
const { parentPort, workerData } = require('node:worker_threads');
const ctrl = new Int32Array(workerData.sab);
const cache = new Map();
parentPort.on('message', (msg) => {
  let out = ${BAD_PATTERN};
  try {
    let re = cache.get(msg.p);
    if (re === undefined) {
      re = new RegExp(msg.p, 'u');
      if (cache.size >= ${REGEX_CACHE_SIZE}) cache.clear();
      cache.set(msg.p, re);
    }
    out = re.test(msg.v) ? ${MATCH} : ${NO_MATCH};
  } catch {
    out = ${BAD_PATTERN};
  }
  Atomics.store(ctrl, ${RESULT}, out);
  Atomics.store(ctrl, ${STATE}, 1);
  Atomics.notify(ctrl, ${STATE});
});
Atomics.store(ctrl, ${READY}, 1);
Atomics.notify(ctrl, ${READY});
`;
let active;
let pending;
/** Epoch ms before which no new worker is started; 0 while the worker path is healthy. */
let retryAt = 0;
let retryBaseMs = REGEX_RETRY_MS;
let retryDelayMs = REGEX_RETRY_MS;
let deadlineMs = REGEX_DEADLINE_MS;
let startupMs = REGEX_STARTUP_MS;
let onDiag;
const poisoned = new Set();
const refusedInThread = new Set();
const regexCache = new Map();
/**
 * Compile with an LRU cache, keyed by the pattern as the policy author wrote
 * it. Throws `SyntaxError` for a pattern V8 rejects. The compiled form always
 * carries the `u` flag: see the module header.
 */
function compile(pattern) {
    const hit = regexCache.get(pattern);
    if (hit !== undefined) {
        regexCache.delete(pattern);
        regexCache.set(pattern, hit);
        return hit;
    }
    const source = toUnicodeSource(pattern);
    const compiled = { re: new RegExp(source, 'u'), source };
    if (regexCache.size >= REGEX_CACHE_SIZE) {
        const oldest = regexCache.keys().next();
        if (!oldest.done)
            regexCache.delete(oldest.value);
    }
    regexCache.set(pattern, compiled);
    return compiled;
}
/** Compile with an LRU cache. Throws `SyntaxError` for a pattern V8 rejects. */
export function compiledRegex(pattern) {
    return compile(pattern).re;
}
function diag(msg) {
    try {
        onDiag?.(msg);
    }
    catch {
        /* even diagnostics are fail-open */
    }
}
/**
 * Install the diagnostics callback (the proxy passes its stderr `diag`).
 * There is deliberately no default: nothing here may write to stdout, which
 * is the proxy's protocol channel.
 */
export function setRegexGuardDiag(fn) {
    onDiag = fn;
}
/** Override the deadline / startup budget / diagnostics (tests, embedders). */
export function configureRegexGuard(opts) {
    if (opts.deadlineMs !== undefined)
        deadlineMs = Math.max(1, opts.deadlineMs);
    if (opts.startupMs !== undefined)
        startupMs = Math.max(0, opts.startupMs);
    if (opts.retryMs !== undefined) {
        retryBaseMs = Math.max(0, opts.retryMs);
        retryDelayMs = retryBaseMs;
        // Re-arm a backoff already in flight, so the new delay takes effect now.
        if (retryAt !== 0)
            retryAt = Date.now() + retryBaseMs;
    }
    if ('onDiag' in opts)
        onDiag = opts.onDiag;
}
function terminate(worker) {
    try {
        void worker.terminate();
    }
    catch {
        /* already gone */
    }
}
/**
 * Forget the current worker WITHOUT degrading: it was healthy until it was
 * killed (a poisoned pattern left it stuck in a regex, a `postMessage`
 * failed), so the next evaluation starts a fresh one the blocking way.
 */
function dropWorker() {
    const current = active;
    active = undefined;
    if (current !== undefined)
        terminate(current.worker);
}
/** Terminate the worker and forget every knob, poisoned pattern and cached regex (tests). */
export function resetRegexGuard() {
    dropWorker();
    if (pending !== undefined)
        terminate(pending.worker);
    pending = undefined;
    retryAt = 0;
    retryBaseMs = REGEX_RETRY_MS;
    retryDelayMs = REGEX_RETRY_MS;
    deadlineMs = REGEX_DEADLINE_MS;
    startupMs = REGEX_STARTUP_MS;
    onDiag = undefined;
    poisoned.clear();
    refusedInThread.clear();
    regexCache.clear();
}
/**
 * Current guard state, for tests and diagnostics. `degraded` means the
 * bounded path is not available right now — either waiting out the retry
 * backoff or waiting for a retried worker's handshake.
 */
export function regexGuardState() {
    return {
        worker: active !== undefined,
        degraded: active === undefined && (retryAt !== 0 || pending !== undefined),
        poisoned: poisoned.size,
        retrying: pending !== undefined,
    };
}
/**
 * Start the worker now (paying the handshake off the hot path) and report
 * whether the bounded path is live. Safe to call more than once; gateway
 * startup is the natural place for it.
 */
export function warmRegexGuard() {
    return ensureWorker() !== undefined;
}
/** Create a worker and wire its lifecycle, or schedule a retry and return undefined. */
function startWorker() {
    try {
        const sab = new SharedArrayBuffer(16);
        const ctrl = new Int32Array(sab);
        const worker = new Worker(WORKER_SOURCE, {
            eval: true,
            workerData: { sab },
            // Keep the worker's stdio to itself: the parent's stdout carries MCP frames.
            stdout: true,
            stderr: true,
        });
        worker.unref();
        worker.on('error', (err) => {
            diag(`policy: regex worker error (${err.message}); a fresh one starts on the next evaluation`);
            if (active?.worker === worker)
                active = undefined;
            if (pending?.worker === worker)
                pending = undefined;
        });
        worker.on('exit', () => {
            if (active?.worker === worker)
                active = undefined;
            if (pending?.worker === worker)
                pending = undefined;
        });
        return { worker, ctrl };
    }
    catch (err) {
        degrade(err instanceof Error ? err.message : String(err));
        return undefined;
    }
}
/**
 * The bounded path, or undefined when this call must fall back in-thread.
 *
 * The FIRST attempt pays the handshake synchronously (~60 ms), so a healthy
 * process has its worker before the first `args` rule is evaluated. Every
 * later attempt after a failure is asynchronous: the worker is started and
 * adopted by a subsequent call, so a broken environment costs the proxy
 * nothing per request and a single slow handshake never disables the bounded
 * path for good.
 */
function ensureWorker() {
    if (active !== undefined)
        return active;
    if (pending !== undefined) {
        if (Atomics.load(pending.ctrl, READY) === 1) {
            active = { worker: pending.worker, ctrl: pending.ctrl };
            pending = undefined;
            retryAt = 0;
            diag('policy: regex guard worker started; args regexes are bounded off-thread again');
            return active;
        }
        if (Date.now() - pending.startedAt >= startupMs) {
            const stale = pending;
            pending = undefined;
            terminate(stale.worker);
            degrade(`did not start within ${startupMs} ms`);
        }
        return undefined;
    }
    if (retryAt !== 0 && Date.now() < retryAt)
        return undefined;
    const started = startWorker();
    if (started === undefined)
        return undefined;
    if (retryAt !== 0) {
        // A retry must not block the proxy: a later call adopts it once ready.
        pending = { ...started, startedAt: Date.now() };
        return undefined;
    }
    if (Atomics.load(started.ctrl, READY) === 0 && Atomics.wait(started.ctrl, READY, 0, startupMs) === 'timed-out') {
        terminate(started.worker);
        degrade(`did not start within ${startupMs} ms`);
        return undefined;
    }
    active = started;
    return active;
}
/** Give up on the worker for now, and say when the guard will try again. */
function degrade(why) {
    active = undefined;
    const waited = retryDelayMs;
    retryAt = Date.now() + waited;
    retryDelayMs = Math.min(retryDelayMs * 2, REGEX_RETRY_MAX_MS);
    diag(`policy: regex guard worker unavailable (${why}); args regexes are now matched in-thread and any pattern` +
        ` that is not provably linear is denied (a new worker is tried again in ${Math.round(waited / 1_000)} s)`);
}
function poison(pattern) {
    if (poisoned.has(pattern))
        return;
    if (poisoned.size >= MAX_POISONED) {
        const oldest = poisoned.values().next();
        if (!oldest.done)
            poisoned.delete(oldest.value);
    }
    poisoned.add(pattern);
    diag(`policy: args regex timed out after ${deadlineMs} ms and is disabled for this process` +
        ` (every rule using it now denies): ${JSON.stringify(pattern)}`);
}
function timedOut() {
    return new RegexGuardError('timeout', 'regex timed out');
}
/** Report an in-thread refusal once per pattern (the deny itself is unconditional). */
function noteRefusal(pattern, why) {
    if (refusedInThread.has(pattern))
        return;
    if (refusedInThread.size >= MAX_POISONED) {
        const oldest = refusedInThread.values().next();
        if (!oldest.done)
            refusedInThread.delete(oldest.value);
    }
    refusedInThread.add(pattern);
    diag(`policy: no regex guard worker, and ${JSON.stringify(pattern)} cannot be proved bounded (${why});` +
        ' every rule using it denies until a worker is available');
}
/**
 * In-thread match, allowed ONLY for patterns {@link checkProvablyLinear}
 * clears — the absence of a known-bad shape is not enough without a worker to
 * abandon a runaway match. A cleared match that still overruns the deadline
 * cannot be interrupted, so its answer is discarded and the pattern is
 * poisoned: it can cost the proxy one over-budget match, never two, and never
 * an allow.
 */
function matchInThread(pattern, re, value) {
    const why = checkProvablyLinear(pattern);
    if (why !== undefined) {
        noteRefusal(pattern, why);
        throw new RegexGuardError('unavailable', 'regex could not be evaluated safely (guard worker unavailable)');
    }
    const started = performance.now();
    const matched = re.test(value);
    if (performance.now() - started > deadlineMs) {
        poison(pattern);
        throw timedOut();
    }
    return matched;
}
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
export function matchBounded(pattern, value) {
    const { re, source } = compile(pattern); // compiling is linear; only matching can blow up
    if (poisoned.has(pattern))
        throw timedOut();
    const guard = ensureWorker();
    if (guard === undefined)
        return matchInThread(pattern, re, value);
    const { ctrl } = guard;
    Atomics.store(ctrl, RESULT, NO_MATCH);
    Atomics.store(ctrl, STATE, 0);
    try {
        guard.worker.postMessage({ p: source, v: value });
    }
    catch (err) {
        dropWorker();
        diag(`policy: regex worker post failed (${err instanceof Error ? err.message : String(err)})`);
        return matchInThread(pattern, re, value);
    }
    let waited;
    try {
        waited = Atomics.wait(ctrl, STATE, 0, deadlineMs);
    }
    catch (err) {
        // An agent that may not block (some embeddings forbid it) can never use
        // the worker while that holds: fall back, and retry on the usual backoff
        // rather than turning the bounded path off for the whole process.
        dropWorker();
        degrade(err instanceof Error ? err.message : String(err));
        return matchInThread(pattern, re, value);
    }
    if (waited === 'timed-out') {
        dropWorker(); // the worker is stuck inside the regex; it never comes back
        poison(pattern);
        throw timedOut();
    }
    retryDelayMs = retryBaseMs; // the worker answered: reset the backoff
    const result = Atomics.load(ctrl, RESULT);
    // The worker refused a pattern this thread just compiled: fall back rather
    // than guess, so the two engines can never disagree silently.
    if (result === BAD_PATTERN)
        return matchInThread(pattern, re, value);
    return result === MATCH;
}
//# sourceMappingURL=regex-guard.js.map