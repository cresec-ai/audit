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

import { Worker } from 'node:worker_threads';
import { checkCatastrophicShape } from './redos.js';

/** Max wall-clock time one `match.args` regex may take before it is abandoned. */
export const REGEX_DEADLINE_MS = 25;

/** Budget for the one-time worker startup handshake (paid on the first `args` rule only). */
export const REGEX_STARTUP_MS = 1_000;

/** Max compiled arg regexes retained (LRU). */
export const REGEX_CACHE_SIZE = 512;

/** Max patterns remembered as poisoned; beyond this the oldest is forgotten. */
const MAX_POISONED = 1_024;

/** Why a bounded match could not produce an answer. Always fail-closed for the caller. */
export type RegexGuardFailure = 'timeout' | 'unavailable';

/**
 * An `args` regex that could not be evaluated within its deadline (or at all).
 * `message` is the stem the engine stamps the rule id onto.
 */
export class RegexGuardError extends Error {
  readonly failure: RegexGuardFailure;
  constructor(failure: RegexGuardFailure, message: string) {
    super(message);
    this.name = 'RegexGuardError';
    this.failure = failure;
  }
}

export interface RegexGuardOptions {
  /** Per-match deadline in ms (default {@link REGEX_DEADLINE_MS}). */
  deadlineMs?: number;
  /** Worker startup budget in ms (default {@link REGEX_STARTUP_MS}). */
  startupMs?: number;
  /** One line of diagnostics; called at most once per poisoned pattern / degradation. */
  onDiag?: (msg: string) => void;
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
      re = new RegExp(msg.p);
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

/* ------------------------------ caller side ------------------------------ */

interface GuardWorker {
  worker: Worker;
  ctrl: Int32Array;
}

let active: GuardWorker | undefined;
/** True once the worker path has been given up on for this process. */
let degraded = false;
let deadlineMs = REGEX_DEADLINE_MS;
let startupMs = REGEX_STARTUP_MS;
let onDiag: ((msg: string) => void) | undefined;

const poisoned = new Set<string>();
const regexCache = new Map<string, RegExp>();

/** Compile with an LRU cache. Throws `SyntaxError` for a pattern V8 rejects. */
export function compiledRegex(pattern: string): RegExp {
  const hit = regexCache.get(pattern);
  if (hit !== undefined) {
    regexCache.delete(pattern);
    regexCache.set(pattern, hit);
    return hit;
  }
  const re = new RegExp(pattern);
  if (regexCache.size >= REGEX_CACHE_SIZE) {
    const oldest = regexCache.keys().next();
    if (!oldest.done) regexCache.delete(oldest.value);
  }
  regexCache.set(pattern, re);
  return re;
}

function diag(msg: string): void {
  try {
    onDiag?.(msg);
  } catch {
    /* even diagnostics are fail-open */
  }
}

/**
 * Install the diagnostics callback (the proxy passes its stderr `diag`).
 * There is deliberately no default: nothing here may write to stdout, which
 * is the proxy's protocol channel.
 */
export function setRegexGuardDiag(fn: ((msg: string) => void) | undefined): void {
  onDiag = fn;
}

/** Override the deadline / startup budget / diagnostics (tests, embedders). */
export function configureRegexGuard(opts: RegexGuardOptions): void {
  if (opts.deadlineMs !== undefined) deadlineMs = Math.max(1, opts.deadlineMs);
  if (opts.startupMs !== undefined) startupMs = Math.max(0, opts.startupMs);
  if ('onDiag' in opts) onDiag = opts.onDiag;
}

function dropWorker(): void {
  const current = active;
  active = undefined;
  if (current === undefined) return;
  try {
    void current.worker.terminate();
  } catch {
    /* already gone */
  }
}

/** Terminate the worker and forget every knob, poisoned pattern and cached regex (tests). */
export function resetRegexGuard(): void {
  dropWorker();
  degraded = false;
  deadlineMs = REGEX_DEADLINE_MS;
  startupMs = REGEX_STARTUP_MS;
  onDiag = undefined;
  poisoned.clear();
  regexCache.clear();
}

/** Current guard state, for tests and diagnostics. */
export function regexGuardState(): { worker: boolean; degraded: boolean; poisoned: number } {
  return { worker: active !== undefined, degraded, poisoned: poisoned.size };
}

/**
 * Start the worker now (paying the handshake off the hot path) and report
 * whether the bounded path is live. Safe to call more than once; gateway
 * startup is the natural place for it.
 */
export function warmRegexGuard(): boolean {
  return ensureWorker() !== undefined;
}

function ensureWorker(): GuardWorker | undefined {
  if (active !== undefined) return active;
  if (degraded) return undefined;
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
    worker.on('error', (err: Error) => {
      diag(`policy: regex worker error (${err.message}); a fresh one starts on the next evaluation`);
      if (active?.worker === worker) active = undefined;
    });
    worker.on('exit', () => {
      if (active?.worker === worker) active = undefined;
    });
    if (Atomics.load(ctrl, READY) === 0 && Atomics.wait(ctrl, READY, 0, startupMs) === 'timed-out') {
      try {
        void worker.terminate();
      } catch {
        /* nothing to clean up */
      }
      return degrade(`did not start within ${startupMs} ms`);
    }
    active = { worker, ctrl };
    return active;
  } catch (err) {
    return degrade(err instanceof Error ? err.message : String(err));
  }
}

function degrade(why: string): undefined {
  degraded = true;
  active = undefined;
  diag(
    `policy: regex guard worker unavailable (${why}); args regexes are now matched in-thread and any pattern` +
      ' that is not provably linear is denied',
  );
  return undefined;
}

function poison(pattern: string): void {
  if (poisoned.has(pattern)) return;
  if (poisoned.size >= MAX_POISONED) {
    const oldest = poisoned.values().next();
    if (!oldest.done) poisoned.delete(oldest.value);
  }
  poisoned.add(pattern);
  diag(
    `policy: args regex timed out after ${deadlineMs} ms and is disabled for this process` +
      ` (every rule using it now denies): ${JSON.stringify(pattern)}`,
  );
}

function timedOut(): RegexGuardError {
  return new RegexGuardError('timeout', 'regex timed out');
}

/** In-thread match, allowed only for patterns the structural check clears. */
function matchInThread(pattern: string, re: RegExp, value: string): boolean {
  if (checkCatastrophicShape(pattern) !== undefined) {
    throw new RegexGuardError('unavailable', 'regex could not be evaluated safely (guard worker unavailable)');
  }
  return re.test(value);
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
export function matchBounded(pattern: string, value: string): boolean {
  const re = compiledRegex(pattern); // compiling is linear; only matching can blow up
  if (poisoned.has(pattern)) throw timedOut();
  const guard = ensureWorker();
  if (guard === undefined) return matchInThread(pattern, re, value);

  const { ctrl } = guard;
  Atomics.store(ctrl, RESULT, NO_MATCH);
  Atomics.store(ctrl, STATE, 0);
  try {
    guard.worker.postMessage({ p: pattern, v: value });
  } catch (err) {
    dropWorker();
    diag(`policy: regex worker post failed (${err instanceof Error ? err.message : String(err)})`);
    return matchInThread(pattern, re, value);
  }
  let waited: 'ok' | 'not-equal' | 'timed-out';
  try {
    waited = Atomics.wait(ctrl, STATE, 0, deadlineMs);
  } catch (err) {
    // An agent that may not block (some embeddings forbid it) can never use
    // the worker: degrade for good rather than deny every args rule.
    dropWorker();
    degrade(err instanceof Error ? err.message : String(err));
    return matchInThread(pattern, re, value);
  }
  if (waited === 'timed-out') {
    dropWorker(); // the worker is stuck inside the regex; it never comes back
    poison(pattern);
    throw timedOut();
  }
  const result = Atomics.load(ctrl, RESULT);
  // The worker refused a pattern this thread just compiled: fall back rather
  // than guess, so the two engines can never disagree silently.
  if (result === BAD_PATTERN) return matchInThread(pattern, re, value);
  return result === MATCH;
}
