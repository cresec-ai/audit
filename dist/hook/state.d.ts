/**
 * `mcp-recorder hook` per-session / per-call marker files.
 *
 * Claude Code spawns one short-lived `mcp-recorder hook` PROCESS per hook
 * event — unlike `record`'s single long-lived proxy process — so state that
 * needs to survive across hook invocations of the same session (or the same
 * tool call) lives on disk under the data dir, not in memory.
 *
 * Session markers (`<data-dir>/hook-sessions/<session_id>`) dedupe
 * `session_start`: an empty file created with the exclusive `wx` flag means
 * at most one concurrent invocation "wins" the create and is responsible for
 * emitting session_start — the same race-safe pattern src/chain/keys.ts's
 * `Signer.load` already uses for identity.key across concurrent `record`
 * processes sharing one data dir.
 *
 * Pending markers (`<data-dir>/hook-pending/<request_id>`) carry the
 * PreToolUse timestamp forward to the matching PostToolUse (or
 * PostToolUseFailure — Claude Code fires exactly one of the two per call)
 * invocation so `duration_ms` can be measured across two separate processes;
 * read once and deleted.
 *
 * A pending marker can OUTLIVE its call. The post half never fires when
 * Claude Code itself is killed mid-call, when a cloud session's container is
 * reclaimed, or when the hook is uninstalled / its matcher narrowed between
 * the two halves — and before PostToolUseFailure was handled, every failed
 * call left its marker behind too (cloud dogfood 3). Nothing else ever
 * deletes them, so `sweepStalePending` garbage-collects markers older than
 * `PENDING_MARKER_MAX_AGE_MS` by file mtime; run.ts calls it from the Stop
 * (turn boundary) and SessionEnd paths, where a little extra work is off
 * the tool-call path the hook is otherwise attached to.
 */
/** A pending marker older than this (by mtime) is stale: no real tool call
 *  stays in flight for a day, and Claude Code's own hook timeout is seconds. */
export declare const PENDING_MARKER_MAX_AGE_MS: number;
/** Upper bound on the markers one sweep stats/removes, so a pathological
 *  backlog is drained a slice per Stop/SessionEnd rather than in one long
 *  synchronous pass inside a hook invocation. */
export declare const PENDING_SWEEP_MAX_ENTRIES = 1000;
/**
 * True (and creates the marker) the FIRST time this is called for
 * `sessionId` under `dataDir`; false on every later call, from this process
 * or another. Throws only on a real filesystem error other than "already
 * exists" — callers wrap this fail-open.
 */
export declare function claimSessionStart(dataDir: string, sessionId: string): boolean;
/** Record the PreToolUse timestamp (epoch ms, `Date.now()`) for `requestId`.
 *  Best-effort: a marker that already exists (a retried/duplicate
 *  PreToolUse for the same tool_use_id) is left as-is, never an error. */
export declare function markPending(dataDir: string, requestId: string, t0Ms: number): void;
/**
 * Read back and DELETE the pending marker for `requestId`, if any. Undefined
 * when no PreToolUse marker was recorded for this call (the hook was
 * installed mid-session, a policy file started denying between Pre and
 * Post, --all-tools was toggled, the marker dir was cleaned up, ...) — the
 * caller falls back to `duration_ms: 0` in that case.
 */
export declare function takePending(dataDir: string, requestId: string): number | undefined;
/**
 * Delete pending markers whose mtime is older than `maxAgeMs` (see the
 * file-level comment for how a marker outlives its call). Bounded: at most
 * `PENDING_SWEEP_MAX_ENTRIES` directory entries are examined per call.
 * Never throws — a missing directory means nothing to sweep, and a marker
 * that can't be stat'ed or removed is simply left for a later sweep. Returns
 * the number of markers removed (for tests and diagnostics).
 */
export declare function sweepStalePending(dataDir: string, nowMs?: number, maxAgeMs?: number): number;
