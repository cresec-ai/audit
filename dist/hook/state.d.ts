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
 * PreToolUse timestamp forward to the matching PostToolUse invocation so
 * `duration_ms` can be measured across two separate processes; read once and
 * deleted.
 */
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
