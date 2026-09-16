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
import { mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
const SESSIONS_DIR = 'hook-sessions';
const PENDING_DIR = 'hook-pending';
/** A pending marker older than this (by mtime) is stale: no real tool call
 *  stays in flight for a day, and Claude Code's own hook timeout is seconds. */
export const PENDING_MARKER_MAX_AGE_MS = 24 * 60 * 60 * 1000;
/** Upper bound on the markers one sweep stats/removes, so a pathological
 *  backlog is drained a slice per Stop/SessionEnd rather than in one long
 *  synchronous pass inside a hook invocation. */
export const PENDING_SWEEP_MAX_ENTRIES = 1000;
/** A request_id (a `tool_use_id` or our own sha256 fallback) is already
 *  filesystem-safe in practice, but this is defense in depth against an
 *  unexpected value reaching a filename unsanitized. */
function safeFileName(id) {
    const safe = id.replace(/[^A-Za-z0-9_.-]/g, '_').slice(0, 200);
    return safe.length > 0 ? safe : 'unknown';
}
/**
 * True (and creates the marker) the FIRST time this is called for
 * `sessionId` under `dataDir`; false on every later call, from this process
 * or another. Throws only on a real filesystem error other than "already
 * exists" — callers wrap this fail-open.
 */
export function claimSessionStart(dataDir, sessionId) {
    const dir = join(dataDir, SESSIONS_DIR);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const path = join(dir, safeFileName(sessionId));
    try {
        writeFileSync(path, '', { flag: 'wx' });
        return true;
    }
    catch (cause) {
        if (cause.code === 'EEXIST')
            return false;
        throw cause;
    }
}
/** Record the PreToolUse timestamp (epoch ms, `Date.now()`) for `requestId`.
 *  Best-effort: a marker that already exists (a retried/duplicate
 *  PreToolUse for the same tool_use_id) is left as-is, never an error. */
export function markPending(dataDir, requestId, t0Ms) {
    const dir = join(dataDir, PENDING_DIR);
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    const path = join(dir, safeFileName(requestId));
    try {
        writeFileSync(path, String(t0Ms), { flag: 'wx' });
    }
    catch (cause) {
        if (cause.code !== 'EEXIST')
            throw cause;
    }
}
/**
 * Read back and DELETE the pending marker for `requestId`, if any. Undefined
 * when no PreToolUse marker was recorded for this call (the hook was
 * installed mid-session, a policy file started denying between Pre and
 * Post, --all-tools was toggled, the marker dir was cleaned up, ...) — the
 * caller falls back to `duration_ms: 0` in that case.
 */
export function takePending(dataDir, requestId) {
    const path = join(dataDir, PENDING_DIR, safeFileName(requestId));
    let text;
    try {
        text = readFileSync(path, 'utf8');
    }
    catch {
        return undefined;
    }
    try {
        rmSync(path, { force: true });
    }
    catch {
        /* fail-open: a leftover marker is harmless, just wasted disk */
    }
    const n = Number(text);
    return Number.isFinite(n) ? n : undefined;
}
/**
 * Delete pending markers whose mtime is older than `maxAgeMs` (see the
 * file-level comment for how a marker outlives its call). Bounded: at most
 * `PENDING_SWEEP_MAX_ENTRIES` directory entries are examined per call.
 * Never throws — a missing directory means nothing to sweep, and a marker
 * that can't be stat'ed or removed is simply left for a later sweep. Returns
 * the number of markers removed (for tests and diagnostics).
 */
export function sweepStalePending(dataDir, nowMs = Date.now(), maxAgeMs = PENDING_MARKER_MAX_AGE_MS) {
    const dir = join(dataDir, PENDING_DIR);
    let names;
    try {
        names = readdirSync(dir);
    }
    catch {
        return 0;
    }
    let removed = 0;
    for (const name of names.slice(0, PENDING_SWEEP_MAX_ENTRIES)) {
        const path = join(dir, name);
        try {
            const st = statSync(path);
            if (!st.isFile() || nowMs - st.mtimeMs <= maxAgeMs)
                continue;
            rmSync(path, { force: true });
            removed++;
        }
        catch {
            /* fail-open: leave it for a later sweep */
        }
    }
    return removed;
}
//# sourceMappingURL=state.js.map