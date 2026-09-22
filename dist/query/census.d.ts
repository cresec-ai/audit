/**
 * `mcp-recorder sessions --tools`: one row per (server, tool) actually
 * observed on the chain — the per-server, per-tool census of MCP traffic.
 *
 * It answers "what did our agents call, and what did the gateway do about
 * it?" from the evidence alone, so a policy is written against the tools
 * that are really in use rather than the ones someone remembers. The
 * counting rules are the ones `sessions` uses for its per-session row
 * (SessionSummary in src/types.ts), applied per tool:
 *
 *  - CALLS: `tool_call` events with no `phase` (a proxy call, already
 *    request+response correlated) or `phase: 'pre'` (a hook call; its
 *    `post` twin is the same call). A lone `pre` still counts once.
 *  - ERRORS: `tool_call` events with `is_error: true`, whichever phase.
 *  - DENIED: the gateway's synthetic deny `tool_call` (`gateway.decision:
 *    'deny'`), or the hook's deny shape — a `pre` with `error.type:
 *    'policy_denied'`. Counted off the `tool_call`, never the
 *    `policy_decision` that accompanies a gateway deny, so one refusal is
 *    one here.
 *  - HELD: `tool_call` events whose `gateway.decision` is `hold` — one per
 *    RESOLVED hold, whatever its outcome, as DECISIONS counts them.
 *
 * `server` is the event's own `server.name`: the wrapped server for a proxy
 * session, the `mcp__<segment>__` segment for a hook session. That segment
 * is the platform's to choose (docs/hooks.md), so one hosted connector can
 * appear under more than one server name across sessions; the census shows
 * what was recorded and does not guess which names are the same server.
 *
 * Reads only; never writes, never touches the forwarding path.
 */
import type { ChainRecord } from '../schema/events.js';
export interface ToolCensusRow {
    server: string;
    tool: string;
    calls: number;
    errors: number;
    denied: number;
    held: number;
    /** Distinct sessions that called this tool. */
    sessions: number;
    first_seen: string;
    last_seen: string;
}
/** Rows sorted by server, then tool (plain code-unit order, stable run to run). */
export declare function toolCensus(records: Iterable<ChainRecord>): ToolCensusRow[];
