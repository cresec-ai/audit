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
function isHookDeny(ev) {
    if (ev.kind !== 'tool_call' || ev.phase !== 'pre')
        return false;
    return ev.error?.type === 'policy_denied';
}
/** Rows sorted by server, then tool (plain code-unit order, stable run to run). */
export function toolCensus(records) {
    const rows = new Map();
    for (const record of records) {
        const ev = record.event;
        if (ev.kind !== 'tool_call')
            continue;
        const server = typeof ev.server?.name === 'string' ? ev.server.name : '';
        // A NUL cannot occur in either half, so the key cannot collide.
        const key = `${server}\u0000${ev.tool}`;
        let entry = rows.get(key);
        if (entry === undefined) {
            entry = {
                row: {
                    server,
                    tool: ev.tool,
                    calls: 0,
                    errors: 0,
                    denied: 0,
                    held: 0,
                    sessions: 0,
                    first_seen: ev.timestamp,
                    last_seen: ev.timestamp,
                },
                sessions: new Set(),
            };
            rows.set(key, entry);
        }
        const { row, sessions } = entry;
        if (ev.timestamp < row.first_seen)
            row.first_seen = ev.timestamp;
        if (ev.timestamp > row.last_seen)
            row.last_seen = ev.timestamp;
        // An explicit `phase: null` reads as "no phase", as it does in `sessions`.
        const phase = ev.phase ?? undefined;
        if (phase === undefined || phase === 'pre') {
            row.calls += 1;
            sessions.add(ev.session_id);
            row.sessions = sessions.size;
        }
        if (ev.is_error === true)
            row.errors += 1;
        if (ev.gateway?.decision === 'deny' || isHookDeny(ev))
            row.denied += 1;
        if (ev.gateway?.decision === 'hold')
            row.held += 1;
    }
    return [...rows.values()]
        .map((e) => e.row)
        .sort((a, b) => (a.server < b.server ? -1 : a.server > b.server ? 1 : a.tool < b.tool ? -1 : a.tool > b.tool ? 1 : 0));
}
//# sourceMappingURL=census.js.map