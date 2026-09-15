/**
 * Split a Claude Code hook `tool_name` into (server, tool).
 *
 * MCP tools are presented to the model — and to hooks — as
 * `mcp__<server>__<tool>` (see the "MCP Tool Naming Pattern" in
 * https://code.claude.com/docs/en/hooks, e.g. `mcp__memory__create_entities`,
 * `mcp__filesystem__read_file`). Built-in tools (`Bash`, `Edit`, `Read`, ...)
 * carry no such prefix. `mcp-recorder hook` records the underlying MCP tool
 * name the same way the stdio/http proxy would have seen it (bare, no
 * `mcp__<server>__` prefix — that prefix is Claude Code's own routing
 * namespace, never part of the wire-level MCP `tools/call` name), with the
 * server it went to stamped on `ServerContext.name` instead.
 */
/**
 * Non-greedy up to the FIRST "__": the canonical shape is exactly one
 * separator between server and tool. A plugin-bundled server name may itself
 * contain single underscores/hyphens (e.g. `mcp__plugin_my-plugin_db__query`
 * per the docs) — none of that confuses this split, since it never contains
 * a literal "__" before the real separator in any example the docs give.
 */
const MCP_TOOL_RE = /^mcp__(.+?)__(.+)$/;
export function parseToolName(toolName) {
    const m = MCP_TOOL_RE.exec(toolName);
    if (m !== null) {
        return { isMcp: true, server: m[1], tool: m[2] };
    }
    return { isMcp: false, server: 'claude-code', tool: toolName };
}
/**
 * The policy ALIAS of an MCP tool name: the same `mcp__<server>__<tool>`
 * shape with the server segment replaced by the hostname the server was
 * resolved to (src/hook/mcp-config.ts), e.g.
 * `mcp__mcp.clickup.com__clickup_get_list` for a cloud session's
 * `mcp__47d587b8-3fb9-42e9-b596-f8b25371248c__clickup_get_list`. A policy
 * rule matches when its regex matches either the raw name or this alias,
 * so one rule written against the vendor host works in a local session
 * (readable server names) and a cloud session (opaque UUID names) alike.
 * The alias is never recorded or shown to Claude Code — it only exists for
 * policy evaluation; `server.name` stays what Claude Code calls the server.
 */
export function hostAliasToolName(host, tool) {
    return `mcp__${host}__${tool}`;
}
//# sourceMappingURL=names.js.map