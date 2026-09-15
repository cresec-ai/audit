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
export interface ParsedToolName {
    /** True for a `mcp__<server>__<tool>` name; false for a built-in tool. */
    isMcp: boolean;
    /** Logical server name: the MCP server for an mcp__ tool, else 'claude-code'. */
    server: string;
    /** Tool name as recorded: the bare MCP tool name, else the full built-in tool name. */
    tool: string;
}
export declare function parseToolName(toolName: string): ParsedToolName;
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
export declare function hostAliasToolName(host: string, tool: string): string;
