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

/**
 * Non-greedy up to the FIRST "__": the canonical shape is exactly one
 * separator between server and tool. A plugin-bundled server name may itself
 * contain single underscores/hyphens (e.g. `mcp__plugin_my-plugin_db__query`
 * per the docs) — none of that confuses this split, since it never contains
 * a literal "__" before the real separator in any example the docs give.
 */
const MCP_TOOL_RE = /^mcp__(.+?)__(.+)$/;

export function parseToolName(toolName: string): ParsedToolName {
  const m = MCP_TOOL_RE.exec(toolName);
  if (m !== null) {
    return { isMcp: true, server: m[1]!, tool: m[2]! };
  }
  return { isMcp: false, server: 'claude-code', tool: toolName };
}
