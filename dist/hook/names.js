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
 * A hostname the policy alias may be built from: lowercase DNS labels
 * (`[a-z0-9-]`) joined by AT LEAST ONE dot, no underscore, at most 253
 * characters (the DNS limit). Requiring a dot and forbidding `_` keeps an
 * alias from ever colliding with the raw `mcp__<server>__<tool>` grammar —
 * a readable server segment (`github`, `ClickUp`, `plugin_x_db`) is never
 * dotted, and `__` can never appear inside the host — so a rule written
 * against a raw name (`^mcp__github__.*$`) cannot be satisfied by an alias
 * whose config-file host happens to read `github` or
 * `github__pull_request_read` (review of the integrated change, E1b).
 * WHATWG parsing already lowercases and punycodes a special-scheme host, so
 * an IDN arrives here as `xn--…`, and an IPv6 literal (`[::1]`) or a bare
 * label (`localhost`, `github`) simply gets no alias.
 */
export const POLICY_ALIAS_HOST_RE = /^[a-z0-9-]+(\.[a-z0-9-]+)+$/;
export const POLICY_ALIAS_HOST_MAX_LEN = 253;
/**
 * The policy ALIAS of an MCP tool name: the same `mcp__<server>__<tool>`
 * shape with the server segment replaced by the hostname the server was
 * resolved to (src/hook/mcp-config.ts), e.g.
 * `mcp__mcp.clickup.com__clickup_get_list` for a cloud session's
 * `mcp__47d587b8-3fb9-42e9-b596-f8b25371248c__clickup_get_list`, or
 * undefined when `host` is not a plausible dotted hostname (see
 * `POLICY_ALIAS_HOST_RE`). The alias is tested against DENY rules only
 * (`evaluatePolicy`, src/hook/policy.ts): the host comes from a file the
 * agent under policy can write (`/tmp/mcp-config-*.json`), so it may add a
 * deny but never satisfy an allow. One deny rule written against the vendor
 * host thus works in a local session (readable server names) and a cloud
 * session (opaque UUID names) alike. The alias is never recorded or shown
 * to Claude Code — it only exists for policy evaluation; `server.name`
 * stays what Claude Code calls the server.
 */
export function hostAliasToolName(host, tool) {
    if (host.length > POLICY_ALIAS_HOST_MAX_LEN || !POLICY_ALIAS_HOST_RE.test(host))
        return undefined;
    return `mcp__${host}__${tool}`;
}
//# sourceMappingURL=names.js.map