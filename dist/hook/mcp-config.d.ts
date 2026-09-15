/**
 * Resolve where a Claude Code MCP server segment actually points, from the
 * MCP config file Claude Code itself was started with.
 *
 * WHY. In a Claude Code cloud session the Anthropic-hosted connectors are
 * registered under opaque UUID names, so the hook sees tool names like
 * `mcp__47d587b8-3fb9-42e9-b596-f8b25371248c__clickup_get_list` — only
 * `github` keeps a readable name (cloud dogfood 3, surprise 2). Recorded
 * as-is, `server.name` is the UUID, and a policy written the documented way
 * (`^mcp__ClickUp__…`) never matches. The UUID → service mapping exists in
 * exactly one place: the config file Claude Code was started with,
 * `/tmp/mcp-config-<session>.json` in a cloud session, shaped like
 *
 *   {"mcpServers":{
 *     "github":{"url":"https://api.anthropic.com/v2/ccr-sessions/<session>/github/mcp",
 *               "type":"http","headers":{"X-Session-UUID":"<session>","X-MCP-Server-ID":"…"}},
 *     "47d587b8-3fb9-42e9-b596-f8b25371248c":{
 *               "url":"https://api.anthropic.com/v2/ccr-sessions/<session>/mcp?mcp_server_id=…&mcp_url=https%3A%2F%2Fmcp.clickup.com%2Fmcp&toolbox_mcp_server_id=47d587b8-…",
 *               "type":"http","tools":[{"name":"clickup_get_list","permission_policy":"always_allow"},…]},
 *     …}}
 *
 * WHAT IS TAKEN from it — for the ONE entry named exactly like the segment,
 * and nothing else: the vendor endpoint carried (URL-encoded) in the relay
 * URL's `mcp_url` query parameter when present (`https://mcp.clickup.com/mcp`),
 * else the entry's own `url` (the Anthropic relay); scrubbed by
 * `scrubOriginUrl` below; plus that URL's hostname, which `run.ts` turns
 * into the policy alias `mcp__<host>__<tool>`. No headers (they carry the
 * session id and server ids), no session ids (the relay PATH embeds one —
 * it is hashed in place, see `scrubOriginUrl`), no tool lists, no
 * permission policies, no other entries.
 *
 * SOURCES, in order: `MCP_RECORDER_MCP_CONFIG` (one path, or comma-separated
 * paths, tried in order) when set; else the files matching
 * `/tmp/mcp-config-*.json` (what a cloud session has). The first file whose
 * `mcpServers` has the segment wins. Resolution is attempted for every MCP
 * tool event — a UUID segment is the case this exists for, and a readable
 * name (`github`) still gets its relay URL — but it is cheap: a file that
 * does not even contain the quoted segment is skipped before parsing.
 *
 * FAIL-OPEN, ALWAYS: `resolveServerOrigin` never throws and never blocks.
 * A missing, unreadable, oversized (> `MCP_CONFIG_MAX_BYTES`), malformed or
 * oddly-shaped file is simply skipped; an entry with no usable URL yields
 * `{}`. The hook records the same event either way, just without `url`.
 * `env`, `readFile` and `glob` are injectable so tests never touch the
 * real `/tmp` or the real environment.
 *
 * TRUST. What this returns is ASSERTED by a file, never observed on the
 * wire: the hook sends nothing anywhere. In a cloud session `/tmp` is
 * world-writable and the hook runs as the same user as the agent, so an
 * agent with Bash can rewrite, shadow (a name that sorts first) or delete
 * `/tmp/mcp-config-*.json`; `MCP_RECORDER_MCP_CONFIG` names a path in that
 * same environment and changes nothing about that. Consumers therefore
 * treat `url` as the config file's claim about the server, and the policy
 * alias built from `host` is DENY-ONLY (src/hook/policy.ts): a forged file
 * can add a deny or make one miss, never turn a deny into an allow.
 */
/** Where a cloud session's Claude Code MCP config lives (one per session). */
export declare const CLOUD_MCP_CONFIG_GLOB = "/tmp/mcp-config-*.json";
/** A config file larger than this is ignored, never read or parsed. The
 *  real cloud file is a few hundred KB at most (one entry per connector,
 *  each listing its tools); anything past 4 MiB is not that file. */
export declare const MCP_CONFIG_MAX_BYTES: number;
/** Upper bound on the candidate files one resolution consults, so a
 *  pathological `/tmp` (or env value) cannot turn a hook invocation into a
 *  directory walk. */
export declare const MCP_CONFIG_MAX_FILES = 16;
/** An origin URL longer than this (after scrubbing) is not usable: the whole
 *  origin — `url` AND `host`, so "no url, no alias" always holds — is
 *  dropped, and `originFromEntryUrl` falls back to the relay exactly as for
 *  a non-http `mcp_url`. Defense in depth against a config file stuffing
 *  arbitrary text into every event through a URL, mirroring
 *  `structuralString`'s cap on wire-level strings. */
export declare const MAX_ORIGIN_URL_LEN = 2048;
export interface ServerOrigin {
    /** The server's endpoint, scrubbed (see `scrubOriginUrl`): the vendor
     *  `mcp_url` of a hosted connector, else the config entry's own URL. */
    url?: string;
    /** `url`'s hostname, e.g. `mcp.clickup.com` — the policy alias segment.
     *  Always set together with `url`, never without it. */
    host?: string;
}
export interface ResolveServerOriginOpts {
    /** Environment to read `MCP_RECORDER_MCP_CONFIG` from (default: process.env). */
    env?: Record<string, string | undefined>;
    /** Read a file's full text, or return undefined to skip it (unreadable,
     *  oversized, not a file). Default: `readConfigText` (bounded by
     *  `MCP_CONFIG_MAX_BYTES`). May throw — the caller swallows it. */
    readFile?: (path: string) => string | undefined;
    /** Expand one glob pattern into matching paths, sorted. Default:
     *  `simpleGlob` (a single `*` in the basename). May throw — swallowed. */
    glob?: (pattern: string) => string[];
}
/** The config files to consult, in order — see the file-level comment. */
export declare function candidateConfigPaths(env: Record<string, string | undefined>, glob: (pattern: string) => string[]): string[];
/** Expand a pattern whose basename holds exactly one `*` (e.g.
 *  `/tmp/mcp-config-*.json`) by listing its directory. Anything else — no
 *  `*`, a `*` in a directory component, an unreadable directory — yields
 *  the literal path (no `*`) or nothing. Sorted, so resolution order is
 *  deterministic. Node 20 (the engine floor) has no `fs.globSync`. */
export declare function simpleGlob(pattern: string): string[];
/** Read a config file's text, or undefined when it is not a regular file or
 *  is larger than `MCP_CONFIG_MAX_BYTES` (checked by size BEFORE reading,
 *  so an oversized file is never loaded, and again on the text read, in
 *  case it grew in between). Throws on a missing/unreadable path — callers
 *  treat that as "skip". */
export declare function readConfigText(path: string): string | undefined;
/**
 * The recorded form of an origin URL. Same rules the http proxy applies to
 * its `--target` before stamping it on events (docs/event-schema.md,
 * "`command` target-URL handling"), plus the opaque-token rule above:
 *  - userinfo (`user:pass@`) is stripped;
 *  - every path segment that is secret-shaped, an opaque identifier (a
 *    UUID, a cloud session id) or not a short vocabulary token
 *    (`PATH_VOCAB_RE`) is replaced in place by its `sha256:<hex>` ref —
 *    computed exactly like every other redacted value (`sha256Ref`), so a
 *    blast-radius `query` for a session id still finds the event;
 *  - the query string and fragment are dropped unconditionally (any single
 *    parameter can be a bearer credential — `?api_key=…`);
 *  - only http(s) URLs qualify, and a scrubbed URL longer than
 *    `MAX_ORIGIN_URL_LEN` is not usable either; both yield undefined.
 * Unlike the http proxy's `--target`, the stripped pieces are NOT
 * fingerprinted (`identity.credential_fingerprints`): the proxy fingerprints
 * a credential it goes on to send, while the hook sends nothing — a
 * credential sitting in this file is dropped, not attested.
 * The hostname is never altered: it is the whole point (the policy alias).
 */
export declare function scrubOriginUrl(u: URL): ServerOrigin | undefined;
/** The origin of one config entry's `url`: the decoded `mcp_url` query
 *  parameter (the vendor endpoint behind an Anthropic relay) when it is a
 *  usable http(s) URL, else the entry URL itself. Undefined when neither
 *  parses. Exported for tests; `resolveServerOrigin` is the entry point. */
export declare function originFromEntryUrl(entryUrl: string): ServerOrigin | undefined;
/** Look `segment` up in one config file's text. Undefined when the file
 *  does not contain it, is not JSON, is not shaped `{mcpServers:{…}}`, or
 *  the entry has no usable `url` (a stdio server, for instance). */
export declare function originFromConfigText(text: string, segment: string): ServerOrigin | undefined;
/**
 * Resolve the origin of the MCP server Claude Code calls `segment` (the
 * `<server>` in `mcp__<server>__<tool>`). `{}` whenever nothing usable is
 * found. Never throws.
 */
export declare function resolveServerOrigin(segment: string, opts?: ResolveServerOriginOpts): ServerOrigin;
