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
 * WHICH ENTRY, in this order, and never by guesswork:
 *   1. KEY — the entry whose `mcpServers` key is exactly the segment. The
 *      precise route; tried in every candidate file before route 2 is.
 *   2. DECLARED TOOL — the entry whose `tools[]` declares exactly the tool
 *      being called, used ONLY when EXACTLY ONE entry of a file declares it
 *      and that file has no entry keyed by the segment at all. Zero matches,
 *      or two or more, resolve to nothing.
 *
 * WHY ROUTE 2 EXISTS. The config key and the tool-name segment disagree in
 * real sessions, and which way varies per session. Cloud dogfood 3: config
 * UUID-keyed, tool names UUID-prefixed — route 1 worked. Cloud dogfood 4:
 * config UUID-keyed, tool names FRIENDLY
 * (`mcp__ClickUp__clickup_filter_tasks`) — route 1 missed, so no
 * `server.url` was recorded for any hosted connector, no host alias existed,
 * and both of that run's live deny rules failed to fire while the calls went
 * through to the real workspace. A local session is keyed by friendly name
 * with friendly tool names (route 1 again). Resolution therefore may not
 * assume the key equals the segment.
 *
 * WHAT IS TAKEN from the chosen entry, and nothing else: the vendor endpoint
 * carried (URL-encoded) in the relay URL's `mcp_url` query parameter when
 * present (`https://mcp.clickup.com/mcp`), else the entry's own `url` (the
 * Anthropic relay); scrubbed by `scrubOriginUrl` below; plus that URL's
 * hostname, which `run.ts` turns into the policy alias `mcp__<host>__<tool>`.
 * No headers (they carry the session id and server ids), no session ids (the
 * relay PATH embeds one — it is hashed in place, see `scrubOriginUrl`), no
 * permission policies, no other entries; a `tools[].name` is READ by route 2
 * (compared against the tool being called) but never recorded.
 *
 * SOURCES, in order: `MCP_RECORDER_MCP_CONFIG` (one path, or comma-separated
 * paths, tried in order) when set; else the files matching
 * `/tmp/mcp-config-*.json` (what a cloud session has — one file per live
 * session, so several can match). The first file whose `mcpServers` has the
 * segment as a KEY wins; only when NO file does is route 2 tried, again in
 * file order, so the precise route beats the fallback even across files.
 * Resolution is attempted for every MCP tool event — a UUID segment is the
 * case this exists for, and a readable name (`github`) still gets its relay
 * URL — but it is cheap: a file containing neither the quoted segment nor
 * the quoted tool name is skipped before parsing.
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
 * can add a deny or make one miss, never turn a deny into an allow. Route 2
 * changes nothing about that — it only decides WHICH entry of the same
 * (already untrusted) file is read, and the uniqueness requirement keeps a
 * forged or sloppy file from attributing a tool to the wrong vendor and so
 * producing a WRONG deny.
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
    /** The bare MCP tool name of the call being resolved — the `<tool>` of
     *  `mcp__<server>__<tool>` (`parseToolName`, src/hook/names.ts). Enables
     *  route 2, the declared-tool fallback, for a config file that does not
     *  key any entry by the segment. Omitted (or empty): route 1 only. */
    tool?: string;
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
/** ROUTE 1. Look `segment` up as an `mcpServers` KEY in one config file's
 *  text. Undefined when the file does not contain it, is not JSON, is not
 *  shaped `{mcpServers:{…}}`, or the entry has no usable `url` (a stdio
 *  server, for instance). */
export declare function originFromConfigText(text: string, segment: string): ServerOrigin | undefined;
/** ROUTE 2, the fallback for a file whose keys are not the tool-name segments
 *  (cloud dogfood 4 — see WHICH ENTRY at the top): the entry that DECLARES
 *  this exact tool name in its `tools[]`, used only when EXACTLY ONE entry
 *  does. Undefined otherwise — zero declarations, two or more (two vendors
 *  claiming one tool name is ambiguous, and a wrong attribution would produce
 *  a WRONG deny), or an entry with no usable `url`.
 *
 *  A file that keys an entry by `segment` is left to route 1 entirely: that
 *  entry IS the server Claude Code routes to, whether or not it yielded a
 *  usable URL, so there is nothing to fall back to within that file. */
export declare function originFromDeclaredTool(text: string, segment: string, tool: string): ServerOrigin | undefined;
/**
 * Resolve the origin of the MCP server Claude Code calls `segment` (the
 * `<server>` in `mcp__<server>__<tool>`), optionally using `opts.tool` (the
 * `<tool>` of the same name) for the declared-tool fallback. `{}` whenever
 * nothing usable is found. Never throws.
 */
export declare function resolveServerOrigin(segment: string, opts?: ResolveServerOriginOpts): ServerOrigin;
