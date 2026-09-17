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
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { sha256Ref } from '../chain/hash.js';
import { looksSecret } from '../redact/redactor.js';
import { ENV } from '../types.js';
/** Where a cloud session's Claude Code MCP config lives (one per session). */
export const CLOUD_MCP_CONFIG_GLOB = '/tmp/mcp-config-*.json';
/** A config file larger than this is ignored, never read or parsed. The
 *  real cloud file is a few hundred KB at most (one entry per connector,
 *  each listing its tools); anything past 4 MiB is not that file. */
export const MCP_CONFIG_MAX_BYTES = 4 * 1024 * 1024;
/** Upper bound on the candidate files one resolution consults, so a
 *  pathological `/tmp` (or env value) cannot turn a hook invocation into a
 *  directory walk. */
export const MCP_CONFIG_MAX_FILES = 16;
/** An origin URL longer than this (after scrubbing) is not usable: the whole
 *  origin — `url` AND `host`, so "no url, no alias" always holds — is
 *  dropped, and `originFromEntryUrl` falls back to the relay exactly as for
 *  a non-http `mcp_url`. Defense in depth against a config file stuffing
 *  arbitrary text into every event through a URL, mirroring
 *  `structuralString`'s cap on wire-level strings. */
export const MAX_ORIGIN_URL_LEN = 2048;
/** A path segment recorded verbatim must be a short vocabulary token —
 *  `v2`, `ccr-sessions`, `github`, `mcp`; everything else (readable free
 *  text, percent-encoded bytes, anything over 32 chars) is replaced by its
 *  `sha256:` ref, in addition to the secret/opaque rules below. Mirrors
 *  `structuralString`'s caps: the file is agent-writable (see TRUST above),
 *  so no readable text it chooses may reach the store through a path. */
const PATH_VOCAB_RE = /^[A-Za-z0-9._-]{1,32}$/;
function isPlainObject(v) {
    return typeof v === 'object' && v !== null && !Array.isArray(v);
}
/* ------------------------------- sources -------------------------------- */
/** The config files to consult, in order — see the file-level comment. */
export function candidateConfigPaths(env, glob) {
    const fromEnv = env[ENV.MCP_CONFIG];
    let paths;
    if (typeof fromEnv === 'string' && fromEnv.trim() !== '') {
        paths = fromEnv
            .split(',')
            .map((p) => p.trim())
            .filter((p) => p !== '');
    }
    else {
        paths = glob(CLOUD_MCP_CONFIG_GLOB);
    }
    return paths.slice(0, MCP_CONFIG_MAX_FILES);
}
/** Expand a pattern whose basename holds exactly one `*` (e.g.
 *  `/tmp/mcp-config-*.json`) by listing its directory. Anything else — no
 *  `*`, a `*` in a directory component, an unreadable directory — yields
 *  the literal path (no `*`) or nothing. Sorted, so resolution order is
 *  deterministic. Node 20 (the engine floor) has no `fs.globSync`. */
export function simpleGlob(pattern) {
    if (!pattern.includes('*'))
        return [pattern];
    const dir = dirname(pattern);
    const base = basename(pattern);
    const star = base.indexOf('*');
    if (dir.includes('*') || star < 0 || base.indexOf('*', star + 1) >= 0)
        return [];
    const prefix = base.slice(0, star);
    const suffix = base.slice(star + 1);
    let names;
    try {
        names = readdirSync(dir);
    }
    catch {
        return [];
    }
    return names
        .filter((n) => n.length >= prefix.length + suffix.length && n.startsWith(prefix) && n.endsWith(suffix))
        .sort()
        .map((n) => join(dir, n));
}
/** Read a config file's text, or undefined when it is not a regular file or
 *  is larger than `MCP_CONFIG_MAX_BYTES` (checked by size BEFORE reading,
 *  so an oversized file is never loaded, and again on the text read, in
 *  case it grew in between). Throws on a missing/unreadable path — callers
 *  treat that as "skip". */
export function readConfigText(path) {
    const st = statSync(path);
    if (!st.isFile() || st.size > MCP_CONFIG_MAX_BYTES)
        return undefined;
    const text = readFileSync(path, 'utf8');
    // UTF-16 code units never outnumber UTF-8 bytes, so this is a safe
    // (conservative) re-check without a second byte count.
    return text.length > MCP_CONFIG_MAX_BYTES ? undefined : text;
}
/* ------------------------------ scrubbing ------------------------------- */
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** An opaque identifier: 16+ chars of [A-Za-z0-9_-] mixing letters and
 *  digits — the shape of a cloud session id (`cse_01NRTz…`) and of the
 *  server ids in relay URLs, which `looksSecret` (tuned for credential
 *  shapes) does not catch on its own. Short vocabulary segments like `v2`,
 *  `ccr-sessions`, `github`, `mcp` are untouched. */
const OPAQUE_TOKEN_RE = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9_-]{16,}$/;
function isOpaqueSegment(seg) {
    return UUID_RE.test(seg) || OPAQUE_TOKEN_RE.test(seg) || looksSecret(seg) || !PATH_VOCAB_RE.test(seg);
}
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
export function scrubOriginUrl(u) {
    if (u.protocol !== 'http:' && u.protocol !== 'https:')
        return undefined;
    if (u.hostname === '')
        return undefined;
    const clean = new URL(u.href);
    clean.username = '';
    clean.password = '';
    const segments = clean.pathname.split('/');
    for (let i = 0; i < segments.length; i++) {
        const seg = segments[i];
        if (seg !== '' && isOpaqueSegment(seg))
            segments[i] = sha256Ref(seg);
    }
    clean.pathname = segments.join('/');
    clean.search = '';
    clean.hash = '';
    const url = clean.toString();
    if (url.length > MAX_ORIGIN_URL_LEN)
        return undefined;
    return { host: clean.hostname, url };
}
/** The origin of one config entry's `url`: the decoded `mcp_url` query
 *  parameter (the vendor endpoint behind an Anthropic relay) when it is a
 *  usable http(s) URL, else the entry URL itself. Undefined when neither
 *  parses. Exported for tests; `resolveServerOrigin` is the entry point. */
export function originFromEntryUrl(entryUrl) {
    let entry;
    try {
        entry = new URL(entryUrl);
    }
    catch {
        return undefined;
    }
    const mcpUrl = entry.searchParams.get('mcp_url');
    if (mcpUrl !== null && mcpUrl !== '') {
        try {
            const vendor = scrubOriginUrl(new URL(mcpUrl));
            if (vendor !== undefined)
                return vendor;
        }
        catch {
            /* not a URL: fall through to the relay */
        }
    }
    return scrubOriginUrl(entry);
}
/* ------------------------------ resolution ------------------------------ */
/** The `mcpServers` object of one config file's text, or undefined when the
 *  text is not JSON or is not shaped `{mcpServers:{…}}`. Never throws. */
function mcpServersOf(text) {
    let raw;
    try {
        raw = JSON.parse(text);
    }
    catch {
        return undefined;
    }
    if (!isPlainObject(raw) || !isPlainObject(raw.mcpServers))
        return undefined;
    return raw.mcpServers;
}
/** One entry's origin, or undefined when it is not an object or carries no
 *  usable `url` (a stdio server, for instance). */
function originFromEntry(entry) {
    if (!isPlainObject(entry) || typeof entry.url !== 'string' || entry.url === '')
        return undefined;
    return originFromEntryUrl(entry.url);
}
/** Does this entry's `tools` array declare exactly this tool name? Anything
 *  but an array of objects with a matching own string `name` is simply "no":
 *  `tools: null` (the `github` entry's real shape) and an absent, malformed
 *  or oddly-typed list never match, and the own-property check keeps a
 *  `name` inherited from the prototype chain out of it. */
function declaresTool(entry, tool) {
    if (!isPlainObject(entry) || !Array.isArray(entry.tools))
        return false;
    for (const decl of entry.tools) {
        if (!isPlainObject(decl) || !Object.prototype.hasOwnProperty.call(decl, 'name'))
            continue;
        const name = decl.name;
        if (typeof name === 'string' && name === tool)
            return true;
    }
    return false;
}
/** ROUTE 1. Look `segment` up as an `mcpServers` KEY in one config file's
 *  text. Undefined when the file does not contain it, is not JSON, is not
 *  shaped `{mcpServers:{…}}`, or the entry has no usable `url` (a stdio
 *  server, for instance). */
export function originFromConfigText(text, segment) {
    // Cheap pre-check: the segment must appear as a quoted JSON key before
    // the (comparatively costly) parse is worth doing. A miss here is only
    // ever "unresolved", never an error.
    if (!text.includes(JSON.stringify(segment)))
        return undefined;
    const servers = mcpServersOf(text);
    if (servers === undefined)
        return undefined;
    // Own-property check: a segment like `constructor` or `__proto__` must
    // never resolve through the prototype chain.
    if (!Object.prototype.hasOwnProperty.call(servers, segment))
        return undefined;
    return originFromEntry(servers[segment]);
}
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
export function originFromDeclaredTool(text, segment, tool) {
    // Same cheap pre-check as route 1, on the tool name this time.
    if (tool === '' || !text.includes(JSON.stringify(tool)))
        return undefined;
    const servers = mcpServersOf(text);
    if (servers === undefined)
        return undefined;
    if (Object.prototype.hasOwnProperty.call(servers, segment))
        return undefined;
    let match;
    let matches = 0;
    // Object.keys: own enumerable properties only, like route 1's own-property
    // check — nothing from the prototype chain is ever an entry.
    for (const name of Object.keys(servers)) {
        const entry = servers[name];
        if (!declaresTool(entry, tool))
            continue;
        matches += 1;
        if (matches > 1)
            return undefined; // ambiguous: never guess, never pick the first
        match = entry;
    }
    if (matches !== 1)
        return undefined;
    return originFromEntry(match);
}
/**
 * Resolve the origin of the MCP server Claude Code calls `segment` (the
 * `<server>` in `mcp__<server>__<tool>`), optionally using `opts.tool` (the
 * `<tool>` of the same name) for the declared-tool fallback. `{}` whenever
 * nothing usable is found. Never throws.
 */
export function resolveServerOrigin(segment, opts = {}) {
    try {
        if (typeof segment !== 'string' || segment === '')
            return {};
        const env = opts.env ?? process.env;
        const readFile = opts.readFile ?? readConfigText;
        const glob = opts.glob ?? simpleGlob;
        const tool = typeof opts.tool === 'string' && opts.tool !== '' ? opts.tool : undefined;
        const paths = candidateConfigPaths(env, glob);
        // Route 1 across every candidate file, and only then route 2 across them
        // again: the exact key is preferred over a declared-tool match even when
        // the match sits in an earlier file, which is a real case — `/tmp` holds
        // one `mcp-config-<session>.json` per live session. The second pass
        // re-reads (rather than caching up to 16 × 4 MiB of text in a hook
        // process), and only ever runs when the first pass resolved nothing.
        for (const byKey of [true, false]) {
            if (!byKey && tool === undefined)
                break;
            for (const path of paths) {
                let text;
                try {
                    text = readFile(path);
                }
                catch {
                    continue; // missing / unreadable: skip
                }
                if (text === undefined)
                    continue;
                const origin = byKey ? originFromConfigText(text, segment) : originFromDeclaredTool(text, segment, tool);
                if (origin !== undefined)
                    return origin;
            }
        }
    }
    catch {
        /* fail-open: an origin is a nice-to-have, never a reason to fail a hook */
    }
    return {};
}
//# sourceMappingURL=mcp-config.js.map